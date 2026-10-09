//! pod-netns — run a program in a network namespace with all egress through a
//! SOCKS5 or HTTP proxy, with no `LD_PRELOAD` and no interposers.
//!
//! A shim can only reach a dynamic binary. A network namespace is enforced by
//! the kernel, so a static binary, a Go binary, and a program that never calls
//! libc's `connect(3)` are all treated the same. This is the practical use of
//! the userspace virtual network in `cfrs::vnet`: a TUN device is the only
//! interface inside the namespace, the host side of it is a `smoltcp` stack,
//! and every flow is handed to an upstream proxy.
//!
//! ```text
//!   pod-netns [opts] -- PROGRAM
//!     │
//!     ├─ child: unshare(NEWUSER|NEWNET), lo up, TUN eth0, exec PROGRAM
//!     │
//!     └─ parent: smoltcp over the TUN, fake-IP DNS, SOCKS5/HTTP upstream
//! ```
//!
//! Requires unprivileged user namespaces and `/dev/net/tun`. `pod-netns
//! doctor` measures both before anything is attempted; where the host denies
//! them (a sealed sandbox can), it says so with the errno and exits non-zero.

use std::collections::{HashMap, VecDeque};
use std::ffi::CString;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::socket::udp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpListenEndpoint, Ipv4Address};

/// A std `Ipv4Addr` as smoltcp's wire type.
fn smol_v4(addr: Ipv4Addr) -> Ipv4Address {
    Ipv4Address::from_bytes(&addr.octets())
}

// ── tunables ────────────────────────────────────────────────────────────────

/// Address on the TUN inside the namespace (the guest side of the /31).
const TUN_ADDR: Ipv4Addr = Ipv4Addr::new(10, 66, 255, 255);
/// The gateway the stack impersonates, and the DNS server handed to the guest.
const TUN_GW: Ipv4Addr = Ipv4Addr::new(10, 66, 255, 254);
const TUN_PREFIX: u8 = 31;
const TUN_MTU: usize = 1500;
const TCP_BUF: usize = 64 * 1024;
const DNS_PORT: u16 = 53;
/// RFC 2544 benchmarking range, used by proxychains and friends for fake IPs.
const FAKE_IP_BASE: u32 = 0xC612_0000; // 198.18.0.0
const FAKE_IP_COUNT: u32 = 1 << 17; // 198.18.0.0/15

const TUNSETIFF: libc::c_ulong = 0x4004_54CA;
const IFF_TUN: libc::c_int = 0x0001;
const IFF_NO_PI: libc::c_int = 0x1000;

// ── errors ──────────────────────────────────────────────────────────────────

/// Exit code for "this host cannot run any backend", distinct from a failure
/// of the program itself.
const EXIT_NO_BACKEND: i32 = 3;

// ── proxy configuration ─────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
enum ProxyKind {
    Socks5,
    Http,
}

#[derive(Clone, Debug)]
struct Proxy {
    kind: ProxyKind,
    host: String,
    port: u16,
    user: Option<String>,
    pass: Option<String>,
}

impl Proxy {
    fn parse(spec: &str) -> Result<Self> {
        let (scheme, rest) = match spec.split_once("://") {
            Some((s, r)) => (s, r),
            None => ("socks5", spec),
        };
        let kind = match scheme {
            "socks5" | "socks5h" | "socks" => ProxyKind::Socks5,
            "http" | "https" => ProxyKind::Http,
            other => bail!("unknown proxy scheme {other:?} (socks5:// or http://)"),
        };
        // user:pass@host:port
        let (creds, hostport) = match rest.rsplit_once('@') {
            Some((c, h)) => (Some(c), h),
            None => (None, rest),
        };
        let (user, pass) = match creds {
            Some(c) => match c.split_once(':') {
                Some((u, p)) => (Some(u.to_string()), Some(p.to_string())),
                None => (Some(c.to_string()), None),
            },
            None => (None, None),
        };
        let (host, port) = hostport
            .rsplit_once(':')
            .with_context(|| format!("proxy {spec:?} needs host:port"))?;
        Ok(Self {
            kind,
            host: host.to_string(),
            port: port.parse().context("proxy port")?,
            user,
            pass,
        })
    }

    fn endpoint(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

// ── command line ────────────────────────────────────────────────────────────

struct Args {
    proxies: Vec<Proxy>,
    program: Vec<String>,
    doctor: bool,
    verbose: bool,
}

fn usage() -> String {
    "\
pod-netns — run a program in a netns with all egress through a proxy

USAGE:
    pod-netns [OPTIONS] -- PROGRAM [ARGS...]
    pod-netns doctor

OPTIONS:
    -x, --proxy SPEC     Upstream proxy: socks5://[user:pass@]host:port or
                         http://[user:pass@]host:port (repeatable)
    -v, --verbose        Log each flow
    -h, --help           This text

The first proxy is the default route. Requires unprivileged user namespaces and
/dev/net/tun; run `pod-netns doctor` to measure them.
"
    .to_string()
}

fn parse_args(argv: &[String]) -> Result<Args> {
    let mut proxies = Vec::new();
    let mut program = Vec::new();
    let mut doctor = false;
    let mut verbose = false;
    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--" => {
                program = argv[i + 1..].to_vec();
                break;
            }
            "doctor" if i == 0 => {
                doctor = true;
                i += 1;
            }
            "-h" | "--help" => {
                print!("{}", usage());
                std::process::exit(0);
            }
            "-v" | "--verbose" => {
                verbose = true;
                i += 1;
            }
            "-x" | "--proxy" => {
                let spec = argv.get(i + 1).context("--proxy needs a value")?;
                proxies.push(Proxy::parse(spec)?);
                i += 2;
            }
            other => bail!("unexpected argument {other:?}; see --help"),
        }
    }
    if !doctor && program.is_empty() {
        bail!("nothing to run; usage: pod-netns [OPTIONS] -- PROGRAM");
    }
    Ok(Args { proxies, program, doctor, verbose })
}

// ── capability probes ───────────────────────────────────────────────────────

struct Probe {
    name: &'static str,
    ok: bool,
    detail: String,
}

fn probe_unshare(flags: libc::c_int) -> Probe {
    // Probe in a forked child: a successful unshare would otherwise take the
    // probe process out of the host's network namespace permanently.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let r = unsafe { libc::unshare(flags) };
        let code = if r == 0 {
            0
        } else {
            std::io::Error::last_os_error().raw_os_error().unwrap_or(1)
        };
        unsafe { libc::_exit(code) };
    }
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    let code = if libc::WIFEXITED(status) { libc::WEXITSTATUS(status) } else { -1 };
    let name = if flags == libc::CLONE_NEWNET { "unshare(CLONE_NEWNET)" } else { "unshare(NEWUSER|NEWNET)" };
    if code == 0 {
        Probe { name, ok: true, detail: "ok".into() }
    } else {
        let errno = std::io::Error::from_raw_os_error(code);
        Probe { name, ok: false, detail: format!("{errno}") }
    }
}

fn probe_tun() -> Probe {
    let path = c"/dev/net/tun";
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if fd < 0 {
        let e = std::io::Error::last_os_error();
        return Probe { name: "open(/dev/net/tun)", ok: false, detail: format!("{e}") };
    }
    unsafe { libc::close(fd) };
    Probe { name: "open(/dev/net/tun)", ok: true, detail: "ok".into() }
}

fn probe_ptrace() -> Probe {
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let r = unsafe { libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) };
        if r != 0 {
            unsafe { libc::_exit(1) };
        }
        unsafe { libc::raise(libc::SIGSTOP) };
        unsafe { libc::_exit(0) };
    }
    // The child is our tracer's child, so its SIGSTOP is a ptrace-stop; use
    // WUNTRACED so a plain stop is still reported if TRACEME failed silently.
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, libc::WUNTRACED) };
    let stopped = libc::WIFSTOPPED(status);
    let detail = if stopped {
        "descendant ptrace allowed".to_string()
    } else {
        "ptrace not permitted".to_string()
    };
    unsafe {
        libc::ptrace(libc::PTRACE_DETACH, pid, 0, 0);
        libc::kill(pid, libc::SIGKILL);
        libc::waitpid(pid, &mut status, 0);
    }
    Probe { name: "PTRACE_TRACEME (fallback backend)", ok: stopped, detail }
}

/// Can a seccomp filter that returns `SECCOMP_RET_USER_NOTIF` be installed and
/// handed a listener fd? That is the only `LD_PRELOAD`-free interception left
/// when namespaces and ptrace are both denied.
fn probe_seccomp_notif() -> Probe {
    const BPF_LD_ABS_W: u16 = 0x20; // BPF_LD | BPF_W | BPF_ABS
    const BPF_JEQ_K: u16 = 0x15; // BPF_JMP | BPF_JEQ | BPF_K
    const BPF_RET_K: u16 = 0x06; // BPF_RET | BPF_K
    const RET_USER_NOTIF: u32 = 0x7fc0_0000;
    const RET_ALLOW: u32 = 0x7fff_0000;
    const SET_MODE_FILTER: libc::c_uint = 1;
    const FLAG_NEW_LISTENER: libc::c_uint = 1;

    let filter = [
        libc::sock_filter { code: BPF_LD_ABS_W, jt: 0, jf: 0, k: 0 },
        libc::sock_filter {
            code: BPF_JEQ_K,
            jt: 0,
            jf: 1,
            k: libc::SYS_getpid as u32,
        },
        libc::sock_filter { code: BPF_RET_K, jt: 0, jf: 0, k: RET_USER_NOTIF },
        libc::sock_filter { code: BPF_RET_K, jt: 0, jf: 0, k: RET_ALLOW },
    ];
    let prog = libc::sock_fprog { len: filter.len() as u16, filter: filter.as_ptr() as *mut _ };
    let r = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SET_MODE_FILTER,
            FLAG_NEW_LISTENER,
            &prog as *const libc::sock_fprog,
        )
    };
    if r < 0 {
        return Probe {
            name: "seccomp(SECCOMP_RET_USER_NOTIF)",
            ok: false,
            detail: format!("{}", std::io::Error::last_os_error()),
        };
    }
    let fd = r as RawFd;
    unsafe { libc::close(fd) };
    Probe { name: "seccomp(SECCOMP_RET_USER_NOTIF)", ok: true, detail: "listener installed".into() }
}

fn doctor() -> i32 {
    let probes = [
        probe_unshare(libc::CLONE_NEWNET),
        probe_unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET),
        probe_tun(),
        probe_ptrace(),
        probe_seccomp_notif(),
    ];
    println!("pod-netns: capability report");
    for p in &probes {
        println!("  {:<34} {:<5} {}", p.name, if p.ok { "ok" } else { "no" }, p.detail);
    }
    // The netns backend needs a network namespace and a TUN device.
    let netns_ok = probes[0].ok || probes[1].ok;
    if netns_ok && probes[2].ok {
        println!("pod-netns: backend netns: available");
        return 0;
    }
    println!("pod-netns: backend netns: unavailable");
    if probes[3].ok {
        println!("pod-netns: note: descendant ptrace works, so a ptrace backend could run here");
    }
    if probes[4].ok {
        println!("pod-netns: note: SECCOMP_RET_USER_NOTIF works, so a seccomp backend could run here");
    }
    EXIT_NO_BACKEND
}

// ── namespace + TUN setup (child side) ──────────────────────────────────────

fn write_proc(path: &str, data: &str) -> Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .with_context(|| format!("open {path}"))?;
    f.write_all(data.as_bytes()).with_context(|| format!("write {path}"))
}

fn write_id_maps(pid: u32) -> Result<()> {
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    write_proc(&format!("/proc/{pid}/setgroups"), "deny")?;
    write_proc(&format!("/proc/{pid}/uid_map"), &format!("{uid} {uid} 1\n"))?;
    write_proc(&format!("/proc/{pid}/gid_map"), &format!("{gid} {gid} 1\n"))?;
    Ok(())
}

fn ifreq_for(name: &str) -> libc::ifreq {
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    for (i, b) in name.bytes().enumerate().take(libc::IF_NAMESIZE - 1) {
        ifr.ifr_name[i] = b as libc::c_char;
    }
    ifr
}

fn bringup_loopback() -> Result<()> {
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if sock < 0 {
        bail!("socket() for lo: {}", std::io::Error::last_os_error());
    }
    let mut ifr = ifreq_for("lo");
    let r = unsafe {
        ifr.ifr_ifru.ifru_flags = (libc::IFF_UP | libc::IFF_RUNNING) as i16;
        libc::ioctl(sock, libc::SIOCSIFFLAGS as _, &ifr as *const _)
    };
    unsafe { libc::close(sock) };
    if r < 0 {
        bail!("ioctl SIOCSIFFLAGS lo: {}", std::io::Error::last_os_error());
    }
    Ok(())
}

/// Create and configure the TUN device inside the namespace. Returns its fd.
fn create_tun(name: &str) -> Result<OwnedFd> {
    if name.len() >= libc::IF_NAMESIZE {
        bail!("TUN name {name:?} is too long");
    }
    let fd = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("open /dev/net/tun");
    }
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };

    let mut ifr = ifreq_for(name);
    let r = unsafe {
        ifr.ifr_ifru.ifru_flags = (IFF_TUN | IFF_NO_PI) as libc::c_short;
        libc::ioctl(owned.as_raw_fd(), TUNSETIFF as _, &mut ifr as *mut libc::ifreq)
    };
    if r < 0 {
        return Err(std::io::Error::last_os_error()).context("ioctl TUNSETIFF");
    }

    // Configure with ioctls rather than `ip`: RTNETLINK can fail inside a user
    // namespace even when the ioctls succeed.
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if sock < 0 {
        bail!("socket() for tun config: {}", std::io::Error::last_os_error());
    }
    let guard = FdGuard(sock);
    let set_addr = |cmd: libc::c_ulong, addr: Ipv4Addr| -> Result<()> {
        let mut ifr = ifreq_for(name);
        let r = unsafe {
            let sin =
                &mut ifr.ifr_ifru.ifru_addr as *mut libc::sockaddr as *mut libc::sockaddr_in;
            (*sin).sin_family = libc::AF_INET as u16;
            (*sin).sin_addr.s_addr = u32::from_ne_bytes(addr.octets());
            libc::ioctl(guard.0, cmd as _, &ifr as *const _)
        };
        if r < 0 {
            bail!("ioctl {cmd:#x}: {}", std::io::Error::last_os_error());
        }
        Ok(())
    };

    let mut mtu_ifr = ifreq_for(name);
    let mtu_r = unsafe {
        mtu_ifr.ifr_ifru.ifru_mtu = TUN_MTU as libc::c_int;
        libc::ioctl(guard.0, libc::SIOCSIFMTU as _, &mtu_ifr as *const _)
    };
    if mtu_r < 0 {
        bail!("ioctl SIOCSIFMTU: {}", std::io::Error::last_os_error());
    }
    set_addr(libc::SIOCSIFADDR, TUN_ADDR)?;
    let netmask = u32::MAX << (32 - TUN_PREFIX as u32);
    set_addr(libc::SIOCSIFNETMASK, Ipv4Addr::from(netmask.to_be_bytes()))?;

    let mut up = ifreq_for(name);
    let up_r = unsafe {
        up.ifr_ifru.ifru_flags = (libc::IFF_UP | libc::IFF_RUNNING) as i16;
        libc::ioctl(guard.0, libc::SIOCSIFFLAGS as _, &up as *const _)
    };
    if up_r < 0 {
        bail!("ioctl SIOCSIFFLAGS up: {}", std::io::Error::last_os_error());
    }

    // Default route via the gateway the userspace stack impersonates.
    let mut route: libc::rtentry = unsafe { std::mem::zeroed() };
    let dst = &mut route.rt_dst as *mut libc::sockaddr as *mut libc::sockaddr_in;
    let gw = &mut route.rt_gateway as *mut libc::sockaddr as *mut libc::sockaddr_in;
    let mask = &mut route.rt_genmask as *mut libc::sockaddr as *mut libc::sockaddr_in;
    unsafe {
        (*dst).sin_family = libc::AF_INET as u16;
        (*gw).sin_family = libc::AF_INET as u16;
        (*gw).sin_addr.s_addr = u32::from_ne_bytes(TUN_GW.octets());
        (*mask).sin_family = libc::AF_INET as u16;
    }
    route.rt_flags = libc::RTF_UP | libc::RTF_GATEWAY;
    let name_c = CString::new(name)?;
    route.rt_dev = name_c.as_ptr() as *mut libc::c_char;
    if unsafe { libc::ioctl(guard.0, libc::SIOCADDRT as _, &route as *const _) } < 0 {
        bail!("ioctl SIOCADDRT: {}", std::io::Error::last_os_error());
    }
    Ok(owned)
}

struct FdGuard(RawFd);
impl Drop for FdGuard {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

// ── fd passing (child → parent) ─────────────────────────────────────────────

/// Send one fd over a unix socketpair with SCM_RIGHTS.
fn send_fd(sock: RawFd, fd: RawFd) -> Result<()> {
    let mut iov = libc::iovec { iov_base: std::ptr::null_mut(), iov_len: 0 };
    let mut cmsg = [0u8; 64];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg.len();
    unsafe {
        let hdr = CMSG_FIRSTHDR(&msg);
        (*hdr).cmsg_level = libc::SOL_SOCKET;
        (*hdr).cmsg_type = libc::SCM_RIGHTS;
        (*hdr).cmsg_len = CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as _;
        std::ptr::copy_nonoverlapping(
            &fd as *const RawFd as *const u8,
            CMSG_DATA(hdr),
            std::mem::size_of::<RawFd>(),
        );
        msg.msg_controllen = (*hdr).cmsg_len as _;
        if libc::sendmsg(sock, &msg, 0) < 0 {
            bail!("sendmsg(SCM_RIGHTS): {}", std::io::Error::last_os_error());
        }
    }
    Ok(())
}

#[allow(non_snake_case)]
unsafe fn CMSG_FIRSTHDR(msg: *const libc::msghdr) -> *mut libc::cmsghdr {
    if (*msg).msg_controllen >= std::mem::size_of::<libc::cmsghdr>() as _ {
        (*msg).msg_control as *mut libc::cmsghdr
    } else {
        std::ptr::null_mut()
    }
}

#[allow(non_snake_case)]
unsafe fn CMSG_DATA(hdr: *mut libc::cmsghdr) -> *mut u8 {
    (hdr as *mut u8).add(std::mem::size_of::<libc::cmsghdr>())
}

#[allow(non_snake_case)]
fn CMSG_LEN(len: u32) -> u32 {
    (std::mem::size_of::<libc::cmsghdr>() as u32 + len + 7) & !7
}

/// Receive one fd over a unix socketpair.
fn recv_fd(sock: RawFd) -> Result<RawFd> {
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec { iov_base: byte.as_mut_ptr() as *mut _, iov_len: 1 };
    let mut cmsg = [0u8; 64];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg.len();
    let n = unsafe { libc::recvmsg(sock, &mut msg, 0) };
    if n <= 0 {
        bail!("recvmsg(SCM_RIGHTS): {}", std::io::Error::last_os_error());
    }
    let hdr = unsafe { CMSG_FIRSTHDR(&msg) };
    if hdr.is_null() {
        bail!("no fd in the received message");
    }
    let mut fd: RawFd = -1;
    unsafe {
        std::ptr::copy_nonoverlapping(
            CMSG_DATA(hdr) as *const RawFd,
            &mut fd,
            std::mem::size_of::<RawFd>(),
        );
    }
    Ok(fd)
}

// ── TUN as a smoltcp device ─────────────────────────────────────────────────

struct Tun {
    fd: RawFd,
    mtu: usize,
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
}

impl Tun {
    fn new(fd: RawFd, mtu: usize) -> Self {
        // The read loop drains until EAGAIN, so the fd must not block.
        unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) };
        Self { fd, mtu, rx: VecDeque::new(), tx: VecDeque::new() }
    }

    /// Read whatever the kernel has queued into `rx`.
    fn read_ready(&mut self) {
        loop {
            let mut buf = vec![0u8; self.mtu];
            let n = unsafe { libc::read(self.fd, buf.as_mut_ptr() as *mut _, self.mtu) };
            if n <= 0 {
                break;
            }
            buf.truncate(n as usize);
            self.rx.push_back(buf);
        }
    }

    fn flush(&mut self) {
        while let Some(pkt) = self.tx.pop_front() {
            let mut off = 0;
            while off < pkt.len() {
                let n = unsafe {
                    libc::write(self.fd, pkt[off..].as_ptr() as *const _, pkt.len() - off)
                };
                if n <= 0 {
                    return;
                }
                off += n as usize;
            }
        }
    }
}

impl Device for Tun {
    type RxToken<'a> = TunRx;
    type TxToken<'a> = TunTx<'a>;
    fn receive(&mut self, _t: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let pkt = self.rx.pop_front()?;
        Some((TunRx(pkt), TunTx { out: &mut self.tx }))
    }
    fn transmit(&mut self, _t: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(TunTx { out: &mut self.tx })
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps.checksum = ChecksumCapabilities::default();
        caps
    }
}

struct TunRx(Vec<u8>);
impl RxToken for TunRx {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(mut self, f: F) -> R {
        f(&mut self.0)
    }
}
struct TunTx<'a> {
    out: &'a mut VecDeque<Vec<u8>>,
}
impl TxToken for TunTx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        self.out.push_back(buf);
        r
    }
}

// ── fake-IP DNS ─────────────────────────────────────────────────────────────

struct FakeDns {
    by_ip: HashMap<Ipv4Addr, String>,
    by_name: HashMap<String, Ipv4Addr>,
    next: u32,
}

impl FakeDns {
    fn new() -> Self {
        Self { by_ip: HashMap::new(), by_name: HashMap::new(), next: 0 }
    }

    fn address_for(&mut self, name: &str) -> Ipv4Addr {
        if let Some(ip) = self.by_name.get(name) {
            return *ip;
        }
        let ip = Ipv4Addr::from((FAKE_IP_BASE + (self.next % FAKE_IP_COUNT)).to_be_bytes());
        self.next += 1;
        self.by_name.insert(name.to_string(), ip);
        self.by_ip.insert(ip, name.to_string());
        ip
    }

    fn name_for(&self, ip: Ipv4Addr) -> Option<&str> {
        self.by_ip.get(&ip).map(String::as_str)
    }
}

// ── the stack loop ──────────────────────────────────────────────────────────

/// One outbound flow: a smoltcp TCP socket and the upstream proxy connection.
struct Flow {
    upstream: tokio::net::TcpStream,
    to_upstream: Vec<u8>,
    to_app: Vec<u8>,
    up_eof: bool,
}

struct Backend {
    device: Tun,
    interface: Interface,
    sockets: SocketSet<'static>,
    dns_socket: SocketHandle,
    dns: FakeDns,
    /// destination port → listener handle created for it
    listeners: HashMap<u16, SocketHandle>,
    flows: HashMap<SocketHandle, Flow>,
    proxies: Vec<Proxy>,
    verbose: bool,
}

impl Backend {
    fn new(fd: RawFd, proxies: Vec<Proxy>, verbose: bool) -> Result<Self> {
        let mut device = Tun::new(fd, TUN_MTU);
        let mut config = IfaceConfig::new(HardwareAddress::Ip);
        config.random_seed = seed();
        let mut interface = Interface::new(config, &mut device, SmolInstant::now());
        interface.update_ip_addrs(|addrs| {
            addrs.push(IpCidr::new(IpAddress::Ipv4(smol_v4(TUN_GW)), TUN_PREFIX)).unwrap();
        });
        interface.routes_mut().add_default_ipv4_route(smol_v4(TUN_GW)).unwrap();
        // Accept packets addressed to any destination: the guest connects to
        // real addresses, and we impersonate all of them.
        interface.set_any_ip(true);

        let mut sockets = SocketSet::new(Vec::new());
        let dns_socket = add_udp(&mut sockets, DNS_PORT);
        Ok(Self {
            device,
            interface,
            sockets,
            dns_socket,
            dns: FakeDns::new(),
            listeners: HashMap::new(),
            flows: HashMap::new(),
            proxies,
            verbose,
        })
    }

    /// A SYN to a new destination port needs a listen socket before smoltcp
    /// processes the packet.
    fn observe_syns(&mut self) {
        let mut new_ports = Vec::new();
        for pkt in &self.device.rx {
            if let Some((_src, _sport, _dst, dport)) = parse_tcp_syn(pkt) {
                if !self.listeners.contains_key(&dport) && !new_ports.contains(&dport) {
                    new_ports.push(dport);
                }
            }
        }
        for port in new_ports {
            let mut socket = tcp_socket();
            let endpoint = IpListenEndpoint { addr: None, port };
            if socket.listen(endpoint).is_ok() {
                let handle = self.sockets.add(socket);
                self.listeners.insert(port, handle);
                if self.verbose {
                    eprintln!("pod-netns: listening for outbound port {port}");
                }
            }
        }
    }

    async fn tick(&mut self) -> Result<()> {
        self.observe_syns();
        self.answer_dns();
        self.interface.poll(SmolInstant::now(), &mut self.device, &mut self.sockets);
        self.accept_flows().await;
        self.shuttle().await;
        self.device.flush();
        Ok(())
    }

    fn answer_dns(&mut self) {
        let socket = self.sockets.get_mut::<udp::Socket>(self.dns_socket);
        while socket.can_recv() {
            let Ok((data, meta)) = socket.recv() else { break };
            let Ok(query) = cfrs::vnet::dns::ParsedQuery::parse(data) else { continue };
            let ip = self.dns.address_for(&query.name);
            let answers = vec![IpAddr::V4(ip)];
            let reply = cfrs::vnet::dns::build_response(&query, &answers, 0);
            let _ = socket.send_slice(&reply, meta.endpoint);
        }
    }

    async fn accept_flows(&mut self) {
        let handles: Vec<SocketHandle> = self.listeners.values().copied().collect();
        for handle in handles {
            if self.flows.contains_key(&handle) {
                continue;
            }
            // The destination is the socket's local endpoint; the source is
            // the guest's. Read it under an immutable borrow, then release it
            // before touching the map again.
            let target = {
                let socket = self.sockets.get::<tcp::Socket>(handle);
                if !matches!(socket.state(), tcp::State::Established) {
                    continue;
                }
                let Some(local) = socket.local_endpoint() else { continue };
                let IpAddress::Ipv4(dst_ip) = local.addr else { continue };
                let b = dst_ip.as_bytes();
                let dst_ip = Ipv4Addr::new(b[0], b[1], b[2], b[3]);
                match self.dns.name_for(dst_ip) {
                    Some(name) => format!("{name}:{}", local.port),
                    None => format!("{dst_ip}:{}", local.port),
                }
            };
            let proxy = self.proxies[0].clone();
            if self.verbose {
                eprintln!("pod-netns: {target} via {}", proxy.endpoint());
            }
            match connect_upstream(&proxy, &target).await {
                Ok(stream) => {
                    self.flows.insert(handle, Flow {
                        upstream: stream,
                        to_upstream: Vec::new(),
                        to_app: Vec::new(),
                        up_eof: false,
                    });
                }
                Err(e) => {
                    if self.verbose {
                        eprintln!("pod-netns: upstream for {target} failed: {e:#}");
                    }
                    self.sockets.get_mut::<tcp::Socket>(handle).abort();
                }
            }
        }
    }

    async fn shuttle(&mut self) {
        let handles: Vec<SocketHandle> = self.flows.keys().copied().collect();
        for handle in handles {
            let mut flow = self.flows.remove(&handle).unwrap();
            let socket = self.sockets.get_mut::<tcp::Socket>(handle);
            let mut close = false;

            // app → upstream
            while socket.can_recv() {
                match socket.recv(|buf| {
                    let n = buf.len().min(64 * 1024);
                    flow.to_upstream.extend_from_slice(&buf[..n]);
                    (n, ())
                }) {
                    Ok(()) => {}
                    Err(_) => break,
                }
            }
            while !flow.to_upstream.is_empty() {
                match flow.upstream.try_write(&flow.to_upstream) {
                    Ok(0) => break,
                    Ok(n) => {
                        flow.to_upstream.drain(..n);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(_) => {
                        close = true;
                        break;
                    }
                }
            }

            // upstream → app
            let mut buf = [0u8; 16 * 1024];
            loop {
                match flow.upstream.try_read(&mut buf) {
                    Ok(0) => {
                        flow.up_eof = true;
                        break;
                    }
                    Ok(n) => flow.to_app.extend_from_slice(&buf[..n]),
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(_) => {
                        close = true;
                        break;
                    }
                }
            }
            while !flow.to_app.is_empty() && socket.can_send() {
                match socket.send_slice(&flow.to_app) {
                    Ok(n) => {
                        flow.to_app.drain(..n);
                    }
                    Err(_) => break,
                }
            }

            if (flow.up_eof && flow.to_app.is_empty()) || close || !socket.may_send() {
                socket.close();
                self.flows.remove(&handle);
                continue;
            }
            self.flows.insert(handle, flow);
        }
    }
}

fn tcp_socket() -> tcp::Socket<'static> {
    let rx = tcp::SocketBuffer::new(vec![0u8; TCP_BUF]);
    let tx = tcp::SocketBuffer::new(vec![0u8; TCP_BUF]);
    let mut socket = tcp::Socket::new(rx, tx);
    socket.set_nagle_enabled(false);
    socket
}

fn add_udp(sockets: &mut SocketSet<'static>, port: u16) -> SocketHandle {
    let rx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0u8; 8 * 1024]);
    let tx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0u8; 8 * 1024]);
    let mut socket = udp::Socket::new(rx, tx);
    socket.bind(IpListenEndpoint { addr: None, port }).unwrap();
    sockets.add(socket)
}

fn seed() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9e37_79b9_7f4a_7c15)
}

/// Parse a bare TCP SYN and return (src ip, src port, dst ip, dst port).
fn parse_tcp_syn(pkt: &[u8]) -> Option<(Ipv4Addr, u16, Ipv4Addr, u16)> {
    if pkt.len() < 40 || (pkt[0] >> 4) != 4 {
        return None;
    }
    if pkt[9] != 6 {
        return None;
    }
    let ihl = (pkt[0] & 0x0f) as usize * 4;
    if pkt.len() < ihl + 20 {
        return None;
    }
    let flags = pkt[ihl + 13];
    if flags & 0x02 == 0 || flags & 0x10 != 0 {
        return None; // SYN set, ACK clear
    }
    let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    let sport = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
    let dport = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
    Some((src, sport, dst, dport))
}

// ── upstream proxy client ───────────────────────────────────────────────────

async fn connect_upstream(proxy: &Proxy, target: &str) -> Result<tokio::net::TcpStream> {
    let stream = tokio::net::TcpStream::connect(proxy.endpoint())
        .await
        .with_context(|| format!("connect to proxy {}", proxy.endpoint()))?;
    match proxy.kind {
        ProxyKind::Socks5 => socks5_connect(stream, proxy, target).await,
        ProxyKind::Http => http_connect(stream, proxy, target).await,
    }
}

async fn socks5_connect(
    mut stream: tokio::net::TcpStream,
    proxy: &Proxy,
    target: &str,
) -> Result<tokio::net::TcpStream> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let methods: &[u8] = if proxy.user.is_some() { &[0x00, 0x02] } else { &[0x00] };
    stream.write_all(&[0x05, methods.len() as u8]).await?;
    stream.write_all(methods).await?;
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await?;
    if resp[0] != 0x05 || resp[1] == 0xff {
        bail!("proxy refused SOCKS5 methods");
    }
    if resp[1] == 0x02 {
        let user = proxy.user.as_deref().unwrap_or("");
        let pass = proxy.pass.as_deref().unwrap_or("");
        stream.write_all(&[0x01, user.len() as u8]).await?;
        stream.write_all(user.as_bytes()).await?;
        stream.write_all(&[pass.len() as u8]).await?;
        stream.write_all(pass.as_bytes()).await?;
        let mut auth = [0u8; 2];
        stream.read_exact(&mut auth).await?;
        if auth[1] != 0x00 {
            bail!("SOCKS5 authentication failed");
        }
    }
    let (host, port) = split_target(target)?;
    let mut req = vec![0x05, 0x01, 0x00];
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        req.push(0x01);
        req.extend_from_slice(&ip.octets());
    } else {
        req.push(0x03);
        req.push(host.len() as u8);
        req.extend_from_slice(host.as_bytes());
    }
    req.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&req).await?;
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[1] != 0x00 {
        bail!("SOCKS5 connect to {target} failed: code {}", head[1]);
    }
    // Drain the bound address.
    match head[3] {
        0x01 => {
            let mut b = [0u8; 6];
            stream.read_exact(&mut b).await?;
        }
        0x04 => {
            let mut b = [0u8; 18];
            stream.read_exact(&mut b).await?;
        }
        0x03 => {
            let mut l = [0u8; 1];
            stream.read_exact(&mut l).await?;
            let mut b = vec![0u8; l[0] as usize + 2];
            stream.read_exact(&mut b).await?;
        }
        _ => bail!("bad SOCKS5 address type"),
    }
    Ok(stream)
}

async fn http_connect(
    mut stream: tokio::net::TcpStream,
    proxy: &Proxy,
    target: &str,
) -> Result<tokio::net::TcpStream> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
    if let (Some(u), Some(p)) = (&proxy.user, &proxy.pass) {
        let creds = base64(format!("{u}:{p}").as_bytes());
        req.push_str(&format!("Proxy-Authorization: Basic {creds}\r\n"));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).await?;
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            bail!("proxy closed during CONNECT");
        }
        buf.push(byte[0]);
        if buf.len() > 8192 {
            bail!("proxy CONNECT response too large");
        }
    }
    let text = String::from_utf8_lossy(&buf);
    let status = text.split_whitespace().nth(1).and_then(|s| s.parse::<u16>().ok());
    if status != Some(200) {
        bail!("proxy CONNECT to {target} failed: {}", text.lines().next().unwrap_or(""));
    }
    Ok(stream)
}

fn split_target(target: &str) -> Result<(String, u16)> {
    let (host, port) = target
        .rsplit_once(':')
        .with_context(|| format!("target {target:?} has no port"))?;
    Ok((host.to_string(), port.parse().context("target port")?))
}

fn base64(data: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 { T[((n >> 6) & 63) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { T[(n & 63) as usize] as char } else { '=' });
    }
    out
}

// ── process orchestration ───────────────────────────────────────────────────

fn run(args: Args) -> Result<i32> {
    let (parent, child) = socketpair()?;
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        bail!("fork: {}", std::io::Error::last_os_error());
    }
    if pid == 0 {
        // Child: new namespace, TUN, then the program.
        unsafe { libc::close(parent) };
        let result = child_setup(child, &args);
        // child_setup only returns on error; it execs on success.
        if let Err(e) = result {
            eprintln!("pod-netns: {e:#}");
            unsafe { libc::_exit(EXIT_NO_BACKEND) };
        }
        unsafe { libc::_exit(0) };
    }
    unsafe { libc::close(child) };

    // Parent: the child reports whether it made a user namespace; if so, write
    // its id maps before it continues, then take the TUN fd.
    let mut kind = [0u8; 1];
    if read_exact_fd(parent, &mut kind)? == 0 {
        bail!("child died before reporting its namespace");
    }
    if kind[0] == b'u' {
        write_id_maps(pid as u32).context("write uid/gid maps")?;
        write_all_fd(parent, b"a")?;
    }
    let tun_fd = recv_fd(parent).context("receive TUN fd")?;
    unsafe { libc::close(parent) };

    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let proxies = args.proxies.clone();
    let verbose = args.verbose;
    let result = runtime.block_on(async move {
        let mut backend = Backend::new(tun_fd, proxies, verbose)?;
        let fd = backend.device.fd;
        let async_fd = tokio::io::unix::AsyncFd::with_interest(
            unsafe { OwnedFd::from_raw_fd(libc::dup(fd)) },
            tokio::io::Interest::READABLE,
        )?;
        loop {
            backend.device.read_ready();
            backend.tick().await?;
            // Wake on TUN input or a short timer, whichever comes first.
            let _ = tokio::time::timeout(Duration::from_millis(20), async_fd.readable()).await;
            let mut status = 0;
            let r = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
            if r == pid {
                return Ok::<i32, anyhow::Error>(if libc::WIFEXITED(status) {
                    libc::WEXITSTATUS(status)
                } else {
                    128 + libc::WTERMSIG(status)
                });
            }
        }
    });
    // Reap if the loop exited without seeing it.
    let mut status = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    result
}

fn child_setup(sock: RawFd, args: &Args) -> Result<()> {
    // A network namespace alone needs CAP_SYS_ADMIN; the user-namespace pair
    // works unprivileged and the parent writes the maps.
    let userns = if unsafe { libc::unshare(libc::CLONE_NEWNET) } == 0 {
        false
    } else {
        let e = std::io::Error::last_os_error();
        if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) } != 0 {
            bail!(
                "unshare(CLONE_NEWNET) failed ({e}) and unshare(CLONE_NEWUSER|CLONE_NEWNET) failed ({})",
                std::io::Error::last_os_error()
            );
        }
        true
    };
    // Tell the parent, and wait for the id maps before using the namespace.
    write_all_fd(sock, if userns { b"u" } else { b"n" })?;
    if userns {
        let mut ack = [0u8; 1];
        if read_exact_fd(sock, &mut ack)? == 0 {
            bail!("parent died before writing the id maps");
        }
    }
    bringup_loopback()?;
    let tun = create_tun("eth0")?;
    send_fd(sock, tun.as_raw_fd())?;
    unsafe { libc::close(sock) };
    std::mem::forget(tun); // the parent owns its own handle; keep ours open too

    let program = &args.program;
    let path = CString::new(program[0].as_bytes())?;
    let mut argv: Vec<CString> = Vec::with_capacity(program.len() + 1);
    for a in program {
        argv.push(CString::new(a.as_bytes())?);
    }
    let ptrs: Vec<*const libc::c_char> = argv.iter().map(|c| c.as_ptr()).chain(std::iter::once(std::ptr::null())).collect();
    unsafe {
        libc::execvp(path.as_ptr(), ptrs.as_ptr());
    }
    bail!("execvp {}: {}", program[0], std::io::Error::last_os_error())
}

fn write_all_fd(fd: RawFd, mut buf: &[u8]) -> Result<()> {
    while !buf.is_empty() {
        let n = unsafe { libc::write(fd, buf.as_ptr() as *const _, buf.len()) };
        if n <= 0 {
            bail!("write: {}", std::io::Error::last_os_error());
        }
        buf = &buf[n as usize..];
    }
    Ok(())
}

fn read_exact_fd(fd: RawFd, buf: &mut [u8]) -> Result<usize> {
    let mut off = 0;
    while off < buf.len() {
        let n = unsafe { libc::read(fd, buf[off..].as_mut_ptr() as *mut _, buf.len() - off) };
        if n < 0 {
            bail!("read: {}", std::io::Error::last_os_error());
        }
        if n == 0 {
            return Ok(off);
        }
        off += n as usize;
    }
    Ok(off)
}

fn socketpair() -> Result<(RawFd, RawFd)> {
    let mut fds = [0 as RawFd; 2];
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0, fds.as_mut_ptr()) } != 0 {
        bail!("socketpair: {}", std::io::Error::last_os_error());
    }
    Ok((fds[0], fds[1]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_proxy_specs() {
        let p = Proxy::parse("socks5://user:pass@127.0.0.1:1080").unwrap();
        assert_eq!(p.kind, ProxyKind::Socks5);
        assert_eq!(p.host, "127.0.0.1");
        assert_eq!(p.port, 1080);
        assert_eq!(p.user.as_deref(), Some("user"));
        assert_eq!(p.pass.as_deref(), Some("pass"));

        let p = Proxy::parse("http://proxy.example:8080").unwrap();
        assert_eq!(p.kind, ProxyKind::Http);
        assert_eq!(p.endpoint(), "proxy.example:8080");

        assert!(Proxy::parse("ftp://x:1").is_err());
        assert!(Proxy::parse("socks5://nohostport").is_err());
    }

    #[test]
    fn fake_dns_is_stable_and_reversible() {
        let mut dns = FakeDns::new();
        let a = dns.address_for("example.com");
        let b = dns.address_for("example.com");
        assert_eq!(a, b, "the same name must map to the same fake ip");
        assert_eq!(dns.name_for(a), Some("example.com"));
        let other = dns.address_for("example.org");
        assert_ne!(a, other);
        assert!(a.octets()[0] == 198 && a.octets()[1] == 18);
    }

    #[test]
    fn base64_matches_known_vectors() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64(b"user:pass"), "dXNlcjpwYXNz");
    }

    #[test]
    fn split_target_keeps_ipv4_and_names() {
        assert_eq!(split_target("example.com:443").unwrap(), ("example.com".into(), 443));
        assert_eq!(split_target("1.2.3.4:80").unwrap(), ("1.2.3.4".into(), 80));
        assert!(split_target("noport").is_err());
    }

    #[test]
    fn parses_a_tcp_syn() {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45; // IPv4, IHL 5
        pkt[9] = 6; // TCP
        pkt[12..16].copy_from_slice(&[10, 0, 0, 2]);
        pkt[16..20].copy_from_slice(&[93, 184, 216, 34]);
        pkt[20..22].copy_from_slice(&40000u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&443u16.to_be_bytes());
        pkt[33] = 0x02; // SYN
        assert_eq!(
            parse_tcp_syn(&pkt),
            Some((Ipv4Addr::new(10, 0, 0, 2), 40000, Ipv4Addr::new(93, 184, 216, 34), 443))
        );

        // An ACK is not a SYN.
        pkt[33] = 0x10;
        assert_eq!(parse_tcp_syn(&pkt), None);
        // UDP is not TCP.
        pkt[9] = 17;
        pkt[33] = 0x02;
        assert_eq!(parse_tcp_syn(&pkt), None);
        // Too short.
        assert_eq!(parse_tcp_syn(&pkt[..20]), None);
    }
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let args = match parse_args(&argv) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("pod-netns: {e:#}");
            std::process::exit(2);
        }
    };
    if args.doctor {
        std::process::exit(doctor());
    }
    match run(args) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("pod-netns: {e:#}");
            std::process::exit(EXIT_NO_BACKEND);
        }
    }
}
