//! Measure what the host actually permits.
//!
//! The design in `VIRTUAL-NETWORK.md` rests on a measured claim: `AF_INET`
//! bind/connect is denied, `AF_UNIX` (including the abstract namespace) is
//! allowed, namespaces are unprivileged-denied, and `LD_PRELOAD` works. This
//! module re-runs those probes on the running host and prints the results, so
//! a session never infers a capability from a package list or a mount option.
//!
//! Every result is an errno or a real value, not a guess.

/// The outcome of one probe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProbeResult {
    /// The operation worked; the string is what was observed.
    Ok(String),
    /// The operation was refused; the string is the errno.
    Fail(String),
    /// The probe does not apply on this platform.
    Unsupported,
}

impl ProbeResult {
    pub fn is_ok(&self) -> bool {
        matches!(self, Self::Ok(_))
    }

    pub fn render(&self) -> String {
        match self {
            Self::Ok(value) => format!("OK   {value}"),
            Self::Fail(value) => format!("FAIL {value}"),
            Self::Unsupported => "n/a  unsupported on this platform".to_string(),
        }
    }
}

/// One named probe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Probe {
    pub name: &'static str,
    pub result: ProbeResult,
}

/// Run every probe, in the document's order.
pub fn run() -> Vec<Probe> {
    #[cfg(target_os = "linux")]
    {
        linux::run()
    }
    #[cfg(not(target_os = "linux"))]
    {
        vec![Probe {
            name: "abstract namespace and LD_PRELOAD",
            result: ProbeResult::Unsupported,
        }]
    }
}

/// Render probes as the document's table.
pub fn render(probes: &[Probe]) -> String {
    let mut out = String::new();
    let width = probes.iter().map(|p| p.name.len()).max().unwrap_or(0);
    for probe in probes {
        out.push_str(&format!("{:<width$}  {}\n", probe.name, probe.result.render()));
    }
    out
}

/// True when the core requirements hold: no `AF_INET` bind, `AF_UNIX` binds
/// work, and a C compiler can build the shim.
pub fn ready(probes: &[Probe]) -> bool {
    let lookup = |name: &str| probes.iter().find(|probe| probe.name == name).map(|p| &p.result);
    let inet_denied = lookup("bind(AF_INET, 127.0.0.1:0)")
        .map(|result| !result.is_ok())
        .unwrap_or(false);
    let unix_ok = lookup("bind(AF_UNIX, path)").map(ProbeResult::is_ok).unwrap_or(false);
    let compiler = lookup("cc -shared -fPIC").map(ProbeResult::is_ok).unwrap_or(false);
    inet_denied && unix_ok && compiler
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{Probe, ProbeResult};
    use std::mem::size_of;
    use std::os::unix::ffi::OsStrExt;

    const AF_VSOCK: i32 = 40;
    const AF_NETLINK: i32 = 16;

    fn errno(result: i32) -> ProbeResult {
        if result == 0 {
            ProbeResult::Ok("allowed".into())
        } else {
            ProbeResult::Fail(
                std::io::Error::last_os_error()
                    .raw_os_error()
                    .map(errno_name)
                    .unwrap_or_else(|| std::io::Error::last_os_error().to_string()),
            )
        }
    }

    fn errno_name(code: i32) -> String {
        match code {
            libc::EPERM => "EPERM".into(),
            libc::EACCES => "EACCES".into(),
            libc::EAFNOSUPPORT => "EAFNOSUPPORT".into(),
            libc::EADDRINUSE => "EADDRINUSE".into(),
            libc::EINVAL => "EINVAL".into(),
            libc::EOPNOTSUPP => "EOPNOTSUPP".into(),
            other => format!("errno {other}"),
        }
    }

    fn unshare_probe(name: &'static str, flag: i32) -> Probe {
        // Run in a forked child. A successful `unshare` would otherwise change
        // this process for every later probe, so the table would measure the
        // new namespace instead of the host.
        //
        // SAFETY: pipe/fork/read/write/waitpid with valid buffers. The child
        // calls only async-signal-safe functions and never returns through
        // Rust, so sharing the address space with threads is safe.
        unsafe {
            let mut fds = [0i32; 2];
            if libc::pipe(fds.as_mut_ptr()) != 0 {
                return Probe { name, result: ProbeResult::Fail("pipe failed".into()) };
            }
            let pid = libc::fork();
            if pid < 0 {
                libc::close(fds[0]);
                libc::close(fds[1]);
                return Probe { name, result: ProbeResult::Fail("fork failed".into()) };
            }
            if pid == 0 {
                libc::close(fds[0]);
                let rc = libc::unshare(flag);
                let code = if rc == 0 {
                    0i32
                } else {
                    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
                };
                let bytes = code.to_ne_bytes();
                let _ = libc::write(fds[1], bytes.as_ptr() as *const libc::c_void, bytes.len());
                libc::_exit(0);
            }
            libc::close(fds[1]);
            let mut bytes = [0u8; 4];
            let got = libc::read(fds[0], bytes.as_mut_ptr() as *mut libc::c_void, bytes.len());
            libc::close(fds[0]);
            let mut status = 0i32;
            libc::waitpid(pid, &mut status, 0);
            if got == 4 {
                let code = i32::from_ne_bytes(bytes);
                if code == 0 {
                    Probe { name, result: ProbeResult::Ok("allowed".into()) }
                } else {
                    Probe { name, result: ProbeResult::Fail(errno_name(code)) }
                }
            } else {
                Probe { name, result: ProbeResult::Fail("probe child produced no result".into()) }
            }
        }
    }

    fn bind_v4(host: [u8; 4]) -> ProbeResult {
        // SAFETY: a fresh socket and a fully initialised sockaddr_in.
        unsafe {
            let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
            if fd < 0 {
                return errno(-1);
            }
            let mut addr: libc::sockaddr_in = std::mem::zeroed();
            addr.sin_family = libc::AF_INET as libc::sa_family_t;
            addr.sin_port = 0;
            addr.sin_addr.s_addr = u32::from_be_bytes(host).to_be();
            let rc = libc::bind(
                fd,
                &addr as *const libc::sockaddr_in as *const libc::sockaddr,
                size_of::<libc::sockaddr_in>() as libc::socklen_t,
            );
            let result = errno(rc);
            libc::close(fd);
            result
        }
    }

    fn bind_v6_loopback() -> ProbeResult {
        // SAFETY: a fresh socket and a fully initialised sockaddr_in6.
        unsafe {
            let fd = libc::socket(libc::AF_INET6, libc::SOCK_STREAM, 0);
            if fd < 0 {
                return errno(-1);
            }
            let mut addr: libc::sockaddr_in6 = std::mem::zeroed();
            addr.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            addr.sin6_port = 0;
            addr.sin6_addr.s6_addr[15] = 1; // ::1
            let rc = libc::bind(
                fd,
                &addr as *const libc::sockaddr_in6 as *const libc::sockaddr,
                size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            );
            let result = errno(rc);
            libc::close(fd);
            result
        }
    }

    fn bind_unix_path(path: &std::path::Path) -> ProbeResult {
        // SAFETY: a fresh socket and a sun_path built from a bounded path.
        unsafe {
            let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
            if fd < 0 {
                return errno(-1);
            }
            let mut addr: libc::sockaddr_un = std::mem::zeroed();
            addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
            let bytes = path.as_os_str().as_bytes();
            let take = bytes.len().min(addr.sun_path.len() - 1);
            for (index, byte) in bytes[..take].iter().enumerate() {
                addr.sun_path[index] = *byte as libc::c_char;
            }
            let rc = libc::bind(
                fd,
                &addr as *const libc::sockaddr_un as *const libc::sockaddr,
                (size_of::<libc::sa_family_t>() + take + 1) as libc::socklen_t,
            );
            let result = errno(rc);
            libc::close(fd);
            result
        }
    }

    fn bind_unix_abstract(name: &[u8]) -> ProbeResult {
        // SAFETY: a fresh socket and an abstract sun_path (leading NUL).
        unsafe {
            let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
            if fd < 0 {
                return errno(-1);
            }
            let mut addr: libc::sockaddr_un = std::mem::zeroed();
            addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
            let take = name.len().min(addr.sun_path.len() - 1);
            for (index, byte) in name[..take].iter().enumerate() {
                addr.sun_path[index + 1] = *byte as libc::c_char;
            }
            let rc = libc::bind(
                fd,
                &addr as *const libc::sockaddr_un as *const libc::sockaddr,
                (size_of::<libc::sa_family_t>() + 1 + take) as libc::socklen_t,
            );
            let result = errno(rc);
            libc::close(fd);
            result
        }
    }

    fn bind_vsock() -> ProbeResult {
        // SAFETY: a fresh AF_VSOCK socket and a fully initialised sockaddr_vm
        // with CID_ANY/PORT_ANY, exactly the document's probe.
        unsafe {
            let fd = libc::socket(AF_VSOCK, libc::SOCK_STREAM, 0);
            if fd < 0 {
                return errno(-1);
            }
            let mut addr: libc::sockaddr_vm = std::mem::zeroed();
            addr.svm_family = AF_VSOCK as libc::sa_family_t;
            addr.svm_port = libc::VMADDR_PORT_ANY;
            addr.svm_cid = libc::VMADDR_CID_ANY;
            let rc = libc::bind(
                fd,
                &addr as *const libc::sockaddr_vm as *const libc::sockaddr,
                size_of::<libc::sockaddr_vm>() as libc::socklen_t,
            );
            let result = errno(rc);
            libc::close(fd);
            result
        }
    }

    fn bind_netlink() -> ProbeResult {
        // SAFETY: a fresh AF_NETLINK socket and a zeroed sockaddr_nl, which
        // asks the kernel to assign the port id.
        unsafe {
            let fd = libc::socket(AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE);
            if fd < 0 {
                return errno(-1);
            }
            let mut addr: libc::sockaddr_nl = std::mem::zeroed();
            addr.nl_family = AF_NETLINK as libc::sa_family_t;
            let rc = libc::bind(
                fd,
                &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            );
            let result = errno(rc);
            libc::close(fd);
            result
        }
    }

    fn option(name: &'static str, present: bool) -> Probe {
        Probe {
            name,
            result: if present {
                ProbeResult::Ok("present".into())
            } else {
                ProbeResult::Fail("absent".into())
            },
        }
    }

    fn compiler_probe() -> Probe {
        let program = std::env::var("CC").unwrap_or_else(|_| "cc".to_string());
        let found = crate::vnet::shim::which(&program);
        let result = match found {
            Some(path) => {
                // Compile a trivial shared object to prove the whole path works.
                let dir = std::env::temp_dir().join(format!("cfrsnet-probe-{}", std::process::id()));
                let source = dir.join("probe.c");
                let output = dir.join("probe.so");
                if std::fs::create_dir_all(&dir).is_err() {
                    return Probe { name: "cc -shared -fPIC", result: ProbeResult::Fail("cannot create a scratch dir".into()) };
                }
                if std::fs::write(&source, "int cfrsnet_probe(void){return 0;}\n").is_err() {
                    return Probe { name: "cc -shared -fPIC", result: ProbeResult::Fail("cannot write probe.c".into()) };
                }
                let status = std::process::Command::new(&path)
                    .arg("-shared")
                    .arg("-fPIC")
                    .arg("-o")
                    .arg(&output)
                    .arg(&source)
                    .status();
                let _ = std::fs::remove_dir_all(&dir);
                match status {
                    Ok(status) if status.success() => ProbeResult::Ok(format!(
                        "{} ({})",
                        program,
                        path.display()
                    )),
                    Ok(status) => ProbeResult::Fail(format!("{program} exited {status}")),
                    Err(err) => ProbeResult::Fail(format!("{program}: {err}")),
                }
            }
            None => ProbeResult::Fail(format!("{program} not found")),
        };
        Probe { name: "cc -shared -fPIC", result }
    }

    fn status_field(field: &str) -> Option<String> {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix(field) {
                return Some(rest.trim_start_matches(':').trim().to_string());
            }
        }
        None
    }

    pub fn run() -> Vec<Probe> {
        let mut probes = vec![
            unshare_probe("unshare(CLONE_NEWUSER)", libc::CLONE_NEWUSER),
            unshare_probe("unshare(CLONE_NEWNET)", libc::CLONE_NEWNET),
            unshare_probe("unshare(CLONE_NEWNS)", libc::CLONE_NEWNS),
            Probe { name: "bind(AF_INET, 127.0.0.1:0)", result: bind_v4([127, 0, 0, 1]) },
            Probe { name: "bind(AF_INET, 127.0.0.2:0)", result: bind_v4([127, 0, 0, 2]) },
            Probe { name: "bind(AF_INET6, [::1]:0)", result: bind_v6_loopback() },
            Probe { name: "bind(AF_VSOCK, CID_ANY:0)", result: bind_vsock() },
            Probe { name: "bind(AF_NETLINK, ...)", result: bind_netlink() },
        ];
        let path = std::env::temp_dir().join(format!("cfrsnet-probe-{}.sock", std::process::id()));
        let path_result = bind_unix_path(&path);
        let _ = std::fs::remove_file(&path);
        probes.push(Probe { name: "bind(AF_UNIX, path)", result: path_result });
        probes.push(Probe {
            name: "bind(AF_UNIX, \\0abstract)",
            result: bind_unix_abstract(format!("cfrsnet-probe-{}", std::process::id()).as_bytes()),
        });
        probes.push(option("/dev/net/tun", std::path::Path::new("/dev/net/tun").exists()));
        probes.push(option("/dev/vsock", std::path::Path::new("/dev/vsock").exists()));
        probes.push(compiler_probe());
        probes.push(Probe {
            name: "Seccomp",
            result: match status_field("Seccomp") {
                Some(value) => ProbeResult::Ok(value),
                None => ProbeResult::Unsupported,
            },
        });
        probes.push(Probe {
            name: "NoNewPrivs",
            result: match status_field("NoNewPrivs") {
                Some(value) => ProbeResult::Ok(value),
                None => ProbeResult::Unsupported,
            },
        });
        probes.push(Probe {
            name: "CapEff",
            result: match status_field("CapEff") {
                Some(value) => ProbeResult::Ok(value),
                None => ProbeResult::Unsupported,
            },
        });
        probes.push(Probe {
            name: "arch",
            result: ProbeResult::Ok(std::env::consts::ARCH.to_string()),
        });
        probes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probes_run_and_render() {
        let probes = run();
        assert!(!probes.is_empty());
        let rendered = render(&probes);
        assert!(rendered.contains("bind(AF_UNIX, path)"));
        assert!(!ready(&[]), "an empty probe set is not ready");
    }

    #[test]
    fn ready_requires_the_core_conditions() {
        let probes = vec![
            Probe { name: "bind(AF_INET, 127.0.0.1:0)", result: ProbeResult::Fail("EACCES".into()) },
            Probe { name: "bind(AF_UNIX, path)", result: ProbeResult::Ok("allowed".into()) },
            Probe { name: "cc -shared -fPIC", result: ProbeResult::Ok("cc".into()) },
        ];
        assert!(ready(&probes));
        let mut not_ready = probes.clone();
        not_ready[0].result = ProbeResult::Ok("allowed".into());
        assert!(!ready(&not_ready));
    }
}
