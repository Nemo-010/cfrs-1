//! The userspace IP stack.
//!
//! A [`NetStack`] owns a private IPv4/IPv6 address space and implements the
//! TCP and UDP state machines for it. Its link layer is an in-process packet
//! queue ([`crate::vnet::device::LinkDevice`]), so the stack never issues a
//! kernel `AF_INET` call. Two modes:
//!
//! * **loopback** — the link's transmit path feeds its own receive path, so a
//!   process can open a listener and a client against itself. This is the
//!   document's §9.1 proof and the basis of deterministic tests.
//! * **over a link** — an external pump moves framed packets between
//!   [`NetStack::link_in`] / [`NetStack::link_out`] and a real byte stream: a
//!   unix socket, a QUIC connection, or a `cfrs` WebSocket forward.
//!
//! The clock is monotonic and real (`std::time::Instant`), and the reactor
//! blocks on the device's waker or the interface's next deadline instead of
//! spinning, which is what §11 asked for.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use futures::task::AtomicWaker;
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, oneshot, Notify};

use crate::vnet::addr::{VirtAddr, VirtualSubnet};
use crate::vnet::device::{DeviceStats, DeviceStatsSnapshot, LinkDevice, PacketQueue};
use crate::vnet::dns::Resolver;
use crate::vnet::policy::Acl;

/// A monotonic millisecond clock for smoltcp.
#[derive(Clone, Debug)]
pub struct Clock {
    start: std::time::Instant,
    base_ms: i64,
}

impl Default for Clock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock {
    pub fn new() -> Self {
        Self { start: std::time::Instant::now(), base_ms: 0 }
    }

    /// A clock whose first reading is `base_ms`, for deterministic tests.
    pub fn starting_at(base_ms: i64) -> Self {
        Self { start: std::time::Instant::now(), base_ms }
    }

    pub fn now_ms(&self) -> i64 {
        self.base_ms + self.start.elapsed().as_millis() as i64
    }

    pub fn now(&self) -> SmolInstant {
        SmolInstant::from_millis(self.now_ms())
    }
}

/// Stack configuration.
#[derive(Clone)]
pub struct StackConfig {
    pub subnet: VirtualSubnet,
    /// The address this stack owns (and answers for) in the v4 space.
    pub local_v4: Ipv4Addr,
    /// The address this stack owns in the v6 space.
    pub local_v6: Ipv6Addr,
    pub mtu: usize,
    pub tcp_buffer: usize,
    pub udp_packets: usize,
    pub udp_payload: usize,
    /// Listeners keep at most this many listening sockets, which bounds
    /// simultaneous half-open inbound connections.
    pub accept_pool: usize,
    pub max_connections: usize,
    /// Connect-time access policy.
    pub acl: Option<Arc<Acl>>,
    /// A resolver served at the gateway's port 53. When set, the stack owns the
    /// gateway address and answers A/AAAA queries for the names in the table.
    pub dns: Option<Arc<Resolver>>,
    /// Seed for smoltcp's port/sequence randomisation.
    pub random_seed: u64,
    /// Upper bound on the reactor's sleep between polls.
    pub max_poll_interval: Duration,
}

impl Default for StackConfig {
    fn default() -> Self {
        Self {
            subnet: VirtualSubnet::default(),
            local_v4: Ipv4Addr::new(10, 66, 0, 2),
            local_v6: "fd00:66::2".parse().unwrap(),
            mtu: 1280,
            tcp_buffer: 64 * 1024,
            udp_packets: 64,
            udp_payload: 64 * 1024,
            accept_pool: 8,
            max_connections: 4096,
            acl: None,
            dns: None,
            random_seed: seed_from_time(),
            max_poll_interval: Duration::from_millis(100),
        }
    }
}

fn seed_from_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9e37_79b9_7f4a_7c15)
}

/// Something worth observing happened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StackEvent {
    ListenerBound { addr: VirtAddr },
    Accepted { id: u32, local: VirtAddr, remote: VirtAddr },
    Connected { id: u32, local: VirtAddr, remote: VirtAddr },
    Refused { remote: VirtAddr, reason: String },
    Closed { id: u32 },
    Datagram { from: VirtAddr, to: VirtAddr, len: usize },
}

/// Connection counters, readable while the reactor runs.
#[derive(Debug, Default)]
pub struct NetStats {
    pub accepted: AtomicU64,
    pub connected: AtomicU64,
    pub refused: AtomicU64,
    pub closed: AtomicU64,
    pub datagrams: AtomicU64,
    /// Inbound connections the accept queue could not take. Counted separately
    /// from `accepted` because a drop is not an acceptance, and a counter that
    /// silently under-reports is worse than no counter: an operator watching
    /// `accepted` would see a number lower than the peer's connection count
    /// with nothing indicating anything was lost.
    pub dropped: AtomicU64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NetStatsSnapshot {
    pub accepted: u64,
    pub connected: u64,
    pub refused: u64,
    pub closed: u64,
    pub datagrams: u64,
    pub dropped: u64,
}

impl NetStats {
    fn snapshot(&self) -> NetStatsSnapshot {
        NetStatsSnapshot {
            accepted: self.accepted.load(Ordering::Relaxed),
            connected: self.connected.load(Ordering::Relaxed),
            refused: self.refused.load(Ordering::Relaxed),
            closed: self.closed.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            datagrams: self.datagrams.load(Ordering::Relaxed),
        }
    }
}

fn to_smoltcp(ip: IpAddr) -> IpAddress {
    match ip {
        IpAddr::V4(ip) => IpAddress::Ipv4(ip.into()),
        IpAddr::V6(ip) => IpAddress::Ipv6(ip.into()),
    }
}

fn from_smoltcp(ip: IpAddress) -> IpAddr {
    match ip {
        IpAddress::Ipv4(ip) => IpAddr::V4(ip.into()),
        IpAddress::Ipv6(ip) => IpAddr::V6(ip.into()),
    }
}

fn endpoint_to_virt(endpoint: IpEndpoint) -> VirtAddr {
    VirtAddr::new(from_smoltcp(endpoint.addr), endpoint.port)
}

// ── connection plumbing ─────────────────────────────────────────────────────

#[derive(Debug)]
enum AppEvent {
    Data(Vec<u8>),
    Eof,
    Reset(String),
}

#[derive(Debug)]
enum ConnCmd {
    Close,
    Abort,
    SetNodelay(bool),
}

/// A TCP connection in the virtual network. It implements
/// [`AsyncRead`]/[`AsyncWrite`], so it composes with the rest of the crate.
pub struct TcpStream {
    id: u32,
    local: VirtAddr,
    remote: VirtAddr,
    read_rx: mpsc::Receiver<AppEvent>,
    write_tx: mpsc::Sender<Vec<u8>>,
    write_waker: Arc<AtomicWaker>,
    ctl_tx: mpsc::Sender<ConnCmd>,
    kick: Arc<Notify>,
    read_buf: Vec<u8>,
    read_pos: usize,
    eof: bool,
    nodelay: bool,
}

impl std::fmt::Debug for TcpStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpStream")
            .field("id", &self.id)
            .field("local", &self.local)
            .field("remote", &self.remote)
            .field("eof", &self.eof)
            .finish()
    }
}

impl TcpStream {
    pub fn id(&self) -> u32 {
        self.id
    }

    pub fn local_addr(&self) -> VirtAddr {
        self.local
    }

    pub fn peer_addr(&self) -> VirtAddr {
        self.remote
    }

    /// Record `TCP_NODELAY`. The reactor applies it to the smoltcp socket,
    /// which is how the shim's swallowed `setsockopt` reaches the stack.
    pub fn set_nodelay(&mut self, enabled: bool) {
        self.nodelay = enabled;
        let _ = self.ctl_tx.try_send(ConnCmd::SetNodelay(enabled));
        self.kick.notify_one();
    }

    pub fn nodelay(&self) -> bool {
        self.nodelay
    }

    /// Half-close the write side.
    pub fn shutdown(&self) {
        let _ = self.ctl_tx.try_send(ConnCmd::Close);
        self.kick.notify_one();
    }

    /// Abort the connection (RST).
    pub fn abort(&self) {
        let _ = self.ctl_tx.try_send(ConnCmd::Abort);
        self.kick.notify_one();
    }

    fn drain_read_buffer(&mut self, buf: &mut [u8]) -> usize {
        let available = self.read_buf.len() - self.read_pos;
        let n = available.min(buf.len());
        buf[..n].copy_from_slice(&self.read_buf[self.read_pos..self.read_pos + n]);
        self.read_pos += n;
        if self.read_pos >= self.read_buf.len() {
            self.read_buf.clear();
            self.read_pos = 0;
        }
        n
    }
}

impl AsyncRead for TcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.read_pos < self.read_buf.len() {
            let want = buf.remaining();
            let mut temp = vec![0u8; want.min(self.read_buf.len() - self.read_pos)];
            let n = self.drain_read_buffer(&mut temp);
            buf.put_slice(&temp[..n]);
            return Poll::Ready(Ok(()));
        }
        if self.eof {
            return Poll::Ready(Ok(()));
        }
        match self.read_rx.poll_recv(cx) {
            Poll::Ready(Some(AppEvent::Data(data))) => {
                self.read_buf = data;
                self.read_pos = 0;
                let want = buf.remaining();
                let mut temp = vec![0u8; want.min(self.read_buf.len())];
                let n = self.drain_read_buffer(&mut temp);
                buf.put_slice(&temp[..n]);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(AppEvent::Eof)) => {
                self.eof = true;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(AppEvent::Reset(message))) => {
                Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionReset, message)))
            }
            Poll::Ready(None) => {
                self.eof = true;
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match self.write_tx.try_send(buf.to_vec()) {
            Ok(()) => {
                // The reactor may be parked waiting for link traffic; tell it
                // there is application data to move now, not on the next tick.
                self.kick.notify_one();
                Poll::Ready(Ok(buf.len()))
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                // The reactor drains the channel each time it services the
                // connection and wakes this waker; that is the write-side
                // backpressure path.
                self.write_waker.register(cx.waker());
                Poll::Pending
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "virtual TCP connection is closed",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let _ = self.ctl_tx.try_send(ConnCmd::Close);
        self.kick.notify_one();
        Poll::Ready(Ok(()))
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        // A dropped stream must release its virtual socket, but it must not do
        // so by closing the connection while data is still in flight.
        //
        // The problem this solves: without any Drop impl, dropping the handle
        // drops `ctl_tx` and the reactor never learns about it. It watches
        // `to_app.is_closed()` to notice that the application has gone, but
        // `to_app` runs the other way and stays open. The socket then sits in
        // CloseWait until the peer closes, which for two handles dropped by the
        // same task never happens, and each such connection keeps its smoltcp
        // socket resident for the life of the process.
        //
        // Why not an unconditional graceful close: a program that writes, then
        // reads to EOF, then drops, has its own `Drop` fire before the peer's
        // reply arrives, and a graceful close cuts the exchange short. That was
        // observed as two tests reading an empty response.
        //
        // Why not an unconditional abort: an abort discards queued data, so a
        // program that wrote and then dropped without reading loses the reply it
        // had not collected.
        //
        // So the close is deferred to the reactor, which knows whether bytes
        // were still owed in either direction, and reaped the socket either way.
        // The handle only asks; the reactor decides.
        let _ = self.ctl_tx.try_send(ConnCmd::Close);
        self.kick.notify_one();
    }
}

/// A UDP socket in the virtual network.
pub struct UdpSocket {
    id: u32,
    local: VirtAddr,
    recv_rx: mpsc::Receiver<(Vec<u8>, VirtAddr)>,
    send_tx: mpsc::Sender<(Vec<u8>, VirtAddr)>,
    kick: Arc<Notify>,
}

impl std::fmt::Debug for UdpSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpSocket").field("id", &self.id).field("local", &self.local).finish()
    }
}

impl UdpSocket {
    pub fn id(&self) -> u32 {
        self.id
    }

    pub fn local_addr(&self) -> VirtAddr {
        self.local
    }

    pub async fn send_to(&self, buf: &[u8], remote: VirtAddr) -> io::Result<usize> {
        self.send_tx
            .send((buf.to_vec(), remote))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "virtual UDP socket is closed"))?;
        self.kick.notify_one();
        Ok(buf.len())
    }

    pub async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, VirtAddr)> {
        match self.recv_rx.recv().await {
            Some((data, from)) => {
                let n = data.len().min(buf.len());
                buf[..n].copy_from_slice(&data[..n]);
                Ok((n, from))
            }
            None => Err(io::Error::new(io::ErrorKind::BrokenPipe, "virtual UDP socket is closed")),
        }
    }
}

/// An accepted-connection queue for one virtual listener.
pub struct TcpListener {
    local: VirtAddr,
    rx: mpsc::Receiver<TcpStream>,
}

impl std::fmt::Debug for TcpListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpListener").field("local", &self.local).finish()
    }
}

impl TcpListener {
    pub fn local_addr(&self) -> VirtAddr {
        self.local
    }

    pub async fn accept(&mut self) -> io::Result<TcpStream> {
        self.rx
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "virtual listener is closed"))
    }
}

// ── the reactor core ────────────────────────────────────────────────────────

struct Conn {
    handle: SocketHandle,
    to_app: mpsc::Sender<AppEvent>,
    from_app: mpsc::Receiver<Vec<u8>>,
    write_waker: Arc<AtomicWaker>,
    ctl: mpsc::Receiver<ConnCmd>,
    closing: bool,
    recv_eof_sent: bool,
}

struct UdpConn {
    handle: SocketHandle,
    local: VirtAddr,
    to_app: mpsc::Sender<(Vec<u8>, VirtAddr)>,
    from_app: mpsc::Receiver<(Vec<u8>, VirtAddr)>,
}

/// The virtual resolver served at the gateway.
struct DnsService {
    handle: SocketHandle,
    resolver: Arc<Resolver>,
}

struct Listener {
    addr: VirtAddr,
    handles: Vec<SocketHandle>,
    accept_tx: mpsc::Sender<TcpStream>,
}

enum Command {
    Listen {
        addr: VirtAddr,
        reply: oneshot::Sender<io::Result<TcpListener>>,
    },
    Connect {
        remote: VirtAddr,
        local_port: u16,
        reply: oneshot::Sender<io::Result<TcpStream>>,
    },
    BindUdp {
        addr: VirtAddr,
        reply: oneshot::Sender<io::Result<UdpSocket>>,
    },
    Shutdown,
}

/// Live and high-water socket counts for one stack.
///
/// `live` is the number of sockets the reactor currently holds, `peak` the
/// largest it has ever been. A `peak` that rises with every connection while
/// `live` returns to its starting value is the signature of a set that is not
/// being pruned.
#[derive(Debug, Default)]
pub struct SocketCount {
    live: AtomicU64,
    peak: AtomicU64,
}

impl SocketCount {
    fn add(&self) {
        let now = self.live.fetch_add(1, Ordering::Relaxed) + 1;
        self.peak.fetch_max(now, Ordering::Relaxed);
    }

    fn remove(&self) {
        // Saturating: a double remove would otherwise wrap the live count to
        // u64::MAX and make every later observation meaningless.
        let mut current = self.live.load(Ordering::Relaxed);
        loop {
            if current == 0 {
                return;
            }
            match self.live.compare_exchange_weak(
                current,
                current - 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(actual) => current = actual,
            }
        }
    }

    /// Sockets the reactor holds right now.
    pub fn live(&self) -> u64 {
        self.live.load(Ordering::Relaxed)
    }

    /// The largest number of sockets ever held at once.
    pub fn peak(&self) -> u64 {
        self.peak.load(Ordering::Relaxed)
    }
}

struct Core {
    iface: Interface,
    device: LinkDevice,
    sockets: SocketSet<'static>,
    /// Live and high-water socket counts, shared with the handle.
    ///
    /// A `SocketSet` only grows: `add` reuses a vacant slot but nothing reclaims
    /// one on its own, so a set that is not pruned on close grows without bound.
    /// The set itself lives inside the reactor task, so the count is what makes
    /// that observable from outside, and a test can assert on it instead of
    /// inferring a leak from a connection failing later.
    socket_count: Arc<SocketCount>,
    clock: Clock,
    config: StackConfig,
    listeners: Vec<Listener>,
    conns: HashMap<u32, Conn>,
    udp: HashMap<u32, UdpConn>,
    next_id: u32,
    events: mpsc::UnboundedSender<StackEvent>,
    stats: Arc<NetStats>,
    kick: Arc<Notify>,
    dns: Option<DnsService>,
}

fn new_tcp_socket(config: &StackConfig) -> tcp::Socket<'static> {
    let size = config.tcp_buffer;
    tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0u8; size]),
        tcp::SocketBuffer::new(vec![0u8; size]),
    )
}

fn new_udp_socket(config: &StackConfig) -> udp::Socket<'static> {
    udp::Socket::new(
        udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; config.udp_packets],
            vec![0u8; config.udp_payload],
        ),
        udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; config.udp_packets],
            vec![0u8; config.udp_payload],
        ),
    )
}

impl Core {
    fn new(
        config: StackConfig,
        mut device: LinkDevice,
        events: mpsc::UnboundedSender<StackEvent>,
        kick: Arc<Notify>,
        socket_count: Arc<SocketCount>,
    ) -> Self {
        let mut iface_config = IfaceConfig::new(HardwareAddress::Ip);
        iface_config.random_seed = config.random_seed;
        let mut iface = Interface::new(iface_config, &mut device, SmolInstant::ZERO);
        let gateway_v4 = config.subnet.gateway(crate::vnet::addr::Family::V4);
        let gateway_v6 = config.subnet.gateway(crate::vnet::addr::Family::V6);
        iface.update_ip_addrs(|addrs| {
            let prefix = config.subnet.v4_prefix;
            let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(config.local_v4.into()), prefix));
            let v6_prefix = config.subnet.v6_prefix;
            let _ = addrs.push(IpCidr::new(IpAddress::Ipv6(config.local_v6.into()), v6_prefix));
            // The stack also answers for the gateway, where the virtual
            // resolver lives, so a client can reach `10.66.0.1:53`.
            if let IpAddr::V4(gateway) = gateway_v4 {
                if gateway != config.local_v4 {
                    let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(gateway.into()), prefix));
                }
            }
            if let IpAddr::V6(gateway) = gateway_v6 {
                if gateway != config.local_v6 {
                    let _ = addrs.push(IpCidr::new(IpAddress::Ipv6(gateway.into()), v6_prefix));
                }
            }
        });
        let mut sockets: SocketSet<'static> = SocketSet::new(Vec::new());
        let dns = config.dns.clone().and_then(|resolver| {
            let handle = sockets.add(new_udp_socket(&config));
            let socket = sockets.get_mut::<udp::Socket>(handle);
            let listen = IpListenEndpoint { addr: Some(to_smoltcp(gateway_v4)), port: 53 };
            socket.bind(listen).ok()?;
            Some(DnsService { handle, resolver })
        });
        Self {
            iface,
            device,
            sockets,
            socket_count: socket_count.clone(),
            clock: Clock::starting_at(0),
            config,
            listeners: Vec::new(),
            conns: HashMap::new(),
            udp: HashMap::new(),
            next_id: 1,
            events,
            stats: Arc::new(NetStats::default()),
            kick,
            dns,
        }
    }

    fn poll_iface(&mut self) {
        let now = self.clock.now();
        let _ = self.iface.poll(now, &mut self.device, &mut self.sockets);
    }

    fn next_delay(&mut self) -> Option<Duration> {
        let now = self.clock.now();
        self.iface
            .poll_delay(now, &self.sockets)
            .map(|delay| Duration::from_millis(delay.total_millis()))
            .map(|delay| delay.min(self.config.max_poll_interval))
    }

    fn tcp_socket(&self) -> tcp::Socket<'static> {
        new_tcp_socket(&self.config)
    }

    fn udp_socket(&self) -> udp::Socket<'static> {
        new_udp_socket(&self.config)
    }

    fn emit(&self, event: StackEvent) {
        let _ = self.events.send(event);
    }

    fn acl_allows(&self, addr: &VirtAddr) -> bool {
        match &self.config.acl {
            Some(acl) => acl.allows(&addr.ip, addr.port),
            None => true,
        }
    }

    fn in_subnet(&self, addr: &VirtAddr) -> bool {
        self.config.subnet.contains(&addr.ip)
    }

    fn handle(&mut self, command: Command) {
        match command {
            Command::Listen { addr, reply } => {
                let _ = reply.send(self.listen(addr));
            }
            Command::Connect { remote, local_port, reply } => {
                let _ = reply.send(self.connect(remote, local_port));
            }
            Command::BindUdp { addr, reply } => {
                let _ = reply.send(self.bind_udp(addr));
            }
            Command::Shutdown => {}
        }
    }

    fn listen(&mut self, addr: VirtAddr) -> io::Result<TcpListener> {
        if !self.in_subnet(&addr) {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("{addr} is outside the virtual subnet"),
            ));
        }
        if !self.acl_allows(&addr) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("ACL denies binding {addr}"),
            ));
        }
        if self.listeners.iter().any(|listener| listener.addr == addr) {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                format!("{addr} is already bound"),
            ));
        }
        let (accept_tx, accept_rx) = mpsc::channel(self.config.accept_pool.max(1) * 4);
        let mut handles = Vec::with_capacity(self.config.accept_pool.max(1));
        for _ in 0..self.config.accept_pool.max(1) {
            handles.push(self.spawn_listener_socket(addr)?);
        }
        self.listeners.push(Listener { addr, handles, accept_tx });
        self.emit(StackEvent::ListenerBound { addr });
        Ok(TcpListener { local: addr, rx: accept_rx })
    }

    fn spawn_listener_socket(&mut self, addr: VirtAddr) -> io::Result<SocketHandle> {
        let handle = self.sockets.add(self.tcp_socket());
        self.socket_count.add();
        let socket = self.sockets.get_mut::<tcp::Socket>(handle);
        socket
            .listen(IpListenEndpoint {
                addr: Some(to_smoltcp(addr.ip)),
                port: addr.port,
            })
            .map_err(|err| io::Error::new(io::ErrorKind::AddrInUse, err.to_string()))?;
        Ok(handle)
    }

    fn connect(&mut self, remote: VirtAddr, local_port: u16) -> io::Result<TcpStream> {
        if !self.in_subnet(&remote) {
            self.stats.refused.fetch_add(1, Ordering::Relaxed);
            self.emit(StackEvent::Refused {
                remote,
                reason: "outside the virtual subnet".into(),
            });
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("{remote} is outside the virtual subnet"),
            ));
        }
        if !self.acl_allows(&remote) {
            self.stats.refused.fetch_add(1, Ordering::Relaxed);
            self.emit(StackEvent::Refused {
                remote,
                reason: "denied by ACL".into(),
            });
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("ACL denies connecting to {remote}"),
            ));
        }
        if self.conns.len() >= self.config.max_connections {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "virtual connection limit reached",
            ));
        }
        let local_port = if local_port == 0 {
            ephemeral_port(self.next_id, self.config.random_seed)
        } else {
            local_port
        };
        // The local address must share the remote's family: smoltcp will not
        // connect a v4 socket to a v6 peer (or the other way round).
        let local_ip = if remote.ip.is_ipv4() {
            IpAddr::V4(self.config.local_v4)
        } else {
            IpAddr::V6(self.config.local_v6)
        };
        let local = VirtAddr::new(local_ip, local_port);
        let handle = self.sockets.add(self.tcp_socket());
        self.socket_count.add();
        {
            let socket = self.sockets.get_mut::<tcp::Socket>(handle);
            socket
                .connect(
                    self.iface.context(),
                    IpEndpoint::new(to_smoltcp(remote.ip), remote.port),
                    IpListenEndpoint {
                        addr: Some(to_smoltcp(local.ip)),
                        port: local.port,
                    },
                )
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
        }
        let id = self.next_id;
        self.next_id += 1;
        let (to_app_tx, to_app_rx) = mpsc::channel(64);
        let (from_app_tx, from_app_rx) = mpsc::channel(64);
        let (ctl_tx, ctl_rx) = mpsc::channel(16);
        let write_waker = Arc::new(AtomicWaker::new());
        self.conns.insert(
            id,
            Conn {
                handle,
                to_app: to_app_tx,
                from_app: from_app_rx,
                write_waker: write_waker.clone(),
                ctl: ctl_rx,
                closing: false,
                recv_eof_sent: false,
            },
        );
        self.emit(StackEvent::Connected { id, local, remote });
        self.stats.connected.fetch_add(1, Ordering::Relaxed);
        Ok(TcpStream {
            id,
            local,
            remote,
            read_rx: to_app_rx,
            write_tx: from_app_tx,
            write_waker,
            ctl_tx,
            kick: self.kick.clone(),
            read_buf: Vec::new(),
            read_pos: 0,
            eof: false,
            nodelay: false,
        })
    }

    fn bind_udp(&mut self, addr: VirtAddr) -> io::Result<UdpSocket> {
        if !self.in_subnet(&addr) {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("{addr} is outside the virtual subnet"),
            ));
        }
        if !self.acl_allows(&addr) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("ACL denies binding {addr}"),
            ));
        }
        if self.udp.values().any(|conn| conn.local == addr) {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                format!("{addr} is already bound"),
            ));
        }
        let handle = self.sockets.add(self.udp_socket());
        self.socket_count.add();
        {
            let socket = self.sockets.get_mut::<udp::Socket>(handle);
            socket
                .bind(IpListenEndpoint {
                    addr: Some(to_smoltcp(addr.ip)),
                    port: addr.port,
                })
                .map_err(|err| io::Error::new(io::ErrorKind::AddrInUse, err.to_string()))?;
        }
        let id = self.next_id;
        self.next_id += 1;
        let (to_app_tx, to_app_rx) = mpsc::channel(64);
        let (send_tx, send_rx) = mpsc::channel(64);
        self.udp.insert(
            id,
            UdpConn {
                handle,
                local: addr,
                to_app: to_app_tx,
                from_app: send_rx,
            },
        );
        Ok(UdpSocket {
            id,
            local: addr,
            recv_rx: to_app_rx,
            send_tx,
            kick: self.kick.clone(),
        })
    }

    /// Move data between smoltcp and the application, adopt inbound
    /// connections, and reap closed sockets.
    fn service(&mut self) {
        self.accept_inbound();
        self.service_conns();
        self.service_udp();
        self.service_dns();
    }

    /// Answer datagrams that arrive at the gateway's port 53 from the virtual
    /// resolver. An unknown name with no upstream is answered `NXDOMAIN` by the
    /// resolver; a name configured for upstream forwarding is dropped here (the
    /// host process owns the real forwarding path).
    fn service_dns(&mut self) {
        let Some(service) = self.dns.as_ref() else { return };
        let handle = service.handle;
        let resolver = service.resolver.clone();
        loop {
            let socket = self.sockets.get_mut::<udp::Socket>(handle);
            if !socket.can_recv() {
                break;
            }
            let mut buffer = [0u8; 1232];
            let (n, metadata) = match socket.recv_slice(&mut buffer) {
                Ok(received) => received,
                Err(_) => break,
            };
            let Some(response) = resolver.handle(&buffer[..n]) else { continue };
            let socket = self.sockets.get_mut::<udp::Socket>(handle);
            let _ = socket.send_slice(&response, metadata.endpoint);
        }
    }

    fn accept_inbound(&mut self) {
        let events = self.events.clone();
        let mut adopted: Vec<(usize, SocketHandle, VirtAddr, VirtAddr)> = Vec::new();
        for (index, listener) in self.listeners.iter().enumerate() {
            for handle in &listener.handles {
                let socket = self.sockets.get::<tcp::Socket>(*handle);
                if socket.may_recv() {
                    if let Some(remote) = socket.remote_endpoint() {
                        adopted.push((index, *handle, listener.addr, endpoint_to_virt(remote)));
                    }
                }
            }
        }
        for (index, handle, local, remote) in adopted {
            if let Some(listener) = self.listeners.get_mut(index) {
                listener.handles.retain(|candidate| *candidate != handle);
            }
            let (to_app_tx, to_app_rx) = mpsc::channel(64);
            let (from_app_tx, from_app_rx) = mpsc::channel(64);
            let (ctl_tx, ctl_rx) = mpsc::channel(16);
            let write_waker = Arc::new(AtomicWaker::new());
            let id = self.next_id;
            self.next_id += 1;
            let stream = TcpStream {
                id,
                local,
                remote,
                read_rx: to_app_rx,
                write_tx: from_app_tx,
                write_waker: write_waker.clone(),
                ctl_tx,
                kick: self.kick.clone(),
                read_buf: Vec::new(),
                read_pos: 0,
                eof: false,
                nodelay: false,
            };
            self.conns.insert(
                id,
                Conn {
                    handle,
                    to_app: to_app_tx,
                    from_app: from_app_rx,
                    write_waker,
                    ctl: ctl_rx,
                    closing: false,
                    recv_eof_sent: false,
                },
            );
            let addr = self
                .listeners
                .get(index)
                .map(|listener| listener.addr)
                .unwrap_or(local);
            match self.spawn_listener_socket(addr) {
                Ok(replacement) => {
                    if let Some(listener) = self.listeners.get_mut(index) {
                        listener.handles.push(replacement);
                    }
                }
                Err(err) => tracing::warn!(error = %err, "could not replenish the listener pool"),
            }
            let queued = self
                .listeners
                .get_mut(index)
                .map(|listener| listener.accept_tx.try_send(stream).is_ok());
            if queued != Some(true) {
                tracing::warn!("inbound connection dropped: accept queue is full");
                // Free the socket too. The connection is already established,
                // so leaving it in the SocketSet leaks its buffers and holds a
                // half-open connection from the peer's point of view, since
                // nothing will ever service it.
                if let Some(dropped) = self.conns.remove(&id) {
                    self.sockets.remove(dropped.handle);
                    self.socket_count.remove();
                }
                self.stats.dropped.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            let _ = events.send(StackEvent::Accepted { id, local, remote });
            self.stats.accepted.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn service_conns(&mut self) {
        let ids: Vec<u32> = self.conns.keys().copied().collect();
        let mut reap: Vec<(u32, Option<String>)> = Vec::new();
        for id in ids {
            let Some(conn) = self.conns.get_mut(&id) else { continue };
            let mut reset_reason: Option<String> = None;
            let mut closed = false;
            let mut close_requested = false;

            // Control commands.
            loop {
                match conn.ctl.try_recv() {
                    // A close request marks the connection for finishing.
                    // Whether the socket closes on this pass or waits is
                    // decided after the queues are drained below, because a
                    // handle dropped while a reply is still in flight must not
                    // cut the exchange short.
                    //
                    // This is the only path by which a dropped handle is noticed
                    // at all: `Drop` on `TcpStream` sends this, and the reactor
                    // watches `to_app.is_closed()`, which runs the other way and
                    // stays open after the application goes.
                    Ok(ConnCmd::Close) => {
                        conn.closing = true;
                        close_requested = true;
                    }
                    Ok(ConnCmd::Abort) => {
                        self.sockets.get_mut::<tcp::Socket>(conn.handle).abort();
                        reset_reason = Some("connection aborted".into());
                        closed = true;
                    }
                    Ok(ConnCmd::SetNodelay(enabled)) => {
                        self.sockets
                            .get_mut::<tcp::Socket>(conn.handle)
                            .set_nagle_enabled(!enabled);
                    }
                    Err(_) => break,
                }
            }
            if closed {
                reap.push((id, reset_reason));
                continue;
            }

            // App -> stack.
            let mut wrote = false;
            loop {
                let socket = self.sockets.get_mut::<tcp::Socket>(conn.handle);
                if !socket.may_send() {
                    break;
                }
                match conn.from_app.try_recv() {
                    Ok(data) => {
                        let _ = socket.send_slice(&data);
                        wrote = true;
                    }
                    Err(_) => break,
                }
            }
            // stack -> app, but only while the app is reading.
            let socket = self.sockets.get_mut::<tcp::Socket>(conn.handle);
            while socket.may_recv() {
                let mut buffer = [0u8; 4096];
                match socket.recv_slice(&mut buffer) {
                    Ok(0) => break,
                    Ok(n) => {
                        let packet = buffer[..n].to_vec();
                        if conn.to_app.try_send(AppEvent::Data(packet)).is_err() {
                            // Backpressure or a gone reader. A gone reader is
                            // detected below; a full one just waits.
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            // A reader that has gone away closes the socket.
            if conn.to_app.is_closed() {
                self.sockets.get_mut::<tcp::Socket>(conn.handle).close();
                conn.closing = true;
            }
            let (state, send_queue, recv_queue, open) = {
                let socket = self.sockets.get::<tcp::Socket>(conn.handle);
                (socket.state(), socket.send_queue(), socket.recv_queue(), socket.is_open())
            };
            // The remote half-closed: tell the app once, but keep the write
            // side open until the app closes it.
            if state == tcp::State::CloseWait && recv_queue == 0 && !conn.recv_eof_sent {
                conn.recv_eof_sent = true;
                let _ = conn.to_app.try_send(AppEvent::Eof);
            }
            // A close request closes the socket only once nothing is still owed in
            // either direction, so a handle dropped mid-exchange does not
            // discard the reply that is on its way. This is the decision
            // `TcpStream::drop` cannot make for itself: it does not know whether
            // the reactor is holding data it still owes.
            if close_requested && send_queue == 0 && recv_queue == 0 {
                self.sockets.get_mut::<tcp::Socket>(conn.handle).close();
            }
            // A socket in TIME_WAIT is finished for this stack's purposes: it
            // holds no buffers of anything and smoltcp will never move it again,
            // because the segment that ends a TIME_WAIT is sent by the socket
            // that closes last, which is the peer. Keeping it resident means a
            // short-lived connection leaves a corpse behind, and a workload that
            // makes many of them grows without bound. `TimeWait` is therefore
            // treated as closed here even though it is not `Closed`.
            let closed_now = !open
                || matches!(state, tcp::State::Closed | tcp::State::TimeWait | tcp::State::Closing);
            if wrote {
                // The app had data waiting on a full channel; it can try again.
                conn.write_waker.wake();
            }
            if closed_now {
                reap.push((id, None));
            }
        }
        for (id, reason) in reap {
            if let Some(conn) = self.conns.remove(&id) {
                if let Some(reason) = reason {
                    let _ = conn.to_app.try_send(AppEvent::Reset(reason));
                } else {
                    let _ = conn.to_app.try_send(AppEvent::Eof);
                }
                // Free the smoltcp socket. A SocketSet only grows: `add` reuses
                // a vacant slot, but nothing reclaims one on its own, so
                // dropping the Conn without removing the handle leaves the
                // socket resident with both of its buffers attached for the life
                // of the process. The reference implementation never called
                // `remove`, so every connection ever made leaked.
                self.sockets.remove(conn.handle);
                self.socket_count.remove();
                self.emit(StackEvent::Closed { id });
                self.stats.closed.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn service_udp(&mut self) {
        let ids: Vec<u32> = self.udp.keys().copied().collect();
        let events = self.events.clone();
        for id in ids {
            let Some(conn) = self.udp.get_mut(&id) else { continue };
            // App -> stack.
            while let Ok((data, remote)) = conn.from_app.try_recv() {
                let in_subnet = self.config.subnet.contains(&remote.ip);
                let allowed = self
                    .config
                    .acl
                    .as_ref()
                    .map(|acl| acl.allows(&remote.ip, remote.port))
                    .unwrap_or(true);
                if !in_subnet || !allowed {
                    self.stats.refused.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let socket = self.sockets.get_mut::<udp::Socket>(conn.handle);
                if socket
                    .send_slice(&data, IpEndpoint::new(to_smoltcp(remote.ip), remote.port))
                    .is_err()
                {
                    break;
                }
                let _ = events.send(StackEvent::Datagram {
                    from: conn.local,
                    to: remote,
                    len: data.len(),
                });
                self.stats.datagrams.fetch_add(1, Ordering::Relaxed);
            }
            // stack -> app.
            loop {
                let socket = self.sockets.get_mut::<udp::Socket>(conn.handle);
                if !socket.can_recv() {
                    break;
                }
                let mut buffer = [0u8; 65535];
                match socket.recv_slice(&mut buffer) {
                    Ok((n, metadata)) => {
                        let from = endpoint_to_virt(metadata.endpoint);
                        let data = buffer[..n].to_vec();
                        if conn.to_app.try_send((data, from)).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        }
    }
}

fn ephemeral_port(id: u32, seed: u64) -> u16 {
    // 49152..=65535 is the dynamic range; mix the id and seed so restarts do
    // not collide.
    let mixed = (id as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ seed;
    49152 + (mixed % (65535 - 49152 + 1)) as u16
}

// ── async facade ────────────────────────────────────────────────────────────

/// The reactor task's runtime handle.
pub struct NetStack {
    cmd: mpsc::Sender<Command>,
    link_in: PacketQueue,
    link_out: PacketQueue,
    stats: Arc<NetStats>,
    device_stats: Arc<DeviceStats>,
    socket_count: Arc<SocketCount>,
    shutdown: Arc<Notify>,
    kick: Arc<Notify>,
    events_rx: Option<mpsc::UnboundedReceiver<StackEvent>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl NetStack {
    /// A stack whose link loops back into itself.
    pub fn loopback() -> Self {
        Self::new(StackConfig::default(), true)
    }

    /// A stack with a configurable loopback link.
    pub fn loopback_with(config: StackConfig) -> Self {
        Self::new(config, true)
    }

    /// A stack whose packets leave and enter through a real link.
    pub fn over_link(config: StackConfig) -> Self {
        Self::new(config, false)
    }

    fn new(config: StackConfig, loopback: bool) -> Self {
        let device = if loopback {
            LinkDevice::loopback(config.mtu)
        } else {
            LinkDevice::tunnel(config.mtu)
        };
        let link_in = device.inbound();
        let link_out = device.outbound();
        let device_stats = device.stats();
        let (events_tx, events_rx) = mpsc::unbounded_channel();
        let kick = Arc::new(Notify::new());
        let max_poll_interval = config.max_poll_interval;
        let socket_count = Arc::new(SocketCount::default());
        let core = Core::new(config, device, events_tx, kick.clone(), socket_count.clone());
        let stats = core.stats.clone();
        let (cmd_tx, cmd_rx) = mpsc::channel(64);
        let shutdown = Arc::new(Notify::new());
        let inbound_wait = link_in.clone();
        let shutdown_flag = shutdown.clone();
        let run_kick = kick.clone();
        let task = tokio::spawn(async move {
            run(
                core,
                cmd_rx,
                inbound_wait,
                shutdown_flag,
                run_kick,
                max_poll_interval,
            )
            .await;
        });
        Self {
            cmd: cmd_tx,
            link_in,
            link_out,
            stats,
            device_stats,
            socket_count,
            shutdown,
            kick,
            events_rx: Some(events_rx),
            task: Some(task),
        }
    }

    async fn send(&self, command: Command) -> io::Result<()> {
        self.cmd
            .send(command)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "virtual stack is shut down"))
    }

    /// Bind a virtual TCP listener.
    pub async fn listen(&self, addr: VirtAddr) -> io::Result<TcpListener> {
        let (reply, rx) = oneshot::channel();
        self.send(Command::Listen { addr, reply }).await?;
        rx.await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "virtual stack is shut down"))?
    }

    /// Open a virtual TCP connection.
    pub async fn connect(&self, remote: VirtAddr) -> io::Result<TcpStream> {
        self.connect_from(remote, 0).await
    }

    pub async fn connect_from(&self, remote: VirtAddr, local_port: u16) -> io::Result<TcpStream> {
        let (reply, rx) = oneshot::channel();
        self.send(Command::Connect { remote, local_port, reply }).await?;
        rx.await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "virtual stack is shut down"))?
    }

    /// Bind a virtual UDP socket.
    pub async fn bind_udp(&self, addr: VirtAddr) -> io::Result<UdpSocket> {
        let (reply, rx) = oneshot::channel();
        self.send(Command::BindUdp { addr, reply }).await?;
        rx.await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "virtual stack is shut down"))?
    }

    /// Packets arriving from the external link (written by the pump, read by
    /// the stack).
    pub fn link_in(&self) -> PacketQueue {
        self.link_in.clone()
    }

    /// Packets leaving the stack (read by the pump, written to the link).
    pub fn link_out(&self) -> PacketQueue {
        self.link_out.clone()
    }

    pub fn stats(&self) -> NetStatsSnapshot {
        self.stats.snapshot()
    }

    pub fn device_stats(&self) -> DeviceStatsSnapshot {
        self.device_stats.snapshot()
    }

    /// Sockets the reactor holds right now, and the largest number it has held
    /// at once.
    ///
    /// A `SocketSet` reuses a vacant slot on `add` but never reclaims one, so a
    /// set that is not pruned when a connection closes grows without bound. This
    /// makes that visible: `live` returns to its resting value after connections
    /// close if the set is being pruned, and climbs if it is not.
    pub fn socket_count(&self) -> (u64, u64) {
        (self.socket_count.live(), self.socket_count.peak())
    }

    /// Take the event stream, at most once.
    pub fn take_events(&mut self) -> Option<mpsc::UnboundedReceiver<StackEvent>> {
        self.events_rx.take()
    }

    /// Stop the reactor.
    pub async fn shutdown(&mut self) {
        let _ = self.cmd.try_send(Command::Shutdown);
        self.shutdown.notify_one();
        self.kick.notify_one();
        if let Some(task) = self.task.take() {
            let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
        }
    }
}

impl Drop for NetStack {
    fn drop(&mut self) {
        // `notify_one`, not `notify_waiters`: it stores a permit, so a notify
        // that lands while the reactor is between polls is not lost.
        self.shutdown.notify_one();
        self.kick.notify_one();
    }
}

async fn run(
    mut core: Core,
    mut cmd_rx: mpsc::Receiver<Command>,
    inbound_wait: PacketQueue,
    shutdown: Arc<Notify>,
    kick: Arc<Notify>,
    max_poll_interval: Duration,
) {
    loop {
        core.poll_iface();
        core.service();
        core.poll_iface();

        // `next_delay` already clamps to the configured maximum, so clamping
        // again to a hardcoded 100ms would make `max_poll_interval` a no-op for
        // every value above 100ms: a stack configured to poll every 5s would
        // still poll every 100ms. The only floor applied here keeps a
        // zero-valued configuration from turning the loop into a busy spin.
        let floor = Duration::from_micros(200).min(max_poll_interval);
        let delay = core.next_delay().unwrap_or(max_poll_interval).max(floor);

        tokio::select! {
            biased;
            command = cmd_rx.recv() => {
                match command {
                    Some(Command::Shutdown) | None => break,
                    Some(command) => {
                        core.handle(command);
                        // The command may have created a socket; poll promptly.
                    }
                }
            }
            _ = kick.notified() => {}
            _ = inbound_wait.wait() => {}
            _ = tokio::time::sleep(delay) => {}
            _ = shutdown.notified() => break,
        }
    }
    // Wake anything still blocked on a channel.
    core.conns.clear();
    core.udp.clear();
}

// ── the synchronous §9.1 proof ──────────────────────────────────────────────

/// The steps and verdict of a userspace TCP handshake + transfer, run
/// entirely in-process.
///
/// The `kernel_af_inet_*` fields are **not** measurements. A userspace stack has
/// no way to observe its own syscalls, so the report says which link layer it
/// ran over rather than asserting a kernel call count it cannot see. The
/// original set the count to a literal zero and printed "kernel AF_INET
/// bind/connect used: none", which reads as a syscall trace and is not one: a
/// direct `AF_INET` connect added anywhere on this path would not change it.
#[derive(Clone, Debug)]
pub struct ProofReport {
    pub steps: Vec<String>,
    pub server_state: String,
    pub client_state: String,
    /// The link layer the stack ran over: `"in-process loopback"` or `"a
    /// tunnel"`. The second would mean packets could reach a kernel socket.
    pub link_layer: String,
    pub bytes_received: usize,
}

impl ProofReport {
    pub fn passed(&self) -> bool {
        self.server_state == "ESTABLISHED"
            && self.client_state == "ESTABLISHED"
            && self.bytes_received > 0
    }

    pub fn render(&self) -> String {
        let mut out = String::new();
        for step in &self.steps {
            out.push_str("  ");
            out.push_str(step);
            out.push('\n');
        }
        out.push_str("\n--- verdict ---\n");
        out.push_str(&format!(
            "link layer: {}\n",
            self.link_layer
        ));
        out.push_str(
            "note: this proves the stack ran in-process. It cannot observe its own\n\
             \x20     syscalls; tests/af_inet_kernel.rs measures the kernel side by socket inode.\n",
        );
        out.push_str(&format!("server socket final state: {}\n", self.server_state));
        out.push_str(&format!("client socket final state: {}\n", self.client_state));
        if self.passed() {
            out.push_str("PROOF: userspace TCP handshake + request/response complete\n");
        } else {
            out.push_str("FAIL: the handshake did not complete\n");
        }
        out
    }
}

/// Run the §9.1 proof with the crate's own device and no external link.
pub fn loopback_proof() -> ProofReport {
    use smoltcp::wire::Ipv4Address;

    let mut device = LinkDevice::loopback(1500);
    let mut config = IfaceConfig::new(HardwareAddress::Ip);
    config.random_seed = 0x1234_5678;
    let mut iface = Interface::new(config, &mut device, SmolInstant::ZERO);
    let ip = Ipv4Address::new(10, 66, 0, 2);
    iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(ip), 24));
    });
    let mk = || {
        tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; 8192]),
            tcp::SocketBuffer::new(vec![0u8; 8192]),
        )
    };
    let mut sockets: SocketSet<'static> = SocketSet::new(Vec::new());
    let server = sockets.add(mk());
    let client = sockets.add(mk());
    sockets
        .get_mut::<tcp::Socket>(server)
        .listen(IpListenEndpoint { addr: Some(IpAddress::Ipv4(ip)), port: 8080 })
        .unwrap();
    sockets
        .get_mut::<tcp::Socket>(client)
        .connect(
            iface.context(),
            IpEndpoint::new(IpAddress::Ipv4(ip), 8080),
            IpListenEndpoint { addr: Some(IpAddress::Ipv4(ip)), port: 49152 },
        )
        .unwrap();

    let mut steps = Vec::new();
    let mut request_sent = false;
    let mut response = Vec::new();
    let mut accepted = false;
    for tick in 1..=20_000i64 {
        let now = SmolInstant::from_millis(tick);
        let _ = iface.poll(now, &mut device, &mut sockets);

        {
            let socket = sockets.get_mut::<tcp::Socket>(server);
            if !accepted && socket.may_recv() {
                accepted = true;
                if let Some(remote) = socket.remote_endpoint() {
                    steps.push(format!(
                        "server ACCEPTED from {}:{}",
                        from_smoltcp(remote.addr),
                        remote.port
                    ));
                }
            }
            if socket.may_recv() {
                let mut buffer = [0u8; 512];
                if let Ok(n) = socket.recv_slice(&mut buffer) {
                    if n > 0 {
                        let got = String::from_utf8_lossy(&buffer[..n]).to_string();
                        steps.push(format!("server READ {n}B: {}", got.trim()));
                        let reply = format!(
                            "HTTP/1.0 200 OK\r\n\r\nuserspace tcp says: {}",
                            got.trim()
                        );
                        let _ = socket.send_slice(reply.as_bytes());
                        steps.push("server WROTE response".into());
                    }
                }
            }
        }
        {
            let socket = sockets.get_mut::<tcp::Socket>(client);
            if !request_sent && socket.may_send() {
                request_sent = true;
                let request = b"GET /hello HTTP/1.0\r\n\r\n";
                let n = socket.send_slice(request).unwrap();
                steps.push(format!("client WROTE {n}B request (state={})", socket.state()));
            }
            if socket.may_recv() {
                let mut buffer = [0u8; 512];
                if let Ok(n) = socket.recv_slice(&mut buffer) {
                    if n > 0 {
                        response.extend_from_slice(&buffer[..n]);
                        steps.push(format!("client READ {n}B"));
                    }
                }
            }
        }
        if response.windows(4).any(|window| window == b"\r\n\r\n") && response.len() > 20 {
            break;
        }
    }
    let server_state = sockets.get::<tcp::Socket>(server).state().to_string();
    let client_state = sockets.get::<tcp::Socket>(client).state().to_string();
    ProofReport {
        steps,
        server_state,
        client_state,
        link_layer: "in-process loopback".to_string(),
        bytes_received: response.len(),
    }
}

/// A deterministic integration test of the full async stack: a listener and a
/// client in one loopback stack, with a real request/response.
pub async fn loopback_round_trip() -> io::Result<(usize, Vec<u8>)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut net = NetStack::loopback();
    let addr = VirtAddr::new(net::LOCAL_IP, 8080);
    let mut listener = net.listen(addr).await?;
    let server = tokio::spawn(async move {
        let mut stream = listener.accept().await.unwrap();
        let mut buffer = vec![0u8; 1024];
        let n = stream.read(&mut buffer).await.unwrap();
        let body = format!("HTTP/1.0 200 OK\r\n\r\nuserspace tcp says: {}", String::from_utf8_lossy(&buffer[..n]).trim());
        stream.write_all(body.as_bytes()).await.unwrap();
        stream.flush().await.unwrap();
        n
    });
    let mut client = net.connect(addr).await?;
    client.write_all(b"GET /hello HTTP/1.0\r\n\r\n").await?;
    client.flush().await?;
    let mut response = Vec::new();
    client.read_to_end(&mut response).await?;
    let request_len = server.await.unwrap();
    net.shutdown().await;
    Ok((request_len, response))
}

/// Small helper namespace so the integration helper does not need a public
/// alias for `Vec<u8>`.
pub mod net {
    use std::net::IpAddr;

    /// The default local address this crate uses for loopback tests.
    pub const LOCAL_IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(10, 66, 0, 2));
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn proof_completes() {
        let report = loopback_proof();
        assert!(report.passed(), "{}", report.render());
        assert!(
            report.link_layer == "in-process loopback",
            "the loopback proof must say which link it ran over: {:?}",
            report.link_layer
        );
        assert!(report.bytes_received > 20);
        assert!(report.render().contains("PROOF"));
    }

    #[test]
    fn clock_is_monotonic() {
        let clock = Clock::starting_at(100);
        let a = clock.now_ms();
        std::thread::sleep(Duration::from_millis(2));
        let b = clock.now_ms();
        assert!(b > a);
    }

    #[tokio::test]
    async fn async_loopback_round_trip() {
        let (request_len, response) = loopback_round_trip().await.unwrap();
        assert_eq!(request_len, 23);
        let text = String::from_utf8_lossy(&response);
        assert!(text.contains("200 OK"), "{text:?}");
        assert!(text.contains("GET /hello"), "{text:?}");
    }

    #[tokio::test]
    async fn udp_loopback_round_trip() {
        let mut net = NetStack::loopback();
        let server_addr = VirtAddr::new(net::LOCAL_IP, 5353);
        let client_addr = VirtAddr::new(net::LOCAL_IP, 40000);
        let mut server = net.bind_udp(server_addr).await.unwrap();
        let client = net.bind_udp(client_addr).await.unwrap();
        client.send_to(b"ping", server_addr).await.unwrap();
        let mut buffer = [0u8; 64];
        let (n, from) = tokio::time::timeout(
            Duration::from_secs(2),
            server.recv_from(&mut buffer),
        )
        .await
        .expect("udp timed out")
        .unwrap();
        assert_eq!(&buffer[..n], b"ping");
        assert_eq!(from, client_addr);
        net.shutdown().await;
    }

    #[tokio::test]
    async fn virtual_dns_answers_at_the_gateway() {
        use crate::vnet::dns::{build_query, parse_answers, TYPE_A};
        let resolver = Arc::new(Resolver::new().with("web", "10.66.0.2".parse().unwrap()));
        let config = StackConfig { dns: Some(resolver), ..StackConfig::default() };
        let mut net = NetStack::loopback_with(config);
        let mut client = net.bind_udp(VirtAddr::new(net::LOCAL_IP, 40053)).await.unwrap();
        let gateway = VirtAddr::new("10.66.0.1".parse().unwrap(), 53);
        let query = build_query(0x1234, "web", TYPE_A).unwrap();
        client.send_to(&query, gateway).await.unwrap();
        let mut buffer = [0u8; 512];
        let (n, from) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buffer))
            .await
            .expect("dns timed out")
            .unwrap();
        assert_eq!(from, gateway);
        assert_eq!(parse_answers(&buffer[..n]).unwrap(), vec!["10.66.0.2".parse::<IpAddr>().unwrap()]);
        net.shutdown().await;
    }

    #[tokio::test]
    async fn acl_refuses_connections() {
        let acl = Acl::default_deny();
        let config = StackConfig { acl: Some(Arc::new(acl)), ..StackConfig::default() };
        let mut net = NetStack::loopback_with(config);
        let err = net
            .connect(VirtAddr::new(net::LOCAL_IP, 8080))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(net.stats().refused, 1);
        net.shutdown().await;
    }

    #[tokio::test]
    async fn outside_subnet_is_refused() {
        let mut net = NetStack::loopback();
        let err = net
            .connect(VirtAddr::new("10.99.0.2".parse().unwrap(), 80))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AddrNotAvailable);
        net.shutdown().await;
    }

    #[tokio::test]
    async fn tcp_nodelay_is_recorded() {
        let mut net = NetStack::loopback();
        let mut client = net.connect(VirtAddr::new(net::LOCAL_IP, 9)).await.unwrap();
        client.set_nodelay(true);
        assert!(client.nodelay());
        net.shutdown().await;
    }

    /// An application write must wake the reactor, not wait for the poll tick.
    /// The timeout is below `max_poll_interval`, so a missing wakeup fails.
    #[tokio::test]
    async fn application_writes_wake_the_reactor() {
        let mut net = NetStack::loopback();
        let addr = VirtAddr::new(net::LOCAL_IP, 8123);
        let mut listener = net.listen(addr).await.unwrap();
        let server = tokio::spawn(async move {
            let mut stream = listener.accept().await.unwrap();
            let mut buffer = [0u8; 16];
            stream.read(&mut buffer).await.unwrap()
        });
        let mut client = net.connect(addr).await.unwrap();
        client.write_all(b"hello").await.unwrap();
        let read = tokio::time::timeout(Duration::from_millis(60), server).await;
        assert!(read.is_ok(), "the reactor did not service the write within 60ms");
        assert_eq!(read.unwrap().unwrap(), 5);
        net.shutdown().await;
    }

    #[tokio::test]
    async fn ipv6_loopback_round_trip() {
        let mut net = NetStack::loopback();
        let addr = VirtAddr::new("fd00:66::2".parse().unwrap(), 8090);
        let mut listener = net.listen(addr).await.unwrap();
        let server = tokio::spawn(async move {
            let mut stream = listener.accept().await.unwrap();
            let mut buffer = [0u8; 32];
            let n = stream.read(&mut buffer).await.unwrap();
            stream.write_all(b"ok").await.unwrap();
            n
        });
        let mut client = net.connect(addr).await.unwrap();
        assert!(client.local_addr().ip.is_ipv6(), "local is {:?}", client.local_addr());
        client.write_all(b"v6 hello").await.unwrap();
        let mut reply = [0u8; 2];
        tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut reply))
            .await
            .expect("v6 read timed out")
            .unwrap();
        assert_eq!(&reply, b"ok");
        assert_eq!(server.await.unwrap(), 8);
        net.shutdown().await;
    }
}
