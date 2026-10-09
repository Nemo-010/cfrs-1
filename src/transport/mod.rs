//! How bytes leave the machine: the transport layer.
//!
//! # Why this is a trait
//!
//! A tunnel client needs one thing from the network: a duplex byte stream to
//! some destination. How that stream is obtained varies enormously between
//! environments, and no single mechanism works everywhere:
//!
//! * **Direct** is the normal case, and the only one fast enough for QUIC.
//! * **HTTP CONNECT** is what a sandbox offers. The proxy resolves DNS, so this
//!   also solves name resolution where there is no resolver.
//! * **SSH** reaches a TCP relay that publishes the stream as a forwarded
//!   channel, for networks that allow only port 443.
//! * **WebSocket** carries the stream inside an HTTPS upgrade, for proxies that
//!   inspect traffic and want to see ordinary web requests.
//!
//! Expressing these as one trait means the tunnel, the edge client and the
//! origin never learn which is in use, and adding a transport is one impl.

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};

pub mod ssh;
pub mod websocket;

/// A duplex byte stream from a transport.
pub type TransportStream = Box<dyn Duplex>;

/// Object-safe read + write, so halves can be taken independently.
pub trait Duplex: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin> Duplex for T {}

/// Something that can produce a byte stream to a destination.
pub trait Transport: Send + Sync {
    /// Open a stream to `host:port`.
    ///
    /// Written as a boxed future rather than with `async_trait` so the crate
    /// needs no proc-macro dependency for one method.
    ///
    /// Implementations must include name resolution and any handshake in
    /// `timeout`, so a caller has one deadline to reason about.
    fn connect<'a>(
        &'a self,
        host: &'a str,
        port: u16,
        timeout: Duration,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<TransportStream, TransportError>> + Send + 'a>,
    >;

    /// A short name for logs, such as `direct` or `http-connect`.
    fn name(&self) -> &'static str;
}

/// Why a transport could not open a stream.
#[derive(Debug)]
pub enum TransportError {
    /// The destination could not be reached.
    Unreachable(String),
    /// An intermediate hop (proxy, relay) refused.
    Refused(String),
    /// TLS or WebSocket negotiation failed.
    Handshake(String),
    /// This transport cannot be used for this destination.
    Unsupported(String),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportError::Unreachable(m) => write!(f, "{m}"),
            TransportError::Refused(m) => write!(f, "refused: {m}"),
            TransportError::Handshake(m) => write!(f, "handshake failed: {m}"),
            TransportError::Unsupported(m) => write!(f, "unsupported: {m}"),
        }
    }
}

impl std::error::Error for TransportError {}

/// A direct TCP connection, with no intermediate hop.
#[derive(Debug, Clone, Default)]
pub struct Direct {
    /// Applied to every connection; cloudflared calls this the edge bind
    /// address. Useful when the host has several interfaces.
    pub bind_address: Option<std::net::SocketAddr>,
    /// Disable Nagle. A tunnel carries many small messages, so waiting to
    /// coalesce them costs latency for no benefit.
    pub no_delay: bool,
}

impl Direct {
    /// A direct transport with defaults.
    pub fn new() -> Self {
        Self::default()
    }
}

impl Transport for Direct {
    fn connect<'a>(
        &'a self,
        host: &'a str,
        port: u16,
        timeout: Duration,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<TransportStream, TransportError>> + Send + 'a>,
    > {
        Box::pin(async move {
        // Try every resolved address rather than the first, so a host with both
        // AAAA and A records still connects when only one family is routable.
        let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((host, port))
            .await
            .map_err(|e| {
                TransportError::Unreachable(format!("cannot resolve {host}:{port}: {e}"))
            })?
            .collect();

        if addrs.is_empty() {
            return Err(TransportError::Unreachable(format!(
                "{host} resolved to no addresses"
            )));
        }

        let mut last: Option<std::io::Error> = None;
        for addr in &addrs {
            // Bind to a specific local address when one was configured, so a
            // multi-homed host picks the interface cloudflared would.
            let socket = match self.bind_address {
                Some(bind) => {
                    let socket = tokio::net::TcpSocket::new_v4().map_err(|e| {
                        TransportError::Unreachable(format!("socket for {host}:{port}: {e}"))
                    })?;
                    socket.bind(bind).map_err(|e| {
                        TransportError::Unreachable(format!("bind {bind}: {e}"))
                    })?;
                    socket
                }
                None => tokio::net::TcpSocket::new_v4().map_err(|e| {
                    TransportError::Unreachable(format!("socket for {host}:{port}: {e}"))
                })?,
            };
            match tokio::time::timeout(timeout, socket.connect(*addr)).await {
                Ok(Ok(stream)) => {
                    if self.no_delay {
                        let _ = stream.set_nodelay(true);
                    }
                    return Ok(Box::new(stream) as TransportStream);
                }
                Ok(Err(e)) => last = Some(e),
                Err(_) => {
                    return Err(TransportError::Unreachable(format!(
                        "timed out connecting to {addr}"
                    )))
                }
            }
        }

        Err(TransportError::Unreachable(format!(
            "cannot connect to {host}:{port}{}",
            last.map(|e| format!(": {e}")).unwrap_or_default()
        )))
        })
    }

    fn name(&self) -> &'static str {
        "direct"
    }
}

/// A stream tunnelled through an HTTP CONNECT proxy.
///
/// Besides reaching the destination, this solves DNS: the proxy resolves the
/// name, so a host with no resolver of its own can still connect.
#[derive(Debug, Clone)]
pub struct HttpConnect {
    /// `host:port` of the proxy.
    pub proxy_addr: String,
    /// Optional `user:pass` for proxy authentication.
    pub credentials: Option<(String, String)>,
    /// Reuse one connection for several destinations, as a real proxy allows.
    pub keep_alive: bool,
}

impl HttpConnect {
    /// Build from a proxy address, optionally with credentials.
    pub fn new(proxy_addr: impl Into<String>) -> Self {
        Self {
            proxy_addr: proxy_addr.into(),
            credentials: None,
            keep_alive: false,
        }
    }

    /// Attach proxy credentials.
    pub fn with_credentials(mut self, user: impl Into<String>, pass: impl Into<String>) -> Self {
        self.credentials = Some((user.into(), pass.into()));
        self
    }
}

impl Transport for HttpConnect {
    fn connect<'a>(
        &'a self,
        host: &'a str,
        port: u16,
        timeout: Duration,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<TransportStream, TransportError>> + Send + 'a>,
    > {
        Box::pin(async move {
        let tunnel = crate::proxy::connect_tunnel_with_auth(
            &self.proxy_addr,
            host,
            port,
            timeout,
            self.credentials
                .as_ref()
                .map(|(u, p)| (u.as_str(), p.as_str())),
        )
        .map_err(|e| TransportError::Refused(format!("proxy {host}:{port}: {e}")))?;

        let (stream, leftover) = tunnel.into_parts();
        stream
            .set_nonblocking(true)
            .map_err(|e| TransportError::Unreachable(format!("set nonblocking: {e}")))?;
        let stream = tokio::net::TcpStream::from_std(stream)
            .map_err(|e| TransportError::Unreachable(format!("wrap stream: {e}")))?;
        // Bytes the proxy coalesced past the CONNECT response must be replayed
        // before anything the peer sends, or the first read is short.
        Ok(Box::new(crate::transport::websocket::Prefixed::new(
            leftover, stream,
        )) as TransportStream)
        })
    }

    fn name(&self) -> &'static str {
        "http-connect"
    }
}

/// Try transports in order until one connects.
///
/// This is what makes the tool usable across environments without the user
/// having to know which mechanism their network allows. A direct attempt is
/// usually tried first because it is cheapest, and the fallbacks are the
/// expensive ones.
#[derive(Default)]
pub struct Chain {
    transports: Vec<Box<dyn Transport>>,
}

impl Chain {
    /// An empty chain.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a transport.
    pub fn push(mut self, transport: Box<dyn Transport>) -> Self {
        self.transports.push(transport);
        self
    }

    /// How many transports are in the chain.
    pub fn len(&self) -> usize {
        self.transports.len()
    }

    /// Whether the chain is empty.
    pub fn is_empty(&self) -> bool {
        self.transports.is_empty()
    }

    /// Open a stream using the first transport that succeeds.
    ///
    /// Each attempt gets its own timeout budget, since a failing transport may
    /// burn the whole allowance trying. The error from every attempt is kept so
    /// the failure explains what was tried.
    pub async fn connect(
        &self,
        host: &str,
        port: u16,
        timeout: Duration,
    ) -> Result<(TransportStream, &'static str), TransportError> {
        if self.transports.is_empty() {
            return Err(TransportError::Unsupported(
                "no transports configured".into(),
            ));
        }

        let mut failures: Vec<String> = Vec::new();
        for transport in &self.transports {
            match transport.connect(host, port, timeout).await {
                Ok(stream) => return Ok((stream, transport.name())),
                Err(e) => failures.push(format!("{}: {e}", transport.name())),
            }
        }

        Err(TransportError::Unreachable(format!(
            "all transports failed for {host}:{port}: {}",
            failures.join("; ")
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A transport that always fails, so the chain's fallback logic can be
    /// tested without a network.
    struct Failing(&'static str, &'static str);

    impl Transport for Failing {
        fn connect<'a>(
            &'a self,
            _host: &'a str,
            _port: u16,
            _timeout: Duration,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<TransportStream, TransportError>> + Send + 'a>,
        > {
            let msg = self.1.to_string();
            Box::pin(async move { Err(TransportError::Refused(msg)) })
        }
        fn name(&self) -> &'static str {
            self.0
        }
    }

    /// A transport that yields a fixed byte string, standing in for a
    /// successful connection without touching the network.
    struct Fixed;

    impl Transport for Fixed {
        fn connect<'a>(
            &'a self,
            _host: &'a str,
            _port: u16,
            _timeout: Duration,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<TransportStream, TransportError>> + Send + 'a>,
        > {
            Box::pin(async move {
                let (a, _b) = tokio::io::duplex(64);
                Ok(Box::new(a) as TransportStream)
            })
        }
        fn name(&self) -> &'static str {
            "fixed"
        }
    }

    #[tokio::test]
    async fn an_empty_chain_reports_that_it_is_empty() {
        let chain = Chain::new();
        assert!(chain.is_empty());
        let err = match chain.connect("h", 1, Duration::from_millis(10)).await {
            Err(e) => e,
            Ok(_) => panic!("an empty chain must not connect"),
        };
        assert!(err.to_string().contains("no transports"), "{err}");
    }

    #[tokio::test]
    async fn the_chain_falls_through_to_a_working_transport() {
        let chain = Chain::new()
            .push(Box::new(Failing("first", "nope")))
            .push(Box::new(Fixed))
            .push(Box::new(Failing("third", "also nope")));
        let (_stream, used) = chain
            .connect("h", 1, Duration::from_millis(50))
            .await
            .expect("the fixed transport should succeed");
        assert_eq!(used, "fixed");
    }

    #[tokio::test]
    async fn a_fully_failing_chain_reports_every_attempt() {
        let chain = Chain::new()
            .push(Box::new(Failing("direct", "no route")))
            .push(Box::new(Failing("http-connect", "not on allowlist")));
        let err = match chain.connect("h", 1, Duration::from_millis(50)).await {
            Err(e) => e,
            Ok(_) => panic!("an all-failing chain must not connect"),
        };
        let text = err.to_string();
        assert!(text.contains("direct"), "{text}");
        assert!(text.contains("http-connect"), "{text}");
        assert!(text.contains("all transports failed"), "{text}");
    }

    #[tokio::test]
    async fn direct_reports_an_unresolvable_host() {
        let d = Direct::new();
        let err = match d
            .connect("this-host-does-not-exist.invalid", 443, Duration::from_millis(500))
            .await
        {
            Err(e) => e,
            Ok(_) => panic!("an invalid host must not connect"),
        };
        assert!(
            matches!(err, TransportError::Unreachable(_)),
            "expected Unreachable, got {err}"
        );
    }

    #[tokio::test]
    async fn transports_name_themselves() {
        assert_eq!(Direct::new().name(), "direct");
        assert_eq!(HttpConnect::new("p:1").name(), "http-connect");
        assert_eq!(ssh::SshRelay::default().name(), "ssh");
        assert_eq!(websocket::WebSocketTunnel::default().name(), "websocket");
    }

    #[tokio::test]
    async fn a_refused_proxy_is_reported_as_refused() {
        let t = HttpConnect::new("127.0.0.1:1");
        let err = match t
            .connect("example.com", 443, Duration::from_millis(500))
            .await
        {
            Err(e) => e,
            Ok(_) => panic!("a dead proxy must not connect"),
        };
        assert!(
            matches!(err, TransportError::Refused(_)),
            "expected Refused, got {err}"
        );
    }
}