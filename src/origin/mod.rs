//! The origin abstraction: where a tunnelled request is delivered.
//!
//! An origin is the thing behind the tunnel. cloudflared models this as a
//! `service:` string on an ingress rule (`http://`, `unix:`, `tcp://`), and so
//! do the Rust projects surveyed for this rewrite. Keeping that shape means a
//! cloudflared `config.yml` ports across unchanged, and it means the same
//! tunnel can serve HTTP, a unix socket and raw TCP without special-casing in
//! the data path.
//!
//! Every origin is reached through [`Origin::connect`], which returns an
//! ordered byte stream. The tunnel layer never learns what kind of origin it
//! is talking to; it only moves bytes. That is what lets HTTP, WebSocket and
//! raw TCP share one code path, and it is why a unix-socket origin works in a
//! sandbox where `bind()` on TCP is refused.

use std::path::PathBuf;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};

pub mod static_files;
pub mod tcp;
pub mod unix_socket;

pub use static_files::StaticDir;
pub use tcp::TcpOrigin;
pub use unix_socket::UnixOrigin;

/// A duplex byte stream to an origin.
pub type OriginStream = Box<dyn DuplexStream>;

/// The object-safe half of `AsyncRead + AsyncWrite`, so an origin can return
/// either half independently.
pub trait DuplexStream: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin> DuplexStream for T {}

/// Where to deliver tunnelled traffic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    /// Plain HTTP to a TCP host.
    Http { host: String, port: u16 },
    /// HTTPS to a TCP host, verified against `ca_file` unless `insecure`.
    Https {
        host: String,
        port: u16,
        insecure: bool,
        ca_file: Option<PathBuf>,
    },
    /// HTTP over a unix domain socket. The `unix:` cloudflared service.
    Unix { path: PathBuf },
    /// TLS over a unix domain socket. The `unix+tls:` service.
    UnixTls {
        path: PathBuf,
        insecure: bool,
        ca_file: Option<PathBuf>,
    },
    /// Raw TCP, for non-HTTP protocols (ssh, rdp, database, game servers).
    Tcp { host: String, port: u16 },
    /// Serve a directory of files. The `static:` service.
    Static { dir: PathBuf, spa: bool, index: String },
    /// Reply with a fixed status and no body. The `http_status:` service.
    Status { code: u16 },
    /// A canned hello-world page, matching cloudflared's `--hello-world`.
    HelloWorld,
}

/// Why an origin connection failed.
#[derive(Debug)]
pub enum OriginError {
    /// The origin could not be reached.
    Unreachable(String),
    /// The origin was reached but TLS setup failed.
    Tls(String),
    /// The service string could not be parsed.
    BadService(String),
    /// The origin is missing something it needs on disk.
    NotFound(String),
    /// Something else went wrong.
    Other(String),
}

impl std::fmt::Display for OriginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OriginError::Unreachable(m) => write!(f, "origin unreachable: {m}"),
            OriginError::Tls(m) => write!(f, "origin TLS failed: {m}"),
            OriginError::BadService(m) => write!(f, "invalid service string: {m}"),
            OriginError::NotFound(m) => write!(f, "origin not found: {m}"),
            OriginError::Other(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for OriginError {}

impl Origin {
    /// Parse a cloudflared-style `service:` string.
    ///
    /// The grammar is the one cloudflared accepts, so existing configs work:
    /// `http://host:port`, `https://`, `unix:`, `unix+tls:`, `tcp://`,
    /// `static:`, `spa:`, `http_status:NNN`, and the bare `hello_world`.
    pub fn parse(service: &str) -> Result<Origin, OriginError> {
        let s = service.trim();

        if s == "hello_world" || s == "hello-world" {
            return Ok(Origin::HelloWorld);
        }

        if let Some(rest) = s.strip_prefix("http_status:") {
            let code: u16 = rest
                .trim()
                .parse()
                .map_err(|_| OriginError::BadService(format!("bad status code in {service:?}")))?;
            if !(100..=999).contains(&code) {
                return Err(OriginError::BadService(format!(
                    "status code {code} out of range 100-999"
                )));
            }
            return Ok(Origin::Status { code });
        }

        for prefix in ["spa:", "static:"] {
            if let Some(rest) = s.strip_prefix(prefix) {
                let dir = rest.trim();
                if dir.is_empty() {
                    return Err(OriginError::BadService(format!(
                        "{prefix} needs a directory"
                    )));
                }
                return Ok(Origin::Static {
                    dir: PathBuf::from(dir),
                    spa: prefix == "spa:",
                    index: "index.html".to_string(),
                });
            }
        }

        if let Some(rest) = s.strip_prefix("unix+tls:") {
            if rest.is_empty() {
                return Err(OriginError::BadService("unix+tls: needs a socket path".into()));
            }
            return Ok(Origin::UnixTls {
                path: PathBuf::from(rest),
                insecure: false,
                ca_file: None,
            });
        }

        if let Some(rest) = s.strip_prefix("unix:") {
            if rest.is_empty() {
                return Err(OriginError::BadService("unix: needs a socket path".into()));
            }
            return Ok(Origin::Unix {
                path: PathBuf::from(rest),
            });
        }

        if let Some(rest) = s.strip_prefix("tcp://") {
            let (host, port) = split_host_port(rest, 7844)?;
            return Ok(Origin::Tcp { host, port });
        }

        if let Some(rest) = s.strip_prefix("https://") {
            let (host, port) = split_host_port(rest, 443)?;
            return Ok(Origin::Https {
                host,
                port,
                insecure: false,
                ca_file: None,
            });
        }

        if let Some(rest) = s.strip_prefix("http://") {
            let (host, port) = split_host_port(rest, 80)?;
            return Ok(Origin::Http { host, port });
        }

        Err(OriginError::BadService(format!(
            "unrecognised service {service:?}; expected http://, https://, unix:, unix+tls:, tcp://, static:, spa:, http_status:NNN or hello_world"
        )))
    }

    /// Render back to the cloudflared `service:` form, so a parsed config can
    /// be written out unchanged.
    pub fn to_service_string(&self) -> String {
        match self {
            Origin::Http { host, port } => format!("http://{host}:{port}"),
            Origin::Https { host, port, .. } => format!("https://{host}:{port}"),
            Origin::Unix { path } => format!("unix:{}", path.display()),
            Origin::UnixTls { path, .. } => format!("unix+tls:{}", path.display()),
            Origin::Tcp { host, port } => format!("tcp://{host}:{port}"),
            Origin::Static { dir, spa, .. } => {
                format!("{}:{}", if *spa { "spa" } else { "static" }, dir.display())
            }
            Origin::Status { code } => format!("http_status:{code}"),
            Origin::HelloWorld => "hello_world".to_string(),
        }
    }

    /// A short name for logs and metrics.
    pub fn kind(&self) -> &'static str {
        match self {
            Origin::Http { .. } => "http",
            Origin::Https { .. } => "https",
            Origin::Unix { .. } => "unix",
            Origin::UnixTls { .. } => "unix+tls",
            Origin::Tcp { .. } => "tcp",
            Origin::Static { .. } => "static",
            Origin::Status { .. } => "http_status",
            Origin::HelloWorld => "hello_world",
        }
    }

    /// True when the origin speaks HTTP and so wants request handling rather
    /// than a blind byte pipe.
    pub fn is_http(&self) -> bool {
        matches!(
            self,
            Origin::Http { .. }
                | Origin::Https { .. }
                | Origin::Unix { .. }
                | Origin::UnixTls { .. }
                | Origin::Static { .. }
                | Origin::Status { .. }
                | Origin::HelloWorld
        )
    }

    /// Open a byte stream to this origin.
    pub async fn connect(&self, timeout: Duration) -> Result<OriginStream, OriginError> {
        match self {
            Origin::Http { host, port } => {
                TcpOrigin::new(host, *port).connect(timeout).await
            }
            Origin::Https {
                host,
                port,
                insecure,
                ca_file,
            } => TcpOrigin::new_tls(host, *port, *insecure, ca_file.clone())
                .connect(timeout)
                .await,
            Origin::Unix { path } => UnixOrigin::new(path.clone()).connect(timeout).await,
            Origin::UnixTls {
                path,
                insecure,
                ca_file,
            } => UnixOrigin::new_tls(path.clone(), *insecure, ca_file.clone())
                .connect(timeout)
                .await,
            Origin::Tcp { host, port } => TcpOrigin::new(host, *port).connect(timeout).await,
            // In-process origins are answered by the tunnel layer itself, not
            // dialled. Reporting them as such here keeps the data path honest.
            Origin::Static { .. } | Origin::Status { .. } | Origin::HelloWorld => {
                Err(OriginError::Other(format!(
                    "{} is served in-process and has no outbound stream",
                    self.kind()
                )))
            }
        }
    }

    /// Whether this origin is answered by cfrs itself.
    pub fn is_in_process(&self) -> bool {
        matches!(
            self,
            Origin::Static { .. } | Origin::Status { .. } | Origin::HelloWorld
        )
    }
}

/// Split `host:port`, defaulting the port when absent.
fn split_host_port(rest: &str, default_port: u16) -> Result<(String, u16), OriginError> {
    let rest = rest.trim().trim_end_matches('/');
    if rest.is_empty() {
        return Err(OriginError::BadService("empty host".into()));
    }
    match rest.rsplit_once(':') {
        // Guard against IPv6 literals like [::1]:8080 and bare [::1].
        Some((host, port)) if !host.ends_with(']') || port.chars().all(|c| c.is_ascii_digit()) => {
            let port: u16 = port
                .parse()
                .map_err(|_| OriginError::BadService(format!("bad port in {rest:?}")))?;
            let host = host.trim_start_matches('[').trim_end_matches(']');
            Ok((host.to_string(), port))
        }
        _ => Ok((rest.to_string(), default_port)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_cloudflared_service_grammar() {
        let cases: Vec<(&str, &str)> = vec![
            ("http://localhost:8080", "http"),
            ("https://example.com", "https"),
            ("unix:/tmp/app.sock", "unix"),
            ("unix+tls:/tmp/app.sock", "unix+tls"),
            ("tcp://db.internal:5432", "tcp"),
            ("static:/srv/www", "static"),
            ("spa:/srv/app", "static"),
            ("http_status:404", "http_status"),
            ("hello_world", "hello_world"),
        ];
        for (service, kind) in cases {
            let o = Origin::parse(service).unwrap_or_else(|e| panic!("{service}: {e}"));
            assert_eq!(o.kind(), kind, "{service} parsed to {}", o.kind());
        }
    }

    #[test]
    fn applies_default_ports() {
        assert_eq!(
            Origin::parse("http://example.com").unwrap(),
            Origin::Http {
                host: "example.com".into(),
                port: 80
            }
        );
        assert_eq!(
            Origin::parse("https://example.com").unwrap(),
            Origin::Https {
                host: "example.com".into(),
                port: 443,
                insecure: false,
                ca_file: None
            }
        );
        assert_eq!(
            Origin::parse("tcp://db").unwrap(),
            Origin::Tcp {
                host: "db".into(),
                port: 7844
            }
        );
    }

    #[test]
    fn round_trips_through_the_service_string() {
        for service in [
            "http://localhost:8080",
            "https://example.com:8443",
            "unix:/tmp/app.sock",
            "unix+tls:/tmp/tls.sock",
            "tcp://db:5432",
            "hello_world",
        ] {
            let parsed = Origin::parse(service).expect("parse");
            let rendered = parsed.to_service_string();
            assert_eq!(rendered, service, "round trip changed {service}");
        }
    }

    #[test]
    fn rejects_unknown_and_malformed_services() {
        for bad in [
            "ftp://host",
            "http_status:abc",
            "http_status:42",
            "static:",
            "unix:",
            "nonsense",
        ] {
            assert!(
                Origin::parse(bad).is_err(),
                "{bad:?} should not parse as an origin"
            );
        }
    }

    #[test]
    fn http_origins_are_distinguished_from_raw_tcp() {
        assert!(Origin::parse("http://h:1").unwrap().is_http());
        assert!(Origin::parse("unix:/x").unwrap().is_http());
        assert!(!Origin::parse("tcp://h:1").unwrap().is_http());
    }

    #[test]
    fn in_process_origins_have_no_outbound_stream() {
        let o = Origin::HelloWorld;
        assert!(o.is_in_process());
        let r = futures_block(async { o.connect(Duration::from_millis(1)).await });
        match r {
            Err(_) => {}
            Ok(_) => panic!("hello_world must not pretend to dial"),
        }
    }

    /// A tiny blocking executor so the test can await without pulling tokio's
    /// test macros into a non-test build.
    fn futures_block<F: std::future::Future>(mut fut: F) -> F::Output {
        use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
        fn noop(_: *const ()) {}
        fn clone(_: *const ()) -> RawWaker {
            RawWaker::new(std::ptr::null(), &VTABLE)
        }
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
        let waker =
            unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) };
        let mut cx = Context::from_waker(&waker);
        let mut fut = std::pin::pin!(fut);
        loop {
            match fut.as_mut().poll(&mut cx) {
                Poll::Ready(v) => return v,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }
}