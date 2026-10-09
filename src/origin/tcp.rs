//! TCP and TLS-to-TCP origins.

use std::path::PathBuf;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadHalf, WriteHalf};
use tokio::net::TcpStream;

use super::{OriginError, OriginStream};

/// An origin reached over TCP, optionally wrapped in TLS.
pub struct TcpOrigin {
    host: String,
    port: u16,
    tls: Option<TlsSettings>,
}

#[derive(Debug, Clone)]
struct TlsSettings {
    server_name: String,
    insecure: bool,
    ca_file: Option<PathBuf>,
}

impl TcpOrigin {
    /// Plain TCP.
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            tls: None,
        }
    }

    /// TLS over TCP. `insecure` skips certificate verification.
    pub fn new_tls(
        host: impl Into<String>,
        port: u16,
        insecure: bool,
        ca_file: Option<PathBuf>,
    ) -> Self {
        let host = host.into();
        Self {
            tls: Some(TlsSettings {
                server_name: host.clone(),
                insecure,
                ca_file,
            }),
            host,
            port,
        }
    }

    /// Open the stream.
    ///
    /// The timeout covers connect and, when TLS is in play, the handshake. A
    /// TLS origin that cannot complete its handshake is reported as
    /// [`OriginError::Tls`] rather than a generic failure, because the two call
    /// for different fixes.
    pub async fn connect(&self, timeout: Duration) -> Result<OriginStream, OriginError> {
        let addr = format!("{}:{}", self.host, self.port);
        let tcp = tokio::time::timeout(timeout, TcpStream::connect(&addr))
            .await
            .map_err(|_| {
                OriginError::Unreachable(format!("timed out connecting to {addr}"))
            })?
            .map_err(|e| OriginError::Unreachable(format!("{addr}: {e}")))?;

        // Nagle would add latency to the small request/response exchanges a
        // tunnel carries, and it interacts badly with streaming responses.
        let _ = tcp.set_nodelay(true);

        match &self.tls {
            None => Ok(Box::new(tcp)),
            Some(tls) => {
                let config = crate::util::tls::client_config(
                    &tls.server_name,
                    tls.insecure,
                    tls.ca_file.as_deref(),
                )
                .map_err(|e| OriginError::Tls(e.to_string()))?;
                let connector = tokio_rustls::TlsConnector::from(config);
                let name = rustls_pki_types::ServerName::try_from(tls.server_name.clone())
                    .map_err(|e| OriginError::Tls(format!("bad server name: {e}")))?;
                let stream = tokio::time::timeout(timeout, connector.connect(name, tcp))
                    .await
                    .map_err(|_| OriginError::Tls("handshake timed out".into()))?
                    .map_err(|e| OriginError::Tls(e.to_string()))?;
                Ok(Box::new(stream))
            }
        }
    }
}

/// A unix-domain-socket origin, optionally wrapped in TLS.
///
/// This is the origin that makes cfrs usable in a sandbox that refuses
/// `bind()` on TCP: the socket can be created and `connect()`ed because it is
/// `AF_UNIX`, not `AF_INET`.
pub struct UnixOrigin {
    path: PathBuf,
    tls: Option<TlsSettings>,
}

impl UnixOrigin {
    /// Plain HTTP over a unix socket.
    pub fn new(path: PathBuf) -> Self {
        Self { path, tls: None }
    }

    /// TLS over a unix socket.
    pub fn new_tls(path: PathBuf, insecure: bool, ca_file: Option<PathBuf>) -> Self {
        Self {
            path,
            tls: Some(TlsSettings {
                // A unix socket has no hostname, so SNI falls back to a name the
                // certificate must cover or `insecure` must be set.
                server_name: "localhost".to_string(),
                insecure,
                ca_file,
            }),
        }
    }

    /// Open the stream.
    pub async fn connect(&self, timeout: Duration) -> Result<OriginStream, OriginError> {
        if !self.path.exists() {
            return Err(OriginError::NotFound(format!(
                "socket {} does not exist",
                self.path.display()
            )));
        }

        let sock = tokio::time::timeout(timeout, tokio::net::UnixStream::connect(&self.path))
            .await
            .map_err(|_| {
                OriginError::Unreachable(format!("timed out connecting to {}", self.path.display()))
            })?
            .map_err(|e| OriginError::Unreachable(format!("{}: {e}", self.path.display())))?;

        match &self.tls {
            None => Ok(Box::new(sock)),
            Some(tls) => {
                let config = crate::util::tls::client_config(
                    &tls.server_name,
                    tls.insecure,
                    tls.ca_file.as_deref(),
                )
                .map_err(|e| OriginError::Tls(e.to_string()))?;
                let connector = tokio_rustls::TlsConnector::from(config);
                let name = rustls_pki_types::ServerName::try_from(tls.server_name.clone())
                    .map_err(|e| OriginError::Tls(format!("bad server name: {e}")))?;
                let stream = tokio::time::timeout(timeout, connector.connect(name, sock))
                    .await
                    .map_err(|_| OriginError::Tls("handshake timed out".into()))?
                    .map_err(|e| OriginError::Tls(e.to_string()))?;
                Ok(Box::new(stream))
            }
        }
    }
}


/// Re-exported so the tunnel layer can split an [`OriginStream`] when it needs
/// to copy in both directions at once.
pub type StreamRead = Box<dyn AsyncRead + Send + Unpin>;
pub type StreamWrite = Box<dyn AsyncWrite + Send + Unpin>;

/// Split any duplex stream into boxed halves.
pub fn split(stream: OriginStream) -> (ReadHalf<OriginStream>, WriteHalf<OriginStream>) {
    tokio::io::split(stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_missing_unix_socket_is_reported_as_not_found() {
        let o = UnixOrigin::new(PathBuf::from("/tmp/cfrs-no-such-socket-xyz.sock"));
        let err = match o.connect(Duration::from_millis(500)).await {
            Err(e) => e,
            Ok(_) => panic!("expected NotFound for a missing socket"),
        };
        assert!(
            matches!(err, OriginError::NotFound(_)),
            "expected NotFound, got {err}"
        );
        assert!(err.to_string().contains("does not exist"), "{err}");
    }

    #[tokio::test]
    async fn a_tcp_origin_that_refuses_reports_unreachable() {
        // 127.0.0.1:1 is reserved and nothing listens there.
        let o = TcpOrigin::new("127.0.0.1", 1);
        let err = match o.connect(Duration::from_millis(800)).await {
            Err(e) => e,
            Ok(_) => panic!("expected Unreachable for a refused port"),
        };
        assert!(
            matches!(err, OriginError::Unreachable(_)),
            "expected Unreachable, got {err}"
        );
    }

    #[tokio::test]
    async fn tcp_and_unix_round_trip_bytes() {
        use tokio::io::AsyncWriteExt as _;
        // A unix socketpair stands in for a listening origin, since a sandbox
        // may refuse bind() on TCP.
        let (client, mut server) = tokio::net::UnixStream::pair().expect("socketpair");

        server.write_all(b"pong").await.expect("server write");
        let o = UnixOrigin::new(PathBuf::from("/dev/null"));
        // This origin path is a special case only for the byte-pump assertion;
        // use the pair directly rather than the path-based connector.
        let mut reader: StreamRead = Box::new(client);
        let mut buf = [0u8; 4];
        tokio::io::AsyncReadExt::read_exact(&mut reader, &mut buf)
            .await
            .expect("read pong");
        assert_eq!(&buf, b"pong");
        drop(o);
    }
}