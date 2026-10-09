//! A SOCKS5 / HTTP `CONNECT` front door into the virtual network.
//!
//! Programs that cannot be interposed — a statically linked binary, a language
//! runtime that resolves its own network stack — still honour `ALL_PROXY`.
//! [`handle_connection`] speaks the client side of SOCKS5 and HTTP `CONNECT`
//! and dials the requested endpoint through a [`NetStack`].
//!
//! A virtual endpoint only exists while something listens on it. [`forward`]
//! supplies that: it binds a virtual listener and splices every accepted
//! connection to a real destination reached through the host, so a fixed
//! virtual address can name a service that actually exists:
//!
//! ```text
//! ALL_PROXY=socks5h:///tmp/cfrsnet.socks
//! curl http://10.66.0.2:8080/        # -> 127.0.0.1:3000
//! ```

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, BufReader};
use tokio::task::JoinHandle;

use crate::vnet::addr::VirtAddr;
use crate::vnet::socks::{self, ProxyHost};
use crate::vnet::stack::NetStack;

/// Where the proxy accepts clients.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProxyListen {
    /// An `AF_UNIX` socket, usually an abstract-free filesystem path.
    Unix(PathBuf),
    /// A real TCP listener, for a host that permits `AF_INET` binds.
    Tcp(SocketAddr),
}

impl ProxyListen {
    /// Parse `unix:/path` or `tcp://host:port`.
    pub fn parse(value: &str) -> Result<Self> {
        if let Some(path) = value.strip_prefix("unix:") {
            if path.is_empty() {
                bail!("unix: listen address has no path");
            }
            return Ok(Self::Unix(PathBuf::from(path)));
        }
        for prefix in ["tcp://", "tcp:"] {
            if let Some(rest) = value.strip_prefix(prefix) {
                return Ok(Self::Tcp(rest.parse().with_context(|| format!("bad TCP listen address {rest:?}"))?));
            }
        }
        if let Ok(addr) = value.parse::<SocketAddr>() {
            return Ok(Self::Tcp(addr));
        }
        bail!("listen address {value:?} is not unix:/path or tcp://host:port")
    }
}

/// A destination table for names the virtual network cannot resolve.
pub type Resolver = HashMap<String, IpAddr>;

/// Turn a parsed request into a virtual endpoint.
pub fn resolve_target(request: &socks::ProxyRequest, resolver: &Resolver, default_port: u16) -> Result<VirtAddr> {
    let port = if request.port == 0 { default_port } else { request.port };
    match &request.host {
        ProxyHost::Ip(ip) => Ok(VirtAddr::new(*ip, port)),
        ProxyHost::Domain(name) => resolver
            .get(&name.to_ascii_lowercase())
            .map(|ip| VirtAddr::new(*ip, port))
            .ok_or_else(|| anyhow::anyhow!("no virtual address for {name:?}")),
    }
}

/// Serve one proxy client: negotiate, dial `net`, and splice both directions.
///
/// The protocol is detected from the first byte (SOCKS5 begins with `0x05`),
/// so one listener serves both SOCKS5 and HTTP `CONNECT` clients.
pub use crate::vnet::stack::TcpStream;

/// How long one proxied client connection may take, end to end. A client that
/// opens a connection to the front door and then says nothing holds a task and
/// an origin socket until this expires.
const CLIENT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

pub async fn handle_connection<S>(stream: S, net: Arc<NetStack>, resolver: Resolver, default_port: u16)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut reader = BufReader::new(stream);
    let first = match reader.fill_buf().await {
        Ok(buffer) if !buffer.is_empty() => buffer[0],
        _ => return,
    };
    let is_socks = socks::looks_like_socks5(first);
    let request = if is_socks {
        match socks::socks5_read_request(&mut reader).await {
            Ok(request) => request,
            Err(_) => return,
        }
    } else if let Ok(request) = socks::http_read_connect(&mut reader).await {
        request
    } else {
        return;
    };

    let target = match resolve_target(&request, &resolver, default_port) {
        Ok(target) => target,
        Err(err) => {
            fail(&mut reader, is_socks, &err.to_string()).await;
            return;
        }
    };
    // `net.connect` returns as soon as the socket exists and the SYN is queued,
    // which is not the same as the connection being established. The client has
    // already sent its request and is waiting, so if nothing is listening it
    // waits for data that will never arrive. Refusing instead means the client
    // gets a SOCKS5 error or a 502, which it can act on.
    match net.connect(target).await {
        Ok(mut remote) => {
            if let Err(message) = wait_established(&mut remote).await {
                fail(&mut reader, is_socks, &message).await;
                return;
            }
            let reply = if is_socks {
                socks::socks5_reply(&mut reader, 0x00, None).await
            } else {
                socks::http_connect_ok(&mut reader).await
            };
            if reply.is_err() {
                return;
            }
            // Bound the whole exchange. Without this a client that opens a
            // connection and then stops reading holds a task and both sockets
            // indefinitely, and there is nothing else in the process that would
            // notice.
            let _ = tokio::time::timeout(
                CLIENT_TIMEOUT,
                tokio::io::copy_bidirectional(&mut reader, &mut remote),
            )
            .await;
        }
        Err(err) => fail(&mut reader, is_socks, &err.to_string()).await,
    }
}

/// Wait for the virtual connection to be established, or report why it failed.
///
/// [`crate::vnet::stack::NetStack::connect`] returns once the socket is created,
/// which for a nonexistent listener still succeeds at the API level. A caller
/// that must choose between "refuse" and "accept" needs the handshake's outcome.
async fn wait_established(stream: &mut TcpStream) -> Result<(), String> {
    use tokio::io::AsyncReadExt;
    // The stack signals a reset or a refusal through the read side, and a
    // pending connection by not completing one. A zero-length read resolves as
    // soon as the reactor has made the connection usable, and returns an error
    // when the connection was reset.
    loop {
        let mut probe = [0u8; 0];
        match tokio::time::timeout(
            std::time::Duration::from_millis(250),
            stream.read(&mut probe),
        )
        .await
        {
            Ok(Ok(_)) => return Ok(()),
            Ok(Err(err)) => return Err(err.to_string()),
            // Still pending: give the reactor more time.
            Err(_) => continue,
        }
    }
}

async fn fail<S>(stream: &mut S, is_socks: bool, message: &str)
where
    S: AsyncWrite + Unpin,
{
    if is_socks {
        let _ = socks::socks5_reply(stream, socks::socks5_code_for_error(message), None).await;
    } else {
        let _ = socks::http_connect_reply(stream, 502, "Bad Gateway").await;
    }
}

/// Bind a virtual listener and splice each accepted connection to a real
/// destination. `dial` is called once per connection, so it can open a fresh
/// real socket; the test suite passes a duplex instead.
pub fn forward<F, Fut, S>(net: Arc<NetStack>, virt: VirtAddr, dial: F) -> JoinHandle<()>
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = std::io::Result<S>> + Send + 'static,
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut listener = match net.listen(virt).await {
            Ok(listener) => listener,
            Err(err) => {
                tracing::warn!(%virt, error = %err, "virtual forward could not bind");
                return;
            }
        };
        tracing::info!(%virt, "virtual forward listening");
        while let Ok(mut virtual_stream) = listener.accept().await {
            let dialed = dial();
            tokio::spawn(async move {
                match dialed.await {
                    Ok(mut real) => {
                        let _ = tokio::io::copy_bidirectional(&mut virtual_stream, &mut real).await;
                    }
                    Err(err) => {
                        tracing::warn!(error = %err, "virtual forward could not reach the real service");
                        // A reset is closer to the truth than a silent close.
                        virtual_stream.abort();
                    }
                }
            });
        }
    })
}

/// The running proxy: the accept loop plus every forward task.
pub struct Proxy {
    pub listen: ProxyListen,
    accepts: JoinHandle<()>,
    forwards: Vec<JoinHandle<()>>,
}

impl Proxy {
    /// Start forwarding the configured virtual endpoints.
    pub fn spawn_forwards<F, Fut, S>(&mut self, net: Arc<NetStack>, virt: VirtAddr, dial: F)
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = std::io::Result<S>> + Send + 'static,
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        self.forwards.push(forward(net, virt, dial));
    }

    /// Stop the accept loop and every forward.
    pub fn abort(self) {
        self.accepts.abort();
        for task in self.forwards {
            task.abort();
        }
    }
}

/// Bind the client-facing listener and start accepting.
pub async fn serve(net: Arc<NetStack>, listen: ProxyListen, resolver: Resolver, default_port: u16) -> Result<Proxy> {
    let accepts = match &listen {
        ProxyListen::Tcp(bind) => {
            let listener = tokio::net::TcpListener::bind(bind)
                .await
                .with_context(|| format!("binding {bind}"))?;
            let net = net.clone();
            let resolver = resolver.clone();
            tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    tokio::spawn(handle_connection(stream, net.clone(), resolver.clone(), default_port));
                }
            })
        }
        ProxyListen::Unix(path) => {
            #[cfg(unix)]
            {
                let listener = bind_unix(path)?;
                let net = net.clone();
                let resolver = resolver.clone();
                tokio::spawn(async move {
                    while let Ok((stream, _)) = listener.accept().await {
                        tokio::spawn(handle_connection(stream, net.clone(), resolver.clone(), default_port));
                    }
                })
            }
            #[cfg(not(unix))]
            {
                let _ = (net, path);
                bail!("unix sockets are not supported on this platform");
            }
        }
    };
    Ok(Proxy { listen, accepts, forwards: Vec::new() })
}

#[cfg(unix)]
fn bind_unix(path: &std::path::Path) -> Result<tokio::net::UnixListener> {
    let _ = std::fs::remove_file(path);
    tokio::net::UnixListener::bind(path).with_context(|| format!("binding unix:{}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// An echo server on the far end of a duplex, returned as the `dial`
    /// closure shape.
    async fn echo(stream: tokio::io::DuplexStream) {
        let (mut read, mut write) = tokio::io::split(stream);
        let _ = tokio::io::copy(&mut read, &mut write).await;
    }

    #[test]
    fn parses_listen_addresses() {
        assert_eq!(
            ProxyListen::parse("unix:/tmp/x.sock").unwrap(),
            ProxyListen::Unix(PathBuf::from("/tmp/x.sock"))
        );
        assert_eq!(
            ProxyListen::parse("tcp://127.0.0.1:1080").unwrap(),
            ProxyListen::Tcp("127.0.0.1:1080".parse().unwrap())
        );
        assert_eq!(
            ProxyListen::parse("127.0.0.1:1080").unwrap(),
            ProxyListen::Tcp("127.0.0.1:1080".parse().unwrap())
        );
        assert!(ProxyListen::parse("nonsense").is_err());
        assert!(ProxyListen::parse("unix:").is_err());
    }

    #[tokio::test]
    async fn socks5_to_virtual_echo() {
        let net = Arc::new(NetStack::loopback());
        let virt: VirtAddr = "10.66.0.2:8080".parse().unwrap();
        let handle = forward(net.clone(), virt, || async {
            let (real, far) = tokio::io::duplex(4096);
            tokio::spawn(echo(far));
            Ok(real)
        });
        // Give the forward a moment to bind its virtual listener.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let (mut client, server) = tokio::io::duplex(4096);
        let proxy = {
            let net = net.clone();
            tokio::spawn(async move {
                handle_connection(server, net, Resolver::new(), 80).await;
            })
        };
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0]);
        client
            .write_all(&[5, 1, 0, 1, 10, 66, 0, 2, 0x1f, 0x90])
            .await
            .unwrap();
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0, "SOCKS5 CONNECT should succeed");
        client.write_all(b"ping").await.unwrap();
        let mut back = [0u8; 4];
        tokio::time::timeout(std::time::Duration::from_secs(2), client.read_exact(&mut back))
            .await
            .expect("echo timed out")
            .unwrap();
        assert_eq!(&back, b"ping");
        drop(client);
        let _ = proxy.await;
        handle.abort();
    }

    #[tokio::test]
    async fn names_resolve_through_the_table() {
        let net = Arc::new(NetStack::loopback());
        let virt: VirtAddr = "10.66.0.2:8080".parse().unwrap();
        let handle = forward(net.clone(), virt, || async {
            let (real, far) = tokio::io::duplex(4096);
            tokio::spawn(echo(far));
            Ok(real)
        });
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let mut resolver = Resolver::new();
        resolver.insert("api".into(), "10.66.0.2".parse().unwrap());

        let (mut client, server) = tokio::io::duplex(4096);
        let proxy = {
            let net = net.clone();
            tokio::spawn(async move { handle_connection(server, net, resolver, 80).await })
        };
        // HTTP CONNECT to the name on the forwarded port.
        client
            .write_all(b"CONNECT api:8080 HTTP/1.1\r\nHost: api\r\n\r\n")
            .await
            .unwrap();
        let mut response = [0u8; 39];
        client.read_exact(&mut response).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200"), "{}", String::from_utf8_lossy(&response));
        client.write_all(b"hello").await.unwrap();
        let mut back = [0u8; 5];
        tokio::time::timeout(std::time::Duration::from_secs(2), client.read_exact(&mut back))
            .await
            .expect("echo timed out")
            .unwrap();
        assert_eq!(&back, b"hello");
        drop(client);
        let _ = proxy.await;
        handle.abort();
    }
}
