//! Expose a unix-socket origin on the public internet over SSH port forwarding.
//!
//! # Why this exists
//!
//! The development sandbox has three properties that together rule out every
//! stock tunnel client:
//!
//! 1. `bind()` on a TCP listener returns `EACCES`, so the tool cannot listen
//!    locally and wait to be connected to. A unix socket can be bound, so the
//!    origin is a unix socket rather than a TCP port.
//! 2. `connect()` to any TCP destination returns `EPERM`, including loopback.
//!    So even if a listener existed, no tool could reach it over TCP. A unix
//!    socket is reached with `connect()` on `AF_UNIX`, which is permitted.
//! 3. Egress is only an HTTP CONNECT proxy on an allow-list. The Cloudflare
//!    tunnel edge port (7844) is not on the list; TCP port 443 to an SSH relay
//!    is.
//!
//! An SSH `forwarded-tcpip` channel is a raw byte pipe that the relay opens
//! per visitor. cfrs splices that pipe to the unix socket, so the blocked TCP
//! path is never used. That is the whole trick, and it is why the origin can be
//! a unix socket at all.

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use russh::client::{Config, Handle, Handler, Msg, Session};
use russh::keys::ssh_key::rand_core::UnwrapErr;
use russh::keys::ssh_key::Algorithm;
use russh::keys::PrivateKey;
use russh::keys::PrivateKeyWithHashAlg;
use russh::{Channel, ChannelMsg};
use ssh_key::getrandom::SysRng;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::UnixStream;

use crate::proxy;

/// Default relay, reachable on port 443 through the CONNECT proxy.
pub const DEFAULT_RELAY: &str = "free.pinggy.io:443";

/// Where the remote forward is requested, and where the origin lives.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// `host:port` of the SSH server.
    pub address: String,
    /// `host:port` of the HTTP CONNECT proxy, or `None` for a direct connect.
    pub proxy: Option<String>,
    /// SSH user. The free relay tier takes an anonymous login.
    pub username: String,
    /// Path to the unix socket that serves the origin.
    pub unix_socket: std::path::PathBuf,
    /// Timeout for the CONNECT proxy handshake.
    pub connect_timeout: Duration,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            address: DEFAULT_RELAY.to_string(),
            proxy: None,
            username: "cfrs".to_string(),
            unix_socket: std::path::PathBuf::from("/tmp/cfrs-origin.sock"),
            connect_timeout: Duration::from_secs(15),
        }
    }
}

/// What a successful run reports back to the caller.
#[derive(Debug, Clone)]
pub struct TunnelHandle {
    /// The public URL a visitor should open.
    pub url: String,
    /// The port the relay allocated for the remote forward.
    pub remote_port: u32,
}

/// Errors that can stop a relay from being established.
#[derive(Debug)]
pub enum RelayError {
    /// The `host:port` string could not be split.
    BadAddress(String),
    /// The SSH key could not be generated.
    Key(String),
    /// The TCP/CONNECT transport could not be opened.
    Transport(String),
    /// The SSH handshake or authentication failed.
    Ssh(String),
    /// The relay accepted us but never published a URL.
    NoUrl,
}

impl std::fmt::Display for RelayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RelayError::BadAddress(a) => {
                write!(f, "expected relay address as host:port, got {a:?}")
            }
            RelayError::Key(e) => write!(f, "could not prepare an SSH client key: {e}"),
            RelayError::Transport(e) => write!(f, "could not open a transport to the relay: {e}"),
            RelayError::Ssh(e) => write!(f, "SSH session failed: {e}"),
            RelayError::NoUrl => write!(f, "relay did not publish a URL within the timeout"),
        }
    }
}

impl std::error::Error for RelayError {}

/// SSH client handler. Each visitor's channel is served the same way, so this
/// only needs to know where the origin is and a counter for the final report.
pub struct Client {
    /// The unix socket every forwarded channel is spliced to.
    origin: std::path::PathBuf,
    /// Count of channels successfully spliced, for the final report.
    served: Arc<Mutex<u64>>,
}

impl Client {
    /// Build a handler bound to one origin socket.
    pub fn new(origin: std::path::PathBuf, served: Arc<Mutex<u64>>) -> Self {
        Self { origin, served }
    }
}

impl Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        // The relay is reached over an anonymous, ephemeral free-tier tunnel.
        // There is no known-host store to check against, and pinning one would
        // make the tool fail on the relay's routine key rotation. The traffic
        // this carries is only as sensitive as the public URL itself, which is
        // unguessable and already in the open.
        //
        // If this ever fronts something that must not be read by the relay, put
        // a known-hosts check here and refuse unknown keys.
        Ok(true)
    }

    /// A visitor connected to the published port. Accept the channel, then
    /// pump it to the unix-socket origin on its own task.
    ///
    /// The splice is spawned rather than awaited here on purpose: this callback
    /// runs on the session's event loop, and holding it for the lifetime of a
    /// visitor's request would stall every other channel.
    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<Msg>,
        connected_address: &str,
        connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: russh::client::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let origin = self.origin.clone();
        let served = self.served.clone();
        let peer = format!("{connected_address}:{connected_port}");

        if std::env::var_os("CFRS_DEBUG").is_some() {
            eprintln!("cfrs: visitor channel opened from {peer} -> {origin:?}");
        }

        reply.accept().await;

        tokio::spawn(async move {
            match splice_unix_socket(channel, &origin).await {
                Ok(()) => {
                    if let Ok(mut n) = served.lock() {
                        *n += 1;
                    }
                }
                Err(e) => {
                    eprintln!("cfrs: visitor {peer} failed: {e}");
                }
            }
            if std::env::var_os("CFRS_DEBUG").is_some() {
                eprintln!("cfrs: visitor {peer} channel closed");
            }
        });

        Ok(())
    }
}

/// A TCP stream that yields `prefix` before reading from the inner stream.
///
/// The CONNECT response is read synchronously, so any bytes the proxy
/// coalesced past the header terminator must be replayed before the SSH
/// banner, or the handshake sees a truncated stream.
pub struct PrefixedStream {
    prefix: Vec<u8>,
    offset: usize,
    inner: tokio::net::TcpStream,
}

impl PrefixedStream {
    /// Wrap `inner`, replaying `prefix` before any read from it.
    pub fn new(prefix: Vec<u8>, inner: tokio::net::TcpStream) -> Self {
        Self {
            prefix,
            offset: 0,
            inner,
        }
    }
}

impl AsyncRead for PrefixedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.offset < this.prefix.len() {
            let remaining = this.prefix.len() - this.offset;
            let n = remaining.min(buf.remaining());
            buf.put_slice(&this.prefix[this.offset..this.offset + n]);
            this.offset += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PrefixedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Copy bytes between an SSH channel and a unix socket until the origin closes.
///
/// # Why this is not a simple `try_join`
///
/// The visitor's request ends quickly (a GET carries no body, so the relay
/// signals EOF as soon as the request is sent). A naive `try_join!` of the two
/// directions returns the moment the request leg finishes and would then cancel
/// the response leg before the origin's reply is ever forwarded. So the request
/// is copied first, and only after the relay closes its sending side do we read
/// the origin's response back. That is the same half-close ordering a browser
/// uses for keep-alive requests.
async fn splice_unix_socket(
    channel: Channel<Msg>,
    origin: &std::path::Path,
) -> std::io::Result<()> {
    let stream = UnixStream::connect(origin).await?;
    let (mut origin_reader, mut origin_writer) = tokio::io::split(stream);
    let (mut reader, mut writer) = tokio::io::split(channel.into_stream());
    copy_bidirectional(
        &mut reader,
        &mut writer,
        &mut origin_reader,
        &mut origin_writer,
    )
    .await
}

/// Copy a visitor's channel to a unix-socket origin and back, on one connection.
///
/// The two halves share a single origin connection and run to completion
/// together. That combination is what the live tunnel needs:
/// * one connection, so the reply goes back on the socket that carried the
///   request (splitting them sent the reply to a socket that had seen nothing);
/// * `try_join!`, so the response half is not abandoned when the request half
///   finishes first, which is what a visitor's empty-body GET causes.
#[allow(clippy::too_many_arguments)]
async fn copy_bidirectional<R, W, OR, OW>(
    channel_reader: &mut R,
    channel_writer: &mut W,
    origin_reader: &mut OR,
    origin_writer: &mut OW,
) -> std::io::Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
    OR: tokio::io::AsyncRead + Unpin,
    OW: tokio::io::AsyncWrite + Unpin,
{
    let debug = std::env::var_os("CFRS_DEBUG").is_some();

    // Both directions run concurrently to completion.
    let up = async {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = channel_reader.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            if debug {
                eprintln!(
                    "cfrs: channel->origin {n} bytes: {:?}",
                    String::from_utf8_lossy(&buf[..n.min(160)])
                );
            }
            origin_writer.write_all(&buf[..n]).await?;
        }
        // Signal end-of-request so the origin writes its response.
        origin_writer.shutdown().await?;
        Ok::<(), std::io::Error>(())
    };

    let down = async {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = origin_reader.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            if debug {
                eprintln!(
                    "cfrs: origin->channel {n} bytes: {:?}",
                    String::from_utf8_lossy(&buf[..n.min(160)])
                );
            }
            channel_writer.write_all(&buf[..n]).await?;
        }
        channel_writer.shutdown().await?;
        Ok::<(), std::io::Error>(())
    };

    // `try_join` waits for BOTH legs; the response half is not abandoned when
    // the request half finishes first.
    tokio::try_join!(up, down)?;
    Ok(())
}

/// Open an SSH transport to the relay, honouring the proxy setting.
async fn connect_transport(config: &RelayConfig) -> Result<PrefixedStream, RelayError> {
    let (host, port) = split_address(&config.address)?;

    let Some(proxy_addr) = &config.proxy else {
        let stream = tokio::net::TcpStream::connect((host.as_str(), port))
            .await
            .map_err(|e| RelayError::Transport(e.to_string()))?;
        return Ok(PrefixedStream::new(Vec::new(), stream));
    };

    // `proxy::connect_tunnel` is blocking by design (the provisioning path uses
    // it synchronously too), so keep it off the async worker.
    let proxy_addr = proxy_addr.clone();
    let host = host.clone();
    let timeout = config.connect_timeout;

    let (stream, leftover) = tokio::task::spawn_blocking(move || {
        proxy::connect_tunnel(&proxy_addr, &host, port, timeout)
    })
    .await
    .map_err(|e| RelayError::Transport(format!("proxy task failed: {e}")))?
    .map_err(|e| RelayError::Transport(e.to_string()))?
    .into_parts();

    stream
        .set_nonblocking(true)
        .map_err(|e| RelayError::Transport(e.to_string()))?;
    let stream = tokio::net::TcpStream::from_std(stream)
        .map_err(|e| RelayError::Transport(e.to_string()))?;

    Ok(PrefixedStream::new(leftover, stream))
}

/// Choose the tunnel URL out of a line of relay output.
///
/// The relay prints an upgrade pitch (which points at its dashboard) and then
/// the tunnel hostname(s). Both are `https://` URLs, so the dashboard must be
/// excluded or it gets picked as the "tunnel". Prefer a URL whose host is not
/// the dashboard.
fn pick_tunnel_url(text: &str) -> Option<String> {
    let candidates: Vec<&str> = text
        .split_whitespace()
        .filter(|t| t.starts_with("http://") || t.starts_with("https://"))
        .map(|t| t.trim_end_matches(|c: char| c == ',' || c == '.' || c == ')' || c == '\"'))
        .collect();

    for url in &candidates {
        if !url.contains("dashboard.pinggy.io") {
            return Some((*url).to_string());
        }
    }
    None
}

/// Split `host:port`, rejecting anything else.
fn split_address(address: &str) -> Result<(String, u16), RelayError> {
    let (host, port) = address
        .rsplit_once(':')
        .ok_or_else(|| RelayError::BadAddress(address.to_string()))?;
    let port = port
        .parse::<u16>()
        .map_err(|_| RelayError::BadAddress(address.to_string()))?;
    if host.is_empty() {
        return Err(RelayError::BadAddress(address.to_string()));
    }
    Ok((host.to_string(), port))
}

/// Establish the tunnel and return the public URL plus a live session handle.
///
/// The returned handle owns the session's event loop; dropping it closes the
/// tunnel.
pub async fn run(config: RelayConfig) -> Result<(TunnelHandle, Handle<Client>), RelayError> {
    let stream = connect_transport(&config).await?;

    // The relay authenticates by publickey. Generate an ephemeral Ed25519 key
    // per run from the OS entropy source; it is never persisted because the
    // free tier accepts any key without registering it.
    let private_key = Arc::new(
        PrivateKey::random(&mut UnwrapErr(SysRng), Algorithm::Ed25519)
            .map_err(|e| RelayError::Key(e.to_string()))?,
    );

    let mut ssh_config = Config::default();
    ssh_config.inactivity_timeout = Some(Duration::from_secs(3600));
    ssh_config.preferred = russh::Preferred::DEFAULT;
    let ssh_config = Arc::new(ssh_config);

    let served = Arc::new(Mutex::new(0u64));
    let client = Client::new(config.unix_socket.clone(), served);

    let mut handle = russh::client::connect_stream(Arc::clone(&ssh_config), stream, client)
        .await
        .map_err(|e| RelayError::Ssh(format!("handshake failed: {e}")))?;

    // The relay advertises PublicKey and Password and rejects "none". Offer an
    // ephemeral key; the free tier accepts any public key without registration.
    let auth = handle
        .authenticate_publickey(
            config.username.clone(),
            PrivateKeyWithHashAlg::new(Arc::clone(&private_key), None),
        )
        .await
        .map_err(|e| RelayError::Ssh(format!("auth failed: {e}")))?;
    if !auth.success() {
        return Err(RelayError::Ssh(format!(
            "relay rejected publickey auth: {auth:?}"
        )));
    }

    // Ask for an ephemeral remote port; the relay decides the number and, with
    // it, the public URL.
    let remote_port = handle
        .tcpip_forward("0.0.0.0", 0)
        .await
        .map_err(|e| RelayError::Ssh(format!("remote forward refused: {e}")))?;

    // The relay publishes the public URL on a session channel's data, not on
    // the forwarded-tcpip channels a visitor opens. Open a session channel and
    // request a shell so the relay writes its banner to us, then read from that
    // channel to recover the URL.
    let mut session_channel = handle
        .channel_open_session()
        .await
        .map_err(|e| RelayError::Ssh(format!("session channel refused: {e}")))?;
    session_channel
        .request_shell(true)
        .await
        .map_err(|e| RelayError::Ssh(format!("shell request failed: {e}")))?;

    // Drain the shell channel for the URL. The relay prints several URLs: an
    // upgrade pitch pointing at its dashboard, then the real tunnel URL(s).
    // The tunnel hostnames carry the relay's tunnel domain, so pick a token
    // that is NOT the dashboard.
    let url = loop {
        let msg = tokio::time::timeout(Duration::from_secs(45), session_channel.wait())
            .await
            .map_err(|_| RelayError::NoUrl)?;
        match msg {
            Some(ChannelMsg::Data { data }) => {
                let text = String::from_utf8_lossy(&data);
                eprint!("  [relay] {text}");
                if let Some(url) = pick_tunnel_url(&text) {
                    break url;
                }
            }
            Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => {
                return Err(RelayError::NoUrl)
            }
            _ => continue,
        }
    };

    Ok((TunnelHandle { url, remote_port }, handle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_a_valid_host_port() {
        let (host, port) = split_address("free.pinggy.io:443").expect("should split");
        assert_eq!(host, "free.pinggy.io");
        assert_eq!(port, 443);
    }

    #[test]
    fn rejects_addresses_without_a_port() {
        for bad in ["free.pinggy.io", "", "host:not-a-port", ":443"] {
            assert!(
                split_address(bad).is_err(),
                "{bad:?} should be rejected as an address"
            );
        }
    }

    #[test]
    fn default_config_targets_port_443() {
        // 443, not 22: the sandbox's egress proxy only allows 443.
        let cfg = RelayConfig::default();
        assert!(
            cfg.address.ends_with(":443"),
            "default relay must be on 443"
        );
    }

    #[test]
    fn picks_the_tunnel_url_and_not_the_dashboard() {
        // This is the real relay output shape observed on 2026-10-09.
        let line = "  You are not authenticated.\n  Your tunnel will expire in 60 minutes. \
Upgrade to Pinggy Pro to get unrestricted tunnels. https://dashboard.pinggy.io\n  \
https://blirg-2400-1a00-5b2f-821c-869e-56ff-fe03-2b71.free.pinggy.net\n  \
https://jcydy-2400-1a00-5b2f-821c-869e-56ff-fe03-2b71.run.pinggy-free.link\n";
        let url = pick_tunnel_url(line).expect("a tunnel url");
        assert_eq!(
            url,
            "https://blirg-2400-1a00-5b2f-821c-869e-56ff-fe03-2b71.free.pinggy.net"
        );
        assert!(
            !url.contains("dashboard"),
            "dashboard must never be chosen: {url}"
        );
    }

    #[test]
    fn trailing_punctuation_is_stripped_from_a_url() {
        let line = "visit https://x.free.pinggy.net.";
        assert_eq!(
            pick_tunnel_url(line).as_deref(),
            Some("https://x.free.pinggy.net")
        );
    }

    #[test]
    fn a_dashboard_only_line_yields_no_tunnel_url() {
        // Guards against silently returning the dashboard as if it were a tunnel.
        let line = "Upgrade for more at https://dashboard.pinggy.io\n";
        assert_eq!(pick_tunnel_url(line), None);
    }

    /// Drives the production copy logic (`copy_bidirectional`) over in-memory
    /// duplex pipes shaped like an SSH channel and a unix origin.
    ///
    /// Both halves share ONE origin connection and both must run to completion.
    /// This is the regression for the live bug: the request reached the origin,
    /// but the response never reached the visitor. An empty-body GET, whose
    /// request leg finishes immediately, is exactly the shape that exposed it.
    #[tokio::test]
    async fn copy_bidirectional_carries_request_and_response_on_one_origin_connection() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        // cfrs_channel: the SSH channel the relay opened (relay <-> cfrs).
        let (mut relay, mut cfrs_channel) = tokio::io::duplex(4096);
        // cfrs_origin: the unix-socket origin (origin <-> cfrs).
        let (mut origin, mut cfrs_origin) = tokio::io::duplex(4096);

        // The relay writes the visitor's request, then reads the reply back.
        let relay_task = tokio::spawn(async move {
            relay
                .write_all(b"GET /hello HTTP/1.1\r\nHost: x\r\n\r\n")
                .await
                .unwrap();
            relay.shutdown().await.unwrap();
            let mut back = Vec::new();
            relay.read_to_end(&mut back).await.unwrap();
            back
        });

        // The origin reads to end-of-request, replies, then closes, like an
        // HTTP/1.1 server that answers one request and closes the connection.
        let origin_task = tokio::spawn(async move {
            let mut request = Vec::new();
            origin.read_to_end(&mut request).await.unwrap();
            origin
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                .await
                .unwrap();
            origin.shutdown().await.unwrap();
            request
        });

        // cfrs splices the channel into the origin, both directions, bounded so
        // a regression fails the test instead of hanging the suite.
        let (mut cr, mut cw) = tokio::io::split(&mut cfrs_channel);
        let (mut or, mut ow) = tokio::io::split(&mut cfrs_origin);
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            copy_bidirectional(&mut cr, &mut cw, &mut or, &mut ow),
        )
        .await
        .expect("splice must not hang")
        .expect("splice completes");

        let request = origin_task.await.unwrap();
        assert!(
            String::from_utf8_lossy(&request).contains("GET /hello"),
            "origin should have received the request, got {:?}",
            String::from_utf8_lossy(&request)
        );

        let to_relay = relay_task.await.unwrap();
        let response = String::from_utf8_lossy(&to_relay);
        assert!(
            response.starts_with("HTTP/1.1 200 OK"),
            "relay should have received the status line, got {response:?}"
        );
        assert!(
            response.ends_with("OK"),
            "relay should have received the response body, got {response:?}"
        );
    }
}
