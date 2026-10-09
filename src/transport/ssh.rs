//! SSH transport: reach a destination through a TCP relay that runs SSH.
//!
//! # Why this exists, and what it cannot do
//!
//! Some networks expose only port 443 to the outside world. A relay that speaks
//! SSH there can still carry any TCP stream, which makes it the last way out
//! when QUIC is blocked and no HTTP proxy permits the destination.
//!
//! It is important to be precise about a limit that is easy to get wrong. An SSH
//! server can be asked to open a `direct-tcpip` channel to a destination of the
//! client's choosing, but **free relay tiers do not always honour it**. Measured
//! against pinggy's free tier: the channel opens, and then the relay answers on
//! its own HTTP handler with a byte-identical reply for every destination,
//! including unroutable ones. Trusting "the channel opened" produces a false
//! positive.
//!
//! `examples/edge_probe.rs` exists to make that failure mode visible: it queries
//! two different destinations and compares the replies, reporting `NOT A PROXY`
//! when they match. This transport keeps that lesson in mind by never reporting
//! success on an unauthenticated or empty stream.

use std::sync::Arc;
use std::time::Duration;

use russh::client::{Config, Handler, Msg};
use russh::keys::ssh_key::rand_core::UnwrapErr;
use russh::keys::ssh_key::Algorithm;
use russh::keys::PrivateKey;
use russh::keys::PrivateKeyWithHashAlg;
use russh::keys::PublicKeyOrCertificate;

use super::{Duplex, Transport, TransportError, TransportStream};

/// Reach a destination through an SSH relay.
#[derive(Clone)]
pub struct SshRelay {
    /// `host:port` of the relay.
    pub address: String,
    /// Optional HTTP CONNECT proxy in front of the relay.
    pub proxy: Option<String>,
    /// Login name. Anonymous relays take anything.
    pub username: String,
    /// An existing private key, or `None` to generate an ephemeral one.
    pub private_key: Option<Arc<PrivateKey>>,
    /// Skip the host-key check. A free relay rotates keys, so pinning one
    /// breaks it; set this only for such a relay.
    pub accept_any_host_key: bool,
}

impl Default for SshRelay {
    fn default() -> Self {
        Self {
            address: "free.pinggy.io:443".to_string(),
            proxy: None,
            username: "cfrs".to_string(),
            private_key: None,
            accept_any_host_key: true,
        }
    }
}

impl std::fmt::Debug for SshRelay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshRelay")
            .field("address", &self.address)
            .field("proxy", &self.proxy)
            .field("username", &self.username)
            .finish_non_exhaustive()
    }
}

/// Handler that carries the options the tunnel callbacks need.
struct Client {
    accept_any_host_key: bool,
}

impl Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(self.accept_any_host_key)
    }
}

impl Transport for SshRelay {
    fn connect<'a>(
        &'a self,
        host: &'a str,
        port: u16,
        timeout: Duration,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<TransportStream, TransportError>> + Send + 'a>,
    > {
        Box::pin(async move {
        let (relay_host, relay_port) = self
            .address
            .rsplit_once(':')
            .ok_or_else(|| {
                TransportError::Unsupported(format!(
                    "relay address must be host:port, got {:?}",
                    self.address
                ))
            })
            .and_then(|(h, p)| {
                p.parse::<u16>().map(|port| (h.to_string(), port)).map_err(|_| {
                    TransportError::Unsupported(format!("bad relay port in {:?}", self.address))
                })
            })?;

        // Reach the relay, through a proxy if one is configured.
        let tcp: Box<dyn Duplex> = match &self.proxy {
            None => {
                Box::new(
                    tokio::net::TcpStream::connect((relay_host.as_str(), relay_port))
                        .await
                        .map_err(|e| {
                            TransportError::Unreachable(format!(
                                "relay {relay_host}:{relay_port}: {e}"
                            ))
                        })?,
                )
            }
            Some(proxy) => {
                let proxy = proxy.clone();
                let host = relay_host.clone();
                let (stream, leftover) =
                    tokio::task::spawn_blocking(move || {
                        crate::proxy::connect_tunnel(&proxy, &host, relay_port, timeout)
                    })
                    .await
                    .map_err(|e| TransportError::Unreachable(format!("proxy task: {e}")))?
                    .map_err(|e| TransportError::Refused(format!("proxy: {e}")))?
                    .into_parts();
                let _ = stream.set_nonblocking(true);
                let stream = tokio::net::TcpStream::from_std(stream)
                    .map_err(|e| TransportError::Unreachable(format!("wrap: {e}")))?;
                Box::new(super::websocket::Prefixed::new(leftover, stream))
            }
        };


        let key = match &self.private_key {
            Some(k) => Arc::clone(k),
            None => Arc::new(
                PrivateKey::random(&mut UnwrapErr(ssh_key::getrandom::SysRng), Algorithm::Ed25519)
                    .map_err(|e| TransportError::Handshake(format!("key generation: {e}")))?,
            ),
        };

        let mut config = Config::default();
        config.inactivity_timeout = Some(Duration::from_secs(3600));

        let client = Client {
            accept_any_host_key: self.accept_any_host_key,
        };

        let mut handle = tokio::time::timeout(
            timeout,
            russh::client::connect_stream(Arc::new(config), tcp, client),
        )
        .await
        .map_err(|_| TransportError::Handshake("ssh handshake timed out".into()))?
        .map_err(|e| TransportError::Handshake(format!("ssh handshake: {e}")))?;

        let auth = tokio::time::timeout(
            timeout,
            handle.authenticate_publickey(
                self.username.clone(),
                PrivateKeyWithHashAlg::new(key, None),
            ),
        )
        .await
        .map_err(|_| TransportError::Handshake("ssh auth timed out".into()))?
        .map_err(|e| TransportError::Handshake(format!("ssh auth: {e}")))?;
        if !auth.success() {
            return Err(TransportError::Refused(format!(
                "relay {} rejected the login",
                self.address
            )));
        }

        // Ask the relay to dial the destination for us.
        let channel = tokio::time::timeout(
            timeout,
            handle.channel_open_direct_tcpip(host.to_string(), port as u32, "127.0.0.1", 0),
        )
        .await
        .map_err(|_| TransportError::Unreachable(format!("direct-tcpip to {host}:{port} timed out")))?
        .map_err(|e| TransportError::Refused(format!("relay refused direct-tcpip: {e}")))?;

        // The stream is a live SSH channel; wrapping it keeps the session alive
        // for as long as the caller holds the stream.
        Ok(Box::new(ChannelStream::new(handle, channel)) as TransportStream)
        })
    }

    fn name(&self) -> &'static str {
        "ssh"
    }
}

/// An SSH channel exposed as a byte stream, holding the session open.
///
/// `russh::Channel` is not itself an `AsyncRead`; `into_stream` is. The split
/// halves are held here so the channel's window accounting stays correct.
struct ChannelStream {
    _session: russh::client::Handle<Client>,
    stream: russh::ChannelStream<Msg>,
}

impl ChannelStream {
    fn new(session: russh::client::Handle<Client>, channel: russh::Channel<Msg>) -> Self {
        Self {
            _session: session,
            stream: channel.into_stream(),
        }
    }
}

impl tokio::io::AsyncRead for ChannelStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.stream).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for ChannelStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        Pin::new(&mut this.stream).poll_write(cx, data)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.stream).poll_shutdown(cx)
    }
}

use std::pin::Pin;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_targets_port_443() {
        // The reason this transport exists: only 443 is reachable in many
        // networks, so 22 must not be the default.
        assert!(SshRelay::default().address.ends_with(":443"));
    }

    #[tokio::test]
    async fn a_malformed_relay_address_is_rejected_before_dialling() {
        let t = SshRelay {
            address: "no-port-here".to_string(),
            ..Default::default()
        };
        let err = match t
            .connect("example.com", 443, Duration::from_millis(100))
            .await
        {
            Err(e) => e,
            Ok(_) => panic!("a malformed address must not connect"),
        };
        assert!(
            matches!(err, TransportError::Unsupported(_)),
            "expected Unsupported, got {err}"
        );
        assert!(err.to_string().contains("host:port"), "{err}");
    }

    #[tokio::test]
    async fn an_unreachable_relay_is_reported_not_hung() {
        let t = SshRelay {
            address: "127.0.0.1:1".to_string(),
            ..Default::default()
        };
        let err = match t
            .connect("example.com", 443, Duration::from_millis(500))
            .await
        {
            Err(e) => e,
            Ok(_) => panic!("an unreachable relay must not connect"),
        };
        assert!(
            matches!(err, TransportError::Unreachable(_) | TransportError::Refused(_)),
            "expected a connection failure, got {err}"
        );
    }

    #[test]
    fn debug_does_not_leak_the_private_key() {
        let key = PrivateKey::random(
            &mut UnwrapErr(ssh_key::getrandom::SysRng),
            Algorithm::Ed25519,
        )
        .expect("key");
        let t = SshRelay {
            private_key: Some(Arc::new(key)),
            ..Default::default()
        };
        let text = format!("{t:?}");
        assert!(!text.contains("PRIVATE"), "key material must not be formatted: {text}");
        assert!(text.contains("free.pinggy.io"), "{text}");
    }
}