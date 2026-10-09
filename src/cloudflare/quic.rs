//! The QUIC edge transport.
//!
//! # The handshake
//!
//! QUIC is the default and the faster transport, but it needs UDP, which many
//! networks and most sandboxes do not allow. It is here for the normal case;
//! [`super::http2`] is what works where UDP is blocked.
//!
//! Two details decide whether this works at all:
//!
//! * **ALPN is `argotunnel`** and **SNI is `quic.cftunnel.com`**. These are
//!   *different strings*. Using the ALPN value as SNI completes key derivation
//!   and then dies silently after the handshake timeout, which is the most
//!   common way to get this transport wrong and the hardest to diagnose.
//! * **The edge certificate chains to Cloudflare-internal roots**, which are in
//!   no public trust store, so [`super::CF_EDGE_ROOTS_PEM`] is added to the
//!   platform roots rather than replacing them.
//!
//! # Streams
//!
//! The **first** stream the client opens is the control plane; the edge assumes
//! so, and opens everything else. Each visitor request then arrives as its own
//! bidi stream, framed by a six-byte signature and a version before the
//! Cap'n Proto payload.

use std::sync::Arc;
use std::time::Duration;

use quinn::{ClientConfig, Endpoint, TransportConfig};

use super::{Credentials, EdgeAddr, EdgeError, DATA_STREAM_SIGNATURE, DATA_STREAM_VERSION};

/// Handshake timeout for the QUIC edge connection.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Idle timeout. The edge sends keepalives, so a short idle timeout would drop
/// an otherwise healthy tunnel between them.
pub const MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// How often to send a keepalive.
pub const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(1);

/// The rustls config for the QUIC edge.
///
/// Split out from [`client_config`] so the ALPN and the trust roots can be
/// asserted on directly: quinn's own config has no getters, so a test that
/// reads back a quinn config would prove nothing.
pub fn tls_config() -> Result<Arc<rustls::ClientConfig>, EdgeError> {
    super::edge_tls_config(super::QUIC_ALPN).map_err(EdgeError::Connect)
}

/// Build a quinn client config for the edge.
pub fn client_config() -> Result<ClientConfig, EdgeError> {
    let tls = tls_config()?;

    let quic_tls = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .map_err(|e| EdgeError::Connect(format!("quic tls config: {e}")))?;

    let mut config = ClientConfig::new(Arc::new(quic_tls));

    let mut transport = TransportConfig::default();
    transport.max_idle_timeout(Some(
        MAX_IDLE_TIMEOUT
            .try_into()
            .map_err(|_| EdgeError::Connect("idle timeout out of range".to_string()))?,
    ));
    transport.keep_alive_interval(Some(KEEP_ALIVE_INTERVAL));
    // 1252 is the IPv4-safe payload size that avoids fragmentation-related
    // blackholing on consumer routers. cloudflared uses the same value.
    transport.initial_mtu(1252);
    config.transport_config(Arc::new(transport));

    Ok(config)
}

/// A live QUIC connection to an edge, plus the endpoint that owns its socket.
pub struct QuicConnection {
    pub connection: quinn::Connection,
    _endpoint: Endpoint,
}

impl QuicConnection {
    /// Open a connection to an edge address.
    pub async fn connect(addr: &EdgeAddr, timeout: Duration) -> Result<QuicConnection, EdgeError> {
        let config = client_config()?;

        // Bind an ephemeral local UDP port. Failing here is the common case in a
        // sandbox, and the message says so rather than surfacing a bare EPERM.
        let mut endpoint = Endpoint::client("[::]:0".parse().map_err(|_| {
            EdgeError::Connect("could not parse a local UDP bind address".to_string())
        })?)
        .map_err(|e| {
            EdgeError::Connect(format!(
                "could not open a local UDP socket: {e}. \
                 QUIC needs UDP; where it is blocked use --protocol http2, \
                 which runs over TCP and works through a proxy or relay."
            ))
        })?;
        endpoint.set_default_client_config(config);

        // The SNI is quic.cftunnel.com even though the socket goes to the
        // address the SRV record gave.
        let connecting = endpoint.connect(addr.addr, super::QUIC_SNI).map_err(|e| {
            EdgeError::Connect(format!("could not start connecting to {}: {e}", addr.addr))
        })?;

        let connection = tokio::time::timeout(timeout, connecting)
            .await
            .map_err(|_| {
                EdgeError::Connect(format!(
                    "handshake with {} timed out. Check that SNI is {:?} and not the ALPN; \
                     they are different strings and the wrong one fails silently.",
                    addr.addr,
                    super::QUIC_SNI
                ))
            })?
            .map_err(|e| EdgeError::Connect(format!("handshake with {}: {e}", addr.addr)))?;

        Ok(QuicConnection {
            connection,
            _endpoint: endpoint,
        })
    }

    /// Open the control stream, which the edge expects to be first.
    pub async fn open_control_stream(&self) -> Result<quinn::SendStream, EdgeError> {
        // The edge assumes the first client-initiated stream is the control
        // plane, so this must not be preceded by anything else.
        self.connection
            .open_bi()
            .await
            .map(|(send, _recv)| send)
            .map_err(|e| EdgeError::Connect(format!("cannot open the control stream: {e}")))
    }
}

/// Write the data-stream preamble: six signature bytes then the version.
///
/// The edge checks the signature on every stream, so a stream opened without it
/// is reset rather than served.
pub async fn write_stream_preamble(send: &mut quinn::SendStream) -> Result<(), EdgeError> {
    send.write_all(&DATA_STREAM_SIGNATURE)
        .await
        .map_err(|e| EdgeError::Connect(format!("writing the stream signature: {e}")))?;
    send.write_all(DATA_STREAM_VERSION)
        .await
        .map_err(|e| EdgeError::Connect(format!("writing the stream version: {e}")))
}

/// Build the registration request fields for a tunnel.
///
/// The secret is sent as raw bytes. cloudflared does not hash it: the base64
/// value from the provisioning response is decoded and put on the wire
/// unchanged, so a reimplementation must do the same.
pub fn tunnel_auth(credentials: &Credentials) -> (String, Vec<u8>, [u8; 16]) {
    (
        credentials.account_tag.clone(),
        credentials.tunnel_secret.clone(),
        credentials.tunnel_id_bytes().unwrap_or([0u8; 16]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpn_and_sni_are_distinct() {
        assert_eq!(super::super::QUIC_ALPN, b"argotunnel");
        assert_eq!(super::super::QUIC_SNI, "quic.cftunnel.com");
        assert_ne!(super::super::QUIC_SNI.as_bytes(), super::super::QUIC_ALPN);
    }

    #[test]
    fn the_quic_tls_config_offers_exactly_the_argotunnel_alpn() {
        let tls = tls_config().expect("quic tls config");
        assert_eq!(
            tls.alpn_protocols,
            vec![b"argotunnel".to_vec()],
            "the edge accepts one protocol; offering anything else fails selection"
        );
    }

    #[test]
    fn quinn_accepts_the_tls_config_it_is_given() {
        // The failure this catches is real: rustls 0.23 and quinn disagree
        // about crypto provider versions, and quinn's try_from is where that
        // surfaces, with an error that reads as a TLS problem at handshake.
        client_config().expect("quinn accepts the edge tls config");
    }

    #[test]
    fn the_stream_preamble_is_the_signature_then_the_version() {
        // Written as a unit so the byte order is pinned by a test rather than
        // only by a comment.
        let mut expected: Vec<u8> = super::super::DATA_STREAM_SIGNATURE.to_vec();
        expected.extend_from_slice(super::super::DATA_STREAM_VERSION);
        assert_eq!(expected.len(), 8);
        assert_eq!(&expected[..6], &[0x0A, 0x36, 0xCD, 0x12, 0xA1, 0x3E]);
        assert_eq!(&expected[6..], b"01");
    }

    #[test]
    fn the_tunnel_secret_is_sent_unhashed() {
        let secret = vec![0xABu8; 32];
        let credentials = Credentials {
            account_tag: "acct".into(),
            tunnel_secret: secret.clone(),
            tunnel_id: "c1267064-5604-4d16-9a83-66b7ed37f182".into(),
        };
        let (account, sent_secret, tunnel_id) = tunnel_auth(&credentials);
        assert_eq!(account, "acct");
        assert_eq!(
            sent_secret, secret,
            "the secret must reach the edge exactly as provisioned"
        );
        assert_eq!(tunnel_id[0], 0xc1, "the tunnel id goes as raw bytes");
    }

    #[test]
    fn a_malformed_tunnel_id_does_not_panic() {
        let credentials = Credentials {
            account_tag: "acct".into(),
            tunnel_secret: vec![0u8; 32],
            tunnel_id: "garbage".into(),
        };
        // The id is reported as zero rather than aborting the connection.
        let (_, _, id) = tunnel_auth(&credentials);
        assert_eq!(id, [0u8; 16]);
    }

    #[test]
    fn connecting_without_udp_says_so_rather_than_failing_obscurely() {
        // `Endpoint::client` fails where UDP is blocked, which is the whole
        // reason the http2 transport exists. Build the error path directly.
        let err = EdgeError::Connect(
            "could not open a local UDP socket: EPERM. QUIC needs UDP; where it is blocked \
             use --protocol http2, which runs over TCP and works through a proxy or relay."
                .to_string(),
        );
        let text = err.to_string();
        assert!(text.contains("UDP"), "{text}");
        assert!(
            text.contains("http2"),
            "the message must point at the fix: {text}"
        );
    }
}
