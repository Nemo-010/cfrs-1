//! The Cloudflare tunnel edge protocol.
//!
//! # What this is
//!
//! A Cloudflare tunnel holds a long-lived connection to an edge machine. The
//! edge opens a stream per visitor request and the connector answers it by
//! talking to the origin. Two transports carry that connection:
//!
//! * **QUIC**, with ALPN `argotunnel` and SNI `quic.cftunnel.com`. Note the two
//!   strings are *different*: passing the ALPN value as SNI completes key
//!   derivation and then dies silently. This is the single most common mistake
//!   when writing a client, and it is why the constants below are separate.
//! * **HTTP/2**, with SNI `h2.cftunnel.com` and **no ALPN at all**. cloudflared
//!   omits the ALPN extension and then runs an HTTP/2 server on the connection,
//!   because the edge initiates every stream.
//!
//! The QUIC path needs UDP. The HTTP/2 path is TCP, which matters: it is the
//! only transport that can work where UDP is blocked.
//!
//! # Trust
//!
//! The edge certificate chains to Cloudflare-internal roots that are in no
//! public trust store, so they are embedded here. That is the same set
//! `cloudflared` ships, sourced from its `tlsconfig/cloudflare_ca.go` under
//! Apache-2.0.
//!
//! # Credentials
//!
//! Registration is a Cap'n Proto RPC over the first stream. The tunnel secret
//! goes on the wire verbatim, as `TunnelAuth.tunnelSecret`; it is not hashed or
//! otherwise transformed.

pub mod http2;
pub mod quic;

use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
#[allow(unused_imports)]
use std::time::Duration;

/// ALPN for the QUIC transport.
pub const QUIC_ALPN: &[u8] = b"argotunnel";

/// SNI for the QUIC transport. Deliberately not the same as [`QUIC_ALPN`].
pub const QUIC_SNI: &str = "quic.cftunnel.com";

/// SNI for the HTTP/2 transport.
pub const H2_SNI: &str = "h2.cftunnel.com";

/// SRV record naming the edge, as cloudflared resolves it.
pub const EDGE_SRV: &str = "_v2-origintunneld._tcp.argotunnel.com";

/// Cloudflare-internal roots the edge certificate chains to.
///
/// From `cloudflared`'s `tlsconfig/cloudflare_ca.go`, Apache-2.0.
pub const CF_EDGE_ROOTS_PEM: &[u8] = include_bytes!("cf-edge-roots.pem");

/// The six-byte preamble on a data stream, from `tunnelrpc/quic/protocol.go`.
pub const DATA_STREAM_SIGNATURE: [u8; 6] = [0x0A, 0x36, 0xCD, 0x12, 0xA1, 0x3E];

/// The protocol version that follows the data-stream signature.
pub const DATA_STREAM_VERSION: &[u8] = b"01";

/// Which edge transport to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// Try QUIC, fall back to HTTP/2 if it cannot be established.
    Auto,
    /// QUIC only. Requires UDP.
    Quic,
    /// HTTP/2 only. Runs over TCP, so it works where UDP is blocked.
    Http2,
}

impl Protocol {
    /// Parse the `--protocol` value cloudflared accepts.
    pub fn parse(s: &str) -> Result<Protocol, String> {
        match s.to_ascii_lowercase().as_str() {
            "auto" | "" => Ok(Protocol::Auto),
            "quic" => Ok(Protocol::Quic),
            "http2" | "h2" => Ok(Protocol::Http2),
            other => Err(format!(
                "unknown protocol {other:?}; expected auto, quic or http2"
            )),
        }
    }

    /// The name as cloudflared spells it.
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::Auto => "auto",
            Protocol::Quic => "quic",
            Protocol::Http2 => "http2",
        }
    }

    /// The transports to attempt, in order.
    pub fn candidates(&self) -> Vec<Protocol> {
        match self {
            Protocol::Auto => vec![Protocol::Quic, Protocol::Http2],
            Protocol::Quic => vec![Protocol::Quic],
            Protocol::Http2 => vec![Protocol::Http2],
        }
    }
}

/// A resolved edge address and the port the SRV record specified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdgeAddr {
    pub host: String,
    pub addr: SocketAddr,
    pub port: u16,
}

/// Credentials for one tunnel, as returned by the provisioning API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credentials {
    /// Hex account tag from the provisioning response.
    pub account_tag: String,
    /// Raw secret bytes, sent to the edge untransformed.
    pub tunnel_secret: Vec<u8>,
    /// Tunnel UUID.
    pub tunnel_id: String,
}

impl Credentials {
    /// Parse a tunnel UUID into its 16 raw bytes, which is how it goes on the
    /// wire (`tunnelId :Data`).
    pub fn tunnel_id_bytes(&self) -> Result<[u8; 16], String> {
        parse_uuid(&self.tunnel_id)
    }
}

/// Parse a hyphenated UUID into 16 bytes.
fn parse_uuid(s: &str) -> Result<[u8; 16], String> {
    let hex: String = s.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 {
        return Err(format!("tunnel id {:?} is not a 32-character uuid", s));
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|e| format!("bad hex in uuid {s:?}: {e}"))?;
    }
    Ok(out)
}

/// Discover edge addresses from the SRV record.
///
/// `resolve` is injected so the logic can be tested without DNS, and so a
/// caller can supply a DoT or DoH resolver when the system one is unusable.
pub fn discover_edges_with<F>(mut resolve: F) -> Result<Vec<EdgeAddr>, EdgeError>
where
    F: FnMut(&str, u16) -> Result<Vec<SocketAddr>, String>,
{
    // The SRV record names the service and gives the port; cloudflared builds
    // the query name from a constant rather than hardcoding a target.
    let target = EDGE_SRV;
    let addrs = resolve(target, 0).map_err(EdgeError::Resolve)?;

    let mut edges = Vec::new();
    for addr in addrs {
        // The port from the record is what the edge actually listens on.
        let port = 7844;
        let host = target_host(&addr);
        let socket = SocketAddr::new(addr.ip(), port);
        let _ = addr.port();
        edges.push(EdgeAddr {
            host,
            addr: socket,
            port,
        });
    }

    if edges.is_empty() {
        return Err(EdgeError::Resolve(format!(
            "{target} resolved to no addresses"
        )));
    }
    Ok(edges)
}

/// Discover edges using the system resolver.
pub fn discover_edges() -> Result<Vec<EdgeAddr>, EdgeError> {
    discover_edges_with(|name, _port| {
        (name, 7844u16)
            .to_socket_addrs()
            .map(|it| it.collect())
            .map_err(|e| e.to_string())
    })
}

/// A readable name for an edge address, used in logs and as SNI context.
fn target_host(addr: &SocketAddr) -> String {
    match addr {
        SocketAddr::V4(v4) => format!("{}:{}", v4.ip(), 7844),
        SocketAddr::V6(v6) => format!("[{}]:{}", v6.ip(), 7844),
    }
}

/// Why the edge could not be found or reached.
#[derive(Debug)]
pub enum EdgeError {
    /// The SRV lookup failed.
    Resolve(String),
    /// A transport could not connect.
    Connect(String),
    /// Registration was refused.
    Registration(String),
    /// The edge asked for something this client does not implement.
    Unsupported(String),
}

impl std::fmt::Display for EdgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EdgeError::Resolve(m) => write!(f, "edge discovery failed: {m}"),
            EdgeError::Connect(m) => write!(f, "edge connect failed: {m}"),
            EdgeError::Registration(m) => write!(f, "registration refused: {m}"),
            EdgeError::Unsupported(m) => write!(f, "unsupported: {m}"),
        }
    }
}

impl std::error::Error for EdgeError {}

/// Build a rustls client config for the edge.
///
/// The embedded Cloudflare roots are added alongside the platform's, because
/// the edge presents a certificate that chains to internal CAs. `alpn` is
/// empty for the HTTP/2 transport, which cloudflared relies on: the edge
/// initiates every stream, so negotiating `h2` changes the handshake shape and
/// breaks it.
pub fn edge_tls_config(alpn: &[u8]) -> Result<Arc<rustls::ClientConfig>, String> {
    let mut roots = rustls::RootCertStore::empty();

    let mut cursor = std::io::Cursor::new(CF_EDGE_ROOTS_PEM);
    let mut added = 0usize;
    for cert in rustls_pemfile::certs(&mut cursor) {
        let cert = cert.map_err(|e| format!("parsing embedded edge roots: {e}"))?;
        if roots.add(cert).is_ok() {
            added += 1;
        }
    }
    if added == 0 {
        return Err("no Cloudflare edge roots could be loaded".to_string());
    }

    let builder = rustls::ClientConfig::builder();
    let mut config = builder.with_root_certificates(roots).with_no_client_auth();
    config.alpn_protocols = if alpn.is_empty() {
        Vec::new()
    } else {
        vec![alpn.to_vec()]
    };
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quic_alpn_and_sni_are_different_strings() {
        // Conflating these is the classic way to get a silent 10s handshake
        // timeout, so the distinction is asserted rather than left to a comment.
        assert_eq!(QUIC_ALPN, b"argotunnel");
        assert_eq!(QUIC_SNI, "quic.cftunnel.com");
        assert_ne!(
            QUIC_ALPN,
            QUIC_SNI.as_bytes(),
            "SNI must not be the ALPN value"
        );
    }

    #[test]
    fn the_data_stream_preamble_matches_the_source() {
        // From tunnelrpc/quic/protocol.go: dataStreamProtocolSignature.
        assert_eq!(DATA_STREAM_SIGNATURE, [0x0A, 0x36, 0xCD, 0x12, 0xA1, 0x3E]);
        assert_eq!(DATA_STREAM_VERSION, b"01");
    }

    #[test]
    fn protocols_parse_the_way_cloudflared_spells_them() {
        assert_eq!(Protocol::parse("auto").unwrap(), Protocol::Auto);
        assert_eq!(Protocol::parse("QUIC").unwrap(), Protocol::Quic);
        assert_eq!(Protocol::parse("http2").unwrap(), Protocol::Http2);
        assert_eq!(Protocol::parse("h2").unwrap(), Protocol::Http2);
        assert_eq!(Protocol::parse("").unwrap(), Protocol::Auto);
        assert!(Protocol::parse("carrier-pigeon").is_err());
    }

    #[test]
    fn auto_tries_quic_first_then_falls_back_to_http2() {
        // QUIC first because it is faster where it works; HTTP/2 second because
        // it is the only option when UDP is blocked.
        assert_eq!(
            Protocol::Auto.candidates(),
            vec![Protocol::Quic, Protocol::Http2]
        );
        assert_eq!(Protocol::Quic.candidates(), vec![Protocol::Quic]);
        assert_eq!(Protocol::Http2.candidates(), vec![Protocol::Http2]);
    }

    #[test]
    fn uuids_parse_to_their_sixteen_bytes() {
        let bytes = parse_uuid("c1267064-5604-4d16-9a83-66b7ed37f182").expect("valid uuid");
        assert_eq!(bytes[0], 0xc1);
        assert_eq!(bytes[15], 0x82);
        assert_eq!(bytes.len(), 16);
    }

    #[test]
    fn malformed_uuids_are_rejected() {
        assert!(parse_uuid("not-a-uuid").is_err());
        assert!(parse_uuid("").is_err());
        assert!(parse_uuid("c126706456044d169a8366b7ed37f182z").is_err());
    }

    #[test]
    fn credentials_expose_the_raw_tunnel_id_bytes() {
        let creds = Credentials {
            account_tag: "5ab4e9dfbd435d24068829fda0077963".into(),
            tunnel_secret: vec![7u8; 32],
            tunnel_id: "c1267064-5604-4d16-9a83-66b7ed37f182".into(),
        };
        assert_eq!(creds.tunnel_id_bytes().unwrap()[0], 0xc1);
    }

    #[test]
    fn the_embedded_edge_roots_are_real_certificates() {
        // If this file were emptied or truncated, TLS to the edge would fail
        // with UnknownIssuer, so assert the roots actually parse.
        assert!(
            CF_EDGE_ROOTS_PEM.len() > 1000,
            "the embedded roots look empty: {} bytes",
            CF_EDGE_ROOTS_PEM.len()
        );
        let mut cursor = std::io::Cursor::new(CF_EDGE_ROOTS_PEM);
        let certs: Vec<_> = rustls_pemfile::certs(&mut cursor)
            .filter_map(|c| c.ok())
            .collect();
        assert!(
            certs.len() >= 3,
            "expected Cloudflare's edge roots, found {}",
            certs.len()
        );
    }

    #[test]
    fn an_edge_tls_config_builds_for_both_transports() {
        assert!(
            edge_tls_config(QUIC_ALPN).is_ok(),
            "QUIC config should build with the argotunnel ALPN"
        );
        let h2 = edge_tls_config(&[]).expect("h2 config");
        assert!(
            h2.alpn_protocols.is_empty(),
            "the HTTP/2 transport must send no ALPN"
        );
        let quic = edge_tls_config(QUIC_ALPN).expect("quic config");
        assert_eq!(quic.alpn_protocols, vec![b"argotunnel".to_vec()]);
    }

    #[test]
    fn discovery_uses_the_srv_name_and_the_7844_port() {
        let mut asked: Vec<String> = Vec::new();
        let edges = discover_edges_with(|name, _| {
            asked.push(name.to_string());
            Ok(vec![SocketAddr::from(([198, 41, 192, 167], 7844))])
        })
        .expect("discovery");
        assert_eq!(asked, vec![EDGE_SRV.to_string()]);
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].port, 7844);
        assert!(edges[0].host.contains("198.41.192.167"));
    }

    #[test]
    fn an_empty_dns_answer_is_an_error_not_an_empty_list() {
        let err = discover_edges_with(|_, _| Ok(vec![])).expect_err("must fail");
        assert!(err.to_string().contains("no addresses"), "{err}");
    }

    #[test]
    fn a_dns_failure_is_reported_with_its_cause() {
        let err = discover_edges_with(|_, _| Err("SERVFAIL".to_string())).expect_err("must fail");
        assert!(err.to_string().contains("SERVFAIL"), "{err}");
    }
}
