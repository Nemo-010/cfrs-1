//! The HTTP/2 edge transport.
//!
//! # Why this is the important one
//!
//! The Cloudflare edge accepts the tunnel protocol on two transports. QUIC
//! (ALPN `argotunnel`) is the default and the faster, but it needs UDP. HTTP/2
//! is TCP, and TCP is reachable in places UDP is not: through an HTTP CONNECT
//! proxy, through an SSH relay, and on any network that blocks or drops
//! outbound UDP. So a client that only speaks QUIC works on a normal host and
//! fails silently in exactly the constrained environments where a tunnel is
//! most useful.
//!
//! # The handshake, which is not the usual one
//!
//! Normally a client offers `h2` in ALPN and speaks HTTP/2 as the client. This
//! transport does neither:
//!
//! * **SNI is `h2.cftunnel.com`** while the connection is opened to an IP from
//!   the SRV record, so TLS must be configured with that name and the address
//!   taken separately.
//! * **No ALPN is offered at all.** cloudflared omits the extension and then
//!   runs an HTTP/2 *server* on the connection, because the edge initiates every
//!   stream. Offering `h2` changes the handshake and breaks it.
//! * **The edge opens the control stream**, identified by a request header
//!   `Cf-Cloudflared-Proxy-Connection-Upgrade: control-stream`. There is no
//!   client-initiated registration call; the client answers the request.
//!
//! Getting any one of those wrong produces a connection that opens and then
//! does nothing, which is why each is asserted in the tests here.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use super::{EdgeAddr, H2_SNI};

/// The header that marks a stream as the control stream rather than a visitor.
pub const CONTROL_STREAM_HEADER: &str = "Cf-Cloudflared-Proxy-Connection-Upgrade";

/// The value that header carries for the control stream.
pub const CONTROL_STREAM_VALUE: &str = "control-stream";

/// Header carrying the visitor's origin destination.
pub const PROXY_SRC_HEADER: &str = "Cf-Cloudflared-Proxy-Src";

/// Headers are encoded as base64 of the name, then base64 of the value, joined
/// by `;` and repeated after a colon. That is not a conventional format; it is
/// what `connection/header.go` does.
///
/// Only the response direction uses it. `RequestUserHeaders` is defined in
/// header.go and referenced nowhere else upstream, because the edge sends the
/// visitor request as ordinary HTTP/2 headers; only an origin response has to
/// be serialized, so that HTTP/2 header validation is not applied to values
/// that came from an HTTP/1 origin.
const RESPONSE_HEADERS_HEADER: &str = "cf-cloudflared-response-headers";
const RESPONSE_META_HEADER: &str = "cf-cloudflared-response-meta";

/// Base64 alphabet, standard encoding.
const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode bytes as standard base64 with no padding.
///
/// `connection/header.go` uses `base64.RawStdEncoding`: the standard alphabet
/// with the `=` padding omitted. Emitting padding here produces a value the
/// edge's decoder rejects.
pub fn base64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity((input.len() + 2) / 3 * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(B64[((n >> 18) & 63) as usize] as char);
        out.push(B64[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(B64[((n >> 6) & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(B64[(n & 63) as usize] as char);
        }
    }
    out
}

/// Decode standard base64, ignoring whitespace.
pub fn base64_decode(input: &str) -> Option<Vec<u8>> {
    fn value(c: u8) -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => u32::from(c - b'A'),
            b'a'..=b'z' => u32::from(c - b'a') + 26,
            b'0'..=b'9' => u32::from(c - b'0') + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        })
    }

    let bytes: Vec<u8> = input.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for b in &bytes {
        if *b == b'=' {
            break;
        }
        let v = value(*b)?;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xFF) as u8);
        }
    }
    Some(out)
}

/// Encode a header list the way `connection/header.go` does.
///
/// Each header becomes `base64(name):base64(value)`, separated by `;`, with no
/// trailing separator. The base64 layer is what lets arbitrary header bytes
/// survive an HTTP header value.
pub fn encode_headers(headers: &[(String, String)]) -> String {
    let mut out = String::new();
    for (name, value) in headers {
        if !out.is_empty() {
            out.push(';');
        }
        out.push_str(&base64_encode(canonical_header_name(name).as_bytes()));
        out.push(':');
        out.push_str(&base64_encode(value.as_bytes()));
    }
    out
}

/// Canonicalize a header name the way Go's `textproto.CanonicalMIMEHeaderKey` does.
///
/// The edge's Go code reads headers into a map, which canonicalizes every name
/// before it is written back, so the serialized form carries `Content-Type`
/// rather than `content-type`. Names are case-insensitive on the wire
/// (RFC 9110 section 5.1) so this is cosmetic rather than a correctness
/// requirement, but matching the reference keeps the encoding verifiable.
pub fn canonical_header_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut capitalize = true;
    for ch in name.chars() {
        if ch == '-' {
            out.push('-');
            capitalize = true;
            continue;
        }
        // A name with anything other than token characters is left alone,
        // exactly as Go does: canonicalization stops at the first byte that is
        // not a letter, digit or dash.
        if !(ch.is_ascii_alphanumeric() || ch == '-') {
            return name.to_string();
        }
        if capitalize {
            out.extend(ch.to_uppercase());
            capitalize = false;
        } else {
            out.extend(ch.to_lowercase());
        }
    }
    out
}

/// Decode the format produced by [`encode_headers`].
pub fn decode_headers(encoded: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for entry in encoded.split(';') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let Some((name, value)) = entry.split_once(':') else {
            continue;
        };
        let (Some(name), Some(value)) = (base64_decode(name), base64_decode(value)) else {
            continue;
        };
        if let (Ok(n), Ok(v)) = (String::from_utf8(name), String::from_utf8(value)) {
            out.push((n, v));
        }
    }
    out
}

/// Classify a stream the edge opened, from its headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamKind {
    /// The registration and configuration stream.
    Control,
    /// A visitor's request to the origin.
    Visitor { address: String, port: u32 },
    /// A configuration push from the edge.
    Configuration,
    /// Something this client does not implement.
    Unknown,
}

/// Decide what a stream is for.
///
/// The order matters: a configuration push is checked before the visitor case,
/// because an update-configuration request can also carry a proxy-source
/// header and would otherwise be misrouted to an origin.
pub fn classify_stream(headers: &[(String, String)]) -> StreamKind {
    let get = |name: &str| {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
    };

    match get(CONTROL_STREAM_HEADER).as_deref() {
        Some("update-configuration") => return StreamKind::Configuration,
        Some(CONTROL_STREAM_VALUE) => return StreamKind::Control,
        _ => {}
    }

    if let Some(src) = get(PROXY_SRC_HEADER).filter(|s| !s.is_empty()) {
        // The value is `host:port`.
        let (address, port) = src
            .rsplit_once(':')
            .map(|(h, p)| (h.to_string(), p.parse().unwrap_or(0)))
            .unwrap_or((src, 0));
        return StreamKind::Visitor { address, port };
    }

    StreamKind::Visitor {
        address: String::new(),
        port: 0,
    }
}

/// The TLS configuration for the HTTP/2 edge transport.
///
/// `alpn` must be empty. cloudflared does not offer ALPN on this path, and
/// offering `h2` changes the handshake.
pub fn edge_tls() -> Result<Arc<rustls::ClientConfig>, String> {
    super::edge_tls_config(&[])
}

/// Open a TLS connection to the edge and complete an HTTP/2 handshake.
///
/// `addr` supplies the socket to dial; TLS uses `h2.cftunnel.com` regardless of
/// what address the SRV record produced. The returned stream is ready for the
/// edge to open streams on.
pub async fn connect(addr: &EdgeAddr, timeout: Duration) -> Result<TlsH2Stream, super::EdgeError> {
    let tcp = tokio::time::timeout(timeout, TcpStream::connect(addr.addr))
        .await
        .map_err(|_| super::EdgeError::Connect(format!("connect {} timed out", addr.addr)))?
        .map_err(|e| super::EdgeError::Connect(format!("connect {}: {e}", addr.addr)))?;
    let _ = tcp.set_nodelay(true);

    let config = edge_tls().map_err(super::EdgeError::Connect)?;
    let connector = tokio_rustls::TlsConnector::from(config);
    let name = rustls_pki_types::ServerName::try_from(H2_SNI.to_string())
        .map_err(|e| super::EdgeError::Connect(format!("bad SNI: {e}")))?;

    let tls = tokio::time::timeout(timeout, connector.connect(name, tcp))
        .await
        .map_err(|_| super::EdgeError::Connect("tls handshake timed out".into()))?
        .map_err(|e| super::EdgeError::Connect(format!("tls handshake: {e}")))?;

    Ok(TlsH2Stream { tls })
}

/// A TLS connection to the edge, ready for HTTP/2 framing.
pub struct TlsH2Stream {
    tls: tokio_rustls::client::TlsStream<TcpStream>,
}

impl TlsH2Stream {
    /// Take the inner stream for handing to an HTTP/2 library.
    pub fn into_inner(self) -> tokio_rustls::client::TlsStream<TcpStream> {
        self.tls
    }
}

impl AsyncRead for TlsH2Stream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        std::pin::Pin::new(&mut this.tls).poll_read(cx, buf)
    }
}

impl AsyncWrite for TlsH2Stream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        std::pin::Pin::new(&mut this.tls).poll_write(cx, data)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        std::pin::Pin::new(&mut this.tls).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        std::pin::Pin::new(&mut this.tls).poll_shutdown(cx)
    }
}

/// Build the visitor request to send to an origin.
///
/// The edge hands over the visitor's request with its headers as ordinary
/// HTTP/2 headers, so they are forwarded as they arrive. Only two classes are
/// dropped: the `cf-` families, which describe the edge connection rather than
/// the message, and the hop-by-hop headers, which HTTP/2 forbids on a stream
/// (RFC 9113 section 8.2.2).
///
pub fn build_visitor_request(
    method: &str,
    path: &str,
    authority: &str,
    headers: &[(String, String)],
) -> http::Request<()> {
    // The edge replays these to the origin, so control headers and the
    // hop-by-hop ones are dropped rather than forwarded.
    let replayed: Vec<(String, String)> = headers
        .iter()
        .filter(|(name, _)| !is_control_header(name) && !is_hop_by_hop(name))
        .cloned()
        .collect();

    let mut builder = http::Request::builder()
        .method(method)
        .uri(path)
        .header("host", authority);
    for (name, value) in &replayed {
        builder = builder.header(name.as_str(), value.as_str());
    }
    builder.body(()).unwrap_or_else(|_| http::Request::new(()))
}

/// Headers that describe one hop rather than the message.
///
/// RFC 9110 section 7.6.1, plus the two the edge handles itself. Sending any of
/// these on an HTTP/2 stream makes the origin or the edge act on a connection
/// that does not exist.
pub fn build_origin_response(
    status: u16,
    headers: &[(String, String)],
) -> (u16, Vec<(String, String)>) {
    let mut real: Vec<(String, String)> = Vec::with_capacity(headers.len());
    let mut serialized: Vec<(String, String)> = Vec::new();

    for (name, value) in headers {
        let lower = name.to_ascii_lowercase();
        if lower == "content-length" {
            // Meaningful in HTTP/2 and used by the edge, so it goes on the
            // wire as well as inside the serialized blob.
            real.push((lower.clone(), value.clone()));
        }
        if !is_control_header(&lower) {
            // Everything else is serialized, so that HTTP/2 header validation
            // is not applied to values that came from an HTTP/1 origin.
            serialized.push((name.clone(), value.clone()));
        }
    }

    real.push((
        RESPONSE_HEADERS_HEADER.to_string(),
        encode_headers(&serialized),
    ));
    // The edge records who answered. "origin" says the origin served it.
    real.push((
        RESPONSE_META_HEADER.to_string(),
        r#"{"src":"origin"}"#.to_string(),
    ));

    // HTTP/2 has no 101 (RFC 9113 section 8.1.1); the edge expects 200.
    let status = if status == 101 { 200 } else { status };
    (status, real)
}

/// Decode the serialized response headers off an origin response.
///
/// A malformed entry is skipped rather than failing the response: one bad
/// header should not cost the visitor the whole page.
pub fn decode_origin_response(headers: &[(String, String)]) -> Vec<(String, String)> {
    let get = |want: &str| {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(want))
            .map(|(_, v)| v.clone())
    };
    match get(RESPONSE_HEADERS_HEADER) {
        Some(encoded) => decode_headers(&encoded),
        None => headers
            .iter()
            .filter(|(k, _)| !is_control_header(k))
            .cloned()
            .collect(),
    }
}

/// Whether the response meta header says an origin answered, rather than
/// cloudflared serving the error itself.
pub fn served_by_origin(headers: &[(String, String)]) -> bool {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(RESPONSE_META_HEADER))
        .map(|(_, v)| v.contains(r#""src":"origin""#))
        .unwrap_or(false)
}

/// Headers that describe one hop rather than the message.
///
/// RFC 9110 section 7.6.1. Sending any of these on an HTTP/2 stream makes the
/// origin or the edge act on a connection that does not exist.
pub fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

/// Which headers belong to the visitor rather than to the edge connection.
///
/// Anything with a `:` prefix is HTTP/2 pseudo-headers, and the `cf-` families
/// are Cloudflare's own bookkeeping; forwarding either confuses the origin.
pub fn is_control_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.starts_with(':')
        || lower.starts_with("cf-int-")
        || lower.starts_with("cf-cloudflared-")
        || lower.starts_with("cf-proxy-")
}

#[cfg(test)]
mod tests {
    use super::super::Credentials;
    use super::*;

    #[test]
    fn the_control_stream_headers_match_the_source() {
        // From connection/http2.go: InternalUpgradeHeader / ControlStreamUpgrade.
        assert_eq!(
            CONTROL_STREAM_HEADER.to_ascii_lowercase(),
            "cf-cloudflared-proxy-connection-upgrade"
        );
        assert_eq!(CONTROL_STREAM_VALUE, "control-stream");
    }

    #[test]
    fn base64_round_trips() {
        for s in ["", "a", "ab", "abc", "hello world", "\u{0}binary"] {
            let enc = base64_encode(s.as_bytes());
            assert_eq!(
                base64_decode(&enc).as_deref(),
                Some(s.as_bytes()),
                "round trip failed for {s:?} via {enc:?}"
            );
        }
    }

    #[test]
    fn base64_matches_the_known_encoding() {
        // The unpadded RFC 4648 vectors, because cloudflared uses
        // base64.RawStdEncoding rather than padded StdEncoding.
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg");
        assert_eq!(base64_encode(b"fo"), "Zm8");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn headers_round_trip_through_the_encoded_form() {
        let headers = vec![
            ("Host".to_string(), "example.com".to_string()),
            ("User-Agent".to_string(), "curl/8.22.0".to_string()),
            ("X-Binary".to_string(), "\u{1}\u{2}\u{3}".to_string()),
        ];
        let encoded = encode_headers(&headers);
        assert!(
            !encoded.ends_with(';'),
            "SerializeHeaders omits the last separator"
        );
        assert_eq!(encoded.matches(';').count(), headers.len() - 1);
        assert_eq!(decode_headers(&encoded), headers);
    }

    #[test]
    fn a_malformed_encoded_header_is_skipped_not_fatal() {
        let encoded = format!(
            "{}:{};garbage;!!!:???;",
            base64_encode(b"A"),
            base64_encode(b"B")
        );
        assert_eq!(
            decode_headers(&encoded),
            vec![("A".to_string(), "B".to_string())],
            "one bad entry must not lose the good ones"
        );
    }

    #[test]
    fn a_control_stream_is_recognised() {
        let headers = vec![(
            CONTROL_STREAM_HEADER.to_string(),
            CONTROL_STREAM_VALUE.to_string(),
        )];
        assert_eq!(classify_stream(&headers), StreamKind::Control);
    }

    #[test]
    fn a_configuration_push_wins_over_the_visitor_case() {
        // It can also carry a proxy-source header, and misrouting it to an
        // origin would send a control message to a web server.
        let headers = vec![
            (
                CONTROL_STREAM_HEADER.to_string(),
                "update-configuration".to_string(),
            ),
            (PROXY_SRC_HEADER.to_string(), "127.0.0.1:8080".to_string()),
        ];
        assert_eq!(classify_stream(&headers), StreamKind::Configuration);
    }

    #[test]
    fn a_visitor_stream_carries_its_destination() {
        let headers = vec![(PROXY_SRC_HEADER.to_string(), "10.0.0.5:8080".to_string())];
        assert_eq!(
            classify_stream(&headers),
            StreamKind::Visitor {
                address: "10.0.0.5".into(),
                port: 8080
            }
        );
    }

    #[test]
    fn a_request_with_no_special_headers_is_a_visitor() {
        let headers = vec![("host".to_string(), "example.com".to_string())];
        assert_eq!(
            classify_stream(&headers),
            StreamKind::Visitor {
                address: String::new(),
                port: 0
            }
        );
    }

    #[test]
    fn header_matching_is_case_insensitive_as_http_requires() {
        let headers = vec![(
            "cf-cloudflared-proxy-connection-upgrade".to_string(),
            "control-stream".to_string(),
        )];
        assert_eq!(classify_stream(&headers), StreamKind::Control);
    }

    #[test]
    fn pseudo_and_cf_headers_are_not_forwarded_to_the_origin() {
        assert!(is_control_header(":authority"));
        assert!(is_control_header("cf-int-something"));
        assert!(is_control_header("cf-cloudflared-response-headers"));
        assert!(is_control_header("CF-Proxy-Src"));
        assert!(!is_control_header("host"));
        assert!(!is_control_header("content-type"));
    }

    #[test]
    fn the_edge_tls_config_offers_no_alpn() {
        // Offering h2 here is the mistake that makes this transport hang.
        let config = edge_tls().expect("config");
        assert!(
            config.alpn_protocols.is_empty(),
            "the HTTP/2 edge transport must offer no ALPN"
        );
    }

    #[test]
    fn a_visitor_request_carries_method_path_and_authority() {
        let req = build_visitor_request(
            "POST",
            "/api?x=1",
            "example.com",
            &[("content-type".into(), "application/json".into())],
        );
        assert_eq!(req.method(), "POST");
        assert_eq!(req.uri().path(), "/api");
        assert_eq!(req.uri().query(), Some("x=1"));
        assert_eq!(req.headers().get("host").unwrap(), "example.com");
        assert!(req.headers().contains_key("content-type"));
    }

    #[test]
    fn credentials_are_not_needed_to_describe_a_stream() {
        // A compile-time reminder that stream framing is independent of auth:
        // credentials travel on the control stream only.
        let creds = Credentials {
            account_tag: "abc".into(),
            tunnel_secret: vec![0u8; 32],
            tunnel_id: "00000000-0000-0000-0000-000000000000".into(),
        };
        assert_eq!(creds.tunnel_secret.len(), 32);
        assert!(creds.tunnel_id_bytes().is_ok());
    }
}
#[cfg(test)]
mod protocol_tests {
    use super::*;

    // connection/header.go: `var headerEncoding = base64.RawStdEncoding`.
    // Standard alphabet, no padding. Padded output is rejected by the edge's
    // decoder, so this is a protocol requirement, not a style choice.
    #[test]
    fn header_base64_is_unpadded_standard() {
        for (input, expected) in [
            (&b"a"[..], "YQ"),
            (&b"ab"[..], "YWI"),
            (&b"abc"[..], "YWJj"),
            (&b"abcd"[..], "YWJjZA"),
            (&b"content-type"[..], "Y29udGVudC10eXBl"),
            (&b"host"[..], "aG9zdA"),
            (&b"127.0.0.1:8080"[..], "MTI3LjAuMC4xOjgwODA"),
        ] {
            assert_eq!(
                base64_encode(input),
                expected,
                "base64 of {:?}",
                String::from_utf8_lossy(input)
            );
            assert!(
                !base64_encode(input).contains('='),
                "RawStdEncoding never emits padding"
            );
            assert_eq!(base64_decode(expected).as_deref(), Some(input));
        }
    }

    #[test]
    fn encoded_headers_are_name_then_value_separated_by_colon_and_semicolon() {
        // Exactly what SerializeHeaders produces.
        let encoded = encode_headers(&[
            ("host".into(), "example.com".into()),
            ("cf-connecting-ip".into(), "1.2.3.4".into()),
        ]);
        assert_eq!(
            encoded,
            "SG9zdA:ZXhhbXBsZS5jb20;Q2YtQ29ubmVjdGluZy1JcA:MS4yLjMuNA"
        );
        assert_eq!(base64_decode("SG9zdA").unwrap(), b"Host");
        // One past pair: the base64 is unpadded, so decode must not require
        // the '=' that padded encoders append.
        assert_eq!(
            base64_decode("Q2YtQ29ubmVjdGluZy1JcA").unwrap(),
            b"Cf-Connecting-Ip"
        );
    }

    #[test]
    fn a_single_header_serializes_without_a_trailing_semicolon() {
        // SerializeHeaders writes a separator only when the buffer is non-empty,
        // so one header ends in the value with no trailing ';'.
        assert_eq!(encode_headers(&[("host".into(), "a".into())]), "SG9zdA:YQ");
    }

    #[test]
    fn the_visitor_request_forwards_the_origins_headers_unencoded() {
        // cloudflared's ServeHTTP passes the edge's request straight to the
        // origin proxy, so the headers arrive as ordinary HTTP/2 headers.
        // Serialization is the response direction only; RequestUserHeaders is
        // defined in header.go and referenced nowhere else upstream.
        let headers = vec![
            ("content-type".to_string(), "text/plain".to_string()),
            ("cf-connecting-ip".to_string(), "1.2.3.4".to_string()),
        ];
        let request = build_visitor_request("POST", "/api/x", "example.com", &headers);

        assert_eq!(request.headers().get("content-type").unwrap(), "text/plain");
        // cf-connecting-ip is not one of IsControlResponseHeader's four
        // prefixes, so cloudflared does forward it to the origin.
        assert_eq!(
            request.headers().get("cf-connecting-ip").unwrap(),
            "1.2.3.4"
        );
        assert!(
            request
                .headers()
                .get("cf-cloudflared-request-headers")
                .is_none(),
            "the request direction is not serialized; RequestUserHeaders is dead upstream"
        );
        assert_eq!(request.method(), "POST");
        assert_eq!(request.uri().path(), "/api/x");
    }

    #[test]
    fn the_visitor_request_does_not_put_hop_by_hop_headers_on_the_wire() {
        let headers = vec![
            ("connection".to_string(), "keep-alive".to_string()),
            ("transfer-encoding".to_string(), "chunked".to_string()),
            (":method".to_string(), "GET".to_string()),
            ("cf-proxy-internal".to_string(), "x".to_string()),
            ("cf-int-trace".to_string(), "y".to_string()),
            ("accept".to_string(), "*/*".to_string()),
        ];
        let request = build_visitor_request("GET", "/", "example.com", &headers);

        for name in request.headers().keys() {
            let lower = name.as_str().to_ascii_lowercase();
            assert!(
                !is_control_header(&lower),
                "{} must not be sent as a real header",
                lower
            );
            assert_ne!(lower, "transfer-encoding", "hop-by-hop on the edge stream");
        }
        assert!(request.headers().contains_key("accept"));
        assert!(!request.headers().contains_key("keep-alive"));
        assert_eq!(request.method(), "GET");
        assert_eq!(request.uri().path(), "/");
        assert_eq!(request.headers().get("host").unwrap(), "example.com");
    }

    #[test]
    fn control_header_matching_follows_the_go_prefixes() {
        // IsControlResponseHeader in connection/header.go.
        for name in [
            ":status",
            "cf-int-something",
            "cf-cloudflared-request-headers",
            "cf-proxy-something",
        ] {
            assert!(is_control_header(name), "{} is a control header", name);
        }
        for name in [
            "content-type",
            "cf-something",
            "x-forwarded-for",
            "cloudflared",
        ] {
            assert!(!is_control_header(name), "{} is a visitor header", name);
        }
    }

    #[test]
    fn a_request_with_no_headers_still_reaches_the_origin() {
        let request = build_visitor_request("GET", "/", "example.com", &[]);
        assert_eq!(request.headers().get("host").unwrap(), "example.com");
        assert_eq!(request.headers().len(), 1, "only the host header");
    }

    #[test]
    fn origin_response_headers_are_serialized_into_one_edge_header() {
        let (status, out) = build_origin_response(
            200,
            &[
                ("Content-Type".into(), "text/html".into()),
                ("Content-Length".into(), "12".into()),
                ("cf-proxy-internal".into(), "drop".into()),
                (":status".into(), "200".into()),
            ],
        );

        assert_eq!(status, 200);
        let real: Vec<&str> = out
            .iter()
            .filter(|(k, _)| k == "content-length")
            .map(|(_, v)| v.as_str())
            .collect();
        assert_eq!(real, vec!["12"], "content-length goes on the wire too");

        let serialized = out
            .iter()
            .find(|(k, _)| k == RESPONSE_HEADERS_HEADER)
            .map(|(_, v)| v.clone())
            .expect("the serialized blob is always present");
        let decoded = decode_headers(&serialized);
        assert!(decoded
            .iter()
            .any(|(k, v)| k == "Content-Type" && v == "text/html"));
        assert!(
            !decoded
                .iter()
                .any(|(k, _)| k == "cf-proxy-internal" || k == ":status"),
            "control headers are not replayed to the visitor: {:?}",
            decoded
        );
    }

    #[test]
    fn an_origin_switching_protocols_101_becomes_200() {
        // HTTP/2 has no 101; cloudflared rewrites it (http2.go).
        let (status, _) = build_origin_response(101, &[]);
        assert_eq!(status, 200);
        let (status, _) = build_origin_response(204, &[]);
        assert_eq!(status, 204, "other statuses pass through unchanged");
    }

    #[test]
    fn the_response_meta_header_records_that_an_origin_answered() {
        let (_, out) = build_origin_response(502, &[]);
        assert!(served_by_origin(&out));
        assert!(out
            .iter()
            .any(|(k, v)| k == RESPONSE_META_HEADER && v == r#"{"src":"origin"}"#));
        assert!(
            !served_by_origin(&[(RESPONSE_HEADERS_HEADER.into(), String::new())]),
            "no meta header means cloudflared served it, not an origin"
        );
    }

    #[test]
    fn hop_by_hop_headers_are_recognised() {
        for name in [
            "Connection",
            "keep-alive",
            "Proxy-Authenticate",
            "te",
            "trailer",
            "Transfer-Encoding",
            "upgrade",
        ] {
            assert!(is_hop_by_hop(name), "{} is hop-by-hop", name);
        }
        for name in ["content-length", "cf-proxy-x", "accept"] {
            assert!(!is_hop_by_hop(name), "{} is not hop-by-hop", name);
        }
    }

    #[test]
    fn header_names_are_canonicalized_like_go_does() {
        // textproto.CanonicalMIMEHeaderKey, which is what the edge's map holds
        // by the time the name reaches the encoder.
        assert_eq!(canonical_header_name("host"), "Host");
        assert_eq!(canonical_header_name("content-type"), "Content-Type");
        assert_eq!(
            canonical_header_name("cf-connecting-ip"),
            "Cf-Connecting-Ip"
        );
        assert_eq!(canonical_header_name("a"), "A");
        assert_eq!(canonical_header_name("x-forwarded-for"), "X-Forwarded-For");
        assert_eq!(canonical_header_name("X-Weird-Header"), "X-Weird-Header");
        // A name that is already canonical is unchanged, so encoding is stable.
        assert_eq!(canonical_header_name("Content-Type"), "Content-Type");
    }

    #[test]
    fn a_non_token_header_name_is_left_exactly_as_given() {
        // Go's canonicalization stops at the first byte that is not a letter,
        // digit or dash, and returns the original string.
        for name in ["x_forwarded_for", "weird name", "a.b", "ünicode", ""] {
            assert_eq!(
                canonical_header_name(name),
                name,
                "{} must pass through untouched",
                name
            );
        }
    }

    #[test]
    fn canonicalization_does_not_change_what_the_edge_decodes() {
        // Canonicalizing is cosmetic: the decoded name is the same header.
        let lower = encode_headers(&[("content-type".into(), "text/plain".into())]);
        let canonical = encode_headers(&[("Content-Type".into(), "text/plain".into())]);
        // "content-type" and "Content-Type" canonicalize identically, so the
        // wire form is the same; a name Go would spell differently is not.
        assert_eq!(lower, canonical);
        assert_eq!(decode_headers(&lower), decode_headers(&canonical));
        assert_eq!(decode_headers(&canonical)[0].0, "Content-Type");

        // CF_CONNECTING_IP is not canonical (the underscore is not a token
        // char), so Go leaves it alone and so must we.
        let odd = encode_headers(&[("CF_CONNECTING_IP".into(), "1.2.3.4".into())]);
        assert_eq!(decode_headers(&odd)[0].0, "CF_CONNECTING_IP");
    }

    /// The recorded output of cloudflared's own `SerializeHeaders`, captured by
    /// running a verbatim copy of it in Go (see tools/check-header-oracle.sh).
    ///
    /// The cases are compared pair by pair because Go serializes in randomized
    /// map order, so the order of pairs is not part of the format. This exists
    /// because hand-written base64 literals get transcribed wrongly: an earlier
    /// version of this file asserted `Q2YtY29ubmVjdGluZy1JcA` where the correct
    /// value is `Q2YtY29ubmVjdGluZy1JcA`, differing in a single character that
    /// no eyeball check would catch.
    #[test]
    fn the_encoding_matches_the_recorded_go_oracle() {
        let recorded = include_str!("../../tools/header-oracle.txt");
        let mut blocks = recorded.split("---").filter(|b| !b.trim().is_empty());

        let cases: Vec<Vec<(&str, &str)>> = vec![
            vec![("host", "a")],
            vec![("host", "example.com")],
            vec![("X-Binary", "x")],
            vec![("host", "example.com"), ("cf-connecting-ip", "1.2.3.4")],
            vec![("a", "y"), ("b", "z"), ("c", "w")],
        ];

        for (case, block) in cases.iter().zip(blocks.by_ref()) {
            let owned: Vec<(String, String)> = case
                .iter()
                .map(|(n, v)| (n.to_string(), v.to_string()))
                .collect();
            let mut ours: Vec<String> = encode_headers(&owned)
                .split(';')
                .map(str::to_string)
                .collect();
            ours.sort();

            let mut theirs: Vec<String> = block
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect();
            theirs.sort();

            assert_eq!(
                ours, theirs,
                "header encoding differs from cloudflared's SerializeHeaders for {:?}",
                case
            );
        }
        assert!(
            blocks.next().is_none(),
            "tools/header-oracle.txt has more cases than this test covers; \
             add them here or re-record the oracle"
        );
    }

    #[test]
    fn the_sni_is_not_the_hostname_the_srv_record_points_at() {
        // The SNI is h2.cftunnel.com even though the socket goes to whatever
        // the SRV record resolved. Getting this wrong hands you Cloudflare's
        // generic HTTP frontend instead of the tunnel edge, and the symptom is
        // an HTTP/1.1 400 with no ALPN negotiated.
        assert_eq!(super::H2_SNI, "h2.cftunnel.com");
        assert_ne!(super::H2_SNI, "region1.v2.argotunnel.com");
        assert_ne!(super::H2_SNI, super::super::QUIC_SNI);
    }

    #[test]
    fn the_stream_headers_match_the_edge_names() {
        // Names taken from connection/header.go.
        assert_eq!(
            super::CONTROL_STREAM_HEADER,
            "Cf-Cloudflared-Proxy-Connection-Upgrade"
        );
        assert_eq!(super::PROXY_SRC_HEADER, "Cf-Cloudflared-Proxy-Src");
        assert_eq!(RESPONSE_HEADERS_HEADER, "cf-cloudflared-response-headers");
        // RequestUserHeaders exists upstream but is referenced nowhere there.
        assert_eq!(RESPONSE_META_HEADER, "cf-cloudflared-response-meta");
    }
}
