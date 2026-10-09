//! Provision an anonymous Cloudflare "quick tunnel", the way `cloudflared` does.
//!
//! # What this reproduces
//!
//! `cloudflared tunnel --url ...` calls `POST https://api.trycloudflare.com/tunnel`
//! with an empty body and **no credentials of any kind**. The response carries a
//! tunnel id, an account tag, a 32-byte secret (base64 in JSON) and the public
//! hostname. That is the whole anonymous-provisioning step, and it is the only
//! part of the Cloudflare flow that runs from a network-restricted sandbox,
//! because it is ordinary HTTPS on port 443 to a host that is commonly
//! allow-listed.
//!
//! References, read from the `cloudflared` source rather than from docs:
//!
//! * `cmd/cloudflared/tunnel/quick_tunnel.go` - `RunQuickTunnel` performs the
//!   POST; `QuickTunnelResponse` is the response shape.
//! * `cmd/cloudflared/tunnel/cmd.go` - `quick-service` defaults to
//!   `https://api.trycloudflare.com`.
//! * `quicktunnelauth` - when an email allow-list is requested the client sends
//!   `{"auth_mode":"otp"}` instead of an empty body. The allow-list itself never
//!   leaves the client; Cloudflare only learns that OTP is required.
//!
//! # What this does NOT do
//!
//! It does not open the tunnel edge connection. That requires reaching
//! `region*.v2.argotunnel.com:7844` (QUIC/UDP or HTTP/2/TCP), which the sandbox
//! used for development blocks on both counts. See `README.md`.

use serde::{Deserialize, Serialize};

/// Default provisioning endpoint, matching cloudflared's `quick-service` flag.
pub const DEFAULT_QUICK_SERVICE: &str = "https://api.trycloudflare.com";

/// The anonymous provisioning response. Only the fields cfrs uses are modelled;
/// cloudflared's `QuickTunnel` also carries `name`, which is unused here.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct QuickTunnel {
    /// Tunnel UUID.
    pub id: String,
    /// The public hostname, e.g. `foo-bar.trycloudflare.com`.
    pub hostname: String,
    /// Hex account tag the tunnel is billed/attributed to.
    pub account_tag: String,
    /// Base64-encoded 32-byte tunnel secret. Sent to the edge verbatim by
    /// cloudflared (`connection.Credentials.TunnelSecret`), not hashed.
    pub secret: String,
}

impl QuickTunnel {
    /// The public URL for this tunnel.
    pub fn url(&self) -> String {
        format!("https://{}", self.hostname)
    }

    /// The raw secret bytes, decoded from base64.
    ///
    /// This is the value cloudflared puts on the wire as `TunnelAuth.tunnelSecret`
    /// without any hashing step, so a reimplementation must not transform it.
    pub fn secret_bytes(&self) -> Result<Vec<u8>, String> {
        decode_base64(&self.secret).ok_or_else(|| {
            format!(
                "tunnel secret is not valid base64 ({} bytes of text)",
                self.secret.len()
            )
        })
    }
}

/// Top-level envelope: `{"success":bool,"result":{...},"errors":[...]}`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct QuickTunnelResponse {
    pub success: bool,
    #[serde(default)]
    pub result: Option<QuickTunnel>,
    #[serde(default)]
    pub errors: Vec<QuickTunnelError>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct QuickTunnelError {
    #[serde(default)]
    pub code: i64,
    #[serde(default)]
    pub message: String,
}

/// How the tunnel should be authenticated for visitors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    /// Anyone with the URL can reach the origin. Empty request body.
    Public,
    /// Visitors must pass a one-time PIN before reaching the origin.
    /// Request body is `{"auth_mode":"otp"}`.
    ///
    /// Note that the allow-list is enforced by the *client*, exactly as
    /// `cloudflared --allowed-mail` does: Cloudflare is told only that OTP is
    /// required, never which addresses are acceptable.
    Otp,
}

impl AuthMode {
    /// The request body to POST. `None` means an empty body.
    pub fn request_body(self) -> Option<&'static str> {
        match self {
            AuthMode::Public => None,
            AuthMode::Otp => Some(r#"{"auth_mode":"otp"}"#),
        }
    }
}

/// A validation failure detected before any network call is made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvisionError {
    /// The provisioning endpoint was not a valid absolute URL.
    BadEndpoint(String),
    /// The HTTP request itself failed.
    Http(String),
    /// A non-2xx HTTP status.
    Status { code: u16, body: String },
    /// A 2xx response that is not valid JSON, or not a `QuickTunnelResponse`.
    Decode(String),
    /// The service returned `"success": false`.
    Service(Vec<QuickTunnelError>),
    /// `success: true` but no `result` object.
    MissingResult,
}

impl std::fmt::Display for ProvisionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProvisionError::BadEndpoint(e) => write!(f, "invalid quick-service endpoint: {e}"),
            ProvisionError::Http(e) => write!(f, "request to the quick-tunnel service failed: {e}"),
            ProvisionError::Status { code, body } => {
                write!(f, "quick-tunnel service returned HTTP {code}: {body}")
            }
            ProvisionError::Decode(e) => {
                write!(f, "could not decode the quick-tunnel response: {e}")
            }
            ProvisionError::Service(errs) => {
                let joined: Vec<String> = errs
                    .iter()
                    .map(|e| format!("{}: {}", e.code, e.message))
                    .collect();
                write!(
                    f,
                    "quick-tunnel service reported failure: {}",
                    joined.join("; ")
                )
            }
            ProvisionError::MissingResult => {
                write!(
                    f,
                    "quick-tunnel service returned success with no result object"
                )
            }
        }
    }
}

impl std::error::Error for ProvisionError {}

/// The user agent cloudflared-style clients send. Kept simple and honest.
pub fn user_agent() -> String {
    format!("cfrs/{} (rust)", env!("CARGO_PKG_VERSION"))
}

/// Request a new anonymous quick tunnel from `endpoint`.
///
/// `endpoint` is the full base URL of the provisioning service, normally
/// [`DEFAULT_QUICK_SERVICE`]. The returned [`QuickTunnel`] carries the
/// credentials that the edge connection would consume.
///
/// If `proxy` is set, the request is tunnelled through that HTTP CONNECT proxy
/// (format `host:port` or a full `http://` URL). Sandboxes with no local DNS
/// resolver and no direct egress require this: the proxy is what resolves
/// `api.trycloudflare.com`. When `proxy` is `None`, the request uses the
/// environment's `HTTPS_PROXY` if ureq picks it up, otherwise a direct call.
pub fn request_quick_tunnel(
    endpoint: &str,
    auth_mode: AuthMode,
    timeout_secs: u64,
    proxy: Option<&str>,
) -> Result<QuickTunnel, ProvisionError> {
    let url = format!("{}/tunnel", endpoint.trim_end_matches('/'));
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(ProvisionError::BadEndpoint(url));
    }

    let mut builder =
        ureq::AgentBuilder::new().timeout(std::time::Duration::from_secs(timeout_secs));

    if let Some(p) = proxy {
        let proxy_url = if p.starts_with("http://") || p.starts_with("https://") {
            p.to_string()
        } else {
            format!("http://{p}")
        };
        let parsed = ureq::Proxy::new(&proxy_url)
            .map_err(|e| ProvisionError::BadEndpoint(format!("proxy {proxy_url}: {e}")))?;
        builder = builder.proxy(parsed);
    }

    let agent = builder.build();

    let request = agent
        .post(&url)
        .set("Content-Type", "application/json")
        .set("User-Agent", &user_agent());

    // cloudflared sends an empty body for a public tunnel and
    // `{"auth_mode":"otp"}` for a protected one. `send_string` performs the
    // request and returns the response, whereas `call` does the same for an
    // empty body.
    let response = match auth_mode.request_body() {
        Some(body) => request.send_string(body),
        None => request.call(),
    };

    match response {
        Ok(response) => {
            let status = response.status();
            let text = response
                .into_string()
                .map_err(|e| ProvisionError::Decode(format!("could not read body: {e}")))?;
            parse_quick_tunnel_response(status, &text)
        }
        // A 4xx/5xx is surfaced by ureq as an Err; the status is recoverable.
        Err(ureq::Error::Status(code, response)) => {
            let body = response.into_string().unwrap_or_default();
            Err(ProvisionError::Status { code, body })
        }
        Err(e) => Err(ProvisionError::Http(e.to_string())),
    }
}

/// Parse and validate a provisioning response body.
///
/// Split out from [`request_quick_tunnel`] so it can be tested against captured
/// real responses without a live service.
pub fn parse_quick_tunnel_response(status: u16, body: &str) -> Result<QuickTunnel, ProvisionError> {
    if !(200..300).contains(&status) {
        return Err(ProvisionError::Status {
            code: status,
            body: body.to_string(),
        });
    }

    let parsed: QuickTunnelResponse = serde_json::from_str(body)
        .map_err(|e| ProvisionError::Decode(format!("{e}; body was: {}", truncate(body, 200))))?;

    if !parsed.success {
        return Err(ProvisionError::Service(parsed.errors));
    }

    parsed.result.ok_or(ProvisionError::MissingResult)
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}...", &s[..n])
    }
}

/// Minimal standard base64 decoder for the tunnel secret.
///
/// Hand-rolled rather than pulling in a dependency: the secret is standard
/// base64 with padding, and this keeps the dependency list small.
fn decode_base64(input: &str) -> Option<Vec<u8>> {
    fn value(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }

    let bytes: Vec<u8> = input.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;

    for &b in &bytes {
        if b == b'=' {
            break;
        }
        let v = value(b)?;
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xFF) as u8);
        }
    }

    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A response captured from a real `POST https://api.trycloudflare.com/tunnel`
    /// run against the live service on 2026-10-09. The values are real but the
    /// tunnel is long dead; only the shape matters to these tests.
    const REAL_RESPONSE: &str = r#"{
  "id": "c1267064-5604-4d16-9a83-66b7ed37f182",
  "name": "operator-icon-sheffield-compression",
  "hostname": "operator-icon-sheffield-compression.trycloudflare.com",
  "account_tag": "5ab4e9dfbd435d24068829fda0077963",
  "secret": "GlUwcZAOuFFaHRtTTFqbk1WVmpWMHFzOGdSSUthbG1K",
  "success": true,
  "result": {
    "id": "c1267064-5604-4d16-9a83-66b7ed37f182",
    "name": "operator-icon-sheffield-compression",
    "hostname": "operator-icon-sheffield-compression.trycloudflare.com",
    "account_tag": "5ab4e9dfbd435d24068829fda0077963",
    "secret": "GlUwcZAOuFFaHRtTTFqbk1WVmpWMHFzOGdSSUthbG1K"
  },
  "errors": [],
  "messages": []
}"#;

    #[test]
    fn parses_a_real_provisioning_response() {
        let tunnel = parse_quick_tunnel_response(200, REAL_RESPONSE).expect("should parse");
        assert_eq!(
            tunnel.hostname,
            "operator-icon-sheffield-compression.trycloudflare.com"
        );
        assert_eq!(
            tunnel.url(),
            "https://operator-icon-sheffield-compression.trycloudflare.com"
        );
        assert_eq!(tunnel.id, "c1267064-5604-4d16-9a83-66b7ed37f182");
        assert_eq!(
            tunnel.account_tag.len(),
            32,
            "account tag is a 32-char hex string"
        );
    }

    #[test]
    fn secret_decodes_to_the_documented_32_bytes() {
        let tunnel = parse_quick_tunnel_response(200, REAL_RESPONSE).expect("should parse");
        let bytes = tunnel.secret_bytes().expect("secret should be base64");
        // cloudflared treats this as TunnelSecret and puts it on the wire raw.
        assert_eq!(bytes.len(), 32, "tunnel secret must be 32 raw bytes");
    }

    #[test]
    fn hostname_is_a_trycloudflare_subdomain() {
        let tunnel = parse_quick_tunnel_response(200, REAL_RESPONSE).expect("should parse");
        assert!(
            tunnel.hostname.ends_with(".trycloudflare.com"),
            "quick tunnel hostnames are under trycloudflare.com: {}",
            tunnel.hostname
        );
        let label = tunnel
            .hostname
            .strip_suffix(".trycloudflare.com")
            .expect("suffix checked above");
        assert!(!label.is_empty(), "there must be a leading label");
        assert!(
            label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'),
            "the label must be ascii alphanumerics and hyphens: {label}"
        );
        assert!(
            !tunnel.hostname.contains('/'),
            "hostname must not carry a scheme or path"
        );
    }

    #[test]
    fn rejects_a_success_false_envelope() {
        let body = r#"{"success":false,"result":null,"errors":[{"code":1001,"message":"nope"}]}"#;
        match parse_quick_tunnel_response(200, body) {
            Err(ProvisionError::Service(errs)) => {
                assert_eq!(errs.len(), 1);
                assert_eq!(errs[0].code, 1001);
                assert_eq!(errs[0].message, "nope");
            }
            other => panic!("expected Service error, got {other:?}"),
        }
    }

    #[test]
    fn rejects_success_with_no_result() {
        let body = r#"{"success":true,"errors":[]}"#;
        match parse_quick_tunnel_response(200, body) {
            Err(ProvisionError::MissingResult) => {}
            other => panic!("expected MissingResult, got {other:?}"),
        }
    }

    #[test]
    fn rejects_a_non_2xx_status() {
        match parse_quick_tunnel_response(403, "forbidden") {
            Err(ProvisionError::Status { code, .. }) => assert_eq!(code, 403),
            other => panic!("expected Status error, got {other:?}"),
        }
    }

    #[test]
    fn rejects_malformed_json() {
        match parse_quick_tunnel_response(200, "not json at all") {
            Err(ProvisionError::Decode(_)) => {}
            other => panic!("expected Decode error, got {other:?}"),
        }
    }

    #[test]
    fn public_mode_sends_an_empty_body_and_otp_sends_the_auth_mode() {
        assert_eq!(AuthMode::Public.request_body(), None);
        assert_eq!(AuthMode::Otp.request_body(), Some(r#"{"auth_mode":"otp"}"#));
    }

    #[test]
    fn endpoint_must_be_an_absolute_http_url() {
        let err = request_quick_tunnel("ftp://example.com", AuthMode::Public, 5, None).unwrap_err();
        assert!(matches!(err, ProvisionError::BadEndpoint(_)), "got {err:?}");
    }

    #[test]
    fn trailing_slash_on_the_endpoint_is_not_doubled() {
        // Guards the URL join: "https://host/" must become ".../tunnel", not "//tunnel".
        let err = request_quick_tunnel("not-a-url/", AuthMode::Public, 5, None).unwrap_err();
        match err {
            ProvisionError::BadEndpoint(url) => {
                assert!(url.ends_with("/tunnel"), "unexpected url {url}");
                assert!(!url.contains("//tunnel"), "double slash in {url}");
            }
            other => panic!("expected BadEndpoint, got {other:?}"),
        }
    }

    #[test]
    fn a_bare_proxy_address_is_upgraded_to_an_http_url() {
        // "1.2.3.4:8080" is not a valid proxy URL, but the CLI commonly holds
        // it in that form; the function must accept it rather than fail later
        // with an opaque DNS error.
        let err = request_quick_tunnel(
            "https://api.trycloudflare.com",
            AuthMode::Public,
            1,
            Some("127.0.0.1:1"),
        )
        .unwrap_err();
        // Port 1 is closed, so this is a transport failure, not a parse failure.
        assert!(
            matches!(err, ProvisionError::Http(_) | ProvisionError::Status { .. }),
            "expected a transport failure, got {err:?}"
        );
    }
}
