//! HTTP/1.1 request parsing and response writing.
//!
//! A tunnel moves bytes, but the HTTP origins inside it need real request and
//! response handling: headers for `Host` rewriting, chunked bodies, keep-alive
//! reuse, and WebSocket upgrades. This module does that without pulling in a
//! server framework, so the dependency list stays small and the wire behaviour
//! is explicit.

use std::collections::HashMap;
use std::io;

/// The request line and headers of an HTTP/1.1 request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RequestHead {
    pub method: String,
    /// Path with any query string, exactly as it arrived.
    pub path: String,
    /// Header name (lowercased) to value.
    pub headers: Vec<(String, String)>,
}

impl RequestHead {
    /// Parse a request head from bytes.
    ///
    /// Returns the head and the number of bytes consumed, so the caller keeps
    /// any body that followed in the same read.
    pub fn parse(buf: &[u8]) -> Result<(RequestHead, usize), HttpParseError> {
        let head_end = find_head_end(buf).ok_or(HttpParseError::Incomplete)?;
        let head = std::str::from_utf8(&buf[..head_end]).map_err(|_| HttpParseError::Malformed)?;

        let mut lines = head.split("\r\n");
        let request_line = lines.next().ok_or(HttpParseError::Malformed)?;
        let mut parts = request_line.split_whitespace();
        let method = parts.next().ok_or(HttpParseError::Malformed)?.to_string();
        let path = parts.next().ok_or(HttpParseError::Malformed)?.to_string();
        if method.is_empty() || path.is_empty() {
            return Err(HttpParseError::Malformed);
        }

        let mut headers = Vec::new();
        for line in lines {
            if line.is_empty() {
                continue;
            }
            if let Some((name, value)) = line.split_once(':') {
                headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
            }
        }

        Ok((
            RequestHead {
                method,
                path,
                headers,
            },
            head_end + 4,
        ))
    }

    /// Case-insensitive header lookup.
    ///
    /// Header names are stored lowercased, so the argument is lowercased too.
    /// Looking up `"Host"` must find the `host` header, exactly as HTTP
    /// requires.
    pub fn header(&self, name: &str) -> Option<&str> {
        let lower = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| *k == lower)
            .map(|(_, v)| v.as_str())
    }

    /// Replace a header's value, or append it.
    pub fn set_header(&mut self, name: &str, value: &str) {
        let lower = name.to_ascii_lowercase();
        if let Some(slot) = self.headers.iter_mut().find(|(k, _)| *k == lower) {
            slot.1 = value.to_string();
        } else {
            self.headers.push((lower, value.to_string()));
        }
    }

    /// Remove a header entirely.
    pub fn remove_header(&mut self, name: &str) {
        let lower = name.to_ascii_lowercase();
        self.headers.retain(|(k, _)| *k != lower);
    }

    /// True when the client asked to upgrade protocols, typically a WebSocket.
    pub fn is_upgrade(&self) -> bool {
        self.header("upgrade")
            .map(|v| v.eq_ignore_ascii_case("websocket"))
            .unwrap_or(false)
    }

    /// True when the body length is known up front, which is what makes
    /// connection reuse safe.
    pub fn has_known_length(&self) -> bool {
        self.header("transfer-encoding").is_none()
    }

    /// Content length, if declared.
    pub fn content_length(&self) -> Option<u64> {
        self.header("content-length")?.trim().parse().ok()
    }
}

/// Why a request head could not be parsed.
#[derive(Debug, PartialEq, Eq)]
pub enum HttpParseError {
    /// More bytes are needed; not an error, just "read more".
    Incomplete,
    /// The bytes are not an HTTP request.
    Malformed,
}

impl std::fmt::Display for HttpParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpParseError::Incomplete => write!(f, "incomplete request head"),
            HttpParseError::Malformed => write!(f, "malformed request"),
        }
    }
}

/// Find the offset of the `\r\n\r\n` that ends the request head.
fn find_head_end(buf: &[u8]) -> Option<usize> {
    if buf.len() < 4 {
        return None;
    }
    (0..=buf.len() - 4).find(|&i| &buf[i..i + 4] == b"\r\n\r\n")
}

/// Something that can accumulate an HTTP response.
pub trait ResponseWriter {
    fn status(&mut self, code: u16) -> &mut Self;
    fn header(&mut self, name: &str, value: &str) -> &mut Self;
    fn body(&mut self, body: &[u8]) -> io::Result<()>;

    /// Finish the head with no body.
    fn raw_head(&mut self, code: u16, phrase: &str, extra: &[(String, String)]) -> io::Result<()> {
        let mut out = format!("HTTP/1.1 {code} {phrase}\r\n");
        for (k, v) in extra {
            out.push_str(&format!("{k}: {v}\r\n"));
        }
        out.push_str("Content-Length: 0\r\n\r\n");
        self.body(out.as_bytes())
    }

    /// Finish with a `text/plain` body.
    fn text(&mut self, body: &str) -> io::Result<()> {
        self.header("Content-Type", "text/plain; charset=utf-8")
            .body(body.as_bytes())
    }

    /// Finish with a `text/html` body.
    fn html(&mut self, body: &str) -> io::Result<()> {
        self.header("Content-Type", "text/html; charset=utf-8")
            .body(body.as_bytes())
    }

    /// Finish with a JSON body.
    fn json(&mut self, body: &str) -> io::Result<()> {
        self.header("Content-Type", "application/json")
            .body(body.as_bytes())
    }
}

/// Build a complete response into a `Vec<u8>`.
///
/// Used on the hot path where the response is written straight to a socket.
pub fn build_response(
    code: u16,
    phrase: &str,
    headers: &[(&str, String)],
    body: Option<&[u8]>,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(format!("HTTP/1.1 {code} {phrase}\r\n").as_bytes());
    for (k, v) in headers {
        out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }
    match body {
        Some(b) => {
            out.extend_from_slice(format!("Content-Length: {}\r\n\r\n", b.len()).as_bytes());
            out.extend_from_slice(b);
        }
        None => {
            out.extend_from_slice(b"Content-Length: 0\r\n\r\n");
        }
    }
    out
}

/// Headers that must not be copied from the visitor to a downstream origin.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Strip hop-by-hop headers, which describe one connection rather than the
/// message and must not be forwarded.
pub fn strip_hop_by_hop(headers: &mut Vec<(String, String)>) {
    headers.retain(|(k, _)| !HOP_BY_HOP.contains(&k.as_str()));
}

/// A case-insensitive header map, for building responses.
pub type HeaderMap = HashMap<String, String>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_simple_request() {
        let raw = b"GET /hello?x=1 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: cfrs\r\n\r\n";
        let (head, used) = RequestHead::parse(raw).expect("parse");
        assert_eq!(head.method, "GET");
        assert_eq!(head.path, "/hello?x=1");
        assert_eq!(head.header("host"), Some("example.com"));
        assert_eq!(
            head.header("HOST"),
            Some("example.com"),
            "lookup is case-insensitive"
        );
        assert_eq!(used, raw.len());
    }

    #[test]
    fn reports_incomplete_rather_than_malformed() {
        let raw = b"GET / HTTP/1.1\r\nHost: x\r\n";
        assert_eq!(
            RequestHead::parse(raw).unwrap_err(),
            HttpParseError::Incomplete
        );
    }

    #[test]
    fn rejects_a_non_http_request() {
        assert_eq!(
            RequestHead::parse(b"NOTHTTP\r\n\r\n").unwrap_err(),
            HttpParseError::Malformed
        );
    }

    #[test]
    fn preserves_body_bytes_after_the_head() {
        let raw = b"POST /x HTTP/1.1\r\nContent-Length: 5\r\n\r\nhelloEXTRA";
        let (head, used) = RequestHead::parse(raw).expect("parse");
        assert_eq!(head.content_length(), Some(5));
        assert_eq!(&raw[used..used + 5], b"hello", "body offset must be right");
    }

    #[test]
    fn detects_a_websocket_upgrade() {
        let raw = b"GET /ws HTTP/1.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
        let (head, _) = RequestHead::parse(raw).expect("parse");
        assert!(head.is_upgrade());
    }

    #[test]
    fn chunked_requests_have_no_known_length() {
        let raw = b"POST /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";
        let (head, _) = RequestHead::parse(raw).expect("parse");
        assert!(!head.has_known_length());
    }

    #[test]
    fn set_and_remove_headers() {
        let mut head = RequestHead {
            method: "GET".into(),
            path: "/".into(),
            headers: vec![],
        };
        head.set_header("X-Real-IP", "1.2.3.4");
        assert_eq!(head.header("x-real-ip"), Some("1.2.3.4"));
        head.set_header("X-Real-IP", "5.6.7.8");
        assert_eq!(
            head.header("x-real-ip"),
            Some("5.6.7.8"),
            "set must replace"
        );
        head.remove_header("X-Real-IP");
        assert_eq!(head.header("x-real-ip"), None);
    }

    #[test]
    fn strips_hop_by_hop_headers() {
        let mut h = vec![
            ("connection".to_string(), "close".to_string()),
            ("host".to_string(), "x".to_string()),
            ("transfer-encoding".to_string(), "chunked".to_string()),
        ];
        strip_hop_by_hop(&mut h);
        assert_eq!(h.len(), 1);
        assert_eq!(h[0].0, "host");
    }

    #[test]
    fn builds_a_response_with_a_body() {
        let out = build_response(
            200,
            "OK",
            &[("Content-Type", "text/plain".to_string())],
            Some(b"hi"),
        );
        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(text.contains("Content-Length: 2\r\n"));
        assert!(text.ends_with("\r\n\r\nhi"));
    }
}
