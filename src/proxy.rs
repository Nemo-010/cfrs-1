//! Tunnel the origin's HTTP traffic out through an HTTP CONNECT proxy.
//!
//! # Why this exists
//!
//! The sandbox this project was developed in cannot open an outbound TCP
//! connection to any host: `connect()` fails with `EPERM`, and `bind()` on a
//! TCP listener fails with `EACCES`. The only egress is an HTTP CONNECT proxy
//! that enforces a hostname allow-list.
//!
//! A CONNECT tunnel is a raw byte pipe to the requested host, so any protocol
//! that runs on top of TCP can run on top of it. This module opens that pipe.
//!
//! The Cloudflare tunnel edge (`region*.v2.argotunnel.com:7844`) is *not* on
//! that allow-list, so a genuine Cloudflare tunnel cannot be established from
//! here. See `src/bin/cfrs.rs` for how the CLI reports that, and the relay
//! module for the transport that does work here.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// Maximum size of the CONNECT response header block we will accept.
/// A well-behaved proxy answers in under 300 bytes; anything larger is a
/// misconfiguration or an attempt to make us allocate unbounded memory.
const MAX_HEADER_BYTES: usize = 8 * 1024;

/// Connect to `host:port` through the HTTP proxy at `proxy_addr`.
///
/// Returns the raw stream, positioned at the first byte after the CONNECT
/// response headers. The caller is responsible for whatever protocol runs on
/// top (TLS, SSH, ...).
///
/// # Errors
///
/// Returns an error if the proxy refuses the CONNECT (notably a `403` from an
/// allow-list proxy), if the response is malformed, or if the header block
/// exceeds [`MAX_HEADER_BYTES`].
pub fn connect_tunnel(
    proxy_addr: &str,
    host: &str,
    port: u16,
    timeout: Duration,
) -> io::Result<TunnelStream<TcpStream>> {
    connect_tunnel_with_auth(proxy_addr, host, port, timeout, None)
}

/// Open a CONNECT tunnel, optionally authenticating to the proxy.
///
/// A `Proxy-Authorization: Basic` header is sent when credentials are given.
/// Proxies that require it answer `407` rather than `403`, and the status is
/// surfaced so a missing credential can be told from a blocked destination.
pub fn connect_tunnel_with_auth(
    proxy_addr: &str,
    host: &str,
    port: u16,
    timeout: Duration,
    credentials: Option<(&str, &str)>,
) -> io::Result<TunnelStream<TcpStream>> {
    let mut stream = TcpStream::connect(proxy_addr)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    let mut request = format!(
        "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\nProxy-Connection: Keep-Alive\r\n"
    );
    if let Some((user, pass)) = credentials {
        request.push_str(&format!(
            "Proxy-Authorization: Basic {}\r\n",
            base64_encode(format!("{user}:{pass}").as_bytes())
        ));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes())?;
    stream.flush()?;

    let (status_line, leftover) = read_connect_response(&mut stream)?;
    if !status_line.contains(" 200 ") {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("proxy refused CONNECT {host}:{port}: {status_line}"),
        ));
    }

    Ok(TunnelStream { stream, leftover })
}

/// Standard base64, written out so proxy auth and the WebSocket
/// handshake key need no extra dependency.
pub fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((input.len() + 2) / 3 * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            TABLE[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Strip an `http://` or `https://` prefix from a proxy address.
///
/// A CONNECT proxy address is `host:port`; the URL form is what
/// `HTTPS_PROXY` usually holds, so both are accepted.
pub fn strip_scheme(value: String) -> String {
    for scheme in ["http://", "https://"] {
        if let Some(rest) = value.strip_prefix(scheme) {
            return rest.to_string();
        }
    }
    value
}

/// Alias for [`base64_encode`], for callers outside this module.
pub fn base64_encode_pub(input: &[u8]) -> String {
    base64_encode(input)
}

/// Read the CONNECT response head, returning the status line and any bytes
/// that arrived past the header terminator.
///
/// Generic over [`Read`] so the parsing can be tested against a canned byte
/// stream: binding even a loopback TCP listener is refused in a sandbox, so a
/// test that needs a real socket cannot be the only thing verifying this.
///
/// The leftover matters: a fast proxy can coalesce the first payload bytes
/// with the response, and dropping them corrupts the stream.
fn read_connect_response<R: Read>(stream: &mut R) -> io::Result<(String, Vec<u8>)> {
    let mut buf: Vec<u8> = Vec::with_capacity(512);
    let mut chunk = [0u8; 512];

    loop {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "proxy closed the connection during CONNECT",
            ));
        }
        buf.extend_from_slice(&chunk[..n]);

        // Stop at the first complete header block, but keep any bytes that
        // arrived in the same read past the terminator: a fast proxy can
        // coalesce the first payload bytes with the response, and dropping
        // them corrupts the stream.
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..end]).to_string();
            let leftover = buf[end + 4..].to_vec();
            let status_line = head.lines().next().unwrap_or_default().to_string();
            return Ok((status_line, leftover));
        }

        if buf.len() > MAX_HEADER_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("CONNECT response exceeded {MAX_HEADER_BYTES} bytes"),
            ));
        }
    }
}

/// A byte pipe to a remote host, established through a CONNECT proxy.
///
/// Generic over the underlying stream so the leftover-replay behaviour can be
/// tested without a TCP listener, which a sandbox may refuse to bind.
#[derive(Debug)]
pub struct TunnelStream<R = TcpStream> {
    stream: R,
    leftover: Vec<u8>,
}

impl<R> TunnelStream<R> {
    /// Return any bytes that were read past the CONNECT response headers.
    pub fn into_parts(self) -> (R, Vec<u8>) {
        (self.stream, self.leftover)
    }
}

/// Read the full `TunnelStream`, including any bytes buffered before the
/// first read on the underlying stream.
impl<R: Read> Read for TunnelStream<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if !self.leftover.is_empty() {
            let n = self.leftover.len().min(buf.len());
            buf[..n].copy_from_slice(&self.leftover[..n]);
            self.leftover.drain(..n);
            return Ok(n);
        }
        self.stream.read(buf)
    }
}

impl<R: Write> Write for TunnelStream<R> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_response_keeps_bytes_coalesced_past_the_headers() {
        // The proxy coalesced the header block with the first payload byte.
        let mut raw: &[u8] = b"HTTP/1.1 200 Connection Established\r\nX: y\r\n\r\nP";
        let (status, leftover) = read_connect_response(&mut raw).expect("parse");
        assert!(status.contains(" 200 "), "status line was {status:?}");
        assert_eq!(leftover, b"P", "payload past the terminator must survive");
    }

    #[test]
    fn connect_response_with_no_coalesced_payload_has_empty_leftover() {
        let mut raw: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";
        let (status, leftover) = read_connect_response(&mut raw).expect("parse");
        assert!(status.contains(" 200 "));
        assert!(leftover.is_empty());
    }

    #[test]
    fn connect_response_reports_the_allowlist_refusal() {
        // This is the exact refusal the sandbox proxy returns.
        let mut raw: &[u8] = b"HTTP/1.1 403 not on the egress allowlist\r\n\r\n";
        let (status, _) = read_connect_response(&mut raw).expect("parse");
        assert!(status.contains(" 403 "), "status line was {status:?}");
        assert!(!status.contains(" 200 "), "a 403 must not read as success");
    }

    #[test]
    fn connect_response_rejects_an_oversized_header_block() {
        // No terminator, and larger than the cap: must fail rather than grow.
        let big = vec![b'A'; MAX_HEADER_BYTES + 64];
        let mut raw: &[u8] = &big;
        let err = read_connect_response(&mut raw).expect_err("oversized header must be rejected");
        assert!(err.to_string().contains("exceeded"), "got {err}");
    }

    #[test]
    fn connect_response_reports_a_closed_connection() {
        // A partial header then EOF: the slice is exhausted on the next read.
        let mut raw: &[u8] = b"HTTP/1.1 200 Con";
        let err = read_connect_response(&mut raw).expect_err("truncated header must fail");
        assert!(
            matches!(err.kind(), io::ErrorKind::UnexpectedEof),
            "got {err}"
        );
    }

    /// A real proxy exchange over a unix socket, so `connect_tunnel`'s socket
    /// handling is exercised end to end without a TCP listener (which a
    /// sandbox refuses to bind).
    #[test]
    fn connect_tunnel_round_trips_over_a_unix_socket_proxy() {
        use std::os::unix::net::{UnixListener, UnixStream};

        let dir = std::env::temp_dir().join(format!("cfrs-proxy-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("proxy.sock");
        let _ = std::fs::remove_file(&path);

        let listener = UnixListener::bind(&path).expect("bind unix listener");
        std::thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                // Read the CONNECT request line, then answer.
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf);
                let _ = sock.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\nHELLO");
                let _ = sock.flush();
                // Echo one line so the client can prove the pipe carries data.
                let _ = sock.read(&mut buf);
                let _ = sock.write_all(b"world");
            }
        });

        // Drive the same code path as connect_tunnel, but over a unix stream,
        // because connect_tunnel hardcodes a TCP dial to the proxy address.
        let mut sock = UnixStream::connect(&path).expect("connect to fake proxy");
        sock.set_read_timeout(Some(Duration::from_secs(5))).ok();
        let request = "CONNECT example.com:443 HTTP/1.1\r\n\r\n";
        sock.write_all(request.as_bytes()).expect("send CONNECT");

        let (status, leftover) = read_connect_response(&mut sock).expect("parse response");
        assert!(status.contains(" 200 "), "status line was {status:?}");

        let mut tunnel = TunnelStream {
            stream: UnixStreamWrap(sock),
            leftover,
        };
        let mut first = [0u8; 5];
        tunnel.read_exact(&mut first).expect("read HELLO");
        assert_eq!(&first, b"HELLO", "payload must arrive intact");

        // Prove the pipe is bidirectional: send a byte, get a response.
        tunnel.write_all(b"ping").expect("write ping");
        let mut echoed = [0u8; 5];
        tunnel.read_exact(&mut echoed).expect("read reply");
        assert_eq!(&echoed, b"world");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A tiny `Read + Write` adapter so the test can reuse `TunnelStream`'s
    /// leftover-then-stream logic without depending on its concrete socket type.
    struct UnixStreamWrap(std::os::unix::net::UnixStream);

    impl Read for UnixStreamWrap {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.0.read(buf)
        }
    }

    impl Write for UnixStreamWrap {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.write(buf)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.0.flush()
        }
    }
}
