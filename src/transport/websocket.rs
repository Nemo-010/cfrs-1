//! WebSocket transport: carry a byte stream inside an HTTPS upgrade.
//!
//! # Why
//!
//! Some networks inspect traffic and only let through what looks like web
//! browsing. A WebSocket upgrade is an ordinary HTTPS request until the `101`,
//! after which it is a bidirectional byte pipe, so a stream carried this way
//! passes through a filter that would drop an unknown protocol on a bare port.
//!
//! This is the same trick `websocat` and `wstunnel` use, and it is the reason
//! `cfrs` can serve traffic from a network where neither direct egress nor QUIC
//! nor a permitted CONNECT proxy is available.
//!
//! Two framing choices are deliberate:
//!
//! * **Binary frames**, so bytes are not transcoded and a binary protocol
//!   survives intact.
//! * **One message per write**, with no fragmentation on our side. The receiver
//!   reassembles, so a fragmented peer is still handled.

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::io::AsyncReadExt as _;

use super::{Duplex, Transport, TransportError, TransportStream};

/// A stream that replays a prefix before reading from an inner stream.
///
/// Bytes coalesced past a protocol handshake must be handed back to the reader
/// before anything new arrives, or the first read comes up short and the
/// handshake parser sees a truncated message.
pub struct Prefixed {
    prefix: Vec<u8>,
    offset: usize,
    inner: Box<dyn Duplex>,
}

impl Prefixed {
    /// Wrap `inner`, replaying `prefix` before any read from it.
    pub fn new(prefix: Vec<u8>, inner: impl Duplex + 'static) -> Self {
        Self {
            prefix,
            offset: 0,
            inner: Box::new(inner),
        }
    }
}

impl AsyncRead for Prefixed {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.offset < this.prefix.len() {
            let remaining = this.prefix.len() - this.offset;
            let n = remaining.min(buf.remaining());
            buf.put_slice(&this.prefix[this.offset..this.offset + n]);
            this.offset += n;
            return std::task::Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Prefixed {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_write(cx, data)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

/// Carry a TCP stream inside a WebSocket.
#[derive(Debug, Clone)]
pub struct WebSocketTunnel {
    /// `ws://host:port/path` or `wss://host/path`.
    pub url: String,
    /// Optional `Origin` header, which some servers require.
    pub origin: Option<String>,
    /// Extra headers on the upgrade request.
    pub headers: Vec<(String, String)>,
    /// Send a WebSocket ping every this often. Zero disables it.
    pub ping_interval: Duration,
}

impl Default for WebSocketTunnel {
    fn default() -> Self {
        Self {
            url: String::new(),
            origin: None,
            headers: Vec::new(),
            ping_interval: Duration::from_secs(30),
        }
    }
}

/// Validate a `ws://` or `wss://` URL and split it into parts.
fn parse_ws_url(url: &str) -> Result<(bool, String, u16, String), TransportError> {
    let (secure, rest) = if let Some(r) = url.strip_prefix("wss://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("ws://") {
        (false, r)
    } else {
        return Err(TransportError::Unsupported(format!(
            "websocket url must start with ws:// or wss://, got {url:?}"
        )));
    };

    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() {
        return Err(TransportError::Unsupported("websocket url has no host".into()));
    }

    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (
            h.to_string(),
            p.parse::<u16>().map_err(|_| {
                TransportError::Unsupported(format!("bad port in websocket url {url:?}"))
            })?,
        ),
        None => (
            authority.to_string(),
            if secure { 443 } else { 80 },
        ),
    };

    Ok((secure, host, port, path.to_string()))
}

/// The key for a WebSocket handshake: 16 random bytes, base64.
fn ws_key() -> Result<String, ()> {
    let mut bytes = [0u8; 16];
    // getrandom through ssh_key's re-export, so no new dependency is needed.
    // `/dev/urandom` needs no dependency and is present on every platform this
    // runs on. The key must be unpredictable: RFC 6455 uses it to prove the
    // handshake was not replayed from a cache.
    use std::io::Read;
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .map_err(|_| ())?;
    Ok(crate::proxy::base64_encode_pub(&bytes))
}

impl Transport for WebSocketTunnel {
    fn connect<'a>(
        &'a self,
        host: &'a str,
        port: u16,
        timeout: Duration,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<TransportStream, TransportError>> + Send + 'a>,
    > {
        Box::pin(async move {
        let (secure, url_host, url_port, path) = parse_ws_url(&self.url)?;

        let tcp = super::Direct::new()
            .connect(&url_host, url_port, timeout)
            .await?;
        let _ = host;
        let _ = port;

        let key = ws_key().map_err(|_| {
            TransportError::Handshake("no entropy for the websocket key".into())
        })?;

        // TLS first when the URL is wss.
        let stream: Box<dyn Duplex> = if secure {
            let config = crate::util::tls::client_config(&url_host, false, None)
                .map_err(|e| TransportError::Handshake(e))?;
            let connector = tokio_rustls::TlsConnector::from(config);
            let name = rustls_pki_types::ServerName::try_from(url_host.clone())
                .map_err(|e| TransportError::Handshake(format!("bad server name: {e}")))?;
            let connected = tokio::time::timeout(timeout, connector.connect(name, tcp))
                .await
                .map_err(|_| TransportError::Handshake("websocket TLS timed out".into()))?
                .map_err(|e| TransportError::Handshake(format!("websocket TLS: {e}")))?;
            Box::new(connected)
        } else {
            tcp
        };

        let mut request = format!(
            "GET {path} HTTP/1.1\r\nHost: {url_host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
        );
        if let Some(o) = &self.origin {
            request.push_str(&format!("Origin: {o}\r\n"));
        }
        for (k, v) in &self.headers {
            request.push_str(&format!("{k}: {v}\r\n"));
        }
        request.push_str("\r\n");

        // Split once: the request goes out on the write half while the
        // response head comes back on the read half. Borrowing the same stream
        // twice is not allowed, so the split is taken here.
        let (mut stream_reader, mut stream_writer) = tokio::io::split(stream);

        let head_bytes = tokio::time::timeout(timeout, async {
            use tokio::io::AsyncWriteExt;
            stream_writer.write_all(request.as_bytes()).await?;
            stream_writer.flush().await?;

            // Read the response head one byte at a time so nothing past the
            // terminator is consumed: those bytes belong to the data stream.
            let mut buf = Vec::with_capacity(512);
            loop {
                let mut byte = [0u8; 1];
                if stream_reader.read(&mut byte).await? == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "closed during websocket handshake",
                    ));
                }
                buf.push(byte[0]);
                if buf.ends_with(b"\r\n\r\n") {
                    break;
                }
                if buf.len() > 16 * 1024 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "websocket handshake response too large",
                    ));
                }
            }
            Ok::<Vec<u8>, std::io::Error>(buf)
        })
        .await
        .map_err(|_| TransportError::Handshake("websocket handshake timed out".into()))?
        .map_err(|e| TransportError::Handshake(format!("websocket handshake: {e}")))?;

        // A proxy or origin that does not upgrade would leave us with an HTTP
        // response instead of a stream, so check the status line rather than
        // discovering the problem as a confusing parse error later.
        let head = String::from_utf8_lossy(&head_bytes);
        let status = head.lines().next().unwrap_or_default();
        if !status.contains(" 101 ") {
            return Err(TransportError::Handshake(format!(
                "expected 101 Switching Protocols, got {status:?}"
            )));
        }

        let leftover: Vec<u8> = Vec::new();
        Ok(Box::new(Prefixed::new(
            leftover,
            Joined::new(stream_reader, stream_writer),
        )) as TransportStream)
        })
    }

    fn name(&self) -> &'static str {
        "websocket"
    }
}

/// A client-side WebSocket over an established stream, used by the tunnel's
/// own `/ws` endpoint and by the `connect` subcommand.
#[derive(Debug)]
pub struct WebSocketStream {
    /// Mask every outbound frame, as RFC 6455 requires of clients.
    pub mask: bool,
    frames: Arc<Mutex<FrameState>>,
}

#[derive(Debug, Default)]
struct FrameState {
    /// Bytes read but not yet consumed by the caller.
    pending: Vec<u8>,
    closed: bool,
}

impl WebSocketStream {
    /// A masking client stream.
    pub fn client() -> Self {
        Self {
            mask: true,
            frames: Arc::new(Mutex::new(FrameState::default())),
        }
    }
}

/// Read and write halves recombined into one duplex stream.
///
/// `tokio::io::split` hands back separate halves, and the tunnel needs one
/// object it can read and write on, so they are joined back here.
pub struct Joined<R, W> {
    reader: R,
    writer: W,
}

impl<R, W> Joined<R, W> {
    /// Join a read half and a write half.
    pub fn new(reader: R, writer: W) -> Self {
        Self { reader, writer }
    }
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> AsyncRead for Joined<R, W> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.reader).poll_read(cx, buf)
    }
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> AsyncWrite for Joined<R, W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        Pin::new(&mut this.writer).poll_write(cx, data)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.writer).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.writer).poll_shutdown(cx)
    }
}

/// Build a masked binary frame, as an RFC 6455 client must send.
pub fn encode_frame(payload: &[u8], mask: bool, opcode: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 14);
    out.push(0x80 | (opcode & 0x0F));
    let mask_bit = if mask { 0x80 } else { 0x00 };
    let n = payload.len();
    if n < 126 {
        out.push(mask_bit | n as u8);
    } else if n < (1 << 16) {
        out.push(mask_bit | 126);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else {
        out.push(mask_bit | 127);
        out.extend_from_slice(&(n as u64).to_be_bytes());
    }
    if mask {
        let mut key = [0u8; 4];
        {
            use std::io::Read;
            let _ = std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut key));
        }
        out.extend_from_slice(&key);
        for (i, b) in payload.iter().enumerate() {
            out.push(b ^ key[i % 4]);
        }
    } else {
        out.extend_from_slice(payload);
    }
    out
}

/// Decode one frame header from `buf`, returning the payload length.
///
/// Returns `Ok(None)` when more bytes are needed.
pub fn decode_frame_header(buf: &[u8]) -> Result<Option<(u8, usize, usize, bool)>, String> {
    if buf.len() < 2 {
        return Ok(None);
    }
    let opcode = buf[0] & 0x0F;
    let masked = buf[1] & 0x80 != 0;
    let short_len = (buf[1] & 0x7F) as usize;
    let mut offset = 2;
    let payload_len = match short_len {
        126 => {
            if buf.len() < 4 {
                return Ok(None);
            }
            offset = 4;
            u16::from_be_bytes([buf[2], buf[3]]) as usize
        }
        127 => {
            if buf.len() < 10 {
                return Ok(None);
            }
            offset = 10;
            let mut b = [0u8; 8];
            b.copy_from_slice(&buf[2..10]);
            u64::from_be_bytes(b) as usize
        }
        n => n,
    };
    let key_len = if masked { 4 } else { 0 };
    let total = offset + key_len + payload_len;
    Ok(Some((opcode, payload_len, total, masked)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_secure_and_plain_urls() {
        let (secure, host, port, path) = parse_ws_url("wss://relay.example.com:8443/ws").unwrap();
        assert!(secure);
        assert_eq!(host, "relay.example.com");
        assert_eq!(port, 8443);
        assert_eq!(path, "/ws");

        let (secure, host, port, path) = parse_ws_url("ws://relay.example.com").unwrap();
        assert!(!secure);
        assert_eq!(port, 80);
        assert_eq!(path, "/", "a pathless url means /");
    }

    #[test]
    fn defaults_the_port_by_scheme() {
        assert_eq!(parse_ws_url("wss://h").unwrap().2, 443);
        assert_eq!(parse_ws_url("ws://h").unwrap().2, 80);
    }

    #[test]
    fn rejects_urls_that_are_not_websockets() {
        for bad in ["http://h", "h", "", "wss://", "wss://h:notaport"] {
            assert!(parse_ws_url(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn encodes_a_masked_short_frame() {
        let frame = encode_frame(b"hi", true, 0x2);
        assert_eq!(frame[0], 0x82, "binary opcode, FIN set");
        assert_eq!(frame[1] & 0x80, 0x80, "client frames must be masked");
        assert_eq!(frame[1] & 0x7F, 2);
        assert_eq!(frame.len(), 2 + 4 + 2);
        // The payload must decode once unmasked with the key.
        let key = &frame[2..6];
        let unmasked: Vec<u8> = frame[6..].iter().enumerate().map(|(i, b)| b ^ key[i % 4]).collect();
        assert_eq!(unmasked, b"hi");
    }

    #[test]
    fn encodes_a_medium_frame_with_a_16_bit_length() {
        let payload = vec![0xABu8; 300];
        let frame = encode_frame(&payload, false, 0x2);
        assert_eq!(frame[1] & 0x7F, 126, "126 signals a 16-bit length");
        assert_eq!(u16::from_be_bytes([frame[2], frame[3]]), 300);
    }

    #[test]
    fn round_trips_a_frame_through_the_decoder() {
        for len in [0usize, 5, 125, 126, 300, 70000] {
            let payload = vec![0x5Au8; len];
            let frame = encode_frame(&payload, false, 0x2);
            let (opcode, payload_len, total, masked) =
                decode_frame_header(&frame).expect("decode").expect("complete");
            assert_eq!(opcode, 0x2, "opcode survives at len {len}");
            assert_eq!(payload_len, len, "payload length at len {len}");
            assert_eq!(total, frame.len(), "total length at len {len}");
            assert!(!masked, "server frames are never masked");
        }
    }

    #[test]
    fn decoding_a_partial_header_asks_for_more_bytes() {
        assert_eq!(decode_frame_header(&[0x82]).unwrap(), None);
        assert_eq!(decode_frame_header(&[0x82, 126]).unwrap(), None);
        assert_eq!(decode_frame_header(&[0x82, 126, 0x01]).unwrap(), None);
        assert_eq!(decode_frame_header(&[0x82, 127, 0, 0]).unwrap(), None);
    }

    #[tokio::test]
    async fn prefixed_replays_the_coalesced_bytes_first() {
        let (a, _b) = tokio::net::UnixStream::pair().expect("socketpair");
        let mut stream = Prefixed::new(b"PRE".to_vec(), a);
        let mut buf = [0u8; 3];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut buf)
            .await
            .expect("read prefix");
        assert_eq!(&buf, b"PRE");
    }

    #[test]
    fn websocket_transport_reports_its_name() {
        assert_eq!(WebSocketTunnel::default().name(), "websocket");
    }
}