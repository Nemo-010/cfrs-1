//! Packet framing for a byte-oriented link.
//!
//! A stream link (QUIC, TLS, a unix socket, a `cfrs` forward WebSocket carried
//! as a byte pipe) has no message boundaries, but the stack hands the device
//! one IP packet at a time. Every packet is therefore written as:
//!
//! ```text
//! u16 big-endian length | packet bytes
//! ```
//!
//! A link that already preserves message boundaries (a WebSocket binary
//! message, an `AF_UNIX` `SOCK_DGRAM` datagram) can use one packet per
//! message and skip the prefix; [`FrameDecoder`] is only needed for streams.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Largest packet the framing can carry, the `u16` length field.
pub const MAX_FRAME: usize = u16::MAX as usize;

/// Write one length-prefixed frame.
pub async fn write_frame<W>(writer: &mut W, packet: &[u8]) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    if packet.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "empty frame (a zero-length packet is never a valid link frame)",
        ));
    }
    if packet.len() > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("packet of {} bytes exceeds the {MAX_FRAME}-byte frame limit", packet.len()),
        ));
    }
    let header = (packet.len() as u16).to_be_bytes();
    writer.write_all(&header).await?;
    writer.write_all(packet).await?;
    writer.flush().await?;
    Ok(())
}

/// Read one length-prefixed frame into `packet`, replacing its contents.
///
/// Returns `Ok(None)` on a clean end of stream before any header byte, and
/// `Err` on a truncated header, a truncated body, or a zero-length frame
/// (which is never produced by [`write_frame`]).
pub async fn read_frame<R>(reader: &mut R, packet: &mut Vec<u8>) -> io::Result<Option<usize>>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; 2];
    match reader.read(&mut header[..1]).await {
        Ok(0) => return Ok(None),
        Ok(_) => {}
        Err(err) => return Err(err),
    }
    reader.read_exact(&mut header[1..]).await.map_err(|err| {
        if err.kind() == io::ErrorKind::UnexpectedEof {
            io::Error::new(io::ErrorKind::UnexpectedEof, "truncated frame header")
        } else {
            err
        }
    })?;
    let len = u16::from_be_bytes(header) as usize;
    if len == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "zero-length frame",
        ));
    }
    packet.clear();
    packet.resize(len, 0);
    reader.read_exact(packet).await?;
    Ok(Some(len))
}

/// An incremental decoder for a stream that is fed bytes in arbitrary chunks.
#[derive(Debug, Default)]
pub struct FrameDecoder {
    buffer: Vec<u8>,
    frame: Vec<u8>,
    expected: Option<usize>,
}

impl FrameDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of bytes buffered but not yet returned as a frame.
    pub fn buffered(&self) -> usize {
        self.buffer.len()
    }

    /// Feed bytes and pull out every complete frame.
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        self.buffer.extend_from_slice(bytes);
        let mut frames = Vec::new();
        loop {
            if self.expected.is_none() {
                if self.buffer.len() < 2 {
                    break;
                }
                let len = u16::from_be_bytes([self.buffer[0], self.buffer[1]]) as usize;
                if len == 0 {
                    // A zero-length frame cannot be told from the start of the
                    // next one by the length alone, so the decoder has no way to
                    // resynchronise: every later push re-reads the same two
                    // bytes and fails identically. Returning the error with
                    // those bytes still at the head wedges the decoder for the
                    // life of the connection and grows the buffer without
                    // bound. Report it and stop, so the caller can drop the
                    // connection deliberately rather than being stuck.
                    self.expected = None;
                    self.frame.clear();
                    return Err("zero-length frame".into());
                }
                self.expected = Some(len);
                self.buffer.drain(..2);
                self.frame.clear();
                self.frame.reserve(len);
            }
            let want = self.expected.unwrap_or(0).saturating_sub(self.frame.len());
            let take = want.min(self.buffer.len());
            if take > 0 {
                self.frame.extend_from_slice(&self.buffer[..take]);
                self.buffer.drain(..take);
            }
            if self.frame.len() == self.expected.unwrap_or(0) {
                frames.push(std::mem::take(&mut self.frame));
                self.expected = None;
            } else {
                break;
            }
        }
        Ok(frames)
    }
}

/// Synchronous framing helpers, for record/replay and tests.
pub struct FrameEncoder;

impl FrameEncoder {
    /// Encode one frame with its length prefix.
    pub fn encode(packet: &[u8]) -> Result<Vec<u8>, String> {
        let mut out = Vec::with_capacity(packet.len() + 2);
        Self::encode_into(&mut out, packet)?;
        Ok(out)
    }

    /// Encode and append to `out`.
    pub fn encode_into(out: &mut Vec<u8>, packet: &[u8]) -> Result<(), String> {
        if packet.is_empty() {
            return Err("empty frame (a zero-length packet is never a valid link frame)".into());
        }
        if packet.len() > MAX_FRAME {
            return Err(format!("packet of {} bytes exceeds {MAX_FRAME}", packet.len()));
        }
        out.extend_from_slice(&(packet.len() as u16).to_be_bytes());
        out.extend_from_slice(packet);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoder_round_trips_through_decoder() {
        let mut decoder = FrameDecoder::new();
        let frames = decoder.push(b"\x00\x03abc\x00\x01z").unwrap();
        assert_eq!(frames, vec![b"abc".to_vec(), b"z".to_vec()]);
        assert_eq!(decoder.buffered(), 0);
    }

    #[test]
    fn decoder_handles_split_and_merged_chunks() {
        let mut decoder = FrameDecoder::new();
        let mut all = Vec::new();
        all.extend(decoder.push(&[0x00]).unwrap());
        all.extend(decoder.push(&[0x03, b'h']).unwrap());
        all.extend(decoder.push(b"i!\x00\x01").unwrap());
        all.extend(decoder.push(b"Z").unwrap());
        assert_eq!(all, vec![b"hi!".to_vec(), b"Z".to_vec()]);
        assert_eq!(decoder.buffered(), 0);
    }

    #[test]
    fn decoder_rejects_zero_length() {
        let mut decoder = FrameDecoder::new();
        assert!(decoder.push(&[0, 0]).is_err());
    }

    #[test]
    fn encoder_matches_write_frame_layout() {
        assert_eq!(FrameEncoder::encode(b"hi").unwrap(), b"\x00\x02hi");
        let mut out = Vec::new();
        FrameEncoder::encode_into(&mut out, b"abc").unwrap();
        FrameEncoder::encode_into(&mut out, b"z").unwrap();
        assert_eq!(out, b"\x00\x03abc\x00\x01z");
        // The encoder and the decoder agree on the layout.
        let mut decoder = FrameDecoder::new();
        assert_eq!(decoder.push(&out).unwrap(), vec![b"abc".to_vec(), b"z".to_vec()]);
        // The encoder and the decoder agree that a zero-length frame is junk.
        assert!(FrameEncoder::encode(b"").is_err());
    }

    #[tokio::test]
    async fn async_round_trip_and_eof() {
        let (mut a, mut b) = tokio::io::duplex(64);
        let writer = tokio::spawn(async move {
            write_frame(&mut a, b"GET / HTTP/1.0").await.unwrap();
            write_frame(&mut a, &[0u8; 300]).await.unwrap();
        });
        let mut packet = Vec::new();
        let n = read_frame(&mut b, &mut packet).await.unwrap();
        assert_eq!(n, Some(14));
        assert_eq!(packet, b"GET / HTTP/1.0");
        let n = read_frame(&mut b, &mut packet).await.unwrap();
        assert_eq!(n, Some(300));
        assert_eq!(packet.len(), 300);
        // Clean EOF after the last frame.
        assert_eq!(read_frame(&mut b, &mut packet).await.unwrap(), None);
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn read_frame_rejects_truncated_body() {
        let (mut a, mut b) = tokio::io::duplex(8);
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            a.write_all(b"\x00\x05ab").await.unwrap();
            drop(a);
        });
        let mut packet = Vec::new();
        let err = read_frame(&mut b, &mut packet).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }
}
