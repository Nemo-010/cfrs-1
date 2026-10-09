//! The shim/stack control protocol.
//!
//! The shim's `bind`/`connect` connects to `\0cfrsnet/ctl` and registers the
//! logical endpoint; the stack binds the corresponding abstract name and
//! multiplexes logical connections over one `AF_UNIX` connection with a
//! per-connection stream id. File descriptors are never passed (`SCM_RIGHTS`),
//! so the stack is independent of the shim's process lifetime.
//!
//! Framing is the document's:
//!
//! ```text
//! u8 op | u16 len | payload
//! ```
//!
//! with `len` being the payload length only.

use anyhow::{bail, Result};

use crate::vnet::addr::{Family, VirtAddr};

/// Protocol version exchanged in [`ControlMessage::Hello`].
pub const CONTROL_VERSION: u16 = 1;
/// Largest payload a single control frame may carry.
pub const MAX_CONTROL_PAYLOAD: usize = u16::MAX as usize;

/// Control message kinds. The first four are the document's; the rest are the
/// extension needed for stream multiplexing, datagrams, backpressure and
/// liveness.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ControlOp {
    RegisterBind = 1,
    RegisterConnect = 2,
    Unregister = 3,
    Datagram = 4,
    /// Stream payload for `id`.
    Data = 5,
    /// Half-close for `id`.
    Eof = 6,
    /// Abort for `id`.
    Reset = 7,
    Ack = 8,
    Error = 9,
    Hello = 10,
    Ping = 11,
    Pong = 12,
}

impl ControlOp {
    pub fn from_u8(value: u8) -> Result<Self> {
        Ok(match value {
            1 => Self::RegisterBind,
            2 => Self::RegisterConnect,
            3 => Self::Unregister,
            4 => Self::Datagram,
            5 => Self::Data,
            6 => Self::Eof,
            7 => Self::Reset,
            8 => Self::Ack,
            9 => Self::Error,
            10 => Self::Hello,
            11 => Self::Ping,
            12 => Self::Pong,
            other => bail!("unknown control op {other}"),
        })
    }
}

/// Error codes carried by [`ControlMessage::Error`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ErrorCode {
    /// No route or no listener.
    Refused = 1,
    /// ACL denied the destination.
    Denied = 2,
    /// The virtual address could not be bound.
    AddressInUse = 3,
    /// Malformed request.
    BadRequest = 4,
    /// Out of sockets.
    ResourceExhausted = 5,
    /// The destination address is not in the virtual subnet.
    NoRoute = 6,
}

impl ErrorCode {
    pub fn from_u8(value: u8) -> Self {
        match value {
            2 => Self::Denied,
            3 => Self::AddressInUse,
            4 => Self::BadRequest,
            5 => Self::ResourceExhausted,
            6 => Self::NoRoute,
            _ => Self::Refused,
        }
    }
}

/// A decoded control message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ControlMessage {
    Hello { version: u16, features: u32 },
    RegisterBind { id: u32, addr: VirtAddr },
    RegisterConnect { id: u32, addr: VirtAddr },
    Unregister { id: u32 },
    Datagram { id: u32, from: VirtAddr, to: VirtAddr, data: Vec<u8> },
    Data { id: u32, data: Vec<u8> },
    Eof { id: u32 },
    Reset { id: u32 },
    Ack { id: u32 },
    Error { id: u32, code: ErrorCode, message: String },
    Ping { token: u64 },
    Pong { token: u64 },
}

impl ControlMessage {
    pub fn op(&self) -> ControlOp {
        match self {
            Self::Hello { .. } => ControlOp::Hello,
            Self::RegisterBind { .. } => ControlOp::RegisterBind,
            Self::RegisterConnect { .. } => ControlOp::RegisterConnect,
            Self::Unregister { .. } => ControlOp::Unregister,
            Self::Datagram { .. } => ControlOp::Datagram,
            Self::Data { .. } => ControlOp::Data,
            Self::Eof { .. } => ControlOp::Eof,
            Self::Reset { .. } => ControlOp::Reset,
            Self::Ack { .. } => ControlOp::Ack,
            Self::Error { .. } => ControlOp::Error,
            Self::Ping { .. } => ControlOp::Ping,
            Self::Pong { .. } => ControlOp::Pong,
        }
    }

    /// The stream id this message belongs to, when it has one.
    pub fn id(&self) -> Option<u32> {
        match self {
            Self::RegisterBind { id, .. }
            | Self::RegisterConnect { id, .. }
            | Self::Unregister { id }
            | Self::Datagram { id, .. }
            | Self::Data { id, .. }
            | Self::Eof { id }
            | Self::Reset { id }
            | Self::Ack { id }
            | Self::Error { id, .. } => Some(*id),
            Self::Hello { .. } | Self::Ping { .. } | Self::Pong { .. } => None,
        }
    }

    /// Encode as `op | u16 len | payload`.
    ///
    /// No control frame may exceed [`MAX_CONTROL_PAYLOAD`] bytes of payload,
    /// because the length field is a `u16`. A `Data` or `Datagram` body that
    /// would exceed it is truncated at the wire limit (the in-tree producers
    /// chunk at 4 KiB well below it); an `Error` message is truncated before
    /// its length prefix so the frame always stays self-consistent.
    pub fn encode(&self) -> Vec<u8> {
        let mut payload = self.encode_payload();
        payload.truncate(MAX_CONTROL_PAYLOAD);
        let mut out = Vec::with_capacity(payload.len() + 3);
        out.push(self.op() as u8);
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        out.extend_from_slice(&payload);
        out
    }

    fn encode_payload(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Self::Hello { version, features } => {
                out.extend_from_slice(&version.to_be_bytes());
                out.extend_from_slice(&features.to_be_bytes());
            }
            Self::RegisterBind { id, addr } | Self::RegisterConnect { id, addr } => {
                out.extend_from_slice(&id.to_be_bytes());
                encode_addr(&mut out, addr);
            }
            Self::Unregister { id }
            | Self::Eof { id }
            | Self::Reset { id }
            | Self::Ack { id } => out.extend_from_slice(&id.to_be_bytes()),
            Self::Datagram { id, from, to, data } => {
                out.extend_from_slice(&id.to_be_bytes());
                encode_addr(&mut out, from);
                encode_addr(&mut out, to);
                out.extend_from_slice(data);
            }
            Self::Data { id, data } => {
                out.extend_from_slice(&id.to_be_bytes());
                out.extend_from_slice(data);
            }
            Self::Error { id, code, message } => {
                // id(4) + code(1) + len(2) = 7 bytes of overhead.
                // id(4) + code(1) + msg_len(2) + message. The message length is a
                // separate field inside the payload, and the decoder requires
                // it, so it has to be written even when the message is clipped.
                // The clip is on a character boundary: the reference
                // implementation clipped at a raw byte budget, which panics when
                // the budget lands inside a multi-byte character and yields
                // invalid UTF-8 when it does not.
                let body = floor_char_boundary(message, u16::MAX as usize - 7);
                let mut payload = Vec::with_capacity(7 + body);
                payload.extend_from_slice(&id.to_be_bytes());
                payload.push(*code as u8);
                payload.extend_from_slice(&(body as u16).to_be_bytes());
                payload.extend_from_slice(message.as_bytes().get(..body).unwrap_or(&[]));
                out.extend_from_slice(&payload);
            }
            Self::Ping { token } | Self::Pong { token } => {
                out.extend_from_slice(&token.to_be_bytes());
            }
        }
        out
    }

    /// Decode one frame. Returns `Ok(None)` when `buf` holds only part of a
    /// frame, and the number of consumed bytes otherwise.
    pub fn decode(buf: &[u8]) -> Result<Option<(Self, usize)>> {
        if buf.len() < 3 {
            return Ok(None);
        }
        let op = ControlOp::from_u8(buf[0])?;
        let len = u16::from_be_bytes([buf[1], buf[2]]) as usize;
        let total = 3 + len;
        if buf.len() < total {
            return Ok(None);
        }
        let payload = &buf[3..total];
        let message = decode_payload(op, payload)?;
        Ok(Some((message, total)))
    }
}

fn encode_addr(out: &mut Vec<u8>, addr: &VirtAddr) {
    match addr.ip {
        std::net::IpAddr::V4(ip) => {
            out.push(Family::V4.number());
            out.extend_from_slice(&ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            out.push(Family::V6.number());
            out.extend_from_slice(&ip.octets());
        }
    }
    out.extend_from_slice(&addr.port.to_be_bytes());
}

fn decode_addr(payload: &[u8], offset: &mut usize) -> Result<VirtAddr> {
    let family = *payload
        .get(*offset)
        .ok_or_else(|| anyhow::anyhow!("control frame ends before the family"))?;
    *offset += 1;
    let (ip, width) = match Family::from_number(family)? {
        Family::V4 => {
            let bytes: [u8; 4] = payload
                .get(*offset..*offset + 4)
                .ok_or_else(|| anyhow::anyhow!("control frame ends before the IPv4 address"))?
                .try_into()
                .unwrap();
            (std::net::IpAddr::V4(bytes.into()), 4)
        }
        Family::V6 => {
            let bytes: [u8; 16] = payload
                .get(*offset..*offset + 16)
                .ok_or_else(|| anyhow::anyhow!("control frame ends before the IPv6 address"))?
                .try_into()
                .unwrap();
            (std::net::IpAddr::V6(bytes.into()), 16)
        }
    };
    *offset += width;
    let port = u16::from_be_bytes(
        payload
            .get(*offset..*offset + 2)
            .ok_or_else(|| anyhow::anyhow!("control frame ends before the port"))?
            .try_into()
            .unwrap(),
    );
    *offset += 2;
    Ok(VirtAddr::new(ip, port))
}

fn take_u32(payload: &[u8], offset: &mut usize) -> Result<u32> {
    let bytes: [u8; 4] = payload
        .get(*offset..*offset + 4)
        .ok_or_else(|| anyhow::anyhow!("control frame ends before a u32 field"))?
        .try_into()
        .unwrap();
    *offset += 4;
    Ok(u32::from_be_bytes(bytes))
}

fn take_u64(payload: &[u8], offset: &mut usize) -> Result<u64> {
    let bytes: [u8; 8] = payload
        .get(*offset..*offset + 8)
        .ok_or_else(|| anyhow::anyhow!("control frame ends before a u64 field"))?
        .try_into()
        .unwrap();
    *offset += 8;
    Ok(u64::from_be_bytes(bytes))
}

fn decode_payload(op: ControlOp, payload: &[u8]) -> Result<ControlMessage> {
    let mut offset = 0usize;
    Ok(match op {
        ControlOp::Hello => {
            let version = u16::from_be_bytes(
                payload
                    .get(0..2)
                    .ok_or_else(|| anyhow::anyhow!("Hello frame is too short"))?
                    .try_into()
                    .unwrap(),
            );
            let features = u32::from_be_bytes(
                payload
                    .get(2..6)
                    .ok_or_else(|| anyhow::anyhow!("Hello frame is too short"))?
                    .try_into()
                    .unwrap(),
            );
            ControlMessage::Hello { version, features }
        }
        ControlOp::RegisterBind => {
            let id = take_u32(payload, &mut offset)?;
            let addr = decode_addr(payload, &mut offset)?;
            ControlMessage::RegisterBind { id, addr }
        }
        ControlOp::RegisterConnect => {
            let id = take_u32(payload, &mut offset)?;
            let addr = decode_addr(payload, &mut offset)?;
            ControlMessage::RegisterConnect { id, addr }
        }
        ControlOp::Unregister => ControlMessage::Unregister { id: take_u32(payload, &mut offset)? },
        ControlOp::Eof => ControlMessage::Eof { id: take_u32(payload, &mut offset)? },
        ControlOp::Reset => ControlMessage::Reset { id: take_u32(payload, &mut offset)? },
        ControlOp::Ack => ControlMessage::Ack { id: take_u32(payload, &mut offset)? },
        ControlOp::Datagram => {
            let id = take_u32(payload, &mut offset)?;
            let from = decode_addr(payload, &mut offset)?;
            let to = decode_addr(payload, &mut offset)?;
            ControlMessage::Datagram {
                id,
                from,
                to,
                data: payload[offset..].to_vec(),
            }
        }
        ControlOp::Data => {
            let id = take_u32(payload, &mut offset)?;
            ControlMessage::Data { id, data: payload[offset..].to_vec() }
        }
        ControlOp::Error => {
            let id = take_u32(payload, &mut offset)?;
            let code = ErrorCode::from_u8(
                *payload
                    .get(offset)
                    .ok_or_else(|| anyhow::anyhow!("Error frame has no code"))?,
            );
            offset += 1;
            let len = u16::from_be_bytes(
                payload
                    .get(offset..offset + 2)
                    .ok_or_else(|| anyhow::anyhow!("Error frame has no message length"))?
                    .try_into()
                    .unwrap(),
            ) as usize;
            offset += 2;
            let message = String::from_utf8_lossy(
                payload
                    .get(offset..offset + len)
                    .ok_or_else(|| anyhow::anyhow!("Error frame message is truncated"))?,
            )
            .into_owned();
            ControlMessage::Error { id, code, message }
        }
        ControlOp::Ping => ControlMessage::Ping { token: take_u64(payload, &mut offset)? },
        ControlOp::Pong => ControlMessage::Pong { token: take_u64(payload, &mut offset)? },
    })
}

/// An incremental control-protocol decoder over a byte stream.
/// Frames decoded from a single `push` before the resynchronisation loop gives
/// up, so a peer streaming rubbish cannot spin a caller forever.
const MAX_FRAMES_PER_PUSH: usize = 1024;

/// The largest index at or below `limit` that is a UTF-8 character boundary.
///
/// A `&str` may only be sliced at a character boundary, so every byte-budget
/// truncation of a `&str` has to go through this rather than through `min`. A
/// budget that lands mid-character and is then sliced panics.
fn floor_char_boundary(text: &str, limit: usize) -> usize {
    if limit >= text.len() {
        return text.len();
    }
    let mut cut = limit;
    while cut > 0 && !text.is_char_boundary(cut) {
        cut -= 1;
    }
    cut
}

/// The total byte length of the frame at the head of `buf`, if the header
/// names one.
///
/// `None` when there are not yet three bytes to read a header, which means the
/// frame is merely incomplete and must be kept rather than dropped.
fn frame_length(buf: &[u8]) -> Option<usize> {
    if buf.len() < 3 {
        return None;
    }
    let len = u16::from_be_bytes([buf[1], buf[2]]) as usize;
    Some(3 + len)
}

#[derive(Debug, Default)]
pub struct ControlDecoder {
    buffer: Vec<u8>,
    dropped_frames: u32,
}

impl ControlDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed more bytes and take every complete message out of the buffer.
    ///
    /// A frame with an unknown opcode is dropped rather than wedging the stream.
    /// The reference implementation returned the error with the offending byte
    /// still at the head of the buffer, so every later `push` re-read the same
    /// byte, failed identically, and never drained: the connection was
    /// permanently desynchronised and the buffer grew with everything the peer
    /// kept sending. Dropping the bad frame keeps the decoder usable, and
    /// reporting the drop lets the caller log it.
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<ControlMessage>> {
        self.buffer.extend_from_slice(bytes);
        let mut messages = Vec::new();
        loop {
            match ControlMessage::decode(&self.buffer) {
                Ok(Some((message, used))) => {
                    self.buffer.drain(..used);
                    messages.push(message);
                }
                // A partial frame at the head: wait for more bytes.
                Ok(None) => break,
                Err(e) => {
                    // Resynchronise on the frame boundary the length prefix
                    // describes, not on a single byte.
                    //
                    // The header is op(1) | len(2), so once the opcode is known
                    // the frame's total length is known even when the payload
                    // will not decode. Dropping that whole frame is what keeps a
                    // good frame behind the rubbish decodable: dropping one byte
                    // at a time would walk into the middle of the next frame,
                    // reinterpret its payload bytes as an opcode, and consume
                    // it as rubbish.
                    let skip = match frame_length(&self.buffer) {
                        Some(len) => len,
                        // Fewer than three bytes and still undecodable, which
                        // cannot happen for a well-formed header but can for a
                        // peer sending noise. Wait for more bytes.
                        None => break,
                    };
                    tracing::warn!(bytes = skip, error = %e, "control frame dropped");
                    self.dropped_frames += 1;
                    self.buffer.drain(..skip.min(self.buffer.len()));
                    // Bound the work one push can do, so a peer streaming
                    // rubbish cannot spin this loop for the length of the
                    // stream.
                    if messages.len() + self.dropped_frames as usize >= MAX_FRAMES_PER_PUSH {
                        break;
                    }
                }
            }
        }
        Ok(messages)
    }

    /// How many frames have been discarded as undecodable since this decoder
    /// was created. A non-zero value means the peer is speaking something other
    /// than this protocol.
    pub fn dropped(&self) -> u32 {
        self.dropped_frames
    }

    pub fn pending(&self) -> usize {
        self.buffer.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(message: ControlMessage) {
        let bytes = message.encode();
        assert_eq!(bytes[0], message.op() as u8);
        let (decoded, used) = ControlMessage::decode(&bytes).unwrap().unwrap();
        assert_eq!(used, bytes.len());
        assert_eq!(decoded, message);
    }

    #[test]
    fn messages_round_trip() {
        round_trip(ControlMessage::Hello { version: CONTROL_VERSION, features: 0x7 });
        round_trip(ControlMessage::RegisterBind {
            id: 7,
            addr: VirtAddr::v4("10.66.0.2".parse().unwrap(), 8080),
        });
        round_trip(ControlMessage::RegisterConnect {
            id: 8,
            addr: VirtAddr::v6("fd00::2".parse().unwrap(), 443),
        });
        round_trip(ControlMessage::Unregister { id: 9 });
        round_trip(ControlMessage::Datagram {
            id: 10,
            from: VirtAddr::v4("10.66.0.2".parse().unwrap(), 5353),
            to: VirtAddr::v4("10.66.0.1".parse().unwrap(), 53),
            data: b"dns".to_vec(),
        });
        round_trip(ControlMessage::Data { id: 11, data: vec![0, 1, 2, 255] });
        round_trip(ControlMessage::Eof { id: 12 });
        round_trip(ControlMessage::Reset { id: 13 });
        round_trip(ControlMessage::Ack { id: 14 });
        round_trip(ControlMessage::Error {
            id: 15,
            code: ErrorCode::Denied,
            message: "blocked by ACL".into(),
        });
        round_trip(ControlMessage::Ping { token: 0xdead_beef_cafe_f00d });
        round_trip(ControlMessage::Pong { token: 1 });
    }

    #[test]
    fn decoder_is_incremental() {
        let a = ControlMessage::Data { id: 1, data: b"hello".to_vec() }.encode();
        let b = ControlMessage::Eof { id: 1 }.encode();
        let mut decoder = ControlDecoder::new();
        // Feed one byte at a time; nothing completes until the whole frame.
        let mut messages = Vec::new();
        for byte in a.iter().chain(b.iter()) {
            messages.extend(decoder.push(&[*byte]).unwrap());
        }
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0], ControlMessage::Data { id: 1, data: b"hello".to_vec() });
        assert_eq!(messages[1], ControlMessage::Eof { id: 1 });
        assert_eq!(decoder.pending(), 0);
    }

    #[test]
    fn decode_reports_none_on_partial() {
        let bytes = ControlMessage::Data { id: 1, data: b"abc".to_vec() }.encode();
        assert!(ControlMessage::decode(&bytes[..2]).unwrap().is_none());
        assert!(ControlMessage::decode(&bytes[..bytes.len() - 1]).unwrap().is_none());
    }

    #[test]
    fn id_is_reported() {
        assert_eq!(ControlMessage::Ping { token: 0 }.id(), None);
        assert_eq!(ControlMessage::Data { id: 4, data: vec![] }.id(), Some(4));
    }

    #[test]
    fn oversized_frames_stay_self_consistent() {
        // A Data body over the u16 limit must not wrap the length field.
        let big = ControlMessage::Data { id: 1, data: vec![7u8; MAX_CONTROL_PAYLOAD + 100] };
        let bytes = big.encode();
        assert_eq!(bytes.len(), 3 + MAX_CONTROL_PAYLOAD);
        let (decoded, used) = ControlMessage::decode(&bytes).unwrap().unwrap();
        assert_eq!(used, bytes.len());
        assert_eq!(decoded, ControlMessage::Data { id: 1, data: vec![7u8; MAX_CONTROL_PAYLOAD - 4] });
        // An Error message that hits the limit is cut before its length prefix.
        let long = ControlMessage::Error {
            id: 2,
            code: ErrorCode::BadRequest,
            message: "e".repeat(MAX_CONTROL_PAYLOAD + 100),
        };
        let (decoded, used) = ControlMessage::decode(&long.encode()).unwrap().unwrap();
        assert_eq!(used, 3 + MAX_CONTROL_PAYLOAD);
        let ControlMessage::Error { message, .. } = decoded else { panic!("wrong kind") };
        assert_eq!(message.len(), MAX_CONTROL_PAYLOAD - 7);
    }
}
