//! Packet capture, record and replay.
//!
//! Every packet that crosses the virtual link can be captured, written to a
//! `.pcap` for Wireshark, replayed into a deterministic stack, or compared
//! between two stack versions. None of it needs `CAP_NET_RAW`, a host
//! interface, or `tcpdump`, because the "wire" is the in-process queue.

use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

/// Which way a captured packet was travelling.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    /// Link -> stack.
    Inbound,
    /// Stack -> link.
    Outbound,
}

/// One captured packet.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordedPacket {
    /// Milliseconds since the recorder was created.
    pub timestamp_ms: i64,
    pub direction: Direction,
    /// Base64 is not needed: serde_json encodes a byte vector as an array.
    pub data: Vec<u8>,
}

impl RecordedPacket {
    pub fn new(timestamp_ms: i64, direction: Direction, data: Vec<u8>) -> Self {
        Self { timestamp_ms, direction, data }
    }
}

#[derive(Debug)]
struct RecorderState {
    packets: Vec<RecordedPacket>,
    limit: usize,
    start: Instant,
}

/// A packet sink shared by a device wrapper and the reactor.
///
/// Cloning a `Recorder` shares its packets *and* its time origin, so a clone
/// that records stamps packets on the same timeline as the original.
#[derive(Clone, Debug)]
pub struct Recorder {
    state: Arc<Mutex<RecorderState>>,
}

impl Default for Recorder {
    fn default() -> Self {
        Self::new()
    }
}

impl Recorder {
    pub fn new() -> Self {
        Self::with_limit(usize::MAX)
    }

    /// A recorder that keeps at most `limit` packets, dropping the oldest.
    pub fn with_limit(limit: usize) -> Self {
        Self {
            state: Arc::new(Mutex::new(RecorderState {
                packets: Vec::new(),
                limit: limit.max(1),
                start: Instant::now(),
            })),
        }
    }

    /// Record one packet. `packet` may be empty; an empty frame is preserved
    /// rather than silently dropped.
    pub fn record(&self, direction: Direction, packet: &[u8]) {
        let timestamp_ms = self
            .state
            .lock()
            .unwrap()
            .start
            .elapsed()
            .as_millis() as i64;
        self.record_at(timestamp_ms, direction, packet);
    }

    pub fn record_at(&self, timestamp_ms: i64, direction: Direction, packet: &[u8]) {
        let mut state = self.state.lock().unwrap();
        if state.packets.len() >= state.limit {
            state.packets.remove(0);
        }
        state
            .packets
            .push(RecordedPacket::new(timestamp_ms, direction, packet.to_vec()));
    }

    pub fn packets(&self) -> Vec<RecordedPacket> {
        self.state.lock().unwrap().packets.clone()
    }

    pub fn len(&self) -> usize {
        self.state.lock().unwrap().packets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn clear(&self) {
        self.state.lock().unwrap().packets.clear();
    }

    /// Serialize as `.pcap` bytes (link type 101, raw IP).
    pub fn pcap_bytes(&self) -> Vec<u8> {
        PcapFile::encode(&self.packets())
    }

    pub fn write_pcap(&self, path: &std::path::Path) -> Result<()> {
        std::fs::write(path, self.pcap_bytes())
            .with_context(|| format!("writing pcap {}", path.display()))?;
        Ok(())
    }

    /// Serialize as JSON for a faithful record (direction and relative time).
    pub fn save_json(&self, path: &std::path::Path) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(&self.packets())?;
        std::fs::write(path, bytes)
            .with_context(|| format!("writing capture {}", path.display()))?;
        Ok(())
    }

    /// A replayer over the packets captured so far.
    pub fn replayer(&self) -> Replayer {
        Replayer::new(self.packets())
    }
}

/// A deterministic packet source, used to drive a stack with a captured link.
#[derive(Debug, Clone)]
pub struct Replayer {
    packets: Vec<RecordedPacket>,
    next: usize,
}

impl Replayer {
    pub fn new(packets: Vec<RecordedPacket>) -> Self {
        Self { packets, next: 0 }
    }

    pub fn load_json(path: &std::path::Path) -> Result<Self> {
        let bytes = std::fs::read(path)
            .with_context(|| format!("reading capture {}", path.display()))?;
        let packets: Vec<RecordedPacket> = serde_json::from_slice(&bytes)
            .with_context(|| format!("parsing capture {}", path.display()))?;
        Ok(Self::new(packets))
    }

    pub fn remaining(&self) -> usize {
        self.packets.len().saturating_sub(self.next)
    }

    pub fn is_done(&self) -> bool {
        self.next >= self.packets.len()
    }

    /// Every inbound packet whose timestamp is at or before `now_ms`.
    pub fn due(&mut self, now_ms: i64) -> Vec<&[u8]> {
        let mut out = Vec::new();
        while self.next < self.packets.len() {
            let packet = &self.packets[self.next];
            if packet.timestamp_ms > now_ms {
                break;
            }
            self.next += 1;
            if packet.direction == Direction::Inbound {
                out.push(packet.data.as_slice());
            }
        }
        out
    }

    /// Feed every packet into a queue, respecting relative timing from
    /// `start_ms` by returning the elapsed schedule. The caller drives the
    /// clock; nothing here sleeps.
    pub fn push_due(&mut self, queue: &crate::vnet::device::PacketQueue, now_ms: i64) -> usize {
        let due = self.due(now_ms);
        let count = due.len();
        for packet in due {
            queue.push(packet.to_vec());
        }
        count
    }
}

/// `.pcap` encoding and decoding.
pub struct PcapFile;

/// `LINKTYPE_RAW` — packets begin with an IPv4/IPv6 header.
pub const PCAP_LINKTYPE_RAW: u32 = 101;
const PCAP_MAGIC: u32 = 0xa1b2_c3d4;
const PCAP_GLOBAL_HEADER_LEN: usize = 24;
const PCAP_RECORD_HEADER_LEN: usize = 16;

impl PcapFile {
    /// Encode a list of packets as a little-endian `.pcap` file.
    pub fn encode(packets: &[RecordedPacket]) -> Vec<u8> {
        let mut out = Vec::with_capacity(PCAP_GLOBAL_HEADER_LEN + packets.len() * 64);
        out.extend_from_slice(&PCAP_MAGIC.to_le_bytes());
        out.extend_from_slice(&2u16.to_le_bytes()); // major
        out.extend_from_slice(&4u16.to_le_bytes()); // minor
        out.extend_from_slice(&0i32.to_le_bytes()); // thiszone
        out.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
        out.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
        out.extend_from_slice(&PCAP_LINKTYPE_RAW.to_le_bytes());
        for packet in packets {
            let secs = packet.timestamp_ms.div_euclid(1000) as u32;
            let micros = (packet.timestamp_ms.rem_euclid(1000) * 1000) as u32;
            out.extend_from_slice(&secs.to_le_bytes());
            out.extend_from_slice(&micros.to_le_bytes());
            out.extend_from_slice(&(packet.data.len() as u32).to_le_bytes());
            out.extend_from_slice(&(packet.data.len() as u32).to_le_bytes());
            out.extend_from_slice(&packet.data);
        }
        out
    }

    /// Decode a `.pcap` produced by [`PcapFile::encode`]. Every packet is
    /// reported as [`Direction::Inbound`], because pcap has no direction
    /// field; use the JSON capture to preserve direction.
    pub fn decode(bytes: &[u8]) -> Result<Vec<RecordedPacket>> {
        if bytes.len() < PCAP_GLOBAL_HEADER_LEN {
            bail!("pcap is shorter than the global header");
        }
        let magic = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        if magic != PCAP_MAGIC {
            bail!("pcap magic {magic:#010x} is not {PCAP_MAGIC:#010x}");
        }
        let network = u32::from_le_bytes(bytes[20..24].try_into().unwrap());
        if network != PCAP_LINKTYPE_RAW {
            bail!("pcap link type {network} is not raw IP ({PCAP_LINKTYPE_RAW})");
        }
        let mut packets = Vec::new();
        let mut offset = PCAP_GLOBAL_HEADER_LEN;
        while offset + PCAP_RECORD_HEADER_LEN <= bytes.len() {
            let secs = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
            let micros = u32::from_le_bytes(bytes[offset + 4..offset + 8].try_into().unwrap());
            let incl = u32::from_le_bytes(bytes[offset + 8..offset + 12].try_into().unwrap()) as usize;
            let orig = u32::from_le_bytes(bytes[offset + 12..offset + 16].try_into().unwrap()) as usize;
            offset += PCAP_RECORD_HEADER_LEN;
            if offset + incl > bytes.len() {
                bail!("pcap record at {offset} is truncated: {incl} bytes claimed");
            }
            if incl != orig {
                bail!("pcap record at {offset} is truncated in the capture: {incl} of {orig}");
            }
            let timestamp_ms = secs as i64 * 1000 + (micros / 1000) as i64;
            packets.push(RecordedPacket::new(
                timestamp_ms,
                Direction::Inbound,
                bytes[offset..offset + incl].to_vec(),
            ));
            offset += incl;
        }
        if offset != bytes.len() {
            bail!("pcap has {} trailing bytes", bytes.len() - offset);
        }
        Ok(packets)
    }

    pub fn write(path: &std::path::Path, packets: &[RecordedPacket]) -> Result<()> {
        std::fs::write(path, Self::encode(packets))
            .with_context(|| format!("writing pcap {}", path.display()))?;
        Ok(())
    }

    pub fn read(path: &std::path::Path) -> Result<Vec<RecordedPacket>> {
        let bytes = std::fs::read(path)
            .with_context(|| format!("reading pcap {}", path.display()))?;
        Self::decode(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pcap_round_trips() {
        let packets = vec![
            RecordedPacket::new(0, Direction::Outbound, vec![0x45, 0, 0, 20]),
            RecordedPacket::new(1500, Direction::Inbound, vec![0x60, 0, 0, 40, 1]),
            RecordedPacket::new(65_432, Direction::Outbound, vec![0xff]),
        ];
        let bytes = PcapFile::encode(&packets);
        let decoded = PcapFile::decode(&bytes).unwrap();
        assert_eq!(decoded.len(), 3);
        assert_eq!(decoded[1].timestamp_ms, 1500);
        assert_eq!(decoded[1].data, vec![0x60, 0, 0, 40, 1]);
        assert_eq!(decoded[2].timestamp_ms, 65_432);
        // Direction is not preserved by pcap.
        assert_eq!(decoded[0].direction, Direction::Inbound);
    }

    #[test]
    fn pcap_rejects_bad_input() {
        assert!(PcapFile::decode(b"short").is_err());
        let mut bad = PcapFile::encode(&[]);
        bad[0] = 0;
        assert!(PcapFile::decode(&bad).is_err());
        let mut truncated = PcapFile::encode(&[RecordedPacket::new(0, Direction::Inbound, vec![1, 2, 3])]);
        truncated.truncate(truncated.len() - 1);
        assert!(PcapFile::decode(&truncated).is_err());
    }

    #[test]
    fn recorder_counts_and_limits() {
        let recorder = Recorder::with_limit(2);
        recorder.record(Direction::Inbound, b"a");
        recorder.record(Direction::Outbound, b"b");
        recorder.record(Direction::Inbound, b"c");
        assert_eq!(recorder.len(), 2);
        let packets = recorder.packets();
        assert_eq!(packets[0].data, b"b");
        assert_eq!(packets[1].data, b"c");
    }

    #[test]
    fn replayer_respects_due_times() {
        let packets = vec![
            RecordedPacket::new(1, Direction::Inbound, b"one".to_vec()),
            RecordedPacket::new(5, Direction::Outbound, b"skip".to_vec()),
            RecordedPacket::new(9, Direction::Inbound, b"two".to_vec()),
        ];
        let mut replayer = Replayer::new(packets);
        assert!(replayer.due(0).is_empty());
        let due = replayer.due(5);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0], b"one");
        let due = replayer.due(100);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0], b"two");
        assert!(replayer.is_done());
    }

    #[test]
    fn recorder_json_round_trips() {
        let recorder = Recorder::new();
        recorder.record(Direction::Outbound, b"x");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cap.json");
        recorder.save_json(&path).unwrap();
        let replayer = Replayer::load_json(&path).unwrap();
        assert_eq!(replayer.remaining(), 1);
    }
}
