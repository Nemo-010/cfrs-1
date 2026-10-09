//! Link devices for the userspace stack.
//!
//! The stack's link layer is an in-process packet queue pair: packets the
//! stack transmits land in an outbound queue, and packets read from the
//! outside world are pushed into an inbound queue. A pump (the reactor, or a
//! tunnel task) moves bytes between those queues and the real link, whatever
//! it is — a unix socket, a QUIC stream, or a `cfrs` WebSocket forward.
//!
//! Keeping the smoltcp `Device` purely in-process means it never has to be
//! generic over an async transport, and the same device serves loopback (the
//! transmit queue feeds the receive queue), a tunnel, a packet capture and a
//! fault injector.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;

/// Counters shared by every clone of a link.
#[derive(Debug, Default)]
pub struct DeviceStats {
    pub rx_packets: AtomicU64,
    pub tx_packets: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub rx_dropped: AtomicU64,
    pub tx_dropped: AtomicU64,
}

/// An immutable snapshot of [`DeviceStats`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DeviceStatsSnapshot {
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_dropped: u64,
    pub tx_dropped: u64,
}

impl DeviceStats {
    pub fn snapshot(&self) -> DeviceStatsSnapshot {
        DeviceStatsSnapshot {
            rx_packets: self.rx_packets.load(Ordering::Relaxed),
            tx_packets: self.tx_packets.load(Ordering::Relaxed),
            rx_bytes: self.rx_bytes.load(Ordering::Relaxed),
            tx_bytes: self.tx_bytes.load(Ordering::Relaxed),
            rx_dropped: self.rx_dropped.load(Ordering::Relaxed),
            tx_dropped: self.tx_dropped.load(Ordering::Relaxed),
        }
    }
}

struct QueueInner {
    packets: VecDeque<Vec<u8>>,
    waker: Option<Waker>,
    capacity: usize,
    dropped: u64,
}

/// A bounded packet queue with a waker, shared between the device and its
/// pump.
#[derive(Clone)]
pub struct PacketQueue {
    inner: Arc<Mutex<QueueInner>>,
}

impl std::fmt::Debug for PacketQueue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let inner = self.inner.lock().unwrap();
        f.debug_struct("PacketQueue")
            .field("len", &inner.packets.len())
            .field("capacity", &inner.capacity)
            .field("dropped", &inner.dropped)
            .finish()
    }
}

impl PacketQueue {
    /// `capacity` packets may sit in the queue; further pushes are dropped and
    /// counted, which is the right behaviour for a link that can outrun the
    /// stack (dropping makes TCP retransmit rather than growing without bound).
    pub fn bounded(capacity: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(QueueInner {
                packets: VecDeque::new(),
                waker: None,
                capacity: capacity.max(1),
                dropped: 0,
            })),
        }
    }

    pub fn unbounded() -> Self {
        Self::bounded(usize::MAX)
    }

    /// Push a packet, waking a reader. Returns false when the packet was
    /// dropped because the queue was full.
    pub fn push(&self, packet: Vec<u8>) -> bool {
        let waker = {
            let mut inner = self.inner.lock().unwrap();
            if inner.packets.len() >= inner.capacity {
                inner.dropped += 1;
                return false;
            }
            inner.packets.push_back(packet);
            inner.waker.take()
        };
        // Wake outside the lock: a waker must never re-enter `push`/`pop` and
        // deadlock on the mutex it was called under.
        if let Some(waker) = waker {
            waker.wake();
        }
        true
    }

    pub fn pop(&self) -> Option<Vec<u8>> {
        self.inner.lock().unwrap().packets.pop_front()
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().packets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn dropped(&self) -> u64 {
        self.inner.lock().unwrap().dropped
    }

    pub fn clear(&self) {
        self.inner.lock().unwrap().packets.clear();
    }

    /// Register `waker`; a later push wakes it. A packet already queued wakes
    /// it immediately.
    pub fn poll_recv(&self, cx: &mut Context<'_>) -> Poll<Vec<u8>> {
        let mut inner = self.inner.lock().unwrap();
        if let Some(packet) = inner.packets.pop_front() {
            return Poll::Ready(packet);
        }
        inner.waker = Some(cx.waker().clone());
        Poll::Pending
    }

    /// Await the next packet.
    pub async fn recv(&self) -> Vec<u8> {
        std::future::poll_fn(|cx| self.poll_recv(cx)).await
    }

    /// Wait until the queue is non-empty, without consuming a packet.
    pub fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<()> {
        let mut inner = self.inner.lock().unwrap();
        if !inner.packets.is_empty() {
            return Poll::Ready(());
        }
        inner.waker = Some(cx.waker().clone());
        Poll::Pending
    }

    /// Await until a packet is available (it stays queued for the device).
    pub async fn wait(&self) {
        std::future::poll_fn(|cx| self.poll_ready(cx)).await
    }

    /// Await a packet, or `None` if `should_stop` becomes true first. Used to
    /// keep a pump responsive to shutdown.
    pub async fn recv_or<F: Fn() -> bool>(&self, should_stop: F) -> Option<Vec<u8>> {
        std::future::poll_fn(|cx| {
            if should_stop() {
                return Poll::Ready(None);
            }
            match self.poll_recv(cx) {
                Poll::Ready(packet) => Poll::Ready(Some(packet)),
                Poll::Pending => Poll::Pending,
            }
        })
        .await
    }
}

/// The stack's link device: an inbound queue, an outbound queue, and optional
/// loopback.
pub struct LinkDevice {
    rx: PacketQueue,
    tx: PacketQueue,
    stats: Arc<DeviceStats>,
    mtu: usize,
    medium: Medium,
    loopback: bool,
}

/// Alias kept for the protocol documentation's name.
pub type TunnelDevice = LinkDevice;

impl std::fmt::Debug for LinkDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinkDevice")
            .field("rx", &self.rx)
            .field("tx", &self.tx)
            .field("mtu", &self.mtu)
            .field("loopback", &self.loopback)
            .finish()
    }
}

impl LinkDevice {
    /// A device whose transmit path feeds its own receive path, for a stack
    /// that only talks to itself (the §9.1 proof, deterministic tests, a
    /// process-level loopback network).
    pub fn loopback(mtu: usize) -> Self {
        Self::new(mtu, true)
    }

    /// A device bridged to an external link by a pump.
    pub fn tunnel(mtu: usize) -> Self {
        Self::new(mtu, false)
    }

    fn new(mtu: usize, loopback: bool) -> Self {
        Self {
            rx: PacketQueue::unbounded(),
            tx: PacketQueue::unbounded(),
            stats: Arc::new(DeviceStats::default()),
            mtu: mtu.max(1280),
            medium: Medium::Ip,
            loopback,
        }
    }

    pub fn inbound(&self) -> PacketQueue {
        self.rx.clone()
    }

    pub fn outbound(&self) -> PacketQueue {
        self.tx.clone()
    }

    pub fn stats(&self) -> Arc<DeviceStats> {
        self.stats.clone()
    }

    pub fn mtu(&self) -> usize {
        self.mtu
    }

    pub fn is_loopback(&self) -> bool {
        self.loopback
    }
}

impl Device for LinkDevice {
    type RxToken<'a> = LinkRx;
    type TxToken<'a> = LinkTx;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.rx.pop()?;
        self.stats.rx_packets.fetch_add(1, Ordering::Relaxed);
        self.stats
            .rx_bytes
            .fetch_add(packet.len() as u64, Ordering::Relaxed);
        Some((LinkRx { packet }, self.tx_token()))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(self.tx_token())
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = self.medium;
        capabilities.max_transmission_unit = self.mtu;
        capabilities.max_burst_size = Some(1);
        capabilities
    }
}

impl LinkDevice {
    fn tx_token(&mut self) -> LinkTx {
        LinkTx {
            tx: self.tx.clone(),
            rx: self.loopback.then(|| self.rx.clone()),
            stats: self.stats.clone(),
        }
    }
}

/// Receive token: a packet popped from the inbound queue.
pub struct LinkRx {
    packet: Vec<u8>,
}

impl RxToken for LinkRx {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(&mut self.packet)
    }
}

/// Transmit token: writes the frame into the outbound queue (or, in loopback
/// mode, straight back into the inbound queue).
pub struct LinkTx {
    tx: PacketQueue,
    rx: Option<PacketQueue>,
    stats: Arc<DeviceStats>,
}

impl TxToken for LinkTx {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
        self.stats.tx_packets.fetch_add(1, Ordering::Relaxed);
        self.stats
            .tx_bytes
            .fetch_add(buffer.len() as u64, Ordering::Relaxed);
        match &self.rx {
            Some(rx) => {
                if !rx.push(buffer) {
                    self.stats.rx_dropped.fetch_add(1, Ordering::Relaxed);
                }
            }
            None => {
                if !self.tx.push(buffer) {
                    self.stats.tx_dropped.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        result
    }
}

/// A device wrapper that records every packet in both directions.
///
/// It is deliberately a plain wrapper rather than something that reaches into
/// the queue, so it composes with the tunnel device and with the loopback
/// device.
pub struct RecordingDevice<D: Device> {
    inner: D,
    recorder: crate::vnet::record::Recorder,
}

impl<D: Device> RecordingDevice<D> {
    pub fn new(inner: D, recorder: crate::vnet::record::Recorder) -> Self {
        Self { inner, recorder }
    }

    pub fn into_inner(self) -> D {
        self.inner
    }

    pub fn recorder(&self) -> &crate::vnet::record::Recorder {
        &self.recorder
    }
}

impl<D: Device> Device for RecordingDevice<D> {
    type RxToken<'a> = RecordRx<'a, D::RxToken<'a>> where Self: 'a;
    type TxToken<'a> = RecordTx<'a, D::TxToken<'a>> where Self: 'a;

    fn receive(&mut self, timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let (rx, tx) = self.inner.receive(timestamp)?;
        Some((
            RecordRx { inner: rx, recorder: &self.recorder },
            RecordTx { inner: tx, recorder: &self.recorder },
        ))
    }

    fn transmit(&mut self, timestamp: Instant) -> Option<Self::TxToken<'_>> {
        let tx = self.inner.transmit(timestamp)?;
        Some(RecordTx { inner: tx, recorder: &self.recorder })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        self.inner.capabilities()
    }
}

pub struct RecordRx<'a, R> {
    inner: R,
    recorder: &'a crate::vnet::record::Recorder,
}

impl<R: RxToken> RxToken for RecordRx<'_, R> {
    fn consume<Ret, F>(self, f: F) -> Ret
    where
        F: FnOnce(&mut [u8]) -> Ret,
    {
        let recorder = self.recorder;
        self.inner.consume(|buffer| {
            recorder.record(crate::vnet::record::Direction::Inbound, buffer);
            f(buffer)
        })
    }
}

pub struct RecordTx<'a, T> {
    inner: T,
    recorder: &'a crate::vnet::record::Recorder,
}

impl<T: TxToken> TxToken for RecordTx<'_, T> {
    fn consume<Ret, F>(self, len: usize, f: F) -> Ret
    where
        F: FnOnce(&mut [u8]) -> Ret,
    {
        let recorder = self.recorder;
        self.inner.consume(len, |buffer| {
            let result = f(buffer);
            recorder.record(crate::vnet::record::Direction::Outbound, buffer);
            result
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_device_feeds_itself() {
        let mut device = LinkDevice::loopback(1500);
        assert_eq!(device.capabilities().max_transmission_unit, 1500);
        assert_eq!(device.capabilities().medium, Medium::Ip);
        // Transmit one frame; it must come back on receive.
        let token = device.transmit(Instant::ZERO).unwrap();
        token.consume(4, |buf| buf.copy_from_slice(b"ping"));
        let (rx, _tx) = device.receive(Instant::ZERO).expect("loopback frame");
        let mut seen = Vec::new();
        rx.consume(|buf| seen.extend_from_slice(buf));
        assert_eq!(seen, b"ping");
        let stats = device.stats().snapshot();
        assert_eq!(stats.rx_packets, 1);
        assert_eq!(stats.tx_packets, 1);
        assert_eq!(stats.rx_bytes, 4);
        assert_eq!(stats.tx_bytes, 4);
    }

    #[test]
    fn tunnel_device_queues_outbound() {
        let mut device = LinkDevice::tunnel(1280);
        let outbound = device.outbound();
        let token = device.transmit(Instant::ZERO).unwrap();
        token.consume(3, |buf| buf.copy_from_slice(b"tx!"));
        assert_eq!(outbound.pop().unwrap(), b"tx!");
        assert!(device.receive(Instant::ZERO).is_none());
    }

    #[test]
    fn inbound_frames_arrive() {
        let mut device = LinkDevice::tunnel(1280);
        let inbound = device.inbound();
        assert!(inbound.push(b"hello".to_vec()));
        let (rx, _) = device.receive(Instant::ZERO).unwrap();
        let mut seen = Vec::new();
        rx.consume(|buf| seen.extend_from_slice(buf));
        assert_eq!(seen, b"hello");
    }

    #[test]
    fn bounded_queue_drops_and_counts() {
        let queue = PacketQueue::bounded(2);
        assert!(queue.push(b"1".to_vec()));
        assert!(queue.push(b"2".to_vec()));
        assert!(!queue.push(b"3".to_vec()));
        assert_eq!(queue.dropped(), 1);
        assert_eq!(queue.len(), 2);
    }

    #[tokio::test]
    async fn queue_wakes_a_waiter() {
        let queue = PacketQueue::unbounded();
        let waiter = {
            let queue = queue.clone();
            tokio::spawn(async move { queue.recv().await })
        };
        // Give the waiter a chance to park.
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        queue.push(b"wake".to_vec());
        let packet = tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
            .await
            .expect("waiter timed out")
            .unwrap();
        assert_eq!(packet, b"wake");
    }
}
