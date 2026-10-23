//! The per-connection outbound queue of the connection-oriented transports
//! (TCP, TLS, WS/WSS and SCTP), bounded by bytes rather than by messages.
//!
//! Every connection has one writer task, fed by one [`SendQueue`]. The outbound
//! distributor enqueues with [`SendQueue::try_send`], which never awaits: it
//! runs while holding a `connection_map` shard guard, and parking there would
//! stall every other connection and the accept loop's insert on that shard.
//!
//! The bound used to be 64 messages. A burst bigger than that is ordinary on a
//! connection that carries a whole registration load between two proxies, and
//! the distributor fills a queue far faster than the writer task is scheduled to
//! drain it, so a peer that was reading normally lost the overflow. Bounding by
//! bytes ([`DEFAULT_SEND_QUEUE_BYTES`], `listen.stream_send_queue_bytes`) keeps
//! the memory one connection can hold in check without that cliff, and ordering
//! is preserved because a frame either joins the one FIFO or is refused.
//!
//! What decides a peer is stuck is the writer, not the queue: a write that
//! makes no progress for the write timeout (`listen.stream_write_timeout_ms`)
//! closes the connection, logged with what was still queued and counted in
//! `siphon_stream_stalled_closes_total`. Until then a frame that would take the
//! queue past its bound is refused, loudly: the caller gets the frame back, a
//! pool send turns that into an immediate error (RFC 3261 §8.1.3.1 — a
//! transport error, not a Timer B/F expiry), and the distributor logs it and
//! counts it in `siphon_stream_send_queue_refused_total`.
//!
//! One connection per peer is kept (RFC 5923 connection reuse); opening more
//! connections to spread a burst is not something this queue does.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::sync::mpsc;
use tracing::{error, warn};

pub use tokio::sync::mpsc::error::TrySendError;

use crate::config::ListenConfig;
use crate::metrics::send_queue as metrics;
use crate::transport::{ConnectionId, Transport, WRITE_TIMEOUT};

/// Default bound on what one connection may have queued for its writer.
///
/// A REGISTER or its 200 OK through an IMS core runs to one or two kilobytes,
/// so this is a burst of a few thousand messages: far past anything a peer that
/// is reading produces, and small enough that a thousand connections to peers
/// that stopped reading still cannot exhaust a node.
pub const DEFAULT_SEND_QUEUE_BYTES: usize = 4 * 1024 * 1024;

static SEND_QUEUE_BYTES: OnceLock<usize> = OnceLock::new();
static STREAM_WRITE_TIMEOUT: OnceLock<Duration> = OnceLock::new();

/// Install `listen.stream_send_queue_bytes` and `listen.stream_write_timeout_ms`
/// process-wide. Called once at startup, before any connection exists; a second
/// call is a no-op.
pub fn install(listen: &ListenConfig) {
    let _ = SEND_QUEUE_BYTES.set(listen.stream_send_queue_bytes);
    let _ = STREAM_WRITE_TIMEOUT.set(Duration::from_millis(listen.stream_write_timeout_ms));
}

/// The configured per-connection byte bound.
pub fn send_queue_bytes() -> usize {
    SEND_QUEUE_BYTES
        .get()
        .copied()
        .unwrap_or(DEFAULT_SEND_QUEUE_BYTES)
}

/// How long one write may make no progress before the connection is closed as
/// stuck ([`WRITE_TIMEOUT`] unless configured).
pub fn write_timeout() -> Duration {
    STREAM_WRITE_TIMEOUT.get().copied().unwrap_or(WRITE_TIMEOUT)
}

/// A send queue and its receiving half, bounded by [`send_queue_bytes`].
pub fn channel(
    transport: Transport,
    connection_id: ConnectionId,
) -> (SendQueue, SendQueueReceiver) {
    channel_with_limit(transport, connection_id, send_queue_bytes())
}

/// A send queue and its receiving half, bounded by `limit` bytes.
pub fn channel_with_limit(
    transport: Transport,
    connection_id: ConnectionId,
    limit: usize,
) -> (SendQueue, SendQueueReceiver) {
    let (sender, receiver) = mpsc::unbounded_channel();
    let shared = Arc::new(Shared {
        queued: AtomicUsize::new(0),
        limit,
        transport,
        connection_id,
        last_progress: AtomicU64::new(now_nanos()),
    });
    (
        SendQueue {
            sender,
            shared: Arc::clone(&shared),
        },
        SendQueueReceiver {
            receiver,
            shared,
            stall_reported: false,
        },
    )
}

struct Shared {
    /// Bytes enqueued and not yet taken by the writer.
    queued: AtomicUsize,
    limit: usize,
    transport: Transport,
    connection_id: ConnectionId,
    /// When the writer last took a frame, which it only does once the previous
    /// write has completed: nanoseconds since [`epoch`].
    last_progress: AtomicU64,
}

impl Shared {
    fn release(&self, bytes: usize) {
        self.queued.fetch_sub(bytes, Ordering::AcqRel);
        metrics::add_queued_bytes(self.transport, -(bytes as i64));
    }

    fn since_progress(&self) -> Duration {
        Duration::from_nanos(now_nanos().saturating_sub(self.last_progress.load(Ordering::Acquire)))
    }
}

fn epoch() -> Instant {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    *EPOCH.get_or_init(Instant::now)
}

fn now_nanos() -> u64 {
    u64::try_from(epoch().elapsed().as_nanos()).unwrap_or(u64::MAX)
}

/// The sending half of one connection's queue. Cheap to clone.
#[derive(Clone)]
pub struct SendQueue {
    sender: mpsc::UnboundedSender<Bytes>,
    shared: Arc<Shared>,
}

impl SendQueue {
    /// Queue `frame` for the writer without waiting.
    ///
    /// `Full` hands the frame back when it would take the queue past its byte
    /// bound; an empty queue takes any one frame, so a message larger than the
    /// bound is never refused outright. `Closed` hands it back once the writer
    /// has gone.
    pub fn try_send(&self, frame: Bytes) -> Result<(), TrySendError<Bytes>> {
        if self.sender.is_closed() {
            return Err(TrySendError::Closed(frame));
        }
        let length = frame.len();
        let limit = self.shared.limit;
        let reserved =
            self.shared
                .queued
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |queued| {
                    (queued == 0 || queued.saturating_add(length) <= limit).then(|| queued + length)
                });
        if reserved.is_err() {
            metrics::record_refused(self.shared.transport);
            return Err(TrySendError::Full(frame));
        }
        metrics::add_queued_bytes(self.shared.transport, length as i64);
        match self.sender.send(frame) {
            Ok(()) => Ok(()),
            Err(mpsc::error::SendError(frame)) => {
                self.shared.release(length);
                Err(TrySendError::Closed(frame))
            }
        }
    }

    /// Whether the writer has gone, so nothing sent here can leave.
    pub fn is_closed(&self) -> bool {
        self.sender.is_closed()
    }

    /// Resolves once the writer has gone.
    pub async fn closed(&self) {
        self.sender.closed().await
    }

    /// Bytes queued and not yet taken by the writer.
    pub fn queued_bytes(&self) -> usize {
        self.shared.queued.load(Ordering::Acquire)
    }

    /// The byte bound of this queue.
    pub fn limit(&self) -> usize {
        self.shared.limit
    }

    /// How long since the writer last finished a write and took the next frame.
    /// Only meaningful while something is queued.
    pub fn since_progress(&self) -> Duration {
        self.shared.since_progress()
    }

    /// Log a frame this queue refused as over its bound. One place, so every
    /// refusal reads the same and carries the numbers an operator needs.
    pub fn log_refused(&self, what: &str) {
        warn!(
            transport = %self.shared.transport,
            connection_id = ?self.shared.connection_id,
            queued_bytes = self.queued_bytes(),
            limit = self.shared.limit,
            since_progress = ?self.since_progress(),
            "{what} refused: the connection's send queue is at its byte bound \
             (listen.stream_send_queue_bytes); the peer is draining slower than \
             it is being sent to, and is closed as stuck if a write makes no \
             progress for {:?}",
            write_timeout()
        );
    }
}

/// The receiving half, owned by the connection's writer task.
pub struct SendQueueReceiver {
    receiver: mpsc::UnboundedReceiver<Bytes>,
    shared: Arc<Shared>,
    stall_reported: bool,
}

impl SendQueueReceiver {
    /// The next frame to write, once the previous one is on its way.
    pub async fn recv(&mut self) -> Option<Bytes> {
        let frame = self.receiver.recv().await?;
        self.shared.release(frame.len());
        self.shared
            .last_progress
            .store(now_nanos(), Ordering::Release);
        Some(frame)
    }

    /// The next frame if one is queued, without waiting.
    pub fn try_recv(&mut self) -> Result<Bytes, mpsc::error::TryRecvError> {
        let frame = self.receiver.try_recv()?;
        self.shared.release(frame.len());
        Ok(frame)
    }

    /// Frames still queued.
    pub fn len(&self) -> usize {
        self.receiver.len()
    }

    /// Whether nothing is queued.
    pub fn is_empty(&self) -> bool {
        self.receiver.is_empty()
    }

    /// The writer is giving up on a peer whose write made no progress for the
    /// write timeout: say so, with what is still queued, and count it. The
    /// connection closes when this receiver is dropped.
    pub fn stalled(&mut self, destination: std::net::SocketAddr) {
        self.stall_reported = true;
        metrics::record_stalled(self.shared.transport);
        error!(
            transport = %self.shared.transport,
            connection_id = ?self.shared.connection_id,
            destination = %destination,
            queued_bytes = self.shared.queued.load(Ordering::Acquire),
            queued_frames = self.receiver.len(),
            without_progress = ?self.shared.since_progress(),
            "closing a stuck connection: a write made no progress for the write \
             timeout (listen.stream_write_timeout_ms); the queued frames are \
             discarded and sends on it now fail"
        );
    }
}

impl Drop for SendQueueReceiver {
    fn drop(&mut self) {
        self.receiver.close();
        let mut frames = 0u64;
        let mut bytes = 0usize;
        while let Ok(frame) = self.receiver.try_recv() {
            frames += 1;
            bytes += frame.len();
            self.shared.release(frame.len());
        }
        if frames == 0 {
            return;
        }
        metrics::record_discarded(self.shared.transport, frames);
        if !self.stall_reported {
            warn!(
                transport = %self.shared.transport,
                connection_id = ?self.shared.connection_id,
                frames,
                bytes,
                "connection closed with frames still queued for it; they are discarded"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn queue(limit: usize) -> (SendQueue, SendQueueReceiver) {
        channel_with_limit(Transport::Tcp, ConnectionId(7), limit)
    }

    #[tokio::test]
    async fn the_bound_is_bytes_not_messages() {
        let (sender, mut receiver) = queue(1000);
        for _ in 0..100 {
            sender.try_send(Bytes::from_static(b"0123456789")).unwrap();
        }
        assert_eq!(sender.queued_bytes(), 1000);
        assert!(matches!(
            sender.try_send(Bytes::from_static(b"x")),
            Err(TrySendError::Full(_))
        ));
        receiver.recv().await.unwrap();
        assert_eq!(sender.queued_bytes(), 990);
        sender.try_send(Bytes::from_static(b"0123456789")).unwrap();
    }

    #[tokio::test]
    async fn an_empty_queue_takes_a_frame_larger_than_its_bound() {
        let (sender, mut receiver) = queue(4);
        sender
            .try_send(Bytes::from_static(b"far too long"))
            .unwrap();
        assert!(matches!(
            sender.try_send(Bytes::from_static(b"a")),
            Err(TrySendError::Full(_))
        ));
        assert_eq!(
            receiver.recv().await.unwrap(),
            Bytes::from_static(b"far too long")
        );
        sender.try_send(Bytes::from_static(b"a")).unwrap();
    }

    #[tokio::test]
    async fn frames_leave_in_the_order_they_were_queued() {
        let (sender, mut receiver) = queue(DEFAULT_SEND_QUEUE_BYTES);
        for n in 0..1000u32 {
            sender
                .try_send(Bytes::from(n.to_be_bytes().to_vec()))
                .unwrap();
        }
        for n in 0..1000u32 {
            assert_eq!(
                receiver.recv().await.unwrap(),
                Bytes::from(n.to_be_bytes().to_vec())
            );
        }
        assert_eq!(sender.queued_bytes(), 0);
    }

    #[tokio::test]
    async fn a_dropped_writer_fails_sends_at_once_and_releases_what_was_queued() {
        let (sender, receiver) = queue(1000);
        sender.try_send(Bytes::from_static(b"queued")).unwrap();
        drop(receiver);
        assert!(sender.is_closed());
        assert_eq!(
            sender.queued_bytes(),
            0,
            "the discarded frames are released"
        );
        assert!(matches!(
            sender.try_send(Bytes::from_static(b"late")),
            Err(TrySendError::Closed(_))
        ));
        tokio::time::timeout(Duration::from_secs(1), sender.closed())
            .await
            .expect("closed() resolves once the writer is gone");
    }

    #[tokio::test]
    async fn a_refusal_hands_the_frame_back() {
        let (sender, _receiver) = queue(2);
        sender.try_send(Bytes::from_static(b"ab")).unwrap();
        match sender.try_send(Bytes::from_static(b"cd")) {
            Err(TrySendError::Full(frame)) => assert_eq!(frame, Bytes::from_static(b"cd")),
            other => panic!("expected Full, got {other:?}"),
        }
    }
}
