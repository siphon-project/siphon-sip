//! The bounded, non-blocking per-connection outbound queue and its overflow
//! policy — the mechanism behind the isolation invariant described on the
//! parent module.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;

use tokio::sync::Notify;

use crate::control::protocol::{EventFrame, ReplyFrame};

/// Overflow policy for a per-connection outbound queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SlowConsumerPolicy {
    /// Drop the oldest queued *event* to make room (default). Replies are never
    /// dropped.
    #[default]
    DropOldest,
    /// Mark the connection for disconnect (the writer task closes it).
    Disconnect,
}

impl SlowConsumerPolicy {
    /// Parse the config string (`"drop_oldest"` / `"disconnect"`), defaulting to
    /// `DropOldest` for anything else.
    pub fn from_config(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "disconnect" => SlowConsumerPolicy::Disconnect,
            _ => SlowConsumerPolicy::DropOldest,
        }
    }
}

/// A frame queued for a connection's single write task: either a correlated
/// reply or a pushed event. Both travel through the one queue so replies and
/// events for any given call are totally ordered on the owner socket.
#[derive(Debug, Clone)]
pub enum OutboundFrame {
    /// A correlated reply (never dropped by backpressure).
    Reply(ReplyFrame),
    /// A pushed event (subject to drop-oldest under backpressure).
    Event(EventFrame),
}

impl OutboundFrame {
    fn is_event(&self) -> bool {
        matches!(self, OutboundFrame::Event(_))
    }

    /// Serialize to a JSON text frame.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        match self {
            OutboundFrame::Reply(reply) => serde_json::to_string(reply),
            OutboundFrame::Event(event) => serde_json::to_string(event),
        }
    }
}

/// Result of a single [`OutboundQueue::try_push_event`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushOutcome {
    /// The frame was queued.
    Delivered,
    /// The queue was full; the oldest event was dropped to make room.
    DroppedOldest,
    /// The queue was full and the policy is `Disconnect`; the event was dropped
    /// and the connection is now flagged for disconnect.
    OverflowDisconnect,
}

/// Count a dropped control event against `siphon_control_events_dropped_total{app}`.
///
/// The queue already tracks its own drop count, but that is per-connection and
/// dies with the connection, so a slow consumer that lost events left nothing
/// behind once it reconnected. Both overflow outcomes lose an event: under
/// `DropOldest` the oldest queued event is discarded, and under `Disconnect` the
/// incoming one is.
pub(super) fn record_push_outcome(app: &str, outcome: PushOutcome) {
    if matches!(
        outcome,
        PushOutcome::DroppedOldest | PushOutcome::OverflowDisconnect
    ) {
        if let Some(metrics) = crate::metrics::try_metrics() {
            metrics
                .control_events_dropped_total
                .with_label_values(&[app])
                .inc();
        }
    }
}

/// A bounded, non-blocking outbound queue for one connection.
///
/// Producers (dispatcher / leg actor for events; the read task for replies)
/// call [`try_push_event`](Self::try_push_event) / [`push_reply`](Self::push_reply)
/// — a brief lock, never held across an `.await`. The connection's async writer
/// task calls [`recv_many`](Self::recv_many), parking on a `Notify` until frames
/// are available, then draining them under one lock.
#[derive(Debug)]
pub struct OutboundQueue {
    inner: Mutex<std::collections::VecDeque<OutboundFrame>>,
    notify: Notify,
    capacity: usize,
    policy: SlowConsumerPolicy,
    dropped: AtomicU64,
    disconnect: AtomicBool,
    closed: AtomicBool,
}

impl OutboundQueue {
    /// Create a queue with the given event capacity and overflow policy.
    pub fn new(capacity: usize, policy: SlowConsumerPolicy) -> Self {
        Self {
            inner: Mutex::new(std::collections::VecDeque::with_capacity(capacity.min(64))),
            notify: Notify::new(),
            capacity: capacity.max(1),
            policy,
            dropped: AtomicU64::new(0),
            disconnect: AtomicBool::new(false),
            closed: AtomicBool::new(false),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, std::collections::VecDeque<OutboundFrame>> {
        match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Push one event without ever blocking or awaiting. Under overflow the
    /// oldest *event* is dropped (never a reply).
    pub fn try_push_event(&self, event: EventFrame) -> PushOutcome {
        let outcome = {
            let mut queue = self.lock();
            let event_count = queue.iter().filter(|frame| frame.is_event()).count();
            if event_count >= self.capacity {
                match self.policy {
                    SlowConsumerPolicy::DropOldest => {
                        drop_oldest_event(&mut queue);
                        self.dropped.fetch_add(1, Ordering::Relaxed);
                        queue.push_back(OutboundFrame::Event(event));
                        PushOutcome::DroppedOldest
                    }
                    SlowConsumerPolicy::Disconnect => {
                        self.dropped.fetch_add(1, Ordering::Relaxed);
                        self.disconnect.store(true, Ordering::SeqCst);
                        PushOutcome::OverflowDisconnect
                    }
                }
            } else {
                queue.push_back(OutboundFrame::Event(event));
                PushOutcome::Delivered
            }
        };
        self.notify.notify_one();
        outcome
    }

    /// Push a reply. Replies are **never** dropped: if the queue is at capacity
    /// the oldest *event* is dropped to make room, so a burst of events can
    /// never starve a command's correlated reply.
    pub fn push_reply(&self, reply: ReplyFrame) {
        {
            let mut queue = self.lock();
            let event_count = queue.iter().filter(|frame| frame.is_event()).count();
            if event_count >= self.capacity && drop_oldest_event(&mut queue) {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
            queue.push_back(OutboundFrame::Reply(reply));
        }
        self.notify.notify_one();
    }

    /// Await and drain all currently-queued frames. Returns an empty vector only
    /// when the queue has been [`closed`](Self::close).
    pub async fn recv_many(&self) -> Vec<OutboundFrame> {
        loop {
            {
                let mut queue = self.lock();
                if !queue.is_empty() {
                    return queue.drain(..).collect();
                }
            }
            if self.closed.load(Ordering::SeqCst) {
                return Vec::new();
            }
            self.notify.notified().await;
        }
    }

    /// Signal the writer to stop (used on connection teardown).
    pub fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.notify.notify_one();
    }

    /// Number of events dropped so far due to overflow.
    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Whether the queue has requested a disconnect (overflow under the
    /// `Disconnect` policy).
    pub fn disconnect_requested(&self) -> bool {
        self.disconnect.load(Ordering::SeqCst)
    }

    /// Current queued depth (test/observability only).
    pub fn depth(&self) -> usize {
        self.lock().len()
    }
}

/// Remove the oldest event frame in the queue (leaving replies in place).
/// Returns true if an event was removed.
fn drop_oldest_event(queue: &mut std::collections::VecDeque<OutboundFrame>) -> bool {
    if let Some(index) = queue.iter().position(|frame| frame.is_event()) {
        queue.remove(index);
        true
    } else {
        false
    }
}
