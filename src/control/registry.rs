//! `ControlBus` — the process-global app/connection/channel registry and the
//! bounded per-connection event queue.
//!
//! Installed once at boot (like `registrar_arc()` / `set_uac_sender()`), read by
//! the dispatcher when a controlled call needs an event pushed and by the
//! control WebSocket listener when a connection registers or a command arrives.
//!
//! ## Isolation invariant
//!
//! Publishing an event to a connection is a **non-blocking `try_push`** onto a
//! **bounded** queue — it never `.await`s and never parks the caller (the
//! dispatcher / a leg actor). A stalled application backs up only its own queue;
//! on overflow the oldest event is dropped (default) or the connection is marked
//! for disconnect. Pressure never reaches the signaling plane.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use dashmap::DashMap;
use tokio::sync::{oneshot, Notify};

use super::protocol::{ControlResult, EventFrame};

/// Overflow policy for a per-connection event queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SlowConsumerPolicy {
    /// Drop the oldest queued event to make room (default).
    #[default]
    DropOldest,
    /// Mark the connection for disconnect (the writer task closes it).
    Disconnect,
}

/// Result of a single [`EventQueue::try_push`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushOutcome {
    /// The event was queued.
    Delivered,
    /// The queue was full; the oldest event was dropped to make room.
    DroppedOldest,
    /// The queue was full and the policy is `Disconnect`; the event was dropped
    /// and the connection is now flagged for disconnect.
    OverflowDisconnect,
}

/// A bounded, non-blocking, drop-oldest event queue for one connection.
///
/// The producer (dispatcher / leg actor) calls [`try_push`](Self::try_push) —
/// a brief lock, never held across an `.await`. The connection's async writer
/// task calls [`recv_many`](Self::recv_many) which parks on a `Notify` until
/// events are available, then drains them all under one lock.
#[derive(Debug)]
pub struct EventQueue {
    inner: Mutex<VecDeque<EventFrame>>,
    notify: Notify,
    capacity: usize,
    policy: SlowConsumerPolicy,
    dropped: AtomicU64,
    disconnect: AtomicBool,
    closed: AtomicBool,
}

impl EventQueue {
    /// Create a queue with the given capacity and overflow policy.
    pub fn new(capacity: usize, policy: SlowConsumerPolicy) -> Self {
        Self {
            inner: Mutex::new(VecDeque::with_capacity(capacity.min(64))),
            notify: Notify::new(),
            capacity: capacity.max(1),
            policy,
            dropped: AtomicU64::new(0),
            disconnect: AtomicBool::new(false),
            closed: AtomicBool::new(false),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, VecDeque<EventFrame>> {
        match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Push one event without ever blocking or awaiting.
    pub fn try_push(&self, frame: EventFrame) -> PushOutcome {
        let outcome = {
            let mut queue = self.lock();
            if queue.len() >= self.capacity {
                match self.policy {
                    SlowConsumerPolicy::DropOldest => {
                        queue.pop_front();
                        self.dropped.fetch_add(1, Ordering::Relaxed);
                        queue.push_back(frame);
                        PushOutcome::DroppedOldest
                    }
                    SlowConsumerPolicy::Disconnect => {
                        self.dropped.fetch_add(1, Ordering::Relaxed);
                        self.disconnect.store(true, Ordering::SeqCst);
                        PushOutcome::OverflowDisconnect
                    }
                }
            } else {
                queue.push_back(frame);
                PushOutcome::Delivered
            }
        };
        // Wake the writer (outside the lock). Even on disconnect we notify so
        // the writer observes the flag and closes.
        self.notify.notify_one();
        outcome
    }

    /// Await and drain all currently-queued events. Returns an empty vector only
    /// when the queue has been [`closed`](Self::close).
    pub async fn recv_many(&self) -> Vec<EventFrame> {
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

/// A single control connection registered with the bus.
#[derive(Debug)]
pub struct ConnHandle {
    /// Process-unique connection id.
    pub id: u64,
    /// The application this connection authenticated as.
    pub app: String,
    /// The connection's bounded outbound event queue.
    pub events: Arc<EventQueue>,
}

/// The owner of a controlled channel (for command routing + authZ).
#[derive(Debug, Clone)]
pub struct ChannelOwner {
    /// The application that owns the channel.
    pub app: String,
    /// The specific connection the channel was handed to.
    pub conn: Arc<ConnHandle>,
    /// The internal `CallActor` id backing this channel.
    pub call_actor_id: String,
}

/// The set of connections for one application, with a round-robin cursor.
#[derive(Debug, Default)]
struct AppFanout {
    conns: Mutex<Vec<Arc<ConnHandle>>>,
    cursor: AtomicUsize,
}

impl AppFanout {
    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<Arc<ConnHandle>>> {
        match self.conns.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn add(&self, conn: Arc<ConnHandle>) {
        self.lock().push(conn);
    }

    fn remove(&self, id: u64) {
        self.lock().retain(|conn| conn.id != id);
    }

    fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    fn len(&self) -> usize {
        self.lock().len()
    }

    fn pick(&self) -> Option<Arc<ConnHandle>> {
        let conns = self.lock();
        if conns.is_empty() {
            return None;
        }
        let index = self.cursor.fetch_add(1, Ordering::Relaxed) % conns.len();
        Some(Arc::clone(&conns[index]))
    }
}

/// A command received from a control connection, en route to the dispatcher's
/// apply consumer. `response_tx` carries the *local* [`ControlResult`] back.
#[derive(Debug)]
pub struct ControlCommand {
    /// Client-owned request id (echoed in the reply).
    pub id: String,
    /// The verb to apply.
    pub verb: String,
    /// Adapter-defined target (`serde_json::Value`).
    pub target: serde_json::Value,
    /// Adapter-defined arguments (`serde_json::Value`).
    pub args: serde_json::Value,
    /// Channel back to the connection's read task with the local result.
    pub response_tx: oneshot::Sender<ControlResult>,
}

impl ControlCommand {
    /// Extract the `target.channel` string when present.
    pub fn channel_target(&self) -> Option<String> {
        self.target
            .get("channel")
            .and_then(|value| value.as_str())
            .map(|value| value.to_string())
    }
}

/// Process-global control-plane registry.
#[derive(Debug)]
pub struct ControlBus {
    apps: DashMap<String, AppFanout>,
    channels: DashMap<String, ChannelOwner>,
    command_tx: flume::Sender<ControlCommand>,
    event_queue_depth: usize,
    slow_consumer: SlowConsumerPolicy,
    next_conn_id: AtomicU64,
}

static CONTROL_BUS: OnceLock<Arc<ControlBus>> = OnceLock::new();

impl ControlBus {
    /// Build a new bus. `command_tx` feeds the dispatcher's apply consumer.
    pub fn new(
        command_tx: flume::Sender<ControlCommand>,
        event_queue_depth: usize,
        slow_consumer: SlowConsumerPolicy,
    ) -> Arc<Self> {
        Arc::new(Self {
            apps: DashMap::new(),
            channels: DashMap::new(),
            command_tx,
            event_queue_depth: event_queue_depth.max(1),
            slow_consumer,
            next_conn_id: AtomicU64::new(1),
        })
    }

    /// Install the process-global bus. Returns `Err` if already installed.
    pub fn install(bus: Arc<ControlBus>) -> Result<(), Arc<ControlBus>> {
        CONTROL_BUS.set(bus)
    }

    /// The process-global bus, if installed.
    pub fn global() -> Option<Arc<ControlBus>> {
        CONTROL_BUS.get().cloned()
    }

    /// A cloneable sender for the command channel (used by the listener).
    pub fn command_sender(&self) -> flume::Sender<ControlCommand> {
        self.command_tx.clone()
    }

    /// Register a new connection for `app`. Returns the handle whose `events`
    /// queue the connection's writer task drains.
    pub fn register_connection(&self, app: &str) -> Arc<ConnHandle> {
        let id = self.next_conn_id.fetch_add(1, Ordering::Relaxed);
        let handle = Arc::new(ConnHandle {
            id,
            app: app.to_string(),
            events: Arc::new(EventQueue::new(self.event_queue_depth, self.slow_consumer)),
        });
        self.apps
            .entry(app.to_string())
            .or_default()
            .add(Arc::clone(&handle));
        handle
    }

    /// Remove a connection from its application fanout. Also drops the app entry
    /// once it has no more connections, so `apps` drains to baseline.
    pub fn unregister_connection(&self, conn: &ConnHandle) {
        if let Some(fanout) = self.apps.get(&conn.app) {
            fanout.remove(conn.id);
        }
        conn.events.close();
        self.apps.remove_if(&conn.app, |_, fanout| fanout.is_empty());
    }

    /// Round-robin select a connection of `app` (the `StasisStart` owner).
    pub fn pick_connection(&self, app: &str) -> Option<Arc<ConnHandle>> {
        self.apps.get(app).and_then(|fanout| fanout.pick())
    }

    /// Register a controlled channel to an owning connection.
    pub fn register_channel(
        &self,
        channel_id: &str,
        conn: Arc<ConnHandle>,
        call_actor_id: &str,
    ) {
        self.channels.insert(
            channel_id.to_string(),
            ChannelOwner {
                app: conn.app.clone(),
                conn,
                call_actor_id: call_actor_id.to_string(),
            },
        );
    }

    /// Remove a channel and return its former owner.
    pub fn remove_channel(&self, channel_id: &str) -> Option<ChannelOwner> {
        self.channels.remove(channel_id).map(|(_, owner)| owner)
    }

    /// The owner of a channel, if registered.
    pub fn channel_owner(&self, channel_id: &str) -> Option<ChannelOwner> {
        self.channels.get(channel_id).map(|entry| entry.value().clone())
    }

    /// Publish an event to a channel's owning connection (non-blocking).
    /// Returns `false` if the channel is unknown.
    pub fn publish_to_channel(&self, channel_id: &str, frame: EventFrame) -> bool {
        match self.channels.get(channel_id) {
            Some(entry) => {
                entry.value().conn.events.try_push(frame);
                true
            }
            None => false,
        }
    }

    /// Number of registered channels (drains to baseline — leak gate).
    pub fn channel_count(&self) -> usize {
        self.channels.len()
    }

    /// Number of applications with at least one connection.
    pub fn app_count(&self) -> usize {
        self.apps.len()
    }

    /// Number of connections registered for `app`.
    pub fn app_connection_count(&self, app: &str) -> usize {
        self.apps.get(app).map(|fanout| fanout.len()).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_bus(depth: usize, policy: SlowConsumerPolicy) -> Arc<ControlBus> {
        let (command_tx, _command_rx) = flume::unbounded();
        ControlBus::new(command_tx, depth, policy)
    }

    fn stasis_start(channel: &str, app: &str) -> EventFrame {
        EventFrame::new("StasisStart", channel, app, serde_json::json!({}))
    }

    #[test]
    fn register_and_pick_connection() {
        let bus = test_bus(16, SlowConsumerPolicy::DropOldest);
        assert_eq!(bus.app_count(), 0);
        let conn = bus.register_connection("ivr-app");
        assert_eq!(bus.app_count(), 1);
        assert_eq!(bus.app_connection_count("ivr-app"), 1);
        let picked = bus.pick_connection("ivr-app").unwrap();
        assert_eq!(picked.id, conn.id);
        assert!(bus.pick_connection("other-app").is_none());
    }

    #[test]
    fn round_robin_pick_rotates() {
        let bus = test_bus(16, SlowConsumerPolicy::DropOldest);
        let a = bus.register_connection("app");
        let b = bus.register_connection("app");
        let first = bus.pick_connection("app").unwrap().id;
        let second = bus.pick_connection("app").unwrap().id;
        assert_ne!(first, second);
        let mut ids = [first, second];
        ids.sort_unstable();
        let mut expected = [a.id, b.id];
        expected.sort_unstable();
        assert_eq!(ids, expected);
    }

    #[test]
    fn channel_register_and_publish_to_owner() {
        let bus = test_bus(16, SlowConsumerPolicy::DropOldest);
        let conn = bus.register_connection("ivr-app");
        bus.register_channel("ch1", Arc::clone(&conn), "call-uuid-1");
        assert_eq!(bus.channel_count(), 1);
        assert!(bus.publish_to_channel("ch1", stasis_start("ch1", "ivr-app")));
        assert_eq!(conn.events.depth(), 1);
        assert!(!bus.publish_to_channel("nope", stasis_start("nope", "ivr-app")));
    }

    /// Steady-state leak gate: register N conns + hand over N channels + hang up
    /// all of them + disconnect all conns → both maps drain to their starting
    /// `len()`. This is the co-located analogue of `mem_leak_test.sh` gating
    /// `siphon_proxy_dialog_sessions → 0`.
    #[test]
    fn steady_state_drains_to_baseline() {
        let bus = test_bus(16, SlowConsumerPolicy::DropOldest);
        let start_apps = bus.app_count();
        let start_channels = bus.channel_count();
        assert_eq!(start_apps, 0);
        assert_eq!(start_channels, 0);

        for cycle in 0..5 {
            let mut conns = Vec::new();
            for index in 0..8 {
                let conn = bus.register_connection("ivr-app");
                let channel = format!("ch-{cycle}-{index}");
                bus.register_channel(&channel, Arc::clone(&conn), &format!("call-{cycle}-{index}"));
                bus.publish_to_channel(&channel, stasis_start(&channel, "ivr-app"));
                conns.push((conn, channel));
            }
            assert_eq!(bus.channel_count(), 8);
            assert_eq!(bus.app_connection_count("ivr-app"), 8);

            for (conn, channel) in conns {
                // hangup path: remove the channel + emit StasisEnd to owner.
                let owner = bus.remove_channel(&channel).unwrap();
                owner
                    .conn
                    .events
                    .try_push(EventFrame::new("StasisEnd", &channel, "ivr-app", serde_json::json!({})));
                bus.unregister_connection(&conn);
            }

            assert_eq!(bus.channel_count(), start_channels, "channels leaked on cycle {cycle}");
            assert_eq!(bus.app_count(), start_apps, "apps leaked on cycle {cycle}");
        }
    }

    #[test]
    fn event_queue_bounded_drop_oldest() {
        let queue = EventQueue::new(2, SlowConsumerPolicy::DropOldest);
        assert_eq!(queue.try_push(stasis_start("c", "a")), PushOutcome::Delivered);
        assert_eq!(queue.try_push(stasis_start("c", "a")), PushOutcome::Delivered);
        // Full now — a slow/stuck consumer never grows the queue past capacity.
        assert_eq!(queue.try_push(stasis_start("c", "a")), PushOutcome::DroppedOldest);
        assert_eq!(queue.try_push(stasis_start("c", "a")), PushOutcome::DroppedOldest);
        assert_eq!(queue.depth(), 2, "queue must stay bounded at capacity");
        assert_eq!(queue.dropped_count(), 2);
        assert!(!queue.disconnect_requested());
    }

    #[test]
    fn event_queue_disconnect_policy_flags_slow_consumer() {
        let queue = EventQueue::new(1, SlowConsumerPolicy::Disconnect);
        assert_eq!(queue.try_push(stasis_start("c", "a")), PushOutcome::Delivered);
        assert_eq!(
            queue.try_push(stasis_start("c", "a")),
            PushOutcome::OverflowDisconnect
        );
        assert!(queue.disconnect_requested());
        assert_eq!(queue.depth(), 1, "queue must stay bounded at capacity");
    }

    #[tokio::test]
    async fn event_queue_recv_many_delivers_pushed_events() {
        let queue = Arc::new(EventQueue::new(8, SlowConsumerPolicy::DropOldest));
        let writer = Arc::clone(&queue);
        let handle = tokio::spawn(async move { writer.recv_many().await });
        queue.try_push(stasis_start("c1", "a"));
        let frames = handle.await.unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].channel.as_deref(), Some("c1"));
    }

    #[tokio::test]
    async fn publishing_never_blocks_a_stuck_consumer() {
        // A consumer that never drains: publishing must return immediately and
        // the queue must stay bounded rather than grow without limit.
        let bus = test_bus(4, SlowConsumerPolicy::DropOldest);
        let conn = bus.register_connection("ivr-app");
        bus.register_channel("ch", Arc::clone(&conn), "call");
        for _ in 0..1000 {
            // If this ever awaited/blocked, the test would hang.
            bus.publish_to_channel("ch", stasis_start("ch", "ivr-app"));
        }
        assert_eq!(conn.events.depth(), 4);
        assert_eq!(conn.events.dropped_count(), 996);
    }
}
