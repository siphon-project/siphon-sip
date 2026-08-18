//! `ControlBus` — the process-global app/connection/channel registry, the
//! bounded per-connection outbound queue, and the ownership + resync bookkeeping.
//!
//! Installed once at boot (like `registrar_arc()` / `B2BUA_CONTROL`), read by
//! the dispatcher when a controlled call needs an event pushed and by the
//! control listener when a connection registers or a command arrives.
//!
//! ## Isolation invariant
//!
//! Publishing an event to a connection is a **non-blocking `try_push`** onto a
//! **bounded** queue — it never `.await`s and never parks the caller (the
//! dispatcher / a leg actor). A stalled application backs up only its own queue;
//! on overflow the oldest *event* is dropped (default) or the connection is
//! marked for disconnect. Replies are never dropped. Pressure never reaches the
//! signaling plane.
//!
//! ## Ownership (exactly-one-owner)
//!
//! A channel is owned by exactly one connection. `offer_channel` assigns the
//! owner: round-robin over the app's persistent connections, or (per-call-connect
//! apps) the socket siphon dials for that call. Every command's `target` is
//! looked up here and its owner checked against the commanding connection —
//! server-authoritative, never client-asserted.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use dashmap::DashMap;
use tokio::sync::{oneshot, Notify};
use tracing::{debug, info, warn};

use crate::config::ControlAppConfig;

use super::protocol::{ControlResult, EventFrame, ReplyFrame};

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

/// Length-checked constant-time byte comparison (bearer tokens). Length may leak
/// — a token's length is not the secret.
pub(crate) fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference: u8 = 0;
    for (a, b) in left.iter().zip(right.iter()) {
        difference |= a ^ b;
    }
    difference == 0
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

/// A single control connection registered with the bus.
#[derive(Debug)]
pub struct ConnHandle {
    /// Process-unique connection id.
    pub id: u64,
    /// The application this connection authenticated as.
    pub app: String,
    /// The connection's bounded outbound queue (replies + events).
    pub events: Arc<OutboundQueue>,
}

/// A controlled channel entry (owner + resync/leak bookkeeping).
#[derive(Debug)]
struct ChannelEntry {
    /// The application that owns the channel.
    app: String,
    /// The owning connection id, or 0 when orphaned (owner disconnected).
    conn_id: AtomicU64,
    /// The internal `CallActor` id backing this channel.
    call_actor_id: String,
    /// The per-leg SIP Call-ID (CDR/HEP join key + `b2bua_*` routing).
    sip_call_id: String,
    /// Control-loss policy for this call ("hangup"/"continue"/"fallback").
    on_lost: String,
    /// Per-call variables (drain with the channel — never on `CallActor`).
    vars: Mutex<HashMap<String, String>>,
}

/// A read-only snapshot of a channel a connection owns (for command resolution
/// + resync enumeration).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelRef {
    /// The leg-scoped channel id.
    pub channel_id: String,
    /// The internal `CallActor` id.
    pub call_actor_id: String,
    /// The per-leg SIP Call-ID.
    pub sip_call_id: String,
    /// The owning application.
    pub app: String,
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

    fn get(&self, id: u64) -> Option<Arc<ConnHandle>> {
        self.lock().iter().find(|conn| conn.id == id).map(Arc::clone)
    }

    fn contains(&self, id: u64) -> bool {
        self.lock().iter().any(|conn| conn.id == id)
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

/// A command received from a control connection, en route to the substrate's
/// apply consumer. `response_tx` carries the *local* [`ControlResult`] back.
#[derive(Debug)]
pub struct ControlCommand {
    /// Client-owned request id (echoed in the reply).
    pub id: String,
    /// The authenticated app of the originating connection.
    pub app: String,
    /// The originating connection id (for reattach / resync).
    pub conn_id: u64,
    /// The adapter routing key (absent for substrate verbs).
    pub module: Option<String>,
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

/// The outcome of offering a handed-over call to an app.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfferOutcome {
    /// A persistent connection was assigned as owner and `StasisStart` pushed.
    Assigned,
    /// A per-call-connect dial was launched; ownership completes on connect (or
    /// the handoff deadline fires).
    Dialing,
    /// No controller is available (no connection, or a per-call-connect app with
    /// no `connect_url`) — the caller must apply the handoff default action now.
    NoController,
}

/// Process-global control-plane registry.
#[derive(Debug)]
pub struct ControlBus {
    apps: DashMap<String, AppFanout>,
    channels: DashMap<String, Arc<ChannelEntry>>,
    /// app → set of owned channel ids (disconnect cleanup + resync index).
    app_calls: DashMap<String, HashSet<String>>,
    app_config: HashMap<String, ControlAppConfig>,
    command_tx: flume::Sender<ControlCommand>,
    event_queue_depth: usize,
    slow_consumer: SlowConsumerPolicy,
    reattach_grace_secs: u64,
    handoff_deadline_ms: u64,
    next_conn_id: AtomicU64,
}

static CONTROL_BUS: OnceLock<Arc<ControlBus>> = OnceLock::new();

impl ControlBus {
    /// Build a new bus. `command_tx` feeds the substrate's apply consumer.
    pub fn new(
        command_tx: flume::Sender<ControlCommand>,
        apps: Vec<ControlAppConfig>,
        event_queue_depth: usize,
        slow_consumer: SlowConsumerPolicy,
        reattach_grace_secs: u64,
        handoff_deadline_ms: u64,
    ) -> Arc<Self> {
        let app_config = apps
            .into_iter()
            .map(|app| (app.name.clone(), app))
            .collect();
        Arc::new(Self {
            apps: DashMap::new(),
            channels: DashMap::new(),
            app_calls: DashMap::new(),
            app_config,
            command_tx,
            event_queue_depth: event_queue_depth.max(1),
            slow_consumer,
            reattach_grace_secs,
            handoff_deadline_ms,
            next_conn_id: AtomicU64::new(1),
        })
    }

    /// The default handoff deadline (ms) applied when `call.handover()` passes
    /// none.
    pub fn handoff_deadline_ms(&self) -> u64 {
        self.handoff_deadline_ms
    }

    /// Reattach an app's orphaned channels to the connection identified by
    /// `conn_id` and return the snapshot it now owns (the `resync` reply). Falls
    /// back to a read-only enumeration when the connection is not live.
    pub fn resync(&self, app: &str, conn_id: u64) -> Vec<ChannelRef> {
        match self.connection(app, conn_id) {
            Some(conn) => self.reattach(&conn),
            None => self.owned_channels(app),
        }
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

    /// Whether `app` is a known, configured control application.
    pub fn app_configured(&self, app: &str) -> bool {
        self.app_config.contains_key(app)
    }

    /// Match a presented bearer token against the configured apps, constant-time.
    /// Returns the matching app name, or `None` for an unknown token. An app with
    /// an empty token can never authenticate (fail-closed).
    pub fn authenticate_token(&self, token: &str) -> Option<String> {
        for config in self.app_config.values() {
            if !config.token.is_empty()
                && constant_time_eq(token.as_bytes(), config.token.as_bytes())
            {
                return Some(config.name.clone());
            }
        }
        None
    }

    /// The configured app entry, if any.
    pub fn app_config(&self, app: &str) -> Option<&ControlAppConfig> {
        self.app_config.get(app)
    }

    /// Register a new connection for `app`. Returns the handle whose `events`
    /// queue the connection's writer task drains.
    pub fn register_connection(&self, app: &str) -> Arc<ConnHandle> {
        let id = self.next_conn_id.fetch_add(1, Ordering::Relaxed);
        let handle = Arc::new(ConnHandle {
            id,
            app: app.to_string(),
            events: Arc::new(OutboundQueue::new(self.event_queue_depth, self.slow_consumer)),
        });
        self.apps
            .entry(app.to_string())
            .or_default()
            .add(Arc::clone(&handle));
        handle
    }

    /// Remove a connection from its application fanout, orphan the channels it
    /// owned, and schedule the control-loss (`on_lost`) grace timer for each.
    /// A reconnecting controller of the same app may `resync` within the grace
    /// window to re-claim ownership.
    pub fn unregister_connection(self: &Arc<Self>, conn: &ConnHandle) {
        if let Some(fanout) = self.apps.get(&conn.app) {
            fanout.remove(conn.id);
        }
        conn.events.close();
        self.apps.remove_if(&conn.app, |_, fanout| fanout.is_empty());

        // Orphan every channel this connection owned + arm the grace timer.
        let orphaned: Vec<String> = self
            .app_calls
            .get(&conn.app)
            .map(|entry| entry.value().iter().cloned().collect())
            .unwrap_or_default();
        for channel_id in orphaned {
            if let Some(entry) = self.channels.get(&channel_id) {
                if entry.conn_id.load(Ordering::SeqCst) == conn.id {
                    entry.conn_id.store(0, Ordering::SeqCst);
                    self.schedule_control_loss(&channel_id);
                }
            }
        }
    }

    /// Arm the control-loss grace timer for an orphaned channel. After the grace
    /// window, if it has not been re-claimed (`conn_id` still 0), apply the
    /// call's `on_lost` policy.
    fn schedule_control_loss(self: &Arc<Self>, channel_id: &str) {
        let bus = Arc::clone(self);
        let channel_id = channel_id.to_string();
        let grace = std::time::Duration::from_secs(self.reattach_grace_secs);
        tokio::spawn(async move {
            tokio::time::sleep(grace).await;
            bus.apply_control_loss_if_orphaned(&channel_id);
        });
    }

    fn apply_control_loss_if_orphaned(&self, channel_id: &str) {
        let (still_orphaned, on_lost, sip_call_id, app) = match self.channels.get(channel_id) {
            Some(entry) => (
                entry.conn_id.load(Ordering::SeqCst) == 0,
                entry.on_lost.clone(),
                entry.sip_call_id.clone(),
                entry.app.clone(),
            ),
            None => return,
        };
        if !still_orphaned {
            return; // reattached within the grace window
        }
        info!(
            %channel_id,
            %app,
            on_lost = %on_lost,
            "control plane: owner lost past grace — applying control-loss policy"
        );
        self.remove_channel(channel_id);
        match on_lost.as_str() {
            "continue" => {
                // Leave the call running autonomously; nothing to tear down.
            }
            // "fallback" re-dispatch through Python handlers is a Phase-2 item;
            // degrade to hangup so a lost controller never silently strands a call.
            _ => {
                crate::dispatcher::b2bua_terminate_call(
                    &sip_call_id,
                    Some("control plane owner lost"),
                );
            }
        }
    }

    /// Round-robin select a connection of `app` (the `StasisStart` owner).
    pub fn pick_connection(&self, app: &str) -> Option<Arc<ConnHandle>> {
        self.apps.get(app).and_then(|fanout| fanout.pick())
    }

    /// Look up a live connection of `app` by id.
    fn connection(&self, app: &str, conn_id: u64) -> Option<Arc<ConnHandle>> {
        self.apps.get(app).and_then(|fanout| fanout.get(conn_id))
    }

    /// Register a controlled channel to an owning connection.
    #[allow(clippy::too_many_arguments)]
    pub fn register_channel(
        &self,
        channel_id: &str,
        conn: &ConnHandle,
        call_actor_id: &str,
        sip_call_id: &str,
        on_lost: &str,
        vars: HashMap<String, String>,
    ) {
        self.channels.insert(
            channel_id.to_string(),
            Arc::new(ChannelEntry {
                app: conn.app.clone(),
                conn_id: AtomicU64::new(conn.id),
                call_actor_id: call_actor_id.to_string(),
                sip_call_id: sip_call_id.to_string(),
                on_lost: on_lost.to_string(),
                vars: Mutex::new(vars),
            }),
        );
        self.app_calls
            .entry(conn.app.clone())
            .or_default()
            .insert(channel_id.to_string());
        crate::metrics::try_metrics()
            .inspect(|m| m.control_controlled_calls.with_label_values(&[&conn.app]).inc());
    }

    /// Remove a channel and drop it from the app index. Returns whether it was
    /// present.
    pub fn remove_channel(&self, channel_id: &str) -> bool {
        match self.channels.remove(channel_id) {
            Some((_, entry)) => {
                if let Some(mut set) = self.app_calls.get_mut(&entry.app) {
                    set.remove(channel_id);
                }
                self.app_calls
                    .remove_if(&entry.app, |_, set| set.is_empty());
                crate::metrics::try_metrics()
                    .inspect(|m| m.control_controlled_calls.with_label_values(&[&entry.app]).dec());
                true
            }
            None => false,
        }
    }

    /// The channel id owning `sip_call_id`, if controlled (for a `StasisEnd` /
    /// release before removal). O(channels) — a per-call teardown path, not
    /// per-packet.
    pub fn channel_id_for_sip_call_id(&self, sip_call_id: &str) -> Option<String> {
        self.channels
            .iter()
            .find(|entry| entry.value().sip_call_id == sip_call_id)
            .map(|entry| entry.key().clone())
    }

    /// Release a controlled channel back to siphon (the controller handed control
    /// back with a routing decision — `route`), emitting a `StasisEnd` with the
    /// given `reason` to the owning connection and draining the channel from the
    /// bus. **Distinct from teardown-on-hangup** ([`on_call_terminated`]): the
    /// underlying call lives on — siphon now owns it and drives the B-leg dial
    /// itself. Idempotent — a no-op when the channel is unknown. Returns whether
    /// a channel was released.
    ///
    /// [`on_call_terminated`]: Self::on_call_terminated
    pub fn release_channel(&self, channel_id: &str, reason: &str) -> bool {
        let (app, call_actor_id, sip_call_id) = match self.channels.get(channel_id) {
            Some(entry) => (
                entry.app.clone(),
                entry.call_actor_id.clone(),
                entry.sip_call_id.clone(),
            ),
            None => return false,
        };
        self.publish_to_channel(
            channel_id,
            EventFrame::new(
                "StasisEnd",
                channel_id,
                &app,
                &call_actor_id,
                &sip_call_id,
                serde_json::json!({ "reason": reason }),
            ),
        );
        self.remove_channel(channel_id);
        debug!(%channel_id, %sip_call_id, reason, "control plane: channel released (control returned to siphon)");
        true
    }

    /// Whether the given connection owns the channel (authZ for a command).
    pub fn owns(&self, channel_id: &str, app: &str, conn_id: u64) -> Ownership {
        match self.channels.get(channel_id) {
            None => Ownership::Unknown,
            Some(entry) => {
                if entry.app != app {
                    Ownership::Forbidden
                } else if entry.conn_id.load(Ordering::SeqCst) == conn_id
                    || entry.conn_id.load(Ordering::SeqCst) == 0
                {
                    // Same connection, or an orphaned channel of the same app
                    // being addressed by a reconnecting owner (post-resync).
                    Ownership::Owned(ChannelRef {
                        channel_id: channel_id.to_string(),
                        call_actor_id: entry.call_actor_id.clone(),
                        sip_call_id: entry.sip_call_id.clone(),
                        app: entry.app.clone(),
                    })
                } else {
                    Ownership::Forbidden
                }
            }
        }
    }

    /// Publish an event to a channel's owning connection (non-blocking).
    /// Returns `false` if the channel is unknown or currently orphaned.
    pub fn publish_to_channel(&self, channel_id: &str, frame: EventFrame) -> bool {
        let (app, conn_id) = match self.channels.get(channel_id) {
            Some(entry) => (entry.app.clone(), entry.conn_id.load(Ordering::SeqCst)),
            None => return false,
        };
        if conn_id == 0 {
            return false;
        }
        match self.connection(&app, conn_id) {
            Some(conn) => {
                conn.events.try_push_event(frame);
                true
            }
            None => false,
        }
    }

    /// Emit a `StasisEnd` for the call identified by `sip_call_id` and remove
    /// the channel. Idempotent — a no-op when the call is not controlled.
    /// Called from every B2BUA teardown junction, guarded internally.
    pub fn on_call_terminated(&self, sip_call_id: &str, reason: &str) {
        let Some(channel_id) = self.channel_id_for_sip_call_id(sip_call_id) else {
            return;
        };
        let (app, call_actor_id) = match self.channels.get(&channel_id) {
            Some(entry) => (entry.app.clone(), entry.call_actor_id.clone()),
            None => return,
        };
        self.publish_to_channel(
            &channel_id,
            EventFrame::new(
                "StasisEnd",
                &channel_id,
                &app,
                &call_actor_id,
                sip_call_id,
                serde_json::json!({ "reason": reason }),
            ),
        );
        self.remove_channel(&channel_id);
        debug!(%channel_id, %sip_call_id, reason, "control plane: StasisEnd + channel removed");
    }

    /// Offer a handed-over call to an app: assign a persistent owner (round
    /// robin) and push `StasisStart`, or launch a per-call-connect dial. Returns
    /// the outcome so the dispatcher knows whether to arm the handoff deadline
    /// or apply the default action immediately.
    #[allow(clippy::too_many_arguments)]
    pub fn offer_channel(
        self: &Arc<Self>,
        app: &str,
        channel_id: &str,
        call_actor_id: &str,
        sip_call_id: &str,
        on_lost: &str,
        vars: HashMap<String, String>,
        stasis_payload: serde_json::Value,
    ) -> OfferOutcome {
        let per_call_connect = self
            .app_config
            .get(app)
            .map(|config| config.per_call_connect)
            .unwrap_or(false);

        if per_call_connect {
            let config = match self.app_config.get(app) {
                Some(config) => config.clone(),
                None => return OfferOutcome::NoController,
            };
            let Some(connect_url) = config.connect_url.clone() else {
                warn!(%app, "control plane: per_call_connect app has no connect_url");
                return OfferOutcome::NoController;
            };
            super::outbound::dial_and_own(
                Arc::clone(self),
                config.name.clone(),
                config.token.clone(),
                connect_url,
                super::outbound::PendingOwn {
                    channel_id: channel_id.to_string(),
                    call_actor_id: call_actor_id.to_string(),
                    sip_call_id: sip_call_id.to_string(),
                    on_lost: on_lost.to_string(),
                    vars,
                    stasis_payload,
                },
            );
            return OfferOutcome::Dialing;
        }

        // Persistent inbound mode: round-robin a live connection.
        match self.pick_connection(app) {
            Some(conn) => {
                self.register_channel(channel_id, &conn, call_actor_id, sip_call_id, on_lost, vars);
                conn.events.try_push_event(EventFrame::new(
                    "StasisStart",
                    channel_id,
                    app,
                    call_actor_id,
                    sip_call_id,
                    stasis_payload,
                ));
                OfferOutcome::Assigned
            }
            None => OfferOutcome::NoController,
        }
    }

    /// Re-claim (reattach) an app's orphaned channels to a reconnecting
    /// connection, and return the current snapshot of everything it now owns
    /// (for the `resync` reply).
    pub fn reattach(&self, conn: &ConnHandle) -> Vec<ChannelRef> {
        let channel_ids: Vec<String> = self
            .app_calls
            .get(&conn.app)
            .map(|entry| entry.value().iter().cloned().collect())
            .unwrap_or_default();
        let mut owned = Vec::new();
        for channel_id in channel_ids {
            if let Some(entry) = self.channels.get(&channel_id) {
                let current = entry.conn_id.load(Ordering::SeqCst);
                // Re-point orphaned channels (or channels whose owner conn is no
                // longer live) at this connection.
                if current == 0 || !self.is_conn_live(&conn.app, current) {
                    entry.conn_id.store(conn.id, Ordering::SeqCst);
                }
                owned.push(ChannelRef {
                    channel_id: channel_id.clone(),
                    call_actor_id: entry.call_actor_id.clone(),
                    sip_call_id: entry.sip_call_id.clone(),
                    app: entry.app.clone(),
                });
            }
        }
        owned
    }

    fn is_conn_live(&self, app: &str, conn_id: u64) -> bool {
        self.apps
            .get(app)
            .map(|fanout| fanout.contains(conn_id))
            .unwrap_or(false)
    }

    /// Snapshot the channels an app owns (for resync enumeration + `/admin`).
    pub fn owned_channels(&self, app: &str) -> Vec<ChannelRef> {
        self.app_calls
            .get(app)
            .map(|entry| {
                entry
                    .value()
                    .iter()
                    .filter_map(|channel_id| {
                        self.channels.get(channel_id).map(|entry| ChannelRef {
                            channel_id: channel_id.clone(),
                            call_actor_id: entry.call_actor_id.clone(),
                            sip_call_id: entry.sip_call_id.clone(),
                            app: entry.app.clone(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Set a per-call variable. Returns false when the channel is unknown.
    pub fn set_var(&self, channel_id: &str, key: &str, value: &str) -> bool {
        match self.channels.get(channel_id) {
            Some(entry) => {
                if let Ok(mut vars) = entry.vars.lock() {
                    vars.insert(key.to_string(), value.to_string());
                }
                true
            }
            None => false,
        }
    }

    /// Read a per-call variable (None when the channel or key is unknown).
    pub fn get_var(&self, channel_id: &str, key: &str) -> Option<String> {
        let entry = self.channels.get(channel_id)?;
        let vars = entry.vars.lock().ok()?;
        vars.get(key).cloned()
    }

    /// Snapshot all per-call variables for a channel.
    pub fn vars(&self, channel_id: &str) -> HashMap<String, String> {
        self.channels
            .get(channel_id)
            .and_then(|entry| entry.vars.lock().ok().map(|vars| vars.clone()))
            .unwrap_or_default()
    }

    /// The app that owns the call identified by `sip_call_id`, if controlled.
    pub fn controlling_app(&self, sip_call_id: &str) -> Option<String> {
        self.channels
            .iter()
            .find(|entry| entry.value().sip_call_id == sip_call_id)
            .map(|entry| entry.value().app.clone())
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

/// Outcome of an ownership check for a command target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ownership {
    /// The connection owns the channel — carries the resolved ids.
    Owned(ChannelRef),
    /// The channel exists but is owned by a different app → `forbidden`.
    Forbidden,
    /// No such channel → `not_found`.
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::protocol::ControlResult;

    fn app_cfg(name: &str) -> ControlAppConfig {
        ControlAppConfig {
            name: name.to_string(),
            token: "tok".to_string(),
            per_call_connect: false,
            connect_url: None,
            on_lost: Some("hangup".to_string()),
        }
    }

    fn test_bus(depth: usize, policy: SlowConsumerPolicy) -> Arc<ControlBus> {
        let (command_tx, _command_rx) = flume::unbounded();
        ControlBus::new(command_tx, vec![app_cfg("ivr-app")], depth, policy, 10, 3000)
    }

    fn stasis_start(channel: &str, app: &str) -> EventFrame {
        EventFrame::new("StasisStart", channel, app, "call-uuid", "sipcid", serde_json::json!({}))
    }

    #[test]
    fn authenticate_token_matches_configured_app() {
        let bus = test_bus(16, SlowConsumerPolicy::DropOldest);
        assert_eq!(bus.authenticate_token("tok").as_deref(), Some("ivr-app"));
        assert!(bus.authenticate_token("wrong").is_none());
        assert!(bus.authenticate_token("").is_none());
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
        let a = bus.register_connection("ivr-app");
        let b = bus.register_connection("ivr-app");
        let first = bus.pick_connection("ivr-app").unwrap().id;
        let second = bus.pick_connection("ivr-app").unwrap().id;
        assert_ne!(first, second);
        let mut ids = [first, second];
        ids.sort_unstable();
        let mut expected = [a.id, b.id];
        expected.sort_unstable();
        assert_eq!(ids, expected);
    }

    #[test]
    fn offer_assigns_exactly_one_owner() {
        let bus = test_bus(16, SlowConsumerPolicy::DropOldest);
        let conn = bus.register_connection("ivr-app");
        let outcome = bus.offer_channel(
            "ivr-app",
            "ch1",
            "call-uuid",
            "sipcid",
            "hangup",
            HashMap::new(),
            serde_json::json!({}),
        );
        assert_eq!(outcome, OfferOutcome::Assigned);
        assert_eq!(bus.channel_count(), 1);
        // Exactly one owner: the round-robin winner got the StasisStart.
        assert_eq!(conn.events.depth(), 1);
        match bus.owns("ch1", "ivr-app", conn.id) {
            Ownership::Owned(channel) => assert_eq!(channel.call_actor_id, "call-uuid"),
            other => panic!("expected owned, got {other:?}"),
        }
    }

    #[test]
    fn offer_without_connection_reports_no_controller() {
        let bus = test_bus(16, SlowConsumerPolicy::DropOldest);
        let outcome = bus.offer_channel(
            "ivr-app",
            "ch1",
            "call-uuid",
            "sipcid",
            "hangup",
            HashMap::new(),
            serde_json::json!({}),
        );
        assert_eq!(outcome, OfferOutcome::NoController);
        assert_eq!(bus.channel_count(), 0);
    }

    #[test]
    fn cross_app_target_is_forbidden() {
        let (command_tx, _rx) = flume::unbounded();
        let bus = ControlBus::new(
            command_tx,
            vec![app_cfg("ivr-app"), app_cfg("other")],
            16,
            SlowConsumerPolicy::DropOldest,
            10,
            3000,
        );
        let owner = bus.register_connection("ivr-app");
        let intruder = bus.register_connection("other");
        bus.register_channel("ch1", &owner, "call", "sipcid", "hangup", HashMap::new());
        assert!(matches!(bus.owns("ch1", "ivr-app", owner.id), Ownership::Owned(_)));
        assert_eq!(bus.owns("ch1", "other", intruder.id), Ownership::Forbidden);
        assert_eq!(bus.owns("nope", "ivr-app", owner.id), Ownership::Unknown);
    }

    #[tokio::test]
    async fn cancel_while_parked_emits_stasis_end_and_drains() {
        // Models the teardown the CANCEL path (`handle_b2bua_cancel`) now runs
        // for a handed-over call the caller CANCELs before the controller acts:
        // control_notify_terminated → on_call_terminated. The owning app must be
        // told (StasisEnd) and every bus entry must drain — the leak the report
        // flagged (channel/app_calls/owner cleaned only on app disconnect).
        let bus = test_bus(16, SlowConsumerPolicy::DropOldest);
        let conn = bus.register_connection("ivr-app");
        bus.offer_channel(
            "ivr-app",
            "ch1",
            "call-uuid",
            "sipcid@h",
            "hangup",
            HashMap::new(),
            serde_json::json!({}),
        );
        assert_eq!(bus.channel_count(), 1);
        assert_eq!(bus.owned_channels("ivr-app").len(), 1);

        // Caller CANCEL, keyed on the A-leg Call-ID.
        bus.on_call_terminated("sipcid@h", "cancelled");

        // The owning connection received StasisStart then StasisEnd(cancelled).
        let frames = conn.events.recv_many().await;
        let stasis_end = frames
            .iter()
            .find_map(|frame| match frame {
                OutboundFrame::Event(event) if event.event == "StasisEnd" => Some(event),
                _ => None,
            })
            .expect("owning app must receive StasisEnd on CANCEL");
        assert_eq!(stasis_end.payload["reason"], "cancelled");
        assert_eq!(stasis_end.channel.as_deref(), Some("ch1"));

        // Every per-call entry drained to baseline (no leak).
        assert_eq!(bus.channel_count(), 0, "channel leaked after CANCEL");
        assert!(bus.owned_channels("ivr-app").is_empty(), "app_calls leaked after CANCEL");
    }

    #[tokio::test]
    async fn release_channel_emits_stasis_end_routed_and_drains() {
        // The `route` return-control path: the controller hands the call back to
        // siphon. The owning app must be told (StasisEnd{reason:"routed"}) and the
        // bus must drain — but unlike a hangup, the underlying call lives on
        // (siphon dials the B-leg). Keyed by channel id (not sip_call_id).
        let bus = test_bus(16, SlowConsumerPolicy::DropOldest);
        let conn = bus.register_connection("ivr-app");
        bus.offer_channel(
            "ivr-app",
            "ch1",
            "call-uuid",
            "sipcid@h",
            "hangup",
            HashMap::new(),
            serde_json::json!({}),
        );
        assert_eq!(bus.channel_count(), 1);
        assert_eq!(bus.channel_id_for_sip_call_id("sipcid@h").as_deref(), Some("ch1"));

        assert!(bus.release_channel("ch1", "routed"));

        let frames = conn.events.recv_many().await;
        let stasis_end = frames
            .iter()
            .find_map(|frame| match frame {
                OutboundFrame::Event(event) if event.event == "StasisEnd" => Some(event),
                _ => None,
            })
            .expect("owning app must receive StasisEnd on release");
        assert_eq!(stasis_end.payload["reason"], "routed");
        assert_eq!(stasis_end.channel.as_deref(), Some("ch1"));

        // Every per-call entry drained to baseline (no leak).
        assert_eq!(bus.channel_count(), 0, "channel leaked after release");
        assert!(bus.owned_channels("ivr-app").is_empty(), "app_calls leaked after release");
        assert!(bus.channel_id_for_sip_call_id("sipcid@h").is_none());
        // Idempotent: a second release is a clean no-op.
        assert!(!bus.release_channel("ch1", "routed"));
    }

    /// Steady-state leak gate for the return-control (`route`) path: N cycles of
    /// register-conn + offer-channel + release-channel → both maps drain to their
    /// starting `len()`. The co-located analogue of `mem_leak_test.sh` gating
    /// `siphon_proxy_dialog_sessions → 0`, for the release path specifically.
    #[test]
    fn release_channel_steady_state_drains_to_baseline() {
        let bus = test_bus(16, SlowConsumerPolicy::DropOldest);
        assert_eq!(bus.channel_count(), 0);

        for cycle in 0..5 {
            let mut conns = Vec::new();
            for index in 0..8 {
                let conn = bus.register_connection("ivr-app");
                let channel = format!("ch-{cycle}-{index}");
                bus.offer_channel(
                    "ivr-app",
                    &channel,
                    &format!("call-{cycle}-{index}"),
                    &format!("sip-{cycle}-{index}"),
                    "hangup",
                    HashMap::new(),
                    serde_json::json!({}),
                );
                conns.push((conn, channel));
            }
            assert_eq!(bus.channel_count(), 8);

            for (conn, channel) in conns {
                // Return control to siphon (the call lives on) rather than hangup.
                assert!(bus.release_channel(&channel, "routed"));
                if let Some(fanout) = bus.apps.get(&conn.app) {
                    fanout.remove(conn.id);
                }
                conn.events.close();
                bus.apps.remove_if(&conn.app, |_, fanout| fanout.is_empty());
            }

            assert_eq!(bus.channel_count(), 0, "channels leaked on cycle {cycle}");
            assert_eq!(bus.app_count(), 0, "apps leaked on cycle {cycle}");
            assert!(bus.app_calls.is_empty(), "app_calls index leaked on cycle {cycle}");
        }
    }

    #[test]
    fn per_call_vars_get_set_and_drain() {
        let bus = test_bus(16, SlowConsumerPolicy::DropOldest);
        let conn = bus.register_connection("ivr-app");
        bus.register_channel("ch1", &conn, "call", "sipcid", "hangup", HashMap::new());
        assert!(bus.set_var("ch1", "queue", "support"));
        assert_eq!(bus.get_var("ch1", "queue").as_deref(), Some("support"));
        assert!(!bus.set_var("nope", "k", "v"));
        bus.remove_channel("ch1");
        assert_eq!(bus.get_var("ch1", "queue"), None);
    }

    #[tokio::test]
    async fn resync_enumerates_and_reattaches_owned_channels() {
        let bus = test_bus(16, SlowConsumerPolicy::DropOldest);
        let first = bus.register_connection("ivr-app");
        bus.offer_channel(
            "ivr-app",
            "ch1",
            "call-uuid",
            "sipcid",
            "hangup",
            HashMap::new(),
            serde_json::json!({}),
        );
        // Owner disconnects; the channel is orphaned but not (yet) torn down.
        bus.unregister_connection(&first);
        assert_eq!(bus.channel_count(), 1);
        assert!(!bus.publish_to_channel("ch1", stasis_start("ch1", "ivr-app")));

        // A fresh connection of the same app resyncs and re-claims it.
        let second = bus.register_connection("ivr-app");
        let owned = bus.reattach(&second);
        assert_eq!(owned.len(), 1);
        assert_eq!(owned[0].channel_id, "ch1");
        // Now events route to the reattached connection.
        assert!(bus.publish_to_channel("ch1", stasis_start("ch1", "ivr-app")));
        assert_eq!(second.events.depth(), 1);
    }

    #[tokio::test]
    async fn ordering_events_and_replies_share_one_queue_in_order() {
        let bus = test_bus(16, SlowConsumerPolicy::DropOldest);
        let conn = bus.register_connection("ivr-app");
        bus.register_channel("ch1", &conn, "call", "sipcid", "hangup", HashMap::new());
        // Interleave an event, a reply, an event — the single queue preserves
        // submission order for the call.
        bus.publish_to_channel("ch1", stasis_start("ch1", "ivr-app"));
        conn.events.push_reply(
            ControlResult::Ok(serde_json::json!({"ok": true})).into_reply("c-1".to_string()),
        );
        bus.publish_to_channel(
            "ch1",
            EventFrame::new("StasisEnd", "ch1", "ivr-app", "call", "sipcid", serde_json::json!({})),
        );
        let drained = conn.events.recv_many().await;
        assert_eq!(drained.len(), 3);
        assert!(matches!(drained[0], OutboundFrame::Event(_)));
        assert!(matches!(drained[1], OutboundFrame::Reply(_)));
        assert!(matches!(drained[2], OutboundFrame::Event(_)));
    }

    #[tokio::test]
    async fn reply_never_dropped_even_when_event_queue_full() {
        let queue = OutboundQueue::new(2, SlowConsumerPolicy::DropOldest);
        let event = || EventFrame::new("E", "c", "a", "call", "sip", serde_json::json!({}));
        queue.try_push_event(event());
        queue.try_push_event(event());
        // Queue full of events; a reply must still get in (an event is dropped).
        queue.push_reply(ControlResult::Ok(serde_json::json!({})).into_reply("c-9".to_string()));
        let drained = queue.recv_many().await;
        assert!(drained.iter().any(|frame| matches!(frame, OutboundFrame::Reply(_))));
        assert_eq!(queue.dropped_count(), 1);
    }

    /// Steady-state leak gate: N cycles of register-conn + offer-channel +
    /// hangup + disconnect → both maps drain to their starting `len()`. The
    /// co-located analogue of `mem_leak_test.sh` gating
    /// `siphon_proxy_dialog_sessions → 0`.
    #[test]
    fn steady_state_drains_to_baseline() {
        let bus = test_bus(16, SlowConsumerPolicy::DropOldest);
        assert_eq!(bus.app_count(), 0);
        assert_eq!(bus.channel_count(), 0);

        for cycle in 0..5 {
            let mut conns = Vec::new();
            for index in 0..8 {
                let conn = bus.register_connection("ivr-app");
                let channel = format!("ch-{cycle}-{index}");
                let sip_call_id = format!("sip-{cycle}-{index}");
                bus.register_channel(
                    &channel,
                    &conn,
                    &format!("call-{cycle}-{index}"),
                    &sip_call_id,
                    "hangup",
                    HashMap::new(),
                );
                bus.publish_to_channel(&channel, stasis_start(&channel, "ivr-app"));
                conns.push((conn, channel, sip_call_id));
            }
            assert_eq!(bus.channel_count(), 8);
            assert_eq!(bus.app_connection_count("ivr-app"), 8);

            for (position, (conn, channel, sip_call_id)) in conns.into_iter().enumerate() {
                // Alternate the teardown trigger: half via a direct hangup
                // (remove_channel), half via the CANCEL/BYE path
                // (on_call_terminated by sip_call_id) — the latter is what the
                // report's leak fix restored on the CANCEL-while-parked path.
                if position % 2 == 0 {
                    bus.remove_channel(&channel);
                } else {
                    bus.on_call_terminated(&sip_call_id, "cancelled");
                }
                // Directly remove the fanout entry (no grace timer in a
                // non-tokio test context).
                if let Some(fanout) = bus.apps.get(&conn.app) {
                    fanout.remove(conn.id);
                }
                conn.events.close();
                bus.apps.remove_if(&conn.app, |_, fanout| fanout.is_empty());
            }

            assert_eq!(bus.channel_count(), 0, "channels leaked on cycle {cycle}");
            assert_eq!(bus.app_count(), 0, "apps leaked on cycle {cycle}");
            assert!(bus.app_calls.is_empty(), "app_calls index leaked on cycle {cycle}");
        }
    }

    #[test]
    fn event_queue_bounded_drop_oldest() {
        let queue = OutboundQueue::new(2, SlowConsumerPolicy::DropOldest);
        let event = || EventFrame::new("E", "c", "a", "call", "sip", serde_json::json!({}));
        assert_eq!(queue.try_push_event(event()), PushOutcome::Delivered);
        assert_eq!(queue.try_push_event(event()), PushOutcome::Delivered);
        assert_eq!(queue.try_push_event(event()), PushOutcome::DroppedOldest);
        assert_eq!(queue.try_push_event(event()), PushOutcome::DroppedOldest);
        assert_eq!(queue.depth(), 2, "queue must stay bounded at capacity");
        assert_eq!(queue.dropped_count(), 2);
        assert!(!queue.disconnect_requested());
    }

    #[test]
    fn event_queue_disconnect_policy_flags_slow_consumer() {
        let queue = OutboundQueue::new(1, SlowConsumerPolicy::Disconnect);
        let event = || EventFrame::new("E", "c", "a", "call", "sip", serde_json::json!({}));
        assert_eq!(queue.try_push_event(event()), PushOutcome::Delivered);
        assert_eq!(queue.try_push_event(event()), PushOutcome::OverflowDisconnect);
        assert!(queue.disconnect_requested());
        assert_eq!(queue.depth(), 1, "queue must stay bounded at capacity");
    }

    #[test]
    fn publishing_never_blocks_a_stuck_consumer() {
        // A consumer that never drains: publishing must return immediately and
        // the queue must stay bounded rather than grow without limit.
        let bus = test_bus(4, SlowConsumerPolicy::DropOldest);
        let conn = bus.register_connection("ivr-app");
        bus.register_channel("ch", &conn, "call", "sipcid", "hangup", HashMap::new());
        for _ in 0..1000 {
            bus.publish_to_channel("ch", stasis_start("ch", "ivr-app"));
        }
        assert_eq!(conn.events.depth(), 4);
        assert_eq!(conn.events.dropped_count(), 996);
    }
}
