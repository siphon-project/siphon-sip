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
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use dashmap::DashMap;
use tokio::sync::oneshot;
use tracing::info;

use crate::config::ControlAppConfig;

use super::protocol::ControlResult;

mod channels;
mod events;
mod queue;
#[cfg(test)]
mod tests;
mod transfer;

pub use queue::{OutboundFrame, OutboundQueue, PushOutcome, SlowConsumerPolicy};
pub use transfer::{TransferOutcome, TransferStage};

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
    /// Control-loss policy for this call ("hangup" or "continue").
    on_lost: String,
    /// Per-call variables (drain with the channel — never on `CallActor`).
    vars: Mutex<HashMap<String, String>>,
    /// The `Refer-To` of an outbound REFER whose verdict has not landed yet.
    ///
    /// Set by the first non-terminal [`TransferOutcome`] on this channel and
    /// cleared by the terminal one. Its only job is the teardown flush: RFC 3515
    /// §2.4.4's implicit subscription dies with the dialog, so a call that goes
    /// away mid-transfer would otherwise leave the app waiting on a verdict that
    /// can never arrive. One `Option<String>` per channel, drained by
    /// [`ControlBus::remove_channel`] with everything else on the entry.
    outbound_transfer: Mutex<Option<String>>,
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
        self.lock()
            .iter()
            .find(|conn| conn.id == id)
            .map(Arc::clone)
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

    /// The process-global bus, if installed, without taking a reference: for a
    /// signalling-path check that runs on every call.
    pub fn global_ref() -> Option<&'static Arc<ControlBus>> {
        CONTROL_BUS.get()
    }

    /// Whether any configured app asked for the application-level event
    /// `class` (`control.apps[].events`).
    pub fn wants_app_class(&self, class: &str) -> bool {
        self.app_config
            .values()
            .any(|config| config.events.iter().any(|wanted| wanted == class))
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
            events: Arc::new(OutboundQueue::new(
                self.event_queue_depth,
                self.slow_consumer,
            )),
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
        self.apps
            .remove_if(&conn.app, |_, fanout| fanout.is_empty());

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
            // Anything else ends the call. `hangup` is the only other policy
            // siphon implements, and ending the call is the safe reading of
            // "the owner is gone". `fallback` is refused everywhere a call can
            // set it — `Config::validate_control_apps`, `call.handover(on_lost=…)`
            // and the `originate` verb — so it cannot reach here.
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

    /// The live connection that issued a command, so an adapter verb that
    /// *creates* a channel (`originate`) can register it to the same owner the
    /// command came in on — server-authoritative, never client-asserted, and
    /// the same exactly-one-owner rule every offered channel follows.
    /// `None` once the connection has gone (a command racing its own socket
    /// close), which the adapter answers `unavailable` rather than leaking an
    /// ownerless channel.
    pub fn connection_for_command(&self, app: &str, conn_id: u64) -> Option<Arc<ConnHandle>> {
        self.connection(app, conn_id)
    }

    /// Whether a channel id is already registered. Read by `originate` before
    /// it places anything on the wire so a caller-supplied id that collides is
    /// rejected as `conflict` — never silently re-pointed at a second call,
    /// which would strand the first.
    pub fn channel_exists(&self, channel_id: &str) -> bool {
        self.channels.contains_key(channel_id)
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
