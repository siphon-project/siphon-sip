//! Native JSON-over-TCP control client for the `siphon-rtp` media engine.
//!
//! `siphon-rtp` exposes a native control plane that is the strategic replacement
//! for the rtpengine NG/bencode UDP protocol: length-prefixed JSON frames over a
//! single persistent TCP connection, request/response correlation by a numeric
//! `id`, an optional shared-secret auth handshake, and **server-pushed events**
//! (DTMF, media-timeout) on the same connection.  The wire contract lives in the
//! [`siphon_rtp_proto`] crate (shared by both ends).
//!
//! This client mirrors the public method surface of
//! [`RtpEngineSet`](super::client::RtpEngineSet) so the two are interchangeable
//! behind [`MediaBackend`](super::backend::MediaBackend).  Decoded events are
//! forwarded onto the same `mpsc::Sender<RtpEngineEvent>` the rtpengine TCP
//! event listener feeds, so the dispatcher's DTMF consumer and the
//! `@rtpengine.on_dtmf` handlers work unchanged regardless of backend.
//!
//! Ownership note (3GPP-irrelevant, engine-specific): `siphon-rtp` keys call
//! ownership to the control connection's identity, so **all** commands for a
//! call must travel over one connection — hence a single multiplexed connection,
//! never a pool.  A control-connection reconnect changes that identity and
//! orphans pre-reconnect calls engine-side; that is an accepted v1 limitation.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use futures_util::future::join_all;
use siphon_rtp_proto::{
    frame, CmdResult, Command, Event, PlayEndReason, PlayMediaSource as ProtoPlayMediaSource,
    ProfileFlags, Request, Response,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, watch, Mutex};
use tracing::{debug, info, trace, warn};

use super::client::PlayMediaSource;
use super::error::RtpEngineError;
use super::events::{DtmfEvent, RtpEngineEvent};
use super::profile::NgFlags;

/// Reserved request id for the auth handshake (real requests start at 1).
const AUTH_REQUEST_ID: u64 = 0;
/// Initial reconnect backoff; doubles up to [`MAX_BACKOFF`].
const INITIAL_BACKOFF: Duration = Duration::from_millis(200);
/// Maximum reconnect backoff.
const MAX_BACKOFF: Duration = Duration::from_secs(5);
/// Read buffer chunk size for the control connection.
const READ_CHUNK: usize = 8192;

/// Convert siphon's [`NgFlags`] to the proto [`ProfileFlags`] (its JSON twin).
///
/// A field-for-field copy — the two structs carry identical media-handling
/// semantics; only the wire encoding (JSON vs bencode) differs.  A free
/// function rather than a `From` impl because both `From` and `ProfileFlags`
/// are foreign to this crate (orphan rule).
pub(crate) fn profile_flags_from_ng(flags: &NgFlags) -> ProfileFlags {
    ProfileFlags {
        transport_protocol: flags.transport_protocol.clone(),
        ice: flags.ice.clone(),
        dtls: flags.dtls.clone(),
        replace: flags.replace.clone(),
        flags: flags.flags.clone(),
        direction: flags.direction.clone(),
        record_call: flags.record_call,
        record_path: flags.record_path.clone(),
        // Proto fields siphon's NgFlags has no source for (address_family,
        // ws_uri, received_from, rtcp_mux). Default them: each carries
        // skip_serializing_if, so the emitted wire form is unchanged.
        ..ProfileFlags::default()
    }
}

/// Map siphon's [`PlayMediaSource`] to the proto variant.
fn proto_play_source(source: &PlayMediaSource) -> ProtoPlayMediaSource {
    match source {
        PlayMediaSource::File(path) => ProtoPlayMediaSource::File { path: path.clone() },
        PlayMediaSource::Blob(data) => ProtoPlayMediaSource::Blob { data: data.clone() },
        PlayMediaSource::DbId(id) => ProtoPlayMediaSource::DbId { id: *id },
    }
}

/// Completion signal for a blocking `play_media(wait=True)`: how the prompt ended
/// plus the actual played duration (from `Event::PlayFinished`).
type PlayWaiter = oneshot::Sender<(PlayEndReason, Option<u64>)>;

/// Native JSON-over-TCP control client for `siphon-rtp`.
pub struct SiphonRtpClient {
    /// Control endpoint (`siphon-rtp --control <addr>`).
    address: SocketAddr,
    /// Per-request response timeout.
    timeout_ms: u64,
    /// Fallback cap for a blocking `play_media(wait=True)` — how long to wait for
    /// the `Event::PlayFinished` before giving up (a prompt can be much longer
    /// than a control request, so this is separate from `timeout_ms`).
    play_timeout_ms: u64,
    /// Monotonic request id allocator (starts at 1; 0 is reserved for auth).
    next_id: AtomicU64,
    /// In-flight requests awaiting a response, keyed by request id.
    pending: Arc<DashMap<u64, oneshot::Sender<CmdResult>>>,
    /// Blocking `play_media` waiters keyed by the accept's `play_id`; resolved by
    /// the reader when the matching `Event::PlayFinished` arrives.
    play_pending: Arc<DashMap<u64, PlayWaiter>>,
    /// Write half of the live connection, swapped by the connection manager on
    /// (re)connect and cleared (`None`) while disconnected.
    writer: Arc<Mutex<Option<OwnedWriteHalf>>>,
    /// Connection state, set by the manager: `true` while a connection is
    /// established and (if a secret is configured) authenticated. A command
    /// waits on this — up to its timeout — so a request issued during the
    /// startup or post-reconnect window blocks for the connection rather than
    /// failing instantly.
    connected: watch::Receiver<bool>,
    /// Active call-ids (offer→insert, delete→remove) — mirrors `RtpEngineSet`'s
    /// affinity count for the `rtpengine.active_sessions` Python getter.
    sessions: DashMap<String, ()>,
    /// Dropped when the last `Arc<SiphonRtpClient>` is released, which makes the
    /// connection-manager task observe its receiver close and exit.
    _shutdown_tx: mpsc::Sender<()>,
}

impl SiphonRtpClient {
    /// Create a client and spawn the background connection manager.
    ///
    /// Returns immediately without waiting for the TCP connection: the manager
    /// connects (and re-authenticates) with backoff in the background, so siphon
    /// boots even when `siphon-rtp` is not yet up.  Commands issued while
    /// disconnected fail with a protocol/timeout error, exactly as rtpengine
    /// commands do when that daemon is down.
    pub fn new(
        address: SocketAddr,
        control_secret: Option<String>,
        timeout_ms: u64,
        play_timeout_ms: u64,
        event_tx: mpsc::Sender<RtpEngineEvent>,
    ) -> Arc<Self> {
        let pending: Arc<DashMap<u64, oneshot::Sender<CmdResult>>> = Arc::new(DashMap::new());
        let play_pending: Arc<DashMap<u64, PlayWaiter>> =
            Arc::new(DashMap::new());
        let writer: Arc<Mutex<Option<OwnedWriteHalf>>> = Arc::new(Mutex::new(None));
        let (connected_tx, connected_rx) = watch::channel(false);
        let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>(1);

        tokio::spawn(connection_manager(
            address,
            control_secret,
            timeout_ms,
            Arc::clone(&pending),
            Arc::clone(&play_pending),
            Arc::clone(&writer),
            connected_tx,
            event_tx,
            shutdown_rx,
        ));

        Arc::new(Self {
            address,
            timeout_ms,
            play_timeout_ms,
            next_id: AtomicU64::new(1),
            pending,
            play_pending,
            writer,
            connected: connected_rx,
            sessions: DashMap::new(),
            _shutdown_tx: shutdown_tx,
        })
    }

    /// Encode + send a command and await the correlated [`CmdResult`].
    ///
    /// Waits (up to `timeout_ms`) for an established connection before writing,
    /// so a command issued during the startup or post-reconnect window blocks
    /// for the connection instead of failing immediately. A genuinely
    /// unreachable engine surfaces as [`RtpEngineError::Timeout`].
    async fn request(&self, command: Command) -> Result<CmdResult, RtpEngineError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let bytes = frame::encode(&Request { id, command })
            .map_err(|error| RtpEngineError::Protocol(format!("frame encode failed: {error}")))?;

        let (sender, receiver) = oneshot::channel();
        self.pending.insert(id, sender);

        let outcome = tokio::time::timeout(
            Duration::from_millis(self.timeout_ms),
            self.send_and_wait(id, &bytes, receiver),
        )
        .await;

        match outcome {
            Ok(result) => result,
            Err(_) => {
                self.pending.remove(&id);
                Err(RtpEngineError::Timeout {
                    timeout_ms: self.timeout_ms,
                })
            }
        }
    }

    /// Wait for a connection, write the framed request, and await its response.
    /// Wrapped in the per-command timeout by [`Self::request`].
    async fn send_and_wait(
        &self,
        id: u64,
        bytes: &[u8],
        receiver: oneshot::Receiver<CmdResult>,
    ) -> Result<CmdResult, RtpEngineError> {
        let mut connected = self.connected.clone();
        loop {
            // Block until a connection is established (the manager sets `true`).
            while !*connected.borrow_and_update() {
                if connected.changed().await.is_err() {
                    self.pending.remove(&id);
                    return Err(RtpEngineError::Protocol(
                        "siphon-rtp client shutting down".to_string(),
                    ));
                }
            }
            // Connected: write under the connection lock. If the half is gone
            // (raced with a disconnect), loop and wait for the next connection.
            let mut guard = self.writer.lock().await;
            match guard.as_mut() {
                Some(write_half) => match write_half.write_all(bytes).await {
                    Ok(()) => break,
                    Err(error) => {
                        *guard = None;
                        self.pending.remove(&id);
                        return Err(RtpEngineError::Io(error));
                    }
                },
                None => continue,
            }
        }

        trace!(id, address = %self.address, "siphon-rtp command sent");
        receiver.await.map_err(|_| {
            RtpEngineError::Protocol(
                "siphon-rtp control connection closed before response".to_string(),
            )
        })
    }

    /// Send an `offer`, returning the rewritten SDP.
    pub async fn offer(
        &self,
        call_id: &str,
        from_tag: &str,
        sdp: &[u8],
        flags: &NgFlags,
    ) -> Result<Vec<u8>, RtpEngineError> {
        let result = self
            .request(Command::Offer {
                call_id: call_id.to_string(),
                from_tag: from_tag.to_string(),
                sdp: String::from_utf8_lossy(sdp).into_owned(),
                profile: profile_flags_from_ng(flags),
            })
            .await?;
        let rewritten = expect_sdp(result)?;
        self.sessions.insert(call_id.to_string(), ());
        Ok(rewritten)
    }

    /// Send an `answer`, returning the rewritten SDP.
    pub async fn answer(
        &self,
        call_id: &str,
        from_tag: &str,
        to_tag: &str,
        sdp: &[u8],
        flags: &NgFlags,
    ) -> Result<Vec<u8>, RtpEngineError> {
        let result = self
            .request(Command::Answer {
                call_id: call_id.to_string(),
                from_tag: from_tag.to_string(),
                to_tag: to_tag.to_string(),
                sdp: String::from_utf8_lossy(sdp).into_owned(),
                profile: profile_flags_from_ng(flags),
            })
            .await?;
        expect_sdp(result)
    }

    /// Send a `delete` to tear down a session and drop its active-session entry.
    pub async fn delete(&self, call_id: &str, from_tag: &str) -> Result<(), RtpEngineError> {
        let result = self
            .request(Command::Delete {
                call_id: call_id.to_string(),
                from_tag: from_tag.to_string(),
                to_tag: None,
            })
            .await;
        self.sessions.remove(call_id);
        expect_ok(result?)
    }

    /// Inject an audio prompt; returns the engine-reported duration in ms.
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_arguments)]
    pub async fn play_media(
        &self,
        call_id: &str,
        from_tag: &str,
        source: &PlayMediaSource,
        repeat_times: Option<u64>,
        start_pos_ms: Option<u64>,
        duration_ms: Option<u64>,
        to_tag: Option<&str>,
        wait: bool,
    ) -> Result<Option<u64>, RtpEngineError> {
        let result = self
            .request(Command::PlayMedia {
                call_id: call_id.to_string(),
                from_tag: from_tag.to_string(),
                source: proto_play_source(source),
                repeat_times,
                start_pos_ms,
                duration_ms,
                to_tag: to_tag.map(str::to_string),
            })
            .await?;
        // The accept is immediate (proto ≥0.1.2) and carries the play_id the
        // eventual Event::PlayFinished will echo.
        let (play_id, accept_duration) = match result {
            CmdResult::Ok {
                play_id,
                duration_ms,
                ..
            } => (play_id, duration_ms),
            other => return Err(unexpected_result("play media", other)),
        };

        // Fire-and-forget, or an engine that didn't assign a play_id: return on
        // accept, exactly as before.
        let (true, Some(play_id)) = (wait, play_id) else {
            return Ok(accept_duration);
        };

        // Block until the prompt ends. Register the waiter keyed by play_id (the
        // reader resolves it when PlayFinished arrives), bounded by the fallback
        // timeout so a lost event / dead engine can't hang the call. There is a
        // sub-millisecond race where PlayFinished could arrive before this insert
        // (vs a seconds-long prompt) — the fallback covers that pathological case.
        let (sender, receiver) = oneshot::channel::<(PlayEndReason, Option<u64>)>();
        self.play_pending.insert(play_id, sender);
        let deadline = Duration::from_millis(self.play_timeout_ms.max(1));
        match tokio::time::timeout(deadline, receiver).await {
            // Prompt played out in full.
            Ok(Ok((PlayEndReason::Completed, played_ms))) => Ok(played_ms.or(accept_duration)),
            // Ended early (stopped / superseded) — didn't play out; the script decides.
            Ok(Ok((PlayEndReason::Stopped | PlayEndReason::Superseded, _))) => Ok(None),
            // Engine reported an aborted playback.
            Ok(Ok((PlayEndReason::Error, _))) => {
                warn!(call_id, play_id, "siphon-rtp play_media aborted (engine error)");
                Ok(None)
            }
            // Connection dropped (sender cleared on disconnect) — treat as not completed.
            Ok(Err(_)) => {
                warn!(call_id, play_id, "siphon-rtp play_media: connection lost before completion");
                Ok(None)
            }
            // Fallback timeout — no PlayFinished within play_timeout_ms.
            Err(_) => {
                self.play_pending.remove(&play_id);
                warn!(
                    call_id,
                    play_id,
                    timeout_ms = self.play_timeout_ms,
                    "siphon-rtp play_media: no completion within fallback timeout"
                );
                Ok(None)
            }
        }
    }

    /// Stop any prompt playing on the monologue selected by `from_tag`.
    pub async fn stop_media(&self, call_id: &str, from_tag: &str) -> Result<(), RtpEngineError> {
        expect_ok(
            self.request(Command::StopMedia {
                call_id: call_id.to_string(),
                from_tag: from_tag.to_string(),
            })
            .await?,
        )
    }

    /// Inject DTMF (RFC 4733) toward the peer of the selected monologue.
    #[allow(clippy::too_many_arguments)]
    pub async fn play_dtmf(
        &self,
        call_id: &str,
        from_tag: &str,
        code: &str,
        duration_ms: Option<u64>,
        volume_dbm0: Option<i64>,
        pause_ms: Option<u64>,
        to_tag: Option<&str>,
    ) -> Result<(), RtpEngineError> {
        expect_ok(
            self.request(Command::PlayDtmf {
                call_id: call_id.to_string(),
                from_tag: from_tag.to_string(),
                code: code.to_string(),
                duration_ms,
                volume_dbm0,
                pause_ms,
                to_tag: to_tag.map(str::to_string),
            })
            .await?,
        )
    }

    /// Replace the selected monologue's outgoing audio with comfort silence.
    pub async fn silence_media(&self, call_id: &str, from_tag: &str) -> Result<(), RtpEngineError> {
        expect_ok(
            self.request(Command::SilenceMedia {
                call_id: call_id.to_string(),
                from_tag: from_tag.to_string(),
            })
            .await?,
        )
    }

    /// Resume forwarding original audio after [`Self::silence_media`].
    pub async fn unsilence_media(
        &self,
        call_id: &str,
        from_tag: &str,
    ) -> Result<(), RtpEngineError> {
        expect_ok(
            self.request(Command::UnsilenceMedia {
                call_id: call_id.to_string(),
                from_tag: from_tag.to_string(),
            })
            .await?,
        )
    }

    /// Echo-test mode: the engine reflects a leg's ingress audio back to itself
    /// (single-leg IVR echo). `enabled=false` stops it. siphon-rtp promotes a
    /// plain relay to a processing MediaCall automatically; DTMF and
    /// media-timeout events still fire while echoing.
    pub async fn echo(
        &self,
        call_id: &str,
        from_tag: &str,
        enabled: bool,
    ) -> Result<(), RtpEngineError> {
        expect_ok(
            self.request(Command::Echo {
                call_id: call_id.to_string(),
                from_tag: from_tag.to_string(),
                to_tag: None,
                enabled,
            })
            .await?,
        )
    }

    /// Drop the selected monologue's outgoing packets entirely.
    pub async fn block_media(&self, call_id: &str, from_tag: &str) -> Result<(), RtpEngineError> {
        expect_ok(
            self.request(Command::BlockMedia {
                call_id: call_id.to_string(),
                from_tag: from_tag.to_string(),
            })
            .await?,
        )
    }

    /// Resume forwarding after [`Self::block_media`].
    pub async fn unblock_media(&self, call_id: &str, from_tag: &str) -> Result<(), RtpEngineError> {
        expect_ok(
            self.request(Command::UnblockMedia {
                call_id: call_id.to_string(),
                from_tag: from_tag.to_string(),
            })
            .await?,
        )
    }

    /// Create a media subscription, returning the subscriber SDP.
    ///
    /// `siphon-rtp` does not yet implement subscriptions; this surfaces the
    /// engine's `Error` as [`RtpEngineError::EngineError`] (SIPREC/MPTY are
    /// unsupported on this backend until the engine adds them).
    pub async fn subscribe_request(
        &self,
        call_id: &str,
        from_tag: &str,
        _to_tag: &str,
        sdp: Option<&[u8]>,
        flags: &NgFlags,
    ) -> Result<Vec<u8>, RtpEngineError> {
        let result = self
            .request(Command::SubscribeRequest {
                call_id: call_id.to_string(),
                from_tags: vec![from_tag.to_string()],
                sdp: sdp.map(|bytes| String::from_utf8_lossy(bytes).into_owned()),
                profile: profile_flags_from_ng(flags),
            })
            .await?;
        expect_sdp(result)
    }

    /// SIPREC-mode subscription over both call directions; returns `(sdp, to_tag)`.
    /// Unsupported on `siphon-rtp` today — surfaces the engine `Error`.
    pub async fn subscribe_request_siprec(
        &self,
        call_id: &str,
        from_tags: &[&str],
        profile_flags: Option<&NgFlags>,
    ) -> Result<(Vec<u8>, String), RtpEngineError> {
        let result = self
            .request(Command::SubscribeRequest {
                call_id: call_id.to_string(),
                from_tags: from_tags.iter().map(|tag| tag.to_string()).collect(),
                sdp: None,
                profile: profile_flags
                    .map(profile_flags_from_ng)
                    .unwrap_or_default(),
            })
            .await?;
        match result {
            CmdResult::Ok {
                sdp: Some(sdp),
                to_tag,
                ..
            } => Ok((sdp.into_bytes(), to_tag.unwrap_or_default())),
            CmdResult::Ok { sdp: None, .. } => Err(RtpEngineError::Protocol(
                "siphon-rtp subscribe response missing 'sdp'".to_string(),
            )),
            other => Err(unexpected_result("subscribe request", other)),
        }
    }

    /// Complete a subscription's SDP negotiation; SDP in the response is optional.
    pub async fn subscribe_answer(
        &self,
        call_id: &str,
        from_tag: &str,
        to_tag: &str,
        sdp: &[u8],
        flags: &NgFlags,
    ) -> Result<Vec<u8>, RtpEngineError> {
        let result = self
            .request(Command::SubscribeAnswer {
                call_id: call_id.to_string(),
                from_tag: from_tag.to_string(),
                to_tag: to_tag.to_string(),
                sdp: String::from_utf8_lossy(sdp).into_owned(),
                profile: profile_flags_from_ng(flags),
            })
            .await?;
        match result {
            CmdResult::Ok { sdp, .. } => Ok(sdp.map(String::into_bytes).unwrap_or_default()),
            other => Err(unexpected_result("subscribe answer", other)),
        }
    }

    /// Tear down a subscription.
    pub async fn unsubscribe(
        &self,
        call_id: &str,
        from_tag: &str,
        to_tag: &str,
    ) -> Result<(), RtpEngineError> {
        expect_ok(
            self.request(Command::Unsubscribe {
                call_id: call_id.to_string(),
                from_tag: from_tag.to_string(),
                to_tag: to_tag.to_string(),
            })
            .await?,
        )
    }

    /// Liveness check — `Ping` → `Pong`.
    pub async fn ping(&self) -> Result<(), RtpEngineError> {
        match self.request(Command::Ping).await? {
            CmdResult::Pong => Ok(()),
            CmdResult::Error { reason } => Err(RtpEngineError::EngineError(reason)),
            other => Err(RtpEngineError::Protocol(format!(
                "expected 'pong', got '{}'",
                result_kind(&other)
            ))),
        }
    }

    /// Probe health: a single-element vec `(address, healthy)` so the result is
    /// shaped like `RtpEngineSet::health_check`.
    pub async fn health_check(&self) -> Vec<(SocketAddr, bool)> {
        vec![(self.address, self.ping().await.is_ok())]
    }

    /// Control endpoint this client connects to.
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// Number of active call-ids (offer without a matching delete).
    pub fn active_sessions(&self) -> usize {
        self.sessions.len()
    }

    /// Always 1 — a native client drives a single engine connection.
    pub fn instance_count(&self) -> usize {
        1
    }

    /// The single control endpoint, shaped like `RtpEngineSet::instance_addresses`.
    pub fn instance_addresses(&self) -> Vec<SocketAddr> {
        vec![self.address]
    }
}

/// A set of `siphon-rtp` control connections for HA / load-balancing.
///
/// Mirrors [`RtpEngineSet`](super::client::RtpEngineSet): weighted round-robin
/// instance selection with per-call-id affinity, so every command for a call
/// goes to the same connection (siphon-rtp keys call ownership to the control
/// connection — splitting a call across connections would break `delete`).
/// The shared `control_secret` authenticates every connection; events from all
/// instances feed the one `event_tx`.
pub struct SiphonRtpClientSet {
    clients: Vec<Arc<SiphonRtpClient>>,
    /// Cumulative weights for weighted selection.
    cumulative_weights: Vec<u32>,
    total_weight: u32,
    /// Atomic counter for round-robin.
    counter: AtomicU64,
    /// Call-ID → client index affinity.
    affinity: DashMap<String, usize>,
}

impl SiphonRtpClientSet {
    /// Build a set from `(address, timeout_ms, weight)` triples, spawning one
    /// connection manager per instance. Returns an error only when `instances`
    /// is empty (each client connects lazily in the background).
    pub fn new(
        instances: Vec<(SocketAddr, u64, u32)>,
        control_secret: Option<String>,
        play_timeout_ms: u64,
        event_tx: mpsc::Sender<RtpEngineEvent>,
    ) -> Result<Arc<Self>, RtpEngineError> {
        if instances.is_empty() {
            return Err(RtpEngineError::Protocol(
                "at least one siphon-rtp instance is required".to_string(),
            ));
        }

        let mut clients = Vec::with_capacity(instances.len());
        let mut cumulative_weights = Vec::with_capacity(instances.len());
        let mut running_total = 0u32;
        for (address, timeout_ms, weight) in &instances {
            clients.push(SiphonRtpClient::new(
                *address,
                control_secret.clone(),
                *timeout_ms,
                play_timeout_ms,
                event_tx.clone(),
            ));
            running_total += weight;
            cumulative_weights.push(running_total);
        }

        Ok(Arc::new(Self {
            clients,
            cumulative_weights,
            total_weight: running_total,
            counter: AtomicU64::new(0),
            affinity: DashMap::new(),
        }))
    }

    /// Select a client by call-id affinity or weighted round-robin.
    fn select(&self, call_id: &str) -> &Arc<SiphonRtpClient> {
        if self.clients.len() == 1 {
            return &self.clients[0];
        }
        if let Some(index) = self.affinity.get(call_id) {
            return &self.clients[*index];
        }
        let tick = self.counter.fetch_add(1, Ordering::Relaxed);
        let position = (tick % self.total_weight as u64) as u32;
        let index = self
            .cumulative_weights
            .iter()
            .position(|&cumulative| position < cumulative)
            .unwrap_or(0);
        &self.clients[index]
    }

    /// Record call-id affinity after the first command (multi-instance only).
    fn bind_affinity(&self, call_id: &str) {
        if self.clients.len() <= 1 || self.affinity.contains_key(call_id) {
            return;
        }
        let tick = self
            .counter
            .load(Ordering::Relaxed)
            .wrapping_sub(1);
        let position = (tick % self.total_weight as u64) as u32;
        let index = self
            .cumulative_weights
            .iter()
            .position(|&cumulative| position < cumulative)
            .unwrap_or(0);
        self.affinity.insert(call_id.to_string(), index);
    }

    /// Send an `offer`, binding call-id affinity to the selected instance.
    pub async fn offer(
        &self,
        call_id: &str,
        from_tag: &str,
        sdp: &[u8],
        flags: &NgFlags,
    ) -> Result<Vec<u8>, RtpEngineError> {
        let result = self.select(call_id).offer(call_id, from_tag, sdp, flags).await?;
        self.bind_affinity(call_id);
        Ok(result)
    }

    /// Send an `answer` to the affinity-bound instance.
    pub async fn answer(
        &self,
        call_id: &str,
        from_tag: &str,
        to_tag: &str,
        sdp: &[u8],
        flags: &NgFlags,
    ) -> Result<Vec<u8>, RtpEngineError> {
        self.select(call_id)
            .answer(call_id, from_tag, to_tag, sdp, flags)
            .await
    }

    /// Send a `delete` and drop affinity.
    pub async fn delete(&self, call_id: &str, from_tag: &str) -> Result<(), RtpEngineError> {
        let result = self.select(call_id).delete(call_id, from_tag).await;
        self.affinity.remove(call_id);
        result
    }

    /// Inject an audio prompt via the affinity-bound instance.
    #[allow(clippy::too_many_arguments)]
    pub async fn play_media(
        &self,
        call_id: &str,
        from_tag: &str,
        source: &PlayMediaSource,
        repeat_times: Option<u64>,
        start_pos_ms: Option<u64>,
        duration_ms: Option<u64>,
        to_tag: Option<&str>,
        wait: bool,
    ) -> Result<Option<u64>, RtpEngineError> {
        self.select(call_id)
            .play_media(
                call_id,
                from_tag,
                source,
                repeat_times,
                start_pos_ms,
                duration_ms,
                to_tag,
                wait,
            )
            .await
    }

    /// Stop a prompt via the affinity-bound instance.
    pub async fn stop_media(&self, call_id: &str, from_tag: &str) -> Result<(), RtpEngineError> {
        self.select(call_id).stop_media(call_id, from_tag).await
    }

    /// Inject DTMF via the affinity-bound instance.
    #[allow(clippy::too_many_arguments)]
    pub async fn play_dtmf(
        &self,
        call_id: &str,
        from_tag: &str,
        code: &str,
        duration_ms: Option<u64>,
        volume_dbm0: Option<i64>,
        pause_ms: Option<u64>,
        to_tag: Option<&str>,
    ) -> Result<(), RtpEngineError> {
        self.select(call_id)
            .play_dtmf(call_id, from_tag, code, duration_ms, volume_dbm0, pause_ms, to_tag)
            .await
    }

    /// Silence egress on the affinity-bound instance.
    pub async fn silence_media(&self, call_id: &str, from_tag: &str) -> Result<(), RtpEngineError> {
        self.select(call_id).silence_media(call_id, from_tag).await
    }

    /// Resume egress on the affinity-bound instance.
    pub async fn unsilence_media(
        &self,
        call_id: &str,
        from_tag: &str,
    ) -> Result<(), RtpEngineError> {
        self.select(call_id).unsilence_media(call_id, from_tag).await
    }

    /// Toggle echo-test mode on the affinity-bound instance.
    pub async fn echo(
        &self,
        call_id: &str,
        from_tag: &str,
        enabled: bool,
    ) -> Result<(), RtpEngineError> {
        self.select(call_id).echo(call_id, from_tag, enabled).await
    }

    /// Block egress on the affinity-bound instance.
    pub async fn block_media(&self, call_id: &str, from_tag: &str) -> Result<(), RtpEngineError> {
        self.select(call_id).block_media(call_id, from_tag).await
    }

    /// Resume egress on the affinity-bound instance.
    pub async fn unblock_media(&self, call_id: &str, from_tag: &str) -> Result<(), RtpEngineError> {
        self.select(call_id).unblock_media(call_id, from_tag).await
    }

    /// Create a subscription via the affinity-bound instance.
    pub async fn subscribe_request(
        &self,
        call_id: &str,
        from_tag: &str,
        to_tag: &str,
        sdp: Option<&[u8]>,
        flags: &NgFlags,
    ) -> Result<Vec<u8>, RtpEngineError> {
        self.select(call_id)
            .subscribe_request(call_id, from_tag, to_tag, sdp, flags)
            .await
    }

    /// SIPREC-mode subscription via the affinity-bound instance.
    pub async fn subscribe_request_siprec(
        &self,
        call_id: &str,
        from_tags: &[&str],
        profile_flags: Option<&NgFlags>,
    ) -> Result<(Vec<u8>, String), RtpEngineError> {
        self.select(call_id)
            .subscribe_request_siprec(call_id, from_tags, profile_flags)
            .await
    }

    /// Complete a subscription's SDP negotiation via the affinity-bound instance.
    pub async fn subscribe_answer(
        &self,
        call_id: &str,
        from_tag: &str,
        to_tag: &str,
        sdp: &[u8],
        flags: &NgFlags,
    ) -> Result<Vec<u8>, RtpEngineError> {
        self.select(call_id)
            .subscribe_answer(call_id, from_tag, to_tag, sdp, flags)
            .await
    }

    /// Tear down a subscription via the affinity-bound instance.
    pub async fn unsubscribe(
        &self,
        call_id: &str,
        from_tag: &str,
        to_tag: &str,
    ) -> Result<(), RtpEngineError> {
        self.select(call_id).unsubscribe(call_id, from_tag, to_tag).await
    }

    /// Ping any one instance (the first). For quick health checks.
    pub async fn ping(&self) -> Result<(), RtpEngineError> {
        match self.clients.first() {
            Some(client) => client.ping().await,
            None => Err(RtpEngineError::Protocol(
                "no siphon-rtp instances".to_string(),
            )),
        }
    }

    /// Ping every instance in parallel and return per-instance health status.
    pub async fn health_check(&self) -> Vec<(SocketAddr, bool)> {
        let probes = self
            .clients
            .iter()
            .map(|client| async move { (client.address(), client.ping().await.is_ok()) });
        join_all(probes).await
    }

    /// Total active call-ids across all instances.
    pub fn active_sessions(&self) -> usize {
        self.clients.iter().map(|client| client.active_sessions()).sum()
    }

    /// Number of configured instances.
    pub fn instance_count(&self) -> usize {
        self.clients.len()
    }

    /// Addresses of every configured instance, in registration order.
    pub fn instance_addresses(&self) -> Vec<SocketAddr> {
        self.clients.iter().map(|client| client.address()).collect()
    }
}

/// Interpret a result that must carry rewritten SDP (offer/answer/subscribe req).
fn expect_sdp(result: CmdResult) -> Result<Vec<u8>, RtpEngineError> {
    match result {
        CmdResult::Ok { sdp: Some(sdp), .. } => Ok(sdp.into_bytes()),
        CmdResult::Ok { sdp: None, .. } => Err(RtpEngineError::Protocol(
            "siphon-rtp response missing 'sdp'".to_string(),
        )),
        other => Err(unexpected_result("sdp command", other)),
    }
}

/// Interpret a result for a command that returns only success/failure.
fn expect_ok(result: CmdResult) -> Result<(), RtpEngineError> {
    match result {
        CmdResult::Ok { .. } => Ok(()),
        other => Err(unexpected_result("command", other)),
    }
}

/// Map a non-`Ok` result to the appropriate [`RtpEngineError`].
fn unexpected_result(context: &str, result: CmdResult) -> RtpEngineError {
    match result {
        CmdResult::Error { reason } => RtpEngineError::EngineError(reason),
        CmdResult::Pong => {
            RtpEngineError::Protocol(format!("unexpected 'pong' response to {context}"))
        }
        CmdResult::Ok { .. } => {
            RtpEngineError::Protocol(format!("unexpected 'ok' response to {context}"))
        }
        // Results for cluster/stats/query commands siphon never issues on this
        // control connection (List/Statistics/Load/NodeInfo/Checkpoint). Seeing
        // one is a protocol violation, not a stub — treat it as such.
        other => RtpEngineError::Protocol(format!(
            "unexpected '{}' response to {context}",
            result_kind(&other)
        )),
    }
}

/// A short, stable tag for a [`CmdResult`] variant, for error messages.
fn result_kind(result: &CmdResult) -> &'static str {
    match result {
        CmdResult::Ok { .. } => "ok",
        CmdResult::Error { .. } => "error",
        CmdResult::Pong => "pong",
        CmdResult::List { .. } => "list",
        CmdResult::Statistics { .. } => "statistics",
        CmdResult::Load { .. } => "load",
        CmdResult::NodeInfo { .. } => "node_info",
        CmdResult::Checkpoint { .. } => "checkpoint",
    }
}

/// Convert a proto [`Event`] to siphon's [`RtpEngineEvent`].
///
/// `Event::Dtmf` is a field-for-field twin of [`DtmfEvent`]; `MediaTimeout`
/// maps to the dedicated variant. The conference/quality events
/// (`ActiveSpeaker`, `CallQuality`) are not modelled by a typed handler yet, so
/// they surface through `Unknown` (logged, not dropped) carrying their stream
/// identifiers — a typed Python handler is a follow-up.
fn convert_event(event: Event) -> RtpEngineEvent {
    match event {
        Event::Dtmf {
            call_id,
            from_tag,
            to_tag,
            digit,
            duration_ms,
            volume,
            source,
        } => RtpEngineEvent::Dtmf(DtmfEvent {
            call_id,
            from_tag,
            to_tag,
            digit,
            duration_ms,
            volume,
            source,
        }),
        Event::MediaTimeout { call_id, from_tag } => RtpEngineEvent::MediaTimeout {
            call_id,
            from_tag,
        },
        Event::ActiveSpeaker {
            conference_id,
            from_tag,
        } => RtpEngineEvent::Unknown {
            event: "active_speaker".to_string(),
            call_id: Some(conference_id),
            from_tag,
        },
        Event::CallQuality {
            conference_id,
            call_id,
            from_tag,
            ..
        } => RtpEngineEvent::Unknown {
            event: "call_quality".to_string(),
            call_id: call_id.or(conference_id),
            from_tag: Some(from_tag),
        },
        // Intercepted by route_frame before it reaches here (resolves a blocking
        // play_media). Mapped defensively so the match stays exhaustive and
        // non-panicking if that ordering ever changes.
        Event::PlayFinished {
            call_id, from_tag, ..
        } => RtpEngineEvent::Unknown {
            event: "play_finished".to_string(),
            call_id: Some(call_id),
            from_tag: Some(from_tag),
        },
        Event::Unknown => RtpEngineEvent::Unknown {
            event: "unknown".to_string(),
            call_id: None,
            from_tag: None,
        },
    }
}

/// Background task: maintain the control connection, route responses/events, and
/// reconnect (with backoff + re-auth) until the client is dropped.
#[allow(clippy::too_many_arguments)]
async fn connection_manager(
    address: SocketAddr,
    control_secret: Option<String>,
    timeout_ms: u64,
    pending: Arc<DashMap<u64, oneshot::Sender<CmdResult>>>,
    play_pending: Arc<DashMap<u64, PlayWaiter>>,
    writer: Arc<Mutex<Option<OwnedWriteHalf>>>,
    connected_tx: watch::Sender<bool>,
    event_tx: mpsc::Sender<RtpEngineEvent>,
    mut shutdown_rx: mpsc::Receiver<()>,
) {
    let mut backoff = INITIAL_BACKOFF;
    loop {
        // Connect, cancellable by client shutdown.
        let stream = tokio::select! {
            biased;
            _ = shutdown_rx.recv() => return,
            result = TcpStream::connect(address) => match result {
                Ok(stream) => stream,
                Err(error) => {
                    warn!(%address, %error, "siphon-rtp control connect failed; retrying");
                    if sleep_or_shutdown(backoff, &mut shutdown_rx).await {
                        return;
                    }
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                    continue;
                }
            },
        };
        let _ = stream.set_nodelay(true);
        backoff = INITIAL_BACKOFF;
        let (mut read_half, mut write_half) = stream.into_split();
        let mut buffer: Vec<u8> = Vec::with_capacity(READ_CHUNK);

        // Auth handshake (before publishing the writer, so concurrent commands
        // fail fast until the connection is authenticated and ready).
        if let Some(token) = &control_secret {
            match authenticate(
                &mut write_half,
                &mut read_half,
                &mut buffer,
                token,
                timeout_ms,
            )
            .await
            {
                Ok(()) => {}
                Err(error) => {
                    warn!(%address, %error, "siphon-rtp control auth failed; retrying");
                    if sleep_or_shutdown(backoff, &mut shutdown_rx).await {
                        return;
                    }
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                    continue;
                }
            }
        }

        *writer.lock().await = Some(write_half);
        let _ = connected_tx.send(true);
        info!(%address, "siphon-rtp control connection established");

        let outcome = read_loop(
            &mut read_half,
            &mut buffer,
            &pending,
            &play_pending,
            &event_tx,
            &mut shutdown_rx,
        )
        .await;

        // Connection is gone: stop accepting commands and fail every in-flight
        // request (dropping the senders makes their receivers resolve to Err).
        // Blocking play_media waiters likewise unblock (dropped sender → Err →
        // treated as not-completed) instead of hanging until the fallback.
        let _ = connected_tx.send(false);
        *writer.lock().await = None;
        pending.clear();
        play_pending.clear();

        match outcome {
            ReadOutcome::Shutdown => return,
            ReadOutcome::Disconnected => {
                warn!(%address, "siphon-rtp control disconnected; reconnecting");
                if sleep_or_shutdown(backoff, &mut shutdown_rx).await {
                    return;
                }
            }
        }
    }
}

/// Why [`read_loop`] returned.
enum ReadOutcome {
    /// The client was dropped — stop the manager entirely.
    Shutdown,
    /// The connection closed or errored — reconnect.
    Disconnected,
}

/// Drive the read half: decode frames, route responses to pending requests and
/// events onto `event_tx`, until shutdown or disconnect.
async fn read_loop(
    read_half: &mut OwnedReadHalf,
    buffer: &mut Vec<u8>,
    pending: &DashMap<u64, oneshot::Sender<CmdResult>>,
    play_pending: &DashMap<u64, PlayWaiter>,
    event_tx: &mpsc::Sender<RtpEngineEvent>,
    shutdown_rx: &mut mpsc::Receiver<()>,
) -> ReadOutcome {
    let mut chunk = [0u8; READ_CHUNK];
    loop {
        // Drain any whole frames already buffered (e.g. left over from auth).
        loop {
            match frame::decode::<serde_json::Value>(buffer) {
                Ok(Some((value, consumed))) => {
                    buffer.drain(..consumed);
                    route_frame(value, pending, play_pending, event_tx).await;
                }
                Ok(None) => break,
                Err(error) => {
                    warn!(%error, "siphon-rtp control frame decode failed; dropping connection");
                    return ReadOutcome::Disconnected;
                }
            }
        }

        tokio::select! {
            biased;
            _ = shutdown_rx.recv() => return ReadOutcome::Shutdown,
            result = read_half.read(&mut chunk) => match result {
                Ok(0) => return ReadOutcome::Disconnected,
                Ok(n) => buffer.extend_from_slice(&chunk[..n]),
                Err(error) => {
                    warn!(%error, "siphon-rtp control read error");
                    return ReadOutcome::Disconnected;
                }
            },
        }
    }
}

/// Route one decoded JSON frame: a `Response` (has `id`) to its pending request,
/// or an `Event` (has `event`) onto the event channel.
async fn route_frame(
    value: serde_json::Value,
    pending: &DashMap<u64, oneshot::Sender<CmdResult>>,
    play_pending: &DashMap<u64, PlayWaiter>,
    event_tx: &mpsc::Sender<RtpEngineEvent>,
) {
    if value.get("event").is_some() {
        match serde_json::from_value::<Event>(value) {
            Ok(Event::PlayFinished { play_id, reason, played_ms, .. }) => {
                // Internal correlation for a blocking play_media(wait=True): hand
                // the reason + played duration to the waiting call. No waiter
                // means a wait=False play (or a lost accept/register race, covered
                // by the play fallback timeout) — drop it, don't surface it as an
                // event.
                debug!(play_id, ?reason, played_ms, "siphon-rtp play finished");
                if let Some((_, sender)) = play_pending.remove(&play_id) {
                    let _ = sender.send((reason, played_ms));
                }
            }
            Ok(event) => {
                let converted = convert_event(event);
                debug!(?converted, "siphon-rtp event received");
                // Best-effort: a dropped receiver just means no DTMF consumer.
                let _ = event_tx.send(converted).await;
            }
            Err(error) => warn!(%error, "siphon-rtp event decode failed; skipping"),
        }
    } else if value.get("id").is_some() {
        match serde_json::from_value::<Response>(value) {
            Ok(response) => {
                if let Some((_, sender)) = pending.remove(&response.id) {
                    let _ = sender.send(response.result);
                } else {
                    trace!(id = response.id, "siphon-rtp response for unknown/expired request");
                }
            }
            Err(error) => warn!(%error, "siphon-rtp response decode failed; skipping"),
        }
    } else {
        warn!("siphon-rtp frame had neither 'id' nor 'event'; skipping");
    }
}

/// Perform the shared-secret auth handshake on a fresh connection.
async fn authenticate(
    write_half: &mut OwnedWriteHalf,
    read_half: &mut OwnedReadHalf,
    buffer: &mut Vec<u8>,
    token: &str,
    timeout_ms: u64,
) -> Result<(), RtpEngineError> {
    let bytes = frame::encode(&Request {
        id: AUTH_REQUEST_ID,
        command: Command::Authenticate {
            token: token.to_string(),
        },
    })
    .map_err(|error| RtpEngineError::Protocol(format!("auth frame encode failed: {error}")))?;
    write_half.write_all(&bytes).await?;

    let mut chunk = [0u8; READ_CHUNK];
    let deadline = Duration::from_millis(timeout_ms.max(1));
    tokio::time::timeout(deadline, async {
        loop {
            // Consume buffered frames first; the auth ack is the Response with the
            // reserved id. Any events arriving first are ignored during handshake.
            loop {
                match frame::decode::<serde_json::Value>(buffer) {
                    Ok(Some((value, consumed))) => {
                        buffer.drain(..consumed);
                        if value.get("id").and_then(serde_json::Value::as_u64)
                            == Some(AUTH_REQUEST_ID)
                        {
                            let response: Response = serde_json::from_value(value).map_err(
                                |error| {
                                    RtpEngineError::Protocol(format!(
                                        "auth response decode failed: {error}"
                                    ))
                                },
                            )?;
                            return match response.result {
                                CmdResult::Ok { .. } => Ok(()),
                                CmdResult::Error { reason } => {
                                    Err(RtpEngineError::EngineError(reason))
                                }
                                other => Err(RtpEngineError::Protocol(format!(
                                    "unexpected '{}' response for authenticate",
                                    result_kind(&other)
                                ))),
                            };
                        }
                    }
                    Ok(None) => break,
                    Err(error) => {
                        return Err(RtpEngineError::Protocol(format!(
                            "auth frame decode failed: {error}"
                        )))
                    }
                }
            }
            let n = read_half.read(&mut chunk).await?;
            if n == 0 {
                return Err(RtpEngineError::Protocol(
                    "siphon-rtp closed connection during auth".to_string(),
                ));
            }
            buffer.extend_from_slice(&chunk[..n]);
        }
    })
    .await
    .map_err(|_| RtpEngineError::Timeout {
        timeout_ms: deadline.as_millis() as u64,
    })?
}

/// Sleep for `duration`, returning `true` if a shutdown signal arrived first.
async fn sleep_or_shutdown(duration: Duration, shutdown_rx: &mut mpsc::Receiver<()>) -> bool {
    tokio::select! {
        biased;
        _ = shutdown_rx.recv() => true,
        _ = tokio::time::sleep(duration) => false,
    }
}

// ---------------------------------------------------------------------------
// Tests — exercise the client against an in-process fake engine that speaks the
// real `siphon_rtp_proto` wire format (no external binary needed).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use siphon_rtp_proto::SessionStats;
    use tokio::net::TcpListener;

    /// Read exactly one framed value of type `T` off a stream, growing `buffer`.
    async fn read_frame<T, S>(stream: &mut S, buffer: &mut Vec<u8>) -> T
    where
        T: serde::de::DeserializeOwned,
        S: AsyncReadExt + Unpin,
    {
        let mut chunk = [0u8; 4096];
        loop {
            if let Some((value, consumed)) = frame::decode::<T>(buffer).expect("decode") {
                buffer.drain(..consumed);
                return value;
            }
            let n = stream.read(&mut chunk).await.expect("read");
            assert_ne!(n, 0, "stream closed before a full frame arrived");
            buffer.extend_from_slice(&chunk[..n]);
        }
    }

    /// Like [`read_frame`] but returns `None` on EOF instead of panicking — for
    /// server loops that should exit cleanly when the client disconnects.
    async fn read_frame_opt<T, S>(stream: &mut S, buffer: &mut Vec<u8>) -> Option<T>
    where
        T: serde::de::DeserializeOwned,
        S: AsyncReadExt + Unpin,
    {
        let mut chunk = [0u8; 4096];
        loop {
            if let Some((value, consumed)) = frame::decode::<T>(buffer).expect("decode") {
                buffer.drain(..consumed);
                return Some(value);
            }
            let n = stream.read(&mut chunk).await.ok()?;
            if n == 0 {
                return None;
            }
            buffer.extend_from_slice(&chunk[..n]);
        }
    }

    async fn write_frame<T: serde::Serialize, S: AsyncWriteExt + Unpin>(stream: &mut S, value: &T) {
        let bytes = frame::encode(value).expect("encode");
        stream.write_all(&bytes).await.expect("write");
    }

    /// A fake engine answering Offer/Answer with Ok+SDP, Ping with Pong, and
    /// everything else with bare Ok — for as many connections as arrive.
    async fn spawn_offer_server() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => return,
                };
                tokio::spawn(async move {
                    let mut buffer = Vec::new();
                    while let Some(request) = read_frame_opt::<Request, _>(&mut stream, &mut buffer).await {
                        let result = match request.command {
                            Command::Ping => CmdResult::Pong,
                            Command::Offer { .. } | Command::Answer { .. } => CmdResult::Ok {
                                sdp: Some("v=0\r\nc=IN IP4 203.0.113.1\r\n".to_string()),
                                duration_ms: None,
                                to_tag: None,
                                stats: None,
                                play_id: None,
                            },
                            _ => CmdResult::Ok {
                                sdp: None,
                                duration_ms: None,
                                to_tag: None,
                                stats: None,
                                play_id: None,
                            },
                        };
                        write_frame(
                            &mut stream,
                            &Response {
                                id: request.id,
                                result,
                            },
                        )
                        .await;
                    }
                });
            }
        });
        address
    }

    fn channel() -> (
        mpsc::Sender<RtpEngineEvent>,
        mpsc::Receiver<RtpEngineEvent>,
    ) {
        mpsc::channel(16)
    }

    #[test]
    fn profile_flags_from_ng_maps_every_field() {
        let ng = NgFlags {
            transport_protocol: Some("RTP/SAVPF".into()),
            ice: Some("force".into()),
            dtls: Some("passive".into()),
            replace: vec!["origin".into()],
            flags: vec!["trust-address".into(), "symmetric".into()],
            direction: vec!["external".into(), "internal".into()],
            record_call: true,
            record_path: Some("/var/spool".into()),
        };
        let proto = profile_flags_from_ng(&ng);
        assert_eq!(proto.transport_protocol.as_deref(), Some("RTP/SAVPF"));
        assert_eq!(proto.ice.as_deref(), Some("force"));
        assert_eq!(proto.dtls.as_deref(), Some("passive"));
        assert_eq!(proto.replace, vec!["origin".to_string()]);
        assert_eq!(proto.flags, vec!["trust-address".to_string(), "symmetric".to_string()]);
        assert_eq!(proto.direction, vec!["external".to_string(), "internal".to_string()]);
        assert!(proto.record_call);
        assert_eq!(proto.record_path.as_deref(), Some("/var/spool"));
    }

    #[test]
    fn convert_event_dtmf_is_field_exact() {
        let event = Event::Dtmf {
            call_id: "c".into(),
            from_tag: "f".into(),
            to_tag: Some("t".into()),
            digit: "5".into(),
            duration_ms: 120,
            volume: -8,
            source: Some("rtp".into()),
        };
        match convert_event(event) {
            RtpEngineEvent::Dtmf(dtmf) => {
                assert_eq!(dtmf.call_id, "c");
                assert_eq!(dtmf.from_tag, "f");
                assert_eq!(dtmf.to_tag.as_deref(), Some("t"));
                assert_eq!(dtmf.digit, "5");
                assert_eq!(dtmf.duration_ms, 120);
                assert_eq!(dtmf.volume, -8);
                assert_eq!(dtmf.source.as_deref(), Some("rtp"));
            }
            other => panic!("expected Dtmf, got {other:?}"),
        }
    }

    #[test]
    fn convert_event_media_timeout() {
        match convert_event(Event::MediaTimeout {
            call_id: "c".into(),
            from_tag: "f".into(),
        }) {
            RtpEngineEvent::MediaTimeout { call_id, from_tag } => {
                assert_eq!(call_id, "c");
                assert_eq!(from_tag, "f");
            }
            other => panic!("expected MediaTimeout, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn offer_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = Vec::new();
            let request: Request = read_frame(&mut stream, &mut buffer).await;
            assert_eq!(request.id, 1);
            match request.command {
                Command::Offer {
                    call_id,
                    profile,
                    ..
                } => {
                    assert_eq!(call_id, "call-1");
                    assert_eq!(profile.transport_protocol.as_deref(), Some("RTP/SAVP"));
                }
                other => panic!("expected Offer, got {other:?}"),
            }
            write_frame(
                &mut stream,
                &Response {
                    id: 1,
                    result: CmdResult::Ok {
                        sdp: Some("v=0\r\nc=IN IP4 203.0.113.1\r\n".into()),
                        duration_ms: None,
                        to_tag: None,
                        stats: None,
                        play_id: None,
                    },
                },
            )
            .await;
            // Keep the connection open so the client doesn't see EOF.
            tokio::time::sleep(Duration::from_millis(200)).await;
        });

        let (event_tx, _event_rx) = channel();
        let client = SiphonRtpClient::new(address, None, 2000, 5_000, event_tx);
        let flags = NgFlags {
            transport_protocol: Some("RTP/SAVP".into()),
            ..NgFlags::default()
        };
        let sdp = client.offer("call-1", "tag-a", b"v=0\r\n", &flags).await.unwrap();
        assert!(String::from_utf8_lossy(&sdp).contains("203.0.113.1"));
        assert_eq!(client.active_sessions(), 1);
        assert_eq!(client.instance_count(), 1);
        assert_eq!(client.instance_addresses(), vec![address]);
    }

    /// Fake engine that accepts one `PlayMedia` with `play_id`, then optionally
    /// pushes an `Event::PlayFinished` after a short delay. Returns its address.
    async fn spawn_play_server(
        play_id: u64,
        finish: Option<(PlayEndReason, Option<u64>)>,
    ) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = Vec::new();
            let request: Request = read_frame(&mut stream, &mut buffer).await;
            assert!(matches!(request.command, Command::PlayMedia { .. }));
            // Accept immediately, echoing the play_id.
            write_frame(
                &mut stream,
                &Response {
                    id: request.id,
                    result: CmdResult::Ok {
                        sdp: None,
                        duration_ms: None,
                        to_tag: None,
                        stats: None,
                        play_id: Some(play_id),
                    },
                },
            )
            .await;
            if let Some((reason, played_ms)) = finish {
                // The prompt "plays", then the engine reports completion.
                tokio::time::sleep(Duration::from_millis(30)).await;
                write_frame(
                    &mut stream,
                    &Event::PlayFinished {
                        call_id: "call-play".into(),
                        from_tag: "tag-a".into(),
                        to_tag: None,
                        play_id,
                        reason,
                        played_ms,
                    },
                )
                .await;
            }
            // Keep the connection open so the client doesn't see EOF.
            tokio::time::sleep(Duration::from_millis(200)).await;
        });
        address
    }

    fn play_source() -> PlayMediaSource {
        PlayMediaSource::File("/prompts/welcome.wav".to_string())
    }

    #[tokio::test]
    async fn play_media_wait_returns_played_ms_on_completed() {
        // wait=True blocks until the PlayFinished(Completed) for its play_id and
        // returns the played duration from the event (the accept carried none, so
        // Some(1234) proves it waited for completion rather than returning early).
        let address = spawn_play_server(7, Some((PlayEndReason::Completed, Some(1234)))).await;
        let (event_tx, _event_rx) = channel();
        let client = SiphonRtpClient::new(address, None, 2000, 5_000, event_tx);
        let played = client
            .play_media("call-play", "tag-a", &play_source(), None, None, None, None, true)
            .await
            .unwrap();
        assert_eq!(played, Some(1234));
    }

    #[tokio::test]
    async fn play_media_wait_returns_none_when_stopped() {
        // Ended early (stopped / superseded) → the prompt didn't play out → None.
        let address = spawn_play_server(8, Some((PlayEndReason::Stopped, Some(400)))).await;
        let (event_tx, _event_rx) = channel();
        let client = SiphonRtpClient::new(address, None, 2000, 5_000, event_tx);
        let played = client
            .play_media("call-play", "tag-a", &play_source(), None, None, None, None, true)
            .await
            .unwrap();
        assert_eq!(played, None);
    }

    #[tokio::test]
    async fn play_media_no_wait_returns_on_accept() {
        // wait=False returns as soon as the engine accepts — it must NOT block for
        // a completion event (the fake server never sends one).
        let address = spawn_play_server(9, None).await;
        let (event_tx, _event_rx) = channel();
        let client = SiphonRtpClient::new(address, None, 2000, 5_000, event_tx);
        let played = tokio::time::timeout(
            Duration::from_millis(500),
            client.play_media("call-play", "tag-a", &play_source(), None, None, None, None, false),
        )
        .await
        .expect("play_media(wait=false) must return on accept, not block")
        .unwrap();
        assert_eq!(played, None);
    }

    #[tokio::test]
    async fn play_media_wait_fallback_timeout_returns_none() {
        // No PlayFinished ever arrives; a small play fallback timeout resolves the
        // await to None instead of hanging the call.
        let address = spawn_play_server(10, None).await;
        let (event_tx, _event_rx) = channel();
        // 100 ms play fallback so the test is fast + deterministic.
        let client = SiphonRtpClient::new(address, None, 2000, 100, event_tx);
        let played = tokio::time::timeout(
            Duration::from_millis(2000),
            client.play_media("call-play", "tag-a", &play_source(), None, None, None, None, true),
        )
        .await
        .expect("play_media must give up at the fallback timeout, not hang")
        .unwrap();
        assert_eq!(played, None);
    }

    #[tokio::test]
    async fn auth_handshake_then_offer() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = Vec::new();
            // First frame must be the auth request.
            let auth: Request = read_frame(&mut stream, &mut buffer).await;
            assert_eq!(auth.id, AUTH_REQUEST_ID);
            match auth.command {
                Command::Authenticate { token } => assert_eq!(token, "s3cret"),
                other => panic!("expected Authenticate, got {other:?}"),
            }
            write_frame(
                &mut stream,
                &Response {
                    id: AUTH_REQUEST_ID,
                    result: CmdResult::Ok {
                        sdp: None,
                        duration_ms: None,
                        to_tag: None,
                        stats: None,
                        play_id: None,
                    },
                },
            )
            .await;
            // Then a normal command.
            let request: Request = read_frame(&mut stream, &mut buffer).await;
            assert!(matches!(request.command, Command::Ping));
            write_frame(
                &mut stream,
                &Response {
                    id: request.id,
                    result: CmdResult::Pong,
                },
            )
            .await;
            tokio::time::sleep(Duration::from_millis(200)).await;
        });

        let (event_tx, _event_rx) = channel();
        let client = SiphonRtpClient::new(address, Some("s3cret".into()), 2000, 5_000, event_tx);
        client.ping().await.unwrap();
    }

    #[tokio::test]
    async fn out_of_order_responses_correlate() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = Vec::new();
            let first: Request = read_frame(&mut stream, &mut buffer).await;
            let second: Request = read_frame(&mut stream, &mut buffer).await;
            // Reply in reverse order, tagging the SDP with the request id.
            write_frame(
                &mut stream,
                &Response {
                    id: second.id,
                    result: CmdResult::Ok {
                        sdp: Some(format!("id={}", second.id)),
                        duration_ms: None,
                        to_tag: None,
                        stats: None,
                        play_id: None,
                    },
                },
            )
            .await;
            write_frame(
                &mut stream,
                &Response {
                    id: first.id,
                    result: CmdResult::Ok {
                        sdp: Some(format!("id={}", first.id)),
                        duration_ms: None,
                        to_tag: None,
                        stats: None,
                        play_id: None,
                    },
                },
            )
            .await;
            tokio::time::sleep(Duration::from_millis(300)).await;
        });

        let (event_tx, _event_rx) = channel();
        let client = SiphonRtpClient::new(address, None, 2000, 5_000, event_tx);
        let flags = NgFlags::default();
        let one = client.offer("call-a", "ta", b"v=0\r\n", &flags);
        let two = client.offer("call-b", "tb", b"v=0\r\n", &flags);
        let (one, two) = tokio::join!(one, two);
        assert_eq!(String::from_utf8_lossy(&one.unwrap()), "id=1");
        assert_eq!(String::from_utf8_lossy(&two.unwrap()), "id=2");
    }

    #[tokio::test]
    async fn dtmf_and_media_timeout_events_forwarded() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            write_frame(
                &mut stream,
                &Event::Dtmf {
                    call_id: "c1".into(),
                    from_tag: "f1".into(),
                    to_tag: None,
                    digit: "7".into(),
                    duration_ms: 80,
                    volume: -10,
                    source: None,
                },
            )
            .await;
            write_frame(
                &mut stream,
                &Event::MediaTimeout {
                    call_id: "c2".into(),
                    from_tag: "f2".into(),
                },
            )
            .await;
            tokio::time::sleep(Duration::from_millis(300)).await;
        });

        let (event_tx, mut event_rx) = channel();
        let _client = SiphonRtpClient::new(address, None, 2000, 5_000, event_tx);

        match event_rx.recv().await.unwrap() {
            RtpEngineEvent::Dtmf(dtmf) => {
                assert_eq!(dtmf.digit, "7");
                assert_eq!(dtmf.call_id, "c1");
            }
            other => panic!("expected Dtmf, got {other:?}"),
        }
        match event_rx.recv().await.unwrap() {
            RtpEngineEvent::MediaTimeout { call_id, .. } => assert_eq!(call_id, "c2"),
            other => panic!("expected MediaTimeout, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn error_response_maps_to_engine_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = Vec::new();
            let request: Request = read_frame(&mut stream, &mut buffer).await;
            write_frame(
                &mut stream,
                &Response {
                    id: request.id,
                    result: CmdResult::Error {
                        reason: "no such call".into(),
                    },
                },
            )
            .await;
            tokio::time::sleep(Duration::from_millis(200)).await;
        });

        let (event_tx, _event_rx) = channel();
        let client = SiphonRtpClient::new(address, None, 2000, 5_000, event_tx);
        let error = client.delete("call-x", "tag-a").await.unwrap_err();
        assert!(matches!(error, RtpEngineError::EngineError(_)));
        assert!(error.to_string().contains("no such call"));
    }

    #[tokio::test]
    async fn echo_frames_command_with_enabled_flag() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = Vec::new();

            // First call: echo(enabled=true).
            let request: Request = read_frame(&mut stream, &mut buffer).await;
            match request.command {
                Command::Echo {
                    call_id,
                    from_tag,
                    to_tag,
                    enabled,
                } => {
                    assert_eq!(call_id, "call-echo");
                    assert_eq!(from_tag, "tag-a");
                    assert_eq!(to_tag, None);
                    assert!(enabled, "enabled=true must serialize as true");
                }
                other => panic!("expected Echo, got {other:?}"),
            }
            write_frame(
                &mut stream,
                &Response {
                    id: request.id,
                    result: CmdResult::Ok {
                        sdp: None,
                        duration_ms: None,
                        to_tag: None,
                        stats: None,
                        play_id: None,
                    },
                },
            )
            .await;

            // Second call on the same persistent connection: echo(enabled=false).
            let request: Request = read_frame(&mut stream, &mut buffer).await;
            match request.command {
                Command::Echo { enabled, .. } => {
                    assert!(!enabled, "enabled=false must serialize as false");
                }
                other => panic!("expected Echo, got {other:?}"),
            }
            write_frame(
                &mut stream,
                &Response {
                    id: request.id,
                    result: CmdResult::Ok {
                        sdp: None,
                        duration_ms: None,
                        to_tag: None,
                        stats: None,
                        play_id: None,
                    },
                },
            )
            .await;
            tokio::time::sleep(Duration::from_millis(200)).await;
        });

        let (event_tx, _event_rx) = channel();
        let client = SiphonRtpClient::new(address, None, 2000, 5_000, event_tx);
        client.echo("call-echo", "tag-a", true).await.unwrap();
        client.echo("call-echo", "tag-a", false).await.unwrap();
    }

    #[tokio::test]
    async fn query_stats_response_is_accepted_by_subscribe_answer_shape() {
        // subscribe_answer tolerates a missing SDP; verify Ok{stats} (no sdp)
        // yields an empty body rather than an error.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = Vec::new();
            let request: Request = read_frame(&mut stream, &mut buffer).await;
            assert!(matches!(request.command, Command::SubscribeAnswer { .. }));
            write_frame(
                &mut stream,
                &Response {
                    id: request.id,
                    result: CmdResult::Ok {
                        sdp: None,
                        duration_ms: None,
                        to_tag: None,
                        stats: Some(SessionStats::default()),
                        play_id: None,
                    },
                },
            )
            .await;
            tokio::time::sleep(Duration::from_millis(200)).await;
        });

        let (event_tx, _event_rx) = channel();
        let client = SiphonRtpClient::new(address, None, 2000, 5_000, event_tx);
        let body = client
            .subscribe_answer("c", "f", "t", b"v=0\r\n", &NgFlags::default())
            .await
            .unwrap();
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn reconnects_after_disconnect() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        tokio::spawn(async move {
            // First connection: accept then immediately drop it.
            let (first, _) = listener.accept().await.unwrap();
            drop(first);
            // Second connection: serve a ping.
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = Vec::new();
            let request: Request = read_frame(&mut stream, &mut buffer).await;
            assert!(matches!(request.command, Command::Ping));
            write_frame(
                &mut stream,
                &Response {
                    id: request.id,
                    result: CmdResult::Pong,
                },
            )
            .await;
            tokio::time::sleep(Duration::from_millis(200)).await;
        });

        let (event_tx, _event_rx) = channel();
        let client = SiphonRtpClient::new(address, None, 2000, 5_000, event_tx);
        // Give the manager time to see the drop and reconnect (backoff = 200ms).
        tokio::time::sleep(Duration::from_millis(500)).await;
        client.ping().await.unwrap();
    }

    #[tokio::test]
    async fn command_times_out_when_engine_unreachable() {
        // Nothing listening: the connection never establishes, so a command
        // waits for the connection and then times out (rather than hanging
        // forever or failing instantly during a transient startup window).
        let address: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let (event_tx, _event_rx) = channel();
        let client = SiphonRtpClient::new(address, None, 300, 5_000, event_tx);
        let error = client.ping().await.unwrap_err();
        assert!(matches!(error, RtpEngineError::Timeout { .. }));
    }

    #[test]
    fn client_set_requires_at_least_one_instance() {
        let (event_tx, _event_rx) = channel();
        let result = SiphonRtpClientSet::new(vec![], None, 5_000, event_tx);
        assert!(matches!(result, Err(RtpEngineError::Protocol(_))));
    }

    #[tokio::test]
    async fn client_set_spreads_calls_and_sums_sessions() {
        // Two instances; offers for distinct call-ids succeed across the set and
        // active_sessions sums across instances.
        let address_one = spawn_offer_server().await;
        let address_two = spawn_offer_server().await;
        let (event_tx, _event_rx) = channel();
        let set = SiphonRtpClientSet::new(
            vec![(address_one, 2000, 1), (address_two, 2000, 1)],
            None,
            5_000,
            event_tx,
        )
        .unwrap();

        assert_eq!(set.instance_count(), 2);
        let addresses = set.instance_addresses();
        assert!(addresses.contains(&address_one));
        assert!(addresses.contains(&address_two));

        let flags = NgFlags::default();
        for index in 0..4 {
            let call_id = format!("set-call-{index}");
            let sdp = set
                .offer(&call_id, "tag-a", b"v=0\r\n", &flags)
                .await
                .unwrap();
            assert!(String::from_utf8_lossy(&sdp).contains("203.0.113.1"));
        }
        // Four distinct calls offered → four active sessions across the set.
        assert_eq!(set.active_sessions(), 4);

        // Affinity holds: an answer for an existing call-id routes to the same
        // instance that accepted its offer (no error).
        set.answer("set-call-0", "tag-a", "tag-b", b"v=0\r\n", &flags)
            .await
            .unwrap();

        // Delete drops the session from the set's accounting.
        set.delete("set-call-0", "tag-a").await.unwrap();
        assert_eq!(set.active_sessions(), 3);
    }
}
