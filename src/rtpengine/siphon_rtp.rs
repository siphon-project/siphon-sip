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
    frame, CmdResult, Command, Event, LegSummary as ProtoLegSummary, PlayEndReason,
    PlayMediaSource as ProtoPlayMediaSource, ProfileFlags, Request, Response,
    WsTeeDirection as ProtoWsTeeDirection, WsTeeEndReason as ProtoWsTeeEndReason,
    WsVadEngine as ProtoWsVadEngine,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, watch, Mutex};
use tracing::{debug, info, trace, warn};

use super::client::PlayMediaSource;
use super::error::RtpEngineError;
use super::events::{
    BeepDetectedEvent, CallLegSummary, CallSummary, DtmfEvent, RtpEngineEvent, TextEvent,
    TextStreamStats, WsTeeEndReason, WsTeeStarted, WsTeeEnded,
};
use super::profile::{NgFlags, WsTeeDirection, WsVadEngine};

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
///
/// Deliberately exhaustive — **no `..ProfileFlags::default()` tail**.  The tail
/// is what let the WebSocket-bridge fields sit unreachable from signalling while
/// the engine supported them: a struct-update fallback turns "siphon forgot to
/// carry this" into a silent default instead of a compile error.  Adding a proto
/// field must break this function.
pub(crate) fn profile_flags_from_ng(flags: &NgFlags) -> ProfileFlags {
    ProfileFlags {
        transport_protocol: flags.transport_protocol.clone(),
        ice: flags.ice.clone(),
        dtls: flags.dtls.clone(),
        replace: flags.replace.clone(),
        address_family: flags.address_family.clone(),
        // The native engine implements the same rtpengine codec model but reads
        // it from the flag list (`codec-<op>-<NAME>`) rather than a nested dict,
        // so the profile's `codec:` block is flattened onto the flags here and
        // one profile drives both engines.
        flags: {
            let mut merged = flags.flags.clone();
            merged.extend(flags.codec.to_native_flags());
            merged
        },
        direction: flags.direction.clone(),
        record_call: flags.record_call,
        record_path: flags.record_path.clone(),
        noise_suppression: flags.noise_suppression,
        echo_cancellation: flags.echo_cancellation,
        ws_uri: flags.ws_uri.clone(),
        ws_vad: flags.ws_vad,
        ws_barge_in: flags.ws_barge_in,
        ws_vad_threshold: flags.ws_vad_threshold,
        ws_vad_hangover_ms: flags.ws_vad_hangover_ms,
        ws_sample_rate: flags.ws_sample_rate,
        ws_vad_engine: flags.ws_vad_engine.map(proto_ws_vad_engine),
        ws_vad_min_speech_ms: flags.ws_vad_min_speech_ms,
        beep_detection: flags.beep_detection,
        beep_cadence_guard_ms: flags.beep_cadence_guard_ms,
        ws_tee: flags.ws_tee.clone(),
        ws_tee_direction: flags.ws_tee_direction.map(proto_ws_tee_direction),
        ws_tee_channels: flags.ws_tee_channels,
        ws_tee_sample_rate: flags.ws_tee_sample_rate,
        // The per-call address, not the `carry_received_from` policy bit — the
        // script API injects the former only when the latter is set, so an
        // opted-out profile leaves this `None` and serialises away.
        received_from: flags.received_from,
        rtcp_mux: flags.rtcp_mux.clone(),
        text_events: flags.text_events,
    }
}

/// Map siphon's [`WsTeeDirection`] onto the proto twin.
pub(crate) fn proto_ws_tee_direction(direction: WsTeeDirection) -> ProtoWsTeeDirection {
    match direction {
        WsTeeDirection::Both => ProtoWsTeeDirection::Both,
        WsTeeDirection::Caller => ProtoWsTeeDirection::Caller,
        WsTeeDirection::Callee => ProtoWsTeeDirection::Callee,
    }
}

/// Map siphon's [`WsVadEngine`] onto the proto twin.
///
/// Deliberately exhaustive, mirroring the proto's own refusal to mark
/// `WsVadEngine` `#[non_exhaustive]`: a detector swept into a wildcard here
/// would silently downgrade the call to the detector the script was explicitly
/// avoiding.  A new detector must break this function.
pub(crate) fn proto_ws_vad_engine(engine: WsVadEngine) -> ProtoWsVadEngine {
    match engine {
        WsVadEngine::Energy => ProtoWsVadEngine::Energy,
        WsVadEngine::Neural => ProtoWsVadEngine::Neural,
    }
}

/// Map the proto [`ProtoWsTeeDirection`] back onto siphon's own enum, so the
/// generic event type stays free of the proto.
fn ws_tee_direction_from_proto(direction: ProtoWsTeeDirection) -> WsTeeDirection {
    match direction {
        ProtoWsTeeDirection::Both => WsTeeDirection::Both,
        ProtoWsTeeDirection::Caller => WsTeeDirection::Caller,
        ProtoWsTeeDirection::Callee => WsTeeDirection::Callee,
    }
}

/// Map siphon's [`PlayMediaSource`] to the proto variant.
///
/// Deliberately exhaustive on **siphon's own** enum (which is local, so no
/// wildcard is forced): a source siphon grows must be carried here or fail to
/// compile, never be silently dropped into a `play media` with no source.
fn proto_play_source(source: &PlayMediaSource) -> ProtoPlayMediaSource {
    match source {
        PlayMediaSource::File(path) => ProtoPlayMediaSource::File { path: path.clone() },
        PlayMediaSource::Blob(data) => ProtoPlayMediaSource::Blob { data: data.clone() },
        PlayMediaSource::DbId(id) => ProtoPlayMediaSource::DbId { id: *id },
        PlayMediaSource::Tone(tone) => ProtoPlayMediaSource::Tone { tone: tone.clone() },
        // The engine fetches this itself, bounded by its own connect /
        // first-byte / deadline / size / redirect caps and off the media path.
        // siphon deliberately does not fetch: a controller-side fetch would put
        // an unbounded third-party HTTP round-trip on the call-setup path.
        PlayMediaSource::Http(url) => ProtoPlayMediaSource::Http { url: url.clone() },
    }
}

/// Completion signal for a blocking `play_media(wait=True)`: how the prompt ended
/// plus the actual played duration (from `Event::PlayFinished`).
type PlayWaiter = oneshot::Sender<(PlayEndReason, Option<u64>)>;

/// What a `play media` accept (and, when waited on, its completion) yielded.
///
/// The `play_id` is the engine's handle on that specific playback: it is what
/// `set_play_gain` retunes and what a targeted `stop_media` ends, and it is the
/// only way to address one of the four concurrent overlay slots on a direction.
/// Carried separately from the duration because the two answer different
/// questions and an overlay generally has a handle but no useful duration.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PlayMediaOutcome {
    /// The engine's handle on this playback, when it assigned one.
    pub play_id: Option<u64>,
    /// Played duration in milliseconds, when the engine reported one.  Always
    /// absent for an HTTP source at accept time — the length is not known until
    /// the body has arrived.
    pub duration_ms: Option<u64>,
}

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

    /// Send a `reoffer` — renegotiate a **live** call on the ports it already
    /// holds, returning the rewritten SDP.
    ///
    /// This is what a SIP re-INVITE or UPDATE maps to.  A repeated `offer` on a
    /// live call-id is a *replacement*: the engine tears the old call down and
    /// allocates fresh ports, which drops everything attached to it — the
    /// WebSocket bridge, any tee, any SIPREC subscription — and hands the peer
    /// an address it was never told about.  `reoffer` keeps the ports, the
    /// pipeline and the attachments, and carries an RFC 8445 §9 ICE restart
    /// when the peer sends new credentials.
    ///
    /// The engine refuses a re-offer that changes the negotiated codec (that
    /// needs a pipeline rebuild) — see [`RtpEngineSet::reoffer`], which falls
    /// back to a replacement for exactly that case.
    pub async fn reoffer(
        &self,
        call_id: &str,
        from_tag: &str,
        sdp: &[u8],
        flags: &NgFlags,
    ) -> Result<Vec<u8>, RtpEngineError> {
        let result = self
            .request(Command::Reoffer {
                call_id: call_id.to_string(),
                from_tag: from_tag.to_string(),
                sdp: String::from_utf8_lossy(sdp).into_owned(),
                profile: profile_flags_from_ng(flags),
            })
            .await?;
        expect_sdp(result)
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

    /// Single-leg UAS `answer_local` — the engine *is* the far side (IVR /
    /// echo / announcement), so there is no peer `to_tag`.  Given the offerer's
    /// SDP, the engine synthesises an RFC 3264 answer advertising one encodable
    /// codec and returns it.  When no offered codec is encodable in this build
    /// the engine replies `CmdResult::Error { reason: "no-encodable-codec" }`,
    /// surfaced here as [`RtpEngineError::EngineError`] carrying that reason.
    ///
    /// Bookkeeping mirrors [`Self::offer`]: a single-leg answer establishes a
    /// session, so the call-id is tracked for active-session accounting and a
    /// later `delete`.
    pub async fn answer_local(
        &self,
        call_id: &str,
        from_tag: &str,
        offer_sdp: &str,
        flags: &NgFlags,
    ) -> Result<String, RtpEngineError> {
        let result = self
            .request(Command::AnswerLocal {
                call_id: call_id.to_string(),
                from_tag: from_tag.to_string(),
                sdp: offer_sdp.to_string(),
                profile: profile_flags_from_ng(flags),
            })
            .await?;
        let answer_sdp = expect_sdp(result)?;
        self.sessions.insert(call_id.to_string(), ());
        Ok(String::from_utf8_lossy(&answer_sdp).into_owned())
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
    ///
    /// `overlay` mixes the prompt **under** the party's live egress instead of
    /// replacing it (up to four concurrent overlays per direction, each with its
    /// own `play_id`); `gain_decibels` sets the playout level relative to the
    /// source's own, clamped engine-side to −60..=+12 dB.
    ///
    /// Returns the `play_id` alongside the duration so a caller can retune the
    /// playback with [`SiphonRtpClient::set_play_gain`] or stop just this one.
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
        overlay: bool,
        gain_decibels: Option<i32>,
        wait: bool,
    ) -> Result<PlayMediaOutcome, RtpEngineError> {
        let result = self
            .request(Command::PlayMedia {
                call_id: call_id.to_string(),
                from_tag: from_tag.to_string(),
                source: proto_play_source(source),
                repeat_times,
                start_pos_ms,
                duration_ms,
                overlay,
                gain_decibels,
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
            return Ok(PlayMediaOutcome {
                play_id,
                duration_ms: accept_duration,
            });
        };

        // Block until the prompt ends. Register the waiter keyed by play_id (the
        // reader resolves it when PlayFinished arrives), bounded by the fallback
        // timeout so a lost event / dead engine can't hang the call. There is a
        // sub-millisecond race where PlayFinished could arrive before this insert
        // (vs a seconds-long prompt) — the fallback covers that pathological case.
        let (sender, receiver) = oneshot::channel::<(PlayEndReason, Option<u64>)>();
        self.play_pending.insert(play_id, sender);
        let deadline = Duration::from_millis(self.play_timeout_ms.max(1));
        // Every outcome still reports the play_id: the caller may want to stop or
        // retune a playback that merely failed to *complete* (an overlay ended
        // early is still a live slot from the controller's point of view).
        let outcome = |duration_ms| PlayMediaOutcome {
            play_id: Some(play_id),
            duration_ms,
        };
        match tokio::time::timeout(deadline, receiver).await {
            // Prompt played out in full.
            Ok(Ok((PlayEndReason::Completed, played_ms))) => {
                Ok(outcome(played_ms.or(accept_duration)))
            }
            // Ended early (stopped / superseded) — didn't play out; the script decides.
            Ok(Ok((PlayEndReason::Stopped | PlayEndReason::Superseded, _))) => Ok(outcome(None)),
            // Engine reported an aborted playback — this is also how a bounded
            // HTTP source reports a fetch that failed, since that play never
            // produced audio.
            Ok(Ok((PlayEndReason::Error, _))) => {
                warn!(call_id, play_id, "siphon-rtp play_media aborted (engine error)");
                Ok(outcome(None))
            }
            // A reason this build does not know. `PlayEndReason` is
            // `#[non_exhaustive]` upstream precisely because the safe reading of
            // an unknown reason is the documented one — the playback ended — so
            // this reports "did not complete" rather than inventing a duration.
            Ok(Ok((reason, _))) => {
                warn!(
                    call_id,
                    play_id,
                    ?reason,
                    "siphon-rtp play_media ended for a reason this build does not know"
                );
                Ok(outcome(None))
            }
            // Connection dropped (sender cleared on disconnect) — treat as not completed.
            Ok(Err(_)) => {
                warn!(call_id, play_id, "siphon-rtp play_media: connection lost before completion");
                Ok(outcome(None))
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
                Ok(outcome(None))
            }
        }
    }

    /// Stop prompt playback on the monologue selected by `from_tag`.
    ///
    /// `play_id` targets one playback (an individual overlay slot); `None` stops
    /// everything playing on the leg.
    pub async fn stop_media(
        &self,
        call_id: &str,
        from_tag: &str,
        play_id: Option<u64>,
    ) -> Result<(), RtpEngineError> {
        expect_ok(
            self.request(Command::StopMedia {
                call_id: call_id.to_string(),
                from_tag: from_tag.to_string(),
                play_id,
            })
            .await?,
        )
    }

    /// Retune the playout gain of a playback that is already running — how a
    /// controller ducks a music bed under a prompt and lifts it again.
    ///
    /// `play_id` is the handle the playback's accept returned.  The engine
    /// answers an error when no playback on the call holds that id, so a stale
    /// handle surfaces rather than silently doing nothing.
    pub async fn set_play_gain(
        &self,
        call_id: &str,
        from_tag: &str,
        play_id: u64,
        gain_decibels: i32,
        to_tag: Option<&str>,
    ) -> Result<(), RtpEngineError> {
        expect_ok(
            self.request(Command::SetPlayGain {
                call_id: call_id.to_string(),
                from_tag: from_tag.to_string(),
                play_id,
                gain_decibels,
                to_tag: to_tag.map(str::to_string),
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

    /// Attach a WebSocket tee to a live call — stream a copy of its decoded
    /// audio to `ws_uri` while the call keeps relaying.
    ///
    /// Additive, unlike the `ws_uri` profile flag: the relay/transcode path, any
    /// SIPREC subscription and the recording all keep running.  The engine
    /// promotes a plain in-kernel relay to the userspace pipeline for the tee's
    /// lifetime and demotes it again on detach.
    pub async fn attach_ws_tee(
        &self,
        call_id: &str,
        from_tag: &str,
        ws_uri: &str,
        direction: WsTeeDirection,
        channels: Option<u8>,
        sample_rate: Option<u32>,
    ) -> Result<(), RtpEngineError> {
        expect_ok(
            self.request(Command::AttachWsTee {
                call_id: call_id.to_string(),
                from_tag: from_tag.to_string(),
                ws_uri: ws_uri.to_string(),
                direction: proto_ws_tee_direction(direction),
                channels,
                sample_rate,
            })
            .await?,
        )
    }

    /// Detach a call's WebSocket tee, closing its stream.  Idempotent — the
    /// engine does not treat detaching a call with no tee as an error.
    pub async fn detach_ws_tee(
        &self,
        call_id: &str,
        from_tag: &str,
    ) -> Result<(), RtpEngineError> {
        expect_ok(
            self.request(Command::DetachWsTee {
                call_id: call_id.to_string(),
                from_tag: from_tag.to_string(),
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

    /// Renegotiate a live call on the affinity-bound instance, keeping its ports
    /// and everything attached to them.
    ///
    /// Falls back to a replacement `offer` for the one case the engine refuses:
    /// a re-offer that changes the negotiated codec needs a pipeline rebuild the
    /// engine does not do on a live call, and its own error says to replace the
    /// call instead.  That fallback is today's behaviour for every re-INVITE, so
    /// a codec-changing one is no worse than before — but it *does* re-allocate
    /// ports and drop the call's bridge/tee/SIPREC attachments, so it is logged
    /// rather than performed silently.
    pub async fn reoffer(
        &self,
        call_id: &str,
        from_tag: &str,
        sdp: &[u8],
        flags: &NgFlags,
    ) -> Result<Vec<u8>, RtpEngineError> {
        match self.select(call_id).reoffer(call_id, from_tag, sdp, flags).await {
            Ok(rewritten) => Ok(rewritten),
            Err(error) if is_codec_change_refusal(&error) => {
                tracing::warn!(
                    %call_id,
                    %error,
                    "re-offer changes the negotiated codec; replacing the media session — its \
                     ports are re-allocated and any WebSocket bridge, tee or SIPREC subscription \
                     on it is torn down"
                );
                let result = self.select(call_id).offer(call_id, from_tag, sdp, flags).await?;
                self.bind_affinity(call_id);
                Ok(result)
            }
            Err(error) => Err(error),
        }
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

    /// Single-leg UAS `answer_local` via the affinity-bound instance, binding
    /// call-id affinity (it establishes a session, like `offer`).
    pub async fn answer_local(
        &self,
        call_id: &str,
        from_tag: &str,
        offer_sdp: &str,
        flags: &NgFlags,
    ) -> Result<String, RtpEngineError> {
        let result = self
            .select(call_id)
            .answer_local(call_id, from_tag, offer_sdp, flags)
            .await?;
        self.bind_affinity(call_id);
        Ok(result)
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
        overlay: bool,
        gain_decibels: Option<i32>,
        wait: bool,
    ) -> Result<PlayMediaOutcome, RtpEngineError> {
        self.select(call_id)
            .play_media(
                call_id,
                from_tag,
                source,
                repeat_times,
                start_pos_ms,
                duration_ms,
                to_tag,
                overlay,
                gain_decibels,
                wait,
            )
            .await
    }

    /// Stop a prompt via the affinity-bound instance.
    pub async fn stop_media(
        &self,
        call_id: &str,
        from_tag: &str,
        play_id: Option<u64>,
    ) -> Result<(), RtpEngineError> {
        self.select(call_id).stop_media(call_id, from_tag, play_id).await
    }

    /// Retune a running playback's gain via the affinity-bound instance.
    pub async fn set_play_gain(
        &self,
        call_id: &str,
        from_tag: &str,
        play_id: u64,
        gain_decibels: i32,
        to_tag: Option<&str>,
    ) -> Result<(), RtpEngineError> {
        self.select(call_id)
            .set_play_gain(call_id, from_tag, play_id, gain_decibels, to_tag)
            .await
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

    /// Attach a WebSocket tee on the instance owning this call.
    pub async fn attach_ws_tee(
        &self,
        call_id: &str,
        from_tag: &str,
        ws_uri: &str,
        direction: WsTeeDirection,
        channels: Option<u8>,
        sample_rate: Option<u32>,
    ) -> Result<(), RtpEngineError> {
        self.select(call_id)
            .attach_ws_tee(call_id, from_tag, ws_uri, direction, channels, sample_rate)
            .await
    }

    /// Detach the WebSocket tee on the instance owning this call.
    pub async fn detach_ws_tee(
        &self,
        call_id: &str,
        from_tag: &str,
    ) -> Result<(), RtpEngineError> {
        self.select(call_id).detach_ws_tee(call_id, from_tag).await
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

/// Whether a `reoffer` failure is the engine's "this changes the codec" refusal
/// (the one case that has to be retried as a replacement `offer`) rather than a
/// transport failure, an unknown call, or anything else we must not paper over.
///
/// Matched on the reason text because the control protocol carries a string
/// reason, not a typed error code, for a command-level refusal.  Deliberately
/// narrow: only a refusal naming the codec qualifies, so a future engine error
/// cannot silently acquire a call-replacing retry.
fn is_codec_change_refusal(error: &RtpEngineError) -> bool {
    let reason = error.to_string();
    reason.contains("re-offer changes the negotiated codec")
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
///
/// `CmdResult` is `#[non_exhaustive]` upstream, so the wildcard is forced.  It
/// yields a named placeholder rather than being silently absorbed — the caller
/// is building "unexpected `{kind}` response to {context}", and an empty kind
/// would turn a real protocol violation into an unreadable error.
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
        _ => "unrecognised",
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
        Event::CallSummary {
            call_id,
            reason,
            duration_ms,
            legs,
        } => RtpEngineEvent::CallSummary(CallSummary {
            call_id,
            reason,
            duration_ms,
            legs: legs.into_iter().map(convert_leg_summary).collect(),
        }),
        Event::Text {
            call_id,
            from_tag,
            to_tag,
            text,
            direction,
        } => RtpEngineEvent::Text(TextEvent {
            call_id,
            from_tag,
            to_tag,
            text,
            direction,
        }),
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
        Event::WsTeeStarted {
            call_id,
            from_tag,
            stream_id,
            ws_uri,
            direction,
            channels,
            sample_rate,
        } => RtpEngineEvent::WsTeeStarted(WsTeeStarted {
            call_id,
            from_tag,
            stream_id,
            ws_uri,
            direction: ws_tee_direction_from_proto(direction),
            channels,
            sample_rate,
        }),
        Event::WsTeeEnded {
            call_id,
            from_tag,
            stream_id,
            reason,
            frames_sent,
            frames_dropped,
        } => RtpEngineEvent::WsTeeEnded(WsTeeEnded {
            call_id,
            from_tag,
            stream_id,
            reason: ws_tee_end_reason_from_proto(reason),
            frames_sent,
            frames_dropped,
        }),
        Event::BeepDetected {
            call_id,
            from_tag,
            to_tag,
            frequency_hz,
            duration_ms,
            offset_ms,
        } => RtpEngineEvent::BeepDetected(BeepDetectedEvent {
            call_id,
            from_tag,
            to_tag,
            frequency_hz,
            duration_ms,
            offset_ms,
        }),
        Event::Unknown => RtpEngineEvent::Unknown {
            event: "unknown".to_string(),
            call_id: None,
            from_tag: None,
        },
        // `Event` is `#[non_exhaustive]` upstream, so a build newer than this one
        // can push a variant this one has no arm for. Surfaced through `Unknown`
        // (which the dispatcher logs) rather than dropped — the correlation ids
        // are unreachable behind the wildcard, but the fact that an unmodelled
        // event arrived is exactly what tells an operator siphon is behind the
        // engine. A serde-level `Event::Unknown` (an event tag the *proto* did
        // not recognise) is the arm above; this is a tag it did.
        other => {
            debug!(?other, "siphon-rtp event not modelled by this build");
            RtpEngineEvent::Unknown {
                event: "unmodelled".to_string(),
                call_id: None,
                from_tag: None,
            }
        }
    }
}

/// Map the proto tee end-reason onto siphon's own enum.
///
/// `WsTeeEndReason` is `#[non_exhaustive]` upstream. The wildcard maps to
/// [`WsTeeEndReason::TransportError`] rather than a silent
/// [`WsTeeEndReason::Detached`]: `Detached` is the *only* orderly end, and the
/// dispatcher keys its WARN-when-unexpected logging on that distinction, so
/// treating an unknown reason as orderly would hide a dead stream on a live
/// call — the exact failure this event exists to surface.
fn ws_tee_end_reason_from_proto(reason: ProtoWsTeeEndReason) -> WsTeeEndReason {
    match reason {
        ProtoWsTeeEndReason::Detached => WsTeeEndReason::Detached,
        ProtoWsTeeEndReason::ServerClosed => WsTeeEndReason::ServerClosed,
        ProtoWsTeeEndReason::ServerStopped => WsTeeEndReason::ServerStopped,
        ProtoWsTeeEndReason::CallEnded => WsTeeEndReason::CallEnded,
        ProtoWsTeeEndReason::TransportError => WsTeeEndReason::TransportError,
        _ => WsTeeEndReason::TransportError,
    }
}

/// Convert a proto [`ProtoLegSummary`] into siphon's [`CallLegSummary`] — a
/// field-for-field copy that keeps the generic event enum free of the proto type.
fn convert_leg_summary(leg: ProtoLegSummary) -> CallLegSummary {
    CallLegSummary {
        tag: leg.tag,
        codec: leg.codec,
        packets_in: leg.packets_in,
        bytes_in: leg.bytes_in,
        packets_out: leg.packets_out,
        bytes_out: leg.bytes_out,
        packets_dropped: leg.packets_dropped,
        ssrc: leg.ssrc,
        packets_lost: leg.packets_lost,
        loss_percent: leg.loss_percent,
        jitter_ms: leg.jitter_ms,
        rtt_ms: leg.rtt_ms,
        mos_average: leg.mos_average,
        mos_min: leg.mos_min,
        mos_max: leg.mos_max,
        mos_basis: leg.mos_basis,
        text: leg.text.map(|stats| TextStreamStats {
            packets: stats.packets,
            characters: stats.characters,
            missing_markers: stats.missing_markers,
            recovered_from_redundancy: stats.recovered_from_redundancy,
        }),
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
                            Command::Offer { .. } | Command::Reoffer { .. } | Command::Answer { .. } => CmdResult::Ok {
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

    /// A fake engine that answers like [`spawn_offer_server`] but also hands back
    /// the **raw JSON body** of every frame it received.
    ///
    /// Decoding to `Request` and asserting on the struct would not catch the bug
    /// this work fixes: a field siphon never populates round-trips as `None`
    /// through a `Request` just as happily as one it does populate. Asserting on
    /// the bytes actually written is what proves the field reached the wire.
    async fn spawn_capturing_server() -> (SocketAddr, mpsc::UnboundedReceiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (capture_tx, capture_rx) = mpsc::unbounded_channel::<String>();
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => return,
                };
                let capture_tx = capture_tx.clone();
                tokio::spawn(async move {
                    let mut buffer = Vec::new();
                    loop {
                        // Decode a frame to learn its length, but publish the
                        // raw body bytes rather than the decoded value.
                        let decoded = loop {
                            match frame::decode::<Request>(&buffer) {
                                Ok(Some((request, consumed))) => break Some((request, consumed)),
                                Ok(None) => {
                                    let mut chunk = vec![0u8; READ_CHUNK];
                                    match stream.read(&mut chunk).await {
                                        Ok(0) | Err(_) => break None,
                                        Ok(read) => buffer.extend_from_slice(&chunk[..read]),
                                    }
                                }
                                Err(_) => break None,
                            }
                        };
                        let Some((request, consumed)) = decoded else {
                            return;
                        };
                        let body =
                            String::from_utf8_lossy(&buffer[frame::HEADER_LEN..consumed]).into_owned();
                        buffer.drain(..consumed);
                        let _ = capture_tx.send(body);

                        let result = match request.command {
                            Command::Ping => CmdResult::Pong,
                            Command::Offer { .. }
                            | Command::Reoffer { .. }
                            | Command::Answer { .. }
                            | Command::AnswerLocal { .. } => CmdResult::Ok {
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
                        write_frame(&mut stream, &Response { id: request.id, result }).await;
                    }
                });
            }
        });
        (address, capture_rx)
    }

    /// The emitted offer frame for `flags`, as the raw JSON the engine receives.
    async fn captured_offer_json(flags: &NgFlags) -> String {
        let (address, mut capture_rx) = spawn_capturing_server().await;
        let (event_tx, _event_rx) = channel();
        let client = SiphonRtpClient::new(address, None, 2_000, 5_000, event_tx);
        client
            .offer("call-1", "tag-a", b"v=0\r\n", flags)
            .await
            .expect("offer");
        capture_rx.recv().await.expect("captured frame")
    }

    /// A fake engine that refuses a `reoffer` the way the real one refuses a
    /// codec change, answers `offer` with SDP, and reports which commands it
    /// saw — so the fallback can be proven to be a *retry as offer* and not a
    /// swallowed error.
    async fn spawn_codec_refusing_server() -> (SocketAddr, mpsc::UnboundedReceiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (seen_tx, seen_rx) = mpsc::unbounded_channel::<String>();
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => return,
                };
                let seen_tx = seen_tx.clone();
                tokio::spawn(async move {
                    let mut buffer = Vec::new();
                    while let Some(request) =
                        read_frame_opt::<Request, _>(&mut stream, &mut buffer).await
                    {
                        let result = match request.command {
                            Command::Reoffer { .. } => {
                                let _ = seen_tx.send("reoffer".to_string());
                                CmdResult::Error {
                                    reason: "re-offer changes the negotiated codec (PCMU → PCMA); \
                                             not supported on a live call — replace it with a \
                                             fresh offer instead"
                                        .to_string(),
                                }
                            }
                            Command::Offer { .. } => {
                                let _ = seen_tx.send("offer".to_string());
                                CmdResult::Ok {
                                    sdp: Some("v=0\r\nc=IN IP4 203.0.113.9\r\n".to_string()),
                                    duration_ms: None,
                                    to_tag: None,
                                    stats: None,
                                    play_id: None,
                                }
                            }
                            _ => CmdResult::Ok {
                                sdp: None,
                                duration_ms: None,
                                to_tag: None,
                                stats: None,
                                play_id: None,
                            },
                        };
                        write_frame(&mut stream, &Response { id: request.id, result }).await;
                    }
                });
            }
        });
        (address, seen_rx)
    }

    /// The whole point of the verb: a re-INVITE must not go out as `offer`,
    /// which on this backend frees the call's ports and takes its WebSocket
    /// bridge, tee and SIPREC subscription with them.
    #[tokio::test]
    async fn reoffer_emits_the_reoffer_command_not_an_offer() {
        let (address, mut capture_rx) = spawn_capturing_server().await;
        let (event_tx, _event_rx) = channel();
        let client = SiphonRtpClient::new(address, None, 2_000, 5_000, event_tx);
        client
            .reoffer("call-1", "tag-a", b"v=0\r\n", &NgFlags::default())
            .await
            .expect("reoffer");

        let json = capture_rx.recv().await.expect("captured frame");
        assert!(json.contains(r#""command":"reoffer""#), "wire frame was: {json}");
        assert!(!json.contains(r#""command":"offer""#), "wire frame was: {json}");
        assert!(json.contains(r#""call_id":"call-1""#), "wire frame was: {json}");
    }

    /// A re-offer that changes the codec is the one case the engine refuses, and
    /// its own error says to replace the call.  Retrying as `offer` keeps that
    /// re-INVITE working exactly as it did before this verb existed — but only
    /// that case: any other failure must propagate, or a transport blip would
    /// quietly re-allocate a live call's ports.
    #[tokio::test]
    async fn reoffer_retries_as_offer_only_on_the_codec_change_refusal() {
        let (address, mut seen_rx) = spawn_codec_refusing_server().await;
        let (event_tx, _event_rx) = channel();
        let set = SiphonRtpClientSet::new(vec![(address, 2_000, 1)], None, 5_000, event_tx)
            .expect("set");

        let rewritten = set
            .reoffer("call-1", "tag-a", b"v=0\r\n", &NgFlags::default())
            .await
            .expect("falls back to a replacement offer");
        assert!(String::from_utf8_lossy(&rewritten).contains("203.0.113.9"));

        assert_eq!(seen_rx.recv().await.as_deref(), Some("reoffer"));
        assert_eq!(seen_rx.recv().await.as_deref(), Some("offer"));
    }

    /// Narrow by construction: only a refusal naming the codec earns the retry.
    #[test]
    fn only_the_codec_refusal_is_treated_as_retryable() {
        assert!(is_codec_change_refusal(&RtpEngineError::Protocol(
            "re-offer changes the negotiated codec (PCMU → PCMA)".to_string()
        )));
        for other in [
            "unknown call-id",
            "node is draining; not accepting new sessions",
            "re-offer SDP parse failed: no m= line",
        ] {
            assert!(
                !is_codec_change_refusal(&RtpEngineError::Protocol(other.to_string())),
                "{other} must not earn a call-replacing retry"
            );
        }
    }

    /// The acceptance criterion for the WebSocket bridge: a profile carrying
    /// `ws_uri` must put it on the wire.  This is the assertion that would have
    /// failed for as long as `profile_flags_from_ng` defaulted the field.
    #[tokio::test]
    async fn offer_frame_carries_ws_uri_and_dsp_fields() {
        let json = captured_offer_json(&NgFlags {
            transport_protocol: Some("RTP/AVP".into()),
            replace: vec!["origin".into()],
            ws_uri: Some("wss://ai.example.com/stream/call-1".into()),
            ws_vad: true,
            ws_barge_in: true,
            ws_vad_threshold: Some(2_000_000),
            ws_vad_hangover_ms: Some(300),
            noise_suppression: true,
            echo_cancellation: true,
            rtcp_mux: vec!["require".into()],
            received_from: Some("198.51.100.7".parse().unwrap()),
            ..NgFlags::default()
        })
        .await;

        for expected in [
            r#""ws_uri":"wss://ai.example.com/stream/call-1""#,
            r#""ws_vad":true"#,
            r#""ws_barge_in":true"#,
            r#""ws_vad_threshold":2000000"#,
            r#""ws_vad_hangover_ms":300"#,
            r#""noise_suppression":true"#,
            r#""echo_cancellation":true"#,
            r#""rtcp_mux":["require"]"#,
            r#""received_from":"198.51.100.7""#,
        ] {
            assert!(
                json.contains(expected),
                "offer frame missing {expected}\nframe was: {json}"
            );
        }
    }

    /// The no-wire-drift guard.  A profile that sets none of the new fields must
    /// serialise to exactly the bytes it did before they existed, so no existing
    /// deployment sees its offer change.  Asserted as the whole frame, not a
    /// substring — a spurious `"ws_vad":false` would slip past a `contains`.
    #[tokio::test]
    async fn offer_frame_without_new_fields_is_byte_identical() {
        let json = captured_offer_json(&NgFlags {
            transport_protocol: Some("RTP/AVP".into()),
            ice: Some("remove".into()),
            replace: vec!["origin".into()],
            flags: vec!["trust-address".into()],
            direction: vec!["external".into(), "internal".into()],
            ..NgFlags::default()
        })
        .await;

        assert_eq!(
            json,
            concat!(
                r#"{"id":1,"command":"offer","call_id":"call-1","from_tag":"tag-a","#,
                r#""sdp":"v=0\r\n","profile":{"transport_protocol":"RTP/AVP","ice":"remove","#,
                r#""replace":["origin"],"flags":["trust-address"],"#,
                r#""direction":["external","internal"]}}"#,
            )
        );
    }

    /// `carry_received_from` is siphon-side policy.  Setting it without an
    /// injected address must not add a field to the frame.
    #[tokio::test]
    async fn offer_frame_omits_received_from_when_only_policy_is_set() {
        let json = captured_offer_json(&NgFlags {
            carry_received_from: true,
            ..NgFlags::default()
        })
        .await;
        assert!(
            !json.contains("received_from"),
            "policy bit leaked onto the wire: {json}"
        );
    }

    /// Every field, not just the ones that happened to be wired.
    ///
    /// The earlier version of this test asserted only the nine fields
    /// `profile_flags_from_ng` copied, so it stayed green for as long as the
    /// WebSocket-bridge fields were dropped by a `..ProfileFlags::default()`
    /// tail.  Asserting the whole struct is what makes "every field" mean it —
    /// compare against a fully-populated expected value so a newly-added proto
    /// field cannot pass by being defaulted on both sides.
    /// The text increment must reach the script byte-for-byte, U+FFFD markers
    /// included — they are how a consumer sees where loss occurred (RFC 4103
    /// §5.3), so a conversion that scrubbed them would hide the gap.
    #[test]
    fn convert_event_text_is_field_exact() {
        let event = Event::Text {
            call_id: "call-77".into(),
            from_tag: "caller-tag".into(),
            to_tag: Some("callee-tag".into()),
            text: "hel\u{fffd}o".into(),
            direction: Some("a_to_b".into()),
        };
        match convert_event(event) {
            RtpEngineEvent::Text(text_event) => {
                assert_eq!(text_event.call_id, "call-77");
                assert_eq!(text_event.from_tag, "caller-tag");
                assert_eq!(text_event.to_tag.as_deref(), Some("callee-tag"));
                assert_eq!(text_event.text, "hel\u{fffd}o");
                assert_eq!(text_event.direction.as_deref(), Some("a_to_b"));
            }
            other => panic!("expected a text event, got {other:?}"),
        }
    }

    /// An engine that reported no text stream for the leg must leave the field
    /// absent, not synthesise a zeroed one — a media CDR carrying
    /// `text_packets=0` for an audio-only call reads as a text stream that
    /// carried nothing, which is a different claim.
    #[test]
    fn convert_leg_summary_carries_text_stats_only_when_measured() {
        let with_text = ProtoLegSummary {
            tag: "near".into(),
            codec: Some("PCMU".into()),
            packets_in: 10,
            bytes_in: 100,
            packets_out: 10,
            bytes_out: 100,
            packets_dropped: 0,
            ssrc: None,
            packets_lost: None,
            loss_percent: None,
            jitter_ms: None,
            rtt_ms: None,
            mos_average: None,
            mos_min: None,
            mos_max: None,
            mos_basis: None,
            text: Some(siphon_rtp_proto::TextStreamStats {
                packets: 12,
                characters: 41,
                missing_markers: 2,
                recovered_from_redundancy: 3,
            }),
        };
        let converted = convert_leg_summary(with_text.clone());
        let stats = converted.text.expect("text stats carried");
        assert_eq!(stats.packets, 12);
        assert_eq!(stats.characters, 41);
        assert_eq!(stats.missing_markers, 2);
        assert_eq!(stats.recovered_from_redundancy, 3);

        let audio_only = ProtoLegSummary {
            text: None,
            ..with_text
        };
        assert!(convert_leg_summary(audio_only).text.is_none());
    }

    #[test]
    fn profile_flags_from_ng_maps_every_field() {
        let ng = NgFlags {
            transport_protocol: Some("RTP/SAVPF".into()),
            codec: Default::default(),
            ice: Some("force".into()),
            dtls: Some("passive".into()),
            replace: vec!["origin".into()],
            address_family: Some("IP4".into()),
            flags: vec!["trust-address".into(), "symmetric".into()],
            direction: vec!["external".into(), "internal".into()],
            record_call: true,
            record_path: Some("/var/spool".into()),
            noise_suppression: true,
            echo_cancellation: true,
            ws_uri: Some("wss://ai.invalid/stream".into()),
            ws_vad: true,
            ws_barge_in: true,
            ws_vad_threshold: Some(2_000_000),
            ws_vad_hangover_ms: Some(300),
            ws_sample_rate: Some(24_000),
            ws_vad_engine: Some(WsVadEngine::Neural),
            ws_vad_min_speech_ms: Some(80),
            beep_detection: true,
            beep_cadence_guard_ms: Some(3_000),
            ws_tee: Some("wss://asr.invalid/tee".into()),
            ws_tee_direction: Some(WsTeeDirection::Callee),
            ws_tee_channels: Some(1),
            ws_tee_sample_rate: Some(16_000),
            carry_received_from: true,
            received_from: Some("198.51.100.7".parse().unwrap()),
            rtcp_mux: vec!["require".into()],
            text_events: true,
        };

        let expected = ProfileFlags {
            transport_protocol: Some("RTP/SAVPF".into()),
            ice: Some("force".into()),
            dtls: Some("passive".into()),
            replace: vec!["origin".into()],
            address_family: Some("IP4".into()),
            flags: vec!["trust-address".into(), "symmetric".into()],
            direction: vec!["external".into(), "internal".into()],
            record_call: true,
            record_path: Some("/var/spool".into()),
            noise_suppression: true,
            echo_cancellation: true,
            ws_uri: Some("wss://ai.invalid/stream".into()),
            ws_vad: true,
            ws_barge_in: true,
            ws_vad_threshold: Some(2_000_000),
            ws_vad_hangover_ms: Some(300),
            ws_sample_rate: Some(24_000),
            ws_vad_engine: Some(ProtoWsVadEngine::Neural),
            ws_vad_min_speech_ms: Some(80),
            beep_detection: true,
            beep_cadence_guard_ms: Some(3_000),
            ws_tee: Some("wss://asr.invalid/tee".into()),
            ws_tee_direction: Some(ProtoWsTeeDirection::Callee),
            ws_tee_channels: Some(1),
            ws_tee_sample_rate: Some(16_000),
            received_from: Some("198.51.100.7".parse().unwrap()),
            rtcp_mux: vec!["require".into()],
            text_events: true,
        };

        assert_eq!(profile_flags_from_ng(&ng), expected);
    }

    /// Each new 0.3.0 profile field must reach the **wire**, not merely the
    /// struct.  All six carry `skip_serializing_if`, so a field siphon forgot to
    /// populate is indistinguishable from one it deliberately left unset when
    /// you compare structs — only the emitted JSON tells them apart.
    #[test]
    fn new_profile_fields_reach_the_json_wire() {
        let ng = NgFlags {
            ws_uri: Some("wss://ai.invalid/stream".into()),
            ws_vad: true,
            ws_sample_rate: Some(16_000),
            ws_vad_engine: Some(WsVadEngine::Neural),
            ws_vad_min_speech_ms: Some(80),
            beep_detection: true,
            beep_cadence_guard_ms: Some(3_000),
            ws_tee: Some("wss://asr.invalid/tee".into()),
            ws_tee_sample_rate: Some(48_000),
            ..NgFlags::default()
        };

        let json = serde_json::to_value(profile_flags_from_ng(&ng)).expect("serialize profile");

        assert_eq!(json["ws_sample_rate"], 16_000);
        assert_eq!(json["ws_vad_engine"], "neural");
        assert_eq!(json["ws_vad_min_speech_ms"], 80);
        assert_eq!(json["beep_detection"], true);
        assert_eq!(json["beep_cadence_guard_ms"], 3_000);
        assert_eq!(json["ws_tee_sample_rate"], 48_000);
    }

    /// The mirror of the test above: an unset field must be *absent* from the
    /// wire, not present as a zero/null.  This is what keeps the default profile
    /// serialising to `{}` and an older engine seeing a byte-identical command.
    #[test]
    fn unset_profile_fields_are_omitted_from_the_wire() {
        let json =
            serde_json::to_value(profile_flags_from_ng(&NgFlags::default())).expect("serialize");

        for field in [
            "ws_sample_rate",
            "ws_vad_engine",
            "ws_vad_min_speech_ms",
            "beep_detection",
            "beep_cadence_guard_ms",
            "ws_tee_sample_rate",
        ] {
            assert!(
                json.get(field).is_none(),
                "{field} must be omitted when unset, got {:?}",
                json.get(field)
            );
        }
        assert_eq!(json, serde_json::json!({}), "default profile must be empty");
    }

    /// `energy` is the engine's own default, so siphon must still emit it
    /// explicitly when a profile names it — otherwise a profile that pinned the
    /// cheap detector would be indistinguishable from one that expressed no
    /// preference, and a future change of engine default would silently move it.
    #[test]
    fn ws_vad_engine_energy_is_emitted_not_elided() {
        let ng = NgFlags {
            ws_vad_engine: Some(WsVadEngine::Energy),
            ..NgFlags::default()
        };
        let json = serde_json::to_value(profile_flags_from_ng(&ng)).expect("serialize");
        assert_eq!(json["ws_vad_engine"], "energy");
    }

    #[test]
    fn beep_detected_event_converts_field_for_field() {
        let converted = convert_event(Event::BeepDetected {
            call_id: "call-beep-1".into(),
            from_tag: "callee-tag".into(),
            to_tag: Some("caller-tag".into()),
            frequency_hz: 1_000.5,
            duration_ms: 420,
            offset_ms: 7_300,
        });

        let RtpEngineEvent::BeepDetected(beep) = converted else {
            panic!("expected a BeepDetected event");
        };
        assert_eq!(beep.call_id, "call-beep-1");
        assert_eq!(beep.from_tag, "callee-tag");
        assert_eq!(beep.to_tag.as_deref(), Some("caller-tag"));
        assert!((beep.frequency_hz - 1_000.5).abs() < f32::EPSILON);
        assert_eq!(beep.duration_ms, 420);
        // The offset of the *tone*, not of the event — the event trails it by
        // the cadence guard, so this must be carried through untouched.
        assert_eq!(beep.offset_ms, 7_300);
    }

    /// A `to_tag`-less beep (the common single-leg case, where the field is
    /// skipped on the wire) must still convert.
    #[test]
    fn beep_detected_event_without_to_tag_converts() {
        let converted = convert_event(Event::BeepDetected {
            call_id: "call-beep-2".into(),
            from_tag: "callee-tag".into(),
            to_tag: None,
            frequency_hz: 425.0,
            duration_ms: 250,
            offset_ms: 1_200,
        });

        let RtpEngineEvent::BeepDetected(beep) = converted else {
            panic!("expected a BeepDetected event");
        };
        assert!(beep.to_tag.is_none());
    }

    /// Both new play sources must reach the wire under the tagged shape the
    /// engine reads (`{"source": "...", ...}`).
    #[test]
    fn tone_and_http_play_sources_reach_the_wire() {
        let tone = serde_json::to_value(proto_play_source(&PlayMediaSource::Tone(
            "425/1000,0/4000*inf".into(),
        )))
        .expect("serialize tone");
        assert_eq!(tone["source"], "tone");
        assert_eq!(tone["tone"], "425/1000,0/4000*inf");

        let preset =
            serde_json::to_value(proto_play_source(&PlayMediaSource::Tone("ringback_eu".into())))
                .expect("serialize preset");
        assert_eq!(preset["source"], "tone");
        assert_eq!(preset["tone"], "ringback_eu");

        let http = serde_json::to_value(proto_play_source(&PlayMediaSource::Http(
            "https://prompts.invalid/welcome.wav".into(),
        )))
        .expect("serialize http");
        assert_eq!(http["source"], "http");
        assert_eq!(http["url"], "https://prompts.invalid/welcome.wav");
    }

    /// `set_play_gain` addresses a running playback by its `play_id`; the wire
    /// shape is what the engine matches on.
    #[test]
    fn set_play_gain_command_wire_shape() {
        let json = serde_json::to_value(Command::SetPlayGain {
            call_id: "call-gain".into(),
            from_tag: "leg-a".into(),
            play_id: 4,
            gain_decibels: -18,
            to_tag: None,
        })
        .expect("serialize set_play_gain");

        assert_eq!(json["play_id"], 4);
        assert_eq!(json["gain_decibels"], -18);
        assert!(json.get("to_tag").is_none(), "unset to_tag must be omitted");
    }

    /// An overlay play and a targeted stop both travel by `play_id`.
    #[test]
    fn overlay_and_targeted_stop_wire_shape() {
        let play = serde_json::to_value(Command::PlayMedia {
            call_id: "call-overlay".into(),
            from_tag: "leg-a".into(),
            source: ProtoPlayMediaSource::Tone {
                tone: "ringback_eu".into(),
            },
            repeat_times: None,
            start_pos_ms: None,
            duration_ms: None,
            overlay: true,
            gain_decibels: Some(-12),
            to_tag: None,
        })
        .expect("serialize play_media");
        assert_eq!(play["overlay"], true);
        assert_eq!(play["gain_decibels"], -12);

        let stop = serde_json::to_value(Command::StopMedia {
            call_id: "call-overlay".into(),
            from_tag: "leg-a".into(),
            play_id: Some(4),
        })
        .expect("serialize stop_media");
        assert_eq!(stop["play_id"], 4);

        // A supersede play and an untargeted stop must stay byte-identical to
        // what a pre-0.3.0 engine saw.
        let plain_stop = serde_json::to_value(Command::StopMedia {
            call_id: "call-overlay".into(),
            from_tag: "leg-a".into(),
            play_id: None,
        })
        .expect("serialize stop_media");
        assert!(plain_stop.get("play_id").is_none());
    }

    /// The WS tee's wire rate is a distinct knob from the takeover bridge's.
    #[test]
    fn attach_ws_tee_carries_sample_rate() {
        let json = serde_json::to_value(Command::AttachWsTee {
            call_id: "call-tee".into(),
            from_tag: "leg-a".into(),
            ws_uri: "wss://asr.invalid/tee".into(),
            direction: ProtoWsTeeDirection::Both,
            channels: Some(2),
            sample_rate: Some(16_000),
        })
        .expect("serialize attach_ws_tee");
        assert_eq!(json["sample_rate"], 16_000);
    }

    /// `carry_received_from` is siphon-side policy, not a wire field: on its own
    /// it must change nothing.  Only the injected address is emitted.
    #[test]
    fn profile_flags_from_ng_ignores_received_from_policy_without_address() {
        let ng = NgFlags {
            carry_received_from: true,
            ..NgFlags::default()
        };
        assert_eq!(profile_flags_from_ng(&ng), ProfileFlags::default());
    }

    /// The no-wire-drift guard: a profile setting none of the new fields must
    /// convert to exactly the default `ProfileFlags`, so every existing
    /// deployment's emitted JSON is unchanged.
    #[test]
    fn profile_flags_from_ng_default_is_wire_identical() {
        assert_eq!(
            profile_flags_from_ng(&NgFlags::default()),
            ProfileFlags::default()
        );
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

    #[test]
    fn convert_event_ws_tee_started_carries_the_negotiated_wire_shape() {
        // The wire shape is the point: a consumer decodes the binary frames
        // from these values rather than guessing.
        match convert_event(Event::WsTeeStarted {
            call_id: "c".into(),
            from_tag: "f".into(),
            stream_id: "s-1".into(),
            ws_uri: "wss://asr.invalid/tee".into(),
            direction: ProtoWsTeeDirection::Caller,
            channels: 1,
            sample_rate: 16_000,
        }) {
            RtpEngineEvent::WsTeeStarted(tee) => {
                assert_eq!(tee.call_id, "c");
                assert_eq!(tee.from_tag, "f");
                assert_eq!(tee.stream_id, "s-1");
                assert_eq!(tee.ws_uri, "wss://asr.invalid/tee");
                assert_eq!(tee.direction, WsTeeDirection::Caller);
                assert_eq!(tee.channels, 1);
                assert_eq!(tee.sample_rate, 16_000);
            }
            other => panic!("expected WsTeeStarted, got {other:?}"),
        }
    }

    #[test]
    fn convert_event_ws_tee_ended_maps_every_reason() {
        // Each reason must survive the proto -> siphon hop with its wire
        // spelling intact: a script branches on this string.
        let cases = [
            (ProtoWsTeeEndReason::Detached, "detached", false),
            (ProtoWsTeeEndReason::ServerClosed, "server_closed", true),
            (ProtoWsTeeEndReason::ServerStopped, "server_stopped", true),
            (ProtoWsTeeEndReason::CallEnded, "call_ended", true),
            (ProtoWsTeeEndReason::TransportError, "transport_error", true),
        ];
        for (proto_reason, expected, expected_unexpected) in cases {
            match convert_event(Event::WsTeeEnded {
                call_id: "c".into(),
                from_tag: "f".into(),
                stream_id: "s-1".into(),
                reason: proto_reason,
                frames_sent: Some(4_200),
                frames_dropped: Some(3),
            }) {
                RtpEngineEvent::WsTeeEnded(tee) => {
                    assert_eq!(tee.stream_id, "s-1");
                    assert_eq!(tee.reason.as_str(), expected);
                    assert_eq!(tee.frames_sent, Some(4_200));
                    assert_eq!(tee.frames_dropped, Some(3));
                    // Only an explicit detach is an orderly end; everything else
                    // means audio stopped while the call is still up.
                    assert_eq!(
                        tee.reason.is_unexpected(),
                        expected_unexpected,
                        "{expected} classified wrongly"
                    );
                }
                other => panic!("expected WsTeeEnded, got {other:?}"),
            }
        }
    }

    #[test]
    fn convert_event_call_summary() {
        // A measured near leg (actor quality present) + a counters-only far leg
        // (no actor) — the two shapes the summary must carry through.
        let near = ProtoLegSummary {
            tag: "near-tag".into(),
            codec: Some("AMR-WB".into()),
            packets_in: 2100,
            bytes_in: 336_000,
            packets_out: 2098,
            bytes_out: 335_680,
            packets_dropped: 2,
            ssrc: Some(0xDEAD_BEEF),
            packets_lost: Some(6),
            loss_percent: Some(0.3),
            jitter_ms: Some(4.2),
            rtt_ms: Some(21.0),
            mos_average: Some(4.11),
            mos_min: Some(3.9),
            mos_max: Some(4.3),
            mos_basis: Some("full".into()),
            text: None,
        };
        let far = ProtoLegSummary {
            tag: "far-tag".into(),
            codec: Some("PCMU".into()),
            packets_in: 2099,
            bytes_in: 335_840,
            packets_out: 2100,
            bytes_out: 336_000,
            packets_dropped: 0,
            ssrc: None,
            packets_lost: None,
            loss_percent: None,
            jitter_ms: None,
            rtt_ms: None,
            mos_average: None,
            mos_min: None,
            mos_max: None,
            mos_basis: None,
            text: None,
        };
        match convert_event(Event::CallSummary {
            call_id: "call-9".into(),
            reason: "delete".into(),
            duration_ms: 42_000,
            legs: vec![near, far],
        }) {
            RtpEngineEvent::CallSummary(summary) => {
                assert_eq!(summary.call_id, "call-9");
                assert_eq!(summary.reason, "delete");
                assert_eq!(summary.duration_ms, 42_000);
                assert_eq!(summary.legs.len(), 2);

                let near = &summary.legs[0];
                assert_eq!(near.tag, "near-tag");
                assert_eq!(near.codec.as_deref(), Some("AMR-WB"));
                assert_eq!(near.packets_in, 2100);
                assert_eq!(near.bytes_out, 335_680);
                assert_eq!(near.packets_dropped, 2);
                assert_eq!(near.ssrc, Some(0xDEAD_BEEF));
                assert_eq!(near.packets_lost, Some(6));
                assert_eq!(near.loss_percent, Some(0.3));
                assert_eq!(near.jitter_ms, Some(4.2));
                assert_eq!(near.rtt_ms, Some(21.0));
                assert_eq!(near.mos_average, Some(4.11));
                assert_eq!(near.mos_basis.as_deref(), Some("full"));

                let far = &summary.legs[1];
                assert_eq!(far.tag, "far-tag");
                assert_eq!(far.codec.as_deref(), Some("PCMU"));
                assert_eq!(far.ssrc, None);
                assert_eq!(far.packets_lost, None);
                assert_eq!(far.mos_average, None);
                assert_eq!(far.mos_basis, None);
            }
            other => panic!("expected CallSummary, got {other:?}"),
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

    /// The engine-facing twin of the rtpengine `"address family"` NG key: on this
    /// backend the family rides the offer's `profile.address_family` JSON field.
    /// Asserted on the raw frame so a rename or a drop in the mapping shows up as
    /// a wire change, not just a struct-field change.
    #[tokio::test]
    async fn offer_carries_address_family_on_the_wire() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (frame_tx, frame_rx) = oneshot::channel();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = Vec::new();
            // Decode as raw JSON rather than `Request` so the assertion is on the
            // wire shape the engine actually parses.
            let raw: serde_json::Value = read_frame(&mut stream, &mut buffer).await;
            let _ = frame_tx.send(raw);
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
            tokio::time::sleep(Duration::from_millis(200)).await;
        });

        let (event_tx, _event_rx) = channel();
        let client = SiphonRtpClient::new(address, None, 2000, 5_000, event_tx);
        let flags = NgFlags {
            address_family: Some("IP6".into()),
            ..NgFlags::default()
        };
        client
            .offer("call-af", "tag-a", b"v=0\r\n", &flags)
            .await
            .unwrap();

        let raw = frame_rx.await.unwrap();
        assert_eq!(raw["command"], "offer");
        assert_eq!(raw["profile"]["address_family"], "IP6");
    }

    /// Absent by default — anchoring a plain call must not pin a relay family.
    #[tokio::test]
    async fn offer_omits_address_family_when_unset() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (frame_tx, frame_rx) = oneshot::channel();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = Vec::new();
            let raw: serde_json::Value = read_frame(&mut stream, &mut buffer).await;
            let _ = frame_tx.send(raw);
            write_frame(
                &mut stream,
                &Response {
                    id: 1,
                    result: CmdResult::Ok {
                        sdp: Some("v=0\r\n".into()),
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
        client
            .offer("call-af", "tag-a", b"v=0\r\n", &NgFlags::default())
            .await
            .unwrap();

        let raw = frame_rx.await.unwrap();
        assert!(raw["profile"]["address_family"].is_null());
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
            .play_media("call-play", "tag-a", &play_source(), None, None, None, None, false, None, true)
            .await
            .unwrap();
        assert_eq!(played.duration_ms, Some(1234));
        // The handle must survive alongside the duration so a caller can still
        // stop or retune the playback it just started.
        assert_eq!(played.play_id, Some(7));
    }

    #[tokio::test]
    async fn play_media_wait_returns_none_when_stopped() {
        // Ended early (stopped / superseded) → the prompt didn't play out → None.
        let address = spawn_play_server(8, Some((PlayEndReason::Stopped, Some(400)))).await;
        let (event_tx, _event_rx) = channel();
        let client = SiphonRtpClient::new(address, None, 2000, 5_000, event_tx);
        let played = client
            .play_media("call-play", "tag-a", &play_source(), None, None, None, None, false, None, true)
            .await
            .unwrap();
        assert_eq!(played.duration_ms, None);
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
            client.play_media("call-play", "tag-a", &play_source(), None, None, None, None, false, None, false),
        )
        .await
        .expect("play_media(wait=false) must return on accept, not block")
        .unwrap();
        assert_eq!(played.duration_ms, None);
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
            client.play_media("call-play", "tag-a", &play_source(), None, None, None, None, false, None, true),
        )
        .await
        .expect("play_media must give up at the fallback timeout, not hang")
        .unwrap();
        assert_eq!(played.duration_ms, None);
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
    async fn answer_local_returns_answer_sdp_and_records_session() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = Vec::new();
            let request: Request = read_frame(&mut stream, &mut buffer).await;
            match request.command {
                Command::AnswerLocal {
                    call_id,
                    from_tag,
                    profile,
                    ..
                } => {
                    assert_eq!(call_id, "call-al");
                    assert_eq!(from_tag, "tag-a");
                    assert_eq!(profile.transport_protocol.as_deref(), Some("RTP/AVP"));
                }
                other => panic!("expected AnswerLocal, got {other:?}"),
            }
            write_frame(
                &mut stream,
                &Response {
                    id: request.id,
                    result: CmdResult::Ok {
                        sdp: Some("v=0\r\nm=audio 40000 RTP/AVP 8 101\r\n".into()),
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
        let flags = NgFlags {
            transport_protocol: Some("RTP/AVP".into()),
            ..NgFlags::default()
        };
        let sdp = client
            .answer_local("call-al", "tag-a", "v=0\r\n", &flags)
            .await
            .unwrap();
        assert!(sdp.contains("m=audio"));
        // Mirrors offer's bookkeeping: a single-leg answer establishes a session.
        assert_eq!(client.active_sessions(), 1);
    }

    #[tokio::test]
    async fn answer_local_no_encodable_codec_maps_to_engine_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = Vec::new();
            let request: Request = read_frame(&mut stream, &mut buffer).await;
            assert!(matches!(request.command, Command::AnswerLocal { .. }));
            write_frame(
                &mut stream,
                &Response {
                    id: request.id,
                    result: CmdResult::Error {
                        reason: "no-encodable-codec".into(),
                    },
                },
            )
            .await;
            tokio::time::sleep(Duration::from_millis(200)).await;
        });

        let (event_tx, _event_rx) = channel();
        let client = SiphonRtpClient::new(address, None, 2000, 5_000, event_tx);
        let error = client
            .answer_local("call-al", "tag-a", "v=0\r\n", &NgFlags::default())
            .await
            .unwrap_err();
        match error {
            RtpEngineError::EngineError(reason) => assert_eq!(reason, "no-encodable-codec"),
            other => panic!("expected EngineError(no-encodable-codec), got {other:?}"),
        }
        // No session recorded on failure — the SDP arm never runs.
        assert_eq!(client.active_sessions(), 0);
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
