//! The **SIP facade** over the protocol-agnostic core.
//!
//! [`Call`] is a typed handle whose verbs (`answer`/`progress`/`hangup`/`refer`/
//! …) are thin wrappers that send `command("sip", …)` on the underlying core and
//! await the correlated reply. The `StasisStart`→[`Call`] dispatch and the
//! `on_call` handler live here (they are SIP/ARI concepts) on top of the core's
//! generic event stream, so a future `smpp::Session` / `ss7::Dialog` is an
//! additive sibling module over the same core.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard};

use futures_util::future::BoxFuture;
use serde_json::json;
use tokio::sync::{mpsc, Mutex as AsyncMutex};
use tracing::{debug, warn};

use siphon_control_proto::sip::{
    ChannelDtmfPayload, PlayStartedPayload, SipEvent, SipVerb, TransferOutcomePayload,
    TransferRequestedPayload,
};
use siphon_control_proto::verbs::MODULE_SIP;
use siphon_control_proto::{ChannelSnapshot, EventFrame};

use crate::client::{ClientConfig, ClientEvent, ControlClient};
use crate::error::ControlError;
use crate::server::{ControlServer, ServerConfig};
use crate::session::CommandTransport;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

// ---------------------------------------------------------------------------
// route() target
// ---------------------------------------------------------------------------

/// One entry in a [`Call::route`] target list: a B-leg URI plus optional
/// per-target overrides.
///
/// A bare URI (no overrides) serializes to a plain string on the wire; a target
/// carrying any override serializes to `{uri, next_hop?, headers?, timeout?}` —
/// both shapes the server's `route` verb accepts. Build a bare-URI target with
/// [`RouteTarget::uri`], or from a `&str` / `String`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RouteTarget {
    /// The B-leg request URI to dial.
    pub uri: String,
    /// Route egress to this next hop instead of resolving `uri` (optional).
    pub next_hop: Option<String>,
    /// Headers injected on this attempt's B-leg INVITE (optional).
    pub headers: Vec<(String, String)>,
    /// Per-target ring timeout in seconds (optional).
    pub timeout_secs: Option<u32>,
}

impl RouteTarget {
    /// A bare-URI target with no overrides.
    pub fn uri(uri: impl Into<String>) -> Self {
        Self {
            uri: uri.into(),
            next_hop: None,
            headers: Vec::new(),
            timeout_secs: None,
        }
    }

    /// True when this target carries no overrides (serializes as a bare string).
    fn is_bare(&self) -> bool {
        self.next_hop.is_none() && self.headers.is_empty() && self.timeout_secs.is_none()
    }

    fn to_json(&self) -> serde_json::Value {
        if self.is_bare() {
            return json!(self.uri);
        }
        let mut object = serde_json::Map::new();
        object.insert("uri".to_string(), json!(self.uri));
        if let Some(next_hop) = &self.next_hop {
            object.insert("next_hop".to_string(), json!(next_hop));
        }
        if !self.headers.is_empty() {
            object.insert("headers".to_string(), headers_to_json(&self.headers));
        }
        if let Some(timeout) = self.timeout_secs {
            object.insert("timeout".to_string(), json!(timeout));
        }
        serde_json::Value::Object(object)
    }
}

impl From<&str> for RouteTarget {
    fn from(uri: &str) -> Self {
        Self::uri(uri)
    }
}

impl From<String> for RouteTarget {
    fn from(uri: String) -> Self {
        Self::uri(uri)
    }
}

fn headers_to_json(headers: &[(String, String)]) -> serde_json::Value {
    let mut object = serde_json::Map::new();
    for (name, value) in headers {
        object.insert(name.clone(), json!(value));
    }
    serde_json::Value::Object(object)
}

// ---------------------------------------------------------------------------
// play() source + options
// ---------------------------------------------------------------------------

/// The audio source for [`Call::play`]: exactly one of a server-side file path,
/// an rtpengine media-DB id, or an inline blob.
///
/// A `Blob` is base64-encoded on the wire (the control rail is JSON text), so the
/// caller passes raw bytes and this handle does the encoding — mirroring the
/// in-process `rtpengine.play_media(file=…|db_id=…|blob=…)` mutual exclusion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlaySource {
    /// A file path readable by the media engine.
    File(String),
    /// An id of a prompt in rtpengine's media DB.
    DbId(u64),
    /// Raw audio bytes played inline (base64-encoded on the wire).
    Blob(Vec<u8>),
}

impl PlaySource {
    /// Play a server-side file by path.
    pub fn file(path: impl Into<String>) -> Self {
        Self::File(path.into())
    }

    /// Play a prompt by its rtpengine media-DB id.
    pub fn db_id(id: u64) -> Self {
        Self::DbId(id)
    }

    /// Play raw audio bytes inline (base64-encoded on the wire).
    pub fn blob(bytes: impl Into<Vec<u8>>) -> Self {
        Self::Blob(bytes.into())
    }

    /// Insert the one source arg (`file` / `db_id` / `blob`) into a play args map.
    fn insert_into(&self, args: &mut serde_json::Map<String, serde_json::Value>) {
        match self {
            PlaySource::File(path) => {
                args.insert("file".to_string(), json!(path));
            }
            PlaySource::DbId(id) => {
                args.insert("db_id".to_string(), json!(id));
            }
            PlaySource::Blob(bytes) => {
                use base64::Engine as _;
                let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
                args.insert("blob".to_string(), json!(encoded));
            }
        }
    }
}

/// Optional shaping for [`Call::play`] (all default to the engine's behaviour).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PlayOptions {
    /// Repeat the prompt this many times (0/None → play once).
    pub repeat: Option<u64>,
    /// Start playback at this offset into the source, in milliseconds.
    pub start_ms: Option<u64>,
    /// Cap playback to this duration, in milliseconds.
    pub duration_ms: Option<u64>,
    /// Scope the prompt to one peer of an MPTY bridge (its To-tag).
    pub to_tag: Option<String>,
}

impl PlayOptions {
    fn insert_into(&self, args: &mut serde_json::Map<String, serde_json::Value>) {
        if let Some(repeat) = self.repeat {
            args.insert("repeat".to_string(), json!(repeat));
        }
        if let Some(start_ms) = self.start_ms {
            args.insert("start_ms".to_string(), json!(start_ms));
        }
        if let Some(duration_ms) = self.duration_ms {
            args.insert("duration_ms".to_string(), json!(duration_ms));
        }
        if let Some(to_tag) = &self.to_tag {
            args.insert("to_tag".to_string(), json!(to_tag));
        }
    }
}

/// Optional shaping for [`Call::dtmf`] (all default to the engine's behaviour).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DtmfOptions {
    /// Per-digit tone duration, in milliseconds.
    pub duration_ms: Option<u64>,
    /// Tone volume in dBm0 (negative).
    pub volume_dbm0: Option<i64>,
    /// Inter-digit pause, in milliseconds.
    pub pause_ms: Option<u64>,
    /// Scope the tones to one peer of an MPTY bridge (its To-tag).
    pub to_tag: Option<String>,
}

impl DtmfOptions {
    fn insert_into(&self, args: &mut serde_json::Map<String, serde_json::Value>) {
        if let Some(duration_ms) = self.duration_ms {
            args.insert("duration_ms".to_string(), json!(duration_ms));
        }
        if let Some(volume_dbm0) = self.volume_dbm0 {
            args.insert("volume_dbm0".to_string(), json!(volume_dbm0));
        }
        if let Some(pause_ms) = self.pause_ms {
            args.insert("pause_ms".to_string(), json!(pause_ms));
        }
        if let Some(to_tag) = &self.to_tag {
            args.insert("to_tag".to_string(), json!(to_tag));
        }
    }
}

// ---------------------------------------------------------------------------
// Call handle
// ---------------------------------------------------------------------------

/// One event delivered to a call's stream (`ChannelStateChange`,
/// `ChannelHangupRequest`, `StasisEnd`, …).
#[derive(Debug, Clone)]
pub struct CallEvent {
    /// The parsed event kind.
    pub kind: SipEvent,
    /// The event-specific payload.
    pub payload: serde_json::Value,
    /// The raw frame (for fields not surfaced above).
    pub frame: EventFrame,
}

impl CallEvent {
    fn from_frame(frame: EventFrame) -> Self {
        Self {
            kind: frame.sip_kind(),
            payload: frame.payload.clone(),
            frame,
        }
    }

    /// The typed [`ChannelDtmfPayload`] when this is a
    /// [`SipEvent::ChannelDtmfReceived`] event, else `None`.
    pub fn dtmf(&self) -> Option<ChannelDtmfPayload> {
        if self.kind != SipEvent::ChannelDtmfReceived {
            return None;
        }
        serde_json::from_value(self.payload.clone()).ok()
    }

    /// The typed [`PlayStartedPayload`] when this is a [`SipEvent::PlayStarted`]
    /// event, else `None`.
    ///
    /// This is where a playback's start lives on the event stream. Its `play_id`
    /// is the same handle the `play` command reply carried, so a watchdog or a
    /// gain ramp driven off events correlates the two without a side table.
    pub fn play_started(&self) -> Option<PlayStartedPayload> {
        if self.kind != SipEvent::PlayStarted {
            return None;
        }
        serde_json::from_value(self.payload.clone()).ok()
    }

    /// The typed [`TransferRequestedPayload`] when this is a
    /// [`SipEvent::TransferRequested`] event, else `None`.
    pub fn transfer_requested(&self) -> Option<TransferRequestedPayload> {
        if self.kind != SipEvent::TransferRequested {
            return None;
        }
        serde_json::from_value(self.payload.clone()).ok()
    }

    /// The typed [`TransferOutcomePayload`] when this is a verdict on a transfer
    /// this app asked for ([`SipEvent::TransferProgress`],
    /// [`SipEvent::TransferCompleted`] or [`SipEvent::TransferFailed`]), else
    /// `None`.
    ///
    /// This — not the `refer` call's return value — is where a transfer's
    /// outcome lives: [`Call::refer`] resolves as soon as siphon has sent the
    /// REFER, because RFC 3515 §2.4.4 delivers the outcome afterwards on the
    /// implicit subscription.
    pub fn transfer_outcome(&self) -> Option<TransferOutcomePayload> {
        if !matches!(
            self.kind,
            SipEvent::TransferProgress | SipEvent::TransferCompleted | SipEvent::TransferFailed
        ) {
            return None;
        }
        serde_json::from_value(self.payload.clone()).ok()
    }

    /// Whether this event ends a transfer this app asked for — exactly one such
    /// event arrives per `refer`, so this is the signal to stop waiting.
    pub fn is_transfer_final(&self) -> bool {
        matches!(
            self.kind,
            SipEvent::TransferCompleted | SipEvent::TransferFailed
        )
    }
}

struct CallInner {
    commander: Arc<dyn CommandTransport>,
    channel_id: String,
    call_id: Option<String>,
    sip_call_id: Option<String>,
    app: Option<String>,
    payload: serde_json::Value,
    reattached: bool,
    events: AsyncMutex<mpsc::UnboundedReceiver<CallEvent>>,
}

/// A handed-over SIP call. Cheap to clone (shares one connection + event stream).
#[derive(Clone)]
pub struct Call {
    inner: Arc<CallInner>,
}

impl Call {
    fn from_event(
        commander: Arc<dyn CommandTransport>,
        frame: &EventFrame,
        events: mpsc::UnboundedReceiver<CallEvent>,
        reattached: bool,
    ) -> Self {
        Self {
            inner: Arc::new(CallInner {
                commander,
                channel_id: frame.channel.clone().unwrap_or_default(),
                call_id: frame.call_id.clone(),
                sip_call_id: frame.sip_call_id.clone(),
                app: frame.app.clone(),
                payload: frame.payload.clone(),
                reattached,
                events: AsyncMutex::new(events),
            }),
        }
    }

    fn from_snapshot(
        commander: Arc<dyn CommandTransport>,
        snapshot: ChannelSnapshot,
        events: mpsc::UnboundedReceiver<CallEvent>,
    ) -> Self {
        let payload = serde_json::to_value(&snapshot).unwrap_or(serde_json::Value::Null);
        Self {
            inner: Arc::new(CallInner {
                commander,
                channel_id: snapshot.channel,
                call_id: Some(snapshot.call_id),
                sip_call_id: Some(snapshot.sip_call_id),
                app: None,
                payload,
                reattached: true,
                events: AsyncMutex::new(events),
            }),
        }
    }

    // --- identity / context ------------------------------------------------

    /// The leg-scoped channel id — the address for every verb on this call.
    pub fn channel_id(&self) -> &str {
        &self.inner.channel_id
    }

    /// The internal `CallActor` id (the grouping key across legs), if known.
    pub fn call_id(&self) -> Option<&str> {
        self.inner.call_id.as_deref()
    }

    /// The per-leg SIP `Call-ID` — byte-identical to the CDR / HEP join key.
    pub fn sip_call_id(&self) -> Option<&str> {
        self.inner.sip_call_id.as_deref()
    }

    /// The application this call was handed to.
    pub fn app(&self) -> Option<&str> {
        self.inner.app.as_deref()
    }

    /// The `StasisStart` payload (full SIP context) — or the `resync` snapshot
    /// when [`Call::is_reattached`] is true.
    pub fn payload(&self) -> &serde_json::Value {
        &self.inner.payload
    }

    /// True when this call came from a `resync` re-attach after a reconnect.
    pub fn is_reattached(&self) -> bool {
        self.inner.reattached
    }

    fn target(&self) -> serde_json::Value {
        json!({ "channel": self.inner.channel_id })
    }

    async fn sip(&self, verb: SipVerb, args: serde_json::Value) -> Result<serde_json::Value, ControlError> {
        self.inner
            .commander
            .command(Some(MODULE_SIP.to_string()), verb.as_str().to_string(), self.target(), args)
            .await
    }

    // --- SIP verbs ---------------------------------------------------------

    /// Send a UAS 2xx (default `200 OK`) to the parked A-leg.
    pub async fn answer(&self) -> Result<(), ControlError> {
        self.sip(SipVerb::Answer, json!({})).await.map(drop)
    }

    /// Send a UAS 2xx with an explicit code / reason / body.
    pub async fn answer_with(
        &self,
        code: u16,
        reason: Option<&str>,
        body: Option<&str>,
        content_type: Option<&str>,
    ) -> Result<(), ControlError> {
        self.sip(SipVerb::Answer, response_args(code, reason, body, content_type))
            .await
            .map(drop)
    }

    /// Send `180 Ringing`: alerting only, no early media.
    ///
    /// RFC 3261 §13.2.1 makes the 180 the "callee is being alerted" signal, and
    /// RFC 3960 §3.1 puts early media on a response that carries SDP — two
    /// different acts, so two verbs. Ring for as long as your own policy says,
    /// then [`Call::answer`]; open an early-media path with [`Call::progress`].
    pub async fn ring(&self) -> Result<(), ControlError> {
        self.sip(SipVerb::Ring, json!({})).await.map(drop)
    }

    /// [`Call::ring`] with an explicit reason phrase.
    pub async fn ring_with_reason(&self, reason: &str) -> Result<(), ControlError> {
        self.sip(SipVerb::Ring, json!({ "reason": reason })).await.map(drop)
    }

    /// Send a UAS 1xx, optionally opening an early-media path (default
    /// `183 Session Progress`). For plain alerting use [`Call::ring`].
    pub async fn progress(&self) -> Result<(), ControlError> {
        self.sip(SipVerb::Progress, json!({})).await.map(drop)
    }

    /// Send a UAS 1xx with an explicit code / reason / body.
    pub async fn progress_with(
        &self,
        code: u16,
        reason: Option<&str>,
        body: Option<&str>,
        content_type: Option<&str>,
    ) -> Result<(), ControlError> {
        self.sip(SipVerb::Progress, response_args(code, reason, body, content_type))
            .await
            .map(drop)
    }

    /// Send a final non-2xx and tear the call down.
    pub async fn reject(&self, code: u16, reason: Option<&str>) -> Result<(), ControlError> {
        let mut args = json!({ "code": code });
        if let Some(reason) = reason {
            args["reason"] = json!(reason);
        }
        self.sip(SipVerb::Reject, args).await.map(drop)
    }

    /// Hang up: BYE an answered call, or reject an unanswered one.
    pub async fn hangup(&self) -> Result<(), ControlError> {
        self.sip(SipVerb::Hangup, json!({})).await.map(drop)
    }

    /// Hang up with a `Reason` header value.
    pub async fn hangup_with_reason(&self, reason: &str) -> Result<(), ControlError> {
        self.sip(SipVerb::Hangup, json!({ "reason": reason })).await.map(drop)
    }

    /// Send an in-dialog REFER on the A-leg (blind transfer).
    ///
    /// Resolves as soon as siphon has sent the REFER — `Ok(())` means *sent*,
    /// not *transferred*. RFC 3515 §2.4.4 delivers the outcome afterwards on the
    /// implicit subscription, so read it off the event stream: zero or more
    /// `TransferProgress`, then exactly one `TransferCompleted` /
    /// `TransferFailed`. [`CallEvent::transfer_outcome`] decodes them and
    /// [`CallEvent::is_transfer_final`] says when to stop waiting.
    pub async fn refer(&self, to: &str) -> Result<(), ControlError> {
        self.sip(SipVerb::Refer, json!({ "to": to })).await.map(drop)
    }

    /// Blind-transfer alias for [`Call::refer`].
    pub async fn transfer(&self, to: &str) -> Result<(), ControlError> {
        self.refer(to).await
    }

    /// Attended transfer — REFER with a `Replaces` triple (RFC 3891).
    pub async fn refer_replaces(
        &self,
        to: &str,
        call_id: &str,
        from_tag: &str,
        to_tag: &str,
        early_only: bool,
    ) -> Result<(), ControlError> {
        let args = json!({
            "to": to,
            "replaces": { "call_id": call_id, "from_tag": from_tag, "to_tag": to_tag, "early_only": early_only }
        });
        self.sip(SipVerb::Refer, args).await.map(drop)
    }

    /// Accept a *pending inbound* REFER (surfaced as a
    /// [`SipEvent::TransferRequested`] event) and run the transfer.
    ///
    /// `target` overrides the Refer-To URI (default: the event's target),
    /// `next_hop` steers egress without changing the URI shape, and `mode`
    /// (`"terminate"` / `"transparent"`) overrides `b2bua.default_refer_mode`.
    /// No pending REFER (already decided, timed out, or the call is gone) →
    /// [`ControlError`] with `code == "not_found"`.
    ///
    /// `profile` names the media profile for the pairing the transfer creates,
    /// and is **required when the call is anchored with a direction-bound
    /// profile** — one whose offer and answer halves describe different sides,
    /// such as `srtp_to_rtp` at an SRTP edge. A transfer moves the party that
    /// half was written for out of the call, so inheriting the profile
    /// re-offers *that party's* transport to whoever remains: SRTP toward a
    /// plain-RTP carrier, which answers `m=audio 0`. The call connects and
    /// carries no audio in either direction. Pass the profile for the pair that
    /// remains (commonly `"rtp_passthrough"`); `None` inherits, which is correct
    /// only for a symmetric profile.
    pub async fn accept_refer(
        &self,
        target: Option<&str>,
        next_hop: Option<&str>,
        mode: Option<&str>,
        profile: Option<&str>,
    ) -> Result<(), ControlError> {
        let mut args = serde_json::Map::new();
        if let Some(target) = target {
            args.insert("target".to_string(), json!(target));
        }
        if let Some(next_hop) = next_hop {
            args.insert("next_hop".to_string(), json!(next_hop));
        }
        if let Some(mode) = mode {
            args.insert("mode".to_string(), json!(mode));
        }
        if let Some(profile) = profile {
            args.insert("profile".to_string(), json!(profile));
        }
        self.sip(SipVerb::AcceptRefer, serde_json::Value::Object(args))
            .await
            .map(drop)
    }

    /// Reject a *pending inbound* REFER with a final non-2xx (default
    /// `603 Decline`). No pending REFER → `code == "not_found"`.
    pub async fn reject_refer(&self, code: u16, reason: Option<&str>) -> Result<(), ControlError> {
        let mut args = json!({ "code": code });
        if let Some(reason) = reason {
            args["reason"] = json!(reason);
        }
        self.sip(SipVerb::RejectRefer, args).await.map(drop)
    }

    /// Un-park this controlled call and dial the B-leg via siphon's LCR
    /// sequential-failover engine, returning control to siphon.
    ///
    /// `targets` is a non-empty ordered list of carriers tried cheapest-first: a
    /// bare URI ([`RouteTarget::uri`] / a `&str`) or a [`RouteTarget`] carrying
    /// `next_hop` / `headers` / `timeout_secs` overrides. `strategy` defaults to
    /// `"sequential"` when `None` (the server's default; v1 supports only
    /// `sequential`/`single` — anything else resolves to
    /// [`ControlError::is_unsupported_verb`]). `headers` is applied to every
    /// attempt's B-leg INVITE.
    ///
    /// On success siphon owns the call thereafter and the control app is
    /// released; the returned value is the reply `result`
    /// (`{channel, state: "routing", targets: N}`). An empty / invalid `targets`
    /// list resolves to a `bad_request` error, and a call that is already gone to
    /// `not_found`.
    pub async fn route(
        &self,
        targets: Vec<RouteTarget>,
        strategy: Option<&str>,
        headers: Vec<(String, String)>,
    ) -> Result<serde_json::Value, ControlError> {
        let mut args = json!({
            "targets": targets.iter().map(RouteTarget::to_json).collect::<Vec<_>>(),
        });
        if let Some(strategy) = strategy {
            args["strategy"] = json!(strategy);
        }
        if !headers.is_empty() {
            args["headers"] = headers_to_json(&headers);
        }
        self.sip(SipVerb::Route, args).await
    }

    /// Set a header on the stored A-leg INVITE.
    pub async fn set_header(&self, name: &str, value: &str) -> Result<(), ControlError> {
        self.sip(SipVerb::SetHeader, json!({ "name": name, "value": value }))
            .await
            .map(drop)
    }

    /// Read a header from the stored A-leg INVITE (`None` when absent).
    pub async fn get_header(&self, name: &str) -> Result<Option<String>, ControlError> {
        let result = self.sip(SipVerb::GetHeader, json!({ "name": name })).await?;
        Ok(string_value(&result))
    }

    /// Remove a header from the stored A-leg INVITE.
    pub async fn remove_header(&self, name: &str) -> Result<(), ControlError> {
        self.sip(SipVerb::RemoveHeader, json!({ "name": name }))
            .await
            .map(drop)
    }

    // --- per-call variables (substrate verbs, no module) -------------------

    /// Set a per-call variable (survives a reconnect via `resync`).
    pub async fn set_var(&self, key: &str, value: &str) -> Result<(), ControlError> {
        self.inner
            .commander
            .command(None, "set_var".to_string(), self.target(), json!({ "key": key, "value": value }))
            .await
            .map(drop)
    }

    /// Read a per-call variable (`None` when unset).
    pub async fn get_var(&self, key: &str) -> Result<Option<String>, ControlError> {
        let result = self
            .inner
            .commander
            .command(None, "get_var".to_string(), self.target(), json!({ "key": key }))
            .await?;
        Ok(string_value(&result))
    }

    // --- media -------------------------------------------------------------

    /// Play an announcement on the A-leg media (fire-and-forget).
    ///
    /// `source` is one of [`PlaySource::file`] / [`PlaySource::db_id`] /
    /// [`PlaySource::blob`] (a blob is base64-encoded on the wire); `options`
    /// carries the optional `repeat` / `start_ms` / `duration_ms` / `to_tag`
    /// shaping. Resolves once the media backend *accepts* the command; the far-end
    /// playback outcome is not the reply. A call with no anchored media session →
    /// [`ControlError`] with `code == "not_found"`.
    pub async fn play(
        &self,
        source: PlaySource,
        options: PlayOptions,
    ) -> Result<(), ControlError> {
        let mut args = serde_json::Map::new();
        source.insert_into(&mut args);
        options.insert_into(&mut args);
        self.sip(SipVerb::Play, serde_json::Value::Object(args))
            .await
            .map(drop)
    }

    /// Convenience for [`Call::play`] of a server-side file with default options.
    pub async fn play_file(&self, file: &str) -> Result<(), ControlError> {
        self.play(PlaySource::file(file), PlayOptions::default()).await
    }

    /// Stop the announcement currently playing on the A-leg media.
    pub async fn stop(&self) -> Result<(), ControlError> {
        self.sip(SipVerb::Stop, json!({})).await.map(drop)
    }

    /// Inject DTMF digits toward the A-leg (fire-and-forget). `options` carries
    /// the optional `duration_ms` / `volume_dbm0` / `pause_ms` / `to_tag` shaping.
    pub async fn dtmf(&self, digits: &str, options: DtmfOptions) -> Result<(), ControlError> {
        let mut args = serde_json::Map::new();
        args.insert("digits".to_string(), json!(digits));
        options.insert_into(&mut args);
        self.sip(SipVerb::Dtmf, serde_json::Value::Object(args))
            .await
            .map(drop)
    }

    /// Hold the A-leg media via silence.
    pub async fn hold(&self) -> Result<(), ControlError> {
        self.sip(SipVerb::Hold, json!({})).await.map(drop)
    }

    /// Resume the A-leg media after a [`Call::hold`].
    pub async fn unhold(&self) -> Result<(), ControlError> {
        self.sip(SipVerb::Unhold, json!({})).await.map(drop)
    }

    /// Attach a WebSocket audio tee — stream a copy of the call's decoded audio
    /// to `ws_uri` while the call keeps relaying.
    ///
    /// `direction` is one of `"both"` (default) / `"caller"` / `"callee"`;
    /// `channels` is `1` (mixed mono) or `2` (caller/callee stereo, only
    /// meaningful with `"both"`). siphon-rtp backend only: rtpengine / rtpproxy
    /// answer [`ControlError::is_unsupported_verb`].
    pub async fn stream_start(
        &self,
        ws_uri: &str,
        direction: Option<&str>,
        channels: Option<u8>,
    ) -> Result<(), ControlError> {
        let mut args = json!({ "ws_uri": ws_uri });
        if let Some(direction) = direction {
            args["direction"] = json!(direction);
        }
        if let Some(channels) = channels {
            args["channels"] = json!(channels);
        }
        self.sip(SipVerb::StreamStart, args).await.map(drop)
    }

    /// Detach the WebSocket audio tee (idempotent on siphon-rtp).
    pub async fn stream_stop(&self) -> Result<(), ControlError> {
        self.sip(SipVerb::StreamStop, json!({})).await.map(drop)
    }

    // --- escape hatch + events --------------------------------------------

    /// Send an arbitrary SIP-adapter verb + args and return the raw result.
    pub async fn command(
        &self,
        verb: &str,
        args: serde_json::Value,
    ) -> Result<serde_json::Value, ControlError> {
        self.inner
            .commander
            .command(Some(MODULE_SIP.to_string()), verb.to_string(), self.target(), args)
            .await
    }

    /// Await the next event for this call (`ChannelStateChange`,
    /// `ChannelHangupRequest`, `ChannelDtmfReceived`, `TransferRequested`,
    /// `TransferProgress`, `TransferCompleted`, `TransferFailed`, `StasisEnd`).
    /// `None` once the stream closes. Use [`CallEvent::dtmf`] /
    /// [`CallEvent::transfer_requested`] / [`CallEvent::transfer_outcome`] to
    /// decode the payload.
    pub async fn next_event(&self) -> Option<CallEvent> {
        self.inner.events.lock().await.recv().await
    }
}

impl std::fmt::Debug for Call {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Call")
            .field("channel_id", &self.inner.channel_id)
            .field("sip_call_id", &self.inner.sip_call_id)
            .field("reattached", &self.inner.reattached)
            .finish_non_exhaustive()
    }
}

fn string_value(result: &serde_json::Value) -> Option<String> {
    result.get("value").and_then(|value| value.as_str()).map(|value| value.to_string())
}

fn response_args(
    code: u16,
    reason: Option<&str>,
    body: Option<&str>,
    content_type: Option<&str>,
) -> serde_json::Value {
    let mut args = json!({ "code": code });
    if let Some(reason) = reason {
        args["reason"] = json!(reason);
    }
    if let Some(body) = body {
        args["body"] = json!(body);
    }
    if let Some(content_type) = content_type {
        args["content_type"] = json!(content_type);
    }
    args
}

// ---------------------------------------------------------------------------
// Call dispatch (handler closure or pull stream) + per-channel event routing
// ---------------------------------------------------------------------------

type CallHandler = Arc<dyn Fn(Call) -> BoxFuture<'static, Result<(), ControlError>> + Send + Sync>;

/// The SIP facade's event router: builds `Call`s from `StasisStart`/reattach,
/// routes channel-scoped events to the owning call, and dispatches new calls to
/// a handler or pull stream.
struct SipFacade {
    handler: Mutex<Option<CallHandler>>,
    call_tx: Mutex<Option<mpsc::UnboundedSender<Call>>>,
    channels: Mutex<HashMap<String, mpsc::UnboundedSender<CallEvent>>>,
}

impl SipFacade {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            handler: Mutex::new(None),
            call_tx: Mutex::new(None),
            channels: Mutex::new(HashMap::new()),
        })
    }

    fn set_handler<F, Fut>(&self, handler: F)
    where
        F: Fn(Call) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), ControlError>> + Send + 'static,
    {
        let boxed: CallHandler = Arc::new(move |call| Box::pin(handler(call)) as BoxFuture<'static, _>);
        *lock(&self.handler) = Some(boxed);
    }

    fn set_stream(&self) -> mpsc::UnboundedReceiver<Call> {
        let (sender, receiver) = mpsc::unbounded_channel();
        *lock(&self.call_tx) = Some(sender);
        receiver
    }

    fn handle_client_event(&self, event: ClientEvent, commander: &Arc<dyn CommandTransport>) {
        match event {
            ClientEvent::Event(frame) => self.handle_event(frame, commander),
            ClientEvent::Reattach(snapshot) => self.reattach(snapshot, commander),
        }
    }

    fn handle_event(&self, frame: EventFrame, commander: &Arc<dyn CommandTransport>) {
        match frame.sip_kind() {
            SipEvent::StasisStart => {
                let Some(channel) = frame.channel.clone() else {
                    warn!("control(sip): StasisStart without a channel — dropping");
                    return;
                };
                let (event_tx, event_rx) = mpsc::unbounded_channel();
                lock(&self.channels).insert(channel, event_tx);
                let call = Call::from_event(Arc::clone(commander), &frame, event_rx, false);
                self.dispatch(call);
            }
            SipEvent::StasisEnd => {
                if let Some(channel) = frame.channel.clone() {
                    self.route(&channel, CallEvent::from_frame(frame));
                    lock(&self.channels).remove(&channel);
                }
            }
            _ => {
                if let Some(channel) = frame.channel.clone() {
                    self.route(&channel, CallEvent::from_frame(frame));
                }
            }
        }
    }

    fn reattach(&self, snapshot: ChannelSnapshot, commander: &Arc<dyn CommandTransport>) {
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        lock(&self.channels).insert(snapshot.channel.clone(), event_tx);
        let call = Call::from_snapshot(Arc::clone(commander), snapshot, event_rx);
        self.dispatch(call);
    }

    fn route(&self, channel: &str, event: CallEvent) {
        if let Some(sender) = lock(&self.channels).get(channel) {
            let _ = sender.send(event);
        }
    }

    fn dispatch(&self, call: Call) {
        if let Some(handler) = lock(&self.handler).clone() {
            tokio::spawn(async move {
                if let Err(error) = handler(call).await {
                    warn!(%error, "control(sip): call handler returned an error");
                }
            });
        } else if let Some(sender) = lock(&self.call_tx).as_ref() {
            if sender.send(call).is_err() {
                debug!("control(sip): call queue closed — dropping call");
            }
        } else {
            debug!(channel = %call.channel_id(), "control(sip): no handler/stream — call dropped");
        }
    }
}

/// A pull-style stream of handed-over calls (see [`SipClient::calls`]).
pub struct CallStream {
    receiver: mpsc::UnboundedReceiver<Call>,
}

impl CallStream {
    /// Await the next handed-over call. `None` once the client shuts down.
    pub async fn next(&mut self) -> Option<Call> {
        self.receiver.recv().await
    }
}

// ---------------------------------------------------------------------------
// Inbound-persistent SIP facade
// ---------------------------------------------------------------------------

/// The SIP facade over an inbound-persistent [`ControlClient`].
///
/// ```no_run
/// # use siphon_control_client::{ClientConfig, sip::SipClient};
/// # async fn demo() -> Result<(), siphon_control_client::ControlError> {
/// let client = SipClient::connect(
///     ClientConfig::new("ws://siphon:9090/control/ws", "ivr-app", "s3cr3t"),
/// )
/// .await?;
/// client
///     .on_call(|call| async move {
///         call.answer().await?;
///         call.transfer("sip:agent@pbx").await
///     })
///     .await?;
/// # Ok(())
/// # }
/// ```
pub struct SipClient {
    client: Arc<ControlClient>,
    facade: Arc<SipFacade>,
}

impl std::fmt::Debug for SipClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("SipClient").finish_non_exhaustive()
    }
}

impl SipClient {
    /// Connect + `hello`, then install the SIP event router.
    pub async fn connect(config: ClientConfig) -> Result<Self, ControlError> {
        let client = Arc::new(ControlClient::connect(config).await?);
        Ok(Self::wrap(client))
    }

    /// Wrap an already-connected generic client with the SIP facade.
    pub fn wrap(client: Arc<ControlClient>) -> Self {
        let facade = SipFacade::new();
        let commander = client.commander();
        let routed = Arc::clone(&facade);
        client
            .shared()
            .install_event_callback(Arc::new(move |event| {
                routed.handle_client_event(event, &commander);
            }));
        Self { client, facade }
    }

    /// The underlying generic client (for raw `command` on any module).
    pub fn client(&self) -> &ControlClient {
        &self.client
    }

    /// Register a call handler (does not block).
    pub fn set_call_handler<F, Fut>(&self, handler: F)
    where
        F: Fn(Call) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), ControlError>> + Send + 'static,
    {
        self.facade.set_handler(handler);
    }

    /// Register a call handler **and drive the client to completion** (the
    /// supervised reconnect + resync loop).
    pub async fn on_call<F, Fut>(&self, handler: F) -> Result<(), ControlError>
    where
        F: Fn(Call) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), ControlError>> + Send + 'static,
    {
        self.set_call_handler(handler);
        self.client.run().await
    }

    /// A pull-style stream of handed-over calls (alternative to a handler).
    pub fn calls(&self) -> CallStream {
        CallStream {
            receiver: self.facade.set_stream(),
        }
    }

    /// Drive the supervised connection loop (reconnect + resync).
    pub async fn run(&self) -> Result<(), ControlError> {
        self.client.run().await
    }

    /// Fetch the registered adapters' schema (`describe`).
    pub async fn describe(&self) -> Result<serde_json::Value, ControlError> {
        self.client.describe().await
    }

    /// Send a raw command on any module (the generic escape hatch).
    pub async fn command(
        &self,
        module: Option<&str>,
        verb: &str,
        target: serde_json::Value,
        args: serde_json::Value,
    ) -> Result<serde_json::Value, ControlError> {
        self.client.command(module, verb, target, args).await
    }

    /// Stop the client.
    pub fn shutdown(&self) {
        self.client.shutdown();
    }
}

// ---------------------------------------------------------------------------
// Per-call-connect SIP facade
// ---------------------------------------------------------------------------

/// The SIP facade over a per-call-connect [`ControlServer`].
pub struct SipServer {
    server: Arc<ControlServer>,
    facade: Arc<SipFacade>,
}

impl std::fmt::Debug for SipServer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("SipServer").finish_non_exhaustive()
    }
}

impl SipServer {
    /// Bind the listener and install the SIP event router.
    pub async fn bind(config: ServerConfig) -> Result<Self, ControlError> {
        let server = Arc::new(ControlServer::bind(config).await?);
        let facade = SipFacade::new();
        let routed = Arc::clone(&facade);
        server.on_connection_event(Arc::new(move |frame, commander| {
            routed.handle_event(frame, &commander);
        }));
        Ok(Self { server, facade })
    }

    /// The actual bound address (useful when binding to port 0 in tests).
    pub fn local_addr(&self) -> Result<std::net::SocketAddr, ControlError> {
        self.server.local_addr()
    }

    /// Register a call handler (does not block).
    pub fn set_call_handler<F, Fut>(&self, handler: F)
    where
        F: Fn(Call) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), ControlError>> + Send + 'static,
    {
        self.facade.set_handler(handler);
    }

    /// A pull-style stream of dialed-in calls (alternative to a handler).
    pub fn calls(&self) -> CallStream {
        CallStream {
            receiver: self.facade.set_stream(),
        }
    }

    /// Register a call handler **and run the accept loop** to completion.
    pub async fn on_call<F, Fut>(&self, handler: F) -> Result<(), ControlError>
    where
        F: Fn(Call) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), ControlError>> + Send + 'static,
    {
        self.set_call_handler(handler);
        self.server.run().await
    }

    /// Accept siphon's per-call dials forever.
    pub async fn run(&self) -> Result<(), ControlError> {
        self.server.run().await
    }
}

// ---------------------------------------------------------------------------
// Tests — the emitted `route` frame shape (recording CommandTransport).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use siphon_control_proto::sip::TransferStage;
    use siphon_control_proto::ChannelSnapshot;
    use std::collections::HashMap;

    #[derive(Clone)]
    struct Recorded {
        module: Option<String>,
        verb: String,
        target: serde_json::Value,
        args: serde_json::Value,
    }

    /// A [`CommandTransport`] that records every command and returns a canned
    /// result — the Rust twin of the TypeScript `RecordingTransport`.
    struct RecordingTransport {
        calls: Mutex<Vec<Recorded>>,
        result: serde_json::Value,
    }

    impl CommandTransport for RecordingTransport {
        fn command(
            &self,
            module: Option<String>,
            verb: String,
            target: serde_json::Value,
            args: serde_json::Value,
        ) -> BoxFuture<'_, Result<serde_json::Value, ControlError>> {
            lock(&self.calls).push(Recorded {
                module,
                verb,
                target,
                args,
            });
            let result = self.result.clone();
            Box::pin(async move { Ok(result) })
        }
    }

    fn make_call(transport: Arc<dyn CommandTransport>) -> Call {
        let (_event_tx, event_rx) = mpsc::unbounded_channel();
        let snapshot = ChannelSnapshot {
            channel: "ch1".to_string(),
            call_id: "call-uuid".to_string(),
            sip_call_id: "sip@host".to_string(),
            state: "answered".to_string(),
            vars: HashMap::new(),
        };
        Call::from_snapshot(transport, snapshot, event_rx)
    }

    #[tokio::test]
    async fn route_emits_targets_strategy_and_headers() {
        let recorder = Arc::new(RecordingTransport {
            calls: Mutex::new(Vec::new()),
            result: json!({ "channel": "ch1", "state": "routing", "targets": 2 }),
        });
        let call = make_call(recorder.clone());

        let result = call
            .route(
                vec![
                    RouteTarget::from("sip:carrier1@gw1"),
                    RouteTarget {
                        uri: "sip:carrier2@gw2".to_string(),
                        next_hop: Some("sip:1.2.3.4:5060".to_string()),
                        headers: vec![("X-Foo".to_string(), "bar".to_string())],
                        timeout_secs: Some(30),
                    },
                ],
                Some("sequential"),
                vec![("X-Trace".to_string(), "abc".to_string())],
            )
            .await
            .expect("route ok");

        assert_eq!(result["state"], "routing");
        assert_eq!(result["targets"], 2);

        let recorded = lock(&recorder.calls).clone();
        assert_eq!(recorded.len(), 1);
        let frame = &recorded[0];
        assert_eq!(frame.module.as_deref(), Some("sip"));
        assert_eq!(frame.verb, "route");
        assert_eq!(frame.target, json!({ "channel": "ch1" }));
        assert_eq!(
            frame.args,
            json!({
                "targets": [
                    "sip:carrier1@gw1",
                    {
                        "uri": "sip:carrier2@gw2",
                        "next_hop": "sip:1.2.3.4:5060",
                        "headers": { "X-Foo": "bar" },
                        "timeout": 30
                    }
                ],
                "strategy": "sequential",
                "headers": { "X-Trace": "abc" }
            })
        );
    }

    #[tokio::test]
    async fn route_omits_strategy_and_headers_when_absent() {
        let recorder = Arc::new(RecordingTransport {
            calls: Mutex::new(Vec::new()),
            result: json!({ "channel": "ch1", "state": "routing", "targets": 1 }),
        });
        let call = make_call(recorder.clone());

        call.route(vec![RouteTarget::uri("sip:only@gw")], None, Vec::new())
            .await
            .expect("route ok");

        let recorded = lock(&recorder.calls).clone();
        assert_eq!(recorded[0].args, json!({ "targets": ["sip:only@gw"] }));
    }

    #[tokio::test]
    async fn media_verbs_emit_expected_frames() {
        let recorder = Arc::new(RecordingTransport {
            calls: Mutex::new(Vec::new()),
            result: json!({ "channel": "ch1", "state": "playing" }),
        });
        let call = make_call(recorder.clone());

        call.play(PlaySource::file("/prompts/welcome.wav"), PlayOptions::default())
            .await
            .expect("play file ok");
        call.play(
            PlaySource::blob(b"hi".to_vec()),
            PlayOptions { repeat: Some(2), duration_ms: Some(10_000), ..Default::default() },
        )
        .await
        .expect("play blob ok");
        call.stop().await.expect("stop ok");
        call.dtmf(
            "123#",
            DtmfOptions { duration_ms: Some(100), volume_dbm0: Some(-8), ..Default::default() },
        )
        .await
        .expect("dtmf ok");
        call.hold().await.expect("hold ok");
        call.unhold().await.expect("unhold ok");
        call.stream_start("ws://ai:9000/stream", Some("both"), Some(2))
            .await
            .expect("stream_start ok");
        call.stream_stop().await.expect("stream_stop ok");

        let recorded = lock(&recorder.calls).clone();
        let by_verb = |verb: &str| -> serde_json::Value {
            recorded.iter().find(|call| call.verb == verb).expect("verb recorded").args.clone()
        };
        // Every media verb rides the sip module against this channel.
        for call in &recorded {
            assert_eq!(call.module.as_deref(), Some("sip"));
            assert_eq!(call.target, json!({ "channel": "ch1" }));
        }
        assert_eq!(by_verb("play").get("file").and_then(|v| v.as_str()), Some("/prompts/welcome.wav"));
        // A blob is base64-encoded on the wire ("hi" → "aGk=").
        let blob_args: Vec<&serde_json::Value> = recorded
            .iter()
            .filter(|call| call.verb == "play")
            .map(|call| &call.args)
            .collect();
        assert_eq!(blob_args[1], &json!({ "blob": "aGk=", "repeat": 2, "duration_ms": 10_000 }));
        assert_eq!(by_verb("stop"), json!({}));
        assert_eq!(by_verb("dtmf"), json!({ "digits": "123#", "duration_ms": 100, "volume_dbm0": -8 }));
        assert_eq!(by_verb("hold"), json!({}));
        assert_eq!(by_verb("unhold"), json!({}));
        assert_eq!(
            by_verb("stream_start"),
            json!({ "ws_uri": "ws://ai:9000/stream", "direction": "both", "channels": 2 })
        );
        assert_eq!(by_verb("stream_stop"), json!({}));
    }

    #[tokio::test]
    async fn header_and_refer_verbs_emit_expected_frames() {
        let recorder = Arc::new(RecordingTransport {
            calls: Mutex::new(Vec::new()),
            result: json!({ "channel": "ch1" }),
        });
        let call = make_call(recorder.clone());

        call.remove_header("X-Foo").await.expect("remove_header ok");
        call.accept_refer(
            Some("sip:c@pbx"),
            Some("sip:sbc"),
            Some("terminate"),
            Some("rtp_passthrough"),
        )
        .await
        .expect("accept_refer ok");
        call.reject_refer(603, Some("Decline")).await.expect("reject_refer ok");

        let recorded = lock(&recorder.calls).clone();
        assert_eq!(recorded[0].verb, "remove_header");
        assert_eq!(recorded[0].args, json!({ "name": "X-Foo" }));
        assert_eq!(recorded[1].verb, "accept_refer");
        assert_eq!(
            recorded[1].args,
            json!({
                "target": "sip:c@pbx",
                "next_hop": "sip:sbc",
                "mode": "terminate",
                // The pairing the transfer creates — omitted means "inherit",
                // which is wrong for a direction-bound profile.
                "profile": "rtp_passthrough",
            })
        );
        assert_eq!(recorded[2].verb, "reject_refer");
        assert_eq!(recorded[2].args, json!({ "code": 603, "reason": "Decline" }));
    }

    /// An omitted profile is absent from the frame rather than sent as null, so
    /// the server's "inherit the call's profile" default is what applies.
    #[tokio::test]
    async fn accept_refer_omits_an_unset_profile() {
        let recorder = Arc::new(RecordingTransport {
            calls: Mutex::new(Vec::new()),
            result: json!({ "channel": "ch1" }),
        });
        let call = make_call(recorder.clone());

        call.accept_refer(None, None, Some("terminate"), None)
            .await
            .expect("accept_refer ok");

        let recorded = lock(&recorder.calls).clone();
        assert_eq!(recorded[0].args, json!({ "mode": "terminate" }));
    }

    /// Ringing and early media are two verbs on the wire, not one verb with a
    /// status code the app has to know: `ring` must emit its own token and
    /// carry no body, and `progress` must stay the one that can.
    #[tokio::test]
    async fn ring_and_progress_emit_separate_verbs() {
        let recorder = Arc::new(RecordingTransport {
            calls: Mutex::new(Vec::new()),
            result: json!({ "channel": "ch1", "state": "ringing", "code": 180 }),
        });
        let call = make_call(recorder.clone());

        call.ring().await.expect("ring ok");
        call.ring_with_reason("Alerting").await.expect("ring_with_reason ok");
        call.progress_with(183, Some("Session Progress"), Some("v=0\r\n"), Some("application/sdp"))
            .await
            .expect("progress ok");

        let recorded = lock(&recorder.calls).clone();
        assert_eq!(recorded[0].verb, "ring");
        assert_eq!(recorded[0].args, json!({}));
        assert_eq!(recorded[1].verb, "ring");
        assert_eq!(recorded[1].args, json!({ "reason": "Alerting" }));
        assert_eq!(recorded[2].verb, "progress");
        assert_eq!(recorded[2].args["code"], 183);
        assert_eq!(recorded[2].args["body"], "v=0\r\n");
    }

    #[test]
    fn play_started_parses_from_a_frame() {
        let started = CallEvent::from_frame(EventFrame::new(
            "PlayStarted",
            "ch1",
            "ivr-app",
            "call-uuid",
            "sip@host",
            json!({ "source": "file", "play_id": 7, "duration_ms": 1500 }),
        ));
        assert_eq!(started.kind, SipEvent::PlayStarted);
        let payload = started.play_started().expect("PlayStarted payload");
        assert_eq!(payload.source, "file");
        assert_eq!(payload.play_id, Some(7));
        assert_eq!(payload.duration_ms, Some(1500));

        // The helper must key on the event *kind*, not on whether the payload
        // happens to deserialize: this frame's payload is a perfectly valid
        // PlayStartedPayload, and it is still not a PlayStarted event. A helper
        // gated only on the parse would hand a caller a playback that never
        // started.
        let other = CallEvent::from_frame(EventFrame::new(
            "ChannelStateChange",
            "ch1",
            "ivr-app",
            "call-uuid",
            "sip@host",
            json!({ "source": "file", "play_id": 7, "duration_ms": 1500 }),
        ));
        assert!(other.play_started().is_none());
    }

    #[test]
    fn dtmf_and_transfer_events_parse_from_frames() {
        let dtmf = CallEvent::from_frame(EventFrame::new(
            "ChannelDtmfReceived",
            "ch1",
            "ivr-app",
            "call-uuid",
            "sip@host",
            json!({ "digit": "5", "duration_ms": 100, "volume": -8, "from_tag": "alice-tag" }),
        ));
        assert_eq!(dtmf.kind, SipEvent::ChannelDtmfReceived);
        let payload = dtmf.dtmf().expect("dtmf payload");
        assert_eq!(payload.digit, "5");
        assert_eq!(payload.volume, -8);
        assert_eq!(payload.from_tag, "alice-tag");
        // Wrong-kind accessor returns None.
        assert!(dtmf.transfer_requested().is_none());

        let transfer = CallEvent::from_frame(EventFrame::new(
            "TransferRequested",
            "ch1",
            "ivr-app",
            "call-uuid",
            "sip@host",
            json!({
                "refer_to": "sip:carol@example.com",
                "replaces": { "call_id": "abc", "from_tag": "ft", "to_tag": "tt", "early_only": false },
                "from_tag": "referrer-tag"
            }),
        ));
        assert_eq!(transfer.kind, SipEvent::TransferRequested);
        let payload = transfer.transfer_requested().expect("transfer payload");
        assert_eq!(payload.refer_to, "sip:carol@example.com");
        assert_eq!(payload.replaces.expect("replaces").call_id, "abc");
        assert_eq!(payload.from_tag.as_deref(), Some("referrer-tag"));
        assert!(transfer.dtmf().is_none());
        // An inbound REFER is a request to decide, not a verdict on one we sent.
        assert!(transfer.transfer_outcome().is_none());
        assert!(!transfer.is_transfer_final());
    }

    #[test]
    fn outbound_transfer_verdicts_parse_from_frames() {
        let frame = |event: &str, payload: serde_json::Value| {
            CallEvent::from_frame(EventFrame::new(
                event, "ch1", "ivr-app", "call-uuid", "sip@host", payload,
            ))
        };

        // Progress: the referee challenged and siphon answered (attempt 1). The
        // attempt number is what separates this from a refusal on the same 407.
        let challenged = frame(
            "TransferProgress",
            json!({
                "stage": "challenged",
                "refer_to": "sip:carol@example.net",
                "code": 407,
                "reason": "Proxy Authentication Required",
                "attempt": 1
            }),
        );
        assert_eq!(challenged.kind, SipEvent::TransferProgress);
        let payload = challenged.transfer_outcome().expect("outcome payload");
        assert_eq!(payload.stage, TransferStage::Challenged);
        assert_eq!(payload.code, Some(407));
        assert_eq!(payload.attempt, Some(1));
        assert!(
            !challenged.is_transfer_final(),
            "progress must not end the wait"
        );

        // Completion, from the terminating sipfrag NOTIFY (RFC 3515 §2.4.4).
        let completed = frame(
            "TransferCompleted",
            json!({ "stage": "transferred", "code": 200, "reason": "OK" }),
        );
        assert_eq!(completed.kind, SipEvent::TransferCompleted);
        assert_eq!(
            completed.transfer_outcome().expect("outcome").stage,
            TransferStage::Transferred
        );
        assert!(completed.is_transfer_final());

        // Failure, carrying the sipfrag status the referee reported.
        let failed = frame(
            "TransferFailed",
            json!({ "stage": "refused", "code": 486, "reason": "Busy Here" }),
        );
        assert_eq!(failed.kind, SipEvent::TransferFailed);
        let payload = failed.transfer_outcome().expect("outcome");
        assert_eq!(payload.stage, TransferStage::Refused);
        assert_eq!(payload.code, Some(486));
        assert!(failed.is_transfer_final());
        // Wrong-kind accessors stay None.
        assert!(failed.dtmf().is_none());
        assert!(failed.transfer_requested().is_none());
    }
}
