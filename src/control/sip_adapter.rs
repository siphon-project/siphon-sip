//! The SIP control adapter — binds generic control verbs onto siphon's shipped
//! imperative B2BUA rail (`b2bua_answer_call` / `b2bua_progress_call` /
//! `b2bua_terminate_call` / `b2bua_refer_call`).
//!
//! Every verb is a **synchronous decision core over the call store** — it
//! performs the one bounded local action (send a SIP message / mark the store)
//! and returns "accepted" in microseconds. It **never** waits for the far end;
//! the callee's answer / ACK / BYE-200 arrive later as events. A command against
//! a dead/unknown call returns a typed `not_found`, never hangs.

use std::collections::HashMap;

use futures_util::future::BoxFuture;

use super::protocol::{ControlErrorCode, ControlResult};
use super::registry::{ChannelRef, ControlBus};
use super::{AdapterCommand, AdapterSchema, ControlAdapter, ResolvedTarget, VerbSchema};

/// The SIP adapter (`module() == "sip"`).
#[derive(Debug, Default)]
pub struct SipControlAdapter;

impl SipControlAdapter {
    /// Construct the SIP adapter.
    pub fn new() -> Self {
        Self
    }
}

impl ControlAdapter for SipControlAdapter {
    fn module(&self) -> &str {
        "sip"
    }

    fn apply<'a>(&'a self, command: AdapterCommand) -> BoxFuture<'a, ControlResult> {
        // Media verbs bind to the async MediaBackend, so they run on the async
        // path; every other verb is a synchronous decision over the B2BUA rail.
        Box::pin(async move {
            if command.verb == "originate" {
                // Module-level: it creates the channel rather than addressing one.
                originate(command)
            } else if is_bridge_verb(&command.verb) {
                // Addresses two channels and confirms the media teardown with
                // the backend before it answers, so it runs on the async path.
                apply_bridge_verb(command).await
            } else if is_media_verb(&command.verb) {
                apply_media_verb(command).await
            } else {
                apply_sip(command)
            }
        })
    }

    fn describe(&self) -> AdapterSchema {
        AdapterSchema {
            module: "sip".to_string(),
            verbs: vec![
                verb("originate", "Place an outbound call under a caller-supplied channel id and return as soon as the INVITE is on the wire (args: channel, to, from, from_display, to_display, next_hop, p_asserted_identity, privacy, headers, sdp | media, profile, ws_uri, timeout, on_lost, vars)"),
                verb("answer", "Send a UAS 2xx to the parked A-leg (args: code, reason, body, content_type)"),
                verb("ring", "Send 180 Ringing to the parked A-leg — alerting only, no early media (RFC 3261 §13.2.1); a body is refused, use progress for that (args: reason)"),
                verb("progress", "Send a UAS 1xx, optionally opening an early-media path with SDP (RFC 3960 §3.1); defaults to 183 Session Progress (args: code, reason, body, content_type)"),
                verb("reject", "Send a final non-2xx and tear the call down (args: code, reason)"),
                verb("hangup", "BYE an answered call, or reject an unanswered one (args: reason)"),
                verb("refer", "Send an in-dialog REFER on the A-leg; the reply reports only that it was sent, the far end's verdict arrives as TransferProgress then TransferCompleted / TransferFailed (args: to, replaces)"),
                verb("accept_refer", "Accept a pending inbound REFER (from a TransferRequested event) and run the transfer (args: target, next_hop, mode)"),
                verb("reject_refer", "Reject a pending inbound REFER with a final non-2xx (args: code, reason)"),
                verb("bridge", "Join this channel to another the app owns, so the two parties hear each other; the reply says the media was re-pointed and the first re-INVITE is on the wire, ChannelBridged says the audio meets (args: with, on_peer_hangup)"),
                verb("unbridge", "Break a bridge — both legs stay answered, owned and held; the reply says the hold offers went out, ChannelUnbridged on each leg says it is parted and safe to bridge again (args: reason)"),
                verb("route", "Return control to siphon with a routing decision: un-park the call and dial the B-leg via LCR sequential failover (args: targets, strategy, headers)"),
                verb("set_header", "Set a header on the stored A-leg INVITE (args: name, value)"),
                verb("remove_header", "Remove a header from the stored A-leg INVITE (args: name)"),
                verb("get_header", "Read a header from the stored A-leg INVITE (args: name)"),
                verb("play", "Play an announcement on the A-leg media, fire-and-forget; the reply and a PlayStarted event carry the play_id a later stop addresses (args: one of file|db_id|blob|tone|url, repeat, start_ms, duration_ms, gain_decibels, to_tag)"),
                verb("stop", "Stop the announcement currently playing on the A-leg media"),
                verb("dtmf", "Inject DTMF digits toward the A-leg (args: digits, duration_ms, volume_dbm0, pause_ms, to_tag)"),
                verb("hold", "Hold the A-leg media via silence"),
                verb("unhold", "Resume the A-leg media after a hold"),
                verb("stream_start", "Stream the call's audio to a WebSocket server — siphon-rtp backend only (args: ws_uri, mode=tee|bridge, and for tee: direction, channels, sample_rate). mode=tee streams a copy while the call keeps relaying; mode=bridge is a takeover that makes the server the leg's far side, and re-points in place if one is already attached"),
                verb("stream_stop", "Stop streaming the call's audio (args: mode=tee|bridge). A tee stop is idempotent; a bridge stop is refused where there is no relay to return the call to"),
            ],
            events: vec![
                "StasisStart".to_string(),
                "StasisEnd".to_string(),
                "ChannelStateChange".to_string(),
                "ChannelHangupRequest".to_string(),
                "ChannelDtmfReceived".to_string(),
                // The accept of a `play`, on the event stream rather than only
                // in the command reply, carrying the `play_id` a later `stop` /
                // gain change addresses. "Started" is the media contract's
                // accept-on-start, not a claim that audio is already on the
                // wire — a fetched source accepts before its body arrives.
                "PlayStarted".to_string(),
                // The other half of a play's lifecycle. `play` over this rail is
                // always fire-and-forget — the blocking form is in-process only —
                // so without this an app that acts when a prompt ends has to
                // guess from the accept's duration, which a stop, a supersede or
                // a decode error all make wrong.
                "PlayFinished".to_string(),
                "TransferRequested".to_string(),
                // The verdict on an *outbound* REFER (the `refer` verb). Three
                // names, because RFC 3515 §2.4.4 splits "accepted for
                // processing" (the 2xx to the REFER) from the real outcome (the
                // message/sipfrag NOTIFY that follows): TransferProgress while
                // it moves, then exactly one TransferCompleted / TransferFailed.
                "TransferProgress".to_string(),
                "TransferCompleted".to_string(),
                "TransferFailed".to_string(),
                // The verdict on a `bridge`. The reply to the verb reports only
                // that the media was re-pointed and the first re-INVITE went
                // out; a bridge is two RFC 3261 §14 re-INVITEs and is not formed
                // until both are answered, so the outcome is an event on both
                // channels — exactly one ChannelBridged / BridgeFailed.
                "ChannelBridged".to_string(),
                "BridgeFailed".to_string(),
                "ChannelUnbridged".to_string(),
                // The lifecycle of a `stream_start` with `mode: bridge`. A
                // *tee* dying costs a consumer its copy of the audio; a
                // *bridge* dying costs the call its far side, so a controller
                // that can start one over this rail has to be able to learn it
                // died over the same rail rather than inferring it from both
                // parties going quiet. Exactly one WsBridgeEnded per
                // WsBridgeStarted, and a re-point is an ended+started pair.
                "WsBridgeStarted".to_string(),
                "WsBridgeEnded".to_string(),
                // The tee's lifecycle, on the same rail and for the same
                // reason. A dead tee is less severe than a dead bridge — the
                // call keeps relaying and only the consumer loses its copy —
                // but a controller that started the stream over this rail still
                // cannot otherwise tell that it stopped, and silently losing
                // the audio is exactly what these exist to prevent.
                "WsTeeStarted".to_string(),
                "WsTeeEnded".to_string(),
            ],
        }
    }
}

fn verb(name: &str, summary: &str) -> VerbSchema {
    VerbSchema {
        verb: name.to_string(),
        summary: summary.to_string(),
    }
}

/// The media-control verbs the SIP adapter dispatches asynchronously against the
/// configured [`crate::rtpengine::MediaBackend`] (rather than the synchronous
/// B2BUA rail). Kept in one place so `apply` and the tests agree on the split.
fn is_media_verb(verb: &str) -> bool {
    matches!(
        verb,
        "play" | "stop" | "dtmf" | "hold" | "unhold" | "stream_start" | "stream_stop"
    )
}

/// The verbs that join or part two channels. Split out so `apply` and the tests
/// agree on which verbs take the async path (they confirm the media teardown
/// with the backend before answering).
fn is_bridge_verb(verb: &str) -> bool {
    matches!(verb, "bridge" | "unbridge")
}

/// Resolve the command's channel target and mark the controller as having acted
/// (clearing the answer-timeout handoff default). Shared by the synchronous SIP
/// verbs and the asynchronous media verbs. Returns the typed error result to
/// send back when the command carries no channel target.
fn controlled_channel(command: &AdapterCommand) -> Result<ChannelRef, ControlResult> {
    let channel = match &command.target {
        ResolvedTarget::Channel(channel) => channel.clone(),
        ResolvedTarget::None => {
            return Err(ControlResult::error(
                ControlErrorCode::BadRequest,
                format!("verb '{}' requires a channel target", command.verb),
            ));
        }
    };
    // The controller has acted: clear the handoff deadline so the answer-timeout
    // sweep no longer applies the parked default action to this call.
    if let Some(store) = crate::b2bua::actor::global_call_store() {
        store.mark_controller_acted(&channel.call_actor_id);
    }
    Ok(channel)
}

/// Dispatch one synchronous SIP verb (the imperative B2BUA rail is non-blocking)
/// — returns the local result immediately.
fn apply_sip(command: AdapterCommand) -> ControlResult {
    let channel = match controlled_channel(&command) {
        Ok(channel) => channel,
        Err(result) => return result,
    };

    match command.verb.as_str() {
        "answer" => answer(&channel, &command.args, true),
        "ring" => ring(&channel, &command.args),
        "progress" => answer(&channel, &command.args, false),
        "reject" => reject(&channel, &command.args),
        "hangup" => hangup(&channel, &command.args),
        "refer" => refer(&channel, &command.args),
        "accept_refer" => accept_refer(&channel, &command.args),
        "reject_refer" => reject_refer(&channel, &command.args),
        "route" => route(&channel, &command.args),
        "set_header" => set_header(&channel, &command.args),
        "remove_header" => remove_header(&channel, &command.args),
        "get_header" => get_header(&channel, &command.args),
        other => ControlResult::error(
            ControlErrorCode::UnsupportedVerb,
            format!("sip adapter does not implement verb '{other}' in this build"),
        ),
    }
}

/// Dispatch one media verb asynchronously against the configured MediaBackend.
///
/// The `(media_call_id, from_tag)` tuple is resolved from the channel's SIP
/// Call-ID via [`crate::dispatcher::b2bua_media_target`] (the stateless
/// media-session accessor). A call with no anchored media session returns a typed
/// `not_found` — never a hang, never a fabricated call-id. The verb `.await`s
/// only the backend's *accept* of the command, not the far-end media outcome
/// (playback completion, tee liveness), which arrives later as events.
async fn apply_media_verb(command: AdapterCommand) -> ControlResult {
    let channel = match controlled_channel(&command) {
        Ok(channel) => channel,
        Err(result) => return result,
    };

    match command.verb.as_str() {
        "play" => play(&channel, &command.args).await,
        "stop" => stop(&channel).await,
        "dtmf" => dtmf(&channel, &command.args).await,
        "hold" => hold(&channel, true).await,
        "unhold" => hold(&channel, false).await,
        "stream_start" => stream_start(&channel, &command.args).await,
        "stream_stop" => stream_stop(&channel, &command.args).await,
        other => ControlResult::error(
            ControlErrorCode::UnsupportedVerb,
            format!("sip adapter does not implement verb '{other}' in this build"),
        ),
    }
}

/// Resolve the MediaBackend + media `(call_id, from_tag)` for a controlled call,
/// or the typed `not_found` result to return when no media session is anchored.
fn media_target(
    channel: &ChannelRef,
) -> Result<
    (
        std::sync::Arc<crate::rtpengine::MediaBackend>,
        String,
        String,
    ),
    ControlResult,
> {
    crate::dispatcher::b2bua_media_target(&channel.sip_call_id).ok_or_else(|| {
        ControlResult::error(
            ControlErrorCode::NotFound,
            "call has no anchored media session",
        )
    })
}

/// Map a [`crate::rtpengine::error::RtpEngineError`] to a typed control result —
/// every media command answers, even on error, never a hang.
///   - the engine has no such call → `not_found` (the media session is gone),
///   - the backend can't do it (rtpproxy media / non-siphon-rtp ws_tee) →
///     `unsupported_verb`,
///   - anything else (transport, timeout, engine error) → `unavailable`.
fn media_error(error: crate::rtpengine::error::RtpEngineError) -> ControlResult {
    use crate::rtpengine::error::RtpEngineError;
    if error.is_call_not_found() {
        ControlResult::error(ControlErrorCode::NotFound, "media session is gone")
    } else if matches!(error, RtpEngineError::Unsupported { .. }) {
        ControlResult::error(ControlErrorCode::UnsupportedVerb, error.to_string())
    } else {
        ControlResult::error(ControlErrorCode::Unavailable, error.to_string())
    }
}

/// Parse the `play` source args into a [`crate::rtpengine::client::PlayMediaSource`]:
/// exactly one of `file` (path string), `db_id` (integer), or `blob` (base64
/// string). Mirrors the script API's `resolve_play_media_source` (file/blob/db_id
/// are mutually exclusive), with `blob` carried as base64 since the control wire
/// is JSON text.
fn parse_play_source(
    args: &serde_json::Value,
) -> Result<crate::rtpengine::client::PlayMediaSource, String> {
    use crate::rtpengine::client::PlayMediaSource;
    let file = args.get("file").and_then(|value| value.as_str());
    let db_id = args.get("db_id").and_then(|value| value.as_u64());
    let blob = args.get("blob").and_then(|value| value.as_str());
    let tone = args.get("tone").and_then(|value| value.as_str());
    let url = args.get("url").and_then(|value| value.as_str());
    let count = [
        file.is_some(),
        db_id.is_some(),
        blob.is_some(),
        tone.is_some(),
        url.is_some(),
    ]
    .iter()
    .filter(|present| **present)
    .count();
    if count != 1 {
        return Err(
            "play requires exactly one of args.file (path), args.db_id (int), args.blob \
             (base64), args.tone (preset or cadence spec), or args.url (http/https)"
                .to_string(),
        );
    }
    if let Some(path) = file {
        return Ok(PlayMediaSource::File(path.to_string()));
    }
    if let Some(id) = db_id {
        return Ok(PlayMediaSource::DbId(id));
    }
    if let Some(spec) = tone {
        if spec.trim().is_empty() {
            return Err("play args.tone must be a preset name or a cadence spec".to_string());
        }
        return Ok(PlayMediaSource::Tone(spec.to_string()));
    }
    if let Some(location) = url {
        let lowered = location.trim().to_ascii_lowercase();
        if !(lowered.starts_with("http://") || lowered.starts_with("https://")) {
            return Err("play args.url must be an http:// or https:// URL".to_string());
        }
        return Ok(PlayMediaSource::Http(location.to_string()));
    }
    if let Some(encoded) = blob {
        use base64::Engine as _;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|error| format!("play args.blob is not valid base64: {error}"))?;
        return Ok(PlayMediaSource::Blob(bytes));
    }
    // Unreachable given count == 1, but return a typed error rather than panic.
    Err("play requires a media source".to_string())
}

/// Which kind of WebSocket stream a `stream_start` / `stream_stop` addresses.
///
/// The two are not variations on one thing: a **tee** is additive (the call
/// relays on and a copy is streamed out), a **bridge** is a takeover (the
/// server becomes the leg's far side and A↔B is unwired). Defaulting to `Tee`
/// keeps every existing controller working unchanged — and is the safe default
/// of the two, since a caller who meant `tee` and got `bridge` would have the
/// call's audio path silently replaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamMode {
    Tee,
    Bridge,
}

/// Parse the optional `mode` arg. Absent means `tee`.
fn parse_stream_mode(
    value: Option<&serde_json::Value>,
    verb: &str,
) -> Result<StreamMode, ControlResult> {
    match value {
        None => Ok(StreamMode::Tee),
        Some(value) if value.is_null() => Ok(StreamMode::Tee),
        Some(serde_json::Value::String(mode)) => match mode.as_str() {
            "tee" => Ok(StreamMode::Tee),
            "bridge" => Ok(StreamMode::Bridge),
            other => Err(ControlResult::error(
                ControlErrorCode::BadRequest,
                format!("{verb} args.mode must be one of tee/bridge, got '{other}'"),
            )),
        },
        Some(_) => Err(ControlResult::error(
            ControlErrorCode::BadRequest,
            format!("{verb} args.mode must be a string, one of tee/bridge"),
        )),
    }
}

/// Parse an optional `channels` arg for `stream_start` (1 = mixed mono, 2 =
/// caller/callee stereo). Absent → engine default (`None`).
fn parse_stream_channels(value: Option<&serde_json::Value>) -> Result<Option<u8>, String> {
    match value {
        None => Ok(None),
        Some(value) if value.is_null() => Ok(None),
        Some(value) => match value.as_u64() {
            Some(1) => Ok(Some(1)),
            Some(2) => Ok(Some(2)),
            _ => Err("stream_start args.channels must be 1 (mono) or 2 (stereo)".to_string()),
        },
    }
}

/// The short token naming which source a `play` was started from, carried on the
/// `PlayStarted` event so an application can tell a prompt apart from a tone or
/// a fetched URL without keeping its own table of outstanding plays.
fn play_source_kind(source: &crate::rtpengine::client::PlayMediaSource) -> &'static str {
    use crate::rtpengine::client::PlayMediaSource;
    match source {
        PlayMediaSource::File(_) => "file",
        PlayMediaSource::Blob(_) => "blob",
        PlayMediaSource::DbId(_) => "db_id",
        PlayMediaSource::Tone(_) => "tone",
        PlayMediaSource::Http(_) => "url",
    }
}

/// Turn a `play_media` result into the command reply and, when the playback
/// really started, the `PlayStarted` payload to publish.
///
/// Split out from [`play`] so both halves are directly testable, including the
/// one that matters most: a play the backend **refused** yields `None` — no
/// start event is ever published for a playback that never began, which is what
/// lets a controller read "no `PlayStarted` yet" as "not started", full stop.
///
/// The media contract answers `play_media` **accept-on-start** — the accept
/// carries the `play_id` and means the engine armed the playback — so the accept
/// is the start, and there is no separate engine-side start signal to wait for.
/// It is deliberately *not* a claim that audio has reached the wire: a fetched
/// source (`url`) accepts before its body has arrived, which is why
/// `duration_ms` can be absent here and why a fetch that never completes shows
/// up later as a playback that ends without ever producing audio.
fn play_accept(
    channel_id: &str,
    source: &crate::rtpengine::client::PlayMediaSource,
    result: Result<
        crate::rtpengine::siphon_rtp::PlayMediaOutcome,
        crate::rtpengine::RtpEngineError,
    >,
) -> (ControlResult, Option<serde_json::Value>) {
    let outcome = match result {
        Ok(outcome) => outcome,
        Err(error) => return (media_error(error), None),
    };
    let kind = play_source_kind(source);
    let mut reply = serde_json::json!({ "channel": channel_id, "state": "playing" });
    let mut started = serde_json::json!({ "source": kind });
    // `play_id` is the engine's handle on this one playback — what `stop`
    // targets, what a gain change addresses, and what a completion correlates
    // against. Absent on backends that assign none (rtpengine / rtpproxy), and
    // then omitted rather than faked, so a controller can tell "this engine has
    // no handles" from "handle 0".
    if let (Some(object), Some(play_id)) = (reply.as_object_mut(), outcome.play_id) {
        object.insert("play_id".to_string(), serde_json::json!(play_id));
    }
    if let (Some(object), Some(duration_ms)) = (reply.as_object_mut(), outcome.duration_ms) {
        object.insert("duration_ms".to_string(), serde_json::json!(duration_ms));
    }
    if let (Some(object), Some(play_id)) = (started.as_object_mut(), outcome.play_id) {
        object.insert("play_id".to_string(), serde_json::json!(play_id));
    }
    if let (Some(object), Some(duration_ms)) = (started.as_object_mut(), outcome.duration_ms) {
        object.insert("duration_ms".to_string(), serde_json::json!(duration_ms));
    }
    (ControlResult::Ok(reply), Some(started))
}

/// `play` — start an announcement on the A-leg's media. Fire-and-forget: `wait`
/// is false, so this returns on the backend's *accept*, never blocking on
/// playback completion (the far-end result is not the command reply).
///
/// The accept is also published as a `PlayStarted` event, so a controller that
/// runs its playback logic off the event stream — a watchdog on a source that
/// may never produce audio, a gain ramp on a prompt — has one ordered place to
/// hang it rather than having to join a command reply against later events.
/// The event and the command reply travel on different paths and either may
/// land first; both carry the same `play_id`, which is what correlates them.
async fn play(channel: &ChannelRef, args: &serde_json::Value) -> ControlResult {
    let source = match parse_play_source(args) {
        Ok(source) => source,
        Err(message) => return ControlResult::error(ControlErrorCode::BadRequest, message),
    };
    let repeat = args.get("repeat").and_then(|value| value.as_u64());
    let start_ms = args.get("start_ms").and_then(|value| value.as_u64());
    let duration_ms = args.get("duration_ms").and_then(|value| value.as_u64());
    let to_tag = args
        .get("to_tag")
        .and_then(|value| value.as_str())
        .map(|value| value.to_string());

    let (backend, call_id, from_tag) = match media_target(channel) {
        Ok(target) => target,
        Err(result) => return result,
    };
    let result = backend
        .play_media(
            &call_id,
            &from_tag,
            &source,
            repeat,
            start_ms,
            duration_ms,
            to_tag.as_deref(),
            // The control plane's `play` is a supersede, matching its documented
            // "start an announcement" shape; overlays are a scripting-API verb.
            false,
            args.get("gain_decibels")
                .and_then(|value| value.as_i64())
                .and_then(|value| i32::try_from(value).ok()),
            false,
        )
        .await;
    let (reply, started) = play_accept(&channel.channel_id, &source, result);
    if let Some(payload) = started {
        crate::control::notify_channel_event(&channel.sip_call_id, "PlayStarted", payload);
    }
    reply
}

/// `stop` — stop any prompt currently playing on the A-leg's media.
async fn stop(channel: &ChannelRef) -> ControlResult {
    let (backend, call_id, from_tag) = match media_target(channel) {
        Ok(target) => target,
        Err(result) => return result,
    };
    match backend.stop_media(&call_id, &from_tag, None).await {
        Ok(()) => ControlResult::Ok(
            serde_json::json!({ "channel": channel.channel_id, "state": "stopped" }),
        ),
        Err(error) => media_error(error),
    }
}

/// `dtmf` — inject DTMF digits toward the A-leg (fire-and-forget).
async fn dtmf(channel: &ChannelRef, args: &serde_json::Value) -> ControlResult {
    let digits = match args
        .get("digits")
        .or_else(|| args.get("code"))
        .and_then(|value| value.as_str())
    {
        Some(digits) if !digits.is_empty() => digits.to_string(),
        Some(_) => {
            return ControlResult::error(
                ControlErrorCode::BadRequest,
                "dtmf args.digits must be a non-empty string",
            );
        }
        None => {
            return ControlResult::error(ControlErrorCode::BadRequest, "dtmf requires args.digits");
        }
    };
    let duration_ms = args.get("duration_ms").and_then(|value| value.as_u64());
    let volume_dbm0 = args.get("volume_dbm0").and_then(|value| value.as_i64());
    let pause_ms = args.get("pause_ms").and_then(|value| value.as_u64());
    let to_tag = args
        .get("to_tag")
        .and_then(|value| value.as_str())
        .map(|value| value.to_string());

    let (backend, call_id, from_tag) = match media_target(channel) {
        Ok(target) => target,
        Err(result) => return result,
    };
    match backend
        .play_dtmf(
            &call_id,
            &from_tag,
            &digits,
            duration_ms,
            volume_dbm0,
            pause_ms,
            to_tag.as_deref(),
        )
        .await
    {
        Ok(()) => ControlResult::Ok(
            serde_json::json!({ "channel": channel.channel_id, "state": "playing", "digits": digits }),
        ),
        Err(error) => media_error(error),
    }
}

/// `hold` / `unhold` — gentle media hold via silence. `hold` → `silence_media`,
/// `unhold` → `unsilence_media` (drop/undrop of packets, `block_media`, is a
/// separate future gate verb — deliberately not exposed here).
async fn hold(channel: &ChannelRef, engage: bool) -> ControlResult {
    let (backend, call_id, from_tag) = match media_target(channel) {
        Ok(target) => target,
        Err(result) => return result,
    };
    let outcome = if engage {
        backend.silence_media(&call_id, &from_tag).await
    } else {
        backend.unsilence_media(&call_id, &from_tag).await
    };
    match outcome {
        Ok(()) => {
            let state = if engage { "held" } else { "unheld" };
            ControlResult::Ok(serde_json::json!({ "channel": channel.channel_id, "state": state }))
        }
        Err(error) => media_error(error),
    }
}

/// `stream_start` — attach a WebSocket audio tee streaming a copy of the call's
/// decoded audio to `ws_uri` while the call keeps relaying. siphon-rtp backend
/// only: rtpengine / rtpproxy return `unsupported_verb` (a hollow success would
/// read as "the tee is attached" while nothing reaches the consumer).
async fn stream_start(channel: &ChannelRef, args: &serde_json::Value) -> ControlResult {
    let Some(ws_uri) = args.get("ws_uri").and_then(|value| value.as_str()) else {
        return ControlResult::error(
            ControlErrorCode::BadRequest,
            "stream_start requires args.ws_uri",
        );
    };
    let ws_uri = ws_uri.to_string();
    let mode = match parse_stream_mode(args.get("mode"), "stream_start") {
        Ok(mode) => mode,
        Err(result) => return result,
    };

    if mode == StreamMode::Bridge {
        // `direction`, `channels` and `sample_rate` shape a *tee's* wire; a
        // takeover bridge has one leg and negotiates its own rate with the
        // server. Refused rather than ignored, because silently dropping a
        // `channels: 2` would hand the controller a mono takeover it believed
        // was stereo, and it would not find out from the reply.
        for unsupported in ["direction", "channels", "sample_rate"] {
            if args.get(unsupported).is_some_and(|value| !value.is_null()) {
                return ControlResult::error(
                    ControlErrorCode::BadRequest,
                    format!(
                        "stream_start args.{unsupported} applies to mode=tee only; \
                         a takeover bridge negotiates its own wire shape"
                    ),
                );
            }
        }
        let (backend, call_id, from_tag) = match media_target(channel) {
            Ok(target) => target,
            Err(result) => return result,
        };
        return match backend.attach_ws_bridge(&call_id, &from_tag, &ws_uri).await {
            Ok(()) => {
                crate::dispatcher::b2bua_media_set_ws_bridge_attached(&channel.sip_call_id, true);
                ControlResult::Ok(serde_json::json!({
                    "channel": channel.channel_id,
                    "state": "bridged",
                }))
            }
            Err(error) => media_error(error),
        };
    }
    let direction = match args.get("direction").and_then(|value| value.as_str()) {
        None => crate::rtpengine::profile::WsTeeDirection::Both,
        Some(value) => match crate::rtpengine::profile::WsTeeDirection::parse(value) {
            Some(direction) => direction,
            None => {
                return ControlResult::error(
                    ControlErrorCode::BadRequest,
                    format!("stream_start args.direction must be one of both/caller/callee, got '{value}'"),
                );
            }
        },
    };
    let channels = match parse_stream_channels(args.get("channels")) {
        Ok(channels) => channels,
        Err(message) => return ControlResult::error(ControlErrorCode::BadRequest, message),
    };
    // Rejected here rather than at the engine, which fails the attach on a bad
    // rate rather than clamping — the controller gets the rule, not a generic
    // engine refusal.
    let sample_rate = match args.get("sample_rate") {
        None => None,
        Some(value) if value.is_null() => None,
        Some(value) => {
            let Some(rate) = value.as_u64().and_then(|rate| u32::try_from(rate).ok()) else {
                return ControlResult::error(
                    ControlErrorCode::BadRequest,
                    "stream_start args.sample_rate must be an integer".to_string(),
                );
            };
            if let Err(reason) = crate::rtpengine::profile::validate_ws_sample_rate(rate) {
                return ControlResult::error(
                    ControlErrorCode::BadRequest,
                    format!("stream_start args.sample_rate {reason}"),
                );
            }
            Some(rate)
        }
    };

    let (backend, call_id, from_tag) = match media_target(channel) {
        Ok(target) => target,
        Err(result) => return result,
    };
    match backend
        .attach_ws_tee(
            &call_id,
            &from_tag,
            &ws_uri,
            direction,
            channels,
            sample_rate,
        )
        .await
    {
        Ok(()) => {
            // Recorded only on acceptance, so a refused attach never leaves a
            // later bridge plan detaching a tee that is not there.
            crate::dispatcher::b2bua_media_set_ws_tee(&channel.sip_call_id, Some(ws_uri));
            ControlResult::Ok(
                serde_json::json!({ "channel": channel.channel_id, "state": "streaming" }),
            )
        }
        Err(error) => media_error(error),
    }
}

/// `stream_stop` — detach the WebSocket audio tee (idempotent on siphon-rtp;
/// `unsupported_verb` on the other backends, same reason as `stream_start`).
async fn stream_stop(channel: &ChannelRef, args: &serde_json::Value) -> ControlResult {
    let mode = match parse_stream_mode(args.get("mode"), "stream_stop") {
        Ok(mode) => mode,
        Err(result) => return result,
    };
    let (backend, call_id, from_tag) = match media_target(channel) {
        Ok(target) => target,
        Err(result) => return result,
    };
    // A tee detach is idempotent; a bridge detach is not, and the engine
    // refuses one where there is no relay to return the call to (a
    // `ws_uri`-negotiated bridge, or a single-leg takeover). That refusal is
    // surfaced rather than smoothed into an ok, because the alternative is a
    // live call with no audio path at all.
    let outcome = match mode {
        StreamMode::Tee => backend.detach_ws_tee(&call_id, &from_tag).await,
        StreamMode::Bridge => backend.detach_ws_bridge(&call_id, &from_tag).await,
    };
    match outcome {
        Ok(()) => {
            match mode {
                StreamMode::Tee => {
                    crate::dispatcher::b2bua_media_set_ws_tee(&channel.sip_call_id, None)
                }
                StreamMode::Bridge => crate::dispatcher::b2bua_media_set_ws_bridge_attached(
                    &channel.sip_call_id,
                    false,
                ),
            }
            ControlResult::Ok(
                serde_json::json!({ "channel": channel.channel_id, "state": "detached" }),
            )
        }
        Err(error) => media_error(error),
    }
}

/// `originate` — place an outbound call the controller owns from the moment it
/// is accepted.
///
/// **The channel id comes from the caller, never from siphon.** A controller
/// stages its per-call context — routing, media plan, its own state — keyed on
/// an id it chose *before* anything reaches the network; minting the id here and
/// returning it would force a round-trip that a well-built controller has
/// designed out, and would leave a window where the call exists and the
/// controller cannot name it. A collision with a live channel is a `conflict`,
/// never a silent re-point (which would strand the first call).
///
/// **Asynchronous by construction.** The reply is the *local* action — "the
/// INVITE is on the wire" — and returns before the callee has done anything.
/// Ringing (`ChannelStateChange`), answer (`ChannelStateChange{state:answered}`)
/// and hangup (`StasisEnd`, with the SIP cause) arrive later as events on the
/// supplied id. A synchronous originate that blocked to answer-or-timeout would
/// serialise this connection's whole command stream behind one ringing phone and
/// make ringback or a prompt during ring impossible.
///
/// The channel is registered **before** the INVITE is dialed (the two-phase
/// [`crate::dispatcher::b2bua_originate_prepare`] / `..._dial` split), so a
/// callee that answers instantly cannot beat its own `StasisStart`.
fn originate(command: AdapterCommand) -> ControlResult {
    let Some(bus) = ControlBus::global() else {
        return ControlResult::error(
            ControlErrorCode::Unavailable,
            "control plane is not installed",
        );
    };
    originate_with_bus(&bus, command)
}

/// [`originate`] with the bus injected, so the id-collision and ownership rules
/// are testable without a process-global control plane.
fn originate_with_bus(bus: &std::sync::Arc<ControlBus>, command: AdapterCommand) -> ControlResult {
    let args = &command.args;
    let Some(channel_id) = args.get("channel").and_then(|value| value.as_str()) else {
        return ControlResult::error(
            ControlErrorCode::BadRequest,
            "originate requires args.channel — the caller-supplied channel id this call is addressed by",
        );
    };
    if channel_id.trim().is_empty() {
        return ControlResult::error(
            ControlErrorCode::BadRequest,
            "originate args.channel must not be empty",
        );
    }
    let Some(to) = args.get("to").and_then(|value| value.as_str()) else {
        return ControlResult::error(ControlErrorCode::BadRequest, "originate requires args.to");
    };

    let media = match parse_originate_media(args) {
        Ok(media) => media,
        Err(message) => return ControlResult::error(ControlErrorCode::BadRequest, message),
    };
    let privacy = match parse_privacy(args.get("privacy")) {
        Ok(privacy) => privacy,
        Err(message) => return ControlResult::error(ControlErrorCode::BadRequest, message),
    };
    let headers = parse_extra_headers(args.get("headers"));
    let timeout_secs = args
        .get("timeout")
        .and_then(|value| value.as_u64())
        .unwrap_or(30) as u32;
    let vars: HashMap<String, String> = args
        .get("vars")
        .and_then(|value| value.as_object())
        .map(|object| {
            object
                .iter()
                .filter_map(|(key, value)| value.as_str().map(|v| (key.clone(), v.to_string())))
                .collect()
        })
        .unwrap_or_default();
    let on_lost = args
        .get("on_lost")
        .and_then(|value| value.as_str())
        .unwrap_or("hangup")
        .to_string();

    if bus.channel_exists(channel_id) {
        return ControlResult::error(
            ControlErrorCode::Conflict,
            format!("channel '{channel_id}' is already in use — pick a different id"),
        );
    }
    // Resolve the owner up front: a channel with no live owner would be
    // unaddressable and would leak, so a command racing its own socket close
    // must fail before anything is placed on the wire.
    let Some(conn) = bus.connection_for_command(&command.origin.app, command.origin.conn_id) else {
        return ControlResult::error(
            ControlErrorCode::Unavailable,
            "the commanding connection is gone — nothing would own the originated call",
        );
    };

    let params = crate::dispatcher::OriginateParams {
        to: to.to_string(),
        to_display: string_arg(args, "to_display"),
        from: string_arg(args, "from"),
        from_display: string_arg(args, "from_display"),
        next_hop: string_arg(args, "next_hop"),
        p_asserted_identity: string_arg(args, "p_asserted_identity"),
        privacy,
        headers,
        timeout_secs,
        media,
    };

    let prepared = match crate::dispatcher::b2bua_originate_prepare(params) {
        Ok(prepared) => prepared,
        Err(error) => return originate_error(error),
    };

    // Own it before it rings: register under the caller's id, then dial.
    bus.register_channel(
        channel_id,
        &conn,
        &prepared.internal_call_id,
        &prepared.sip_call_id,
        &on_lost,
        vars,
    );
    if !crate::dispatcher::b2bua_originate_dial(&prepared) {
        bus.remove_channel(channel_id);
        return ControlResult::error(
            ControlErrorCode::Unavailable,
            "the originated call vanished before its INVITE could be sent",
        );
    }

    ControlResult::Ok(serde_json::json!({
        "channel": channel_id,
        "call_id": prepared.internal_call_id,
        "sip_call_id": prepared.sip_call_id,
        "state": "calling",
    }))
}

/// Dispatch `bridge` / `unbridge`.
///
/// `bridge` is the one verb that addresses **two** channels: the substrate
/// resolves and ownership-checks the target, and the second is named in
/// `args.with` and checked here against the same connection — a controller can
/// only bridge two legs it owns, or one app could join another app's call to
/// its own.
async fn apply_bridge_verb(command: AdapterCommand) -> ControlResult {
    let channel = match controlled_channel(&command) {
        Ok(channel) => channel,
        Err(result) => return result,
    };
    match command.verb.as_str() {
        "bridge" => bridge(&channel, &command).await,
        "unbridge" => unbridge(&channel, &command.args).await,
        other => ControlResult::error(
            ControlErrorCode::UnsupportedVerb,
            format!("sip adapter does not implement verb '{other}' in this build"),
        ),
    }
}

/// Join the target channel to the one named in `args.with`.
///
/// The reply reports the **local** action only, the same rule every verb on this
/// rail follows: the media has been re-pointed and the first re-INVITE is on the
/// wire. A bridge is two RFC 3261 §14 re-INVITEs across two dialogs, and whether
/// the far ends accept them is a far-end outcome — it arrives as exactly one
/// `ChannelBridged` / `BridgeFailed` on both channels.
async fn bridge(channel: &ChannelRef, command: &AdapterCommand) -> ControlResult {
    let Some(bus) = ControlBus::global() else {
        return ControlResult::error(
            ControlErrorCode::Unavailable,
            "control plane is not installed",
        );
    };
    bridge_with_bus(&bus, channel, command).await
}

/// [`bridge`] with the bus injected, so the argument and ownership rules are
/// testable without a process-global control plane.
async fn bridge_with_bus(
    bus: &std::sync::Arc<ControlBus>,
    channel: &ChannelRef,
    command: &AdapterCommand,
) -> ControlResult {
    let args = &command.args;
    let Some(with_channel_id) = args.get("with").and_then(|value| value.as_str()) else {
        return ControlResult::error(
            ControlErrorCode::BadRequest,
            "bridge requires args.with — the channel id of the other leg to join",
        );
    };
    if with_channel_id.trim().is_empty() {
        return ControlResult::error(
            ControlErrorCode::BadRequest,
            "bridge args.with must not be empty",
        );
    }
    if with_channel_id == channel.channel_id {
        return ControlResult::error(
            ControlErrorCode::BadRequest,
            format!(
                "cannot bridge channel '{}' to itself — name two different channels",
                channel.channel_id
            ),
        );
    }
    let on_peer_hangup = match args.get("on_peer_hangup") {
        None => crate::b2bua::bridge::PeerHangupPolicy::default(),
        Some(value) if value.is_null() => crate::b2bua::bridge::PeerHangupPolicy::default(),
        Some(value) => {
            let Some(text) = value.as_str() else {
                return ControlResult::error(
                    ControlErrorCode::BadRequest,
                    "bridge args.on_peer_hangup must be a string",
                );
            };
            let Some(policy) = crate::b2bua::bridge::PeerHangupPolicy::parse(text) else {
                let detail = format!(
                    "bridge args.on_peer_hangup must be \"hangup\" or \"hold\", got '{text}'"
                );
                return ControlResult::error(ControlErrorCode::BadRequest, detail);
            };
            policy
        }
    };

    // Ownership on the second leg is checked here, not by the substrate: it only
    // resolves `target`. Same exactly-one-owner rule, same typed answers.
    let with = match bus.owns(with_channel_id, &command.origin.app, command.origin.conn_id) {
        crate::control::Ownership::Owned(reference) => reference,
        crate::control::Ownership::Forbidden => {
            return ControlResult::error(
                ControlErrorCode::Forbidden,
                format!("channel '{with_channel_id}' is not yours to bridge"),
            )
        }
        crate::control::Ownership::Unknown => {
            return ControlResult::error(
                ControlErrorCode::NotFound,
                format!("no such channel '{with_channel_id}'"),
            )
        }
    };

    let params = crate::dispatcher::BridgeParams {
        anchor_sip_call_id: channel.sip_call_id.clone(),
        peer_sip_call_id: with.sip_call_id.clone(),
        on_peer_hangup,
    };
    match crate::dispatcher::b2bua_bridge_calls(params).await {
        Ok(accepted) => {
            // Which of the two legs kept its media. Normally the target, but
            // the other one when only it had a session to keep.
            let anchor_channel = if accepted.anchor_sip_call_id == channel.sip_call_id {
                channel.channel_id.clone()
            } else {
                with.channel_id.clone()
            };
            ControlResult::Ok(serde_json::json!({
                "channel": channel.channel_id,
                "with": with.channel_id,
                "anchor": anchor_channel,
                "call_id": accepted.anchor_call_id,
                "peer_call_id": accepted.peer_call_id,
                "anchored": accepted.anchored,
                "on_peer_hangup": on_peer_hangup.as_str(),
                "state": "bridging",
            }))
        }
        Err(error) => bridge_error(error),
    }
}

/// Break the target channel's bridge. Both legs stay answered, owned and held.
async fn unbridge(channel: &ChannelRef, args: &serde_json::Value) -> ControlResult {
    let reason = args
        .get("reason")
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("unbridged")
        .to_string();
    match crate::dispatcher::b2bua_unbridge_call(&channel.sip_call_id, &reason).await {
        Ok((_peer_call_id, peer_sip_call_id)) => {
            let peer_channel = ControlBus::global()
                .and_then(|bus| bus.channel_id_for_sip_call_id(&peer_sip_call_id));
            ControlResult::Ok(serde_json::json!({
                "channel": channel.channel_id,
                "with": peer_channel,
                "reason": reason,
                "state": "unbridging",
            }))
        }
        Err(error) => bridge_error(error),
    }
}

/// Map a [`crate::b2bua::bridge::BridgeError`] onto its own wire code, so a
/// caller can tell an unknown leg from a leg in the wrong state from a backend
/// that cannot express the bridge — and never gets a hollow success.
fn bridge_error(error: crate::b2bua::bridge::BridgeError) -> ControlResult {
    use crate::b2bua::bridge::BridgeError;
    let message = error.to_string();
    match error {
        // The leg is not there to bridge.
        BridgeError::UnknownLeg { .. } => ControlResult::error(ControlErrorCode::NotFound, message),
        // The frame named the same leg twice — well formed, but not a bridge.
        BridgeError::SameLeg(_) => ControlResult::error(ControlErrorCode::BadRequest, message),
        // The leg exists and is addressable, but is in the wrong state for this
        // verb. Distinct from not_found, and distinct from a malformed frame:
        // the fix is to wait (or unbridge first), not to change the request.
        BridgeError::NotAnswered { .. }
        | BridgeError::AlreadyBridged { .. }
        | BridgeError::NotBridged { .. }
        | BridgeError::Glare { .. }
        | BridgeError::NoMediaDescription { .. } => {
            ControlResult::error(ControlErrorCode::InvalidState, message)
        }
        // The configured media backend cannot express this bridge.
        BridgeError::Unsupported(_) => {
            ControlResult::error(ControlErrorCode::UnsupportedVerb, message)
        }
        BridgeError::Unavailable(_) => ControlResult::error(ControlErrorCode::Unavailable, message),
    }
}

/// Read an optional non-empty string argument.
fn string_arg(args: &serde_json::Value, name: &str) -> Option<String> {
    args.get(name)
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string())
}

/// Parse the media plan: exactly one of `args.sdp` (a controller-supplied
/// offer) or `args.media: true` (siphon anchors the leg on the media backend).
///
/// Neither is a `bad_request` rather than a default, because an INVITE with no
/// offer and no plan to answer the callee's leaves its 2xx un-answerable
/// (RFC 3261 §13.2.2.4) — a connected call with no audio, which is the exact
/// hollow success this rail refuses to produce.
fn parse_originate_media(
    args: &serde_json::Value,
) -> Result<crate::dispatcher::OriginateMedia, String> {
    let sdp = args.get("sdp").and_then(|value| value.as_str());
    let anchor = args
        .get("media")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    match (sdp, anchor) {
        (Some(_), true) => Err(
            "originate takes either args.sdp (your own offer) or args.media=true (siphon anchors the leg), not both"
                .to_string(),
        ),
        (Some(sdp), false) if sdp.trim().is_empty() => {
            Err("originate args.sdp must not be empty".to_string())
        }
        (Some(sdp), false) => Ok(crate::dispatcher::OriginateMedia::Offer(sdp.to_string())),
        (None, true) => Ok(crate::dispatcher::OriginateMedia::Anchor {
            profile: args
                .get("profile")
                .and_then(|value| value.as_str())
                .unwrap_or("rtp_passthrough")
                .to_string(),
            ws_uri: args
                .get("ws_uri")
                .and_then(|value| value.as_str())
                .map(|value| value.to_string()),
        }),
        (None, false) => Err(
            "originate requires a media plan: args.sdp (your own offer) or args.media=true (siphon anchors the leg)"
                .to_string(),
        ),
    }
}

/// Parse the optional `privacy` argument (RFC 3323 §4.1 / TS 24.607). An
/// unrecognised value is a typed error, never a silent "present the CLI" —
/// guessing at a privacy setting is how identities leak.
fn parse_privacy(
    value: Option<&serde_json::Value>,
) -> Result<Option<crate::sip::privacy::CallerIdPresentation>, String> {
    match value {
        None => Ok(None),
        Some(value) if value.is_null() => Ok(None),
        Some(value) => match value.as_str() {
            Some(text) => crate::sip::privacy::CallerIdPresentation::parse(text)
                .map(Some)
                .ok_or_else(|| {
                    format!("originate args.privacy must be \"allowed\" or \"restricted\", got '{text}'")
                }),
            None => Err("originate args.privacy must be a string".to_string()),
        },
    }
}

/// Map an [`crate::dispatcher::OriginateError`] onto its own wire code, so a
/// caller can tell a bad URI from no route from a backend that cannot do it.
fn originate_error(error: crate::dispatcher::OriginateError) -> ControlResult {
    use crate::dispatcher::OriginateError;
    let message = error.to_string();
    match error {
        OriginateError::InvalidUri { .. } => {
            ControlResult::error(ControlErrorCode::BadRequest, message)
        }
        // No reachable destination for the target: the request was well formed
        // and the resource simply is not there to be called.
        OriginateError::Unroutable(_) => ControlResult::error(ControlErrorCode::NotFound, message),
        OriginateError::Unsupported(_) => {
            ControlResult::error(ControlErrorCode::UnsupportedVerb, message)
        }
        OriginateError::Unavailable(_) | OriginateError::BuildFailed(_) => {
            ControlResult::error(ControlErrorCode::Unavailable, message)
        }
    }
}

/// Fetch a clone of the stored A-leg INVITE Arc for a controlled call.
fn stored_invite(
    call_actor_id: &str,
) -> Option<std::sync::Arc<std::sync::Mutex<crate::sip::message::SipMessage>>> {
    let store = crate::b2bua::actor::global_call_store()?;
    let call = store.get_call(call_actor_id)?;
    call.a_leg_invite.clone()
}

/// Read `code`/`reason`/`body`/`content_type` from a verb's args.
fn response_args(
    args: &serde_json::Value,
    default_code: u16,
    default_reason: &str,
) -> (u16, String, Option<Vec<u8>>, Option<String>) {
    let code = args
        .get("code")
        .and_then(|v| v.as_u64())
        .map(|c| c as u16)
        .unwrap_or(default_code);
    let reason = args
        .get("reason")
        .and_then(|v| v.as_str())
        .unwrap_or(default_reason)
        .to_string();
    let body = args
        .get("body")
        .and_then(|v| v.as_str())
        .map(|b| b.as_bytes().to_vec());
    let content_type = args
        .get("content_type")
        .and_then(|v| v.as_str())
        .map(|c| c.to_string());
    (code, reason, body, content_type)
}

/// Whether an argument is present and not JSON `null` — an explicit `null` is
/// how most clients spell "not set", so it has to read as absent.
fn arg_present(args: &serde_json::Value, key: &str) -> bool {
    args.get(key).is_some_and(|value| !value.is_null())
}

/// The `state` token for a provisional siphon just sent, by the **same rule** as
/// the callee-side `ChannelStateChange` on an originated leg: a 1xx carrying a
/// body opened an early-media path (`progress`); one that did not is alerting
/// only (`ringing`). One vocabulary in both directions, so an application that
/// already reads the event needs no second mapping for the verb reply.
///
/// RFC 3261 §13.2.1 makes the 180 the "callee is being alerted" signal and
/// §21.1.2 gives it no session semantics; RFC 3960 §3.1 puts early media on the
/// response that carries the SDP.
fn provisional_state(has_body: bool) -> &'static str {
    if has_body {
        "progress"
    } else {
        "ringing"
    }
}

/// Send one UAS response on the parked A-leg. `Err` is the typed reply to hand
/// back; `Ok` means it is on the wire.
fn send_uas_response(
    channel: &ChannelRef,
    code: u16,
    reason: &str,
    body: Option<Vec<u8>>,
    content_type: Option<&str>,
    final_response: bool,
) -> Result<(), ControlResult> {
    let Some(invite_arc) = stored_invite(&channel.call_actor_id) else {
        return Err(ControlResult::error(
            ControlErrorCode::NotFound,
            "call is gone",
        ));
    };
    let Ok(invite) = invite_arc.lock() else {
        return Err(ControlResult::error(
            ControlErrorCode::Unavailable,
            "call invite lock poisoned",
        ));
    };
    let sent = if final_response {
        crate::dispatcher::b2bua_answer_call(
            &channel.call_actor_id,
            &invite,
            code,
            reason,
            body,
            content_type,
        )
    } else {
        crate::dispatcher::b2bua_progress_call(
            &channel.call_actor_id,
            &invite,
            code,
            reason,
            body,
            content_type,
        )
    };
    if sent {
        Ok(())
    } else {
        Err(ControlResult::error(
            ControlErrorCode::NotFound,
            "call is gone",
        ))
    }
}

fn answer(channel: &ChannelRef, args: &serde_json::Value, final_response: bool) -> ControlResult {
    let (default_code, default_reason) = if final_response {
        (200, "OK")
    } else {
        (183, "Session Progress")
    };
    let (code, reason, body, content_type) = response_args(args, default_code, default_reason);

    if final_response && !(200..300).contains(&code) {
        return ControlResult::error(ControlErrorCode::BadRequest, "answer requires a 2xx code");
    }
    if !final_response && !(100..200).contains(&code) {
        return ControlResult::error(ControlErrorCode::BadRequest, "progress requires a 1xx code");
    }

    let has_body = body.as_ref().is_some_and(|bytes| !bytes.is_empty());
    if let Err(result) = send_uas_response(
        channel,
        code,
        &reason,
        body,
        content_type.as_deref(),
        final_response,
    ) {
        return result;
    }
    if final_response {
        return ControlResult::Ok(
            serde_json::json!({ "channel": channel.channel_id, "state": "answered", "code": code }),
        );
    }
    // The reply names which of the two this provisional actually was, instead of
    // calling every 1xx "ringing": a 183 carrying early media reported as
    // ringing is the exact conflation the `ring` / `progress` split removes.
    ControlResult::Ok(serde_json::json!({
        "channel": channel.channel_id,
        "state": provisional_state(has_body),
        "code": code,
        "early_media": has_body,
    }))
}

/// `ring` — send `180 Ringing` on the parked A-leg: alerting, and nothing else.
///
/// RFC 3261 §13.2.1 has the UAS send a 180 while the callee is being alerted,
/// and §21.1.2 gives that response no session semantics; RFC 3960 §3.1 puts
/// early media on a response that carries SDP. Two different acts, so two verbs:
/// an application rings for an interval of its own choosing with `ring`, and
/// separately opens an early-media path with `progress`, without having to know
/// which status code carries which meaning.
///
/// A body is refused rather than sent, because a 180 with SDP *is* an
/// early-media response — accepting one here would put an early-media offer on
/// the wire under a verb whose contract is that it only alerts.
fn ring(channel: &ChannelRef, args: &serde_json::Value) -> ControlResult {
    if arg_present(args, "body") || arg_present(args, "content_type") {
        return ControlResult::error(
            ControlErrorCode::BadRequest,
            "ring sends a plain 180 Ringing (alerting only); SDP on an 18x is early media \
             (RFC 3960 §3.1) — use the progress verb for that",
        );
    }
    let reason = args
        .get("reason")
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("Ringing")
        .to_string();
    if let Err(result) = send_uas_response(channel, 180, &reason, None, None, false) {
        return result;
    }
    ControlResult::Ok(serde_json::json!({
        "channel": channel.channel_id,
        "state": "ringing",
        "code": 180,
        "early_media": false,
    }))
}

fn reject(channel: &ChannelRef, args: &serde_json::Value) -> ControlResult {
    let (code, reason, _, _) = response_args(args, 603, "Decline");
    if !(300..700).contains(&code) {
        return ControlResult::error(
            ControlErrorCode::BadRequest,
            "reject requires a 3xx-6xx code",
        );
    }
    if crate::dispatcher::b2bua_reject_call(&channel.call_actor_id, code, &reason) {
        ControlResult::Ok(
            serde_json::json!({ "channel": channel.channel_id, "state": "terminated", "code": code }),
        )
    } else {
        ControlResult::error(ControlErrorCode::NotFound, "call is gone")
    }
}

fn hangup(channel: &ChannelRef, args: &serde_json::Value) -> ControlResult {
    let reason = args.get("reason").and_then(|v| v.as_str());
    let (answered, originated) = crate::b2bua::actor::global_call_store()
        .and_then(|store| {
            store.get_call(&channel.call_actor_id).map(|call| {
                (
                    matches!(call.state, crate::b2bua::actor::CallState::Answered),
                    call.originated,
                )
            })
        })
        .unwrap_or((false, false));

    let ok = if answered {
        // Answered: BYE both legs via the full teardown funnel (Rf/Ro/CDR/media).
        crate::dispatcher::b2bua_terminate_call(&channel.sip_call_id, reason)
    } else if originated {
        // A call siphon placed that has not answered: abandon it with a CANCEL on
        // our own INVITE (RFC 3261 §9.1). The arm below sends a final *response*,
        // which a UAC has no business sending to the party it is calling.
        crate::dispatcher::b2bua_cancel_originated_call(
            &channel.sip_call_id,
            Some(reason.unwrap_or("cancelled")),
        )
    } else {
        // Unanswered/parked: send a final non-2xx and tear down (no B-leg to CANCEL
        // in Phase 1's single-CallActor model).
        crate::dispatcher::b2bua_reject_call(
            &channel.call_actor_id,
            603,
            reason.unwrap_or("Decline"),
        )
    };
    if ok {
        ControlResult::Ok(
            serde_json::json!({ "channel": channel.channel_id, "state": "terminated" }),
        )
    } else {
        ControlResult::error(ControlErrorCode::NotFound, "call is gone")
    }
}

/// `refer` — send an in-dialog REFER on the A-leg (a siphon-originated cold
/// transfer).
///
/// The reply says `{"refer": "sent"}` and nothing more, deliberately: RFC 3515
/// §2.4.4 puts the transfer's outcome on the implicit subscription that follows
/// (a `message/sipfrag` NOTIFY), so folding it into the reply would mean waiting
/// on the far end inside a command. The verdict arrives as events instead —
/// `TransferProgress` while it moves, then exactly one `TransferCompleted` /
/// `TransferFailed` (see [`crate::control::TransferStage`]).
fn refer(channel: &ChannelRef, args: &serde_json::Value) -> ControlResult {
    let Some(to) = args.get("to").and_then(|v| v.as_str()) else {
        return ControlResult::error(ControlErrorCode::BadRequest, "refer requires args.to");
    };
    if let Err(error) = crate::sip::parser::parse_uri_standalone(to) {
        return ControlResult::error(
            ControlErrorCode::BadRequest,
            format!("invalid refer target: {error}"),
        );
    }
    let replaces = match parse_replaces_arg(args.get("replaces")) {
        Ok(replaces) => replaces,
        Err(message) => return ControlResult::error(ControlErrorCode::BadRequest, message),
    };
    let refer_to = crate::sip::headers::refer::ReferTo {
        uri: to.to_string(),
        replaces,
    };
    if crate::dispatcher::b2bua_refer_call(&channel.sip_call_id, refer_to) {
        ControlResult::Ok(serde_json::json!({ "channel": channel.channel_id, "refer": "sent" }))
    } else {
        ControlResult::error(ControlErrorCode::NotFound, "call is gone")
    }
}

/// `accept_refer` — accept a *controlled* call's pending inbound REFER (surfaced
/// as a `TransferRequested` event). Drives siphon's shipped transfer machinery in
/// the resolved mode. Optional `target` overrides the Refer-To URI, `next_hop`
/// steers egress, and `mode` (`"terminate"` / `"transparent"`) overrides the
/// configured `b2bua.default_refer_mode`. No pending REFER (already decided,
/// timed out, or the call is gone) → `not_found`.
fn accept_refer(channel: &ChannelRef, args: &serde_json::Value) -> ControlResult {
    let target = args.get("target").and_then(|v| v.as_str());
    if let Some(target) = target {
        if let Err(error) = crate::sip::parser::parse_uri_standalone(target) {
            return ControlResult::error(
                ControlErrorCode::BadRequest,
                format!("invalid refer target: {error}"),
            );
        }
    }
    let next_hop = args.get("next_hop").and_then(|v| v.as_str());
    if let Some(next_hop) = next_hop {
        if let Err(error) = crate::sip::parser::parse_uri_standalone(next_hop) {
            return ControlResult::error(
                ControlErrorCode::BadRequest,
                format!("invalid next_hop: {error}"),
            );
        }
    }
    let mode = match parse_refer_mode(args.get("mode")) {
        Ok(mode) => mode,
        Err(message) => return ControlResult::error(ControlErrorCode::BadRequest, message),
    };

    // Media profile for the pairing the transfer creates. Same requirement as
    // the in-process `accept_refer(profile=…)`: a direction-bound profile
    // (`srtp_to_rtp` and friends) must be replaced, because its answer half was
    // written for the party being transferred away.
    let media_profile = args.get("profile").and_then(|v| v.as_str());

    if crate::dispatcher::b2bua_accept_refer_call(
        &channel.sip_call_id,
        target.map(|s| s.to_string()),
        next_hop.map(|s| s.to_string()),
        mode,
        media_profile.map(|s| s.to_string()),
    ) {
        ControlResult::Ok(
            serde_json::json!({ "channel": channel.channel_id, "transfer": "accepted" }),
        )
    } else {
        ControlResult::error(
            ControlErrorCode::NotFound,
            "no pending transfer for this call",
        )
    }
}

/// `reject_refer` — decline a *controlled* call's pending inbound REFER with a
/// final non-2xx (default `603 Decline`). No pending REFER → `not_found`.
fn reject_refer(channel: &ChannelRef, args: &serde_json::Value) -> ControlResult {
    let (code, reason, _, _) = response_args(args, 603, "Decline");
    if !(300..700).contains(&code) {
        return ControlResult::error(
            ControlErrorCode::BadRequest,
            "reject_refer requires a 3xx-6xx code",
        );
    }
    if crate::dispatcher::b2bua_reject_refer_call(&channel.sip_call_id, code, &reason) {
        ControlResult::Ok(
            serde_json::json!({ "channel": channel.channel_id, "transfer": "rejected", "code": code }),
        )
    } else {
        ControlResult::error(
            ControlErrorCode::NotFound,
            "no pending transfer for this call",
        )
    }
}

/// Parse an optional `mode` arg for `accept_refer` into a
/// [`crate::script::api::call::ReferMode`]. Absent / null → `None` (the rail then
/// applies the configured `b2bua.default_refer_mode`); an unrecognized value is a
/// typed `bad_request`, never a silent default.
fn parse_refer_mode(
    value: Option<&serde_json::Value>,
) -> Result<Option<crate::script::api::call::ReferMode>, String> {
    use crate::script::api::call::ReferMode;
    match value {
        None => Ok(None),
        Some(value) if value.is_null() => Ok(None),
        Some(value) => match value.as_str() {
            Some("terminate") => Ok(Some(ReferMode::Terminate)),
            Some("transparent") => Ok(Some(ReferMode::Transparent)),
            _ => Err("accept_refer args.mode must be \"terminate\" or \"transparent\"".to_string()),
        },
    }
}

/// Parse an optional `replaces` arg (`{call_id, from_tag, to_tag, early_only?}`).
fn parse_replaces_arg(
    value: Option<&serde_json::Value>,
) -> Result<Option<crate::sip::headers::refer::Replaces>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let field = |key: &str| -> Result<String, String> {
        value
            .get(key)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| format!("replaces requires a string '{key}'"))
    };
    Ok(Some(crate::sip::headers::refer::Replaces {
        call_id: field("call_id")?,
        from_tag: field("from_tag")?,
        to_tag: field("to_tag")?,
        early_only: value
            .get("early_only")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
    }))
}

/// Return control to siphon with a routing decision (the `route` verb). Un-parks
/// the deferred-handover call and dials the B-leg via siphon's LCR sequential
/// failover; siphon owns the call thereafter and the control app is released.
///
/// `args.targets` is a non-empty array of either bare URI strings or objects
/// `{uri, next_hop?, headers?, timeout?}`; `args.strategy` defaults to
/// `"sequential"` (v1 supports only sequential/single — anything else is a typed
/// error, never a silent sequential); `args.headers` is an optional object
/// applied to every attempt's B-leg INVITE.
fn route(channel: &ChannelRef, args: &serde_json::Value) -> ControlResult {
    let Some(targets_json) = args.get("targets").and_then(|v| v.as_array()) else {
        return ControlResult::error(
            ControlErrorCode::BadRequest,
            "route requires args.targets (a non-empty array of URIs or {uri, next_hop, headers, timeout})",
        );
    };
    if targets_json.is_empty() {
        return ControlResult::error(
            ControlErrorCode::BadRequest,
            "route requires at least one target",
        );
    }
    let mut targets = Vec::with_capacity(targets_json.len());
    for item in targets_json {
        match parse_route_target(item) {
            Ok(target) => targets.push(target),
            Err(message) => return ControlResult::error(ControlErrorCode::BadRequest, message),
        }
    }
    let strategy = args
        .get("strategy")
        .and_then(|v| v.as_str())
        .unwrap_or("sequential");
    let extra_headers = parse_extra_headers(args.get("headers"));
    let target_count = targets.len();

    match crate::dispatcher::b2bua_route_call(
        &channel.sip_call_id,
        targets,
        strategy,
        &extra_headers,
    ) {
        Ok(true) => ControlResult::Ok(serde_json::json!({
            "channel": channel.channel_id,
            "state": "routing",
            "targets": target_count,
        })),
        Ok(false) => ControlResult::error(ControlErrorCode::NotFound, "call is gone"),
        Err(crate::dispatcher::RouteError::UnsupportedStrategy(strategy)) => ControlResult::error(
            ControlErrorCode::UnsupportedVerb,
            format!("unsupported routing strategy '{strategy}' — v1 supports sequential/single"),
        ),
        Err(crate::dispatcher::RouteError::NoTargets) => ControlResult::error(
            ControlErrorCode::BadRequest,
            "route requires at least one target",
        ),
    }
}

/// Parse one `targets[]` entry: a bare URI string, or an object
/// `{uri, next_hop?, headers?, timeout?}`.
fn parse_route_target(item: &serde_json::Value) -> Result<crate::dispatcher::RouteTarget, String> {
    if let Some(uri) = item.as_str() {
        return Ok(crate::dispatcher::RouteTarget {
            uri: uri.to_string(),
            next_hop: None,
            headers: Vec::new(),
            timeout_secs: None,
        });
    }
    let Some(object) = item.as_object() else {
        return Err(
            "each target must be a URI string or an object {uri, next_hop, headers, timeout}"
                .to_string(),
        );
    };
    let Some(uri) = object.get("uri").and_then(|v| v.as_str()) else {
        return Err("target object requires a string 'uri'".to_string());
    };
    let next_hop = object
        .get("next_hop")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let headers = object
        .get("headers")
        .map(parse_json_headers)
        .unwrap_or_default();
    let timeout_secs = object
        .get("timeout")
        .and_then(|v| v.as_u64())
        .map(|t| t as u32);
    Ok(crate::dispatcher::RouteTarget {
        uri: uri.to_string(),
        next_hop,
        headers,
        timeout_secs,
    })
}

/// Parse a command-level `headers` object (applied to every route attempt).
fn parse_extra_headers(value: Option<&serde_json::Value>) -> Vec<(String, String)> {
    value.map(parse_json_headers).unwrap_or_default()
}

/// Collect string→string pairs from a JSON object (non-string values skipped).
fn parse_json_headers(value: &serde_json::Value) -> Vec<(String, String)> {
    value
        .as_object()
        .map(|object| {
            object
                .iter()
                .filter_map(|(name, value)| value.as_str().map(|v| (name.clone(), v.to_string())))
                .collect()
        })
        .unwrap_or_default()
}

fn set_header(channel: &ChannelRef, args: &serde_json::Value) -> ControlResult {
    let (Some(name), Some(header_value)) = (
        args.get("name").and_then(|v| v.as_str()),
        args.get("value").and_then(|v| v.as_str()),
    ) else {
        return ControlResult::error(
            ControlErrorCode::BadRequest,
            "set_header requires args.name and args.value",
        );
    };
    let Some(invite_arc) = stored_invite(&channel.call_actor_id) else {
        return ControlResult::error(ControlErrorCode::NotFound, "call is gone");
    };
    let Ok(mut invite) = invite_arc.lock() else {
        return ControlResult::error(ControlErrorCode::Unavailable, "call invite lock poisoned");
    };
    invite.headers.set(name, header_value.to_string());
    ControlResult::Ok(serde_json::json!({ "channel": channel.channel_id, "header": name }))
}

/// Remove a header from the stored A-leg INVITE (mirror of [`set_header`], using
/// the `Headers::remove` API). `removed` reports whether the header was present.
fn remove_header(channel: &ChannelRef, args: &serde_json::Value) -> ControlResult {
    let Some(name) = args.get("name").and_then(|v| v.as_str()) else {
        return ControlResult::error(
            ControlErrorCode::BadRequest,
            "remove_header requires args.name",
        );
    };
    let Some(invite_arc) = stored_invite(&channel.call_actor_id) else {
        return ControlResult::error(ControlErrorCode::NotFound, "call is gone");
    };
    let Ok(mut invite) = invite_arc.lock() else {
        return ControlResult::error(ControlErrorCode::Unavailable, "call invite lock poisoned");
    };
    let was_present = invite.headers.has(name);
    invite.headers.remove(name);
    ControlResult::Ok(
        serde_json::json!({ "channel": channel.channel_id, "header": name, "removed": was_present }),
    )
}

fn get_header(channel: &ChannelRef, args: &serde_json::Value) -> ControlResult {
    let Some(name) = args.get("name").and_then(|v| v.as_str()) else {
        return ControlResult::error(
            ControlErrorCode::BadRequest,
            "get_header requires args.name",
        );
    };
    let Some(invite_arc) = stored_invite(&channel.call_actor_id) else {
        return ControlResult::error(ControlErrorCode::NotFound, "call is gone");
    };
    let Ok(invite) = invite_arc.lock() else {
        return ControlResult::error(ControlErrorCode::Unavailable, "call invite lock poisoned");
    };
    let value = invite.headers.get(name).cloned();
    ControlResult::Ok(
        serde_json::json!({ "channel": channel.channel_id, "header": name, "value": value }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn channel() -> ChannelRef {
        ChannelRef {
            channel_id: "ch1".to_string(),
            call_actor_id: "call-uuid".to_string(),
            sip_call_id: "sipcid@host".to_string(),
            app: "ivr-app".to_string(),
        }
    }

    fn test_origin() -> crate::control::CommandOrigin {
        crate::control::CommandOrigin {
            app: "ivr-app".to_string(),
            conn_id: 1,
        }
    }

    fn sip_command(verb: &str, args: serde_json::Value) -> ControlResult {
        apply_sip(AdapterCommand {
            verb: verb.to_string(),
            args,
            target: ResolvedTarget::Channel(channel()),
            origin: test_origin(),
        })
    }

    #[test]
    fn ring_refuses_a_body_because_sdp_on_an_18x_is_early_media() {
        // RFC 3960 §3.1: SDP on an 18x opens an early-media path. `ring` says it
        // only alerts, so it must refuse rather than quietly put an early-media
        // offer on the wire under that name.
        for args in [
            serde_json::json!({ "body": "v=0\r\n" }),
            serde_json::json!({ "content_type": "application/sdp" }),
        ] {
            let result = sip_command("ring", args);
            let ControlResult::Error { code, message } = result else {
                panic!("ring with a body must be refused");
            };
            assert_eq!(code, ControlErrorCode::BadRequest);
            assert!(
                message.contains("progress"),
                "the refusal must point at progress: {message}"
            );
        }
    }

    #[test]
    fn ring_reads_an_explicit_null_body_as_absent() {
        // Most clients spell "not set" as an explicit JSON null; refusing that
        // would make `ring` unusable from a client that always sends the key.
        // With no dispatcher installed the call store is empty, so reaching
        // not_found proves the arg check let it through.
        let result = sip_command(
            "ring",
            serde_json::json!({ "body": null, "content_type": null }),
        );
        assert!(
            matches!(
                result,
                ControlResult::Error {
                    code: ControlErrorCode::NotFound,
                    ..
                }
            ),
            "a null body must read as absent and let ring reach the call store"
        );
    }

    #[test]
    fn stream_mode_defaults_to_tee_and_rejects_anything_else() {
        // Absent and null both mean tee — every controller written before the
        // bridge existed keeps working, and tee is the safe default of the two
        // since a caller who meant tee and got bridge would have the call's
        // audio path silently replaced.
        assert_eq!(parse_stream_mode(None, "stream_start"), Ok(StreamMode::Tee));
        assert_eq!(
            parse_stream_mode(Some(&serde_json::Value::Null), "stream_start"),
            Ok(StreamMode::Tee)
        );
        assert_eq!(
            parse_stream_mode(Some(&serde_json::json!("tee")), "stream_start"),
            Ok(StreamMode::Tee)
        );
        assert_eq!(
            parse_stream_mode(Some(&serde_json::json!("bridge")), "stream_start"),
            Ok(StreamMode::Bridge)
        );

        // An unknown or wrongly-typed mode is refused rather than defaulted:
        // silently treating "bridged" as a tee would leave the controller
        // believing it had taken the call over.
        for bad in [
            serde_json::json!("bridged"),
            serde_json::json!("takeover"),
            serde_json::json!(""),
            serde_json::json!(1),
            serde_json::json!(true),
        ] {
            let result = parse_stream_mode(Some(&bad), "stream_start");
            assert!(
                matches!(
                    result,
                    Err(ControlResult::Error {
                        code: ControlErrorCode::BadRequest,
                        ..
                    })
                ),
                "{bad} must be refused, got {result:?}"
            );
        }
    }

    #[test]
    fn provisional_state_matches_the_originate_side_vocabulary() {
        // The callee-side ChannelStateChange already splits these two by whether
        // the 1xx carried a body; the verb reply must use the identical rule, or
        // an app needs a second mapping for the same distinction. The old reply
        // said "ringing" for every provisional, including a 183 with early media.
        assert_eq!(provisional_state(false), "ringing");
        assert_eq!(provisional_state(true), "progress");
    }

    #[test]
    fn play_accept_publishes_a_start_event_carrying_the_engines_handle() {
        use crate::rtpengine::client::PlayMediaSource;
        use crate::rtpengine::siphon_rtp::PlayMediaOutcome;

        let (reply, started) = play_accept(
            "ch1",
            &PlayMediaSource::File("/prompts/welcome.wav".to_string()),
            Ok(PlayMediaOutcome {
                play_id: Some(7),
                duration_ms: Some(1500),
            }),
        );
        let ControlResult::Ok(value) = reply else {
            panic!("an accepted play must reply ok");
        };
        assert_eq!(value["state"], "playing");
        assert_eq!(value["play_id"], 7);
        assert_eq!(value["duration_ms"], 1500);

        let started = started.expect("an accepted play must publish a start event");
        assert_eq!(started["play_id"], 7);
        assert_eq!(started["duration_ms"], 1500);
        assert_eq!(started["source"], "file");
    }

    #[test]
    fn play_accept_omits_a_handle_the_engine_never_assigned() {
        use crate::rtpengine::client::PlayMediaSource;
        use crate::rtpengine::siphon_rtp::PlayMediaOutcome;

        // rtpengine / rtpproxy assign no play_id and a fetched source has no
        // known length at accept time. Both are omitted rather than faked — a
        // fabricated `play_id: 0` is a handle a later `stop` would aim at the
        // wrong playback.
        let (reply, started) = play_accept(
            "ch1",
            &PlayMediaSource::Http("https://example.com/prompt.wav".to_string()),
            Ok(PlayMediaOutcome {
                play_id: None,
                duration_ms: None,
            }),
        );
        let ControlResult::Ok(value) = reply else {
            panic!("an accepted play must reply ok");
        };
        assert!(value.get("play_id").is_none());
        assert!(value.get("duration_ms").is_none());
        let started = started.expect("a play with no handle still started");
        assert!(started.get("play_id").is_none());
        assert!(started.get("duration_ms").is_none());
        assert_eq!(started["source"], "url");
    }

    #[test]
    fn play_the_backend_refuses_publishes_no_start_event() {
        use crate::rtpengine::client::PlayMediaSource;

        // The negative that makes the start event worth having: a playback that
        // never began must produce no PlayStarted, so "no start event yet" reads
        // as "not started" and never as "started, silently".
        let (reply, started) = play_accept(
            "ch1",
            &PlayMediaSource::File("/prompts/missing.wav".to_string()),
            Err(crate::rtpengine::RtpEngineError::Unsupported {
                operation: "play_media",
                backend: "rtpproxy",
            }),
        );
        assert!(
            matches!(reply, ControlResult::Error { .. }),
            "a refused play must answer with a typed error"
        );
        assert!(
            started.is_none(),
            "a play that never started must publish no start event"
        );
    }

    #[test]
    fn play_source_kind_names_every_source() {
        use crate::rtpengine::client::PlayMediaSource;
        assert_eq!(
            play_source_kind(&PlayMediaSource::File("/a.wav".into())),
            "file"
        );
        assert_eq!(
            play_source_kind(&PlayMediaSource::Blob(vec![0u8; 2])),
            "blob"
        );
        assert_eq!(play_source_kind(&PlayMediaSource::DbId(3)), "db_id");
        assert_eq!(
            play_source_kind(&PlayMediaSource::Tone("ringback_eu".into())),
            "tone"
        );
        assert_eq!(
            play_source_kind(&PlayMediaSource::Http("https://h/x.wav".into())),
            "url"
        );
    }

    fn originate_command(args: serde_json::Value) -> AdapterCommand {
        AdapterCommand {
            verb: "originate".to_string(),
            args,
            target: ResolvedTarget::None,
            origin: test_origin(),
        }
    }

    /// Run `originate` against a fresh bus with a live owning connection, so a
    /// test exercises the argument rules rather than the "no control plane"
    /// short-circuit.
    fn originate_args(args: serde_json::Value) -> ControlResult {
        let bus = test_bus();
        let conn = bus.register_connection("ivr-app");
        let mut command = originate_command(args);
        command.origin.conn_id = conn.id;
        originate_with_bus(&bus, command)
    }

    #[test]
    fn module_is_sip() {
        assert_eq!(SipControlAdapter::new().module(), "sip");
    }

    // --- originate ---------------------------------------------------------

    #[test]
    fn originate_without_a_channel_id_is_bad_request() {
        // The id is the caller's to choose; siphon never mints one, so its
        // absence is a malformed command rather than a defaulted call.
        let result =
            originate_args(serde_json::json!({ "to": "sip:1@carrier.example", "media": true }));
        match result {
            ControlResult::Error { code, ref message } => {
                assert_eq!(code, ControlErrorCode::BadRequest);
                assert!(message.contains("args.channel"), "message was: {message}");
            }
            other => panic!("expected bad_request, got {other:?}"),
        }
    }

    #[test]
    fn originate_with_an_empty_channel_id_is_bad_request() {
        let result = originate_args(serde_json::json!({
            "channel": "   ",
            "to": "sip:1@carrier.example",
            "media": true,
        }));
        assert!(matches!(
            result,
            ControlResult::Error {
                code: ControlErrorCode::BadRequest,
                ..
            }
        ));
    }

    #[test]
    fn originate_without_a_target_is_bad_request() {
        let result = originate_args(serde_json::json!({ "channel": "cb-1", "media": true }));
        assert!(matches!(
            result,
            ControlResult::Error {
                code: ControlErrorCode::BadRequest,
                ..
            }
        ));
    }

    #[test]
    fn originate_without_a_media_plan_is_bad_request() {
        // An INVITE with no offer and no anchor cannot answer the callee's 2xx
        // offer (RFC 3261 §13.2.2.4) — that would connect a call with no audio.
        let result = originate_args(serde_json::json!({
            "channel": "cb-1",
            "to": "sip:1@carrier.example",
        }));
        match result {
            ControlResult::Error { code, ref message } => {
                assert_eq!(code, ControlErrorCode::BadRequest);
                assert!(message.contains("media plan"), "message was: {message}");
            }
            other => panic!("expected bad_request, got {other:?}"),
        }
    }

    #[test]
    fn originate_with_both_media_plans_is_bad_request() {
        let result = originate_args(serde_json::json!({
            "channel": "cb-1",
            "to": "sip:1@carrier.example",
            "sdp": "v=0\r\n",
            "media": true,
        }));
        assert!(matches!(
            result,
            ControlResult::Error {
                code: ControlErrorCode::BadRequest,
                ..
            }
        ));
    }

    #[test]
    fn originate_with_a_bad_privacy_value_is_bad_request() {
        let result = originate_args(serde_json::json!({
            "channel": "cb-1",
            "to": "sip:1@carrier.example",
            "media": true,
            "privacy": "maybe",
        }));
        assert!(matches!(
            result,
            ControlResult::Error {
                code: ControlErrorCode::BadRequest,
                ..
            }
        ));
    }

    fn test_bus() -> std::sync::Arc<ControlBus> {
        use crate::config::ControlAppConfig;
        let (command_tx, _rx) = flume::unbounded();
        ControlBus::new(
            command_tx,
            vec![ControlAppConfig {
                name: "ivr-app".to_string(),
                token: "tok".to_string(),
                per_call_connect: false,
                connect_url: None,
                on_lost: Some("hangup".to_string()),
            }],
            64,
            crate::control::SlowConsumerPolicy::DropOldest,
            10,
            3000,
        )
    }

    #[test]
    fn originate_rejects_a_duplicate_caller_supplied_id_with_conflict() {
        // The caller owns the id, so a collision has to be told apart from a
        // malformed command: retrying the same id can never succeed, and
        // silently re-pointing it at a second call would strand the first.
        let bus = test_bus();
        let conn = bus.register_connection("ivr-app");
        bus.register_channel(
            "cb-1",
            &conn,
            "call-uuid",
            "sipcid@host",
            "hangup",
            HashMap::new(),
        );

        let mut command = originate_command(serde_json::json!({
            "channel": "cb-1",
            "to": "sip:1@carrier.example",
            "media": true,
        }));
        command.origin.conn_id = conn.id;
        let result = originate_with_bus(&bus, command);
        match result {
            ControlResult::Error { code, ref message } => {
                assert_eq!(code, ControlErrorCode::Conflict, "message was: {message}");
                assert!(message.contains("cb-1"), "message was: {message}");
            }
            other => panic!("expected conflict, got {other:?}"),
        }
    }

    #[test]
    fn originate_from_a_dead_connection_is_unavailable() {
        // Nothing would own the resulting channel, so it must fail before an
        // INVITE goes out — an ownerless channel is a leak with a live call
        // behind it.
        let bus = test_bus();
        let mut command = originate_command(serde_json::json!({
            "channel": "cb-ghost",
            "to": "sip:1@carrier.example",
            "media": true,
        }));
        command.origin.conn_id = 99;
        assert!(matches!(
            originate_with_bus(&bus, command),
            ControlResult::Error {
                code: ControlErrorCode::Unavailable,
                ..
            }
        ));
        assert!(
            !bus.channel_exists("cb-ghost"),
            "a refused originate must register no channel"
        );
    }

    #[test]
    fn a_refused_originate_registers_no_channel() {
        // The dispatcher is not running in this process, so prepare fails; the
        // caller's id must be left free for a retry.
        let bus = test_bus();
        let conn = bus.register_connection("ivr-app");
        let mut command = originate_command(serde_json::json!({
            "channel": "cb-2",
            "to": "sip:1@carrier.example",
            "media": true,
        }));
        command.origin.conn_id = conn.id;
        let result = originate_with_bus(&bus, command);
        assert!(
            matches!(result, ControlResult::Error { .. }),
            "got {result:?}"
        );
        assert!(!bus.channel_exists("cb-2"));
    }

    #[test]
    fn originate_without_a_control_bus_is_unavailable_not_a_hollow_ok() {
        // No process-global bus in the unit-test process: the command must
        // answer, and must not answer "ok" for a call nothing would own.
        let result = originate(originate_command(serde_json::json!({
            "channel": "cb-1",
            "to": "sip:1@carrier.example",
            "media": true,
        })));
        assert!(
            matches!(
                result,
                ControlResult::Error {
                    code: ControlErrorCode::Unavailable,
                    ..
                }
            ),
            "got {result:?}"
        );
    }

    #[tokio::test]
    async fn originate_dispatches_through_apply_as_a_module_level_verb() {
        // No channel target: `originate` creates the channel rather than
        // addressing one, so it must not be rejected for a missing target.
        let adapter = SipControlAdapter::new();
        let result = adapter
            .apply(originate_command(serde_json::json!({
                "channel": "cb-1", "to": "sip:1@carrier.example", "media": true
            })))
            .await;
        match result {
            ControlResult::Error { code, ref message } => {
                assert_ne!(
                    code,
                    ControlErrorCode::BadRequest,
                    "originate must not be rejected for the missing channel target: {message}"
                );
            }
            other => panic!("expected an error from the un-booted stack, got {other:?}"),
        }
    }

    #[test]
    fn parse_originate_media_variants() {
        use crate::dispatcher::OriginateMedia;
        assert_eq!(
            parse_originate_media(&serde_json::json!({ "sdp": "v=0\r\n" })),
            Ok(OriginateMedia::Offer("v=0\r\n".to_string()))
        );
        assert_eq!(
            parse_originate_media(&serde_json::json!({ "media": true })),
            Ok(OriginateMedia::Anchor {
                profile: "rtp_passthrough".to_string(),
                ws_uri: None,
            })
        );
        assert_eq!(
            parse_originate_media(&serde_json::json!({
                "media": true, "profile": "voice_ai", "ws_uri": "ws://ai.invalid/{call_id}",
            })),
            Ok(OriginateMedia::Anchor {
                profile: "voice_ai".to_string(),
                ws_uri: Some("ws://ai.invalid/{call_id}".to_string()),
            })
        );
        assert!(parse_originate_media(&serde_json::json!({})).is_err());
        assert!(parse_originate_media(&serde_json::json!({ "sdp": "" })).is_err());
        assert!(
            parse_originate_media(&serde_json::json!({ "sdp": "v=0", "media": true })).is_err()
        );
    }

    #[test]
    fn parse_privacy_variants() {
        use crate::sip::privacy::CallerIdPresentation;
        assert_eq!(parse_privacy(None), Ok(None));
        assert_eq!(parse_privacy(Some(&serde_json::Value::Null)), Ok(None));
        assert_eq!(
            parse_privacy(Some(&serde_json::json!("restricted"))),
            Ok(Some(CallerIdPresentation::Restricted))
        );
        assert_eq!(
            parse_privacy(Some(&serde_json::json!("allowed"))),
            Ok(Some(CallerIdPresentation::Allowed))
        );
        assert!(parse_privacy(Some(&serde_json::json!("sideways"))).is_err());
        assert!(parse_privacy(Some(&serde_json::json!(1))).is_err());
    }

    #[test]
    fn originate_error_maps_each_cause_to_its_own_code() {
        use crate::dispatcher::OriginateError;
        // Requirement: unknown target / bad argument / backend-cannot / stack-down
        // must each be separately actionable on the wire.
        assert!(matches!(
            originate_error(OriginateError::InvalidUri {
                field: "to",
                detail: "nope".to_string()
            }),
            ControlResult::Error {
                code: ControlErrorCode::BadRequest,
                ..
            }
        ));
        assert!(matches!(
            originate_error(OriginateError::Unroutable("no route".to_string())),
            ControlResult::Error {
                code: ControlErrorCode::NotFound,
                ..
            }
        ));
        assert!(matches!(
            originate_error(OriginateError::Unsupported("no answer_local".to_string())),
            ControlResult::Error {
                code: ControlErrorCode::UnsupportedVerb,
                ..
            }
        ));
        assert!(matches!(
            originate_error(OriginateError::Unavailable("down".to_string())),
            ControlResult::Error {
                code: ControlErrorCode::Unavailable,
                ..
            }
        ));
        assert!(matches!(
            originate_error(OriginateError::BuildFailed("bad".to_string())),
            ControlResult::Error {
                code: ControlErrorCode::Unavailable,
                ..
            }
        ));
    }

    #[test]
    fn string_arg_treats_empty_as_absent() {
        let args = serde_json::json!({ "from": "", "from_display": "Support", "x": 7 });
        assert_eq!(string_arg(&args, "from"), None);
        assert_eq!(
            string_arg(&args, "from_display"),
            Some("Support".to_string())
        );
        assert_eq!(string_arg(&args, "x"), None);
        assert_eq!(string_arg(&args, "missing"), None);
    }

    #[test]
    fn describe_lists_core_verbs() {
        let schema = SipControlAdapter::new().describe();
        assert_eq!(schema.module, "sip");
        let verbs: Vec<&str> = schema.verbs.iter().map(|v| v.verb.as_str()).collect();
        for expected in [
            "answer",
            "ring",
            "progress",
            "reject",
            "hangup",
            "refer",
            "accept_refer",
            "reject_refer",
            "route",
            "set_header",
            "remove_header",
            "get_header",
            "play",
            "stop",
            "dtmf",
            "hold",
            "unhold",
            "stream_start",
            "stream_stop",
            "bridge",
            "unbridge",
        ] {
            assert!(verbs.contains(&expected), "missing verb {expected}");
        }
        let events: Vec<&str> = schema.events.iter().map(String::as_str).collect();
        for expected in [
            "StasisStart",
            "StasisEnd",
            "ChannelStateChange",
            "ChannelHangupRequest",
            "ChannelDtmfReceived",
            "PlayStarted",
            "TransferRequested",
            "TransferProgress",
            "TransferCompleted",
            "TransferFailed",
        ] {
            assert!(events.contains(&expected), "missing event {expected}");
        }
    }

    #[test]
    fn ring_and_progress_are_separate_verbs_in_the_schema() {
        // The declared schema is the only thing an app can discover the surface
        // from (`describe`), so the split has to be visible there: one verb that
        // says it only alerts, one that says it can open early media. A single
        // "1xx / early media" verb leaves the app guessing at status codes.
        let schema = SipControlAdapter::new().describe();
        let find = |name: &str| {
            schema
                .verbs
                .iter()
                .find(|verb| verb.verb == name)
                .map(|verb| verb.summary.clone())
                .unwrap_or_default()
        };
        let ring = find("ring");
        assert!(
            ring.contains("180"),
            "ring must name the status it sends: {ring}"
        );
        assert!(
            ring.contains("no early media") || ring.contains("alerting only"),
            "ring must say it does not open early media: {ring}"
        );
        let progress = find("progress");
        assert!(
            progress.contains("early-media") || progress.contains("early media"),
            "progress must name early media as its job: {progress}"
        );
    }

    #[test]
    fn refer_reply_reports_only_local_acceptance() {
        // The command/event split, asserted rather than assumed: the `refer`
        // verb's summary must promise the outcome as an event, because the reply
        // can only report that siphon sent the REFER. RFC 3515 §2.4.4 puts the
        // real verdict on the implicit subscription, which arrives later.
        let schema = SipControlAdapter::new().describe();
        let refer = schema
            .verbs
            .iter()
            .find(|verb| verb.verb == "refer")
            .expect("refer verb");
        assert!(
            refer.summary.contains("TransferCompleted") && refer.summary.contains("TransferFailed"),
            "the refer verb must point at its outcome events, got: {}",
            refer.summary
        );
    }

    #[test]
    fn verb_without_channel_target_is_bad_request() {
        let result = apply_sip(AdapterCommand {
            verb: "answer".to_string(),
            args: serde_json::json!({}),
            target: ResolvedTarget::None,
            origin: test_origin(),
        });
        assert!(matches!(
            result,
            ControlResult::Error {
                code: ControlErrorCode::BadRequest,
                ..
            }
        ));
    }

    #[test]
    fn unknown_verb_is_unsupported() {
        let result = apply_sip(AdapterCommand {
            verb: "teleport".to_string(),
            args: serde_json::json!({}),
            target: ResolvedTarget::Channel(channel()),
            origin: test_origin(),
        });
        assert!(matches!(
            result,
            ControlResult::Error {
                code: ControlErrorCode::UnsupportedVerb,
                ..
            }
        ));
    }

    // -----------------------------------------------------------------------
    // bridge / unbridge
    // -----------------------------------------------------------------------

    fn bridge_command(args: serde_json::Value) -> AdapterCommand {
        AdapterCommand {
            verb: "bridge".to_string(),
            args,
            target: ResolvedTarget::Channel(channel()),
            origin: test_origin(),
        }
    }

    /// A bus with `ch1` (the target) and `ch2` (the `with` leg) both owned by
    /// the commanding connection.
    fn bus_with_two_owned_channels() -> (std::sync::Arc<ControlBus>, u64) {
        let bus = test_bus();
        let conn = bus.register_connection("ivr-app");
        bus.register_channel(
            "ch1",
            &conn,
            "call-uuid",
            "sipcid@host",
            "hangup",
            HashMap::new(),
        );
        bus.register_channel(
            "ch2",
            &conn,
            "call-uuid-2",
            "sipcid2@host",
            "hangup",
            HashMap::new(),
        );
        let conn_id = conn.id;
        (bus, conn_id)
    }

    fn error_code(result: &ControlResult) -> Option<ControlErrorCode> {
        match result {
            ControlResult::Error { code, .. } => Some(*code),
            ControlResult::Ok(_) => None,
        }
    }

    #[tokio::test]
    async fn bridge_without_a_second_leg_is_a_bad_request() {
        let (bus, conn_id) = bus_with_two_owned_channels();
        let mut command = bridge_command(serde_json::json!({}));
        command.origin.conn_id = conn_id;
        let result = bridge_with_bus(&bus, &channel(), &command).await;
        assert_eq!(error_code(&result), Some(ControlErrorCode::BadRequest));

        let mut command = bridge_command(serde_json::json!({ "with": "   " }));
        command.origin.conn_id = conn_id;
        let result = bridge_with_bus(&bus, &channel(), &command).await;
        assert_eq!(error_code(&result), Some(ControlErrorCode::BadRequest));
    }

    #[tokio::test]
    async fn bridging_a_channel_to_itself_is_a_bad_request_not_a_not_found() {
        // Naming the same leg twice is a well-formed frame that is not a bridge.
        // It must read differently from "no such leg" and from "wrong state".
        let (bus, conn_id) = bus_with_two_owned_channels();
        let mut command = bridge_command(serde_json::json!({ "with": "ch1" }));
        command.origin.conn_id = conn_id;
        let result = bridge_with_bus(&bus, &channel(), &command).await;
        assert_eq!(error_code(&result), Some(ControlErrorCode::BadRequest));
        match result {
            ControlResult::Error { message, .. } => {
                assert!(message.contains("itself"), "{message}");
            }
            other => panic!("expected an error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn bridging_to_an_unknown_channel_is_not_found() {
        let (bus, conn_id) = bus_with_two_owned_channels();
        let mut command = bridge_command(serde_json::json!({ "with": "ch-nope" }));
        command.origin.conn_id = conn_id;
        let result = bridge_with_bus(&bus, &channel(), &command).await;
        assert_eq!(error_code(&result), Some(ControlErrorCode::NotFound));
    }

    #[tokio::test]
    async fn bridging_to_another_apps_channel_is_forbidden() {
        // One app must never be able to join another app's call to its own.
        let bus = test_bus();
        let mine = bus.register_connection("ivr-app");
        let theirs = bus.register_connection("edge-app");
        bus.register_channel(
            "ch1",
            &mine,
            "call-uuid",
            "sipcid@host",
            "hangup",
            HashMap::new(),
        );
        bus.register_channel(
            "ch2",
            &theirs,
            "other-uuid",
            "other@host",
            "hangup",
            HashMap::new(),
        );
        let mut command = bridge_command(serde_json::json!({ "with": "ch2" }));
        command.origin.conn_id = mine.id;
        let result = bridge_with_bus(&bus, &channel(), &command).await;
        assert_eq!(error_code(&result), Some(ControlErrorCode::Forbidden));
    }

    #[tokio::test]
    async fn an_unrecognised_peer_hangup_policy_is_refused_never_defaulted() {
        // Guessing at a teardown policy is how a survivor gets stranded (or
        // hung up when the controller wanted to keep it).
        let (bus, conn_id) = bus_with_two_owned_channels();
        for bad in [serde_json::json!("continue"), serde_json::json!(7)] {
            let mut command =
                bridge_command(serde_json::json!({ "with": "ch2", "on_peer_hangup": bad }));
            command.origin.conn_id = conn_id;
            let result = bridge_with_bus(&bus, &channel(), &command).await;
            assert_eq!(error_code(&result), Some(ControlErrorCode::BadRequest));
        }
    }

    #[tokio::test]
    async fn a_well_formed_bridge_reaches_the_dispatcher_and_never_answers_ok_without_one() {
        // Both legs resolve and are owned, so the verb gets past every argument
        // gate and calls into the B2BUA. With no dispatcher installed in a unit
        // -test binary that is a typed `unavailable` — never a hollow ok.
        let (bus, conn_id) = bus_with_two_owned_channels();
        for policy in [
            serde_json::json!("hangup"),
            serde_json::json!("hold"),
            serde_json::Value::Null,
        ] {
            let mut command =
                bridge_command(serde_json::json!({ "with": "ch2", "on_peer_hangup": policy }));
            command.origin.conn_id = conn_id;
            let result = bridge_with_bus(&bus, &channel(), &command).await;
            assert_eq!(error_code(&result), Some(ControlErrorCode::Unavailable));
        }
    }

    #[tokio::test]
    async fn unbridge_without_a_dispatcher_is_unavailable_not_a_hang() {
        let result = unbridge(&channel(), &serde_json::json!({})).await;
        assert_eq!(error_code(&result), Some(ControlErrorCode::Unavailable));
    }

    #[test]
    fn is_bridge_verb_splits_the_two_leg_verbs_from_the_rest() {
        for verb in ["bridge", "unbridge"] {
            assert!(
                is_bridge_verb(verb),
                "{verb} should route to the bridge path"
            );
        }
        for verb in ["answer", "hangup", "play", "originate", "refer", "route"] {
            assert!(
                !is_bridge_verb(verb),
                "{verb} should NOT route to the bridge path"
            );
        }
        // The bridge verbs must not also be classified as media verbs, or they
        // would run through the single-channel media dispatch.
        assert!(!is_media_verb("bridge"));
        assert!(!is_media_verb("unbridge"));
    }

    #[test]
    fn every_bridge_refusal_has_its_own_wire_code_and_matches_the_shared_token() {
        use crate::b2bua::bridge::BridgeError;
        let cases = [
            (
                BridgeError::UnknownLeg {
                    which: "with",
                    id: "ch2".to_string(),
                },
                ControlErrorCode::NotFound,
            ),
            (
                BridgeError::SameLeg("ch1".to_string()),
                ControlErrorCode::BadRequest,
            ),
            (
                BridgeError::NotAnswered {
                    id: "ch1".to_string(),
                    state: "ringing".to_string(),
                },
                ControlErrorCode::InvalidState,
            ),
            (
                BridgeError::AlreadyBridged {
                    id: "ch1".to_string(),
                },
                ControlErrorCode::InvalidState,
            ),
            (
                BridgeError::NotBridged {
                    id: "ch1".to_string(),
                },
                ControlErrorCode::InvalidState,
            ),
            (
                BridgeError::Glare {
                    id: "ch1".to_string(),
                },
                ControlErrorCode::InvalidState,
            ),
            (
                BridgeError::NoMediaDescription {
                    id: "ch1".to_string(),
                },
                ControlErrorCode::InvalidState,
            ),
            (
                BridgeError::Unsupported("no reoffer".to_string()),
                ControlErrorCode::UnsupportedVerb,
            ),
            (
                BridgeError::Unavailable("gone".to_string()),
                ControlErrorCode::Unavailable,
            ),
        ];
        for (error, expected) in cases {
            // The token the in-process rail prefixes its ValueError with has to
            // name the same cause as the wire code, or the two rails disagree
            // about what went wrong.
            let token = error.code();
            let wire = serde_json::to_string(&expected).unwrap_or_default();
            assert_eq!(
                format!("\"{token}\""),
                wire,
                "{error:?}: token {token} vs wire code {wire}"
            );
            assert_eq!(
                error_code(&bridge_error(error.clone())),
                Some(expected),
                "{error:?}"
            );
        }
    }

    #[test]
    fn describe_lists_the_bridge_events() {
        let schema = SipControlAdapter::new().describe();
        let events: Vec<&str> = schema.events.iter().map(String::as_str).collect();
        for expected in ["ChannelBridged", "BridgeFailed", "ChannelUnbridged"] {
            assert!(events.contains(&expected), "missing event {expected}");
        }
    }

    /// Every WebSocket stream a controller can start over this rail must have
    /// its lifecycle on the same rail. `stream_start` shipped before the events
    /// did, which left a controller able to start a tee and unable to learn it
    /// had stopped — the stream just went quiet.
    #[test]
    fn describe_lists_a_lifecycle_for_every_stream_mode() {
        let schema = SipControlAdapter::new().describe();
        let events: Vec<&str> = schema.events.iter().map(String::as_str).collect();
        for expected in [
            "WsTeeStarted",
            "WsTeeEnded",
            "WsBridgeStarted",
            "WsBridgeEnded",
        ] {
            assert!(events.contains(&expected), "missing event {expected}");
        }
    }

    #[test]
    fn is_media_verb_splits_media_from_sip() {
        for verb in [
            "play",
            "stop",
            "dtmf",
            "hold",
            "unhold",
            "stream_start",
            "stream_stop",
        ] {
            assert!(
                is_media_verb(verb),
                "{verb} should route to the async media path"
            );
        }
        for verb in [
            "answer",
            "ring",
            "progress",
            "reject",
            "hangup",
            "refer",
            "accept_refer",
            "reject_refer",
            "route",
            "set_header",
            "remove_header",
            "get_header",
            "collect_dtmf",
            "teleport",
        ] {
            assert!(
                !is_media_verb(verb),
                "{verb} should NOT route to the async media path"
            );
        }
    }

    #[tokio::test]
    async fn media_verbs_without_dispatcher_are_not_found_not_a_hang() {
        // The media verbs now EXIST (they no longer fall to unsupported_verb).
        // With no B2BUA_CONTROL installed, b2bua_media_target() is None, so each
        // resolves to a typed not_found and returns immediately — never a hang,
        // never a fabricated call-id. Args are well-formed so resolution is
        // reached (not short-circuited on a bad_request).
        let cases = [
            (
                "play",
                serde_json::json!({ "file": "/prompts/welcome.wav" }),
            ),
            ("stop", serde_json::json!({})),
            ("dtmf", serde_json::json!({ "digits": "123#" })),
            ("hold", serde_json::json!({})),
            ("unhold", serde_json::json!({})),
            (
                "stream_start",
                serde_json::json!({ "ws_uri": "ws://ai:9000/stream" }),
            ),
            ("stream_stop", serde_json::json!({})),
        ];
        let adapter = SipControlAdapter::new();
        for (verb, args) in cases {
            let result = adapter
                .apply(AdapterCommand {
                    verb: verb.to_string(),
                    args,
                    target: ResolvedTarget::Channel(channel()),
                    origin: test_origin(),
                })
                .await;
            assert!(
                matches!(
                    result,
                    ControlResult::Error {
                        code: ControlErrorCode::NotFound,
                        ..
                    }
                ),
                "media verb {verb} without a dispatcher should be not_found, got {result:?}"
            );
        }
    }

    #[tokio::test]
    async fn play_without_a_source_is_bad_request() {
        // Parsed before media-target resolution, so it holds with no dispatcher.
        let result = play(&channel(), &serde_json::json!({})).await;
        assert!(matches!(
            result,
            ControlResult::Error {
                code: ControlErrorCode::BadRequest,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn play_with_two_sources_is_bad_request() {
        let result = play(
            &channel(),
            &serde_json::json!({ "file": "/a.wav", "db_id": 7 }),
        )
        .await;
        assert!(matches!(
            result,
            ControlResult::Error {
                code: ControlErrorCode::BadRequest,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn dtmf_without_digits_is_bad_request() {
        let missing = dtmf(&channel(), &serde_json::json!({})).await;
        assert!(matches!(
            missing,
            ControlResult::Error {
                code: ControlErrorCode::BadRequest,
                ..
            }
        ));
        let empty = dtmf(&channel(), &serde_json::json!({ "digits": "" })).await;
        assert!(matches!(
            empty,
            ControlResult::Error {
                code: ControlErrorCode::BadRequest,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn stream_start_without_ws_uri_is_bad_request() {
        let result = stream_start(&channel(), &serde_json::json!({})).await;
        assert!(matches!(
            result,
            ControlResult::Error {
                code: ControlErrorCode::BadRequest,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn stream_start_with_bad_direction_is_bad_request() {
        let result = stream_start(
            &channel(),
            &serde_json::json!({ "ws_uri": "ws://ai:9000", "direction": "sideways" }),
        )
        .await;
        assert!(matches!(
            result,
            ControlResult::Error {
                code: ControlErrorCode::BadRequest,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn stream_start_with_bad_channels_is_bad_request() {
        let result = stream_start(
            &channel(),
            &serde_json::json!({ "ws_uri": "ws://ai:9000", "channels": 3 }),
        )
        .await;
        assert!(matches!(
            result,
            ControlResult::Error {
                code: ControlErrorCode::BadRequest,
                ..
            }
        ));
    }

    #[test]
    fn parse_play_source_variants() {
        use crate::rtpengine::client::PlayMediaSource;
        // file
        assert!(matches!(
            parse_play_source(&serde_json::json!({ "file": "/p.wav" })),
            Ok(PlayMediaSource::File(path)) if path == "/p.wav"
        ));
        // db_id
        assert!(matches!(
            parse_play_source(&serde_json::json!({ "db_id": 42 })),
            Ok(PlayMediaSource::DbId(42))
        ));
        // blob (base64 of "hi")
        assert!(matches!(
            parse_play_source(&serde_json::json!({ "blob": "aGk=" })),
            Ok(PlayMediaSource::Blob(bytes)) if bytes == b"hi"
        ));
        // none / two → error
        assert!(parse_play_source(&serde_json::json!({})).is_err());
        assert!(parse_play_source(&serde_json::json!({ "file": "/a", "db_id": 1 })).is_err());
        // invalid base64 → error
        assert!(parse_play_source(&serde_json::json!({ "blob": "not base64!!" })).is_err());
    }

    #[test]
    fn parse_stream_channels_bounds() {
        assert_eq!(parse_stream_channels(None), Ok(None));
        assert_eq!(
            parse_stream_channels(Some(&serde_json::Value::Null)),
            Ok(None)
        );
        assert_eq!(
            parse_stream_channels(Some(&serde_json::json!(1))),
            Ok(Some(1))
        );
        assert_eq!(
            parse_stream_channels(Some(&serde_json::json!(2))),
            Ok(Some(2))
        );
        assert!(parse_stream_channels(Some(&serde_json::json!(3))).is_err());
        assert!(parse_stream_channels(Some(&serde_json::json!(0))).is_err());
    }

    #[test]
    fn media_error_maps_each_backend_error() {
        use crate::rtpengine::error::RtpEngineError;
        // Engine has no such call → not_found.
        assert!(matches!(
            media_error(RtpEngineError::EngineError("Unknown call-id".to_string())),
            ControlResult::Error {
                code: ControlErrorCode::NotFound,
                ..
            }
        ));
        // Backend can't do it → unsupported_verb.
        assert!(matches!(
            media_error(RtpEngineError::Unsupported {
                operation: "attach_ws_tee",
                backend: "rtpengine"
            }),
            ControlResult::Error {
                code: ControlErrorCode::UnsupportedVerb,
                ..
            }
        ));
        // Anything else → unavailable.
        assert!(matches!(
            media_error(RtpEngineError::Timeout { timeout_ms: 1000 }),
            ControlResult::Error {
                code: ControlErrorCode::Unavailable,
                ..
            }
        ));
    }

    #[test]
    fn remove_header_without_name_is_bad_request() {
        let result = remove_header(&channel(), &serde_json::json!({}));
        assert!(matches!(
            result,
            ControlResult::Error {
                code: ControlErrorCode::BadRequest,
                ..
            }
        ));
    }

    #[test]
    fn remove_header_dispatches_through_apply_sip() {
        // Prove the "remove_header" arm is wired in apply_sip: with a name but no
        // stored invite (no call store for this call), it reaches remove_header and
        // returns not_found — not the unsupported_verb catch-all.
        let result = apply_sip(AdapterCommand {
            verb: "remove_header".to_string(),
            args: serde_json::json!({ "name": "X-Foo" }),
            target: ResolvedTarget::Channel(channel()),
            origin: test_origin(),
        });
        assert!(matches!(
            result,
            ControlResult::Error {
                code: ControlErrorCode::NotFound,
                ..
            }
        ));
    }

    #[test]
    fn remove_header_removes_from_the_stored_invite() {
        use crate::b2bua::actor::{CallActorStore, Leg, TransportInfo};
        use crate::transport::{ConnectionId, Transport};
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        use std::sync::{Arc, Mutex};

        // Build an A-leg INVITE carrying an X-Remove-Me header, park it in a fresh
        // call store, and install that store globally (unique call-actor-id so it
        // never collides with other tests that expect their own call absent).
        let raw = concat!(
            "INVITE sip:bob@biloxi.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK-rm1\r\n",
            "From: <sip:alice@atlanta.com>;tag=rmtag\r\n",
            "To: <sip:bob@biloxi.com>\r\n",
            "Call-ID: remove-header-call@atlanta.com\r\n",
            "CSeq: 1 INVITE\r\n",
            "X-Remove-Me: please\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        );
        let invite = crate::sip::parser::parse_sip_message_bytes(raw.as_bytes()).unwrap();
        assert!(invite.headers.has("X-Remove-Me"));
        let invite_arc = Arc::new(Mutex::new(invite));

        let store = Arc::new(CallActorStore::new());
        let transport = TransportInfo {
            remote_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 5060),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: None,
        };
        let a_leg = Leg::new_a_leg(
            "remove-header-call@atlanta.com".to_string(),
            "rmtag".to_string(),
            "z9hG4bK-rm1".to_string(),
            transport,
        );
        let internal_call_id = store.create_call(a_leg);
        store.set_a_leg_invite(&internal_call_id, Arc::clone(&invite_arc));
        crate::b2bua::actor::set_global_call_store(Arc::clone(&store));

        let controlled = ChannelRef {
            channel_id: "ch-rm".to_string(),
            call_actor_id: internal_call_id,
            sip_call_id: "remove-header-call@atlanta.com".to_string(),
            app: "ivr-app".to_string(),
        };

        let result = remove_header(&controlled, &serde_json::json!({ "name": "X-Remove-Me" }));
        // was_present = true → removed: true.
        match result {
            ControlResult::Ok(value) => {
                assert_eq!(value.get("removed").and_then(|v| v.as_bool()), Some(true));
            }
            other => panic!("expected Ok, got {other:?}"),
        }
        // The header is really gone from the stored invite.
        let invite = invite_arc.lock().unwrap();
        assert!(!invite.headers.has("X-Remove-Me"));
    }

    #[test]
    fn answer_rejects_non_2xx_before_touching_the_store() {
        // No call store in a unit context; a bad code must be caught first so
        // this returns bad_request, not a store lookup.
        let result = answer(&channel(), &serde_json::json!({ "code": 486 }), true);
        assert!(matches!(
            result,
            ControlResult::Error {
                code: ControlErrorCode::BadRequest,
                ..
            }
        ));
    }

    #[test]
    fn refer_without_target_is_bad_request() {
        let result = refer(&channel(), &serde_json::json!({}));
        assert!(matches!(
            result,
            ControlResult::Error {
                code: ControlErrorCode::BadRequest,
                ..
            }
        ));
    }

    #[test]
    fn dead_call_returns_not_found_never_hangs() {
        // With no global call store installed, stored_invite() is None → the
        // synchronous core returns not_found immediately (it cannot await a far
        // end — there is no far end to await).
        let result = answer(&channel(), &serde_json::json!({ "code": 200 }), true);
        assert!(matches!(
            result,
            ControlResult::Error {
                code: ControlErrorCode::NotFound,
                ..
            }
        ));
    }

    #[test]
    fn route_without_targets_is_bad_request() {
        // No args.targets at all → bad_request before touching the store.
        let result = route(&channel(), &serde_json::json!({}));
        assert!(matches!(
            result,
            ControlResult::Error {
                code: ControlErrorCode::BadRequest,
                ..
            }
        ));
    }

    #[test]
    fn route_empty_targets_is_bad_request() {
        let result = route(&channel(), &serde_json::json!({ "targets": [] }));
        assert!(matches!(
            result,
            ControlResult::Error {
                code: ControlErrorCode::BadRequest,
                ..
            }
        ));
    }

    #[test]
    fn route_target_object_without_uri_is_bad_request() {
        let result = route(
            &channel(),
            &serde_json::json!({ "targets": [{ "next_hop": "sip:gw@1.2.3.4" }] }),
        );
        assert!(matches!(
            result,
            ControlResult::Error {
                code: ControlErrorCode::BadRequest,
                ..
            }
        ));
    }

    #[test]
    fn route_unsupported_strategy_is_typed_error() {
        // A non-sequential strategy must be a typed unsupported error, NEVER a
        // silent fall-through to sequential. b2bua_route_call validates the
        // strategy before touching the dispatcher, so this holds without one.
        let result = route(
            &channel(),
            &serde_json::json!({ "targets": ["sip:1@carrier.example"], "strategy": "parallel" }),
        );
        assert!(
            matches!(
                result,
                ControlResult::Error {
                    code: ControlErrorCode::UnsupportedVerb,
                    ..
                }
            ),
            "unsupported strategy must be a typed UnsupportedVerb, got {result:?}"
        );
    }

    #[test]
    fn route_valid_targets_without_dispatcher_is_not_found() {
        // With no B2BUA_CONTROL installed (unit context), a well-formed route
        // reaches b2bua_route_call and returns not_found — never hangs.
        let result = route(
            &channel(),
            &serde_json::json!({ "targets": ["sip:1@carrier.example"] }),
        );
        assert!(matches!(
            result,
            ControlResult::Error {
                code: ControlErrorCode::NotFound,
                ..
            }
        ));
    }

    #[test]
    fn route_dispatches_through_apply_sip() {
        // Prove the "route" arm is wired in apply_sip (reaches b2bua_route_call →
        // not_found with no dispatcher, rather than unsupported_verb).
        let result = apply_sip(AdapterCommand {
            verb: "route".to_string(),
            args: serde_json::json!({ "targets": ["sip:1@carrier.example"] }),
            target: ResolvedTarget::Channel(channel()),
            origin: test_origin(),
        });
        assert!(matches!(
            result,
            ControlResult::Error {
                code: ControlErrorCode::NotFound,
                ..
            }
        ));
    }

    #[test]
    fn parse_route_target_string_and_object() {
        // Bare URI string form.
        let string_target =
            parse_route_target(&serde_json::json!("sip:1@carrier.example")).unwrap();
        assert_eq!(string_target.uri, "sip:1@carrier.example");
        assert!(string_target.next_hop.is_none());
        assert!(string_target.headers.is_empty());
        assert!(string_target.timeout_secs.is_none());

        // Full object form.
        let object_target = parse_route_target(&serde_json::json!({
            "uri": "sip:2@carrier.example",
            "next_hop": "sip:gw@203.0.113.7:5060",
            "headers": { "X-Carrier-Token": "abc" },
            "timeout": 12,
        }))
        .unwrap();
        assert_eq!(object_target.uri, "sip:2@carrier.example");
        assert_eq!(
            object_target.next_hop.as_deref(),
            Some("sip:gw@203.0.113.7:5060")
        );
        assert_eq!(object_target.timeout_secs, Some(12));
        assert_eq!(
            object_target.headers,
            vec![("X-Carrier-Token".to_string(), "abc".to_string())]
        );

        // A bare number is neither a string nor an object → error.
        assert!(parse_route_target(&serde_json::json!(42)).is_err());
    }

    #[test]
    fn parse_replaces_arg_roundtrips() {
        let value = serde_json::json!({
            "call_id": "abc", "from_tag": "ft", "to_tag": "tt", "early_only": true
        });
        let replaces = parse_replaces_arg(Some(&value)).unwrap().unwrap();
        assert_eq!(replaces.call_id, "abc");
        assert!(replaces.early_only);
        assert!(parse_replaces_arg(None).unwrap().is_none());
        assert!(parse_replaces_arg(Some(&serde_json::Value::Null))
            .unwrap()
            .is_none());
    }

    #[test]
    fn parse_refer_mode_variants() {
        use crate::script::api::call::ReferMode;
        assert_eq!(parse_refer_mode(None), Ok(None));
        assert_eq!(parse_refer_mode(Some(&serde_json::Value::Null)), Ok(None));
        assert_eq!(
            parse_refer_mode(Some(&serde_json::json!("terminate"))),
            Ok(Some(ReferMode::Terminate))
        );
        assert_eq!(
            parse_refer_mode(Some(&serde_json::json!("transparent"))),
            Ok(Some(ReferMode::Transparent))
        );
        // An unrecognized mode is a typed error, never a silent default.
        assert!(parse_refer_mode(Some(&serde_json::json!("sideways"))).is_err());
        assert!(parse_refer_mode(Some(&serde_json::json!(42))).is_err());
    }

    #[test]
    fn accept_refer_bad_mode_is_bad_request() {
        // Parsed before touching the rail, so it holds with no dispatcher.
        let result = accept_refer(&channel(), &serde_json::json!({ "mode": "sideways" }));
        assert!(matches!(
            result,
            ControlResult::Error {
                code: ControlErrorCode::BadRequest,
                ..
            }
        ));
    }

    #[test]
    fn accept_refer_bad_target_is_bad_request() {
        let result = accept_refer(&channel(), &serde_json::json!({ "target": "not a uri" }));
        assert!(matches!(
            result,
            ControlResult::Error {
                code: ControlErrorCode::BadRequest,
                ..
            }
        ));
    }

    #[test]
    fn accept_refer_without_pending_is_not_found() {
        // No B2BUA_CONTROL installed (unit context) → b2bua_accept_refer_call is
        // false (no pending REFER), mapped to not_found — never a hang.
        let result = accept_refer(&channel(), &serde_json::json!({}));
        assert!(matches!(
            result,
            ControlResult::Error {
                code: ControlErrorCode::NotFound,
                ..
            }
        ));
    }

    #[test]
    fn accept_refer_dispatches_through_apply_sip() {
        // Prove the "accept_refer" arm is wired in apply_sip (reaches the rail →
        // not_found with no dispatcher, rather than the unsupported_verb catch-all).
        let result = apply_sip(AdapterCommand {
            verb: "accept_refer".to_string(),
            args: serde_json::json!({}),
            target: ResolvedTarget::Channel(channel()),
            origin: test_origin(),
        });
        assert!(matches!(
            result,
            ControlResult::Error {
                code: ControlErrorCode::NotFound,
                ..
            }
        ));
    }

    #[test]
    fn reject_refer_bad_code_is_bad_request() {
        let result = reject_refer(&channel(), &serde_json::json!({ "code": 200 }));
        assert!(matches!(
            result,
            ControlResult::Error {
                code: ControlErrorCode::BadRequest,
                ..
            }
        ));
    }

    #[test]
    fn reject_refer_without_pending_is_not_found() {
        let result = reject_refer(
            &channel(),
            &serde_json::json!({ "code": 486, "reason": "Busy" }),
        );
        assert!(matches!(
            result,
            ControlResult::Error {
                code: ControlErrorCode::NotFound,
                ..
            }
        ));
    }

    #[test]
    fn reject_refer_dispatches_through_apply_sip() {
        let result = apply_sip(AdapterCommand {
            verb: "reject_refer".to_string(),
            args: serde_json::json!({}),
            target: ResolvedTarget::Channel(channel()),
            origin: test_origin(),
        });
        assert!(matches!(
            result,
            ControlResult::Error {
                code: ControlErrorCode::NotFound,
                ..
            }
        ));
    }
}
