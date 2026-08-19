//! The SIP control adapter — binds generic control verbs onto siphon's shipped
//! imperative B2BUA rail (`b2bua_answer_call` / `b2bua_progress_call` /
//! `b2bua_terminate_call` / `b2bua_refer_call`).
//!
//! Every verb is a **synchronous decision core over the call store** — it
//! performs the one bounded local action (send a SIP message / mark the store)
//! and returns "accepted" in microseconds. It **never** waits for the far end;
//! the callee's answer / ACK / BYE-200 arrive later as events. A command against
//! a dead/unknown call returns a typed `not_found`, never hangs.

use futures_util::future::BoxFuture;

use super::protocol::{ControlErrorCode, ControlResult};
use super::registry::ChannelRef;
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
            if is_media_verb(&command.verb) {
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
                verb("answer", "Send a UAS 2xx to the parked A-leg (args: code, reason, body, content_type)"),
                verb("progress", "Send a UAS 1xx / early media (args: code, reason, body, content_type)"),
                verb("reject", "Send a final non-2xx and tear the call down (args: code, reason)"),
                verb("hangup", "BYE an answered call, or reject an unanswered one (args: reason)"),
                verb("refer", "Send an in-dialog REFER on the A-leg (args: to, replaces)"),
                verb("route", "Return control to siphon with a routing decision: un-park the call and dial the B-leg via LCR sequential failover (args: targets, strategy, headers)"),
                verb("set_header", "Set a header on the stored A-leg INVITE (args: name, value)"),
                verb("remove_header", "Remove a header from the stored A-leg INVITE (args: name)"),
                verb("get_header", "Read a header from the stored A-leg INVITE (args: name)"),
                verb("play", "Play an announcement on the A-leg media, fire-and-forget (args: one of file|db_id|blob, repeat, start_ms, duration_ms, to_tag)"),
                verb("stop", "Stop the announcement currently playing on the A-leg media"),
                verb("dtmf", "Inject DTMF digits toward the A-leg (args: digits, duration_ms, volume_dbm0, pause_ms, to_tag)"),
                verb("hold", "Hold the A-leg media via silence"),
                verb("unhold", "Resume the A-leg media after a hold"),
                verb("stream_start", "Attach a WebSocket audio tee — siphon-rtp backend only (args: ws_uri, direction, channels)"),
                verb("stream_stop", "Detach the WebSocket audio tee"),
            ],
            events: vec![
                "StasisStart".to_string(),
                "StasisEnd".to_string(),
                "ChannelStateChange".to_string(),
                "ChannelHangupRequest".to_string(),
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
        "progress" => answer(&channel, &command.args, false),
        "reject" => reject(&channel, &command.args),
        "hangup" => hangup(&channel, &command.args),
        "refer" => refer(&channel, &command.args),
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
        "stream_stop" => stream_stop(&channel).await,
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
) -> Result<(std::sync::Arc<crate::rtpengine::MediaBackend>, String, String), ControlResult> {
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
    let count = [file.is_some(), db_id.is_some(), blob.is_some()]
        .iter()
        .filter(|present| **present)
        .count();
    if count != 1 {
        return Err(
            "play requires exactly one of args.file (path), args.db_id (int), or args.blob (base64)"
                .to_string(),
        );
    }
    if let Some(path) = file {
        return Ok(PlayMediaSource::File(path.to_string()));
    }
    if let Some(id) = db_id {
        return Ok(PlayMediaSource::DbId(id));
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

/// `play` — start an announcement on the A-leg's media. Fire-and-forget: `wait`
/// is false, so this returns on the backend's *accept*, never blocking on
/// playback completion (the far-end result is not the command reply).
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
    match backend
        .play_media(
            &call_id,
            &from_tag,
            &source,
            repeat,
            start_ms,
            duration_ms,
            to_tag.as_deref(),
            false,
        )
        .await
    {
        Ok(_) => ControlResult::Ok(
            serde_json::json!({ "channel": channel.channel_id, "state": "playing" }),
        ),
        Err(error) => media_error(error),
    }
}

/// `stop` — stop any prompt currently playing on the A-leg's media.
async fn stop(channel: &ChannelRef) -> ControlResult {
    let (backend, call_id, from_tag) = match media_target(channel) {
        Ok(target) => target,
        Err(result) => return result,
    };
    match backend.stop_media(&call_id, &from_tag).await {
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

    let (backend, call_id, from_tag) = match media_target(channel) {
        Ok(target) => target,
        Err(result) => return result,
    };
    match backend
        .attach_ws_tee(&call_id, &from_tag, &ws_uri, direction, channels)
        .await
    {
        Ok(()) => ControlResult::Ok(
            serde_json::json!({ "channel": channel.channel_id, "state": "streaming" }),
        ),
        Err(error) => media_error(error),
    }
}

/// `stream_stop` — detach the WebSocket audio tee (idempotent on siphon-rtp;
/// `unsupported_verb` on the other backends, same reason as `stream_start`).
async fn stream_stop(channel: &ChannelRef) -> ControlResult {
    let (backend, call_id, from_tag) = match media_target(channel) {
        Ok(target) => target,
        Err(result) => return result,
    };
    match backend.detach_ws_tee(&call_id, &from_tag).await {
        Ok(()) => ControlResult::Ok(
            serde_json::json!({ "channel": channel.channel_id, "state": "detached" }),
        ),
        Err(error) => media_error(error),
    }
}

/// Fetch a clone of the stored A-leg INVITE Arc for a controlled call.
fn stored_invite(call_actor_id: &str) -> Option<std::sync::Arc<std::sync::Mutex<crate::sip::message::SipMessage>>> {
    let store = crate::b2bua::actor::global_call_store()?;
    let call = store.get_call(call_actor_id)?;
    call.a_leg_invite.clone()
}

/// Read `code`/`reason`/`body`/`content_type` from a verb's args.
fn response_args(args: &serde_json::Value, default_code: u16, default_reason: &str) -> (u16, String, Option<Vec<u8>>, Option<String>) {
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

fn answer(channel: &ChannelRef, args: &serde_json::Value, final_response: bool) -> ControlResult {
    let (default_code, default_reason) = if final_response { (200, "OK") } else { (183, "Session Progress") };
    let (code, reason, body, content_type) = response_args(args, default_code, default_reason);

    if final_response && !(200..300).contains(&code) {
        return ControlResult::error(ControlErrorCode::BadRequest, "answer requires a 2xx code");
    }
    if !final_response && !(100..200).contains(&code) {
        return ControlResult::error(ControlErrorCode::BadRequest, "progress requires a 1xx code");
    }

    let Some(invite_arc) = stored_invite(&channel.call_actor_id) else {
        return ControlResult::error(ControlErrorCode::NotFound, "call is gone");
    };
    let Ok(invite) = invite_arc.lock() else {
        return ControlResult::error(ControlErrorCode::Unavailable, "call invite lock poisoned");
    };
    let sent = if final_response {
        crate::dispatcher::b2bua_answer_call(
            &channel.call_actor_id,
            &invite,
            code,
            &reason,
            body,
            content_type.as_deref(),
        )
    } else {
        crate::dispatcher::b2bua_progress_call(
            &channel.call_actor_id,
            &invite,
            code,
            &reason,
            body,
            content_type.as_deref(),
        )
    };
    if !sent {
        return ControlResult::error(ControlErrorCode::NotFound, "call is gone");
    }
    let state = if final_response { "answered" } else { "ringing" };
    ControlResult::Ok(serde_json::json!({ "channel": channel.channel_id, "state": state, "code": code }))
}

fn reject(channel: &ChannelRef, args: &serde_json::Value) -> ControlResult {
    let (code, reason, _, _) = response_args(args, 603, "Decline");
    if !(300..700).contains(&code) {
        return ControlResult::error(ControlErrorCode::BadRequest, "reject requires a 3xx-6xx code");
    }
    if crate::dispatcher::b2bua_reject_call(&channel.call_actor_id, code, &reason) {
        ControlResult::Ok(serde_json::json!({ "channel": channel.channel_id, "state": "terminated", "code": code }))
    } else {
        ControlResult::error(ControlErrorCode::NotFound, "call is gone")
    }
}

fn hangup(channel: &ChannelRef, args: &serde_json::Value) -> ControlResult {
    let reason = args.get("reason").and_then(|v| v.as_str());
    let answered = crate::b2bua::actor::global_call_store()
        .and_then(|store| {
            store
                .get_call(&channel.call_actor_id)
                .map(|call| matches!(call.state, crate::b2bua::actor::CallState::Answered))
        })
        .unwrap_or(false);

    let ok = if answered {
        // Answered: BYE both legs via the full teardown funnel (Rf/Ro/CDR/media).
        crate::dispatcher::b2bua_terminate_call(&channel.sip_call_id, reason)
    } else {
        // Unanswered/parked: send a final non-2xx and tear down (no B-leg to CANCEL
        // in Phase 1's single-CallActor model).
        crate::dispatcher::b2bua_reject_call(&channel.call_actor_id, 603, reason.unwrap_or("Decline"))
    };
    if ok {
        ControlResult::Ok(serde_json::json!({ "channel": channel.channel_id, "state": "terminated" }))
    } else {
        ControlResult::error(ControlErrorCode::NotFound, "call is gone")
    }
}

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
    let strategy = args.get("strategy").and_then(|v| v.as_str()).unwrap_or("sequential");
    let extra_headers = parse_extra_headers(args.get("headers"));
    let target_count = targets.len();

    match crate::dispatcher::b2bua_route_call(&channel.sip_call_id, targets, strategy, &extra_headers) {
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
            "each target must be a URI string or an object {uri, next_hop, headers, timeout}".to_string(),
        );
    };
    let Some(uri) = object.get("uri").and_then(|v| v.as_str()) else {
        return Err("target object requires a string 'uri'".to_string());
    };
    let next_hop = object.get("next_hop").and_then(|v| v.as_str()).map(|s| s.to_string());
    let headers = object.get("headers").map(parse_json_headers).unwrap_or_default();
    let timeout_secs = object.get("timeout").and_then(|v| v.as_u64()).map(|t| t as u32);
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
    ControlResult::Ok(serde_json::json!({ "channel": channel.channel_id, "header": name, "removed": was_present }))
}

fn get_header(channel: &ChannelRef, args: &serde_json::Value) -> ControlResult {
    let Some(name) = args.get("name").and_then(|v| v.as_str()) else {
        return ControlResult::error(ControlErrorCode::BadRequest, "get_header requires args.name");
    };
    let Some(invite_arc) = stored_invite(&channel.call_actor_id) else {
        return ControlResult::error(ControlErrorCode::NotFound, "call is gone");
    };
    let Ok(invite) = invite_arc.lock() else {
        return ControlResult::error(ControlErrorCode::Unavailable, "call invite lock poisoned");
    };
    let value = invite.headers.get(name).cloned();
    ControlResult::Ok(serde_json::json!({ "channel": channel.channel_id, "header": name, "value": value }))
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

    #[test]
    fn module_is_sip() {
        assert_eq!(SipControlAdapter::new().module(), "sip");
    }

    #[test]
    fn describe_lists_core_verbs() {
        let schema = SipControlAdapter::new().describe();
        assert_eq!(schema.module, "sip");
        let verbs: Vec<&str> = schema.verbs.iter().map(|v| v.verb.as_str()).collect();
        for expected in [
            "answer",
            "progress",
            "reject",
            "hangup",
            "refer",
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
        ] {
            assert!(verbs.contains(&expected), "missing verb {expected}");
        }
    }

    #[test]
    fn verb_without_channel_target_is_bad_request() {
        let result = apply_sip(AdapterCommand {
            verb: "answer".to_string(),
            args: serde_json::json!({}),
            target: ResolvedTarget::None,
        });
        assert!(matches!(
            result,
            ControlResult::Error { code: ControlErrorCode::BadRequest, .. }
        ));
    }

    #[test]
    fn unknown_verb_is_unsupported() {
        let result = apply_sip(AdapterCommand {
            verb: "teleport".to_string(),
            args: serde_json::json!({}),
            target: ResolvedTarget::Channel(channel()),
        });
        assert!(matches!(
            result,
            ControlResult::Error { code: ControlErrorCode::UnsupportedVerb, .. }
        ));
    }

    #[test]
    fn is_media_verb_splits_media_from_sip() {
        for verb in ["play", "stop", "dtmf", "hold", "unhold", "stream_start", "stream_stop"] {
            assert!(is_media_verb(verb), "{verb} should route to the async media path");
        }
        for verb in ["answer", "progress", "reject", "hangup", "refer", "route", "set_header", "remove_header", "get_header", "collect_dtmf", "teleport"] {
            assert!(!is_media_verb(verb), "{verb} should NOT route to the async media path");
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
            ("play", serde_json::json!({ "file": "/prompts/welcome.wav" })),
            ("stop", serde_json::json!({})),
            ("dtmf", serde_json::json!({ "digits": "123#" })),
            ("hold", serde_json::json!({})),
            ("unhold", serde_json::json!({})),
            ("stream_start", serde_json::json!({ "ws_uri": "ws://ai:9000/stream" })),
            ("stream_stop", serde_json::json!({})),
        ];
        let adapter = SipControlAdapter::new();
        for (verb, args) in cases {
            let result = adapter
                .apply(AdapterCommand {
                    verb: verb.to_string(),
                    args,
                    target: ResolvedTarget::Channel(channel()),
                })
                .await;
            assert!(
                matches!(result, ControlResult::Error { code: ControlErrorCode::NotFound, .. }),
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
            ControlResult::Error { code: ControlErrorCode::BadRequest, .. }
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
            ControlResult::Error { code: ControlErrorCode::BadRequest, .. }
        ));
    }

    #[tokio::test]
    async fn dtmf_without_digits_is_bad_request() {
        let missing = dtmf(&channel(), &serde_json::json!({})).await;
        assert!(matches!(
            missing,
            ControlResult::Error { code: ControlErrorCode::BadRequest, .. }
        ));
        let empty = dtmf(&channel(), &serde_json::json!({ "digits": "" })).await;
        assert!(matches!(
            empty,
            ControlResult::Error { code: ControlErrorCode::BadRequest, .. }
        ));
    }

    #[tokio::test]
    async fn stream_start_without_ws_uri_is_bad_request() {
        let result = stream_start(&channel(), &serde_json::json!({})).await;
        assert!(matches!(
            result,
            ControlResult::Error { code: ControlErrorCode::BadRequest, .. }
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
            ControlResult::Error { code: ControlErrorCode::BadRequest, .. }
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
            ControlResult::Error { code: ControlErrorCode::BadRequest, .. }
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
        assert_eq!(parse_stream_channels(Some(&serde_json::Value::Null)), Ok(None));
        assert_eq!(parse_stream_channels(Some(&serde_json::json!(1))), Ok(Some(1)));
        assert_eq!(parse_stream_channels(Some(&serde_json::json!(2))), Ok(Some(2)));
        assert!(parse_stream_channels(Some(&serde_json::json!(3))).is_err());
        assert!(parse_stream_channels(Some(&serde_json::json!(0))).is_err());
    }

    #[test]
    fn media_error_maps_each_backend_error() {
        use crate::rtpengine::error::RtpEngineError;
        // Engine has no such call → not_found.
        assert!(matches!(
            media_error(RtpEngineError::EngineError("Unknown call-id".to_string())),
            ControlResult::Error { code: ControlErrorCode::NotFound, .. }
        ));
        // Backend can't do it → unsupported_verb.
        assert!(matches!(
            media_error(RtpEngineError::Unsupported { operation: "attach_ws_tee", backend: "rtpengine" }),
            ControlResult::Error { code: ControlErrorCode::UnsupportedVerb, .. }
        ));
        // Anything else → unavailable.
        assert!(matches!(
            media_error(RtpEngineError::Timeout { timeout_ms: 1000 }),
            ControlResult::Error { code: ControlErrorCode::Unavailable, .. }
        ));
    }

    #[test]
    fn remove_header_without_name_is_bad_request() {
        let result = remove_header(&channel(), &serde_json::json!({}));
        assert!(matches!(
            result,
            ControlResult::Error { code: ControlErrorCode::BadRequest, .. }
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
        });
        assert!(matches!(
            result,
            ControlResult::Error { code: ControlErrorCode::NotFound, .. }
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
            ControlResult::Error { code: ControlErrorCode::BadRequest, .. }
        ));
    }

    #[test]
    fn refer_without_target_is_bad_request() {
        let result = refer(&channel(), &serde_json::json!({}));
        assert!(matches!(
            result,
            ControlResult::Error { code: ControlErrorCode::BadRequest, .. }
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
            ControlResult::Error { code: ControlErrorCode::NotFound, .. }
        ));
    }

    #[test]
    fn route_without_targets_is_bad_request() {
        // No args.targets at all → bad_request before touching the store.
        let result = route(&channel(), &serde_json::json!({}));
        assert!(matches!(
            result,
            ControlResult::Error { code: ControlErrorCode::BadRequest, .. }
        ));
    }

    #[test]
    fn route_empty_targets_is_bad_request() {
        let result = route(&channel(), &serde_json::json!({ "targets": [] }));
        assert!(matches!(
            result,
            ControlResult::Error { code: ControlErrorCode::BadRequest, .. }
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
            ControlResult::Error { code: ControlErrorCode::BadRequest, .. }
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
            matches!(result, ControlResult::Error { code: ControlErrorCode::UnsupportedVerb, .. }),
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
            ControlResult::Error { code: ControlErrorCode::NotFound, .. }
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
        });
        assert!(matches!(
            result,
            ControlResult::Error { code: ControlErrorCode::NotFound, .. }
        ));
    }

    #[test]
    fn parse_route_target_string_and_object() {
        // Bare URI string form.
        let string_target = parse_route_target(&serde_json::json!("sip:1@carrier.example")).unwrap();
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
        assert_eq!(object_target.next_hop.as_deref(), Some("sip:gw@203.0.113.7:5060"));
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
        assert!(parse_replaces_arg(Some(&serde_json::Value::Null)).unwrap().is_none());
    }
}
