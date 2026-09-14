//! Media verbs — `play`, `stop`, `dtmf`, `hold` / `unhold`, `stream_start` /
//! `stream_stop` and `record_start` / `record_stop` — dispatched asynchronously
//! against the configured media backend.

use crate::control::protocol::{ControlErrorCode, ControlResult};
use crate::control::registry::ChannelRef;
use crate::control::AdapterCommand;

use super::controlled_channel;

/// Dispatch one media verb asynchronously against the configured MediaBackend.
///
/// The `(media_call_id, from_tag)` tuple is resolved from the channel's SIP
/// Call-ID via [`crate::dispatcher::b2bua_media_target`] (the stateless
/// media-session accessor). A call with no anchored media session returns a typed
/// `not_found` — never a hang, never a fabricated call-id. The verb `.await`s
/// only the backend's *accept* of the command, not the far-end media outcome
/// (playback completion, tee liveness), which arrives later as events.
pub(super) async fn apply_media_verb(command: AdapterCommand) -> ControlResult {
    let channel = match controlled_channel(&command) {
        Ok(channel) => channel,
        Err(result) => return result,
    };

    match command.verb.as_str() {
        "play" => play(&channel, &command.args).await,
        "stop" => stop(&channel).await,
        "record_start" => record_start(&channel, &command.args).await,
        "record_stop" => record_stop(&channel, &command.args).await,
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
pub(super) fn media_error(error: crate::rtpengine::error::RtpEngineError) -> ControlResult {
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
pub(super) fn parse_play_source(
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
pub(super) enum StreamMode {
    Tee,
    Bridge,
}

/// Parse the optional `mode` arg. Absent means `tee`.
pub(super) fn parse_stream_mode(
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
pub(super) fn parse_stream_channels(
    value: Option<&serde_json::Value>,
) -> Result<Option<u8>, String> {
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
pub(super) fn play_source_kind(source: &crate::rtpengine::client::PlayMediaSource) -> &'static str {
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
pub(super) fn play_accept(
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
pub(super) async fn play(channel: &ChannelRef, args: &serde_json::Value) -> ControlResult {
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

/// `record_start` — record the call's decoded audio to a wav file.
///
/// Not the same thing as `li.record()`, which is SIPREC: that hands a recording
/// *server* its own leg. This writes a file, which is what a voicemail box is,
/// and it works on a single-leg engine-terminated call.
pub(super) async fn record_start(channel: &ChannelRef, args: &serde_json::Value) -> ControlResult {
    use crate::rtpengine::events::{RecordingChannels, RecordingDirection, RecordingRequest};

    let direction = match args.get("direction").and_then(|value| value.as_str()) {
        None | Some("ingress") => RecordingDirection::Ingress,
        Some("egress") => RecordingDirection::Egress,
        Some("both") => RecordingDirection::Both,
        Some(other) => {
            return ControlResult::error(
                ControlErrorCode::BadRequest,
                format!("direction {other:?} is ingress, egress or both"),
            )
        }
    };
    let channels = match args.get("channels").and_then(|value| value.as_str()) {
        None | Some("mono") => RecordingChannels::Mono,
        Some("stereo") => RecordingChannels::Stereo,
        Some(other) => {
            return ControlResult::error(
                ControlErrorCode::BadRequest,
                format!("channels {other:?} is mono or stereo"),
            )
        }
    };
    let path = args
        .get("path")
        .and_then(|value| value.as_str())
        .map(str::to_string);
    let request = RecordingRequest {
        direction,
        channels,
        max_duration_ms: args.get("max_duration_ms").and_then(|v| v.as_u64()),
        silence_ms: args.get("silence_ms").and_then(|v| v.as_u64()),
        path: path.as_deref(),
    };

    let (backend, call_id, from_tag) = match media_target(channel) {
        Ok(target) => target,
        Err(result) => return result,
    };
    match backend.start_recording(&call_id, &from_tag, &request).await {
        Ok(recording_id) => ControlResult::Ok(serde_json::json!({
            "channel": channel.channel_id,
            "state": "recording",
            "recording_id": recording_id,
        })),
        Err(error) => media_error(error),
    }
}

/// `record_stop` — finish a recording, or every recording on the call.
async fn record_stop(channel: &ChannelRef, args: &serde_json::Value) -> ControlResult {
    let recording_id = args
        .get("recording_id")
        .and_then(|value| value.as_str())
        .map(str::to_string);
    let (backend, call_id, from_tag) = match media_target(channel) {
        Ok(target) => target,
        Err(result) => return result,
    };
    match backend
        .stop_recording(&call_id, &from_tag, recording_id.as_deref())
        .await
    {
        // "stopped" is the accept, not the file: `RecordingFinished` is what
        // says the write is done and names the path.
        Ok(()) => ControlResult::Ok(serde_json::json!({
            "channel": channel.channel_id,
            "state": "stopping",
            "recording_id": recording_id,
        })),
        Err(error) => media_error(error),
    }
}

/// `dtmf` — inject DTMF digits toward the A-leg (fire-and-forget).
pub(super) async fn dtmf(channel: &ChannelRef, args: &serde_json::Value) -> ControlResult {
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
pub(super) async fn stream_start(channel: &ChannelRef, args: &serde_json::Value) -> ControlResult {
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
