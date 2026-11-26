//! `stream_start` / `stream_stop` with `mode: "split"`: both legs of an
//! answered two-party call streamed to one duplex stereo WebSocket, the parties
//! isolated from each other while it holds (siphon-rtp's `attach_ws_split`).
//!
//! A sibling of the takeover bridge, and refused on the same terms: the engine
//! must list `ws_split` (otherwise `unsupported_verb`, nothing sent), the
//! rate is one the engine serves, and an engine refusal comes back with its
//! token (`ws-split-not-answered`, `ws-split-seated`, ...) as typed details,
//! the text whole.

use crate::control::protocol::{ControlErrorCode, ControlResult};
use crate::control::registry::ChannelRef;
use crate::rtpengine::{MediaBackend, NgFlags, RtpEngineError};

/// A `stream_start {mode: "split"}`, read and checked, before the call's media
/// is looked up.
#[derive(Debug, Clone)]
pub(super) struct SplitRequest {
    pub(super) ws_uri: String,
    /// The wire rate in Hz; `None` is the engine's default.
    pub(super) sample_rate: Option<u32>,
    /// What runs on each party's uplink: the `answer` half of the named media
    /// profile, as a takeover bridge's profile is read.
    pub(super) offerer_profile: Option<NgFlags>,
    pub(super) answerer_profile: Option<NgFlags>,
}

fn bad(message: String) -> ControlResult {
    ControlResult::error(ControlErrorCode::BadRequest, message)
}

/// The arguments of the other two modes: refused on a split rather than
/// silently dropped, since a `channels: 1` quietly ignored would hand the
/// controller a stereo stream it believed was mono.
const OTHER_MODES_ARGUMENTS: [&str; 4] = ["direction", "channels", "profile", "media_flags"];

/// Read the arguments of a split `stream_start`.
pub(super) fn parse_split_request(
    ws_uri: &str,
    args: &serde_json::Value,
) -> Result<SplitRequest, ControlResult> {
    for unsupported in OTHER_MODES_ARGUMENTS {
        if args.get(unsupported).is_some_and(|value| !value.is_null()) {
            return Err(bad(format!(
                "stream_start args.{unsupported} does not apply to mode=split: a split has \
                 a fixed duplex stereo shape and takes sample_rate, offerer_profile and \
                 answerer_profile"
            )));
        }
    }
    let sample_rate = match args.get("sample_rate") {
        None => None,
        Some(value) if value.is_null() => None,
        Some(value) => {
            let rate = value.as_u64().and_then(|rate| u32::try_from(rate).ok());
            let Some(rate) = rate else {
                return Err(bad(format!(
                    "stream_start args.sample_rate must be 8000, 16000, 24000 or 48000, got {value}"
                )));
            };
            if let Err(error) = siphon_rtp_proto::resolve_ws_split_sample_rate(Some(rate)) {
                return Err(bad(format!("stream_start args.sample_rate: {error}")));
            }
            Some(rate)
        }
    };
    Ok(SplitRequest {
        ws_uri: ws_uri.to_string(),
        sample_rate,
        offerer_profile: party_profile(args.get("offerer_profile"), "offerer_profile")?,
        answerer_profile: party_profile(args.get("answerer_profile"), "answerer_profile")?,
    })
}

/// A party's `…_profile` argument: absent or `null` is none, a string must
/// name a media profile this deployment has.
fn party_profile(
    value: Option<&serde_json::Value>,
    argument: &'static str,
) -> Result<Option<NgFlags>, ControlResult> {
    let name = match value {
        None => return Ok(None),
        Some(value) if value.is_null() => return Ok(None),
        Some(value) => match value.as_str() {
            Some(name) => name,
            None => {
                return Err(bad(format!(
                    "stream_start args.{argument} must be a string naming a media profile"
                )))
            }
        },
    };
    crate::dispatcher::b2bua_media_profile(name)
        .map(Some)
        .map_err(|known| {
            let known = if known.is_empty() {
                "none configured".to_string()
            } else {
                known.join(", ")
            };
            ControlResult::error_with_details(
                ControlErrorCode::BadRequest,
                format!(
                    "stream_start args.{argument} names no media profile this deployment \
                     has: '{name}' (known: {known})"
                ),
                serde_json::json!({
                    "verb": "stream_start",
                    "argument": argument,
                    "reason": "unknown_profile",
                    "profile": name,
                }),
            )
        })
}

/// `stream_start {mode: "split"}` on a call whose media is on `backend` under
/// `call_id` / `from_tag`.
pub(super) async fn attach_split(
    backend: &MediaBackend,
    call_id: &str,
    from_tag: &str,
    channel: &ChannelRef,
    request: &SplitRequest,
) -> ControlResult {
    match backend
        .attach_ws_split(
            call_id,
            from_tag,
            &request.ws_uri,
            request.sample_rate,
            request.offerer_profile.as_ref(),
            request.answerer_profile.as_ref(),
        )
        .await
    {
        Ok(()) => {
            // Also recorded when the engine's `ws_split_started` is handled;
            // set here so a bridge that follows this reply cannot miss it.
            crate::dispatcher::b2bua_media_set_ws_split_attached(&channel.sip_call_id, true);
            ControlResult::Ok(serde_json::json!({
                "channel": channel.channel_id,
                "state": "split",
            }))
        }
        Err(error) => split_error(error),
    }
}

/// `stream_stop {mode: "split"}`: put the direct path back, without a
/// re-INVITE. Idempotent on the engine.
pub(super) async fn detach_split(
    backend: &MediaBackend,
    call_id: &str,
    from_tag: &str,
    channel: &ChannelRef,
) -> ControlResult {
    match backend.detach_ws_split(call_id, from_tag).await {
        Ok(()) => {
            crate::dispatcher::b2bua_media_set_ws_split_attached(&channel.sip_call_id, false);
            ControlResult::Ok(
                serde_json::json!({ "channel": channel.channel_id, "state": "detached" }),
            )
        }
        Err(error) => split_error(error),
    }
}

/// An engine refusal with a token is the call's state (or the controller's
/// argument) refusing it, not the media engine being unavailable: it is
/// `invalid_state` (`bad_request` for the two tokens that name an argument),
/// the engine's text whole, and the token in `details` for a controller to
/// branch on. Any other failure is mapped as every media verb's is.
fn split_error(error: RtpEngineError) -> ControlResult {
    let Some(token) = error.refusal_token() else {
        return super::media::media_error(error);
    };
    let code = match token {
        "ws-split-profile" | "ws-split-sample-rate" => ControlErrorCode::BadRequest,
        _ => ControlErrorCode::InvalidState,
    };
    let details = serde_json::json!({ "verb": "stream_start", "token": token });
    ControlResult::error_with_details(code, error.to_string(), details)
}
