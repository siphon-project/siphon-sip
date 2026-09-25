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

mod bridge;
mod call;
mod media;
mod originate;
mod routing;
#[cfg(test)]
mod tests;
mod transfer;

use bridge::apply_bridge_verb;
use call::{answer, get_header, hangup, reject, remove_header, ring, set_header};
use media::apply_media_verb;
use originate::originate;
#[cfg(test)]
pub(crate) use originate::staged;
use routing::{dial, route};
use transfer::{accept_refer, refer, reject_refer, replace_peer};

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
            } else if is_sip_verb(&command.verb) {
                apply_sip(command)
            } else {
                // Refused at the door rather than by falling through into the
                // SIP table. A verb that reaches the wrong table is answered
                // `unsupported_verb` by accident, which reads exactly like this
                // and is how `record_start` shipped dispatching nowhere.
                ControlResult::error(
                    ControlErrorCode::UnsupportedVerb,
                    format!(
                        "sip adapter does not implement verb '{}' in this build",
                        command.verb
                    ),
                )
            }
        })
    }

    fn describe(&self) -> AdapterSchema {
        AdapterSchema {
            module: "sip".to_string(),
            verbs: vec![
                verb("originate", "Place an outbound call under a caller-supplied channel id and return as soon as the INVITE is on the wire (args: channel, to, from, from_display, to_display, next_hop, p_asserted_identity, privacy, headers, sdp | media, profile, ws_uri, timeout, on_lost, vars, session_timer {expires, min_se, refresher})"),
                verb("answer", "Send a UAS 2xx to the parked A-leg; with anchor (or a profile / ws_uri, which imply it) the SDP answer is synthesized and the media anchored to the media engine in the same act — the verb form of call.handover(answer=True). Without a ws_uri the leg is anchored on the engine with no bridge, which is what play / DTMF / recording need for an IVR, a queue or a voicemail box (args: code, reason, body, content_type, anchor, profile, ws_uri)"),
                verb("ring", "Send 180 Ringing to the parked A-leg — alerting only, no early media (RFC 3261 §13.2.1); a body is refused, use progress for that (args: reason)"),
                verb("progress", "Send a UAS 1xx, optionally opening an early-media path with SDP (RFC 3960 §3.1); defaults to 183 Session Progress. With anchor (or a profile / ws_uri, which imply it) the SDP is the media engine's and a later answer repeats it — how ringback or an announcement plays before answering (args: code, reason, body, content_type, anchor, profile, ws_uri)"),
                verb("reject", "Send a final non-2xx and tear the call down (args: code, reason)"),
                verb("hangup", "BYE an answered call, or reject an unanswered one (args: reason)"),
                verb("refer", "Send an in-dialog REFER on the A-leg; the reply reports only that it was sent, the far end's verdict arrives as TransferProgress then TransferCompleted / TransferFailed (args: to, replaces)"),
                verb("accept_refer", "Accept a pending inbound REFER (from a TransferRequested event) and run the transfer (args: target, next_hop, mode, profile, number_policy, format)"),
                verb("reject_refer", "Reject a pending inbound REFER with a final non-2xx (args: code, reason)"),
                verb("replace_peer", "Replace one leg of this answered call with a freshly dialed target, with no REFER involved: the replaced leg stays up while the target rings and is BYE'd only once it answers. The reply says the INVITE is on the wire, PeerReplaced says the new party is bridged and the old one released (args: target, next_hop, replace_a_leg, profile, number_policy, format, timeout)"),
                verb("bridge", "Join this channel to another the app owns, so the two parties hear each other; the reply says the media was re-pointed and the first re-INVITE is on the wire, ChannelBridged says the audio meets (args: with, on_peer_hangup)"),
                verb("unbridge", "Break a bridge — both legs stay answered, owned and held; the reply says the hold offers went out, ChannelUnbridged on each leg says it is parted and safe to bridge again (args: reason)"),
                verb("route", "Return control to siphon with a routing decision: un-park the call and dial the B-leg via LCR sequential failover (args: targets, strategy, headers)"),
                verb("dial", "Ring one or more targets as B-legs while the caller stays unanswered and this app keeps the channel: each branch is named as it is created by DialBranch (leg_id, leg_sip_call_id, target) and as it ends by DialBranchFailed or DialAnswered, the first 2xx answers the caller and the pair becomes an ordinary two-leg call, and a failure or timeout arrives as DialFailed, listing every branch, with the caller still ringing (args: targets, strategy, timeout, headers, profile, from, from_display, p_asserted_identity, privacy). A target is a URI string, {uri, next_hop, headers} or {aor} — an AoR forks to every registered contact over its own flow, which is the only way to reach a phone registered on TCP, TLS or WSS. The identity arguments present a From of the controller's choosing instead of the caller's own, which on a call out to a trunk is the internal extension"),
                verb("set_header", "Set a header on the stored A-leg INVITE (args: name, value)"),
                verb("remove_header", "Remove a header from the stored A-leg INVITE (args: name)"),
                verb("get_header", "Read a header from the stored A-leg INVITE (args: name)"),
                verb("play", "Play an announcement on the A-leg media, fire-and-forget; the reply and a PlayStarted event carry the play_id a later stop addresses (args: one of file|db_id|blob|tone|url, repeat, start_ms, duration_ms, gain_decibels, to_tag)"),
                verb("stop", "Stop the announcement currently playing on the A-leg media"),
                verb("dtmf", "Inject DTMF digits toward the A-leg (args: digits, duration_ms, volume_dbm0, pause_ms, to_tag)"),
                verb("hold", "Hold the A-leg media via silence"),
                verb("unhold", "Resume the A-leg media after a hold"),
                verb("stream_start", "Stream the call's audio to a WebSocket server — siphon-rtp backend only (args: ws_uri, mode=tee|bridge, and for tee: direction, channels, sample_rate). mode=tee streams a copy while the call keeps relaying; mode=bridge is a takeover that makes the server the leg's far side, and re-points in place if one is already attached"),
                verb("record_start", "Record the call's decoded audio to a wav file, replying with the recording_id a later record_stop and the RecordingFinished event carry (args: direction=ingress|egress|both, channels=mono|stereo, max_duration_ms, silence_ms, path). max_duration_ms and silence_ms are the two stop conditions a voicemail greeting announces, and RecordingFinished fires only once the file is closed — so an app can attach it to an email without racing a half-written one. siphon-rtp only"),
                verb("record_stop", "Stop a recording (args: recording_id; absent stops every recording on the call)"),
                verb("stream_stop", "Stop streaming the call's audio (args: mode=tee|bridge). A tee stop is idempotent; a bridge stop is refused where there is no relay to return the call to"),
            ],
            events: vec![
                "StasisStart".to_string(),
                "StasisEnd".to_string(),
                "ChannelStateChange".to_string(),
                // No `ChannelHangupRequest`: it was advertised here and never
                // emitted, so an app could wait on it for a teardown that
                // announces itself as `StasisEnd` instead — which already
                // carries the hangup cause and the SIP status. `describe` is
                // the only place an app can discover the surface, so a name in
                // it that nothing sends is worse than an absent one.
                "ChannelDtmfReceived".to_string(),
                // Application-level, not channel-level: it concerns the
                // deployment rather than a call, and only reaches an app that
                // opted in with `control.apps[].events: [registration]`.
                "RegistrationChanged".to_string(),
                // Application-level too, behind `events: [dialog]`: the RFC
                // 4235 state of each dialog of a registered AoR through siphon,
                // B2BUA or proxy, as siphon observed it on the wire.
                "DialogStateChanged".to_string(),
                // Fired when the recording's file is CLOSED, which is the
                // thing an app can act on — the `record_stop` reply would
                // race a half-written file.
                "RecordingFinished".to_string(),
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
                // The verdict on a `dial`, per branch and for the dial. Each
                // B-leg it rings is its own SIP dialog on a Call-ID siphon
                // generated, so every branch is named when it is created
                // (DialBranch, the later attempts of a sequential hunt
                // included), once more when it ends without answering
                // (DialBranchFailed), and the winner as DialAnswered. A dial
                // nobody answered is one DialFailed listing every branch.
                "DialBranch".to_string(),
                "DialBranchFailed".to_string(),
                "DialAnswered".to_string(),
                "DialFailed".to_string(),
                // The verdict on a `replace_peer`, for the same reason: the
                // reply says only that the INVITE to the target left the box.
                // Whether the target answered, whether the survivor took the
                // re-INVITE and whether the replaced leg was released all
                // happen afterwards, so a controller that acts on the reply
                // alone would tear down a call whose replacement is still
                // ringing. Exactly one PeerReplaced / ReplaceFailed.
                "PeerReplaced".to_string(),
                "ReplaceFailed".to_string(),
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
        "play"
            | "stop"
            | "dtmf"
            | "hold"
            | "unhold"
            | "stream_start"
            | "stream_stop"
            | "record_start"
            | "record_stop"
    )
}

/// The verbs that join or part two channels. Split out so `apply` and the tests
/// agree on which verbs take the async path (they confirm the media teardown
/// with the backend before answering).
fn is_bridge_verb(verb: &str) -> bool {
    matches!(verb, "bridge" | "unbridge")
}

/// The verbs [`apply_sip`] dispatches synchronously over the B2BUA rail — the
/// arms of its own `match`, restated so the schema guard in the tests can prove
/// every advertised verb is claimed by exactly one dispatch table.
///
/// That guard exists because of a failure mode that is invisible everywhere
/// else: a verb added to `describe()` and to one dispatch table, but not to the
/// classifier in [`ControlAdapter::apply`] that routes to it, falls through to
/// the wrong table and answers `unsupported_verb` on the wire — while every unit
/// test that calls the handler function directly still passes.
fn is_sip_verb(verb: &str) -> bool {
    matches!(
        verb,
        "answer"
            | "ring"
            | "progress"
            | "reject"
            | "hangup"
            | "refer"
            | "accept_refer"
            | "reject_refer"
            | "replace_peer"
            | "route"
            | "dial"
            | "set_header"
            | "remove_header"
            | "get_header"
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
        "ring" => ring(&channel, &command.args),
        "progress" => answer(&channel, &command.args, false),
        "reject" => reject(&channel, &command.args),
        "hangup" => hangup(&channel, &command.args),
        "refer" => refer(&channel, &command.args),
        "accept_refer" => accept_refer(&channel, &command.args),
        "reject_refer" => reject_refer(&channel, &command.args),
        "replace_peer" => replace_peer(&channel, &command.args),
        "route" => route(&channel, &command.args),
        "dial" => dial(&channel, &command.args),
        "set_header" => set_header(&channel, &command.args),
        "remove_header" => remove_header(&channel, &command.args),
        "get_header" => get_header(&channel, &command.args),
        other => ControlResult::error(
            ControlErrorCode::UnsupportedVerb,
            format!("sip adapter does not implement verb '{other}' in this build"),
        ),
    }
}

/// Read an optional non-empty string argument.
fn string_arg(args: &serde_json::Value, name: &str) -> Option<String> {
    args.get(name)
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string())
}
