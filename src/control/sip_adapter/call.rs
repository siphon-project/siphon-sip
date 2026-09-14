//! Verbs on the parked A-leg — `answer`, `ring`, `progress`, `reject` and
//! `hangup` — and the header verbs over its stored INVITE.

use crate::control::protocol::{ControlErrorCode, ControlResult};
use crate::control::registry::ChannelRef;

/// Fetch a clone of the stored A-leg INVITE Arc for a controlled call.
fn stored_invite(
    call_actor_id: &str,
) -> Option<std::sync::Arc<std::sync::Mutex<crate::sip::message::SipMessage>>> {
    let store = crate::b2bua::actor::global_call_store()?;
    let call = store.get_call(call_actor_id)?;
    call.a_leg_invite.clone()
}

/// Read `code`/`reason`/`body`/`content_type` from a verb's args.
pub(super) fn response_args(
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
pub(super) fn provisional_state(has_body: bool) -> &'static str {
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

/// `answer` (`final_response`) and `progress` — the two UAS responses an
/// application sends on a parked A-leg.
///
/// `answer` additionally takes `anchor` (or a `profile` / `ws_uri`, which imply
/// it), which turns it into the verb
/// form of `call.handover(answer=True, profile=…, ws_uri=…)`: siphon synthesizes
/// the RFC 3264 answer against the media engine and anchors the leg's audio to
/// it in the same act. That is the only way an application that accepted an
/// **un-answered** handover can connect the call — it can ring for as long as
/// its own policy says (`ring`), but a plain `answer` anchors nothing, and
/// answering first and attaching a stream afterwards is a different thing:
/// `received_from`, echo cancellation and the VAD engine belong to the answer,
/// not to a bridge bolted on after it.
pub(super) fn answer(
    channel: &ChannelRef,
    args: &serde_json::Value,
    final_response: bool,
) -> ControlResult {
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

    // Answer + anchor in one act, the verb form of
    // `call.handover(answer=True, profile=…, ws_uri=…)`. Without it an app that
    // took the call un-answered could hold it open with `ring` and then had no
    // way to connect it — answering first and bridging afterwards is not the
    // same thing, because `received_from`, echo cancellation and the VAD engine
    // are properties of the answer.
    let profile = args.get("profile").and_then(|value| value.as_str());
    let ws_uri = args.get("ws_uri").and_then(|value| value.as_str());
    // `anchor` on its own means "answer through the media engine on its default
    // profile" — without it, naming neither argument would be indistinguishable
    // from a plain `answer`. Either named argument implies it.
    let anchor = args
        .get("anchor")
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
        || profile.is_some()
        || ws_uri.is_some();
    if anchor {
        if arg_present(args, "body") {
            return ControlResult::error(
                ControlErrorCode::BadRequest,
                "an anchored answer or progress synthesizes the SDP itself (RFC 3264) — a \
                 body passed alongside it would be discarded, so pass one or the other",
            );
        }
        if !final_response {
            // Early media through the engine (RFC 3960 §3.1): the 18x carries
            // the engine's SDP, and the answer is kept so the 2xx repeats it. A
            // 100 is hop-by-hop, opens no early dialog and carries no body
            // (RFC 3261 §8.2.6.1), so there is nothing for it to anchor.
            if code == 100 {
                return ControlResult::error(
                    ControlErrorCode::BadRequest,
                    "an anchored progress needs a 101-199 response to carry its SDP — a 100 \
                     Trying opens no early dialog and carries no body",
                );
            }
            return match crate::dispatcher::b2bua_progress_call_anchored(
                &channel.call_actor_id,
                code,
                &reason,
                profile,
                ws_uri,
            ) {
                Ok(()) => ControlResult::Ok(serde_json::json!({
                    "channel": channel.channel_id,
                    "state": provisional_state(true),
                    "code": code,
                    "early_media": true,
                    "media": "anchored",
                })),
                // Unavailable, not not_found, for the same reason as the
                // anchored answer: the media plan failed and the call is still
                // parked — retry with another profile, answer plainly, or reject.
                Err(reason) => ControlResult::error(ControlErrorCode::Unavailable, reason),
            };
        }
        return match crate::dispatcher::b2bua_answer_call_anchored(
            &channel.call_actor_id,
            code,
            &reason,
            profile,
            ws_uri,
        ) {
            Ok(()) => ControlResult::Ok(serde_json::json!({
                "channel": channel.channel_id,
                "state": "answered",
                "code": code,
                "media": "anchored",
            })),
            // Not `not_found`: the media plan is what failed, and the call is
            // still parked and answerable — the app can retry with another
            // profile or reject. `answer_local` is a siphon-rtp verb, so this
            // is also where an rtpengine / rtpproxy deployment is told so
            // rather than handed a 200 with nothing behind it.
            Err(reason) => ControlResult::error(ControlErrorCode::Unavailable, reason),
        };
    }

    // After anchored early media the caller already holds siphon's SDP answer
    // from the 18x. A 2xx carrying a different one would renegotiate outside an
    // offer/answer exchange (RFC 3264 §4), so it is refused; an answer with no
    // body is accepted and the dispatcher repeats the early answer.
    if final_response {
        if let (Some(given), Some(early)) = (
            body.as_ref(),
            crate::dispatcher::b2bua_early_media_sdp(&channel.call_actor_id),
        ) {
            if given.as_slice() != early.as_bytes() {
                return ControlResult::error(
                    ControlErrorCode::BadRequest,
                    "this call's early media already carried siphon's SDP answer — the 2xx must \
                     repeat it (RFC 3264 §4), so answer with no body",
                );
            }
        }
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
pub(super) fn ring(channel: &ChannelRef, args: &serde_json::Value) -> ControlResult {
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

pub(super) fn reject(channel: &ChannelRef, args: &serde_json::Value) -> ControlResult {
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

pub(super) fn hangup(channel: &ChannelRef, args: &serde_json::Value) -> ControlResult {
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

pub(super) fn set_header(channel: &ChannelRef, args: &serde_json::Value) -> ControlResult {
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
pub(super) fn remove_header(channel: &ChannelRef, args: &serde_json::Value) -> ControlResult {
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

pub(super) fn get_header(channel: &ChannelRef, args: &serde_json::Value) -> ControlResult {
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
