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
        Box::pin(async move { apply_sip(command) })
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
                verb("set_header", "Set a header on the stored A-leg INVITE (args: name, value)"),
                verb("get_header", "Read a header from the stored A-leg INVITE (args: name)"),
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

/// Dispatch one SIP verb. Synchronous (the imperative rail is non-blocking) —
/// returns the local result immediately.
fn apply_sip(command: AdapterCommand) -> ControlResult {
    // All SIP verbs act on a channel.
    let channel = match &command.target {
        ResolvedTarget::Channel(channel) => channel.clone(),
        ResolvedTarget::None => {
            return ControlResult::error(
                ControlErrorCode::BadRequest,
                format!("verb '{}' requires a channel target", command.verb),
            );
        }
    };

    // The controller has acted: clear the handoff deadline so the answer-timeout
    // sweep no longer applies the parked default action to this call.
    if let Some(store) = crate::b2bua::actor::global_call_store() {
        store.mark_controller_acted(&channel.call_actor_id);
    }

    match command.verb.as_str() {
        "answer" => answer(&channel, &command.args, true),
        "progress" => answer(&channel, &command.args, false),
        "reject" => reject(&channel, &command.args),
        "hangup" => hangup(&channel, &command.args),
        "refer" => refer(&channel, &command.args),
        "set_header" => set_header(&channel, &command.args),
        "get_header" => get_header(&channel, &command.args),
        // Media verbs (play/stop/dtmf/collect_dtmf) bind to MediaBackend and land
        // with the AI-park mode — a typed error, never a hang.
        other => ControlResult::error(
            ControlErrorCode::UnsupportedVerb,
            format!("sip adapter does not implement verb '{other}' in this build"),
        ),
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
        for expected in ["answer", "progress", "reject", "hangup", "refer"] {
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
    fn media_verb_is_unsupported_not_a_hang() {
        for verb in ["play", "stop", "dtmf", "collect_dtmf"] {
            let result = apply_sip(AdapterCommand {
                verb: verb.to_string(),
                args: serde_json::json!({}),
                target: ResolvedTarget::Channel(channel()),
            });
            assert!(
                matches!(result, ControlResult::Error { code: ControlErrorCode::UnsupportedVerb, .. }),
                "verb {verb} should be a typed unsupported error"
            );
        }
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
