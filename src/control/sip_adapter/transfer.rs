//! Transfer verbs: `refer`, `accept_refer`, `reject_refer` and `replace_peer`.

use crate::control::protocol::{ControlErrorCode, ControlResult};
use crate::control::registry::ChannelRef;

use super::call::response_args;

/// `refer` — send an in-dialog REFER on the A-leg (a siphon-originated cold
/// transfer).
///
/// The reply says `{"refer": "sent"}` and nothing more, deliberately: RFC 3515
/// §2.4.4 puts the transfer's outcome on the implicit subscription that follows
/// (a `message/sipfrag` NOTIFY), so folding it into the reply would mean waiting
/// on the far end inside a command. The verdict arrives as events instead —
/// `TransferProgress` while it moves, then exactly one `TransferCompleted` /
/// `TransferFailed` (see [`crate::control::TransferStage`]).
pub(super) fn refer(channel: &ChannelRef, args: &serde_json::Value) -> ControlResult {
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
/// Validate the mutually-exclusive `number_policy` / `format` verb arguments.
///
/// Resolved here so an unusable one is a synchronous `bad_request` to the
/// controller rather than a warn-and-skip deep in the send path — the control
/// plane can report it, where the script paths raise on the spot for the same
/// reason.
fn validate_number_shape(
    args: &serde_json::Value,
) -> Result<Option<crate::script::api::numbers::NumberShape>, ControlResult> {
    use crate::script::api::numbers::{resolve_dial_shape, NumberShape};

    let name = args.get("number_policy").and_then(|value| value.as_str());
    let format = args.get("format").and_then(|value| value.as_str());
    let shape = NumberShape::from_args(name, format)
        .map_err(|error| ControlResult::error(ControlErrorCode::BadRequest, format!("{error}")))?;
    resolve_dial_shape(shape.as_ref())
        .map_err(|error| ControlResult::error(ControlErrorCode::BadRequest, format!("{error}")))?;
    Ok(shape)
}

/// Map a `replace_peer` refusal onto its wire code.
///
/// Same discipline as [`bridge_error`]: one code per cause, so a controller can
/// branch on it. `invalid_state` in particular means "retry later or fix the
/// call", never "fix the frame" — a replacement refused because one is already
/// in flight becomes possible again the moment that one settles.
pub(super) fn replace_error(error: crate::b2bua::transfer::ReplaceError) -> ControlResult {
    use crate::b2bua::transfer::ReplaceError;
    let message = error.to_string();
    match error {
        ReplaceError::UnknownCall { .. } => {
            ControlResult::error(ControlErrorCode::NotFound, message)
        }
        ReplaceError::NotAnswered { .. }
        | ReplaceError::NoPeerLeg { .. }
        | ReplaceError::ReplacementInFlight { .. } => {
            ControlResult::error(ControlErrorCode::InvalidState, message)
        }
        ReplaceError::Unroutable { .. } => {
            ControlResult::error(ControlErrorCode::BadRequest, message)
        }
        ReplaceError::Unavailable(_) => {
            ControlResult::error(ControlErrorCode::Unavailable, message)
        }
    }
}

/// `replace_peer` — swap one leg of an answered call for a freshly dialed
/// target, with no REFER anywhere.
///
/// The controller-facing half of the same machinery a siphon-terminated REFER
/// runs. The reply reports only that the INVITE to the target is on the wire;
/// the outcome arrives as `PeerReplaced` / `ReplaceFailed`, because the
/// promotion, the survivor's re-INVITE and the replaced leg's BYE all happen
/// after the target answers.
pub(super) fn replace_peer(channel: &ChannelRef, args: &serde_json::Value) -> ControlResult {
    let Some(target) = args.get("target").and_then(|value| value.as_str()) else {
        return ControlResult::error(
            ControlErrorCode::BadRequest,
            "replace_peer requires a target URI",
        );
    };
    if let Err(error) = crate::sip::parser::parse_uri_standalone(target) {
        return ControlResult::error(
            ControlErrorCode::BadRequest,
            format!("invalid replacement target: {error}"),
        );
    }
    let next_hop = args.get("next_hop").and_then(|value| value.as_str());
    if let Some(next_hop) = next_hop {
        if let Err(error) = crate::sip::parser::parse_uri_standalone(next_hop) {
            return ControlResult::error(
                ControlErrorCode::BadRequest,
                format!("invalid next_hop: {error}"),
            );
        }
    }
    let replace_a_leg = args
        .get("replace_a_leg")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    // Same requirement as the in-process verb: a direction-bound profile
    // describes the party that is leaving, so the caller names the one for the
    // pair that remains.
    let media_profile = args.get("profile").and_then(|value| value.as_str());
    let number_shape = match validate_number_shape(args) {
        Ok(shape) => shape,
        Err(result) => return result,
    };
    let timeout_secs = match args.get("timeout") {
        None => 30,
        Some(value) => match value.as_u64() {
            Some(seconds) if seconds <= u64::from(u32::MAX) => seconds as u32,
            _ => {
                return ControlResult::error(
                    ControlErrorCode::BadRequest,
                    "replace_peer timeout must be a non-negative number of seconds",
                );
            }
        },
    };

    match crate::dispatcher::b2bua_replace_peer(
        &channel.sip_call_id,
        target,
        next_hop,
        replace_a_leg,
        media_profile,
        number_shape.as_ref(),
        timeout_secs,
    ) {
        Ok(()) => ControlResult::Ok(serde_json::json!({
            "channel": channel.channel_id,
            "replacement": "dialing",
            "target": target,
        })),
        Err(error) => replace_error(error),
    }
}

pub(super) fn accept_refer(channel: &ChannelRef, args: &serde_json::Value) -> ControlResult {
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

    // A transfer target is named by the referrer, in the referrer's number
    // format; the carrier the new leg is dialled at expects the trunk's. Same
    // knob, same resolution order, as `call.accept_refer(number_policy=…)`.
    let number_shape = match validate_number_shape(args) {
        Ok(shape) => shape,
        Err(result) => return result,
    };

    if crate::dispatcher::b2bua_accept_refer_call(
        &channel.sip_call_id,
        target.map(|s| s.to_string()),
        next_hop.map(|s| s.to_string()),
        mode,
        media_profile.map(|s| s.to_string()),
        number_shape,
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
pub(super) fn reject_refer(channel: &ChannelRef, args: &serde_json::Value) -> ControlResult {
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
pub(super) fn parse_refer_mode(
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
pub(super) fn parse_replaces_arg(
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
