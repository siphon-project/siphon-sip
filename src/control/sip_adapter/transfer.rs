//! Transfer verbs: `refer`, `accept_refer`, `reject_refer`, `complete_refer`
//! and `replace_peer`.

use crate::control::protocol::{ControlErrorCode, ControlResult};
use crate::control::registry::ChannelRef;
use crate::control::AdapterCommand;

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

/// What a transfer verb dials, and how: the target URI when it names one, with
/// the flow, called party and identity of the leg it creates.
pub(super) struct TransferDial {
    /// The URI to dial: the one named, or the registered contact an `{aor}`
    /// resolved to. `None` when the verb named no target.
    pub(super) target: Option<String>,
    pub(super) dial: crate::dispatcher::ReplacementDial,
}

impl TransferDial {
    /// Whether the verb named anything a transfer siphon does not dial itself
    /// would have to ignore.
    fn names_a_dial(&self) -> bool {
        let shaping = &self.dial.shaping;
        self.dial.aor.is_some()
            || !self.dial.headers.is_empty()
            || shaping.from.is_some()
            || shaping.from_display.is_some()
            || shaping.p_asserted_identity.is_some()
            || shaping.privacy.is_some()
    }
}

/// Parse a transfer verb's `target` and identity arguments.
///
/// `target` is a URI string, `{uri}`, or `{aor}` — a registered AoR, dialled
/// over the flow its phone registered on and through the Path of its binding,
/// which is the only way to reach a phone on TCP, TLS or WebSocket. `from`,
/// `from_display`, `p_asserted_identity`, `privacy` and `headers` are the
/// arguments `dial` takes, and shape the new leg the same way.
///
/// An AoR nobody is registered at is `not_found`. One with several registered
/// contacts rings them all, each on an INVITE of its own: the first to answer
/// is the party brought into the call and the rest are CANCELled (RFC 3261
/// §16.7), which is what calling a party with several phones means.
pub(super) fn parse_transfer_dial(
    verb: &str,
    args: &serde_json::Value,
) -> Result<TransferDial, ControlResult> {
    let bad = |message: String| ControlResult::error(ControlErrorCode::BadRequest, message);
    let shaping = crate::dispatcher::DialShaping {
        profile: None,
        from: super::string_arg(args, "from"),
        from_display: args
            .get("from_display")
            .and_then(|value| value.as_str())
            .map(str::to_string),
        p_asserted_identity: super::string_arg(args, "p_asserted_identity"),
        privacy: super::originate::parse_privacy(verb, args.get("privacy")).map_err(bad)?,
    };
    for (name, value) in [
        ("from", shaping.from.as_deref()),
        (
            "p_asserted_identity",
            shaping.p_asserted_identity.as_deref(),
        ),
    ] {
        if let Some(Err(error)) = value.map(crate::sip::parser::parse_uri_standalone) {
            return Err(bad(format!("{verb} args.{name} is not a SIP URI: {error}")));
        }
    }
    let headers = super::routing::parse_extra_headers(args.get("headers"));
    let uri_target = |uri: &str| match crate::sip::parser::parse_uri_standalone(uri) {
        Ok(_) => Ok(Some(uri.to_string())),
        Err(error) => Err(bad(format!("invalid {verb} target: {error}"))),
    };
    let plain = |target: Option<String>, shaping, headers| TransferDial {
        target,
        dial: crate::dispatcher::ReplacementDial {
            shaping,
            headers,
            ..Default::default()
        },
    };
    let object = match args.get("target") {
        None | Some(serde_json::Value::Null) => return Ok(plain(None, shaping, headers)),
        Some(serde_json::Value::String(uri)) => {
            return Ok(plain(uri_target(uri)?, shaping, headers))
        }
        Some(serde_json::Value::Object(object)) => object,
        Some(_) => {
            return Err(bad(format!(
                "{verb} args.target must be a URI string, {{uri}} or {{aor}}"
            )))
        }
    };
    match (
        object.get("uri").and_then(|value| value.as_str()),
        object.get("aor").and_then(|value| value.as_str()),
    ) {
        (Some(uri), None) => Ok(plain(uri_target(uri)?, shaping, headers)),
        (None, Some(aor)) => {
            if args.get("next_hop").is_some_and(|value| !value.is_null()) {
                return Err(bad(format!(
                    "{verb} args.next_hop does not apply to an {{aor}} target, which is reached over the flow it registered on"
                )));
            }
            let contacts = crate::dispatcher::dial_targets_for_aor(aor).map_err(|error| {
                ControlResult::error(ControlErrorCode::NotFound, error.to_string())
            })?;
            let Some((target, dial)) =
                crate::dispatcher::ReplacementDial::to_contacts(contacts, shaping, headers)
            else {
                return Err(ControlResult::error(
                    ControlErrorCode::NotFound,
                    format!("no registered contact for {aor}"),
                ));
            };
            Ok(TransferDial {
                target: Some(target),
                dial,
            })
        }
        _ => Err(bad(format!(
            "{verb} args.target must name exactly one of uri or aor"
        ))),
    }
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
    let transfer = match parse_transfer_dial("replace_peer", args) {
        Ok(transfer) => transfer,
        Err(refusal) => return refusal,
    };
    let Some(target) = transfer.target.as_deref() else {
        return ControlResult::error(
            ControlErrorCode::BadRequest,
            "replace_peer requires a target: a URI, {uri} or {aor}",
        );
    };
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

    match crate::dispatcher::b2bua_replace_peer_dialling(
        &channel.sip_call_id,
        target,
        next_hop,
        replace_a_leg,
        media_profile,
        number_shape.as_ref(),
        timeout_secs,
        &transfer.dial,
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
    let transfer = match parse_transfer_dial("accept_refer", args) {
        Ok(transfer) => transfer,
        Err(refusal) => return refusal,
    };
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
    // A transparent transfer relays the REFER and dials nothing, so a flow to
    // dial over or an identity to present would be accepted and never used.
    if mode == Some(crate::script::api::call::ReferMode::Transparent) && transfer.names_a_dial() {
        return ControlResult::error(
            ControlErrorCode::BadRequest,
            "accept_refer mode \"transparent\" relays the REFER and dials no leg: an {aor} target, from, from_display, p_asserted_identity, privacy and headers apply to mode \"terminate\"",
        );
    }

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

    if crate::dispatcher::b2bua_accept_refer_call_dialling(
        &channel.sip_call_id,
        transfer.target,
        next_hop.map(|s| s.to_string()),
        mode,
        media_profile.map(|s| s.to_string()),
        number_shape,
        &transfer.dial,
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

/// The arguments of `accept_refer` that describe the leg a transfer dials.
const DIAL_ARGUMENTS: [&str; 10] = [
    "target",
    "next_hop",
    "profile",
    "number_policy",
    "format",
    "from",
    "from_display",
    "p_asserted_identity",
    "privacy",
    "headers",
];

/// Who carries an accepted transfer out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AcceptReferMode {
    /// siphon: it dials the target (`terminate`) or relays the REFER
    /// (`transparent`), or whichever `b2bua.default_refer_mode` names.
    Siphon(Option<crate::script::api::call::ReferMode>),
    /// The application, which reports with `complete_refer`.
    Controller,
}

/// Parse `accept_refer`'s `mode`.
///
/// `controller` exists on this rail only. A script has no `complete_refer` to
/// follow it with, so it is not a [`crate::script::api::call::ReferMode`] and
/// cannot be a configured default.
pub(super) fn parse_accept_refer_mode(
    value: Option<&serde_json::Value>,
) -> Result<AcceptReferMode, String> {
    match value.and_then(|value| value.as_str()) {
        Some("controller") => Ok(AcceptReferMode::Controller),
        _ => parse_refer_mode(value).map(AcceptReferMode::Siphon),
    }
}

/// `accept_refer`, as a controller's command reaches it.
///
/// `mode: "controller"` is the transfer the application carries out itself —
/// see [`accept_refer_controller`]. Every other mode is [`accept_refer`], which
/// has no `timeout` to honour: its transfers end when the target answers or the
/// far end reports, so a `timeout` named with them is refused rather than
/// accepted and ignored.
pub(super) fn accept_refer_command(
    channel: &ChannelRef,
    command: &AdapterCommand,
) -> ControlResult {
    let args = &command.args;
    match parse_accept_refer_mode(args.get("mode")) {
        Ok(AcceptReferMode::Controller) => accept_refer_controller(channel, command),
        Ok(AcceptReferMode::Siphon(_)) if arg_present(args, "timeout") => ControlResult::error(
            ControlErrorCode::BadRequest,
            "accept_refer args.timeout applies to mode \"controller\": it is how long the application has to report with complete_refer",
        ),
        // The mode is parsed again there, with everything else the verb takes.
        _ => accept_refer(channel, args),
    }
}

/// Whether an argument is present and not JSON `null`.
fn arg_present(args: &serde_json::Value, name: &str) -> bool {
    args.get(name).is_some_and(|value| !value.is_null())
}

/// `accept_refer {mode: "controller", timeout?}` — accept the pending REFER for
/// the application to carry out.
///
/// siphon answers `202 Accepted`, sends the first sipfrag NOTIFY (`100 Trying`)
/// and dials nothing. The application moves the parties with its other verbs —
/// `bridge`, `unbridge`, `replace_peer`, `dial` — and then reports with
/// `complete_refer`. `timeout` is how many seconds it has (default 60, at most
/// 180); past it siphon reports a `503` to the referrer itself.
///
/// Every argument describing a leg to dial is refused: none is dialled, so one
/// accepted here would be dropped without a word.
pub(super) fn accept_refer_controller(
    channel: &ChannelRef,
    command: &AdapterCommand,
) -> ControlResult {
    let args = &command.args;
    if let Some(name) = DIAL_ARGUMENTS.iter().find(|name| arg_present(args, name)) {
        return ControlResult::error_with_details(
            ControlErrorCode::BadRequest,
            format!(
                "accept_refer mode \"controller\" dials no leg, so args.{name} has nothing to apply to: target, next_hop, profile, number_policy, format, from, from_display, p_asserted_identity, privacy and headers belong to mode \"terminate\""
            ),
            serde_json::json!({
                "verb": "accept_refer",
                "argument": name,
                "reason": "not_dialled",
            }),
        );
    }
    let timeout = match args.get("timeout") {
        None | Some(serde_json::Value::Null) => None,
        Some(value) => match value.as_u64().map(u32::try_from) {
            Some(Ok(seconds)) if seconds > 0 => Some(seconds),
            _ => {
                return ControlResult::error(
                    ControlErrorCode::BadRequest,
                    "accept_refer timeout must be a positive whole number of seconds",
                )
            }
        },
    };

    let dispatcher = super::dial_bridge::dispatcher_for(&command.origin.app);
    let (Some(state), Some(runtime)) = (dispatcher.state(), dispatcher.runtime()) else {
        // As the other modes answer with no B2BUA running: nothing is pending.
        return controller_refer_refused(
            "accept_refer",
            crate::dispatcher::ControllerReferRefusal::NoPendingRefer,
        );
    };
    // The 202 and the NOTIFY may open a connection (TCP/TLS).
    let _enter = runtime.enter();
    match crate::dispatcher::b2bua_accept_refer_controller_with_state(
        state,
        &channel.sip_call_id,
        timeout,
    ) {
        Ok(timeout) => ControlResult::Ok(serde_json::json!({
            "channel": channel.channel_id,
            "transfer": "accepted",
            "mode": "controller",
            "timeout": timeout,
        })),
        Err(refusal) => controller_refer_refused("accept_refer", refusal),
    }
}

/// `complete_refer {code, reason?}` — report how a transfer accepted in mode
/// `controller` went.
///
/// siphon sends the referrer the sipfrag NOTIFY that ends its subscription
/// (RFC 3515 §2.4.4): `code` is the status in it, a 2xx for a transfer that
/// succeeded, and `reason` its reason phrase, used as given. Nothing else
/// happens — the parties are wherever the application's other verbs put them.
///
/// Refused `invalid_state` with reason `no_transfer_pending` when the call has
/// no such transfer open, and `not_found` when the call or the referrer's leg
/// of it is gone: report before releasing the referrer.
pub(super) fn complete_refer(channel: &ChannelRef, command: &AdapterCommand) -> ControlResult {
    let args = &command.args;
    let code = match args.get("code").and_then(|value| value.as_u64()) {
        Some(code) if (200..=699).contains(&code) => code as u16,
        _ => {
            return ControlResult::error(
                ControlErrorCode::BadRequest,
                "complete_refer requires args.code, the final status of the transfer (200-699): a 2xx reports it succeeded",
            )
        }
    };
    let reason = match args.get("reason") {
        None | Some(serde_json::Value::Null) => None,
        // It becomes the Status-Line of a sipfrag, so it stays on one line.
        Some(serde_json::Value::String(reason))
            if !reason.trim().is_empty() && !reason.chars().any(char::is_control) =>
        {
            Some(reason.trim())
        }
        Some(_) => {
            return ControlResult::error(
                ControlErrorCode::BadRequest,
                "complete_refer reason must be a non-empty reason phrase on one line",
            )
        }
    };

    let dispatcher = super::dial_bridge::dispatcher_for(&command.origin.app);
    let (Some(state), Some(runtime)) = (dispatcher.state(), dispatcher.runtime()) else {
        return ControlResult::error(
            ControlErrorCode::Unavailable,
            "b2bua is not running — no transfer to report on",
        );
    };
    // The NOTIFY may open a connection (TCP/TLS).
    let _enter = runtime.enter();
    match crate::dispatcher::b2bua_complete_refer_with_state(
        state,
        &channel.sip_call_id,
        code,
        reason,
    ) {
        Ok(()) => ControlResult::Ok(serde_json::json!({
            "channel": channel.channel_id,
            "transfer": "completed",
            "code": code,
        })),
        Err(refusal) => controller_refer_refused("complete_refer", refusal),
    }
}

/// The reply for a controller-carried transfer that was not accepted or not
/// reported: `not_found` when there is nothing to act on any more, otherwise
/// `invalid_state`, and always naming why.
pub(super) fn controller_refer_refused(
    verb: &str,
    refusal: crate::dispatcher::ControllerReferRefusal,
) -> ControlResult {
    use crate::dispatcher::ControllerReferRefusal;
    let code = match refusal {
        ControllerReferRefusal::NoPendingRefer
        | ControllerReferRefusal::Gone
        | ControllerReferRefusal::ReferrerGone => ControlErrorCode::NotFound,
        ControllerReferRefusal::TransferOpen | ControllerReferRefusal::NoTransferPending => {
            ControlErrorCode::InvalidState
        }
    };
    ControlResult::error_with_details(
        code,
        refusal.to_string(),
        serde_json::json!({ "verb": verb, "reason": refusal.reason() }),
    )
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
            _ => Err(
                "accept_refer args.mode must be \"terminate\", \"transparent\" or \"controller\""
                    .to_string(),
            ),
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
