//! `bridge` / `unbridge`: joining and parting two channels the app owns.

use crate::control::protocol::{ControlErrorCode, ControlResult};
use crate::control::registry::{ChannelRef, ControlBus};
use crate::control::AdapterCommand;

use super::controlled_channel;

/// Dispatch `bridge` / `unbridge`.
///
/// `bridge` is the one verb that addresses **two** channels: the substrate
/// resolves and ownership-checks the target, and the second is named in
/// `args.with` and checked here against the same connection — a controller can
/// only bridge two legs it owns, or one app could join another app's call to
/// its own.
pub(super) async fn apply_bridge_verb(command: AdapterCommand) -> ControlResult {
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
    let Some((bus, _)) = super::dial_bridge::rail(&command.origin.app) else {
        return ControlResult::error(
            ControlErrorCode::Unavailable,
            "control plane is not installed",
        );
    };
    bridge_with_bus(&bus, channel, command).await
}

/// [`bridge`] with the bus injected, so the argument and ownership rules are
/// testable without a process-global control plane.
pub(super) async fn bridge_with_bus(
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
    let profile = match parse_bridge_profile(args.get("profile")) {
        Ok(profile) => profile,
        Err(refusal) => return refusal,
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

    let dispatcher = super::dial_bridge::dispatcher_for(&command.origin.app);
    let Some(state) = dispatcher.state() else {
        return ControlResult::error(
            ControlErrorCode::Unavailable,
            "b2bua is not running — nothing to bridge",
        );
    };
    if let Some(name) = profile.as_deref() {
        let known = state
            .rtpengine_profiles
            .as_ref()
            .is_some_and(|registry| registry.get(name).is_some());
        if !known {
            return profile_refusal(
                "unknown_profile",
                format!("bridge args.profile names no media profile this deployment has: '{name}'"),
                Some(name),
            );
        }
    }
    let params = crate::dispatcher::BridgeParams {
        anchor_sip_call_id: channel.sip_call_id.clone(),
        peer_sip_call_id: with.sip_call_id.clone(),
        on_peer_hangup,
    };
    match crate::dispatcher::bridge_calls_with_state(state, params, profile.as_deref()).await {
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
                "profile": profile,
                "state": "bridging",
            }))
        }
        Err(error) => bridge_error(error),
    }
}

/// Parse `args.profile`: one media profile for the pair — its `offer` half
/// shapes what the `with` leg is offered, its `answer` half what the target is
/// re-INVITEd with. Absent or `null` leaves each leg shaped by the profile it
/// was anchored with.
pub(super) fn parse_bridge_profile(
    value: Option<&serde_json::Value>,
) -> Result<Option<String>, ControlResult> {
    match value {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(name)) if !name.trim().is_empty() => Ok(Some(name.clone())),
        Some(_) => Err(profile_refusal(
            "invalid_value",
            "bridge args.profile must be a non-empty media profile name".to_string(),
            None,
        )),
    }
}

/// A `bad_request` about `args.profile`, typed the way every verb's argument
/// refusals are: the verb, the argument and why.
fn profile_refusal(reason: &str, message: String, profile: Option<&str>) -> ControlResult {
    let mut details = serde_json::json!({
        "verb": "bridge",
        "argument": "profile",
        "reason": reason,
    });
    if let (Some(profile), Some(fields)) = (profile, details.as_object_mut()) {
        fields.insert("profile".into(), profile.into());
    }
    ControlResult::error_with_details(ControlErrorCode::BadRequest, message, details)
}

/// Break the target channel's bridge. Both legs stay answered, owned and held.
pub(super) async fn unbridge(channel: &ChannelRef, args: &serde_json::Value) -> ControlResult {
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
pub(super) fn bridge_error(error: crate::b2bua::bridge::BridgeError) -> ControlResult {
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
