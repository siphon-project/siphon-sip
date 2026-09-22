//! `route` and `dial`: handing a call back to siphon with a routing decision,
//! or ringing B-legs while the app keeps the channel.

use crate::control::protocol::{ControlErrorCode, ControlResult};
use crate::control::registry::ChannelRef;

/// Return control to siphon with a routing decision (the `route` verb). Un-parks
/// the deferred-handover call and dials the B-leg via siphon's LCR sequential
/// failover; siphon owns the call thereafter and the control app is released.
///
/// `args.targets` is a non-empty array of either bare URI strings or objects
/// `{uri, next_hop?, headers?, timeout?, reroute_after_progress?}`; `args.strategy` defaults to
/// `"sequential"` (v1 supports only sequential/single — anything else is a typed
/// error, never a silent sequential); `args.headers` is an optional object
/// applied to every attempt's B-leg INVITE.
pub(super) fn route(channel: &ChannelRef, args: &serde_json::Value) -> ControlResult {
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

/// `dial` — ring B-legs while the caller stays unanswered and app-owned.
///
/// The difference from [`route`] is who holds the call afterwards. `route`
/// hands it back to siphon, so the app gets `StasisEnd{reason: routed}` and
/// loses it; there is then no way to say "ring the extension, and if nobody
/// answers, voicemail" without answering the caller first — which starts
/// billing before anyone picks up, records an unanswered call as answered, and
/// denies the caller the callee's own ringback.
///
/// `from` / `from_display` / `p_asserted_identity` / `privacy` are the same
/// identity arguments `originate` takes. They matter here because a B-leg
/// otherwise presents the caller's own `From`, which on a call out to a trunk
/// is the internal extension: a carrier that looks its account up by the `From`
/// user does not recognise it and challenges the INVITE however correct the
/// digest is. `From` is framework-managed on a B-leg, so an injected
/// `headers: {"From": …}` cannot do this — see
/// [`crate::dispatcher::DialShaping`].
pub(super) fn dial(channel: &ChannelRef, args: &serde_json::Value) -> ControlResult {
    let profile = match args.get("profile") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(name)) if !name.trim().is_empty() => Some(name.as_str()),
        Some(_) => {
            return ControlResult::error(
                ControlErrorCode::BadRequest,
                "dial profile must be a non-empty profile name",
            )
        }
    };
    let privacy = match super::originate::parse_privacy("dial", args.get("privacy")) {
        Ok(privacy) => privacy,
        Err(message) => return ControlResult::error(ControlErrorCode::BadRequest, message),
    };
    let shaping = crate::dispatcher::DialShaping {
        profile: profile.map(str::to_string),
        from: super::string_arg(args, "from"),
        from_display: super::string_arg(args, "from_display"),
        p_asserted_identity: super::string_arg(args, "p_asserted_identity"),
        privacy,
    };
    let Some(targets_json) = args.get("targets").and_then(|v| v.as_array()) else {
        return ControlResult::error(
            ControlErrorCode::BadRequest,
            "dial requires args.targets (a non-empty array of URIs, {uri, next_hop, headers} or {aor})",
        );
    };
    if targets_json.is_empty() {
        return ControlResult::error(
            ControlErrorCode::BadRequest,
            "dial requires at least one target",
        );
    }

    let mut targets = Vec::with_capacity(targets_json.len());
    for item in targets_json {
        match parse_dial_target(item) {
            Ok(mut resolved) => targets.append(&mut resolved),
            Err(message) => return ControlResult::error(ControlErrorCode::BadRequest, message),
        }
    }
    if targets.is_empty() {
        // Every AoR resolved to nothing. Distinct from a malformed request:
        // the app asked for something reasonable and nobody is registered.
        return ControlResult::error(
            ControlErrorCode::NotFound,
            "no registered contact for any target",
        );
    }

    let strategy = args
        .get("strategy")
        .and_then(|v| v.as_str())
        .unwrap_or("parallel");
    let timeout_secs = args
        .get("timeout")
        .and_then(|v| v.as_u64())
        .unwrap_or(30)
        .clamp(1, 3600) as u32;
    let extra_headers = parse_extra_headers(args.get("headers"));
    let target_count = targets.len();

    match crate::dispatcher::b2bua_dial_call(
        &channel.sip_call_id,
        targets,
        strategy,
        timeout_secs,
        &extra_headers,
        &shaping,
    ) {
        Ok(true) => ControlResult::Ok(serde_json::json!({
            "channel": channel.channel_id,
            "state": "dialing",
            "targets": target_count,
            "strategy": strategy,
            "timeout": timeout_secs,
        })),
        Ok(false) => ControlResult::error(ControlErrorCode::NotFound, "call is gone"),
        Err(error @ crate::dispatcher::DialError::UnsupportedStrategy(_)) => {
            ControlResult::error(ControlErrorCode::UnsupportedVerb, error.to_string())
        }
        Err(error @ crate::dispatcher::DialError::AlreadyAnswered) => {
            ControlResult::error(ControlErrorCode::InvalidState, error.to_string())
        }
        Err(error @ crate::dispatcher::DialError::NoContacts(_)) => {
            ControlResult::error(ControlErrorCode::NotFound, error.to_string())
        }
        Err(error @ crate::dispatcher::DialError::NoTargets) => {
            ControlResult::error(ControlErrorCode::BadRequest, error.to_string())
        }
        Err(error @ crate::dispatcher::DialError::Media(_)) => {
            ControlResult::error(ControlErrorCode::Unavailable, error.to_string())
        }
        Err(error @ crate::dispatcher::DialError::InvalidIdentity(_)) => {
            ControlResult::error(ControlErrorCode::BadRequest, error.to_string())
        }
    }
}

/// Parse one `dial` target into the branches it stands for.
///
/// A URI is one branch. An `{aor}` is one branch per registered contact, each
/// over that contact's own captured flow — a phone on TCP, TLS or WSS behind
/// NAT is reachable only on the connection it registered over, so resolving its
/// Contact URI by DNS reaches nothing.
pub(super) fn parse_dial_target(
    item: &serde_json::Value,
) -> Result<Vec<crate::dispatcher::DialTarget>, String> {
    if let Some(uri) = item.as_str() {
        return Ok(vec![crate::dispatcher::DialTarget {
            uri: uri.to_string(),
            ..Default::default()
        }]);
    }
    let Some(object) = item.as_object() else {
        return Err(
            "each target must be a URI string, {uri, next_hop, headers} or {aor}".to_string(),
        );
    };

    if let Some(aor) = object.get("aor").and_then(|v| v.as_str()) {
        let headers: std::collections::HashMap<String, String> = object
            .get("headers")
            .map(parse_json_headers)
            .unwrap_or_default()
            .into_iter()
            .collect();
        return match crate::dispatcher::dial_targets_for_aor(aor) {
            Ok(mut branches) => {
                for branch in &mut branches {
                    branch.headers.extend(headers.clone());
                }
                Ok(branches)
            }
            // Nobody registered is not a malformed request; the caller gets a
            // typed `not_found` once every target has been tried.
            Err(_) => Ok(Vec::new()),
        };
    }

    let Some(uri) = object.get("uri").and_then(|v| v.as_str()) else {
        return Err("target object requires a string 'uri' or 'aor'".to_string());
    };
    Ok(vec![crate::dispatcher::DialTarget {
        uri: uri.to_string(),
        next_hop: object
            .get("next_hop")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        flow: None,
        route: Vec::new(),
        headers: object
            .get("headers")
            .map(parse_json_headers)
            .unwrap_or_default()
            .into_iter()
            .collect(),
        from: object
            .get("from")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        from_display: object
            .get("from_display")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        p_asserted_identity: object
            .get("p_asserted_identity")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        privacy: super::originate::parse_privacy("dial target", object.get("privacy"))
            .map_err(|error| error.to_string())?,
    }])
}

/// Parse one `targets[]` entry: a bare URI string, or an object
/// `{uri, next_hop?, headers?, timeout?, reroute_after_progress?}`.
pub(super) fn parse_route_target(
    item: &serde_json::Value,
) -> Result<crate::dispatcher::RouteTarget, String> {
    if let Some(uri) = item.as_str() {
        return Ok(crate::dispatcher::RouteTarget {
            uri: uri.to_string(),
            next_hop: None,
            headers: Vec::new(),
            timeout_secs: None,
            reroute_after_progress: false,
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
    // A policy flag: a value that is not a boolean is refused rather than read
    // as `false`, which would quietly keep the carrier on the default rule.
    let reroute_after_progress = match object.get("reroute_after_progress") {
        None => false,
        Some(value) => value
            .as_bool()
            .ok_or_else(|| "target 'reroute_after_progress' must be a boolean".to_string())?,
    };
    Ok(crate::dispatcher::RouteTarget {
        uri: uri.to_string(),
        next_hop,
        headers,
        timeout_secs,
        reroute_after_progress,
    })
}

/// Parse a command-level `headers` object (applied to every route attempt).
pub(super) fn parse_extra_headers(value: Option<&serde_json::Value>) -> Vec<(String, String)> {
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
