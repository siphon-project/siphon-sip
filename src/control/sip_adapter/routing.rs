//! `route` and `dial`: handing a call back to siphon with a routing decision,
//! or ringing B-legs while the app keeps the channel.

use crate::control::protocol::{ControlErrorCode, ControlResult};
use crate::control::registry::ChannelRef;
use crate::control::AdapterCommand;

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
    // The caller's own Contact host and user, which the 2xx relayed to it
    // carries; the targets' `contact_host` / `contact_user` are what each
    // attempt presents its carrier.
    let caller_contact = match super::caller_contact::parse("route", "caller_", args) {
        Ok(contact) => contact,
        Err(refusal) => return refusal,
    };
    if let Err(refusal) = super::caller_contact::apply(
        &crate::dispatcher::RunningDispatcher,
        channel,
        "route",
        "caller_",
        &caller_contact,
    ) {
        return refusal;
    }

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

/// [`route`], refused while a `dial` is still ringing for the call.
///
/// `route` releases the channel, so a dial left ringing behind it would report
/// into a channel that no longer exists and, for a bridging dial, connect a
/// phone to a caller that has since been sent somewhere else. The controller
/// ends the dial first (`cancel_dial`), or waits for its outcome.
pub(super) fn route_unless_dialling(
    channel: &ChannelRef,
    command: &AdapterCommand,
) -> ControlResult {
    if dial_under_way(channel, &command.origin.app) {
        return ControlResult::error_with_details(
            ControlErrorCode::InvalidState,
            "route cannot hand this call back while a dial is still ringing for it — cancel_dial \
             first, or wait for DialAnswered / DialFailed",
            serde_json::json!({ "verb": "route", "reason": "dial_in_progress" }),
        );
    }
    route(channel, &command.args)
}

/// Whether a `dial` — bridging or connecting — is still ringing for the
/// channel's call.
fn dial_under_way(channel: &ChannelRef, app: &str) -> bool {
    let dispatcher = super::dial_bridge::dispatcher_for(app);
    dispatcher.state().is_some_and(|state| {
        state.dial_bridges.is_ringing(&channel.sip_call_id)
            || state.call_actors.is_control_dial(&channel.call_actor_id)
    })
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
///
/// `on_answer: "bridge"` is the other half: a caller siphon already answered
/// (and anchored, typically after an IVR's prompts) is not connected by the
/// phone's answer but bridged to it. See [`super::dial_bridge`].
pub(super) fn dial(channel: &ChannelRef, command: &AdapterCommand) -> ControlResult {
    let args = &command.args;
    let on_answer = match parse_on_answer(args.get("on_answer")) {
        Ok(on_answer) => on_answer,
        Err(refusal) => return refusal,
    };
    let ringback = match super::dial_bridge::parse_ringback(args.get("ringback"), on_answer) {
        Ok(ringback) => ringback,
        Err(refusal) => return refusal,
    };
    let profile = match parse_profile("dial", args.get("profile")) {
        Ok(profile) => profile,
        Err(message) => return ControlResult::error(ControlErrorCode::BadRequest, message),
    };
    let offer = match parse_offer("dial", args.get("offer")) {
        Ok(offer) => offer,
        Err(message) => return offer_refusal(message, "unknown_value"),
    };
    let privacy = match super::originate::parse_privacy("dial", args.get("privacy")) {
        Ok(privacy) => privacy,
        Err(message) => return ControlResult::error(ControlErrorCode::BadRequest, message),
    };
    let shaping = crate::dispatcher::DialShaping {
        profile,
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

    // Only a bridging dial places its legs itself: a connecting dial's
    // branches carry the caller's own offer, so naming when they offer is
    // refused rather than ignored.
    if on_answer == OnAnswer::Connect
        && (offer.is_some() || targets.iter().any(|target| target.offer.is_some()))
    {
        return offer_refusal(
            "dial offer applies to on_answer \"bridge\" — a connecting dial's branches carry the \
             caller's own offer"
                .to_string(),
            "requires_bridge",
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
    // The caller's own Contact host and user. The targets' `contact_host` and
    // `contact_user` belong to the legs siphon places, so the caller side has
    // names of its own.
    let caller_contact = match super::caller_contact::parse("dial", "caller_", args) {
        Ok(contact) => contact,
        Err(refusal) => return refusal,
    };

    if on_answer == OnAnswer::Bridge {
        return super::dial_bridge::dial_bridge(
            channel,
            command,
            super::dial_bridge::BridgeDialRequest {
                targets,
                shaping,
                headers: extra_headers,
                strategy: strategy.to_string(),
                timeout_secs,
                ringback,
                caller_contact,
                offer,
            },
        );
    }
    let dispatcher = super::dial_bridge::dispatcher_for(&command.origin.app);
    if let Err(refusal) = super::caller_contact::apply(
        dispatcher.as_ref(),
        channel,
        "dial",
        "caller_",
        &caller_contact,
    ) {
        return refusal;
    }

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
        Err(error) => dial_error(error),
    }
}

/// `cancel_dial` — give up on the dial ringing for this channel's caller.
///
/// The one way to stop a dial that leaves the caller alone: the phones are
/// CANCELled (RFC 3261 §9.1) and the dial fails with `DialFailed {code: 487}`,
/// the caller exactly as the dial found it and free to be dialled for again.
/// `hangup` ends the caller too, and letting the ring timeout run keeps the
/// phones ringing until it does.
///
/// `args.reason` is reported as the `cause` of a bridging dial's `DialFailed`
/// (default `cancelled`). Refused `invalid_state` with a typed `reason` when no
/// dial is ringing, or when a phone has already answered and is being bridged.
pub(super) fn cancel_dial(channel: &ChannelRef, command: &AdapterCommand) -> ControlResult {
    let reason = match command.args.get("reason") {
        None | Some(serde_json::Value::Null) => crate::dispatcher::DIAL_CANCELLED.to_string(),
        Some(serde_json::Value::String(reason)) if !reason.trim().is_empty() => reason.clone(),
        Some(_) => {
            return ControlResult::error(
                ControlErrorCode::BadRequest,
                "cancel_dial reason must be a non-empty string",
            )
        }
    };
    let dispatcher = super::dial_bridge::dispatcher_for(&command.origin.app);
    let (Some(state), Some(runtime)) = (dispatcher.state(), dispatcher.runtime()) else {
        return ControlResult::error(
            ControlErrorCode::Unavailable,
            "b2bua is not running — no dial to cancel",
        );
    };
    // The CANCELs may open a connection (TCP/TLS).
    let _enter = runtime.enter();
    match crate::dispatcher::b2bua_cancel_dial_with_state(state, &channel.sip_call_id, &reason) {
        Ok(cancelled) => ControlResult::Ok(serde_json::json!({
            "channel": channel.channel_id,
            "state": "cancelled",
            "on_answer": cancelled.on_answer(),
        })),
        Err(refusal) => cancel_dial_refused(refusal),
    }
}

/// How long `cancel_dial` waits for the dial it ended to let go of the caller
/// before answering anyway. What it waits on is local: the dial's own task
/// stopping the ringback on the media engine and reporting `DialFailed`.
const DIAL_CONCLUSION_BOUND: std::time::Duration = std::time::Duration::from_secs(5);

/// The bridging dial a `cancel_dial` is about to end, watched from before the
/// cancel so its conclusion cannot be missed.
pub(super) struct WatchedDial {
    dispatcher: std::sync::Arc<dyn crate::dispatcher::DispatcherHandle>,
    sip_call_id: String,
    conclusion: tokio::sync::watch::Receiver<()>,
}

/// The dial ringing for the caller a `cancel_dial` names, if one is. `None`
/// for any other verb, and for a connecting dial: its cancel is carried out in
/// full before it returns.
pub(super) fn watch_dial_to_cancel(command: &AdapterCommand) -> Option<WatchedDial> {
    if command.verb != "cancel_dial" {
        return None;
    }
    let crate::control::ResolvedTarget::Channel(channel) = &command.target else {
        return None;
    };
    let dispatcher = super::dial_bridge::dispatcher_for(&command.origin.app);
    let conclusion = dispatcher
        .state()?
        .dial_bridges
        .conclusion(&channel.sip_call_id)?;
    Some(WatchedDial {
        dispatcher,
        sip_call_id: channel.sip_call_id.clone(),
        conclusion,
    })
}

/// Hold the reply to an accepted `cancel_dial` until the dial it ended has let
/// go of the caller.
///
/// The cancel itself is synchronous: the phones are CANCELled and each is
/// reported before it returns. What is left runs on the dial's own task, which
/// stops the ringback on the media engine, reports `DialFailed`, and only then
/// lets go of the caller. A reply sent ahead of that told the controller the
/// dial was over while a `route` or a second `dial` was still refused
/// `dial_in_progress`. Waiting here puts `DialFailed` ahead of the reply and
/// makes the reply mean what it says.
///
/// Bounded: a dial that has not concluded by then is let go of here, so the
/// caller is free once the reply is in whatever became of that task.
pub(super) async fn dial_concluded(watched: Option<WatchedDial>, result: &ControlResult) {
    let (Some(mut watched), ControlResult::Ok(_)) = (watched, result) else {
        return;
    };
    let concluded = tokio::time::timeout(DIAL_CONCLUSION_BOUND, async {
        // The watch carries no value: it only closes, with the dial's entry.
        while watched.conclusion.changed().await.is_ok() {}
    })
    .await;
    if concluded.is_ok() {
        return;
    }
    let released = watched.dispatcher.state().is_some_and(|state| {
        state
            .dial_bridges
            .release_watched(&watched.sip_call_id, &watched.conclusion)
    });
    tracing::error!(
        caller = %watched.sip_call_id,
        released,
        "control plane: cancel_dial — the cancelled dial had not reported its end within {} s; \
         the caller is released and DialFailed follows when it does",
        DIAL_CONCLUSION_BOUND.as_secs()
    );
}

/// The reply for a dial that was not cancelled: `not_found` when the call is
/// gone, otherwise `invalid_state` naming why.
pub(super) fn cancel_dial_refused(refusal: crate::dispatcher::DialCancelRefusal) -> ControlResult {
    let code = match refusal {
        crate::dispatcher::DialCancelRefusal::Gone => ControlErrorCode::NotFound,
        _ => ControlErrorCode::InvalidState,
    };
    ControlResult::error_with_details(
        code,
        refusal.to_string(),
        serde_json::json!({ "verb": "cancel_dial", "reason": refusal.reason() }),
    )
}

/// Map a refused `dial` onto its wire code.
///
/// The already-answered refusal also carries `details` (`verb`, `reason`,
/// `call_state`): `invalid_state` alone cannot tell a controller that this call
/// is answered, as opposed to any other invalid state, without it matching the
/// prose.
pub(super) fn dial_error(error: crate::dispatcher::DialError) -> ControlResult {
    use crate::dispatcher::DialError;
    let code = match &error {
        DialError::AlreadyAnswered { call_state } => {
            return ControlResult::error_with_details(
                ControlErrorCode::InvalidState,
                error.to_string(),
                serde_json::json!({
                    "verb": "dial",
                    "reason": "already_answered",
                    "call_state": crate::control::call_state_str(call_state),
                }),
            );
        }
        DialError::UnsupportedStrategy(_) => ControlErrorCode::UnsupportedVerb,
        DialError::NoContacts(_) => ControlErrorCode::NotFound,
        DialError::NoTargets | DialError::InvalidIdentity(_) | DialError::InvalidMedia(_) => {
            ControlErrorCode::BadRequest
        }
        DialError::Media(_) => ControlErrorCode::Unavailable,
    };
    ControlResult::error(code, error.to_string())
}

/// What a `dial` does when a phone answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum OnAnswer {
    /// Answer the caller with the phone's answer: the pair becomes an ordinary
    /// two-leg call. For a caller that is still ringing.
    Connect,
    /// Bridge the phone to a caller siphon already answered.
    Bridge,
}

impl OnAnswer {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::Bridge => "bridge",
        }
    }
}

/// Parse `args.on_answer`: absent is `connect`, today's dial. Anything that is
/// not one of the two names is refused rather than read as the default — a
/// controller that meant `bridge` and got `connect` would find its answered
/// caller refused for a reason it did not ask about.
pub(super) fn parse_on_answer(
    value: Option<&serde_json::Value>,
) -> Result<OnAnswer, ControlResult> {
    match value {
        None | Some(serde_json::Value::Null) => Ok(OnAnswer::Connect),
        Some(serde_json::Value::String(name)) if name == "connect" => Ok(OnAnswer::Connect),
        Some(serde_json::Value::String(name)) if name == "bridge" => Ok(OnAnswer::Bridge),
        Some(other) => Err(ControlResult::error_with_details(
            ControlErrorCode::BadRequest,
            format!("dial args.on_answer must be \"connect\" or \"bridge\", got {other}"),
            serde_json::json!({
                "verb": "dial",
                "argument": "on_answer",
                "reason": "unknown_value",
                "value": other,
            }),
        )),
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

    // What a target says about its own branch, the same on either form: an
    // `{aor}` applies it to every contact it forks to. Read once, so the two
    // forms cannot drift apart again: the AoR form used to read only
    // `headers`, and its identity fields were dropped without a word.
    let string_field = |name: &str| {
        object
            .get(name)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    };
    let shaped = crate::dispatcher::DialTarget {
        headers: object
            .get("headers")
            .map(parse_json_headers)
            .unwrap_or_default()
            .into_iter()
            .collect(),
        from: string_field("from"),
        from_display: string_field("from_display"),
        p_asserted_identity: string_field("p_asserted_identity"),
        privacy: super::originate::parse_privacy("dial target", object.get("privacy"))
            .map_err(|error| error.to_string())?,
        to: string_field("to"),
        contact_host: parse_contact_host(object).map_err(|error| format!("target {error}"))?,
        contact_user: parse_contact_user(object).map_err(|error| format!("target {error}"))?,
        profile: parse_profile("dial target", object.get("profile"))?,
        offer: parse_offer("dial target", object.get("offer"))?,
        ..Default::default()
    };

    let route = parse_route_set(object)?;

    if let Some(aor) = object.get("aor").and_then(|v| v.as_str()) {
        // Each branch of an AoR is routed over its own binding's Path, which
        // is the route set that contact needs. One named here would have to
        // replace that Path or sit in front of it, and either silently changes
        // where a registered phone is reached, so the two are not combined.
        if !route.is_empty() {
            return Err(
                "a target's 'route' applies to a {uri} target: an {aor} routes each branch over \
                 its own binding's Path"
                    .to_string(),
            );
        }
        return match crate::dispatcher::dial_targets_for_aor(aor) {
            Ok(mut branches) => {
                for branch in &mut branches {
                    branch.headers.extend(shaped.headers.clone());
                    branch.from.clone_from(&shaped.from);
                    branch.from_display.clone_from(&shaped.from_display);
                    branch
                        .p_asserted_identity
                        .clone_from(&shaped.p_asserted_identity);
                    branch.privacy = shaped.privacy;
                    branch.to.clone_from(&shaped.to);
                    branch.contact_host.clone_from(&shaped.contact_host);
                    branch.contact_user.clone_from(&shaped.contact_user);
                    branch.profile.clone_from(&shaped.profile);
                    branch.offer = shaped.offer;
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
        next_hop: string_field("next_hop"),
        route,
        // A URI dialled as written names no registered AoR, even one that
        // happens to be a registered contact: only an `{aor}` target says whom
        // the branch was dialled for.
        aor: None,
        ..shaped
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
            route: Vec::new(),
            contact_host: None,
            contact_user: None,
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
    let route = parse_route_set(object)?;
    let contact_host = parse_contact_host(object).map_err(|error| format!("target {error}"))?;
    let contact_user = parse_contact_user(object).map_err(|error| format!("target {error}"))?;
    Ok(crate::dispatcher::RouteTarget {
        uri: uri.to_string(),
        next_hop,
        headers,
        timeout_secs,
        reroute_after_progress,
        route,
        contact_host,
        contact_user,
    })
}

/// Read a media `profile` argument: absent or `null` is none, anything else
/// must name a profile. Whether siphon defines it is the media layer's to say,
/// at dial time, the same for a dial's own profile and a target's.
fn parse_profile(whose: &str, value: Option<&serde_json::Value>) -> Result<Option<String>, String> {
    match value {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(name)) if !name.trim().is_empty() => Ok(Some(name.clone())),
        Some(_) => Err(format!("{whose} profile must be a non-empty profile name")),
    }
}

/// Read an `offer` argument: absent or `null` is none (the dial's, or
/// delayed), else `"early"` or `"delayed"`.
fn parse_offer(
    whose: &str,
    value: Option<&serde_json::Value>,
) -> Result<Option<crate::dispatcher::DialOffer>, String> {
    match value {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(name)) => crate::dispatcher::DialOffer::parse(name)
            .map(Some)
            .ok_or_else(|| {
                format!("{whose} offer must be \"early\" or \"delayed\", got \"{name}\"")
            }),
        Some(other) => Err(format!(
            "{whose} offer must be \"early\" or \"delayed\", got {other}"
        )),
    }
}

/// A `dial` refused over its `offer` argument, with the typed reason.
fn offer_refusal(message: String, reason: &str) -> ControlResult {
    ControlResult::error_with_details(
        ControlErrorCode::BadRequest,
        message,
        serde_json::json!({ "verb": "dial", "argument": "offer", "reason": reason }),
    )
}

/// Read a `contact_host`: the host siphon presents in its own Contact on the
/// leg, in place of the address it advertises, for a peer that identifies the
/// tenant or account by the host of the Contact.
///
/// Absent or `null` is none. Anything else must be a hostname or an IP
/// address and nothing more, returned as the Contact carries it (an IPv6
/// address bracketed). A value siphon cannot put there is refused before
/// anything is sent rather than dropped: the peer would serve the call as some
/// other tenant's. The error names the argument; the caller says whose it is.
pub(super) fn parse_contact_host(
    object: &serde_json::Map<String, serde_json::Value>,
) -> Result<Option<String>, String> {
    match object.get("contact_host") {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(host)) => {
            crate::dispatcher::checked_contact_host(host).map(Some)
        }
        Some(_) => Err("contact_host must be a string".to_string()),
    }
}

/// Read a `contact_user`: the user part siphon presents in its own Contact on
/// the leg, which is otherwise userless, for a peer that keys the account on
/// the Contact user (`<sip:user@host>`).
///
/// Absent or `null` is none. Anything else must be an RFC 3261 `user` and
/// nothing more; a value siphon cannot put there is refused before anything is
/// sent, as for [`parse_contact_host`]. The error names the argument.
pub(super) fn parse_contact_user(
    object: &serde_json::Map<String, serde_json::Value>,
) -> Result<Option<String>, String> {
    match object.get("contact_user") {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(user)) => {
            crate::dispatcher::checked_contact_user(user).map(Some)
        }
        Some(_) => Err("contact_user must be a string".to_string()),
    }
}

/// Read a target's `route`: the route set its B-leg INVITE carries (RFC 3261
/// §8.1.2, §12.2.1.1), in order, topmost first.
///
/// What a controller acting as a routing B2BUA needs to send a request back
/// where it came from: an IMS application server continues the session through
/// the S-CSCF by copying the Route the S-CSCF gave it, which carries the
/// original dialog identifier (TS 24.229 §5.7.5.2.1 step 4, §5.4.3.4). Route
/// is framework-managed on a B-leg, so it cannot ride `headers`, and a
/// `next_hop` sends the INVITE without the entry that tells the S-CSCF which
/// session it continues.
///
/// Absent or `null` is no route set. Anything else must be an array of
/// strings, each exactly one Route entry in its name-addr form (`<sip:...;lr>`,
/// RFC 3261 §25.1, so a URI's `;lr` cannot be mistaken for a header parameter); a
/// value siphon cannot put on the wire is refused rather than dropped, because
/// a request sent without its route set goes somewhere else entirely.
fn parse_route_set(
    object: &serde_json::Map<String, serde_json::Value>,
) -> Result<Vec<String>, String> {
    let entries = match object.get("route") {
        None | Some(serde_json::Value::Null) => return Ok(Vec::new()),
        Some(serde_json::Value::Array(entries)) => entries,
        Some(_) => return Err("target 'route' must be an array of Route entries".to_string()),
    };
    entries
        .iter()
        .map(|entry| {
            let value = entry
                .as_str()
                .ok_or_else(|| "each target 'route' entry must be a string".to_string())?;
            match crate::sip::headers::route::RouteEntry::parse_multi(value) {
                Ok(parsed) if parsed.len() == 1 => Ok(value.trim().to_string()),
                Ok(_) => Err(format!(
                    "target 'route' entry {value:?} must be exactly one Route entry"
                )),
                Err(error) => Err(format!(
                    "target 'route' entry {value:?} is not a Route entry: {error}"
                )),
            }
        })
        .collect()
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
