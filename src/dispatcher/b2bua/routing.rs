//! Choosing where a B-leg goes, and what to try next when it fails.
//!
//! Gateway groups, the LCR route sequence, and the serial failover that
//! advances through carriers on reject or timeout. Each attempt is a fresh
//! B-leg dialog — reusing the Call-ID is the serial-fork footgun.

use crate::dispatcher::*;

/// Resolve a gateway group to a healthy member's next-hop URI (LCR carrier
/// pools). `None` when the group is unknown or entirely down — the caller skips
/// that carrier. The transport is baked into the URI so a TLS/TCP carrier pool
/// routes over the right protocol even if the configured URI omitted it.
pub fn b2bua_resolve_gateway_member(group: &str) -> Option<String> {
    let manager = crate::script::api::gateway_manager()?;
    let destination = manager.select(group, None, None)?;
    let uri = destination.uri.clone();
    if destination.transport == crate::transport::Transport::Udp
        || uri.to_ascii_lowercase().contains("transport=")
    {
        Some(uri)
    } else {
        Some(format!(
            "{uri};transport={}",
            destination.transport.to_string().to_ascii_lowercase()
        ))
    }
}

/// Whether a carrier's failure `status` should trigger LCR failover to the next
/// carrier, per the effective reroute-cause set for the carrier currently in
/// flight: the active route's own set (from the API) > its gateway group's
/// override (`gateway.groups[].reroute_causes`) > the global set
/// (`lcr.reroute_causes`, else the built-in default). Some carriers don't play
/// nice with the standard codes, hence the per-gateway / per-route overrides.
pub fn b2bua_status_reroutes(call_id: &str, status: u16, state: &DispatcherState) -> bool {
    if let Some(route) = state.call_actors.active_route(call_id) {
        if !route.reroute_causes.is_empty() {
            return route.reroute_causes.contains(&status);
        }
        if let Some(group) = route.gateway_group.as_deref() {
            if let Some(manager) = crate::script::api::gateway_manager() {
                let group_causes = manager.group_reroute_causes(group);
                if !group_causes.is_empty() {
                    return group_causes.contains(&status);
                }
            }
        }
    }
    crate::lcr::global_reroute_contains(status)
}

/// The per-route `headers` from an LCR answer that may be injected onto the
/// B-leg INVITE, with the dialog-defining headers filtered out.
///
/// The answer comes from an external routing backend, and the injection runs
/// last — after the header policy and the number policy — so an unfiltered
/// `From` in a route's `headers` overwrote the B-leg From *including its tag*.
/// That doesn't fail visibly: the INVITE goes out, and the damage surfaces
/// later as ACKs and BYEs that no longer match the dialog. `To`, `Call-ID`,
/// `CSeq`, `Via` and `Contact` are exposed the same way.
///
/// The names filtered here are exactly
/// [`crate::b2bua::header_policy::is_framework_auto`] — the set no header
/// policy is allowed to touch either, for the same reason. `Proxy-Authorization`
/// is deliberately *not* in that set and stays injectable, since a per-carrier
/// trunk credential is a legitimate use of this field.
///
/// A refused header is logged at warn naming the carrier and the header, so a
/// backend sending one finds out rather than debugging dropped mid-dialog
/// requests.
pub fn lcr_injectable_headers(route: &crate::lcr::Route, call_id: &str) -> Vec<(String, String)> {
    route
        .headers
        .iter()
        .filter(|(name, _)| {
            if crate::b2bua::header_policy::is_framework_auto(name) {
                warn!(
                    call_id = %call_id,
                    carrier = %route.carrier_id,
                    header = %name,
                    "LCR: refusing to inject a dialog header from a route, ignoring it",
                );
                return false;
            }
            true
        })
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect()
}

/// The inbound flow an INVITE arrived on, for `call.flow`.
///
/// Built straight off the transport frame, so the connection id is the accepted
/// socket the INVITE came in on — which is what makes `call.flow ==
/// contact.flow` an RFC 5626 connection-reuse test on a stream transport rather
/// than an address comparison.
pub fn py_flow_from_inbound(
    inbound: &crate::transport::InboundMessage,
) -> Option<crate::script::api::registrar::PyFlow> {
    Some(crate::script::api::registrar::PyFlow {
        transport: format!("{}", inbound.transport).to_ascii_lowercase(),
        source_addr: inbound.remote_addr,
        local_addr: inbound.local_addr,
        connection_id: inbound.connection_id.0,
    })
}

/// The same flow, recovered from a leg's stored transport binding for the
/// handlers that run after the INVITE frame is gone (`on_answer`, `on_bye`,
/// `on_failure`, `on_cancel`, `on_refer`).
///
/// `local_addr` is only recorded for A-legs, so this yields `None` for a B-leg
/// — which is correct: `call.flow` describes how the caller reached siphon, and
/// a B-leg has no inbound flow to describe.
pub fn py_flow_from_leg(
    transport: &crate::b2bua::actor::TransportInfo,
) -> Option<crate::script::api::registrar::PyFlow> {
    Some(crate::script::api::registrar::PyFlow {
        transport: format!("{}", transport.transport).to_ascii_lowercase(),
        source_addr: transport.remote_addr,
        local_addr: transport.local_addr?,
        connection_id: transport.connection_id.0,
    })
}

/// Build the B-leg R-URI for a carrier route: base is the route's `ruri` (else
/// the A-leg R-URI), with the carrier's tech-prefix prepended to the userpart.
/// For a bare dialed-number route (no `ruri`) dialed via a carrier next-hop, the
/// R-URI host is pointed at the carrier so it sees itself as the target.
pub fn b2bua_carrier_ruri(
    route: &crate::lcr::Route,
    a_leg_ruri: &str,
    next_hop: Option<&str>,
) -> String {
    let base = route.ruri.as_deref().unwrap_or(a_leg_ruri);
    // Per-route destination beats the answer-level one; either replaces the
    // dialled number before anything else touches the R-URI.
    // The answer-level default was already resolved onto each route by
    // `LcrResponse::resolved_routes`, so per-route is the only level here.
    let destination = route
        .destination
        .as_deref()
        .map(lcr_destination_userpart)
        .filter(|value| !value.is_empty());

    let mut uri = match parse_uri_standalone(base) {
        Ok(uri) => uri,
        Err(_) => {
            // Unparseable base — best-effort string prefix so neither the
            // retarget nor the prefix is silently dropped.
            let base = match destination.as_deref() {
                Some(destination) => destination,
                None => base,
            };
            return match route.tech_prefix.as_deref().filter(|p| !p.is_empty()) {
                Some(prefix) => format!("{prefix}{base}"),
                None => base.to_string(),
            };
        }
    };

    // Retarget first (RFC 3261 §16.5), so tech_prefix prepends to the *new*
    // number and gateway-group selection is untouched — the whole point of
    // having this alongside `ruri`, which replaces the host too and so bypasses
    // member selection and health checking.
    if let Some(destination) = destination {
        uri.user = Some(destination);
    }

    if let Some(prefix) = route.tech_prefix.as_deref().filter(|p| !p.is_empty()) {
        let user = uri.user.clone().unwrap_or_default();
        uri.user = Some(format!("{prefix}{user}"));
    }
    if route.ruri.is_none() {
        if let Some(next_hop_uri) = next_hop.and_then(|nh| parse_uri_standalone(nh).ok()) {
            uri.host = next_hop_uri.host;
            uri.port = next_hop_uri.port;
        }
    }
    uri.to_string()
}

/// Replace the userpart of the URI inside a `name-addr` (or of a bare URI),
/// leaving the display name, the host, the port, every URI parameter and every
/// header parameter alone.
///
/// Used to align a retargeted call's To with its new destination. Returns the
/// input unchanged when it cannot be parsed, so a header siphon does not
/// understand is never corrupted.
pub fn rewrite_uri_userpart(value: &str, user: &str) -> String {
    match crate::sip::headers::nameaddr::NameAddr::parse(value) {
        Ok(mut entry) => {
            entry.uri.user = Some(user.to_string());
            entry.to_string()
        }
        Err(_) => value.to_string(),
    }
}

/// The number out of an LCR `destination`, which may be given as a bare number
/// (`"+12025550123"`) or as a full URI whose userpart is the number
/// (`"sip:+12025550123@carrier.net"`).
///
/// Only the userpart is ever taken: the host is siphon's to decide, from the
/// gateway group or the next-hop, so that a retarget can never route the call
/// somewhere the operator did not configure.
pub fn lcr_destination_userpart(destination: &str) -> String {
    match parse_uri_standalone(destination) {
        Ok(uri) => uri.user.unwrap_or_else(|| destination.to_string()),
        Err(_) => destination.to_string(),
    }
}

/// Dial the next routable carrier in a call's sequential-failover queue (LCR
/// `call.route(...)` or `fork(strategy="sequential")`).
///
/// Pops carriers off the pending queue until one resolves — a `gateway_group`
/// to a healthy member (skipping a group that is entirely down), an explicit
/// `next_hop`, or an `ruri` — then sends its B-leg INVITE (a **fresh** dialog:
/// `b2bua_send_b_leg_invite` mints a new Call-ID/From-tag/CSeq) and arms the
/// per-attempt answer deadline. Returns `true` if a carrier was dialed, `false`
/// once the queue is exhausted. `original_request` is the stored A-leg INVITE
/// (its R-URI is the default dial target when a route omits its own `ruri`);
/// the caller passes the locked message so this never re-locks it.
/// Outcome of one [`b2bua_advance_route`] pass.
pub struct RouteAdvance {
    /// Whether a carrier's INVITE actually reached the transport.
    pub dialed: bool,
    /// Carriers this pass burned **without dialling** — an unroutable one
    /// (gateway group unknown or entirely down, no explicit next-hop) or one
    /// whose INVITE could not be sent. Each is already on the call's attempt
    /// list; the caller fires `@b2bua.on_route_failure` for them.
    ///
    /// Returned rather than dispatched here because the hook re-locks the A-leg
    /// INVITE that every caller of this function is holding a guard on — the
    /// same reason the reject and ring-timeout paths already fire it *before*
    /// taking that guard. Firing it inline would deadlock the dispatcher.
    pub burned: Vec<(crate::lcr::Route, u16)>,
}

impl RouteAdvance {
    /// No carrier dialled and nothing burned — the queue was already empty, or
    /// the A-leg INVITE could not be locked.
    pub fn none() -> Self {
        Self {
            dialed: false,
            burned: Vec::new(),
        }
    }
}

/// Status recorded against a carrier the sequence burned without dialling it.
///
/// `503` is what the A-leg already receives when no carrier at all is routable
/// (`503 No Route`), so an exhausted sequence hands the caller the same code
/// however it got there. The attempt's `dialed: false` is what says the carrier
/// never answered this — it is siphon's verdict on the route.
pub const LCR_UNDIALED_STATUS: u16 = 503;

pub fn b2bua_advance_route(
    call_id: &str,
    original_request: &SipMessage,
    state: &DispatcherState,
) -> RouteAdvance {
    let send_socket_str = state.call_actors.route_send_socket(call_id);
    let send_socket = state.resolve_send_socket(send_socket_str.as_deref());
    let a_leg_ruri = match &original_request.start_line {
        StartLine::Request(request_line) => request_line.request_uri.to_string(),
        _ => String::new(),
    };
    let mut burned: Vec<(crate::lcr::Route, u16)> = Vec::new();
    loop {
        let route = match state.call_actors.take_next_route(call_id) {
            Some(route) => route,
            None => {
                return RouteAdvance {
                    dialed: false,
                    burned,
                }
            }
        };
        // Prefer a healthy gateway-group member; fall back to an explicit
        // next-hop. Warn (not silent) when the API named a group that siphon
        // doesn't know or that's entirely down, so a misconfig is visible; the
        // route is still usable if it carries an explicit next_hop / ruri.
        let group_member = route
            .gateway_group
            .as_deref()
            .and_then(b2bua_resolve_gateway_member);
        if route.gateway_group.is_some() && group_member.is_none() {
            warn!(
                call_id = %call_id,
                carrier = %route.carrier_id,
                group = route.gateway_group.as_deref().unwrap_or_default(),
                "LCR: gateway group unknown or all members down — falling back to next_hop / skipping carrier",
            );
        }
        let next_hop = group_member.or_else(|| route.next_hop.clone());
        if next_hop.is_none() && route.ruri.is_none() {
            debug!(
                call_id = %call_id,
                carrier = %route.carrier_id,
                "LCR: carrier unroutable (group unknown/down, no next-hop), skipping",
            );
            // Burned, so it belongs on the attempt list: the sequence consumed
            // this carrier and the call took the consequence. Skipping it
            // silently left `route_attempts` unable to name every carrier the
            // call went through, which is the one thing that list is for.
            b2bua_record_undialed_carrier(call_id, &route, &mut burned, state);
            continue;
        }
        let target = b2bua_carrier_ruri(&route, &a_leg_ruri, next_hop.as_deref());
        // The same value b2bua_carrier_ruri put in the R-URI userpart, so the
        // To can be aligned with it. Resolved here rather than re-derived from
        // the target, which by then carries the tech prefix too.
        let retarget = route
            .destination
            .as_deref()
            .map(lcr_destination_userpart)
            .filter(|value| !value.is_empty());
        let extra_headers = lcr_injectable_headers(&route, call_id);
        let timeout = route.timeout_secs.unwrap_or(30);
        // An unparseable presentation must not silently become "allowed": a
        // withheld call going out with the caller's real number is the failure
        // that matters here, so refuse the value loudly and present nothing
        // rather than guess.
        let caller_id_presentation = match route.caller_id_presentation.as_deref() {
            None => None,
            Some(value) => match crate::sip::privacy::CallerIdPresentation::parse(value) {
                Some(parsed) => Some(parsed),
                None => {
                    warn!(
                        call_id = %call_id,
                        carrier = %route.carrier_id,
                        caller_id_presentation = %value,
                        "LCR: unknown caller_id_presentation, treating the call as restricted",
                    );
                    Some(crate::sip::privacy::CallerIdPresentation::Restricted)
                }
            },
        };
        debug!(
            call_id = %call_id,
            carrier = %route.carrier_id,
            target = %target,
            next_hop = ?next_hop,
            "LCR: dialing carrier",
        );
        // The carrier's identity format, resolved here rather than inside the
        // send path: that path now takes a policy, not a name, so the two
        // callers that shape a B-leg (this one and the leg replacement) cannot
        // disagree about how a selector turns into a policy.
        let carrier_number_policy = match route.number_policy.as_deref() {
            None => None,
            Some(name) => match crate::script::api::numbers::resolve_dial_policy(Some(name)) {
                Ok(policy) => policy,
                Err(_) => {
                    warn!(
                        call_id = %call_id,
                        carrier = %route.carrier_id,
                        policy = %name,
                        "LCR: unknown number_policy on route, skipping identity reshape"
                    );
                    None
                }
            },
        };
        let sent = b2bua_send_b_leg_invite(
            call_id,
            &target,
            next_hop.as_deref(),
            None,
            &[],
            send_socket.as_ref(),
            None,
            original_request,
            carrier_number_policy.as_deref(),
            retarget.as_deref(),
            route.caller_id.as_deref(),
            caller_id_presentation,
            &extra_headers,
            state,
        );
        if !sent {
            // The INVITE never left the box (unresolvable destination, dead
            // egress). Arming the answer deadline here would sit on the caller
            // for this carrier's whole ring timeout and then charge the carrier
            // a 408 for a packet it never received. Burn it and take the next
            // one now — the failure is already known.
            b2bua_record_undialed_carrier(call_id, &route, &mut burned, state);
            continue;
        }
        set_b2bua_answer_deadline(call_id, timeout, state);
        return RouteAdvance {
            dialed: true,
            burned,
        };
    }
}

/// Record a carrier burned without ever being dialled, and queue it for the
/// `@b2bua.on_route_failure` notification its caller will fire.
///
/// Both halves matter: the attempt list is what `call.route_attempts`, the CDR's
/// `lcr_attempts` and the hook all read, and the commitment is that the three
/// never disagree about which carriers a sequence went through.
pub fn b2bua_record_undialed_carrier(
    call_id: &str,
    route: &crate::lcr::Route,
    burned: &mut Vec<(crate::lcr::Route, u16)>,
    state: &DispatcherState,
) {
    if let Some(attempt) = state
        .call_actors
        .record_route_undialed(call_id, LCR_UNDIALED_STATUS)
    {
        info!(
            call_id = %call_id,
            carrier = %attempt.carrier_id,
            status = attempt.status,
            "LCR: carrier burned without dialling — advancing immediately (the carrier never saw this call)"
        );
    }
    burned.push((route.clone(), LCR_UNDIALED_STATUS));
}

/// Fire `@b2bua.on_route_failure` for every carrier a [`RouteAdvance`] burned.
///
/// **Call this only once the A-leg INVITE guard is released** — the handler
/// re-locks it (see [`RouteAdvance::burned`]).
pub fn b2bua_dispatch_burned_routes(
    call_id: &str,
    burned: &[(crate::lcr::Route, u16)],
    state: &DispatcherState,
) {
    if burned.is_empty() {
        return;
    }
    let Some((a_leg, a_leg_invite)) = state
        .call_actors
        .get_call(call_id)
        .map(|call| (call.a_leg.clone(), call.a_leg_invite.clone()))
    else {
        return;
    };
    for (route, status) in burned {
        b2bua_dispatch_route_failure(
            call_id,
            route,
            *status,
            &a_leg,
            a_leg_invite.as_ref(),
            state,
        );
    }
}
