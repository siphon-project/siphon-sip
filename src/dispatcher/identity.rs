//! Who siphon says it is on the wire.
//!
//! Via sent-by, Record-Route URIs, the advertised host, and the Supported /
//! Allow sets. Getting these wrong is not a cosmetic bug: a Record-Route that
//! names a port no IPsec SA covers means nothing in-dialog can reach the UE,
//! and a Via that no self-identity recognises turns the dialog's own requests
//! into 482 Loop Detected.

use super::*;

/// Set `Allow` (RFC 3261 §20.5) to the methods siphon supports, but only when the
/// header is absent — never overwrite a caller/script-set `Allow`. Used on
/// siphon's own UA surfaces (OPTIONS 2xx responses, B2BUA responses) so a peer can
/// discover the supported method set, including REFER/NOTIFY for transfer.
pub(super) fn advertise_supported_methods(headers: &mut SipHeaders) {
    if !headers.has("Allow") {
        headers.set("Allow", crate::sip::SUPPORTED_METHODS.to_string());
    }
}

/// Advertise the SIP extensions siphon implements as a UA, in `Supported`
/// (RFC 3261 §20.37). The counterpart to [`advertise_supported_methods`]:
/// `Allow` says which methods a peer may send, `Supported` says which
/// extensions it may use inside them.
///
/// `replaces` (RFC 3891) is the load-bearing one, and it is not optional:
/// §6.2 is "UAs which support the Replaces header MUST include the 'replaces'
/// option tag in a Supported header field". It is also how a transferor picks
/// between an attended transfer and a blind one — RFC 5589 §7.3 has the
/// Transferor learn that the Transferee supports Replaces "from the
/// `Supported: replaces` header contained in the 200 OK responses from both".
/// Withhold the tag and a transferor that gates on it downgrades a
/// consultative transfer to a REFER carrying no `Replaces`; siphon then dials
/// the target as an unrelated new call and nothing ever replaces the
/// transferor's consultation dialog, which is left up on the transferor's
/// screen while the transfer itself appears to have worked. That is the same
/// failure mode, and the same vendor, as the `Allow` advertisement above.
///
/// Advertising is a statement about the header, not a promise to honour every
/// takeover: an inbound `INVITE` with `Replaces` still runs the
/// `b2bua.accept_replaces` gate and is declined `603` when the operator has not
/// authorised takeovers (RFC 3891 §3's own answer for a dialog a UA is
/// unwilling to replace). The half that needs no authorisation — siphon as the
/// transferee, turning a REFER's `Replaces` into the INVITE it sends the
/// target — is unconditional, and that is the half this tag unblocks.
pub(super) fn advertise_supported_options(headers: &mut SipHeaders) {
    advertise_option_tag(headers, "replaces");
}

/// Option tags siphon implements on a B-leg but claims there only when the
/// caller offered them — the rule both have always followed.
///
/// `100rel`: siphon PRACKs a callee's reliable provisional itself (RFC 3262), so
/// the claim is true, and tying it to the caller's offer keeps a callee from
/// switching to reliable provisionals on calls whose caller never asked for
/// them. `timer`: siphon relays session refreshes and can run the timer itself
/// (RFC 4028), and every built-in preset still copies the caller's
/// `Session-Expires`; without the tag the callee has to take the refresh on
/// itself (§9). When siphon runs the session timer, the B-leg builder adds
/// `timer` whatever the caller offered.
const CALLER_OFFERED_OPTION_TAGS: &[&str] = &["100rel", "timer"];

/// Settle the B-leg INVITE's `Supported` and `Allow` once the header policy has
/// run.
///
/// siphon is the UAC of the B-leg, so both are siphon's own claims (RFC 3261
/// §20.37, §20.5), not the caller's to relay. `outbound` is the B-leg INVITE
/// after the policy, `script` the A-leg INVITE the script shaped, and
/// `script_shaped_headers` the headers the script set or removed.
///
/// - `Supported`: of the caller's tags the policy left on the request, the ones
///   siphon claims on the caller's offer ([`CALLER_OFFERED_OPTION_TAGS`]) and
///   the ones the policy passes end to end
///   ([`ResolvedPolicy::end_to_end_option_tags`](crate::b2bua::header_policy::ResolvedPolicy::end_to_end_option_tags)).
///   The tags siphon claims unconditionally — `replaces`, and `timer` when it
///   runs the session timer — are merged at the end of the build, after the
///   per-carrier headers, as they always were.
/// - `Allow`: siphon's method set, the one its responses advertise.
///
/// A header the script set or removed is the script's value as written: script
/// headers are policy precedence 1, above the per-call deltas and the preset.
/// It is read back from `script` because the policy may have stripped it from
/// `outbound` already.
pub(super) fn advertise_b_leg_capabilities(
    outbound: &mut SipHeaders,
    script: &SipHeaders,
    script_shaped_headers: &[String],
    policy: &crate::b2bua::header_policy::ResolvedPolicy,
) {
    let shaped_by_script = |name: &str| {
        script_shaped_headers
            .iter()
            .any(|shaped| crate::sip::headers::same_header_name(shaped, name))
    };

    if shaped_by_script("Supported") {
        restore_script_header(outbound, script, "Supported");
    } else {
        let end_to_end = policy.end_to_end_option_tags();
        let offered: Vec<String> = outbound
            .get_all("Supported")
            .map(|values| {
                values
                    .iter()
                    .flat_map(|value| value.split(','))
                    .map(|tag| tag.trim().to_string())
                    .filter(|tag| !tag.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        outbound.remove("Supported");
        for tag in offered {
            if CALLER_OFFERED_OPTION_TAGS
                .iter()
                .chain(end_to_end)
                .any(|claimed| claimed.eq_ignore_ascii_case(&tag))
            {
                advertise_option_tag(outbound, &tag);
            }
        }
    }

    if shaped_by_script("Allow") {
        restore_script_header(outbound, script, "Allow");
    } else {
        outbound.remove("Allow");
        advertise_supported_methods(outbound);
    }
}

/// Put `name` on `outbound` exactly as the script left it on `script`: every
/// line it has, or none at all.
fn restore_script_header(outbound: &mut SipHeaders, script: &SipHeaders, name: &str) {
    match script.get_all(name) {
        Some(values) => outbound.set_all(name, values.clone()),
        None => outbound.remove(name),
    }
}

/// Turn a 2xx OPTIONS into a proper capability response (RFC 3261 §11.2): add a
/// `Contact` at the advertised sent-by and advertise the supported methods via
/// `Allow`. Both are added only when absent, so a script-set `Contact`/`Allow`
/// wins. `via_host`/`via_port` are the advertised sent-by for the transport the
/// OPTIONS arrived on; some peers (Microsoft Teams Direct Routing) reject an
/// OPTIONS answer that carries neither `Contact` nor `Record-Route`.
pub(super) fn augment_options_response(
    response: &mut SipMessage,
    via_host: &str,
    via_port: u16,
    transport: Transport,
) {
    if !response.headers.has("Contact") {
        response.headers.set(
            "Contact",
            format!(
                "<sip:{}:{};transport={}>",
                via_host,
                via_port,
                transport.to_string().to_lowercase()
            ),
        );
    }
    advertise_supported_methods(&mut response.headers);
}

/// The response siphon sends when no `@proxy.on_request` handler claims the
/// method — see the call site in [`handle_request`] for why this is two answers
/// and not one.
///
/// `OPTIONS` is answered `200` with `Contact` + `Allow` (RFC 3261 §11.2), so a
/// registrar qualifying its bindings gets a real capability response without
/// every deployment writing the same handler. Every other method is answered
/// `405 Method Not Allowed` with `Allow` (RFC 3261 §8.2.1), which is both true
/// and actionable where the previous `500` was neither.
///
/// `None` means send nothing at all, and only an OPTIONS can produce it: an
/// operator who sets `server.auto_options: false` is saying siphon must not
/// answer for a script that did not ask it to, and the honest form of that is
/// silence rather than a different status code — the same reasoning behind the
/// scripting API's silent drop, which exists so a probe gets no confirmation
/// that anything is listening. The 405 is not opt-out-able: a method siphon
/// genuinely will not handle owes the sender that answer.
///
/// `via_host` / `via_port` / `transport` describe the socket the request
/// arrived on, and are only read for the OPTIONS `Contact`.
pub(super) fn build_no_handler_response(
    request: &SipMessage,
    method: &str,
    auto_options: bool,
    server_header: Option<&str>,
    via_host: &str,
    via_port: u16,
    transport: Transport,
) -> Option<SipMessage> {
    if method == "OPTIONS" {
        if !auto_options {
            return None;
        }
        let mut response = build_response(request, 200, "OK", server_header, &[]);
        augment_options_response(&mut response, via_host, via_port, transport);
        Some(response)
    } else {
        let mut response = build_response(request, 405, "Method Not Allowed", server_header, &[]);
        advertise_supported_methods(&mut response.headers);
        Some(response)
    }
}

/// The port siphon advertises to the A-leg (Contact) and anchors the A-leg
/// dialog on: the listener the INVITE actually arrived on when known
/// (`a_leg_local_addr`), else the default per-transport listener port
/// (`default_via_port`).
///
/// On a multi-homed host the two differ — an INVITE to `:5066` while the first
/// configured listener is `:5060`. Advertising the default there sends every
/// in-dialog request to a port the dialog isn't anchored on (over UDP it splits
/// traffic; over a stream transport RFC 5923 connection reuse masks it). On a
/// single-listener host the arrival port equals `default_via_port`, so this is
/// a no-op — which is why passing `None` (arrival socket unknown) is safe.
pub(super) fn a_leg_advertised_port(
    a_leg_local_addr: Option<SocketAddr>,
    default_via_port: u16,
) -> u16 {
    a_leg_local_addr
        .map(|addr| addr.port())
        .unwrap_or(default_via_port)
}

/// The sent-by (host, port) siphon advertises in the `Via` and `Contact` of
/// every request it originates toward a B-leg.
///
/// `b_leg_local_addr` is [`LegTransport::local_addr`], which is `Some` only for
/// a leg dialled over a captured flow (`call.dial(flow=…)`).  A flow pins the
/// leg to exactly one local socket, and the sent-by has to name *that* socket —
/// not the default per-transport listener — because the far end answers to the
/// sent-by and the response must come back over the same flow.  On an IPsec
/// sec-agree leg that is the whole ballgame (3GPP TS 33.203 §7.4): a soft-UE's
/// MO INVITE leaves the protected client port, so a `Via` naming the plain
/// listener asks the P-CSCF to answer on a port outside the SA, where nothing
/// is listening on the SA and the response is lost — the call then gets no
/// answer at all and times out.  Same invariant the proxy `relay(flow=…)` path
/// enforces in [`relay_request`].
///
/// The socket's own IP is used rather than the advertised host for the same
/// reason: an advertised NAT address or FQDN does not identify the flow the
/// response has to return over.  Unpinned legs (`None` — every non-flow B-leg)
/// fall back to the per-transport advertised identity, byte-for-byte what
/// siphon has always emitted.
pub(super) fn b_leg_sent_by(
    b_leg_local_addr: Option<SocketAddr>,
    state: &DispatcherState,
    transport: &Transport,
) -> (String, u16) {
    match b_leg_local_addr {
        Some(local) => pinned_sent_by(local, || state.via_host(transport)),
        None => (state.via_host(transport), state.via_port(transport)),
    }
}

/// The sent-by naming a socket a leg is pinned to.
///
/// Pure half of [`b_leg_sent_by`], split out so the invariant that actually
/// matters — *advertise the socket you send from* — is unit-testable without a
/// `DispatcherState` fixture.
///
/// The **port** is the whole point of a pin and is always the socket's own. The
/// **host** is the socket's own only when it is concrete: `listen: 0.0.0.0:5060`
/// is the ordinary production shape, and `InboundMessage::local_addr` carries
/// the bind address, so a captured flow on such a listener would otherwise put
/// `0.0.0.0` in a Via — an address no peer can answer to and that no
/// self-identity recognises, which turns the dialog's own in-dialog requests
/// into `482 Loop Detected` on arrival. On a wildcard socket the host falls back
/// to the advertised identity for that transport, keeping the pinned port.
pub(super) fn pinned_sent_by(
    local: SocketAddr,
    advertised_host: impl FnOnce() -> String,
) -> (String, u16) {
    if local.ip().is_unspecified() {
        return (advertised_host(), local.port());
    }
    // Bracket a v6 literal — a raw `ip().to_string()` would emit a malformed
    // unbracketed `SIP/2.0/UDP 2001:db8::10:6100` sent-by.
    (format_sip_host(&local.ip().to_string()), local.port())
}

/// The `Record-Route` entries a record-routing relay stamps — one per **socket**
/// the dialog crosses, returned in the order the caller adds them.
///
/// The discriminator is the socket, not the transport. A proxy that bridges two
/// listeners of the *same* transport crosses two sockets just as surely as one
/// bridging TLS↔TCP, and the peer on each side has to be told the socket facing
/// *it*: RFC 3261 §12.1.1 gives the UAS the Record-Route list in order, §12.1.2
/// gives the UAC the reverse, so a single entry can only ever be right for one
/// of them. The shape that made this urgent is a P-CSCF bridging its protected
/// Gm port to its core port over UDP — keying on transport alone saw one socket,
/// stamped the egress port, and handed every UE a route set pointing at a port
/// with no IPsec SA covering it, so no in-dialog request it ever sent could
/// leave the handset (3GPP TS 33.203 §6.3).
///
/// `inbound_host` is a closure because the single-socket case — every ordinary
/// single-listener proxy, on every relayed request — does not need it, and
/// resolving it costs a listener-registry lookup plus a `String`.
///
/// Returns `(added_first, added_second)`. [`core::add_record_route`] prepends,
/// so the *second* entry ends up topmost, which is what the downstream peer
/// reads as its next hop.
///
/// Known limitation, unchanged from the transport-keyed version it replaces: two
/// listeners sharing a transport and port but bound to different IPs still get
/// one entry (the outbound host). Separating them needs the inbound host
/// resolved on every relay, and that address shape has not shown up in the
/// field the way the port one has.
pub(super) fn record_route_uris(
    inbound_transport: Transport,
    inbound_port: u16,
    inbound_host: impl FnOnce() -> String,
    outbound_transport: Transport,
    outbound_port: u16,
    outbound_host: &str,
) -> (String, Option<String>) {
    let outbound = record_route_uri(outbound_host, outbound_port, outbound_transport);
    if inbound_transport == outbound_transport && inbound_port == outbound_port {
        return (outbound, None);
    }
    let inbound = record_route_uri(&inbound_host(), inbound_port, inbound_transport);
    (inbound, Some(outbound))
}

/// One `Record-Route` URI. `host` is already SIP-formatted (a v6 literal
/// arrives bracketed from [`pinned_sent_by`] / [`resolve_advertised_host`]).
pub(super) fn record_route_uri(host: &str, port: u16, transport: Transport) -> String {
    format!(
        "sip:{}:{};transport={}",
        host,
        port,
        transport.label().to_ascii_lowercase()
    )
}

/// Sent-by for a request siphon is about to send out — a B2BUA B-leg INVITE or
/// a proxy fork branch — by egress-pin precedence:
///
/// 1. **The captured flow's socket.** A flow pins the egress absolutely — the
///    request is written to that socket — so nothing may override it. This is
///    also why a `send_socket=` pin is dropped upstream for a flow-dialled leg.
/// 2. **The script's `send_socket=` listener**, when it applies.
/// 3. **The per-transport advertised identity** (`fallback`) — every ordinary
///    egress, byte-for-byte unchanged. Taken lazily so the pinned paths don't
///    pay for the lookup.
///
/// Pure so the precedence — the part the flow-egress bug got wrong, by using
/// `fallback` even when a flow was attached — is testable without a
/// `DispatcherState` fixture.
///
/// A flow on a wildcard-bound listener keeps its port but borrows `fallback`'s
/// host; see [`pinned_sent_by`] for why `0.0.0.0` in a sent-by is fatal.
pub(super) fn egress_sent_by(
    flow_local_addr: Option<SocketAddr>,
    send_socket_sent_by: Option<(String, u16)>,
    fallback: impl FnOnce() -> (String, u16),
) -> (String, u16) {
    match (flow_local_addr, send_socket_sent_by) {
        (Some(local), _) => pinned_sent_by(local, || fallback().0),
        (None, Some((host, port))) => (format_sip_host(&host), port),
        (None, None) => fallback(),
    }
}

/// The sent-by (host, port) for a request siphon originates on `leg` — BYE,
/// PRACK, refresh re-INVITE.
///
/// Picked by side, because the two sides anchor for different reasons:
///
/// - **A-leg** — [`LegTransport::local_addr`] is the socket the call *arrived*
///   on, so the identity is the advertised one for that socket (a NAT/topology
///   -hiding deployment depends on the peer seeing the advertised host, not the
///   bind IP), with the arrival port for multi-homed source-port parity.
/// - **B-leg** — `local_addr` is set only by a captured flow, which pins the leg
///   to one socket the response has to return over; see [`b_leg_sent_by`].
pub(super) fn leg_sent_by(
    leg: &crate::b2bua::actor::Leg,
    state: &DispatcherState,
) -> (String, u16) {
    let transport = &leg.transport.transport;
    match leg.side {
        crate::b2bua::actor::LegSide::B => {
            b_leg_sent_by(leg.transport.local_addr, state, transport)
        }
        crate::b2bua::actor::LegSide::A => (
            state.a_leg_advertised_host(leg.transport.local_addr, transport),
            a_leg_advertised_port(leg.transport.local_addr, state.via_port(transport)),
        ),
    }
}

/// Build the Route self-identity (RFC 3261 §16.4) from every source that can
/// end up stamped into a Record-Route or Path.
///
/// This deliberately walks `listener_registry` rather than `listen_addrs` /
/// `advertised_addrs`: those two are `entry().or_insert()` maps and so keep only
/// the **first listener per transport** (see `is_own_address`, which already
/// consults the registry for exactly this reason).  A dual-stack P-CSCF's IPv6
/// listener is not the first UDP entry, so a set built from the collapsed maps
/// misses the host it stamps toward every v6 UE — the in-dialog request then
/// fails to match and the 404 this whole mechanism exists to prevent comes back.
///
/// Every case in [`resolve_advertised_host`] has to be represented here, since
/// that function is what produces `via_host`:
///   1. per-listener `advertise`             → registry entries
///   2. transport-level advertised host      → `advertised_addrs`
///   3. the concrete bound IP                → registry entries
///   4. wildcard fallbacks                   → routable local IP, then loopback
///
/// Ports come from the listeners we actually bind, plus the IPsec protected
/// ports (`pcscf_port_c`/`pcscf_port_s`), which a P-CSCF stamps in place of the
/// listen port.  Anything host-only (`domain.local`, `ipsec.path_host`) is added
/// as an any-port alias.
pub(super) fn build_self_identity(
    domain_local: &[String],
    ipsec_ports: Option<(u16, u16)>,
    path_host: Option<&str>,
    listener_registry: &crate::transport::ListenerRegistry,
    advertised_addrs: &std::collections::HashMap<Transport, String>,
    listen_addrs: &std::collections::HashMap<Transport, SocketAddr>,
    via_addr: SocketAddr,
) -> core::SelfIdentity {
    let mut identity = core::SelfIdentity::new();

    // The ports we answer on. A Route at one of our hosts but on a port outside
    // this set belongs to a different proxy co-located on the same address.
    let mut ports: Vec<u16> = Vec::new();
    let add_port = |ports: &mut Vec<u16>, port: u16| {
        if port != 0 && !ports.contains(&port) {
            ports.push(port);
        }
    };
    for (_, addr, _) in listener_registry.entries() {
        add_port(&mut ports, addr.port());
    }
    for addr in listen_addrs.values() {
        add_port(&mut ports, addr.port());
    }
    add_port(&mut ports, via_addr.port());
    if let Some((port_c, port_s)) = ipsec_ports {
        // TS 33.203 §7.1: the protected ports a P-CSCF Record-Routes with.
        add_port(&mut ports, port_c);
        add_port(&mut ports, port_s);
    }

    // 1 + 3: every configured listener — its advertise name and its bound IP.
    for (_, addr, advertise) in listener_registry.entries() {
        if let Some(ref advertise) = advertise {
            identity.add_host(advertise, &ports);
        }
        if !addr.ip().is_unspecified() {
            identity.add_host(&addr.ip().to_string(), &ports);
        }
    }

    // 2: transport-level advertised hosts (global `advertised_address` and any
    //    per-transport `advertise`), which step 2 hands to same-family sockets.
    for host in advertised_addrs.values() {
        identity.add_host(host, &ports);
    }

    // The resolved via address, and the raw bind IP the double-Record-Route
    // branch falls back to as `internal_host`.
    if !via_addr.ip().is_unspecified() {
        identity.add_host(&via_addr.ip().to_string(), &ports);
    }

    // 4: the wildcard-bind fallbacks. Reached only when a listener is bound to
    //    0.0.0.0 / [::] with no advertise, but then it is what we stamp.
    let wildcard_bound = listener_registry
        .entries()
        .iter()
        .any(|(_, addr, _)| addr.ip().is_unspecified())
        || via_addr.ip().is_unspecified();
    if wildcard_bound {
        for ipv6 in [false, true] {
            if let Some(ip) = cached_routable_local_ip(ipv6) {
                identity.add_host(&ip.to_string(), &ports);
            }
        }
        identity.add_host(&std::net::Ipv4Addr::LOCALHOST.to_string(), &ports);
        identity.add_host(&std::net::Ipv6Addr::LOCALHOST.to_string(), &ports);
    }

    // Operator-declared aliases — no port information, so any port matches.
    // `domain.local` stays purely a served-domain list; including it here only
    // preserves the deployments that worked around the old behaviour by adding
    // their own address to it.
    for domain in domain_local {
        identity.add_alias(domain);
    }
    // `add_pcscf_path` stamps `ipsec.path_host` into Path; it returns as the top
    // Route on MT requests, where the documented flow is loose_route() +
    // consumed_route_user (RFC 3327 §5 / TS 24.229 §5.2.7.2).
    if let Some(path_host) = path_host {
        identity.add_alias(path_host);
    }

    identity
}

/// Resolve the family-matched host to advertise to the A-leg, given the socket
/// the request arrived on.  Backing logic for
/// [`DispatcherState::a_leg_advertised_host`], factored out as a free function
/// so it is unit-testable without a `DispatcherState` fixture.
///
/// With `a_leg_local_addr = Some(addr)` the resolution, most-specific first:
///
/// 1. the per-listener `advertise` configured for that exact socket;
/// 2. a transport-level advertised host of the **same family** (preserves the
///    global `advertised_address` / NAT case, but never hands a v4 literal to a
///    v6 UE or vice-versa; an FQDN is family-agnostic and always accepted);
/// 3. the exact bound IP, when concrete (explicit per-family listener);
/// 4. a wildcard bind → a family-matched listener's advertise/bound IP, else a
///    routable local IP of that family, else that family's loopback.
///
/// `None` reproduces the legacy per-transport `via_host` (first advertised host,
/// else the resolved `default_local_ip`).
pub(super) fn resolve_advertised_host(
    registry: &crate::transport::ListenerRegistry,
    advertised_addrs: &std::collections::HashMap<Transport, String>,
    default_local_ip: IpAddr,
    a_leg_local_addr: Option<SocketAddr>,
    transport: &Transport,
) -> String {
    let Some(addr) = a_leg_local_addr else {
        return advertised_addrs
            .get(transport)
            .map(|host| format_sip_host(host))
            .unwrap_or_else(|| format_sip_host(&default_local_ip.to_string()));
    };
    let ipv6 = addr.is_ipv6();

    // 1. Per-listener advertise for this exact socket.
    if let Some(advertise) = registry.resolve(*transport, addr).and_then(|s| s.advertise) {
        return format_sip_host(&advertise);
    }

    // 2. A transport-level advertised host of the same family (or an FQDN).
    //    Strip any v6 brackets before parsing so a bracketed literal
    //    (`[2001:db8::1]`) is still classified as an IP, not an FQDN.
    if let Some(host) = advertised_addrs.get(transport) {
        let family_ok = match strip_ipv6_brackets(host).parse::<IpAddr>() {
            Ok(ip) => ip.is_ipv6() == ipv6,
            Err(_) => true, // FQDN — resolves to whichever family the UE needs.
        };
        if family_ok {
            return format_sip_host(host);
        }
    }

    // 3. The exact bound IP, when concrete.
    if !addr.ip().is_unspecified() {
        return format_sip_host(&addr.ip().to_string());
    }

    // 4. Wildcard bind → family-matched fallback.
    if let Some(send) = registry.resolve_family(*transport, ipv6) {
        if let Some(advertise) = send.advertise {
            return format_sip_host(&advertise);
        }
        if !send.addr.ip().is_unspecified() {
            return format_sip_host(&send.addr.ip().to_string());
        }
    }
    if let Some(ip) = cached_routable_local_ip(ipv6) {
        return format_sip_host(&ip.to_string());
    }
    let loopback = if ipv6 {
        IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
    } else {
        IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
    };
    format_sip_host(&loopback.to_string())
}

/// Process-lifetime cache of [`crate::transport::detect_routable_local_ip`] per
/// family.  Only the wildcard-bind, no-advertise fallback of
/// [`resolve_advertised_host`] reaches the probe, but that path can be
/// per-message, and the probe does a socket create + `connect` + `getsockname`.
/// The routable local IP doesn't change at runtime, so memoise it.
pub(super) fn cached_routable_local_ip(ipv6: bool) -> Option<IpAddr> {
    static V4: std::sync::OnceLock<Option<IpAddr>> = std::sync::OnceLock::new();
    static V6: std::sync::OnceLock<Option<IpAddr>> = std::sync::OnceLock::new();
    let cache = if ipv6 { &V6 } else { &V4 };
    *cache.get_or_init(|| crate::transport::detect_routable_local_ip(ipv6))
}

/// Every host siphon writes into its own Via, Contact and Record-Route for a TLS
/// or WSS listener, as `(transport, listener, host)`, sorted by transport and
/// then listener.
///
/// Two derivations feed those headers, so both are reported, and both go
/// through [`resolve_advertised_host`] rather than a copy of it:
///
/// - **The listener's own host**, resolved with that socket: the Contact on a
///   B2BUA response to a peer that reached siphon there
///   ([`sanitize_b2bua_response`]), and the inbound Record-Route of a relay
///   that bridges two sockets.
/// - **The transport's default host**, resolved with no socket, which is what
///   [`DispatcherState::via_host`] returns: the Via sent-by, the outbound
///   Record-Route and an unpinned B-leg Contact. It is reported against the
///   transport's first configured listener (`listen_addrs`), whose port those
///   headers carry, and only when it differs from that listener's own host.
///
/// The two part ways on a multi-homed host with nothing advertised, where the
/// default falls back to the first listener of any transport. On a wildcard
/// bind with nothing advertised both come out as the auto-detected routable IP,
/// else loopback. Path never comes from here: `add_path` takes the script's URI
/// and `add_pcscf_path` stamps `ipsec.path_host`.
pub(super) fn secure_listener_advertised_hosts(
    registry: &crate::transport::ListenerRegistry,
    advertised_addrs: &std::collections::HashMap<Transport, String>,
    listen_addrs: &std::collections::HashMap<Transport, SocketAddr>,
    default_local_ip: IpAddr,
) -> Vec<(Transport, SocketAddr, String)> {
    let mut listeners: Vec<(Transport, SocketAddr)> = registry
        .entries()
        .into_iter()
        .filter(|(transport, _, _)| {
            matches!(transport, Transport::Tls | Transport::WebSocketSecure)
        })
        .map(|(transport, address, _)| (transport, address))
        .collect();
    // The registry is a HashMap; sort so the warnings come out in a stable order.
    listeners.sort_by_key(|(transport, address)| (transport.label(), *address));

    let mut hosts = Vec::new();
    for (transport, listener) in listeners {
        let own = resolve_advertised_host(
            registry,
            advertised_addrs,
            default_local_ip,
            Some(listener),
            &transport,
        );
        let transport_default = (listen_addrs.get(&transport) == Some(&listener))
            .then(|| {
                resolve_advertised_host(
                    registry,
                    advertised_addrs,
                    default_local_ip,
                    None,
                    &transport,
                )
            })
            .filter(|host| *host != own);
        hosts.push((transport, listener, own));
        if let Some(host) = transport_default {
            hosts.push((transport, listener, host));
        }
    }
    hosts
}

/// Warn, once at startup, for every TLS and WSS listener that advertises an IP
/// literal its certificate cannot be validated against.
///
/// A peer that opens a new TLS connection to siphon, to send the ACK or a later
/// in-dialog request once the original connection is gone or not reused, dials
/// a host from [`secure_listener_advertised_hosts`] and validates the
/// certificate against it. Certificates name DNS names, so an IP there fails
/// the handshake, and nothing shows on siphon's side: the request never
/// arrives. That silence is why this is a warning and not only a line in the
/// docs.
///
/// Checked against `tls.certificate` alone, read once; see
/// [`crate::transport::tls::certificate_ip_addresses`] for why the SNI pairs do
/// not count. A certificate that cannot be read still warns, and says the check
/// was not possible.
pub(super) fn warn_secure_listeners_advertising_ip_literals(
    certificate_path: &str,
    registry: &crate::transport::ListenerRegistry,
    advertised_addrs: &std::collections::HashMap<Transport, String>,
    listen_addrs: &std::collections::HashMap<Transport, SocketAddr>,
    default_local_ip: IpAddr,
) {
    let hosts = secure_listener_advertised_hosts(
        registry,
        advertised_addrs,
        listen_addrs,
        default_local_ip,
    );
    if hosts.is_empty() {
        return;
    }
    let certificate_ip_addresses =
        crate::transport::tls::certificate_ip_addresses(certificate_path)
            .map_err(|error| error.to_string());

    for (transport, listener, host) in hosts {
        let Some((ip, problem)) = crate::transport::tls::advertised_ip_problem(
            transport,
            &host,
            certificate_ip_addresses.as_deref().map_err(String::as_str),
        ) else {
            continue;
        };
        let listen_key = if transport == Transport::WebSocketSecure {
            "listen.wss"
        } else {
            "listen.tls"
        };
        match problem {
            crate::transport::tls::AdvertisedIpProblem::NotInCertificate => warn!(
                transport = %transport,
                listener = %listener,
                advertised = %ip,
                certificate = %certificate_path,
                "{listen_key} listener advertises an IP literal in its Contact/Record-Route/Via \
                 and tls.certificate has no iPAddress subjectAltName for it. A peer that opens a \
                 new TLS connection to that address (to send the ACK or a later in-dialog \
                 request when the original connection is gone or not reused) fails certificate \
                 validation and never sends the request. Set `advertise:` on this listener to a \
                 DNS name the certificate carries."
            ),
            crate::transport::tls::AdvertisedIpProblem::CertificateUnreadable(error) => warn!(
                transport = %transport,
                listener = %listener,
                advertised = %ip,
                certificate = %certificate_path,
                error = %error,
                "{listen_key} listener advertises an IP literal in its Contact/Record-Route/Via \
                 and tls.certificate could not be read, so the SAN check for a matching \
                 iPAddress subjectAltName was not possible. Unless the certificate carries that \
                 IP, a peer that opens a new TLS connection to that address (to send the ACK or \
                 a later in-dialog request when the original connection is gone or not reused) \
                 fails certificate validation and never sends the request. Set `advertise:` on \
                 this listener to a DNS name the certificate carries."
            ),
        }
    }
}
