//! Building and sending the B-leg INVITE, spawning the leg actor behind it,
//! and classifying the responses that come back.
use crate::dispatcher::*;

/// Send a B-leg INVITE for a B2BUA call.
///
/// `target_uri` drives the new INVITE's R-URI (so the called party's IMPU
/// shape is preserved on the wire).  `next_hop`, when set, is used for the
/// wire destination instead of `target_uri` — IMS edge use-case where the
/// R-URI must carry the canonical home-domain IMPU but the message has to
/// be routed via a fixed next-hop (BGCF, I-CSCF, outbound proxy, …).
#[allow(clippy::too_many_arguments)]
/// Build and send a B-leg INVITE. Returns whether it actually reached the
/// transport.
///
/// **The return value is load-bearing** — every caller has already armed an
/// answer deadline by the time this returns, so a caller that ignores a `false`
/// leaves the A-leg ringing for the full ring timeout on a failure siphon knew
/// about instantly (and, on the LCR path, blames the carrier for a `408` it
/// never saw a packet for). The proxy's own relay answers `502` the moment a
/// target will not resolve; this is the B2BUA half of that.
#[must_use = "an unsent B-leg INVITE must fail the call now, not at the ring timeout"]
#[allow(clippy::too_many_lines)] // TODO(1.9.0 split): decomposed by the dispatcher module split. b2bua_send_b_leg_invite
pub fn b2bua_send_b_leg_invite(
    call_id: &str,
    target_uri: &str,
    next_hop: Option<&str>,
    flow: Option<&crate::script::api::registrar::PyFlow>,
    b_leg_route: &[String],
    send_socket: Option<&crate::transport::SendSocket>,
    // When `Some`, forces the new B-leg's SIP Call-ID (and therefore the
    // MediaSessionStore key for a re-anchor). Used by the REFER-terminate
    // transfer so the fresh survivor↔target anchor is keyed on a Call-ID the
    // caller pre-generated. `None` → the normal preserve/generate logic.
    forced_call_id: Option<&str>,
    original_request: &SipMessage,
    number_policy: Option<&crate::numbers::policy::NumberPolicy>,
    // Retargeted destination number (LCR `destination`), when the call was
    // re-aimed. The To userpart follows it so the dialled-in access number
    // never reaches the carrier. Named apart from the local `destination`
    // (a resolved SocketAddr) further down this function.
    retarget_number: Option<&str>,
    // Injected verbatim onto the B-leg INVITE, last, after both the header
    // policy and the number policy. Callers must not put a dialog-defining
    // header in here — see [`lcr_injectable_headers`], which is where the one
    // caller with externally-supplied headers filters them.
    // Presented CLI for this carrier (LCR `caller_id`), substituted before the
    // number policy reshapes its format.
    caller_id: Option<&str>,
    // Whether the calling identity may be presented to this carrier (LCR
    // `caller_id_presentation`). Applied last, after the number policy.
    caller_id_presentation: Option<crate::sip::privacy::CallerIdPresentation>,
    extra_headers: &[(String, String)],
    state: &DispatcherState,
) -> bool {
    // Shadowed rather than branched so every flow-derived decision below — MTU
    // bias, egress pin, Via sent-by, Contact, leg connection id — treats a
    // Path-routed B-leg as the freshly-resolved leg it now is.
    let flow = b_leg_flow(flow, b_leg_route);

    // RFC 3261 §16.6 step 6: with a route set and no explicit next-hop, the
    // request goes to the topmost Route — not to the Request-URI.  Without this
    // the B-leg carried the Route header but was still *sent* to the target URI,
    // so a `route=` set was decorative: an INVITE for a UE registered through an
    // edge proxy went to the UE's own Contact, which is exactly the address that
    // is unreachable (NAT, IPsec, a userless or `.invalid` contact) and is why
    // the binding has a Path at all.
    let route_next_hop = if next_hop.is_none() && !b_leg_route.is_empty() {
        let mut route_headers = crate::sip::headers::SipHeaders::new();
        route_headers.set("Route", b_leg_route.join(", "));
        core::next_hop_from_route(&route_headers)
    } else {
        None
    };
    // The single URI every destination decision below resolves from — both the
    // initial resolve and the over-MTU TCP re-probe.  One binding on purpose:
    // the two must never disagree about which host this B-leg is going to.
    let routing_uri = b_leg_routing_uri(next_hop, route_next_hop.as_deref(), target_uri);

    // Resolve the wire destination: over the captured inbound flow (RFC 5626
    // §5.3 connection reuse — the only way to reach a WebSocket callee, RFC
    // 7118 §5) when one is attached, else from `routing_uri`.  R-URI
    // construction below still uses target_uri unconditionally — that split is
    // the whole point of next_hop.
    let (mut destination, mut outbound_transport) = if let Some(flow) = flow {
        let transport = match flow.transport.as_str() {
            "udp" => Transport::Udp,
            "tcp" => Transport::Tcp,
            "tls" => Transport::Tls,
            "ws" => Transport::WebSocket,
            "wss" => Transport::WebSocketSecure,
            other => {
                warn!(call_id = %call_id, transport = %other, "B2BUA: unknown flow transport");
                return false;
            }
        };
        (flow.source_addr, transport)
    } else {
        let relay_target = match resolve_target(routing_uri, &state.dns_resolver) {
            Some(t) => t,
            None => {
                warn!(
                    call_id = %call_id,
                    target = %target_uri,
                    next_hop = ?next_hop,
                    route_next_hop = ?route_next_hop,
                    "B2BUA: cannot resolve destination",
                );
                return false;
            }
        };
        (
            relay_target.address,
            relay_target.transport.unwrap_or(Transport::Udp),
        )
    };

    // RFC 3261 §18.1.1 — bias an over-MTU UDP B-leg INVITE to TCP.  Skipped for a
    // flow-pinned B-leg.  The length is measured on the A-leg request as an
    // approximation of the derived B-leg INVITE (header-policy strips/adds mean
    // it is not exact); the decision must precede the Via build below so the
    // Via/txn reflect the chosen transport.  An over-estimate cannot drop the
    // call — the reachability probe in resolve_tcp_path keeps UDP when the peer
    // has no TCP listener; an under-estimate simply leaves a borderline B-leg on
    // UDP (fragmenting, as it would pre-feature).
    // It probes `routing_uri` — the same URI the UDP destination was resolved
    // from, which with a route set is the topmost Route and not the callee's
    // Contact.  Handing it the Contact instead would let resolve_tcp_path's
    // A/AAAA lookup replace the destination with the Contact's own address, so
    // an over-MTU B-leg would bypass the very Path the resolve above followed.
    if state.mtu.is_some() && flow.is_none() {
        if let Some((tcp_transport, tcp_addr)) = mtu_tcp_upgrade(
            state.mtu,
            outbound_transport,
            original_request.to_bytes().len(),
            routing_uri,
            destination,
            &state.dns_resolver,
        ) {
            outbound_transport = tcp_transport;
            destination = tcp_addr;
        }
    }

    // A script send_socket= egress pin applies to the B-leg only when it has no
    // captured flow (a flow already pins egress) and its transport matches the
    // B-leg's outbound transport.  When it applies, the B-leg Via sent-by is the
    // pinned listener's advertised address so the callee's response comes back
    // to that socket.
    let send_socket = match send_socket {
        _ if flow.is_some() => None,
        Some(pin) if pin.transport == outbound_transport => Some(pin),
        Some(pin) => {
            warn!(
                call_id = %call_id,
                send_socket = %pin.addr,
                requested_transport = %pin.transport,
                outbound_transport = %outbound_transport,
                "B2BUA: send_socket transport does not match the B-leg transport — ignoring"
            );
            None
        }
        None => None,
    };

    // The local socket this B-leg is anchored on — `Some` when the script
    // dialled over a captured flow, which is what pins the egress.  The leg
    // keeps it (see `LegTransport::local_addr` below) so every later
    // siphon-originated request on this leg leaves from the same socket.
    let flow_local_addr = flow.map(|f| f.local_addr);

    // Build a new INVITE for the B-leg
    let branch = TransactionKey::generate_branch();
    // The one identity this B-leg advertises — Via sent-by AND Contact.  Both
    // have to name the socket the INVITE actually leaves from, or the far end
    // answers somewhere we are not listening on this flow.
    let (via_host, via_port) = egress_sent_by(
        flow_local_addr,
        send_socket.map(|pin| pin.via_sent_by()),
        || {
            (
                state.via_host(&outbound_transport),
                state.via_port(&outbound_transport),
            )
        },
    );
    let via_value = format!(
        "SIP/2.0/{} {}:{};branch={}",
        outbound_transport, via_host, via_port, branch,
    );

    let mut b_leg_invite = original_request.clone();

    // Framework-auto strips — `Record-Route` and `Route` carry the A-leg
    // dialog routing state, independent of B-leg per RFC 3261 §16.  No
    // preset can opt them in (the dialog model breaks if they cross).
    //
    // `Authorization` (RFC 3261 §22.2, end-to-end) and `Proxy-Authorization`
    // (RFC 3261 §22.3, hop-by-hop) are both policy-managed.  Every built-in
    // preset strips them by default; scripts can opt in via
    // `call.dial(copy=[…])` for transparent-federation / transparent-proxy
    // cases (preset validator rejects combinations that would break
    // the Digest hash).
    b_leg_invite.headers.remove("Record-Route");
    b_leg_invite.headers.remove("Route");

    // Script-supplied Route set (`call.dial(route=[…])`) — the captured IMS
    // Service-Route on MO calls, prepended here *after* the A-leg Route strip so
    // the B-leg traverses the originating S-CSCF (RFC 3608 / TS 24.229).
    if !b_leg_route.is_empty() {
        b_leg_invite.headers.set_all("Route", b_leg_route.to_vec());
    }

    // Replace Via with our own (set preserves header position)
    b_leg_invite.headers.set("Via", via_value);
    // Update Request-URI: use dial target for routing (host/port/transport) but
    // preserve the called party's user part from the A-leg RURI.
    // The dial target is a routing destination, not the called party.
    // If the script dials `sip:specific-user@host`, that user is respected.
    if let Ok(mut target_parsed) = parse_uri_standalone(target_uri) {
        if target_parsed.user.is_none() {
            if let StartLine::Request(ref orig_rl) = original_request.start_line {
                target_parsed.user = orig_rl.request_uri.user.clone();
            }
        }
        b_leg_invite.start_line = StartLine::Request(crate::sip::message::RequestLine {
            method: crate::sip::message::Method::Invite,
            request_uri: target_parsed,
            version: crate::sip::message::Version::sip_2_0(),
        });
    }

    // Generate fresh dialog identifiers for the B-leg (proper B2BUA behavior).
    // Call-ID is new by default unless the script called call.preserve_call_id().
    // From-tag is always unique per B-leg regardless.
    let (
        per_call_override,
        preserve_call_id,
        a_leg_call_id,
        a_leg_from_tag,
        from_host_override,
        to_host_override,
        contact_user_override,
        contact_override,
    ) = match state.call_actors.get_call(call_id) {
        Some(c) => (
            c.session_timer_override.clone(),
            c.preserve_call_id,
            c.a_leg.dialog.call_id.clone(),
            c.a_leg.dialog.remote_tag.clone().unwrap_or_default(),
            c.from_host_override.clone(),
            c.to_host_override.clone(),
            c.contact_user_override.clone(),
            c.contact_override.clone(),
        ),
        None => (
            None,
            false,
            String::new(),
            String::new(),
            None,
            None,
            None,
            None,
        ),
    };

    let b_leg_call_id = if let Some(forced) = forced_call_id {
        forced.to_string()
    } else if preserve_call_id {
        a_leg_call_id
    } else {
        crate::b2bua::actor::generate_call_id()
    };
    let b_leg_from_tag = crate::b2bua::actor::generate_tag();

    // Rewrite Call-ID for B-leg dialog
    b_leg_invite.headers.set("Call-ID", b_leg_call_id.clone());

    // Rewrite From for B-leg dialog:
    //  - Replace the tag with a fresh B-leg tag
    //  - Rewrite the URI host (default: mask A-leg identity with our own host)
    if let Some(from) = b_leg_invite
        .headers
        .get("From")
        .or_else(|| b_leg_invite.headers.get("f"))
    {
        let old_pattern = format!("tag={}", a_leg_from_tag);
        let new_pattern = format!("tag={}", b_leg_from_tag);
        let mut new_from = from.replace(&old_pattern, &new_pattern);

        // Rewrite the host in the From URI.  Default: the B2BUA advertised
        // address (topology hiding — mask A-leg identity).  When the script
        // pinned a host via `call.set_from_host()`, use that instead — opt
        // out of From topology-hiding for multitenant edges that select the
        // tenant from the From domain (a domainless call would otherwise land
        // in the downstream's unauthenticated/default routing context).
        // From header format: ["Display" ]<sip:user@host[:port][;params]>[;tag=...]
        let from_host = from_host_override.unwrap_or_else(|| state.via_host(&outbound_transport));
        if let Some(at_pos) = new_from.find('@') {
            // Find the end of the host: first occurrence of '>', ':', or ';' after '@'
            let after_at = &new_from[at_pos + 1..];
            let host_end = after_at.find(['>', ';', ':']).unwrap_or(after_at.len());
            let end_pos = at_pos + 1 + host_end;
            new_from = format!(
                "{}{}{}",
                &new_from[..at_pos + 1],
                from_host,
                &new_from[end_pos..]
            );
        }

        b_leg_invite.headers.set("From", new_from);
    }

    // Set Contact to siphon's own address so in-dialog requests route through us.
    // via_host()/via_port() apply advertised_address fallback and substitute the
    // sanitized local_addr when the bind is 0.0.0.0/[::] — never leak unspecified.
    //
    // The Contact is userless by default (RFC 3261 §8.1.1.8 puts no identity in
    // the Contact userpart; siphon's own address is all that's needed for the
    // §12.2.1.1 in-dialog remote target). A script may override it:
    //   set_contact_user() → keep our host:port, inject a userpart (safe — we
    //     still receive in-dialog requests, the userpart just rides along, e.g.
    //     for a downstream that keys a tenant/extension off the Contact user);
    //   set_contact_uri()  → replace the whole URI (edge/GRUU deployments that
    //     front siphon — the deployment owns routing the in-dialog target back).
    //
    // On a flow-pinned B-leg the Contact names the flow's own socket, the same
    // sent-by as the Via above: an in-dialog request from the far end has to
    // arrive back on the socket the dialog is anchored on, which for an IPsec SA
    // means a protected port (anything else is outside the SA).  A `send_socket=`
    // pin deliberately does NOT move the Contact — that feature pins egress and
    // the Via so the *response* returns to the chosen listener; the in-dialog
    // remote target stays the advertised address, as it was before flows.
    let (b_contact_host, b_contact_port) =
        b_leg_sent_by(flow_local_addr, state, &outbound_transport);
    let b_contact_value = build_b_leg_contact(
        &b_contact_host,
        b_contact_port,
        outbound_transport,
        contact_user_override.as_deref(),
        contact_override.as_deref(),
    );
    b_leg_invite.headers.set("Contact", b_contact_value.clone());

    // User-Agent rewrite is policy-managed (see `transparent-b2bua@2026`
    // → User-Agent: Rewrite(ReplaceWithUserAgentHeader)).  Topology-hiding
    // presets at trust boundaries do the same.

    // Strip any To-tag (B-leg INVITE should not have one) and rewrite the To URI
    // host to match the dial target (topology hiding — A-leg advertised address
    // must not leak to B-leg).
    if let Some(to) = b_leg_invite
        .headers
        .get("To")
        .or_else(|| b_leg_invite.headers.get("t"))
    {
        let mut new_to = to.clone();
        if let Some(tag_start) = new_to.find(";tag=") {
            new_to = new_to[..tag_start].to_string();
        }
        // Rewrite the To URI host.
        if let Some(ref pinned) = to_host_override {
            // Script pinned a host via `call.set_to_host()`: host only — the
            // original To port and URI params are preserved (documented
            // `set_to_host` contract: `value` is a bare host, no port).
            new_to = crate::b2bua::actor::rewrite_uri_host(&new_to, pinned);
        } else if let Ok(target_parsed) = parse_uri_standalone(target_uri) {
            // Default: topology-hide the To to the dial-target authority.  The
            // original To host+port is siphon's own inbound address (leaked
            // from the A-leg) and is meaningless on the B-leg, so replace host
            // AND port with the target's `host[:port]`.  Replacing host-only
            // here would leave the old `:port` in place and, when the target
            // carries a port, emit a malformed `host:newport:oldport`
            // (RFC 3261 §19.1.1 — a URI carries at most one port), which SBCs
            // reject as `400 Wrong URI`.
            let target_authority = match target_parsed.port {
                Some(port) => format!("{}:{}", target_parsed.host, port),
                None => target_parsed.host.clone(),
            };
            new_to = crate::b2bua::actor::rewrite_uri_authority(&new_to, &target_authority);
        }
        // Unparseable target and no override — leave the To host untouched.

        // A retargeted call must not carry the number it was originally
        // addressed to. RFC 3261 §8.1.1.2 does not require To to track the
        // R-URI, but a To still naming the access number both leaks it and
        // reads as malformed to elements that expect the two to agree.
        //
        // The tech prefix is deliberately NOT applied here: it is a carrier
        // routing artifact that `tech_prefix` documents as belonging to the
        // R-URI, and the called-party identity is not the place for it.
        // `number_policy` still owns To's format on top of this.
        if let Some(retarget) = retarget_number.filter(|value| !value.is_empty()) {
            new_to = rewrite_uri_userpart(&new_to, retarget);
        }

        b_leg_invite.headers.set("To", new_to);
    }

    // Regenerate CSeq for B-leg dialog (independent CSeq space, RFC 3261)
    b_leg_invite.headers.set("CSeq", "1 INVITE".to_string());

    // Decrement Max-Forwards (RFC 7332 — B2BUAs MUST decrement)
    let _ = crate::proxy::core::decrement_max_forwards(&mut b_leg_invite.headers);

    // Apply per-call header policy.  Resolves to the per-call preset (when
    // the script attached one via `call.dial(header_policy=…)`), otherwise
    // the configured `b2bua.default_header_policy` (defaults to
    // `transparent-b2bua@2026`, which reproduces siphon's pre-policy B-leg
    // INVITE construction — Authorization strip + User-Agent/PAI rewrite).
    {
        let policy = state.resolve_header_policy(call_id);
        let ctx = crate::b2bua::header_policy::PolicyContext {
            b2bua_host: &b_contact_host,
            b2bua_port: b_contact_port,
            user_agent_header: state.user_agent_header.as_deref(),
            server_header: state.server_header.as_deref(),
        };
        crate::b2bua::header_policy::apply_to_request(&mut b_leg_invite, &policy, &ctx);
    }

    // Per-carrier (LCR) presented CLI: substitute the calling number before the
    // number policy reshapes its format, through the tag-preserving path so the
    // B-leg's From tag survives. `set_header("From", ...)` cannot do this — the
    // host is rewritten after the script runs, and a From written without a tag
    // drops the mandatory dialog tag (RFC 3261 §8.1.1.3).
    if let Some(caller_id) = caller_id.filter(|value| !value.is_empty()) {
        crate::sip::privacy::set_calling_number(&mut b_leg_invite, caller_id);
    }

    // Per-leg number policy (an LCR route's, or a transfer's): reshape this
    // B-leg's identity headers (From / To / P-Asserted-Identity /
    // P-Preferred-Identity) to the carrier's format. The Request-URI is not
    // walked here: every caller that passes a policy has already shaped its
    // target with it — an LCR route in `b2bua_carrier_ruri`, before the route's
    // `tech_prefix` goes on, and a transfer in `reformat_dial_target`. Walking
    // it again would read a tech prefix as part of the number.
    if let Some(policy) = number_policy {
        crate::script::api::numbers::apply_identity_headers(&mut b_leg_invite, policy);
    }

    // Per-carrier (LCR) CLIR: withhold the calling identity from this carrier
    // (RFC 3323 §4.1 / TS 24.607). Deliberately *after* the number policy —
    // anonymisation is the last identity step, or the policy would try to
    // reshape "anonymous" as a number.
    if caller_id_presentation == Some(crate::sip::privacy::CallerIdPresentation::Restricted) {
        crate::sip::privacy::restrict_calling_identity(&mut b_leg_invite);
    }

    // Inject per-carrier (LCR) headers after the header policy, so a carrier's
    // account token / routing tag always lands on the wire regardless of the
    // policy's strip set.
    for (name, value) in extra_headers {
        b_leg_invite.headers.set(name, value.clone());
    }

    // Inject RFC 4028 session timer headers if configured.
    // Per-call override (from call.session_timer()) takes precedence over global config.
    //
    // REPLACE, never append. This INVITE is a clone of the A-leg's, so whatever
    // the caller asked for is already on it — a Teams INVITE arrives carrying
    // `Session-Expires: 3600` and `Min-SE: 300`. `Session-Expires` and `Min-SE`
    // are single-value headers (RFC 4028 §4, §5), so appending emitted two of
    // each and left the callee to pick: siphon's `Min-SE: 90` next to the
    // caller's `Min-SE: 300` is not a longer list, it is two contradictory
    // floors, and which one the far end honours is undefined. Getting the lower
    // one through negotiates a refresh below the interval the caller demanded.
    let session_timer = per_call_override
        .as_ref()
        .map(|override_config| (override_config.session_expires, override_config.min_se))
        .or_else(|| {
            state
                .session_timer_config
                .as_ref()
                .filter(|timer_config| timer_config.enabled)
                .map(|timer_config| (timer_config.session_expires, timer_config.min_se))
        });
    if let Some((session_expires, min_se)) = session_timer {
        b_leg_invite.headers.set(
            "Session-Expires",
            format!("{session_expires};refresher=uac"),
        );
        b_leg_invite.headers.set("Min-SE", min_se.to_string());
        // `Supported` *is* a list header (RFC 3261 §7.3.1), so a second line is
        // legal — but it is still the same option tag twice on the wire. Merge
        // the tag into what the caller already advertised instead.
        advertise_option_tag(&mut b_leg_invite.headers, "timer");
    }

    // The B-leg is siphon's own UA surface too, so it carries siphon's option
    // tags rather than whatever the A-leg advertised. RFC 5589 §7.3 needs the
    // transfer *target* to advertise `replaces` as well as the transferee, and
    // the callee learns siphon's capability from this INVITE.
    advertise_supported_options(&mut b_leg_invite.headers);

    // Sanitize SDP: mask A-leg identity in o= and s= lines, and rewrite
    // the o= address to our advertised address for topology hiding.
    let sdp_addr = state.via_host(&outbound_transport);
    sanitize_sdp_identity(&mut b_leg_invite.body, &state.sdp_name, Some(&sdp_addr));

    // Update Content-Length after SDP rewrite (o=/s= changes may alter body size)
    if !b_leg_invite.body.is_empty() {
        b_leg_invite
            .headers
            .set("Content-Length", b_leg_invite.body.len().to_string());
    }

    // Register B-leg with call manager (Contact built above; local_contact must
    // match the wire Contact so siphon's own mid-dialog requests advertise the
    // same address the callee will target).
    let mut b_leg = Leg::new_b_leg(
        b_leg_call_id,
        b_leg_from_tag,
        target_uri.to_string(),
        branch.clone(),
        LegTransport {
            remote_addr: destination,
            connection_id: flow
                .map(|f| ConnectionId(f.connection_id))
                .unwrap_or_default(),
            transport: outbound_transport,
            // Anchor the leg on the flow's socket so every later B-leg egress
            // leaves from the same place the INVITE did (the Via/Contact above
            // advertise it, and on an IPsec SA it is the only source address
            // the kernel selector matches).
            local_addr: flow_local_addr,
        },
    );
    b_leg.dialog.local_contact = Some(b_contact_value);
    // Store From/To URIs for mid-dialog requests (BYE, re-INVITE).
    // These must match the dialog-creating INVITE's From/To exactly.
    b_leg.dialog.local_from_uri = b_leg_invite.headers.from().cloned();
    b_leg.dialog.remote_to_uri = b_leg_invite.headers.to().cloned();
    debug!(
        call_id = %call_id,
        b_leg_from = ?b_leg.dialog.local_from_uri,
        b_leg_to = ?b_leg.dialog.remote_to_uri,
        "B2BUA: stored B-leg dialog From/To",
    );
    // Store the B-leg's remote AoR host (from dial target) for in-dialog To headers.
    // In-dialog To uses the original AoR, NOT the remote Contact (which is for RURI).
    if let Ok(target_parsed) = parse_uri_standalone(target_uri) {
        b_leg.dialog.remote_aor_host = Some(if let Some(port) = target_parsed.port {
            format!("{}:{}", target_parsed.host, port)
        } else {
            target_parsed.host.clone()
        });
    }
    // Stamp siphon's owned o= identity for this new B-leg (RFC 3264 §8): this is
    // the first SDP siphon emits toward the callee, so it fixes the leg's stable
    // session-id at version 0; the stored leg starts at version 1 for the next
    // emit. Keeps the o= address = siphon's advertised address (as the sanitize
    // above does) for topology hiding. Empty body → no-op.
    if !b_leg_invite.body.is_empty() {
        stamp_sdp_origin(
            &mut b_leg_invite.body,
            &state.sdp_name,
            b_leg.dialog.sdp_session_id,
            b_leg.dialog.sdp_version,
            Some(&sdp_addr),
        );
        b_leg.dialog.sdp_version += 1;
        b_leg_invite
            .headers
            .set("Content-Length", b_leg_invite.body.len().to_string());
    }
    // `media.sdp_strip_attributes`, last: after the script's media engine offer
    // and the o=/s= rewrite above. The copy stashed on the leg below is this
    // message, and the 401/407 retry is rebuilt from that stash, so the retry
    // carries the stripped SDP too.
    strip_relayed_sdp_attributes(&mut b_leg_invite, state);
    // A call that ended while this INVITE was being built — a CANCEL or the ring
    // timeout landing during destination resolution — has nothing left to dial
    // for. Sending anyway rang the callee for a call nobody was on, with no
    // CANCEL ever coming.
    if !state.call_actors.add_b_leg(call_id, b_leg.clone()) {
        debug!(
            call_id = %call_id,
            "B2BUA: the call ended before its B-leg INVITE went out — not sending it"
        );
        return false;
    }
    spawn_b_leg_actor(call_id, &b_leg, state);

    let data = Bytes::from(b_leg_invite.to_bytes());

    // `b2bua.log_dial` — report the outbound leg at info, from the send itself.
    // Deliberately here and not in `call.dial()`: that binding only records a
    // `CallAction` the dispatcher executes after the handler returns, so a line
    // written there (by siphon or by the script) precedes the dial and still
    // claims it when the destination fails to resolve — the paths above this
    // one that `warn!` and return. By this point routing, the header policy,
    // the number policy and the LCR tech-prefix / retarget / CLIR steps have
    // all run, so the R-URI logged is the one on the wire rather than the
    // string the script passed, and `b_leg_call_id` is what the far end quotes
    // back. Every B-leg INVITE funnels through here — dial, each fork branch,
    // each LCR carrier attempt, a REFER-terminate re-dial.
    if state.log_dial {
        let ruri = match &b_leg_invite.start_line {
            StartLine::Request(request_line) => request_line.request_uri.to_string(),
            StartLine::Response(_) => String::new(),
        };
        info!(
            call_id = %call_id,
            b_leg_call_id = %b_leg.dialog.call_id,
            ruri = %ruri,
            next_hop = ?next_hop,
            destination = %destination,
            transport = %outbound_transport,
            source = ?flow.map(|flow| flow.local_addr).or(send_socket.map(|pin| pin.addr)),
            "B2BUA: dialling B-leg",
        );
    }

    // Send: over the captured flow (direct OutboundMessage, bypassing DNS/pool —
    // mirrors the proxy relay(flow=...) path) when one is attached, else via the
    // resolver/pool path.
    //
    // Either way the INVITE gets an RFC 3261 §17.1.1.2 Timer A schedule first
    // (UDP only). Without it this INVITE left the socket exactly once: one lost
    // datagram — the first packet after an idle gap, or one dropped across an
    // IPsec re-key — meant total silence until the 30 s answer timeout
    // synthesised a 408, with the next call seconds later succeeding.
    arm_b2bua_retransmit(
        &b_leg_invite,
        &data,
        outbound_transport,
        destination,
        client_retransmit_source(outbound_transport, destination, flow, send_socket),
        state,
    );

    if let Some(flow) = flow {
        // This branch bypasses `send_to_target`/`send_outbound_from`, so it has
        // to do their HEP capture itself — otherwise a flow-pinned B-leg INVITE
        // is the one request that never reaches Homer.
        if let Some(ref hep) = state.hep_sender {
            hep.capture_outbound(
                state.hep_local_addr(flow.local_addr, outbound_transport),
                destination,
                outbound_transport,
                &data,
            );
        }
        // ...and log the send. Nothing on this path logged before, so an absent
        // "sending message" line was never evidence the INVITE had not been
        // handed to the transport — it simply was never logged.
        debug!(
            call_id = %call_id,
            destination = %destination,
            source = %flow.local_addr,
            transport = %outbound_transport,
            size = data.len(),
            "B2BUA: sending B-leg INVITE over captured flow"
        );
        let outbound_message = OutboundMessage {
            followups: None,
            connection_id: ConnectionId(flow.connection_id),
            transport: outbound_transport,
            destination,
            data,
            source_local_addr: Some(flow.local_addr),
            server_name: None,
        };
        if let Err(error) = state.outbound.send(outbound_message) {
            error!(call_id = %call_id, destination = %destination, transport = %outbound_transport, "B2BUA: flow send failed: {error}");
            // The leg is registered and its actor spawned by this point, but the
            // INVITE is not on the wire and nothing will ever answer it. Report
            // the failure so the caller fails the call now instead of leaving it
            // to the ring timeout; the leg goes with the call's teardown.
            return false;
        }
    } else {
        let relay_target = RelayTarget {
            address: destination,
            transport: Some(outbound_transport),
            server_name: None,
        };
        send_to_target(
            data,
            &relay_target,
            outbound_transport,
            ConnectionId::default(),
            send_socket.map(|pin| pin.addr),
            state,
        );
    }

    // Persist the fully hygiene-processed B-leg INVITE on the leg.
    // The 401/407 auto-retry path rebuilds the retry from this — rebuilding
    // from the A-leg INVITE would leak A-leg headers (Record-Route, Route,
    // Authorization), the original Call-ID/CSeq/From-host, and the un-anchored
    // SDP back to the B-leg. Increment B-leg local CSeq after sending the
    // initial INVITE (CSeq 1 is now used); subsequent requests (re-INVITE,
    // BYE, 401/407 retry) use CSeq >= 2.
    //
    // Also CANCEL this INVITE right away when it is owed one (RFC 3261 §9.1 —
    // a CANCEL copies the INVITE's Via branch and CSeq, so it can only be built
    // once the INVITE is on the wire and its hygiene-processed form stashed):
    //  * a CANCEL was deferred onto the leg while the INVITE was being built —
    //    the caller's CANCEL, or a sibling fork branch answering; or
    //  * the call is gone — torn down between the send above and here — so no
    //    CANCEL path can still reach the leg at all.
    // The leg is found by its branch rather than taken as the last one, since
    // another leg (a fork sibling, a re-INVITE tracker) can be added meanwhile.
    let stored_invite = Arc::new(Mutex::new(b_leg_invite));
    let cancel_now: Option<Leg> = match state.call_actors.get_call_mut(call_id) {
        Some(mut call) => call
            .find_b_leg_by_branch_mut(&branch)
            .and_then(|(_, stashed)| {
                stashed.dialog.local_cseq += 1;
                stashed.b_leg_invite = Some(stored_invite.clone());
                if stashed.pending_cancel {
                    stashed.pending_cancel = false;
                    Some(stashed.clone())
                } else {
                    None
                }
            }),
        None => {
            let mut orphan = b_leg.clone();
            orphan.dialog.local_cseq += 1;
            orphan.b_leg_invite = Some(stored_invite.clone());
            Some(orphan)
        }
    };

    if let Some(leg) = cancel_now {
        let cancel = stored_invite
            .lock()
            .ok()
            .and_then(|invite| build_cancel_from_invite(&invite));
        match cancel {
            Some(cancel_msg) => {
                debug!(
                    call_id = %call_id,
                    branch = %leg.branch,
                    "B2BUA: CANCELling a B-leg INVITE as soon as it is stashed"
                );
                // Kept answerable first, so the 487 this draws is ACKed and a 2xx
                // crossing it is ACKed and BYEd even though the call may be gone.
                state.call_actors.keep_answerable(std::iter::once(&leg));
                // Same egress socket as the INVITE it cancels — RFC 3261 §9.1
                // puts the CANCEL on the INVITE's own hop, and on a flow-pinned
                // leg that hop is the flow's socket.
                send_b2bua_to_bleg(
                    cancel_msg,
                    leg.transport.transport,
                    leg.transport.remote_addr,
                    flow_local_addr,
                    state,
                );
                schedule_zombie_cancelled_expiry(state.call_actors.clone(), vec![leg.branch]);
            }
            None => warn!(
                call_id = %call_id,
                "B2BUA: cannot build the CANCEL a B-leg INVITE is owed from its stored copy — it rings until it answers or times out"
            ),
        }
    }

    true
}

/// Apply 401/407 digest-retry edits to a previously sent B-leg INVITE.
///
/// Clones `original` and returns a copy with:
///   - `Via` replaced (carries the new client-transaction branch).
///   - `CSeq` bumped to `cseq` (RFC 3261 §22.2 — retry uses an incremented
///     sequence number within the same dialog).
///   - Both `Authorization` and `Proxy-Authorization` removed, then
///     `auth_header` (one of those two) added with `auth_value`.
///
/// Every other header — `Contact`, `Call-ID`, `From`, `To`, the Request-URI,
/// `User-Agent`, `P-Asserted-Identity`, the absence of `Record-Route`/`Route`,
/// and the (possibly rtpengine-anchored) SDP body — is preserved verbatim
/// from the prior B-leg INVITE. This is the core fix for the 401/407 retry
/// leak: the prior INVITE was already fully hygiene-processed by
/// [`b2bua_send_b_leg_invite`], so we must not rebuild from the raw A-leg
/// INVITE.
pub fn build_digest_retry_invite(
    original: &SipMessage,
    new_via: String,
    cseq: u32,
    auth_header: &str,
    auth_value: String,
) -> SipMessage {
    let mut retry = original.clone();
    retry.headers.set("Via", new_via);
    retry.headers.set("CSeq", format!("{cseq} INVITE"));
    retry.headers.remove("Authorization");
    retry.headers.remove("Proxy-Authorization");
    retry.headers.add(auth_header, auth_value);
    retry
}

/// Spawn a [`LegActor`] for a B-leg and store its handle in the call.
///
/// The actor classifies inbound SIP messages into [`CallEvent`]s.
/// Call this after `add_b_leg` — uses the last B-leg index.
pub fn spawn_b_leg_actor(call_id: &str, b_leg: &Leg, state: &DispatcherState) {
    if let Some(call) = state.call_actors.get_call(call_id) {
        if let Some(event_tx) = &call.event_tx {
            let (actor, handle) = LegActor::new(b_leg.clone(), event_tx.clone());
            let b_leg_index = call.b_legs.len().saturating_sub(1);
            drop(call);
            tokio::spawn(actor.run());
            if let Some(mut call) = state.call_actors.get_call_mut(call_id) {
                call.set_b_leg_handle(b_leg_index, handle);
            }
        }
    }
}

/// Spawn a [`LegActor`] for a B-leg whose slot is at an explicit `index`.
///
/// Like [`spawn_b_leg_actor`] but stores the handle at `index` rather than the
/// last B-leg. Used by the 401/407 and 422 retry paths, which *supersede* the
/// failed leg in place (via `CallActorStore::replace_b_leg`) instead of
/// appending — so the retry's actor handle must land on the same slot the
/// retry leg occupies.
pub fn spawn_b_leg_actor_at(call_id: &str, b_leg: &Leg, index: usize, state: &DispatcherState) {
    if let Some(call) = state.call_actors.get_call(call_id) {
        if let Some(event_tx) = &call.event_tx {
            let (actor, handle) = LegActor::new(b_leg.clone(), event_tx.clone());
            drop(call);
            tokio::spawn(actor.run());
            if let Some(mut call) = state.call_actors.get_call_mut(call_id) {
                call.set_b_leg_handle(index, handle);
            }
        }
    }
}

/// Receive the next B-leg response classification from the shared per-call
/// event channel, discarding stale `CallEvent::Terminated` notifications.
///
/// Every [`LegActor`] emits `CallEvent::Terminated` as it falls out of its run
/// loop. A 401/407/422 outbound retry supersedes the failed B-leg in place
/// (`CallActorStore::replace_b_leg`), which drops the old leg's actor handle;
/// that actor then exits and pushes a `Terminated` onto the SHARED per-call
/// channel — the very channel the dispatcher block-recvs for each response's
/// classification.
///
/// `Terminated` is a lifecycle notification, never a response classification,
/// and nothing else consumes this channel. Taking one here as though it
/// classified the response just handed to the live actor desyncs the stream by
/// one: the next 200 OK then reads the previous 18x's `Provisional` event, so
/// the 2xx is misclassified as provisional — `set_winner` and the deferred
/// B-leg ACK are skipped, the trunk's 200 OK is never ACKed, and it retransmits
/// until the dialog collapses (BYE storm ~5 s after answer). Filtering
/// `Terminated` out restores the strict one-response/one-classification
/// invariant the caller relies on.
///
/// The caller block-recvs only after a successful `try_send` of the response to
/// the live actor, so exactly one non-`Terminated` classification event is
/// always forthcoming and this loop terminates.
/// How a B-leg response drives the B2BUA: an answer, a ringing indication, or a
/// failure.
#[derive(Debug, PartialEq, Eq)]
pub enum ResponseClass {
    Answered,
    Provisional,
    Failed,
}

/// Classify a B-leg response from its status code. `None` means "absorb" — a
/// `100 Trying` is hop-by-hop and drives nothing here.
///
/// Deliberately a pure function of the status line. This used to be decided by
/// the leg actor's `CallEvent`, which is delivered on a per-call channel shared
/// by every leg and is not guaranteed to describe the response being handled;
/// a 2xx read as its predecessor's `Provisional` skips `set_winner` and the
/// deferred B-leg ACK, so the callee's 200 is never ACKed and it retransmits
/// until the dialog collapses.
pub fn classify_b_leg_response(status_code: u16) -> Option<ResponseClass> {
    if (200..300).contains(&status_code) {
        Some(ResponseClass::Answered)
    } else if (180..200).contains(&status_code) {
        Some(ResponseClass::Provisional)
    } else if status_code >= 300 {
        Some(ResponseClass::Failed)
    } else {
        None
    }
}

pub fn recv_b_leg_classification_event(
    rx: &mut tokio::sync::mpsc::Receiver<CallEvent>,
) -> Option<CallEvent> {
    loop {
        match rx.blocking_recv() {
            Some(CallEvent::Terminated { .. }) => continue,
            other => return other,
        }
    }
}
