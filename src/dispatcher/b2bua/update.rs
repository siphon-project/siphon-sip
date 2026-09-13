//! An inbound UPDATE on a bridged call (RFC 3311).
use crate::dispatcher::*;

/// Bridge an in-dialog UPDATE (RFC 3311) across the B2BUA.
///
/// Mirrors `handle_b2bua_reinvite` minus the INVITE-specific bits:
///   * no 491 glare gate — RFC 3311 §5.2 explicitly permits UPDATE before
///     the initial INVITE is ACKed, and §5.1 places no analogue of RFC 3261
///     §14.1's pending-offer rule on UPDATE
///   * no ACK on 2xx — RFC 3311 §5.4: UPDATE is a normal non-INVITE
///     transaction; the 2xx ACK rule applies to INVITE only
///   * SDP / RTPEngine path is conditional on a non-empty body — empty-body
///     UPDATEs (RFC 4028 session-timer refresh — the common case) bridge
///     headers only
///
/// Tracking uses the `update:` / `update_done:` target_uri prefixes so that
/// concurrent re-INVITE and UPDATE on the same dialog don't collide on a
/// single B-leg slot.
#[allow(clippy::too_many_lines)] // TODO(1.9.0 split): decomposed by the dispatcher module split. handle_b2bua_update
pub fn handle_b2bua_update(inbound: InboundMessage, message: SipMessage, state: &DispatcherState) {
    let sip_call_id = message
        .headers
        .get("Call-ID")
        .map(|s| s.to_string())
        .unwrap_or_default();

    let call_id = match state.call_actors.find_by_sip_call_id(&sip_call_id) {
        Some(id) => id,
        None => {
            // Raced a concurrent teardown. 481 like the no-dialog-leg arm below
            // (RFC 3311 UPDATE, answered per RFC 3261 §12.2.2).
            warn!(sip_call_id = %sip_call_id, "B2BUA UPDATE: no matching call — 481");
            let response = build_response(
                &message,
                481,
                "Call/Transaction Does Not Exist",
                state.server_header.as_deref(),
                &[],
            );
            send_message_from(
                response,
                inbound.transport,
                inbound.remote_addr,
                inbound.connection_id,
                Some(inbound.local_addr),
                state,
            );
            return;
        }
    };

    // In-dialog direction by dialog identity (RFC 3261 §12 — Call-ID + From-tag),
    // never by source socket (RFC 3311 UPDATE; same reconnect/NAT hazard as the
    // re-INVITE path). A Call-ID matching no live dialog leg is answered 481.
    let from_tag = message.typed_from().ok().flatten().and_then(|na| na.tag);
    let from_a_leg = match state
        .call_actors
        .get_call(&call_id)
        .and_then(|call| call.request_direction(&sip_call_id, from_tag.as_deref()))
    {
        Some(crate::b2bua::actor::LegSide::A) => true,
        Some(crate::b2bua::actor::LegSide::B) => false,
        None => {
            warn!(sip_call_id = %sip_call_id, "B2BUA UPDATE: Call-ID matches no dialog leg — 481");
            let response = build_response(
                &message,
                481,
                "Call/Transaction Does Not Exist",
                state.server_header.as_deref(),
                &[],
            );
            send_message_from(
                response,
                inbound.transport,
                inbound.remote_addr,
                inbound.connection_id,
                Some(inbound.local_addr),
                state,
            );
            return;
        }
    };

    // Track the offerer's own new endpoint SDP (its UPDATE offer, raw) so a
    // later siphon-terminated transfer offers this leg's current media if it is
    // the survivor.
    if !message.body.is_empty() {
        state
            .call_actors
            .set_leg_last_sdp(&call_id, from_a_leg, &message.body);
    }

    // Flow refresh (RFC 5626 / RFC 3261 §12.2.2): re-anchor the originating leg
    // on the arrival flow so the UPDATE 200 OK and later in-dialog requests reach
    // the live connection. Done before the snapshot so the clones carry it.
    let refreshed_contact = message
        .headers
        .get("Contact")
        .or_else(|| message.headers.get("m"))
        .map(|value| crate::b2bua::actor::extract_contact_uri(value));
    if let Some(mut call) = state.call_actors.get_call_mut(&call_id) {
        let winner_index = call.winner;
        let origin_leg: Option<&mut Leg> = if from_a_leg {
            Some(&mut call.a_leg)
        } else if let Some(index) = winner_index {
            call.b_legs.get_mut(index)
        } else {
            None
        };
        if let Some(leg) = origin_leg {
            if leg.transport.remote_addr != inbound.remote_addr
                || leg.transport.connection_id != inbound.connection_id
            {
                leg.transport.remote_addr = inbound.remote_addr;
                leg.transport.connection_id = inbound.connection_id;
                leg.transport.local_addr = Some(inbound.local_addr);
            }
            if let Some(ref contact) = refreshed_contact {
                leg.dialog.remote_contact = Some(contact.clone());
            }
        }
    }

    // Snapshot routing info + per-leg contacts AFTER the flow refresh.
    let (a_leg, winner_b_leg) = match state.call_actors.get_call(&call_id) {
        Some(call) => {
            let b_leg = call.winner.and_then(|i| call.b_legs.get(i).cloned());
            (call.a_leg.clone(), b_leg)
        }
        None => return,
    };

    let (target_remote_contact, target_local_contact) = if from_a_leg {
        winner_b_leg
            .as_ref()
            .map(|b| {
                (
                    b.dialog.remote_contact.clone(),
                    b.dialog.local_contact.clone(),
                )
            })
            .unwrap_or((None, None))
    } else {
        (
            a_leg.dialog.remote_contact.clone(),
            a_leg.dialog.local_contact.clone(),
        )
    };

    // A call with no second leg: siphon is the far party, so the UPDATE is
    // answered here rather than forwarded. Before this the no-B-leg arm below
    // returned after the `100 Trying` and sent no final response at all, so the
    // originator's non-INVITE transaction ran to Timer F — and a session-timer
    // refresh sent as an UPDATE (RFC 4028 §10) that is never answered ends the
    // call when the refresher gives up.
    if from_a_leg && winner_b_leg.is_none() {
        crate::dispatcher::b2bua::answer_one_legged_reoffer(
            &inbound, &message, &call_id, &a_leg, "UPDATE", state,
        );
        return;
    }

    debug!(
        call_id = %call_id,
        from_a_leg = from_a_leg,
        has_body = !message.body.is_empty(),
        "B2BUA: forwarding UPDATE"
    );

    // Send 100 Trying so the originator stops T1-backoff retransmits while we
    // forward. UPDATE responses are usually fast, but the 100 keeps the
    // request-side UAC quiet over UDP if the far end stalls.
    let trying = build_response(&message, 100, "Trying", state.server_header.as_deref(), &[]);
    // Answer on the same listener the request arrived on so a multi-homed UDP
    // host keeps a symmetric source port (a peer that sent to :5066 rejects a
    // reply sourced from :5060). No-op for stream transports / single listener.
    send_message_from(
        trying,
        inbound.transport,
        inbound.remote_addr,
        inbound.connection_id,
        Some(inbound.local_addr),
        state,
    );

    let branch = TransactionKey::generate_branch();
    let mut forwarded = message.clone();

    let update_target = if from_a_leg {
        if let Some(b_leg) = &winner_b_leg {
            crate::b2bua::actor::Dialog::rewrite_headers(
                &mut forwarded,
                &b_leg.dialog.call_id,
                a_leg.dialog.remote_tag.as_deref().unwrap_or(""),
                &b_leg.dialog.local_tag,
                b_leg.dialog.remote_tag.as_deref(),
            );
            Some((
                b_leg.transport.remote_addr,
                b_leg.transport.transport,
                b_leg.transport.local_addr,
                b_leg.transport.connection_id,
                b_leg.dialog.call_id.clone(),
                b_leg.dialog.local_tag.clone(),
            ))
        } else {
            // Unreachable since the one-legged arm above returns first, but a
            // request must never be dropped in silence: the originator would
            // retransmit to Timer F and learn nothing.
            warn!(call_id = %call_id, "B2BUA UPDATE: no winning B-leg");
            let response = build_response(
                &message,
                500,
                "Server Internal Error",
                state.server_header.as_deref(),
                &[],
            );
            send_message_from(
                response,
                inbound.transport,
                inbound.remote_addr,
                inbound.connection_id,
                Some(inbound.local_addr),
                state,
            );
            return;
        }
    } else {
        if let Some(b_leg) = &winner_b_leg {
            crate::b2bua::actor::Dialog::rewrite_headers(
                &mut forwarded,
                &a_leg.dialog.call_id,
                &b_leg.dialog.local_tag,
                a_leg.dialog.remote_tag.as_deref().unwrap_or(""),
                Some(&a_leg.dialog.local_tag),
            );
        }
        Some((
            a_leg.transport.remote_addr,
            a_leg.transport.transport,
            a_leg.transport.local_addr,
            a_leg.transport.connection_id,
            a_leg.dialog.call_id.clone(),
            a_leg.dialog.remote_tag.clone().unwrap_or_default(),
        ))
    };

    if let Some((
        destination,
        transport,
        target_local_addr,
        target_connection_id,
        leg_call_id,
        leg_from_tag,
    )) = update_target
    {
        // Via host + port = the target leg's anchored socket (see the re-INVITE
        // forward above for the A/B split).
        let transport_str = format!("{}", transport).to_uppercase();
        let (via_host, via_port) = if from_a_leg {
            b_leg_sent_by(target_local_addr, state, &transport)
        } else {
            (
                state.a_leg_advertised_host(target_local_addr, &transport),
                a_leg_advertised_port(target_local_addr, state.via_port(&transport)),
            )
        };
        let via_value = format!(
            "SIP/2.0/{} {}:{};branch={}",
            transport_str, via_host, via_port, branch,
        );
        forwarded.headers.set("Via", via_value);

        // Strip cross-leg headers (same set as re-INVITE bridging).
        if let Some(ref ua) = state.user_agent_header {
            forwarded.headers.set("User-Agent", ua.clone());
        } else {
            forwarded.headers.remove("User-Agent");
        }
        forwarded.headers.remove("Server");
        forwarded.headers.remove("Allow");
        forwarded.headers.remove("Allow-Events");
        forwarded.headers.remove("Supported");
        forwarded.headers.remove("Require");
        forwarded.headers.remove("Proxy-Require");
        forwarded.headers.remove("P-Asserted-Identity");
        forwarded.headers.remove("P-Access-Network-Info");
        forwarded.headers.remove("Security-Verify");
        forwarded.headers.remove("Security-Client");
        forwarded.headers.remove("Authorization");
        forwarded.headers.remove("Proxy-Authorization");
        forwarded.headers.remove("Record-Route");
        forwarded.headers.remove("Route");

        let target_route_set = if from_a_leg {
            winner_b_leg
                .as_ref()
                .map(|b| b.dialog.route_set.clone())
                .unwrap_or_default()
        } else {
            a_leg.dialog.route_set.clone()
        };
        for route in &target_route_set {
            forwarded.headers.add("Route", route.clone());
        }

        // From/To: stitch the target leg's URI string with the dialog tag.
        // The URI strings are captured at INVITE-send time without tags;
        // the tags arrive in the 2xx response and are stored separately
        // (see the splice at the 2xx capture path). Use ensure_tag so
        // we're robust to the splice not having run (e.g. a 401/407
        // retry path that resets remote_to_uri after the original 2xx,
        // or an early-dialog UPDATE before the 2xx — RFC 3311 §5.2).
        let (target_from_uri, target_from_tag, target_to_uri, target_to_tag) = if from_a_leg {
            let b = winner_b_leg.as_ref();
            (
                b.and_then(|b| b.dialog.local_from_uri.clone()),
                b.map(|b| b.dialog.local_tag.clone()),
                b.and_then(|b| b.dialog.remote_to_uri.clone()),
                b.and_then(|b| b.dialog.remote_tag.clone()),
            )
        } else {
            (
                a_leg.dialog.local_from_uri.clone(),
                Some(a_leg.dialog.local_tag.clone()),
                a_leg.dialog.remote_to_uri.clone(),
                a_leg.dialog.remote_tag.clone(),
            )
        };
        if let Some(uri) = target_from_uri {
            forwarded.headers.set(
                "From",
                crate::b2bua::actor::ensure_tag(&uri, target_from_tag.as_deref()),
            );
        }
        if let Some(uri) = target_to_uri {
            forwarded.headers.set(
                "To",
                crate::b2bua::actor::ensure_tag(&uri, target_to_tag.as_deref()),
            );
        }

        // CSeq: target leg's local sequence + UPDATE method. Per RFC 3311
        // §6, UPDATE shares the dialog's CSeq sequence with INVITE/BYE.
        let target_cseq = if from_a_leg {
            winner_b_leg
                .as_ref()
                .map(|b| b.dialog.local_cseq)
                .unwrap_or(1)
        } else {
            a_leg.dialog.local_cseq
        };
        forwarded
            .headers
            .set("CSeq", format!("{} UPDATE", target_cseq));

        let _ = crate::proxy::core::decrement_max_forwards(&mut forwarded.headers);

        // Body-aware media handling: empty-body UPDATE (session-timer
        // refresh) bypasses SDP rewrite and rtpengine entirely.
        if !forwarded.body.is_empty() {
            // Family-matched to the target leg (same arrival socket as the Via).
            let sdp_addr = state.a_leg_advertised_host(target_local_addr, &transport);
            sanitize_sdp_identity(&mut forwarded.body, &state.sdp_name, Some(&sdp_addr));

            if let (Some(ref rtpengine_set), Some(ref media_sessions), Some(ref profiles)) = (
                &state.rtpengine_set,
                &state.rtpengine_sessions,
                &state.rtpengine_profiles,
            ) {
                let a_sip_call_id = &a_leg.dialog.call_id;
                if let Some(session) = media_sessions.get(a_sip_call_id) {
                    if let Some(profile) = profiles.get(&session.profile) {
                        // Same tag rule as the re-INVITE path: an UPDATE from the callee needs the
                        // callee's own tag, and there is no substitute for it.
                        let Some(offer_tag) = session.offer_tag(from_a_leg) else {
                            warn!(
                                call_id = %call_id,
                                "B2BUA UPDATE from the callee on a media session with no recorded \
                                 answerer tag — rejecting with 488 rather than naming the caller to \
                                 the media engine"
                            );
                            reject_unanchorable_offer(&message, &inbound, state, &call_id, None);
                            return;
                        };
                        let mut offer_flags = profile.offer.clone();
                        if offer_flags.carry_received_from {
                            offer_flags.received_from = Some(inbound.remote_addr.ip());
                        }
                        match tokio::task::block_in_place(|| {
                            tokio::runtime::Handle::current().block_on(rtpengine_set.reoffer(
                                session.rtpengine_id(),
                                offer_tag,
                                &forwarded.body,
                                &offer_flags,
                            ))
                        }) {
                            Ok(rewritten_sdp) => {
                                forwarded.body = rewritten_sdp;
                                debug!(call_id = %call_id, "RTPEngine: rewrote UPDATE SDP (offer)");
                            }
                            Err(error) => {
                                error!(
                                    call_id = %call_id,
                                    "RTPEngine offer for UPDATE failed: {error} — rejecting the \
                                     UPDATE with 488 rather than forwarding SDP that routes both \
                                     parties around the anchor"
                                );
                                reject_unanchorable_offer(
                                    &message, &inbound, state, &call_id, None,
                                );
                                return;
                            }
                        }
                    }
                }
            }
            // Own the o= identity toward the leg this UPDATE is sent to (RFC 3264
            // §8), after any rtpengine rewrite.
            if let Some((sess_id, version)) = state
                .call_actors
                .reserve_leg_sdp_version(&call_id, !from_a_leg)
            {
                stamp_sdp_origin(&mut forwarded.body, &state.sdp_name, sess_id, version, None);
            }
            forwarded
                .headers
                .set("Content-Length", forwarded.body.len().to_string());
        }

        // RURI = target leg's remote Contact (RFC 3261 §12.2.1.1).
        if let Some(ref uri_str) = target_remote_contact {
            if let Ok(parsed) = parse_uri_standalone(uri_str) {
                forwarded.start_line = StartLine::Request(crate::sip::message::RequestLine {
                    method: crate::sip::message::Method::Update,
                    request_uri: parsed,
                    version: crate::sip::message::Version::sip_2_0(),
                });
            }
        }

        if let Some(ref contact) = target_local_contact {
            forwarded.headers.set("Contact", contact.clone());
        }

        // In-dialog requests follow the dialog route set (RFC 3261 §12.2.1.1):
        // send to the route-set first hop, not the cached INVITE next-hop. In an
        // IMS topology the INVITE was sent to a non-Record-Routing I-CSCF while
        // the dialog routes via the S-CSCF, so the cached leg destination is the
        // wrong target for an in-dialog UPDATE (mirrors the PRACK/ACK/BYE paths).
        // Falls back to the cached destination when there is no route set.
        let (send_dest, send_transport) =
            resolve_in_dialog_destination(&target_route_set, state, destination, transport);

        // Track the UPDATE branch under "update:" so the response handler
        // routes the cross-leg response correctly without colliding with a
        // concurrent re-INVITE on the same dialog.
        let direction = if from_a_leg {
            "update:a2b"
        } else {
            "update:b2a"
        };
        let originator_vias = message
            .headers
            .get_all("Via")
            .map(|v| v.to_vec())
            .unwrap_or_default();
        let mut update_leg = Leg::new_b_leg(
            leg_call_id,
            leg_from_tag,
            direction.to_string(),
            branch.clone(),
            LegTransport {
                remote_addr: send_dest,
                // Reuse the target leg's live connection (mirrors the framework
                // BYE) so a B→A forward writes on the connection the peer is on
                // rather than dialing its dead ephemeral source port.
                connection_id: target_connection_id,
                transport: send_transport,
                // Anchor the tracking leg on the target's socket (the A-leg's arrival
                // listener for B→A) so a post-teardown zombie re-ACK to this leg
                // still leaves from the right port on a multi-homed host.
                local_addr: target_local_addr,
            },
        );
        update_leg.stored_vias = originator_vias;
        update_leg.stored_cseq = message.headers.cseq().map(|c| c.to_string());
        // See the re-INVITE tracking leg: the response forwarded to this
        // originator must echo this request's From/To (RFC 3261 §8.2.6.2), not
        // the responder-dialog URIs the relayed answer carries.
        update_leg.stored_from = message.headers.from().map(|f| f.to_string());
        update_leg.stored_to = message.headers.to().map(|t| t.to_string());
        state.call_actors.add_b_leg(&call_id, update_leg);

        // Forward to the target leg. A→B: destination-keyed reuse via
        // stream_connections + pool/SNI. B→A: reuse the target leg's live
        // connection via the connection_map exactly like the framework BYE
        // (send_message_from → OutboundRouter → TLS/TCP distributor connection_map
        // lookup, dialing only on a miss); target_local_addr keeps the UDP egress
        // pinned for multi-homed source-port parity. If the target's TLS
        // connection is dead, dial its remote-target Contact instead of the dead
        // cached socket (RFC 3261 §12.2.1.1).
        let contact_fallback = contact_fallback_target(
            from_a_leg,
            send_dest,
            send_transport,
            target_connection_id,
            target_route_set.is_empty(),
            target_remote_contact.as_deref(),
            state,
        );
        if from_a_leg {
            send_b2bua_to_bleg(
                forwarded,
                send_transport,
                send_dest,
                target_local_addr,
                state,
            );
        } else if let Some(target) = contact_fallback {
            warn!(
                call_id = %call_id, dest = %target.address,
                "B2BUA UPDATE B→A: stored TLS connection dead — dialing remote target Contact"
            );
            let data = Bytes::from(forwarded.to_bytes());
            send_to_target(
                data,
                &target,
                send_transport,
                ConnectionId::default(),
                target_local_addr,
                state,
            );
        } else {
            send_message_from(
                forwarded,
                send_transport,
                send_dest,
                target_connection_id,
                target_local_addr,
                state,
            );
        }

        // Bump local CSeq on the target leg after sending.
        if let Some(mut call) = state.call_actors.get_call_mut(&call_id) {
            if from_a_leg {
                if let Some(winner_idx) = call.winner {
                    if let Some(b_leg) = call.b_legs.get_mut(winner_idx) {
                        b_leg.dialog.local_cseq += 1;
                    }
                }
            } else {
                call.a_leg.dialog.local_cseq += 1;
            }
        }
    }
}

/// Build an in-dialog request (NOTIFY, REFER, …) toward a leg, using that
/// leg's own dialog identity (Call-ID / tags / Route set / remote target).
///
/// Generalization of [`build_b2bua_bye`]: same From/To/Contact/Route/Via
/// construction, but the caller chooses the method, the CSeq number, any extra
/// headers, and an optional body. Used for siphon-originated `message/sipfrag`
/// NOTIFYs on a REFER subscription and for the outbound `call.refer()` REFER.
///
/// `cseq` is used as-is — the caller must have reserved (incremented) the leg's
/// `local_cseq` for this request first.
pub fn build_b2bua_in_dialog_request(
    leg: &crate::b2bua::actor::Leg,
    state: &DispatcherState,
    method: Method,
    cseq: u32,
    extra_headers: &[(&str, String)],
    body: Option<(&str, Vec<u8>)>,
) -> Option<SipMessage> {
    let dialog = &leg.dialog;
    let method_str = method.as_str().to_string();

    // R-URI: the remote target (Contact), RFC 3261 §12.2.1.1.
    let ruri = dialog
        .remote_contact
        .as_deref()
        .and_then(|uri_str| parse_uri_standalone(uri_str).ok())
        .unwrap_or_else(|| {
            dialog
                .target_uri
                .as_deref()
                .and_then(|uri_str| parse_uri_standalone(uri_str).ok())
                .unwrap_or_else(|| SipUri::new("invalid".to_string()))
        });

    let transport_str = format!("{}", leg.transport.transport).to_uppercase();
    let branch = TransactionKey::generate_branch();
    // Sent-by is the socket this leg is anchored on (see `leg_sent_by`).
    let (via_host, via_port) = leg_sent_by(leg, state);
    let via = format!(
        "SIP/2.0/{} {}:{};branch={}",
        transport_str, via_host, via_port, branch,
    );

    let from_header = match &dialog.local_from_uri {
        Some(uri) => crate::b2bua::actor::ensure_tag(uri, Some(&dialog.local_tag)),
        None => format!(
            "<{}>;tag={}",
            dialog.local_contact.as_deref().unwrap_or("sip:invalid"),
            dialog.local_tag,
        ),
    };
    let to_header = match &dialog.remote_to_uri {
        Some(uri) => crate::b2bua::actor::ensure_tag(uri, dialog.remote_tag.as_deref()),
        None => {
            let to_uri = dialog
                .remote_contact
                .as_deref()
                .unwrap_or(dialog.target_uri.as_deref().unwrap_or("sip:invalid"));
            match &dialog.remote_tag {
                Some(tag) => format!("<{}>;tag={}", to_uri, tag),
                None => format!("<{}>", to_uri),
            }
        }
    };

    let mut builder = SipMessageBuilder::new()
        .request(method, ruri)
        .via(via)
        .from(from_header)
        .to(to_header)
        .call_id(dialog.call_id.clone())
        .cseq(format!("{cseq} {method_str}"))
        .header("Max-Forwards", "70".to_string());

    if let Some(ref contact) = dialog.local_contact {
        builder = builder.header("Contact", contact.clone());
    }
    if let Some(ref ua) = state.user_agent_header {
        builder = builder.header("User-Agent", ua.clone());
    } else if let Some(ref srv) = state.server_header {
        builder = builder.header("User-Agent", srv.clone());
    }
    for route in &dialog.route_set {
        builder = builder.header("Route", route.clone());
    }
    for (name, value) in extra_headers {
        builder = builder.header(name, value.clone());
    }

    let builder = match body {
        Some((content_type, bytes)) => builder
            .content_type(content_type.to_string())
            .content_length(bytes.len())
            .body(bytes),
        None => builder.content_length(0),
    };

    match builder.build() {
        Ok(message) => Some(message),
        Err(error) => {
            warn!("B2BUA: failed to build in-dialog {method_str}: {error}");
            None
        }
    }
}
