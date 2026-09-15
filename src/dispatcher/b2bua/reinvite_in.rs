//! An inbound re-INVITE on a bridged call: glare, the offer/answer it drives
//! across the bridge, and the media re-anchor behind it.
use crate::dispatcher::*;

#[allow(clippy::too_many_lines)] // TODO(1.9.0 split): decomposed by the dispatcher module split. handle_b2bua_reinvite
pub fn handle_b2bua_reinvite(
    inbound: InboundMessage,
    message: SipMessage,
    state: &DispatcherState,
) {
    let sip_call_id = message
        .headers
        .get("Call-ID")
        .map(|s| s.to_string())
        .unwrap_or_default();

    let call_id = match state.call_actors.find_by_sip_call_id(&sip_call_id) {
        Some(id) => id,
        None => {
            // Raced a concurrent teardown (the `is_reinvite` gate had matched).
            // 481 like the no-dialog-leg arm below, never a silent drop.
            warn!(sip_call_id = %sip_call_id, "B2BUA re-INVITE: no matching call — 481");
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
    // never by source socket: a Teams-style peer opens a NEW TLS connection (new
    // source port) for its re-INVITE, so a socket comparison misclassifies the
    // direction and reflects the re-INVITE back at the leg it came from.
    let from_tag = message.typed_from().ok().flatten().and_then(|na| na.tag);
    let from_a_leg = match state
        .call_actors
        .get_call(&call_id)
        .and_then(|call| call.request_direction(&sip_call_id, from_tag.as_deref()))
    {
        Some(crate::b2bua::actor::LegSide::A) => true,
        Some(crate::b2bua::actor::LegSide::B) => false,
        None => {
            warn!(sip_call_id = %sip_call_id, "B2BUA re-INVITE: Call-ID matches no dialog leg — 481");
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

    // RFC 4028 §9: a refresh asking for too brief a session interval is refused
    // here, on the dialog it arrived on, and goes nowhere.
    if refuse_too_brief_refresh(&call_id, &inbound, &message, state) {
        return;
    }

    // Track the offerer's own new endpoint SDP (its re-INVITE offer, raw —
    // before any topology/rtpengine rewrite) so a later siphon-terminated
    // transfer offers this leg's *current* media if it is the survivor.
    if !message.body.is_empty() {
        state
            .call_actors
            .set_leg_last_sdp(&call_id, from_a_leg, &message.body);
    }

    // Flow refresh (RFC 5626 / RFC 3261 §12.2.2): the peer may have sent this
    // in-dialog re-INVITE on a new flow (TLS reconnect / NAT rebind). Re-anchor
    // the originating leg's transport + remote target on the arrival flow so the
    // 200 OK toward that peer — and later in-dialog requests — reach the live
    // connection instead of the peer's dead original socket. Done before the
    // snapshot below so the clones carry the live flow.
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

    // Per-leg Contact URIs for RURI and Contact rewriting (RFC 3261 §12.2.1.1)
    let (target_remote_contact, target_local_contact, _target_remote_aor_host) = if from_a_leg {
        // A→B: target is B-leg
        winner_b_leg
            .as_ref()
            .map(|b| {
                (
                    b.dialog.remote_contact.clone(),
                    b.dialog.local_contact.clone(),
                    b.dialog.remote_aor_host.clone(),
                )
            })
            .unwrap_or((None, None, None))
    } else {
        // B→A: target is A-leg
        (
            a_leg.dialog.remote_contact.clone(),
            a_leg.dialog.local_contact.clone(),
            a_leg.dialog.remote_aor_host.clone(),
        )
    };

    // A call with no second leg: siphon *is* the far party — an IVR, a queue,
    // voicemail, or a call a controller answered and anchored. There is nothing
    // to forward to and no glare to have, so this must be answered here.
    //
    // Before this, the glare check below read the absent winning B-leg's
    // `initial_acked` as `false` and answered `491 Request Pending`, so a hold
    // from the handset retried, got `491` again, and never completed. RFC 3261
    // §14.1 reserves `491` for a genuinely crossing offer/answer; there is no
    // second offer here to cross with.
    if from_a_leg && winner_b_leg.is_none() {
        answer_one_legged_reoffer(&inbound, &message, &call_id, &a_leg, "re-INVITE", state);
        return;
    }

    // Glare prevention (RFC 3261 §14.1):
    //  (a) Don't forward a re-INVITE if the target hasn't ACKed the initial
    //      INVITE yet — the offer/answer from the initial transaction is
    //      still in flight.
    //  (b) Don't forward a second re-INVITE while one is already pending
    //      toward the same leg — two concurrent offer/answer exchanges
    //      would leave the media state undefined.
    // In either case we respond 491 Request Pending so the originator can
    // retry after a random delay per the RFC.
    let target_acked = if from_a_leg {
        winner_b_leg
            .as_ref()
            .map(|b| b.initial_acked)
            .unwrap_or(false)
    } else {
        a_leg.initial_acked
    };
    if !target_acked {
        debug!(
            call_id = %call_id,
            from_a_leg = from_a_leg,
            "B2BUA: rejecting re-INVITE with 491 — target leg not yet ACKed"
        );
        let response = build_response(
            &message,
            491,
            "Request Pending",
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

    // `on_a_leg = !from_a_leg` because the "target" of the re-INVITE is the
    // OPPOSITE side from where it arrived. A re-INVITE from the A-leg is
    // forwarded toward the B-leg (and vice versa). Take-and-set the pending
    // flag atomically so the glare check races against nothing.
    let already_pending =
        state
            .call_actors
            .set_pending_reinvite(&call_id, /*on_a_leg=*/ !from_a_leg, true);
    if already_pending {
        debug!(
            call_id = %call_id,
            from_a_leg = from_a_leg,
            "B2BUA: rejecting re-INVITE with 491 — another re-INVITE already pending toward target"
        );
        let response = build_response(
            &message,
            491,
            "Request Pending",
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

    debug!(
        call_id = %call_id,
        from_a_leg = from_a_leg,
        "B2BUA: forwarding re-INVITE"
    );

    // Send 100 Trying to the re-INVITE sender
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

    // Build the forwarded re-INVITE with new Via/branch
    let branch = TransactionKey::generate_branch();

    let mut forwarded = message.clone();
    // Register this branch for response routing back to the re-INVITE sender
    let reinvite_target = if from_a_leg {
        // A→B: forward to winning B-leg, rewrite A-leg → B-leg dialog headers
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
            warn!(call_id = %call_id, "B2BUA re-INVITE: no winning B-leg");
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
        // B→A: forward to A-leg, rewrite B-leg → A-leg dialog headers
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
    )) = reinvite_target
    {
        // Set Via with correct transport for the target leg.
        // Via host + port = the target leg's anchored socket: the A-leg's arrival
        // listener (family-correct, advertised identity) on a B→A forward, the
        // B-leg's flow socket on an A→B forward when it was dialled over one.
        // Unanchored legs keep the per-transport via_host/via_port.
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

        // Sanitize: strip headers that leak the other leg's identity/capabilities.
        // A B2BUA terminates the dialog — no cross-leg headers should pass through.
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
        // Strip cross-leg Record-Route and Route — replace with target leg's route set
        forwarded.headers.remove("Record-Route");
        forwarded.headers.remove("Route");

        // Add target leg's dialog route set as Route headers
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

        // From/To: stitch URI string with dialog tag (RFC 3261 §12.2 —
        // dialog identity requires the tag). The URIs are captured at
        // INVITE-send time without tags; tags arrive in the 2xx and are
        // stored separately. ensure_tag survives the URI being reset by
        // a 401/407 retry path (which re-captures the bare URI).
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

        // Regenerate CSeq for the target leg's dialog (RFC 3261 — independent CSeq per dialog)
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
            .set("CSeq", format!("{} INVITE", target_cseq));

        // Decrement Max-Forwards (RFC 7332 — B2BUAs MUST decrement)
        let _ = crate::proxy::core::decrement_max_forwards(&mut forwarded.headers);

        // Sanitize SDP: mask other leg's identity in o= and s= lines, and
        // rewrite the o= address for topology hiding — family-matched to the
        // target leg (same arrival socket as the Via above), so a v6 A-leg gets
        // a v6 o= address to go with its v6 Via.
        let sdp_addr = state.a_leg_advertised_host(target_local_addr, &transport);
        sanitize_sdp_identity(&mut forwarded.body, &state.sdp_name, Some(&sdp_addr));

        // RTPEngine: rewrite re-INVITE SDP through offer to maintain media anchoring.
        // Without this, re-INVITE SDP passes through unmodified — if the remote side
        // includes stale or cross-wired RTP ports, media breaks (one-way audio).
        if !forwarded.body.is_empty() {
            match reoffer_through_media_engine(
                state,
                &a_leg.dialog.call_id,
                from_a_leg,
                inbound.remote_addr.ip(),
                &forwarded.body,
            ) {
                ReofferOutcome::NotAnchored => {}
                ReofferOutcome::Rewritten(rewritten_sdp) => {
                    forwarded.body = rewritten_sdp;
                    debug!(call_id = %call_id, "RTPEngine: rewrote re-INVITE SDP (offer)");
                }
                ReofferOutcome::NoOfferTag => {
                    warn!(
                        call_id = %call_id,
                        "B2BUA re-INVITE from the callee on a media session with no \
                         recorded answerer tag: rejecting with 488 rather than naming the \
                         caller to the media engine"
                    );
                    reject_unanchorable_offer(
                        &message,
                        &inbound,
                        state,
                        &call_id,
                        Some(!from_a_leg),
                    );
                    return;
                }
                ReofferOutcome::Failed(error) => {
                    error!(
                        call_id = %call_id,
                        "RTPEngine offer for re-INVITE failed: {error}: rejecting the \
                         re-INVITE with 488 rather than forwarding SDP that routes both \
                         parties around the anchor"
                    );
                    reject_unanchorable_offer(
                        &message,
                        &inbound,
                        state,
                        &call_id,
                        Some(!from_a_leg),
                    );
                    return;
                }
            }
        }

        // Own the o= identity toward the leg this re-INVITE is sent to (RFC 3264
        // §8): stable per-leg session-id + monotonic version, applied AFTER any
        // rtpengine rewrite so siphon's o= is final on the wire (address left as
        // rtpengine/sanitize set it — §8 keys on the session-id, not the address).
        if !forwarded.body.is_empty() {
            if let Some((sess_id, version)) = state
                .call_actors
                .reserve_leg_sdp_version(&call_id, !from_a_leg)
            {
                stamp_sdp_origin(&mut forwarded.body, &state.sdp_name, sess_id, version, None);
            }
        }

        // `media.sdp_strip_attributes`, last: after the media engine re-offer and
        // the o= stamp. The engine was handed the offer as the peer sent it.
        strip_relayed_sdp_attributes(&mut forwarded, state);

        // Update Content-Length after SDP rewrite (o=/s= and RTPEngine changes may alter body size)
        if !forwarded.body.is_empty() {
            forwarded
                .headers
                .set("Content-Length", forwarded.body.len().to_string());
        }

        // Rewrite RURI to target leg's remote Contact (RFC 3261 §12.2.1.1).
        // In-dialog requests MUST use the remote target from the last 2xx/INVITE.
        if let Some(ref uri_str) = target_remote_contact {
            if let Ok(parsed) = parse_uri_standalone(uri_str) {
                forwarded.start_line = StartLine::Request(crate::sip::message::RequestLine {
                    method: crate::sip::message::Method::Invite,
                    request_uri: parsed,
                    version: crate::sip::message::Version::sip_2_0(),
                });
            }
        }

        // Rewrite Contact to what we advertised to the target leg
        if let Some(ref contact) = target_local_contact {
            forwarded.headers.set("Contact", contact.clone());
        }

        // In-dialog requests follow the dialog route set (RFC 3261 §12.2.1.1):
        // send to the route-set first hop, not the cached INVITE next-hop. In an
        // IMS topology the INVITE was sent to a non-Record-Routing I-CSCF while
        // the dialog routes via the S-CSCF, so the cached leg destination is the
        // wrong target for an in-dialog re-INVITE (mirrors the PRACK/ACK/BYE
        // paths). Falls back to the cached destination when there is no route set.
        let (send_dest, send_transport) =
            resolve_in_dialog_destination(&target_route_set, state, destination, transport);

        // Track the re-INVITE branch → call_id for response routing.
        // Encode the direction so the response handler knows where to relay.
        // Store the originator's Via(s) so we can restore them on the response.
        let direction = if from_a_leg {
            "reinvite:a2b"
        } else {
            "reinvite:b2a"
        };
        let originator_vias = message
            .headers
            .get_all("Via")
            .map(|v| v.to_vec())
            .unwrap_or_default();
        let mut reinvite_leg = Leg::new_b_leg(
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
        reinvite_leg.stored_vias = originator_vias;
        reinvite_leg.stored_cseq = message.headers.cseq().map(|c| c.to_string());
        // The originator's own From/To, kept verbatim for the same reason as its
        // Via and CSeq: RFC 3261 §8.2.6.2 requires the response to echo the
        // request being answered, and this re-INVITE is that request. The
        // forwarded response is a clone of the *responder's* 200, whose From/To
        // name the far leg's dialog, and swapping only the tags (what
        // `Dialog::rewrite_headers` does) leaves the far leg's URIs in place.
        // Both are in-dialog here, so the To arrives already tagged and is
        // echoed as-is — §8.2.6.2's "if a request contained a To tag ... the To
        // header field in the response MUST equal that of the request".
        reinvite_leg.stored_from = message.headers.from().map(|f| f.to_string());
        reinvite_leg.stored_to = message.headers.to().map(|t| t.to_string());
        // The route set the forwarded re-INVITE carries, so the ACK for its 200
        // is routed identically (RFC 3261 §12.2.1.1).
        reinvite_leg.dialog.route_set = target_route_set.clone();
        // The offer as the target leg is sent it. It is committed to that leg's
        // dialog only when the leg answers 2xx (`forward_reinvite_response`).
        reinvite_leg.offered_sdp = sdp_in_body(message_content_type(&forwarded), &forwarded.body);
        // The interval the relayed request asks for, which a 2xx without a
        // Session-Expires leaves siphon refreshing at (RFC 4028 §7.2).
        reinvite_leg.request_session_expires =
            crate::b2bua::session_timer::requested_interval_of(&forwarded.headers);
        // And what the originator asked of its own dialog, which siphon answers.
        reinvite_leg.session_refresh_request = Some(
            crate::b2bua::session_timer::session_refresh_request(&message.headers),
        );
        state.call_actors.add_b_leg(&call_id, reinvite_leg);
        note_session_refresh_request(&call_id, from_a_leg, &message.headers, state);

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
                "B2BUA re-INVITE B→A: stored TLS connection dead — dialing remote target Contact"
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

        // Increment the target leg's local CSeq after sending the re-INVITE
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

    // Reset session timer on successful re-INVITE (timer reset happens on 200 OK
    // via handle_b2bua_response which calls set_state — we reset the timer there)
}

/// Answer an in-dialog re-offer on a call siphon terminates itself.
///
/// Shared by the re-INVITE and UPDATE paths, which owe the same answer: the
/// offer goes to the media engine as a re-offer siphon answers locally
/// (`answer_local`), and the engine's answer is the body of the `200 OK`. The
/// engine decides the direction, so a `sendonly` hold comes back `recvonly`
/// (RFC 3264 §6.1) and a resume comes back `sendrecv`.
///
/// An offerless refresh (RFC 4028 §10) is answered with the leg's current media
/// instead, because RFC 3261 §13.2.1 makes the 2xx to an offerless INVITE carry
/// the offer. Without a media session there is nothing truthful to answer with,
/// so it is refused rather than answered with an SDP that describes no path.
pub fn answer_one_legged_reoffer(
    inbound: &InboundMessage,
    message: &SipMessage,
    call_id: &str,
    a_leg: &Leg,
    what: &str,
    state: &DispatcherState,
) {
    let (Some(rtpengine_set), Some(media_sessions), Some(profiles)) = (
        state.rtpengine_set.as_ref(),
        state.rtpengine_sessions.as_ref(),
        state.rtpengine_profiles.as_ref(),
    ) else {
        // No media backend at all: the leg carries whatever SDP the peer and
        // siphon agreed at answer, and there is nothing to re-negotiate. A
        // refresh is still a refresh, so accept it without a body.
        debug!(call_id = %call_id, what, "B2BUA: one-legged re-offer with no media backend — 200 without a body");
        send_one_legged_ok(inbound, message, call_id, Vec::new(), state);
        return;
    };

    let session = media_sessions.get(&a_leg.dialog.call_id);
    let profile = session
        .as_ref()
        .and_then(|session| profiles.get(&session.profile));
    let (Some(session), Some(profile)) = (session.as_ref(), profile) else {
        warn!(
            call_id = %call_id,
            what,
            "B2BUA: one-legged re-offer on a call with no media session — 488 rather than an \
             answer describing a media path that does not exist"
        );
        reject_unanchorable_offer(message, inbound, state, call_id, Some(true));
        return;
    };

    // The A-leg is the offering party on a one-legged call, so its own tag is
    // what identifies it to the engine.
    let Some(offer_tag) = session.offer_tag(true) else {
        warn!(call_id = %call_id, what, "B2BUA: one-legged re-offer with no recorded offerer tag — 488");
        reject_unanchorable_offer(message, inbound, state, call_id, Some(true));
        return;
    };

    // An offerless refresh asks us for the offer; answer from the media the leg
    // last described, which is what the engine is already wired to.
    let offer = if message.body.is_empty() {
        match a_leg.last_sdp.as_ref() {
            Some(sdp) => sdp.clone(),
            None => {
                warn!(
                    call_id = %call_id,
                    what,
                    "B2BUA: offerless one-legged re-offer with no stored media to offer back — 488"
                );
                reject_unanchorable_offer(message, inbound, state, call_id, Some(true));
                return;
            }
        }
    } else {
        message.body.clone()
    };

    let mut answer_flags = profile.answer.clone();
    // Pin media ingress where this request actually came from, as the offer path
    // does: a handset that changed network re-offers from a new public address.
    if answer_flags.carry_received_from {
        answer_flags.received_from = Some(inbound.remote_addr.ip());
    }

    let answer_sdp = tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(rtpengine_set.answer_local(
            session.rtpengine_id(),
            offer_tag,
            &String::from_utf8_lossy(&offer),
            &answer_flags,
        ))
    });

    match answer_sdp {
        Ok(sdp) => {
            // The answer is the session description now in force on the leg.
            record_sdp_sent_to_leg(state, call_id, true, "application/sdp", sdp.as_bytes());
            debug!(call_id = %call_id, what, "B2BUA: answered a one-legged re-offer from the media engine");
            send_one_legged_ok(inbound, message, call_id, sdp.into_bytes(), state);
        }
        Err(error) => {
            error!(
                call_id = %call_id,
                what,
                "B2BUA: the media engine refused a one-legged re-offer: {error} — 488 rather than \
                 an answer it will not honour"
            );
            reject_unanchorable_offer(message, inbound, state, call_id, Some(true));
        }
    }
}

/// Send the `200 OK` for a one-legged re-offer, with `body` as its SDP.
///
/// The re-offer is a session refresh request too (RFC 4028 §7.4). With no other
/// party to relay it to, siphon answers it itself (§9): the 2xx answers the
/// request's session timer and restarts the session on the dialog.
fn send_one_legged_ok(
    inbound: &InboundMessage,
    message: &SipMessage,
    call_id: &str,
    body: Vec<u8>,
    state: &DispatcherState,
) {
    let mut response = build_response(message, 200, "OK", state.server_header.as_deref(), &[]);
    note_session_refresh_request(call_id, true, &message.headers, state);
    negotiate_relayed_session_timer(
        call_id,
        true,
        Some(&message.headers),
        &mut response.headers,
        state,
    );
    if !body.is_empty() {
        response
            .headers
            .set("Content-Type", "application/sdp".to_string());
        response
            .headers
            .set("Content-Length", body.len().to_string());
        response.body = body;
    }
    send_message_from(
        response,
        inbound.transport,
        inbound.remote_addr,
        inbound.connection_id,
        Some(inbound.local_addr),
        state,
    );
}

/// What the media engine made of an offer one party of an anchored call re-offers.
pub enum ReofferOutcome {
    /// The call's media is not anchored: the offer goes on as it is.
    NotAnchored,
    /// The engine's offer, facing the other party.
    Rewritten(Vec<u8>),
    /// The engine session has no tag for the offering party, so it cannot be
    /// named to the engine without claiming to be the other one.
    NoOfferTag,
    /// The engine refused the offer.
    Failed(String),
}

/// Re-offer `offer`, from the caller when `from_a_leg` and else from the callee,
/// through the media engine anchoring the call keyed by `a_leg_call_id`, with
/// media ingress pinned to `received_from` where the profile asks for it.
///
/// The offering party is named by its own tag: the engine resolves the
/// re-offering party by tag and answers with the leg facing the other one, so the
/// other party's tag would come back wired to the wrong leg.
pub fn reoffer_through_media_engine(
    state: &DispatcherState,
    a_leg_call_id: &str,
    from_a_leg: bool,
    received_from: std::net::IpAddr,
    offer: &[u8],
) -> ReofferOutcome {
    let (Some(rtpengine_set), Some(media_sessions), Some(profiles)) = (
        &state.rtpengine_set,
        &state.rtpengine_sessions,
        &state.rtpengine_profiles,
    ) else {
        return ReofferOutcome::NotAnchored;
    };
    let Some(session) = media_sessions.get(a_leg_call_id) else {
        return ReofferOutcome::NotAnchored;
    };
    let Some(profile) = profiles.get(&session.profile) else {
        return ReofferOutcome::NotAnchored;
    };
    let Some(offer_tag) = session.offer_tag(from_a_leg) else {
        return ReofferOutcome::NoOfferTag;
    };
    let mut offer_flags = profile.offer.clone();
    // Pin media ingress to where the offer actually came from, the way the initial
    // offer does: a client that changed network re-offers from a new public
    // address, and the engine gates the leg on the last hint it was given.
    if offer_flags.carry_received_from {
        offer_flags.received_from = Some(received_from);
    }
    match tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(rtpengine_set.reoffer(
            session.rtpengine_id(),
            offer_tag,
            offer,
            &offer_flags,
        ))
    }) {
        Ok(rewritten) => ReofferOutcome::Rewritten(rewritten),
        Err(error) => ReofferOutcome::Failed(error.to_string()),
    }
}
