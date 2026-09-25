//! In-dialog requests siphon forwards verbatim across the bridge, and the
//! NOTIFYs a transfer subscription carries.
use crate::dispatcher::*;

/// Forward an in-dialog REFER or NOTIFY across to the far leg of a B2BUA call,
/// on that leg's own dialog identity — the transparent-transfer primitive.
///
/// This is the UPDATE bridge (`handle_b2bua_update`) stripped to the parts a
/// bodyless/opaque-body request needs: no 100 Trying, no SDP/rtpengine (the body,
/// e.g. a NOTIFY `message/sipfrag`, is forwarded verbatim). `method` is the
/// request method; `marker` is the tracking-leg `target_uri` prefix (`"refer"` /
/// `"notify"`) whose response arm relays the far end's reply back to the
/// originator. The caller has already resolved `from_a_leg` by dialog identity.
pub fn b2bua_forward_indialog_request(
    inbound: &InboundMessage,
    message: &SipMessage,
    call_id: &str,
    from_a_leg: bool,
    method: Method,
    marker: crate::b2bua::actor::ForwardedMarker,
    state: &DispatcherState,
) {
    let method_str = method.as_str().to_string();

    // Flow refresh (RFC 5626 / RFC 3261 §12.2.2): re-anchor the originating leg
    // on the arrival flow (TLS reconnect / NAT rebind) before snapshotting.
    let refreshed_contact = message
        .headers
        .get("Contact")
        .or_else(|| message.headers.get("m"))
        .map(|value| crate::b2bua::actor::extract_contact_uri(value));
    if let Some(mut call) = state.call_actors.get_call_mut(call_id) {
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

    let (a_leg, winner_b_leg) = match state.call_actors.get_call(call_id) {
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

    let branch = TransactionKey::generate_branch();
    let mut forwarded = message.clone();

    let target = if from_a_leg {
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
            // One-legged call (UAS-mode answer, handover, IVR, WebSocket
            // takeover): there is no second party to bridge onto, and dropping
            // the request leaves the peer retransmitting to Timer F — 32 s of
            // silence for a request siphon has already decided it cannot serve.
            // Answer instead. See `no_far_leg_final_response`.
            let (code, reason) = no_far_leg_final_response(&method);
            warn!(
                call_id = %call_id,
                code,
                "B2BUA {method_str}: no far leg to forward to — answering {code} {reason}"
            );
            let response =
                build_response(message, code, reason, state.server_header.as_deref(), &[]);
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
        crate::b2bua::actor::Dialog::rewrite_headers(
            &mut forwarded,
            &a_leg.dialog.call_id,
            &winner_b_leg
                .as_ref()
                .map(|b| b.dialog.local_tag.clone())
                .unwrap_or_default(),
            a_leg.dialog.remote_tag.as_deref().unwrap_or(""),
            Some(&a_leg.dialog.local_tag),
        );
        Some((
            a_leg.transport.remote_addr,
            a_leg.transport.transport,
            a_leg.transport.local_addr,
            a_leg.transport.connection_id,
            a_leg.dialog.call_id.clone(),
            a_leg.dialog.remote_tag.clone().unwrap_or_default(),
        ))
    };

    let Some((
        destination,
        transport,
        target_local_addr,
        target_connection_id,
        leg_call_id,
        leg_from_tag,
    )) = target
    else {
        return;
    };

    // Via host + port = the target leg's anchored socket (see the re-INVITE
    // forward for the A/B split).
    let transport_str = format!("{}", transport).to_uppercase();
    let (via_host, via_port) = if from_a_leg {
        b_leg_sent_by(target_local_addr, state, &transport)
    } else {
        (
            state.a_leg_advertised_host(target_local_addr, &transport),
            state.a_leg_advertised_port(target_local_addr, &transport),
        )
    };
    let via_value = format!(
        "SIP/2.0/{} {}:{};branch={}",
        transport_str, via_host, via_port, branch,
    );
    forwarded.headers.set("Via", via_value);

    // Strip cross-leg headers (same hygiene set as the UPDATE bridge). Refer-To,
    // Referred-By, Event and Subscription-State are NOT in this set, so they ride
    // across intact — exactly what the transparent transfer needs.
    if let Some(ref ua) = state.user_agent_header {
        forwarded.headers.set("User-Agent", ua.clone());
    } else {
        forwarded.headers.remove("User-Agent");
    }
    forwarded.headers.remove("Server");
    forwarded.headers.remove("Allow");
    forwarded.headers.remove("Supported");
    forwarded.headers.remove("Require");
    forwarded.headers.remove("Proxy-Require");
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
        .set("CSeq", format!("{target_cseq} {method_str}"));

    let _ = crate::proxy::core::decrement_max_forwards(&mut forwarded.headers);

    // Opaque body forwarded verbatim (NOTIFY message/sipfrag; REFER has none).
    forwarded
        .headers
        .set("Content-Length", forwarded.body.len().to_string());

    if let Some(ref uri_str) = target_remote_contact {
        if let Ok(parsed) = parse_uri_standalone(uri_str) {
            forwarded.start_line = StartLine::Request(crate::sip::message::RequestLine {
                method,
                request_uri: parsed,
                version: crate::sip::message::Version::sip_2_0(),
            });
        }
    }
    if let Some(ref contact) = target_local_contact {
        forwarded.headers.set("Contact", contact.clone());
    }

    let (send_dest, send_transport) =
        resolve_in_dialog_destination(&target_route_set, state, destination, transport);

    let direction = if from_a_leg {
        marker.tracking_target("a2b")
    } else {
        marker.tracking_target("b2a")
    };
    let originator_vias = message
        .headers
        .get_all("Via")
        .map(|v| v.to_vec())
        .unwrap_or_default();
    let mut tracking_leg = Leg::new_b_leg(
        leg_call_id,
        leg_from_tag,
        direction,
        branch.clone(),
        LegTransport {
            remote_addr: send_dest,
            connection_id: target_connection_id,
            transport: send_transport,
            local_addr: target_local_addr,
        },
    );
    tracking_leg.stored_vias = originator_vias;
    tracking_leg.stored_cseq = message.headers.cseq().map(|c| c.to_string());
    // Keep the originator's From/To verbatim so the relayed response echoes them
    // exactly (RFC 3261 §8.2.6.2) instead of reconstructing from dialog URIs,
    // which can carry a `:5060` (or params/display) the peer never sent.
    tracking_leg.stored_from = message.headers.from().map(|f| f.to_string());
    tracking_leg.stored_to = message.headers.to().map(|t| t.to_string());
    state.call_actors.add_b_leg(call_id, tracking_leg);

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
    } else if let Some(fallback) = contact_fallback {
        let data = Bytes::from(forwarded.to_bytes());
        send_to_target(
            data,
            &fallback,
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

    // Bump the target leg's local CSeq after sending.
    if let Some(mut call) = state.call_actors.get_call_mut(call_id) {
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

/// Handle an in-dialog NOTIFY on a tracked B2BUA call — the sipfrag progress of
/// a REFER subscription (RFC 3515 §2.4).
///
/// Two cases:
///   - **siphon owns the subscription** (siphon-originated transfer: siphon sent
///     the REFER and is the subscriber): answer `200 OK` locally, read the
///     `Subscription-State`, and drop the subscription on `terminated`. Not
///     bridged — the subscription lives only between siphon and the referee.
///   - **transparent transfer** (siphon forwarded the REFER; the far end is
///     notifying): bridge the NOTIFY across to the referrer's leg so it sees the
///     transfer progress, exactly like the far end intended.
pub fn handle_b2bua_notify(inbound: InboundMessage, message: SipMessage, state: &DispatcherState) {
    let sip_call_id = message
        .headers
        .get("Call-ID")
        .map(|s| s.to_string())
        .unwrap_or_default();
    let call_id = match state.call_actors.find_by_sip_call_id(&sip_call_id) {
        Some(id) => id,
        None => {
            // Raced a concurrent teardown. 481 like the no-dialog-leg arm below
            // — RFC 6665 §8.2.1 also answers 481 for a NOTIFY whose
            // subscription is gone.
            warn!(sip_call_id = %sip_call_id, "B2BUA NOTIFY: no matching call — 481");
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

    let from_tag = message.typed_from().ok().flatten().and_then(|na| na.tag);
    let from_a_leg = match state
        .call_actors
        .get_call(&call_id)
        .and_then(|call| call.request_direction(&sip_call_id, from_tag.as_deref()))
    {
        Some(crate::b2bua::actor::LegSide::A) => true,
        Some(crate::b2bua::actor::LegSide::B) => false,
        None => {
            warn!(sip_call_id = %sip_call_id, "B2BUA NOTIFY: Call-ID matches no dialog leg — 481");
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

    if state
        .call_actors
        .has_subscriber_refer_subscription(&call_id, from_a_leg)
    {
        // siphon owns this subscription (it sent the REFER). Absorb: 200 OK and
        // read the sipfrag progress; on terminated, drop the subscription.
        let response = build_response(&message, 200, "OK", state.server_header.as_deref(), &[]);
        send_message_from(
            response,
            inbound.transport,
            inbound.remote_addr,
            inbound.connection_id,
            Some(inbound.local_addr),
            state,
        );

        let terminated = message
            .headers
            .get("Subscription-State")
            .map(|value| value.to_ascii_lowercase().contains("terminated"))
            .unwrap_or(false);
        // RFC 3515 §2.4.4: the sipfrag Status-Line in this NOTIFY *is* the
        // transfer's outcome — the 2xx to the REFER only said "accepted for
        // processing". Parsing it is what turns the control rail's transfer
        // report from "asked" into "happened".
        let sipfrag = crate::b2bua::transfer::parse_sipfrag_status(&message.body);
        debug!(
            call_id = %call_id,
            terminated,
            body = %String::from_utf8_lossy(&message.body),
            "B2BUA NOTIFY: siphon-owned REFER subscription progress"
        );
        // A terminating NOTIFY always yields a stage — including the
        // no-readable-status one — so a transfer is never left pending; the
        // verdict goes out alongside the subscription clear below, never instead
        // of it.
        if let Some(stage) = crate::control::TransferStage::from_notify(
            terminated,
            sipfrag.as_ref().map(|(code, _)| *code),
        ) {
            let mut outcome = crate::control::TransferOutcome::new(stage);
            if let Some((code, reason)) = &sipfrag {
                outcome = outcome.with_status(*code, reason);
            }
            control_forward_transfer_outcome(state, &call_id, outcome);
        }
        if terminated {
            state
                .call_actors
                .clear_refer_subscriptions_on_leg(&call_id, from_a_leg);
        }
        return;
    }

    // Transparent transfer: bridge the far end's NOTIFY to the referrer's leg.
    b2bua_forward_indialog_request(
        &inbound,
        &message,
        &call_id,
        from_a_leg,
        Method::Notify,
        crate::b2bua::actor::ForwardedMarker::Notify,
        state,
    );
}
