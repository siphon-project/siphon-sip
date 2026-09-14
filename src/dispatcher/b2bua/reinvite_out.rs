//! Re-INVITEs siphon originates on an established leg: the RFC 4028
//! session refresh and the media re-anchor.
use crate::dispatcher::*;

/// Send a B2BUA-initiated refresh re-INVITE to the B-leg.
pub fn b2bua_send_refresh_reinvite(call_id: &str, state: &DispatcherState) {
    let (a_leg_invite, a_leg_from_tag, winner_b_leg, session_expires) =
        match state.call_actors.get_call(call_id) {
            Some(call) => {
                let b_leg = call.winner.and_then(|i| call.b_legs.get(i).cloned());
                let se = call
                    .session_timer
                    .as_ref()
                    .map(|t| t.session_expires)
                    .unwrap_or(1800);
                (
                    call.a_leg_invite.clone(),
                    call.a_leg.dialog.remote_tag.clone().unwrap_or_default(),
                    b_leg,
                    se,
                )
            }
            None => return,
        };

    let (invite_arc, b_leg) = match (a_leg_invite, winner_b_leg) {
        (Some(invite), Some(b_leg)) => (invite, b_leg),
        _ => {
            debug!(call_id = %call_id, "B2BUA refresh: missing invite or B-leg");
            return;
        }
    };

    let Ok(original) = invite_arc.lock() else {
        error!(call_id = %call_id, "invite_arc lock poisoned during session timer refresh");
        return;
    };
    let mut reinvite = original.clone();
    drop(original);

    // New Via/branch — sent-by is the socket this leg is anchored on, so the
    // refresh's response comes back where the request left from.
    let branch = TransactionKey::generate_branch();
    let transport_str = format!("{}", b_leg.transport.transport).to_uppercase();
    let (via_host, via_port) = leg_sent_by(&b_leg, state);
    let via_value = format!(
        "SIP/2.0/{} {}:{};branch={}",
        transport_str, via_host, via_port, branch,
    );
    reinvite.headers.set("Via", via_value);

    // Update Request-URI to B-leg's remote Contact (RFC 3261 §12.2.1.1),
    // falling back to the original dial target if Contact is not yet captured.
    let reinvite_ruri = b_leg
        .dialog
        .remote_contact
        .as_deref()
        .or(b_leg.dialog.target_uri.as_deref())
        .unwrap_or_default();
    if !reinvite_ruri.is_empty() {
        if let Ok(target_parsed) = parse_uri_standalone(reinvite_ruri) {
            reinvite.start_line = StartLine::Request(crate::sip::message::RequestLine {
                method: crate::sip::message::Method::Invite,
                request_uri: target_parsed,
                version: crate::sip::message::Version::sip_2_0(),
            });
        }
    }

    // Rewrite A-leg dialog headers → B-leg dialog headers.
    // Source is the original out-of-dialog A-leg INVITE (no To-tag), so
    // pass None — the refresh re-INVITE's To-tag, if needed, is set by
    // the in-dialog construction logic elsewhere.
    crate::b2bua::actor::Dialog::rewrite_headers(
        &mut reinvite,
        &b_leg.dialog.call_id,
        &a_leg_from_tag,
        &b_leg.dialog.local_tag,
        None,
    );

    // Rewrite From URI host to our advertised address (topology hiding)
    let b2bua_host = state.via_host(&b_leg.transport.transport);
    if let Some(from) = reinvite
        .headers
        .get("From")
        .or_else(|| reinvite.headers.get("f"))
    {
        reinvite.headers.set(
            "From",
            crate::b2bua::actor::rewrite_uri_host(from, &b2bua_host),
        );
    }

    // Regenerate CSeq for B-leg dialog
    reinvite
        .headers
        .set("CSeq", format!("{} INVITE", b_leg.dialog.local_cseq));

    // Decrement Max-Forwards (RFC 7332)
    let _ = crate::proxy::core::decrement_max_forwards(&mut reinvite.headers);

    // Set Contact to what we advertised to B-leg
    if let Some(ref contact) = b_leg.dialog.local_contact {
        reinvite.headers.set("Contact", contact.clone());
    }

    // Set session timer headers
    reinvite.headers.remove("Session-Expires");
    reinvite.headers.remove("Min-SE");
    reinvite.headers.add(
        "Session-Expires",
        format!("{};refresher=uac", session_expires),
    );
    if let Some(ref timer_config) = state.session_timer_config {
        reinvite
            .headers
            .add("Min-SE", timer_config.min_se.to_string());
    }
    if reinvite.headers.get("Supported").is_none() {
        reinvite.headers.add("Supported", "timer".to_string());
    }

    // Register new branch for response routing (reuse B-leg dialog identifiers)
    // Mark as re-INVITE so the response handler doesn't absorb it as a retransmission
    let mut new_b_leg = Leg::new_b_leg(
        b_leg.dialog.call_id.clone(),
        b_leg.dialog.local_tag.clone(),
        "reinvite:a2b".to_string(),
        branch.clone(),
        LegTransport {
            remote_addr: b_leg.transport.remote_addr,
            // Track the B-leg's live connection (consistent with the in-dialog
            // re-INVITE/UPDATE forward reuse) rather than a placeholder.
            connection_id: b_leg.transport.connection_id,
            transport: b_leg.transport.transport,
            // Inherit the real B-leg's anchored socket so the refresh's response
            // handling (which resolves the pin off the branch-matched leg) sends
            // the ACK back out the same socket.
            local_addr: b_leg.transport.local_addr,
        },
    );
    new_b_leg.stored_vias = vec![];
    // The ACK for this refresh's 200 has to traverse the same proxies the
    // re-INVITE did (RFC 3261 §12.2.1.1), so carry the B-leg's dialog route set
    // on the tracking leg — the response arm reads it back off this leg.
    new_b_leg.dialog.route_set = b_leg.dialog.route_set.clone();
    // Same race as `b2bua_send_reinvite_on_leg`: a call removed since it was read
    // above has already sent this leg its BYE, so no refresh goes out.
    if !state.call_actors.add_b_leg(call_id, new_b_leg) {
        debug!(
            call_id = %call_id,
            "B2BUA refresh: call ended before the re-INVITE went out, not sending it"
        );
        return;
    }

    // Reset timer preemptively (will be confirmed on 200 OK)
    state.call_actors.reset_session_timer(call_id);

    // Own the o= identity toward the B-leg on the refresh (RFC 3264 §8) so a
    // session-timer keepalive shares this leg's stable session-id + a monotonic
    // version rather than re-presenting the caller's forwarded o= (which would
    // read as a session change relative to the initial B-leg INVITE).
    if !reinvite.body.is_empty() {
        if let Some((sess_id, version)) = state.call_actors.reserve_leg_sdp_version(call_id, false)
        {
            stamp_sdp_origin(
                &mut reinvite.body,
                &state.sdp_name,
                sess_id,
                version,
                Some(&b2bua_host),
            );
            reinvite
                .headers
                .set("Content-Length", reinvite.body.len().to_string());
        }
    }

    debug!(call_id = %call_id, "B2BUA: sending session timer refresh re-INVITE");
    send_b2bua_to_bleg(
        reinvite,
        b_leg.transport.transport,
        b_leg.transport.remote_addr,
        b_leg.transport.local_addr,
        state,
    );

    // Increment B-leg CSeq after sending
    if let Some(mut call) = state.call_actors.get_call_mut(call_id) {
        if let Some(winner_idx) = call.winner {
            if let Some(b_leg) = call.b_legs.get_mut(winner_idx) {
                b_leg.dialog.local_cseq += 1;
            }
        }
    }
}

/// Re-INVITE the surviving leg of a siphon-terminated transfer with the transfer
/// target's SDP, so the surviving party's media re-points at the target instead
/// of the departed referrer (RFC 3261 §14). `surviving_on_a_leg` selects the
/// A-leg (referrer was the B-leg) or the winning B-leg (referrer was the A-leg).
///
/// Tracked as a `reinvite:` leg keyed on the re-INVITE's Via branch so the
/// re-INVITE response arm ACKs the 200 — a bare re-INVITE would leave the 200
/// unACKed and the leg retransmitting.
pub fn b2bua_send_media_reinvite(
    call_id: &str,
    surviving_on_a_leg: bool,
    sdp_body: Vec<u8>,
    state: &DispatcherState,
) {
    let tracking = if surviving_on_a_leg {
        "reinvite:b2a"
    } else {
        "reinvite:a2b"
    };
    b2bua_send_reinvite_on_leg(call_id, surviving_on_a_leg, sdp_body, tracking, state);
}

/// Send a siphon-originated re-INVITE on one leg of a call, tracked under
/// `tracking_target` so the response arm knows what it was for.
///
/// The tracking prefix is the whole point of the split: `reinvite:` responses go
/// through the bridged-pair arm (which forwards the answer to the leg that
/// originated the re-INVITE), while `bridge:` responses are absorbed and drive
/// the bridge's next step — a bridged pair has no originator leg, both sides are
/// A-legs of their own call actor. Returns whether the re-INVITE reached the
/// transport.
pub fn b2bua_send_reinvite_on_leg(
    call_id: &str,
    surviving_on_a_leg: bool,
    sdp_body: Vec<u8>,
    tracking_target: &str,
    state: &DispatcherState,
) -> bool {
    let Some(cseq) = state
        .call_actors
        .reserve_leg_cseq(call_id, surviving_on_a_leg)
    else {
        return false;
    };
    let Some(surviving) = state.call_actors.clone_leg(call_id, surviving_on_a_leg) else {
        return false;
    };
    // Re-originate the offered SDP under siphon's o= identity (RFC 3264 §5 /
    // RFC 4566 §5.2) — the target's answer SDP still carries the target's o=
    // owner, which a B2BUA must not leak to the surviving leg. The connection
    // address is left untouched (`None`) so, absent a media anchor, the surviving
    // leg still learns the target's media address.
    let mut sdp_body = sdp_body;
    sanitize_sdp_identity(&mut sdp_body, &state.sdp_name, None);
    // Own the o= session-id/version toward the surviving leg so this re-anchor
    // offer carries a strictly greater version than the last SDP that leg saw
    // (RFC 3264 §8) under a stable session-id — otherwise a strict answerer may
    // treat the changed media as unchanged. Connection address left untouched.
    if let Some((sess_id, version)) = state
        .call_actors
        .reserve_leg_sdp_version(call_id, surviving_on_a_leg)
    {
        stamp_sdp_origin(&mut sdp_body, &state.sdp_name, sess_id, version, None);
    }
    let Some(reinvite) = build_b2bua_in_dialog_request(
        &surviving,
        state,
        Method::Invite,
        cseq,
        &[],
        Some(("application/sdp", sdp_body)),
    ) else {
        return false;
    };

    // Register a tracking leg keyed on the re-INVITE's Via branch so the
    // matching response arm handles + ACKs the surviving leg's 200.
    let branch = reinvite
        .headers
        .get("Via")
        .and_then(|via| via.split(";branch=").nth(1))
        .map(|rest| rest.split([';', ',', ' ']).next().unwrap_or("").to_string())
        .unwrap_or_default();
    if branch.is_empty() {
        warn!(call_id = %call_id, "B2BUA: siphon-originated re-INVITE has no Via branch");
        return false;
    }
    let mut tracking = Leg::new_b_leg(
        surviving.dialog.call_id.clone(),
        surviving.dialog.local_tag.clone(),
        tracking_target.to_string(),
        branch,
        LegTransport {
            remote_addr: surviving.transport.remote_addr,
            connection_id: surviving.transport.connection_id,
            transport: surviving.transport.transport,
            local_addr: surviving.transport.local_addr,
        },
    );
    // No originator leg (siphon-originated) — empty stored Vias tells the
    // re-INVITE response arm to absorb the 200 rather than forward it.
    tracking.stored_vias = vec![];
    // The route set this re-INVITE carries (`build_b2bua_in_dialog_request`
    // builds its Route headers from the same dialog), kept on the tracking leg
    // so the ACK for the 200 follows the same path (RFC 3261 §12.2.1.1).
    tracking.dialog.route_set = surviving.dialog.route_set.clone();
    // The call can end between reading the leg above and registering this
    // entry: the other party hangs up, the call is removed and the surviving
    // leg is sent its BYE. A re-INVITE sent now lands in the dialog that BYE
    // ends, so report the leg as gone, which every caller already handles.
    if !state.call_actors.add_b_leg(call_id, tracking) {
        debug!(
            call_id = %call_id,
            tracking = %tracking_target,
            "B2BUA: call ended before its siphon-originated re-INVITE went out, not sending it"
        );
        return false;
    }

    let (dest, transport) = resolve_in_dialog_destination(
        &surviving.dialog.route_set,
        state,
        surviving.transport.remote_addr,
        surviving.transport.transport,
    );
    send_message_from(
        reinvite,
        transport,
        dest,
        surviving.transport.connection_id,
        surviving.transport.local_addr,
        state,
    );
    debug!(
        call_id = %call_id,
        surviving_on_a_leg,
        tracking = %tracking_target,
        "B2BUA: sent siphon-originated re-INVITE"
    );
    true
}
