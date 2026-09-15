//! Re-INVITEs siphon originates on an established leg: the RFC 4028
//! session refresh and the media re-anchor.
use crate::dispatcher::*;

/// Send a B2BUA-initiated session refresh (RFC 4028) to the winning B-leg.
///
/// A normal re-INVITE on the dialog it refreshes (RFC 4028 §7.4), built from that
/// leg's own dialog like every other in-dialog request siphon originates: its
/// Call-ID, tags, route set, CSeq counter and remote target, and siphon's
/// Contact. The caller's INVITE contributes nothing, since it belongs to another
/// dialog.
///
/// RFC 4028 §7.4 asks for the `Supported`, `Require` and `Proxy-Require` of the
/// initial session refresh request, which on this dialog is the INVITE that set
/// it up, and for an offer in a refresh re-INVITE even when nothing changed. The
/// offer is the session description siphon has in force on the dialog
/// ([`session_refresh_offer`]).
///
/// Sent as a re-INVITE. RFC 4028 §7.4 recommends UPDATE only toward a peer known
/// to support it, which siphon does not track per leg.
pub fn b2bua_send_refresh_reinvite(call_id: &str, state: &DispatcherState) {
    let Some(session_expires) = state.call_actors.get_call(call_id).map(|call| {
        call.session_timer
            .as_ref()
            .map(|timer| timer.session_expires)
            .unwrap_or(1800)
    }) else {
        return;
    };
    let Some(callee) = state.call_actors.clone_leg(call_id, false) else {
        debug!(call_id = %call_id, "B2BUA refresh: no answered B-leg to refresh");
        return;
    };

    let mut headers = initial_option_tags(&callee);
    headers.push((
        "Session-Expires",
        format!("{session_expires};refresher=uac"),
    ));
    if let Some(timer_config) = &state.session_timer_config {
        headers.push(("Min-SE", timer_config.min_se.to_string()));
    }
    let offer = session_refresh_offer(&callee, call_id, state);

    // Reset the timer preemptively; the 200 OK confirms it.
    state.call_actors.reset_session_timer(call_id);

    debug!(call_id = %call_id, "B2BUA: sending session timer refresh re-INVITE");
    if !send_in_dialog_reinvite(call_id, false, offer, &headers, "reinvite:a2b", state) {
        debug!(
            call_id = %call_id,
            "B2BUA refresh: the callee leg went away before the re-INVITE went out"
        );
    }
}

/// The `Supported`, `Require` and `Proxy-Require` values of the INVITE that set
/// `leg`'s dialog up, which RFC 4028 §7.4 says a later session refresh on the
/// dialog MUST use. siphon's own option tags when that INVITE is not on the leg.
fn initial_option_tags(leg: &Leg) -> Vec<(&'static str, String)> {
    let initial = leg
        .b_leg_invite
        .as_ref()
        .and_then(|invite| invite.lock().ok().map(|invite| invite.headers.clone()));
    match initial {
        Some(initial) => ["Supported", "Require", "Proxy-Require"]
            .into_iter()
            .flat_map(|name| {
                initial
                    .get_all(name)
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .map(move |value| (name, value))
            })
            .collect(),
        None => {
            let mut own = crate::sip::headers::SipHeaders::new();
            advertise_supported_options(&mut own);
            advertise_option_tag(&mut own, "timer");
            own.get("Supported")
                .map(|value| vec![("Supported", value.clone())])
                .unwrap_or_default()
        }
    }
}

/// The offer a session refresh carries: the session description siphon has in
/// force on `callee`'s dialog, which is the offer the callee last accepted or the
/// answer siphon last sent it. A held call stays held.
///
/// RFC 3264 §8 decides its `o=`. When siphon has sent the callee no other SDP
/// since, it goes out byte for byte, and the unchanged version says the session
/// has not changed (RFC 4028 §7.4). When a later offer took a version and was
/// refused, the callee has seen that version, so the session in force goes out
/// under the next one. `None` when siphon never sent the dialog a session
/// description.
fn session_refresh_offer(callee: &Leg, call_id: &str, state: &DispatcherState) -> Option<Vec<u8>> {
    let mut sdp = callee.dialog.last_sent_sdp.clone()?;
    let last_version_sent = callee.dialog.sdp_version.checked_sub(1);
    let unchanged = last_version_sent.is_some_and(|version| {
        sdp_origin_identity(&sdp) == Some((callee.dialog.sdp_session_id, version))
    });
    if !unchanged {
        if let Some((session_id, version)) =
            state.call_actors.reserve_leg_sdp_version(call_id, false)
        {
            stamp_sdp_origin(&mut sdp, &state.sdp_name, session_id, version, None);
        }
    }
    Some(sdp)
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

/// Send a siphon-originated re-INVITE on one leg of a call carrying SDP someone
/// else described, tracked under `tracking_target` so the response arm knows
/// what it was for. Returns whether the re-INVITE reached the transport.
pub fn b2bua_send_reinvite_on_leg(
    call_id: &str,
    surviving_on_a_leg: bool,
    sdp_body: Vec<u8>,
    tracking_target: &str,
    state: &DispatcherState,
) -> bool {
    let Some(surviving) = state.call_actors.clone_leg(call_id, surviving_on_a_leg) else {
        return false;
    };
    // Re-originate the offered SDP under siphon's identity toward the surviving
    // leg. It was described by someone else (a transfer target, a `Replaces`
    // newcomer, a bridge peer), whose `o=` owner and address and `s=` a B2BUA must
    // not pass on (RFC 3264 §5 / RFC 4566 §5.2). The `o=` address is siphon's, as
    // on every SDP this leg has been sent before: RFC 3264 §8 lets only the
    // version change between them. The `c=` lines are not identity and stay, so
    // absent a media anchor the surviving leg still learns where the media is.
    // The `o=` is this leg's stable session id at a strictly greater version, so a
    // strict answerer does not take the changed media as unchanged, and the
    // configured attributes are stripped last, after any media engine rewrite the
    // caller made.
    let mut sdp_body = sdp_body;
    let surviving_host = state.a_leg_advertised_host(
        surviving.transport.local_addr,
        &surviving.transport.transport,
    );
    own_sdp_toward_leg(
        &mut sdp_body,
        "application/sdp",
        state,
        call_id,
        surviving_on_a_leg,
        Some(&surviving_host),
    );
    send_in_dialog_reinvite(
        call_id,
        surviving_on_a_leg,
        Some(sdp_body),
        &[],
        tracking_target,
        state,
    )
}

/// Send a re-INVITE siphon originates on one leg's own dialog (the A-leg, or the
/// winning B-leg), with `offer` as its SDP body and `extra_headers` on top of
/// what the dialog gives it. The offer is sent as given; shaping it is the
/// caller's. Returns whether the re-INVITE reached the transport.
///
/// Tracked under `tracking_target`, and that prefix is the point of the split:
/// `reinvite:` responses go through the bridged-pair arm (which forwards the
/// answer to the leg that originated the re-INVITE), while `bridge:` responses
/// are absorbed and drive the bridge's next step, since a bridged pair has no
/// originator leg: both sides are A-legs of their own call actor.
pub fn send_in_dialog_reinvite(
    call_id: &str,
    on_a_leg: bool,
    offer: Option<Vec<u8>>,
    extra_headers: &[(&str, String)],
    tracking_target: &str,
    state: &DispatcherState,
) -> bool {
    let Some(cseq) = state.call_actors.reserve_leg_cseq(call_id, on_a_leg) else {
        return false;
    };
    let Some(leg) = state.call_actors.clone_leg(call_id, on_a_leg) else {
        return false;
    };
    let Some(reinvite) = build_b2bua_in_dialog_request(
        &leg,
        state,
        Method::Invite,
        cseq,
        extra_headers,
        offer.clone().map(|body| ("application/sdp", body)),
    ) else {
        return false;
    };

    // Register a tracking leg keyed on the re-INVITE's Via branch so the
    // matching response arm handles + ACKs the leg's 200.
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
        leg.dialog.call_id.clone(),
        leg.dialog.local_tag.clone(),
        tracking_target.to_string(),
        branch,
        LegTransport {
            remote_addr: leg.transport.remote_addr,
            connection_id: leg.transport.connection_id,
            transport: leg.transport.transport,
            local_addr: leg.transport.local_addr,
        },
    );
    // No originator leg (siphon-originated) — empty stored Vias tells the
    // re-INVITE response arm to absorb the 200 rather than forward it.
    tracking.stored_vias = vec![];
    // The route set this re-INVITE carries (`build_b2bua_in_dialog_request`
    // builds its Route headers from the same dialog), kept on the tracking leg
    // so the ACK for the 200 follows the same path (RFC 3261 §12.2.1.1).
    tracking.dialog.route_set = leg.dialog.route_set.clone();
    // The offer becomes the session description in force on the leg's dialog
    // only when the leg accepts it.
    tracking.offered_sdp = offer;
    // The call can end between reading the leg above and registering this
    // entry: the other party hangs up, the call is removed and the leg is sent
    // its BYE. A re-INVITE sent now lands in the dialog that BYE ends, so report
    // the leg as gone, which every caller already handles.
    if !state.call_actors.add_b_leg(call_id, tracking) {
        debug!(
            call_id = %call_id,
            tracking = %tracking_target,
            "B2BUA: call ended before its siphon-originated re-INVITE went out, not sending it"
        );
        return false;
    }

    let (dest, transport) = resolve_in_dialog_destination(
        &leg.dialog.route_set,
        state,
        leg.transport.remote_addr,
        leg.transport.transport,
    );
    send_message_from(
        reinvite,
        transport,
        dest,
        leg.transport.connection_id,
        leg.transport.local_addr,
        state,
    );
    debug!(
        call_id = %call_id,
        on_a_leg,
        tracking = %tracking_target,
        "B2BUA: sent siphon-originated re-INVITE"
    );
    true
}
