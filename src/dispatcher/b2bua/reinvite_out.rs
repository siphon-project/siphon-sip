//! Requests siphon originates on an established leg's own dialog: the media
//! re-anchor re-INVITE, and the tracked send the RFC 4028 session refresh goes
//! out through as well ([`b2bua_send_session_refresh`]).
use crate::dispatcher::*;

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
///
/// The re-INVITE is a session refresh of that dialog too (RFC 4028 §7.4): it
/// carries the dialog's session timer, or asks for the one siphon runs on the
/// call where the dialog runs none ([`session_timer_headers_for_leg`]), so its 2xx
/// sets the dialog's timer, refresher included.
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
    // A re-INVITE is a session refresh of its dialog (RFC 4028 §7.4).
    let (timer_headers, requested_session_expires) =
        session_timer_headers_for_leg(call_id, on_a_leg, state);
    let mut headers = extra_headers.to_vec();
    for (name, value) in timer_headers {
        headers.push((name, value));
    }
    send_in_dialog_request(
        call_id,
        on_a_leg,
        InDialogRequest {
            method: Method::Invite,
            body: offer,
            extra_headers: &headers,
            tracking_target,
            requested_session_expires,
        },
        |_| {},
        state,
    )
}

/// A request siphon originates on one leg's own dialog, for
/// [`send_in_dialog_request`].
pub struct InDialogRequest<'a> {
    /// INVITE or UPDATE, whose response the tracking prefix routes.
    pub method: Method,
    /// The SDP body, sent as given; shaping it is the caller's.
    pub body: Option<Vec<u8>>,
    /// Headers on top of what the dialog gives the request.
    pub extra_headers: &'a [(&'a str, String)],
    /// The tracking-leg target the response arm keys on (`reinvite:a2b`,
    /// `update:b2a`, ...).
    pub tracking_target: &'a str,
    /// The session interval the request's `Session-Expires` asks for, kept on the
    /// tracking leg for the 2xx (RFC 4028 §7.2).
    pub requested_session_expires: Option<u32>,
}

/// Send `request` on one leg's own dialog (the A-leg, or the winning B-leg),
/// tracked so its response reaches the arm its target names. Returns whether the
/// request reached the transport.
///
/// `before_send` runs with the request's Via branch once the request is tracked
/// and before it goes out, so a response that comes straight back finds what the
/// caller records against that branch. Over UDP the request is retransmitted on
/// the RFC 3261 §17.1 timers until a response arrives, like every request siphon
/// sends a B-leg: without them one lost datagram is a request that never arrived.
pub fn send_in_dialog_request(
    call_id: &str,
    on_a_leg: bool,
    request: InDialogRequest<'_>,
    before_send: impl FnOnce(&str),
    state: &DispatcherState,
) -> bool {
    let InDialogRequest {
        method,
        body,
        extra_headers,
        tracking_target,
        requested_session_expires,
    } = request;
    let Some(cseq) = state.call_actors.reserve_leg_cseq(call_id, on_a_leg) else {
        return false;
    };
    let Some(leg) = state.call_actors.clone_leg(call_id, on_a_leg) else {
        return false;
    };
    let method_name = method.as_str().to_string();
    let Some(message) = build_b2bua_in_dialog_request(
        &leg,
        state,
        method,
        cseq,
        extra_headers,
        body.clone().map(|body| ("application/sdp", body)),
    ) else {
        return false;
    };

    // Register a tracking leg keyed on the request's Via branch so the matching
    // response arm handles the leg's response (and ACKs a 200 to a re-INVITE).
    let branch = message
        .headers
        .get("Via")
        .and_then(|via| via.split(";branch=").nth(1))
        .map(|rest| rest.split([';', ',', ' ']).next().unwrap_or("").to_string())
        .unwrap_or_default();
    if branch.is_empty() {
        warn!(call_id = %call_id, method = %method_name, "B2BUA: siphon-originated in-dialog request has no Via branch");
        return false;
    }
    let mut tracking = Leg::new_b_leg(
        leg.dialog.call_id.clone(),
        leg.dialog.local_tag.clone(),
        tracking_target.to_string(),
        branch.clone(),
        LegTransport {
            remote_addr: leg.transport.remote_addr,
            connection_id: leg.transport.connection_id,
            transport: leg.transport.transport,
            local_addr: leg.transport.local_addr,
        },
    );
    // No originator leg (siphon-originated) — empty stored Vias tells the
    // response arm to absorb the response rather than forward it.
    tracking.stored_vias = vec![];
    // The route set this request carries (`build_b2bua_in_dialog_request` builds
    // its Route headers from the same dialog), kept on the tracking leg so the ACK
    // for a 200 follows the same path (RFC 3261 §12.2.1.1).
    tracking.dialog.route_set = leg.dialog.route_set.clone();
    // The offer becomes the session description in force on the leg's dialog
    // only when the leg accepts it.
    tracking.offered_sdp = body;
    tracking.request_session_expires = requested_session_expires;
    // The call can end between reading the leg above and registering this
    // entry: the other party hangs up, the call is removed and the leg is sent
    // its BYE. A request sent now lands in the dialog that BYE ends, so report
    // the leg as gone, which every caller already handles.
    if !state.call_actors.add_b_leg(call_id, tracking) {
        debug!(
            call_id = %call_id,
            tracking = %tracking_target,
            method = %method_name,
            "B2BUA: call ended before its siphon-originated in-dialog request went out, not sending it"
        );
        return false;
    }
    before_send(&branch);

    let (dest, transport) = resolve_in_dialog_destination(
        &leg.dialog.route_set,
        state,
        leg.transport.remote_addr,
        leg.transport.transport,
    );
    let data = bytes::Bytes::from(message.to_bytes());
    arm_b2bua_retransmit(
        &message,
        &data,
        transport,
        dest,
        udp_egress_source(transport, dest, leg.transport.local_addr),
        state,
    );
    send_message_from(
        message,
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
        method = %method_name,
        "B2BUA: sent siphon-originated in-dialog request"
    );
    true
}
