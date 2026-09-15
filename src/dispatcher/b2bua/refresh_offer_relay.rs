//! The offer a peer answers siphon's offerless session refresh with.
//!
//! A refresh on a dialog siphon holds no session description on is a re-INVITE
//! without an offer toward a peer that allows no UPDATE (RFC 4028 §7.4), and its
//! 2xx brings the peer's offer. The ACK to that 2xx has to carry the answer
//! (RFC 3261 §13.2.2.4, RFC 3264 §4), and siphon has no answer of its own: the
//! other party of the call has it. So the offer goes to the other party in a
//! re-INVITE on that party's dialog, with siphon's identity on it and through the
//! media engine where the call is anchored, and that party's answer goes in the
//! ACK. Media then continues as the two parties agree.
//!
//! Until the answer is in, the ACK is held on the call and copies of the 2xx are
//! absorbed; afterwards every copy draws that same ACK. The refresh counts only
//! once the ACK has gone. When the other party refuses the offer or never
//! answers, or the media engine cannot anchor it, the call ends through its
//! teardown, and the held ACK goes out first with every stream rejected
//! ([`take_held_refresh_ack_rejecting_offer`]).

use crate::b2bua::actor::RefreshOfferRelay;
use crate::dispatcher::*;

/// Q.850 cause 102 ("recovery on timer expiry"), as for a session refresh nobody
/// answers: the refresh did not complete, and a timer is what ended the call.
const REFRESH_OFFER_UNANSWERED_REASON: &str =
    "Q.850;cause=102;text=\"Session refresh offer not answered\"";

/// An ACK owed to a dialog's 2xx, and where it goes: what leaves ahead of that
/// dialog's BYE when the call ends before the ACK could carry its answer.
pub struct HeldAck {
    pub ack: SipMessage,
    pub transport: Transport,
    pub destination: SocketAddr,
    pub local_addr: Option<SocketAddr>,
}

/// Take a response to a session refresh siphon sent without an offer, when it is
/// a 2xx carrying one or a copy of such a 2xx. Returns `true` when the response is
/// taken here, and `false` for every other response.
///
/// The first such 2xx holds its ACK on the call and relays its offer to the other
/// party ([`relay_refresh_offer`]). A copy is absorbed while the answer is out, and
/// ACKed again, answer included, once it is in.
pub fn intercept_refresh_offer(
    call_id: &str,
    branch: &str,
    message: &SipMessage,
    status_code: u16,
    response_source: SocketAddr,
    state: &DispatcherState,
    snapshot: &BLegResponseSnapshot,
) -> bool {
    let held = state.call_actors.get_call(call_id).and_then(|call| {
        call.refresh_offer_relays
            .iter()
            .find(|relay| relay.refresh_branch == branch)
            .cloned()
    });
    if let Some(relay) = held {
        if relay.sent && (200..300).contains(&status_code) {
            debug!(call_id = %call_id, "B2BUA: ACKing a copy of the refresh 2xx with the answer it drew");
            send_held_ack(&relay, state);
        }
        return true;
    }

    let Some(direction) = snapshot
        .b_leg_target
        .as_deref()
        .and_then(|target| target.strip_prefix("reinvite:"))
    else {
        return false;
    };
    // siphon's own re-INVITE (no originator Via), sent without an offer.
    if !snapshot.b_leg_stored_vias.is_empty()
        || snapshot.b_leg_offered_sdp.is_some()
        || !(200..300).contains(&status_code)
    {
        return false;
    }
    let Some(offer) = sdp_in_body(message_content_type(message), &message.body) else {
        return false;
    };
    // A re-INVITE sent toward the B-leg refreshed the callee's dialog.
    let refreshed_on_a_leg = direction != "a2b";
    relay_refresh_offer(
        call_id,
        branch,
        refreshed_on_a_leg,
        message,
        offer,
        response_source,
        state,
    );
    true
}

/// Hold the ACK for `answer_2xx`, the 2xx that brought `offer` back to siphon's
/// offerless refresh of one dialog, and send the offer to the other party of the
/// call in a re-INVITE on that party's dialog.
fn relay_refresh_offer(
    call_id: &str,
    refresh_branch: &str,
    refreshed_on_a_leg: bool,
    answer_2xx: &SipMessage,
    offer: Vec<u8>,
    response_source: SocketAddr,
    state: &DispatcherState,
) {
    let Some(refreshed) = state.call_actors.clone_leg(call_id, refreshed_on_a_leg) else {
        return;
    };
    let Some(ack) = build_ack_for_owned_leg(
        &refreshed,
        answer_2xx,
        &TransactionKey::generate_branch(),
        state,
    ) else {
        warn!(call_id = %call_id, "B2BUA: cannot build the ACK for a refresh 2xx that carried an offer; ending the call");
        end_call(call_id, state);
        return;
    };
    let (destination, transport) = resolve_in_dialog_destination(
        &refreshed.dialog.route_set,
        state,
        refreshed.transport.remote_addr,
        refreshed.transport.transport,
    );
    let relay = RefreshOfferRelay {
        refreshed_on_a_leg,
        refresh_branch: refresh_branch.to_string(),
        refresh_answer_headers: answer_2xx.headers.clone(),
        relay_branch: None,
        ack,
        offer: offer.clone(),
        transport,
        destination,
        connection_id: refreshed.transport.connection_id,
        local_addr: refreshed.transport.local_addr,
        sent: false,
    };
    match state.call_actors.get_call_mut(call_id) {
        Some(mut call) => call.refresh_offer_relays.push(relay),
        None => return,
    }

    let other_on_a_leg = !refreshed_on_a_leg;
    let Some(relayed_offer) =
        offer_toward_other_party(call_id, refreshed_on_a_leg, offer, response_source, state)
    else {
        warn!(call_id = %call_id, "B2BUA: the media engine cannot anchor the offer a refresh drew; ending the call");
        end_call(call_id, state);
        return;
    };
    let (headers, requested_session_expires) = state
        .call_actors
        .leg_session_timer(call_id, other_on_a_leg)
        .map(|timer| {
            (
                session_timer_request_headers(&timer),
                Some(timer.refresh_interval()),
            )
        })
        .unwrap_or_default();
    let request = InDialogRequest {
        method: Method::Invite,
        body: Some(relayed_offer),
        extra_headers: &headers,
        tracking_target: if other_on_a_leg {
            "reinvite:b2a"
        } else {
            "reinvite:a2b"
        },
        requested_session_expires,
    };
    let sent = send_in_dialog_request(
        call_id,
        other_on_a_leg,
        request,
        |relay_branch| {
            if let Some(mut call) = state.call_actors.get_call_mut(call_id) {
                if let Some(relay) = call
                    .refresh_offer_relays
                    .iter_mut()
                    .find(|relay| relay.refresh_branch == refresh_branch)
                {
                    relay.relay_branch = Some(relay_branch.to_string());
                }
            }
        },
        state,
    );
    if sent {
        debug!(call_id = %call_id, refreshed_on_a_leg, "B2BUA: relayed the offer a refresh drew to the other party");
    } else {
        warn!(call_id = %call_id, "B2BUA: the other party is gone before the offer a refresh drew could reach it; ending the call");
        end_call(call_id, state);
    }
}

/// `offer`, from the party whose dialog siphon refreshed, as the other party is
/// sent it: through the media engine when the call is anchored, then with siphon's
/// identity toward that party's dialog and the configured attributes stripped.
/// `None` when the call is anchored and the engine cannot take the offer.
fn offer_toward_other_party(
    call_id: &str,
    refreshed_on_a_leg: bool,
    offer: Vec<u8>,
    response_source: SocketAddr,
    state: &DispatcherState,
) -> Option<Vec<u8>> {
    let a_leg_call_id = state
        .call_actors
        .get_call(call_id)
        .map(|call| call.a_leg.dialog.call_id.clone())?;
    let mut body = match reoffer_through_media_engine(
        state,
        &a_leg_call_id,
        refreshed_on_a_leg,
        response_source.ip(),
        &offer,
    ) {
        ReofferOutcome::NotAnchored => offer,
        ReofferOutcome::Rewritten(rewritten) => rewritten,
        ReofferOutcome::NoOfferTag | ReofferOutcome::Failed(_) => return None,
    };
    let other = state.call_actors.clone_leg(call_id, !refreshed_on_a_leg)?;
    let host = state.a_leg_advertised_host(other.transport.local_addr, &other.transport.transport);
    own_sdp_toward_leg(
        &mut body,
        "application/sdp",
        state,
        call_id,
        !refreshed_on_a_leg,
        Some(&host),
    );
    Some(body)
}

/// Finish the relay a final response on `branch` belongs to, when it is the
/// re-INVITE that carried a refresh's offer to the other party.
///
/// A 2xx carries that party's answer: it goes in the held ACK, with siphon's
/// identity toward the refreshed dialog, and the ACK goes out. The refresh is then
/// done, and the refreshed dialog's session timer is set from the 2xx that drew
/// the offer (RFC 4028 §7.2). A refusal, or a 2xx with no answer, ends the call.
pub fn complete_refresh_offer_relay(
    call_id: &str,
    branch: &str,
    status_code: u16,
    message: &SipMessage,
    state: &DispatcherState,
) {
    if status_code < 200 {
        return;
    }
    let Some(relay) = state.call_actors.get_call(call_id).and_then(|call| {
        call.refresh_offer_relays
            .iter()
            .find(|relay| !relay.sent && relay.relay_branch.as_deref() == Some(branch))
            .cloned()
    }) else {
        return;
    };
    let answer = sdp_in_body(message_content_type(message), &message.body)
        .filter(|_| (200..300).contains(&status_code));
    let Some(mut answer) = answer else {
        warn!(
            call_id = %call_id,
            status = status_code,
            "B2BUA: the other party did not answer the offer a refresh drew; ending the call"
        );
        end_call(call_id, state);
        return;
    };
    let Some(refreshed) = state
        .call_actors
        .clone_leg(call_id, relay.refreshed_on_a_leg)
    else {
        return;
    };
    let host = state.a_leg_advertised_host(
        refreshed.transport.local_addr,
        &refreshed.transport.transport,
    );
    own_sdp_toward_leg(
        &mut answer,
        "application/sdp",
        state,
        call_id,
        relay.refreshed_on_a_leg,
        Some(&host),
    );
    let mut ack = relay.ack.clone();
    set_sdp_body(&mut ack, answer.clone(), "application/sdp");
    let sent = RefreshOfferRelay {
        ack,
        sent: true,
        ..relay
    };
    if let Some(mut call) = state.call_actors.get_call_mut(call_id) {
        if let Some(held) = call
            .refresh_offer_relays
            .iter_mut()
            .find(|held| held.refresh_branch == sent.refresh_branch)
        {
            *held = sent.clone();
        }
    }
    state
        .call_actors
        .set_leg_sent_sdp(call_id, sent.refreshed_on_a_leg, answer);
    debug!(call_id = %call_id, "B2BUA: ACKing the refresh 2xx with the other party's answer");
    send_held_ack(&sent, state);
    session_timer_on_response(
        call_id,
        sent.refreshed_on_a_leg,
        &sent.refresh_branch,
        200,
        &sent.refresh_answer_headers,
        None,
        state,
    );
}

/// The ACK still held for a refresh 2xx on `dialog_leg`'s dialog, completed with
/// an answer that rejects every stream, for a call ending before the other party
/// answered. Marks it sent. `None` when no such ACK is held.
///
/// RFC 3261 §13.2.2.4 still has the 2xx ACKed with a valid answer, and the BYE
/// that follows goes right after it ([`send_or_hold_bye`]).
pub fn take_held_refresh_ack_rejecting_offer(
    call_id: &str,
    dialog_leg: &Leg,
    state: &DispatcherState,
) -> Option<HeldAck> {
    let mut call = state.call_actors.get_call_mut(call_id)?;
    let index = call.refresh_offer_relays.iter().position(|relay| {
        !relay.sent
            && relay
                .ack
                .headers
                .call_id()
                .is_some_and(|ack_call_id| *ack_call_id == dialog_leg.dialog.call_id)
    })?;
    let relay = call.refresh_offer_relays[index].clone();
    let mut body = rejecting_answer(&relay.offer);
    let dialog_call_id = dialog_leg.dialog.call_id.as_str();
    if call.a_leg.dialog.call_id == dialog_call_id {
        stamp_b_leg_origin(
            &mut body,
            "application/sdp",
            &mut call.a_leg,
            &relay.transport,
            state,
        );
        call.a_leg.dialog.last_sent_sdp = Some(body.clone());
    } else if let Some(leg) = call
        .b_legs
        .iter_mut()
        .find(|leg| leg.dialog.call_id == dialog_call_id)
    {
        stamp_b_leg_origin(&mut body, "application/sdp", leg, &relay.transport, state);
        leg.dialog.last_sent_sdp = Some(body.clone());
    } else {
        let mut detached = dialog_leg.clone();
        stamp_b_leg_origin(
            &mut body,
            "application/sdp",
            &mut detached,
            &relay.transport,
            state,
        );
    }
    let held = &mut call.refresh_offer_relays[index];
    set_sdp_body(&mut held.ack, body, "application/sdp");
    held.sent = true;
    Some(HeldAck {
        ack: held.ack.clone(),
        transport: held.transport,
        destination: held.destination,
        local_addr: held.local_addr,
    })
}

/// Send a relay's ACK on the refreshed dialog's flow.
fn send_held_ack(relay: &RefreshOfferRelay, state: &DispatcherState) {
    if relay.refreshed_on_a_leg {
        send_message_from(
            relay.ack.clone(),
            relay.transport,
            relay.destination,
            relay.connection_id,
            relay.local_addr,
            state,
        );
    } else {
        send_b2bua_to_bleg(
            relay.ack.clone(),
            relay.transport,
            relay.destination,
            relay.local_addr,
            state,
        );
    }
}

/// End a call whose refresh offer found no answer, through its teardown.
fn end_call(call_id: &str, state: &DispatcherState) {
    b2bua_terminate_call_inner(
        call_id,
        Some(REFRESH_OFFER_UNANSWERED_REASON),
        "timeout",
        state,
    );
}
