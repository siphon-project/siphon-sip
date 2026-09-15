//! RFC 3261 §15: a BYE waits for the ACK of the 2xx siphon sent on its dialog.
//!
//! siphon is the UAS of every dialog it answered, and a UAS "MUST NOT send a BYE
//! on a confirmed dialog until it has received an ACK for its 2xx response or
//! until the server transaction times out". A call can end inside that window, and
//! a transfer can release a party inside it: the callee hangs up the moment it
//! answers, a timer, a script or the control plane ends the call, a REFER or a
//! `Replaces` takes the dialog away. Everything else runs at once. Only the BYE to
//! that party is parked, in `held_byes`, while its 2xx keeps being retransmitted
//! (§13.3.1.4).
//!
//! The party's ACK sends the BYE right after it ([`release_held_bye`]); at 64×T1
//! `sweep_unacked_uas_2xx` sends it instead, once. A party that sends its own BYE
//! first has ended the dialog itself ([`answer_caller_bye_for_held_dialog`]).

use crate::dispatcher::*;

/// Where a BYE goes: the dialog's next hop and the socket it leaves from.
struct ByeRoute {
    transport: Transport,
    destination: SocketAddr,
    connection_id: ConnectionId,
    local_addr: Option<SocketAddr>,
}

/// Send `bye` on `leg`'s dialog, after whatever that dialog is still owed.
///
/// Every BYE siphon sends to end a call or to release a party goes through here:
/// the other party of a BYE (`handle_b2bua_bye`), both legs of every teardown
/// through `b2bua_terminate_call_inner`, the referrer a REFER releases, the
/// survivor of a transfer that failed after the referrer left, and the party a
/// `Replaces` takes over.
///
/// What is owed is looked up by the dialog's Call-ID, never by the slot the leg
/// sits in: a takeover of the callee's side moves the caller into the B-leg slot.
///
/// - siphon is the dialog's UAS and the peer has not ACKed siphon's 2xx: the BYE
///   is held until that ACK, or until 64×T1 (§15, §13.3.1.4);
/// - siphon is the dialog's UAC and still owes the ACK for a 2xx that carried an
///   offer: that ACK goes out first, every stream rejected, then the BYE
///   (§13.2.2.4);
/// - otherwise the BYE goes out now.
///
/// `sender` is how the BYE leaves, now or when a held BYE is released. The 64×T1
/// teardown is never held: its sweep has taken the answer out of the store before
/// the teardown runs.
pub fn send_or_hold_bye(
    internal_call_id: &str,
    leg: &Leg,
    bye: SipMessage,
    sender: ByeSender,
    state: &DispatcherState,
) {
    // RFC 3261 §12.2.1.1: the next hop is the first Route URI, not the cached
    // source of the INVITE. The socket is the leg's anchored one, so the Via
    // matches (see `build_b2bua_bye`).
    let (destination, transport) = resolve_in_dialog_destination(
        &leg.dialog.route_set,
        state,
        leg.transport.remote_addr,
        leg.transport.transport,
    );
    let route = ByeRoute {
        transport,
        destination,
        connection_id: leg.transport.connection_id,
        local_addr: leg.transport.local_addr,
    };
    let dialog_call_id = leg.dialog.call_id.as_str();

    let answer = state
        .uas_2xx_retransmits
        .get(dialog_call_id)
        .map(|entry| Arc::clone(entry.value()));
    if let Some(answer) = answer {
        hold_bye(
            internal_call_id,
            dialog_call_id,
            bye,
            route,
            sender,
            answer,
            state,
        );
        return;
    }

    // An ACK held for an offer: the callee's delayed offer, or the offer a peer
    // answered siphon's offerless session refresh with.
    let held_ack = take_held_ack_rejecting_offer(internal_call_id, leg, state)
        .map(|held| HeldAck {
            ack: held.ack,
            transport: held.transport,
            destination: held.destination,
            local_addr: held.local_addr,
        })
        .or_else(|| take_held_refresh_ack_rejecting_offer(internal_call_id, leg, state));
    if let Some(held_ack) = held_ack {
        // One ordered unit when they share a next hop: sent separately over UDP
        // they can reach the peer BYE first, for a dialog it has not yet seen
        // confirmed.
        if held_ack.destination == route.destination && held_ack.transport == route.transport {
            send_in_order(vec![held_ack.ack, bye], &route, sender, state);
        } else {
            let ack_route = ByeRoute {
                transport: held_ack.transport,
                destination: held_ack.destination,
                connection_id: route.connection_id,
                local_addr: held_ack.local_addr,
            };
            send_one(held_ack.ack, &ack_route, sender, state);
            send_one(bye, &route, sender, state);
        }
        return;
    }

    send_one(bye, &route, sender, state);
}

/// Park `bye` until the ACK for `answer` arrives, unless that ACK has already
/// taken the answer.
fn hold_bye(
    internal_call_id: &str,
    dialog_call_id: &str,
    bye: SipMessage,
    route: ByeRoute,
    sender: ByeSender,
    answer: Arc<UnackedAnswer>,
    state: &DispatcherState,
) {
    // A BYE already held for this dialog stays the one that is sent: a second
    // teardown racing the first adds none.
    state
        .held_byes
        .entry(dialog_call_id.to_string())
        .or_insert_with(|| HeldBye {
            bye,
            transport: route.transport,
            destination: route.destination,
            connection_id: route.connection_id,
            local_addr: route.local_addr,
            sender,
            internal_call_id: internal_call_id.to_string(),
            answer: Arc::clone(&answer),
        });

    // The ACK or the 64×T1 sweep may have taken the answer between the lookup and
    // the insert, and then neither of them finds this BYE. Each side sends the BYE
    // only if it removes it from the store itself, so it goes out exactly once
    // whichever way that race goes.
    let still_waiting = state
        .uas_2xx_retransmits
        .get(dialog_call_id)
        .is_some_and(|entry| Arc::ptr_eq(entry.value(), &answer));
    if still_waiting {
        debug!(
            call_id = %internal_call_id,
            %dialog_call_id,
            "RFC 3261 §15: the 2xx on this dialog is not ACKed yet, so its BYE waits for the ACK"
        );
        return;
    }
    release_held_bye(dialog_call_id, state);
}

/// Send the BYE held for the dialog `dialog_call_id`, if one is held, and stop the
/// retransmission of the 2xx it waited on. Returns whether a BYE went out.
///
/// Called for the ACK on that dialog, right after it is absorbed; by the 64×T1
/// sweep; and by a hold that finds its answer already taken.
pub fn release_held_bye(dialog_call_id: &str, state: &DispatcherState) -> bool {
    let Some((_, held)) = state.held_byes.remove(dialog_call_id) else {
        return false;
    };
    stop_held_answer(dialog_call_id, &held, state);
    debug!(
        call_id = %held.internal_call_id,
        destination = %held.destination,
        "B2BUA: sending the BYE held for the ACK"
    );
    let route = ByeRoute {
        transport: held.transport,
        destination: held.destination,
        connection_id: held.connection_id,
        local_addr: held.local_addr,
    };
    send_one(held.bye, &route, held.sender, state);
    true
}

/// Answer a BYE for a dialog whose call has ended with siphon's own BYE for it
/// still held. Returns `false`, having done nothing, when no BYE is held for
/// `sip_call_id`.
///
/// The peer ended the dialog first, so its BYE is answered 200 (RFC 3261
/// §15.1.2), not 481: siphon has been retransmitting a 2xx for it all along. The
/// retransmission stops and the held BYE is dropped, since the dialog it would
/// have ended is gone.
pub fn answer_caller_bye_for_held_dialog(
    inbound: &InboundMessage,
    message: &SipMessage,
    sip_call_id: &str,
    state: &DispatcherState,
) -> bool {
    let Some((_, held)) = state.held_byes.remove(sip_call_id) else {
        return false;
    };
    stop_held_answer(sip_call_id, &held, state);
    debug!(
        call_id = %held.internal_call_id,
        "B2BUA: the peer hung up before its held BYE went out; answered, and the held BYE dropped"
    );
    let response = build_response(message, 200, "OK", state.server_header.as_deref(), &[]);
    send_message_from(
        response,
        inbound.transport,
        inbound.remote_addr,
        inbound.connection_id,
        Some(inbound.local_addr),
        state,
    );
    true
}

/// Stop retransmitting the 2xx `held` waited on. Only the entry that is that very
/// answer is removed, so an answer the ACK or the sweep already took is left
/// alone.
fn stop_held_answer(dialog_call_id: &str, held: &HeldBye, state: &DispatcherState) {
    if let Some((_, answer)) = state
        .uas_2xx_retransmits
        .remove_if(dialog_call_id, |_, current| {
            Arc::ptr_eq(current, &held.answer)
        })
    {
        answer.cancel.notify_one();
    }
}

fn send_one(message: SipMessage, route: &ByeRoute, sender: ByeSender, state: &DispatcherState) {
    match sender {
        ByeSender::Dialog => send_message_from(
            message,
            route.transport,
            route.destination,
            route.connection_id,
            route.local_addr,
            state,
        ),
        ByeSender::BLeg => send_b2bua_to_bleg(
            message,
            route.transport,
            route.destination,
            route.local_addr,
            state,
        ),
    }
}

fn send_in_order(
    messages: Vec<SipMessage>,
    route: &ByeRoute,
    sender: ByeSender,
    state: &DispatcherState,
) {
    match sender {
        ByeSender::Dialog => send_messages_in_order_from(
            messages,
            route.transport,
            route.destination,
            route.connection_id,
            route.local_addr,
            state,
        ),
        ByeSender::BLeg => send_b2bua_sequence_to_bleg(
            messages,
            route.transport,
            route.destination,
            route.local_addr,
            state,
        ),
    }
}
