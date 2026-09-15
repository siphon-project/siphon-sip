//! RFC 3261 §15: the caller's BYE waits for the ACK of the 2xx siphon sent it.
//!
//! siphon is the UAS of the caller's dialog, and a UAS "MUST NOT send a BYE on a
//! confirmed dialog until it has received an ACK for its 2xx response or until the
//! server transaction times out". A call can still end inside that window: the
//! callee hangs up the moment it answers, or a timer, a script or the control
//! plane ends the call. The rest of the teardown runs at once, the callee's BYE
//! included. Only the caller's BYE is parked, in `held_a_leg_byes`, while the 2xx
//! keeps being retransmitted to the caller (§13.3.1.4).
//!
//! The caller's ACK sends the BYE right after it ([`release_held_a_leg_bye`]); at
//! 64×T1 `sweep_unacked_uas_2xx` sends it instead, once. A caller that sends its
//! own BYE first has ended the dialog itself
//! ([`answer_caller_bye_for_held_dialog`]).

use crate::dispatcher::*;

/// Send `bye` to the caller on `a_leg`, or hold it until the caller ACKs the 2xx
/// siphon sent it. `internal_call_id` names the call, and with it the answer in
/// `uas_2xx_retransmits` that may still be waiting for that ACK.
///
/// Every siphon BYE to a caller goes through here: the callee's hangup
/// (`handle_b2bua_bye`) and every teardown through `b2bua_terminate_call_inner`.
/// The 64×T1 teardown is never held, since its sweep has taken the answer out of
/// the store before the teardown runs.
pub fn send_or_hold_a_leg_bye(
    internal_call_id: &str,
    a_leg: &Leg,
    bye: SipMessage,
    state: &DispatcherState,
) {
    // RFC 3261 §12.2.1.1: the next hop is the first Route URI, not the cached
    // source of the INVITE.
    let (destination, transport) = resolve_in_dialog_destination(
        &a_leg.dialog.route_set,
        state,
        a_leg.transport.remote_addr,
        a_leg.transport.transport,
    );
    let answer = state
        .uas_2xx_retransmits
        .get(internal_call_id)
        .map(|entry| Arc::clone(entry.value()));
    let Some(answer) = answer else {
        // Sourced from the A-leg's anchored socket, so the Via matches (see
        // `build_b2bua_bye`). No-op on a single-listener host.
        send_message_from(
            bye,
            transport,
            destination,
            a_leg.transport.connection_id,
            a_leg.transport.local_addr,
            state,
        );
        return;
    };

    let a_leg_call_id = answer.a_leg_call_id.clone();
    // A BYE already held for this dialog stays the one that is sent: a second
    // teardown racing the first adds none.
    state
        .held_a_leg_byes
        .entry(a_leg_call_id.clone())
        .or_insert_with(|| HeldBye {
            bye,
            transport,
            destination,
            connection_id: a_leg.transport.connection_id,
            local_addr: a_leg.transport.local_addr,
            internal_call_id: internal_call_id.to_string(),
            answer: Arc::clone(&answer),
        });

    // The caller's ACK or the 64×T1 sweep may have taken the answer between the
    // lookup above and the insert, and then neither of them finds this BYE. Each
    // side sends the BYE only if it removes it from the store itself, so it goes
    // out exactly once whichever way that race goes.
    let still_waiting = state
        .uas_2xx_retransmits
        .get(internal_call_id)
        .is_some_and(|entry| Arc::ptr_eq(entry.value(), &answer));
    if still_waiting {
        debug!(
            call_id = %internal_call_id,
            "RFC 3261 §15: the caller has not ACKed its 2xx, so its BYE waits for the ACK"
        );
        return;
    }
    release_held_a_leg_bye(&a_leg_call_id, state);
}

/// Send the BYE held for the caller whose Call-ID is `a_leg_call_id`, if one is
/// held, and stop the retransmission of the 2xx it waited on. Returns whether a
/// BYE went out.
///
/// Called for the caller's ACK, right after it is absorbed; by the 64×T1 sweep;
/// and by a hold that finds its answer already taken.
pub fn release_held_a_leg_bye(a_leg_call_id: &str, state: &DispatcherState) -> bool {
    let Some((_, held)) = state.held_a_leg_byes.remove(a_leg_call_id) else {
        return false;
    };
    stop_held_answer(&held, state);
    debug!(
        call_id = %held.internal_call_id,
        destination = %held.destination,
        "B2BUA: sending the caller the BYE held for its ACK"
    );
    send_message_from(
        held.bye,
        held.transport,
        held.destination,
        held.connection_id,
        held.local_addr,
        state,
    );
    true
}

/// Answer a caller's BYE for a dialog whose call has ended with that caller's BYE
/// still held. Returns `false`, having done nothing, when no BYE is held for
/// `sip_call_id`.
///
/// The caller ended the dialog first, so its BYE is answered 200 (RFC 3261
/// §15.1.2), not 481: siphon has been retransmitting a 2xx for it all along. The
/// retransmission stops and the held BYE is dropped, since the dialog it would
/// have ended is gone.
pub fn answer_caller_bye_for_held_dialog(
    inbound: &InboundMessage,
    message: &SipMessage,
    sip_call_id: &str,
    state: &DispatcherState,
) -> bool {
    let Some((_, held)) = state.held_a_leg_byes.remove(sip_call_id) else {
        return false;
    };
    stop_held_answer(&held, state);
    debug!(
        call_id = %held.internal_call_id,
        "B2BUA: the caller hung up before its held BYE went out; answered, and the held BYE dropped"
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
fn stop_held_answer(held: &HeldBye, state: &DispatcherState) {
    if let Some((_, answer)) = state
        .uas_2xx_retransmits
        .remove_if(&held.internal_call_id, |_, current| {
            Arc::ptr_eq(current, &held.answer)
        })
    {
        answer.cancel.notify_one();
    }
}
