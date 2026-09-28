//! Ending a call siphon placed before it is answered: the CANCEL a hangup,
//! a ring timeout or an originate group's decision sends, and the release of
//! a group leg that answered after another had won.
use crate::dispatcher::*;

/// Abandon an originated call that has not been answered: CANCEL the INVITE
/// (RFC 3261 §9.1 — same Via branch and CSeq sequence as the request it
/// cancels), stop retransmitting it, emit `StasisEnd`, and tear the call down.
///
/// This is what `hangup` means on an un-answered leg siphon placed. The
/// inbound-call path answers its A-leg with a final non-2xx there, which is
/// exactly wrong here: siphon is the UAC, and sending a *response* to the party
/// it is calling is not a thing (RFC 3261 §8.1 — a UAC answers nothing).
/// Returns `false`, never panics, when the call is already gone.
pub fn b2bua_cancel_originated_call(sip_call_id: &str, reason: Option<&str>) -> bool {
    let Some(control) = B2BUA_CONTROL.get() else {
        return false;
    };
    let _enter = control.runtime.enter();
    cancel_originated_call(&control.state, sip_call_id, reason)
}

/// [`b2bua_cancel_originated_call`] on the dispatcher the caller already holds.
///
/// `sip_call_id` may also name an originate group (the id a controller's
/// channel is bound to while the group rings), which CANCELs every leg it
/// still has ringing.
pub(crate) fn cancel_originated_call(
    state: &DispatcherState,
    sip_call_id: &str,
    reason: Option<&str>,
) -> bool {
    if state.originate_groups.contains(sip_call_id) {
        return cancel_originate_group(
            state,
            sip_call_id,
            OriginateGroupEnd::Cancelled {
                reason: reason.unwrap_or("cancelled").to_string(),
            },
        );
    }
    let Some(internal_call_id) = state.call_actors.find_by_sip_call_id(sip_call_id) else {
        return false;
    };
    abandon_originated_call(
        state,
        &internal_call_id,
        sip_call_id,
        reason,
        crate::b2bua::actor::DialBranchOutcome::new(
            487,
            "Request Terminated",
            crate::b2bua::actor::DialBranchCause::Cancelled,
        ),
    )
}

/// CANCEL an originated call that has not been answered and tear it down,
/// reporting `outcome` to its originate group if it is one's leg: `Cancelled`
/// when siphon gave up on it, `Timeout` when its ring timeout did.
pub(crate) fn abandon_originated_call(
    state: &DispatcherState,
    internal_call_id: &str,
    sip_call_id: &str,
    reason: Option<&str>,
    outcome: crate::b2bua::actor::DialBranchOutcome,
) -> bool {
    let internal_call_id = internal_call_id.to_string();
    let staged = match state.call_actors.get_call(&internal_call_id) {
        Some(call) => call.a_leg_invite.clone().map(|invite| {
            (
                invite,
                call.a_leg.transport.transport,
                call.a_leg.transport.remote_addr,
                call.a_leg.transport.local_addr,
                call.a_leg.branch.clone(),
            )
        }),
        None => return false,
    };
    let Some((invite_arc, transport, destination, local_addr, branch)) = staged else {
        return false;
    };

    // Stop the INVITE's own retransmit schedule first: we are giving up on it,
    // and `arm_b2bua_retransmit` disarms it again when the CANCEL is armed —
    // this also covers a leg whose CANCEL cannot be built.
    state.b2bua_retransmits.disarm_branch(&branch);
    let cancel = match invite_arc.lock() {
        Ok(invite) => build_cancel_from_invite(&invite),
        Err(_) => {
            error!(call_id = %internal_call_id, "originate cancel: stored INVITE mutex poisoned");
            None
        }
    };
    if let Some(cancel) = cancel {
        send_b2bua_to_bleg(cancel, transport, destination, local_addr, state);
    }

    if crate::cdr::auto_emit_enabled() {
        cdr_finalize_b2bua_fail(state, &internal_call_id, 487);
    }
    // RFC 3261 §9.1: the callee answers a CANCELled INVITE `487 Request
    // Terminated`. We abandoned this leg before it was answered, so 487 is the
    // status that ends it — reported here because a controller driving a leg
    // siphon placed has no response frame of its own to read it off.
    control_notify_terminated_with_cause(
        sip_call_id,
        reason.unwrap_or("cancelled"),
        Some(487),
        Some("Request Terminated"),
    );
    // Keep the leg alive as a zombie so a 2xx that raced our CANCEL is still
    // ACKed + BYEd (RFC 3261 §9.1 glare) rather than left ringing on the callee.
    if state
        .call_actors
        .remove_call_after_cancel(&internal_call_id)
    {
        schedule_zombie_cancelled_cleanup(state.call_actors.clone());
    }
    state.call_event_receivers.remove(&internal_call_id);
    originate_group_leg_ended(state, &internal_call_id, outcome);
    true
}

/// Release the dialog a leg of an originate group opened by answering after
/// another leg had already won: ACK its 2xx (RFC 3261 §13.2.2.4), with an
/// answer rejecting every stream when the 2xx carried the offer, then BYE it
/// (§15), and tear the leg down. Nobody is told: the leg was never bound to a
/// channel, and the group reported it when it lost.
pub fn originate_release_losing_answer(
    internal_call_id: &str,
    response: &SipMessage,
    state: &DispatcherState,
) {
    let Some(leg) = state.call_actors.get_call(internal_call_id).map(|call| {
        let mut leg = call.a_leg.clone();
        // The INVITE this leg sent, which tells the release whether the 2xx is
        // owed an answer.
        leg.b_leg_invite = call.a_leg_invite.clone();
        leg
    }) else {
        return;
    };
    let sip_call_id = leg.dialog.call_id.clone();
    b2bua_ack_and_bye_answered_leg(leg, response, true, state);
    info!(
        call_id = %internal_call_id,
        %sip_call_id,
        "originate: a group leg answered after another won — ACK + BYE"
    );
    state.call_actors.remove_call(internal_call_id);
    state.call_event_receivers.remove(internal_call_id);
}
