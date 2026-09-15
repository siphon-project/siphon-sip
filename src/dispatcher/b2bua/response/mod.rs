//! The B-leg response path: everything that happens to a call between the
//! INVITE leaving and the dialog being established or failed.
use crate::dispatcher::*;

mod answered;
mod failed;
mod guards;
mod late_ack;
mod provisional;
mod reinvite;
mod teardown;
mod transfer;
mod update;

pub use answered::*;
pub use failed::*;
pub use guards::*;
pub use late_ack::*;
pub use provisional::*;
pub use reinvite::*;
pub use teardown::*;
pub use transfer::*;
pub use update::*;

/// Everything the response path needs off the [`CallActor`], read once and
/// copied out so the `DashMap` guard is dropped before any Python handler
/// runs. Holding the guard across a handler deadlocks the store against the
/// script's own `call.*` calls.
pub struct BLegResponseSnapshot {
    pub a_leg: Leg,
    pub a_leg_invite: Option<Arc<Mutex<SipMessage>>>,
    pub b_leg_target: Option<String>,
    pub b_leg_remote_contact: Option<String>,
    pub b_leg_dialog: Option<(String, String)>,
    pub b_leg_dest: Option<(SocketAddr, Transport)>,
    pub b_leg_local_addr: Option<SocketAddr>,
    pub b_leg_connection_id: ConnectionId,
    pub b_leg_index: Option<usize>,
    pub b_leg_stored_vias: Vec<String>,
    pub b_leg_stored_cseq: Option<String>,
    pub b_leg_stored_from: Option<String>,
    pub b_leg_stored_to: Option<String>,
    pub call_state: CallState,
    pub outbound_credentials: Option<(String, String)>,
    pub b_leg_handle_tx: Option<tokio::sync::mpsc::Sender<crate::b2bua::actor::LegMessage>>,
    pub b_leg_stored_invite: Option<Arc<Mutex<SipMessage>>>,
    pub b_leg_local_cseq: u32,
    /// On a re-INVITE / UPDATE tracking leg, the SDP offer siphon sent the
    /// responder (`Leg::offered_sdp`), committed to its dialog on a 2xx.
    pub b_leg_offered_sdp: Option<Vec<u8>>,
    /// On a re-INVITE / UPDATE tracking leg, the session interval the request's
    /// `Session-Expires` asked for (`Leg::request_session_expires`).
    pub b_leg_request_session_expires: Option<u32>,
    /// On a tracking leg for a relayed re-INVITE or UPDATE, the originator's
    /// session timer headers (`Leg::session_refresh_request`).
    pub b_leg_session_refresh_request: Option<crate::sip::headers::SipHeaders>,
    /// The Via branch the response carries.
    pub branch: String,
    pub a_leg_local_addr: Option<SocketAddr>,
}

/// Read the A-leg state and the matching B-leg off the call, or `None` when
/// the call is already gone. What a missing call means depends on the message
/// in hand, so the callers log it, not this.
pub fn b_leg_response_snapshot(
    call_id: &str,
    branch: &str,
    state: &DispatcherState,
) -> Option<BLegResponseSnapshot> {
    let call = state.call_actors.get_call(call_id)?;
    let matching_b_idx = call.b_legs.iter().position(|b| b.branch == branch);
    let matching_b = matching_b_idx.map(|i| &call.b_legs[i]);
    let target = matching_b.map(|b| b.dialog.target_uri.clone().unwrap_or_default());
    let remote_contact = matching_b.and_then(|b| b.dialog.remote_contact.clone());
    let dialog = matching_b.map(|b| (b.dialog.call_id.clone(), b.dialog.local_tag.clone()));
    let dest = matching_b.map(|b| (b.transport.remote_addr, b.transport.transport));
    // The socket this B-leg is anchored on — `Some` only when the leg
    // was dialled over a captured flow (`call.dial(flow=…)`). Every
    // siphon-originated request we put back on this leg (auto-PRACK,
    // ACK, BYE, forwarded re-INVITE/UPDATE) has to leave from it.
    let b_local_addr = matching_b.and_then(|b| b.transport.local_addr);
    // The connection_id the original B-leg INVITE was sent on — reused
    // by the 401/407 retry path so the credentialed re-INVITE stays on
    // the same trunk member that issued the nonce (RFC 5923).
    let connection_id = matching_b
        .map(|b| b.transport.connection_id)
        .unwrap_or_default();
    let stored_vias = matching_b
        .map(|b| b.stored_vias.clone())
        .unwrap_or_default();
    let stored_cseq = matching_b.and_then(|b| b.stored_cseq.clone());
    let stored_from = matching_b.and_then(|b| b.stored_from.clone());
    let stored_to = matching_b.and_then(|b| b.stored_to.clone());
    let handle_tx = matching_b_idx
        .and_then(|i| call.b_leg_handles.get(i))
        .and_then(|h| h.as_ref())
        .map(|h| h.tx.clone());
    let stored_invite = matching_b.and_then(|b| b.b_leg_invite.clone());
    let local_cseq = matching_b.map(|b| b.dialog.local_cseq).unwrap_or(2);
    Some(BLegResponseSnapshot {
        a_leg: call.a_leg.clone(),
        a_leg_invite: call.a_leg_invite.clone(),
        b_leg_target: target,
        b_leg_remote_contact: remote_contact,
        b_leg_dialog: dialog,
        b_leg_dest: dest,
        b_leg_local_addr: b_local_addr,
        b_leg_connection_id: connection_id,
        b_leg_index: matching_b_idx,
        b_leg_stored_vias: stored_vias,
        b_leg_stored_cseq: stored_cseq,
        b_leg_stored_from: stored_from,
        b_leg_stored_to: stored_to,
        call_state: call.state.clone(),
        outbound_credentials: call.outbound_credentials.clone(),
        b_leg_handle_tx: handle_tx,
        b_leg_stored_invite: stored_invite,
        b_leg_local_cseq: local_cseq,
        b_leg_offered_sdp: matching_b.and_then(|b| b.offered_sdp.clone()),
        b_leg_request_session_expires: matching_b.and_then(|b| b.request_session_expires),
        b_leg_session_refresh_request: matching_b.and_then(|b| b.session_refresh_request.clone()),
        branch: branch.to_string(),
        a_leg_local_addr: call.a_leg_local_addr,
    })
}

/// The To-tag a B-leg response carries once it is relayed to the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayedToTag {
    /// A provisional keeps the tag it has after its dialog tags are swapped: the
    /// A-leg's early-dialog tag on an 18x that opened one, none on a plain 180.
    AsRelayed,
    /// A final response always carries the A-leg dialog's tag.
    ALegDialog,
}

/// Put the caller's own From and To on a B-leg response relayed to it.
///
/// RFC 3261 §8.2.6.2: a response's From equals its request's, and its To is the
/// request's To plus the UAS tag. A relayed response is the B-leg's message, so
/// until this runs its From is siphon's B-leg identity, shaped for the far side,
/// and its To is the far side's address, which
/// [`crate::b2bua::actor::Dialog::rewrite_headers`] leaves in place when it swaps
/// the tags. Every B-leg response relayed to the caller (provisional, answer,
/// failure) comes through here, so an early dialog shows the caller one identity
/// from its first 18x to its final response, and nothing of the far side leaks.
///
/// The URIs come from the A-leg's arrival snapshot, not from `invite`: the
/// stored INVITE is the buffer a handler reshapes for the B-leg
/// (`call.rewrite_identities()`, `set_from_user`, a route's number policy).
/// `invite` is only the fallback for a call with no snapshot. A response siphon
/// builds itself gets the same echo from [`stamp_uas_echo`], which this reuses.
pub fn echo_caller_identity(
    response: &mut SipMessage,
    a_leg: &Leg,
    invite: &SipMessage,
    to_tag: RelayedToTag,
) {
    let relayed_tag;
    let tag = match to_tag {
        RelayedToTag::ALegDialog => a_leg.dialog.local_tag.as_str(),
        RelayedToTag::AsRelayed => {
            relayed_tag = response
                .headers
                .to()
                .and_then(|to| crate::sip::headers::nameaddr::NameAddr::parse(to).ok())
                .and_then(|name_addr| name_addr.tag);
            // An empty tag adds none, which is what a tagless 180 needs.
            relayed_tag.as_deref().unwrap_or_default()
        }
    };
    stamp_uas_echo(
        response,
        a_leg.stored_from.as_ref().or(invite.headers.from()),
        a_leg.stored_to.as_ref().or(invite.headers.to()),
        tag,
    );
}

/// Handle a response to a B2BUA B-leg INVITE.
///
/// Returns `false` only when the call the branch named is already gone: a
/// teardown removed it while the response was in flight, before it cleaned up
/// the branch index. Nothing has been done with the response then, and the
/// caller handles it as one for a call that ended (a 2xx to our own INVITE is
/// still owed its ACK).
pub fn handle_b2bua_response(
    call_id: &str,
    branch: &str,
    message: &mut SipMessage,
    status_code: u16,
    response_source: SocketAddr,
    state: &DispatcherState,
) -> bool {
    debug!(
        call_id = %call_id,
        branch = %branch,
        status = status_code,
        "B2BUA: received B-leg response"
    );

    // Read the A-leg info and the matching B-leg out of the call and drop the
    // `DashMap` guard before entering Python.
    let Some(snapshot) = b_leg_response_snapshot(call_id, branch, state) else {
        return false;
    };

    // A `2xx` to a B-leg CANCEL shares the INVITE's top Via branch (RFC 3261
    // §9.1), so branch-matching alone would misclassify it as the carrier's
    // INVITE answer and mark the cancelled leg the winner — sending the late
    // ACK and the BYE to the wrong (cancelled) carrier. A CANCEL response needs
    // no action here (siphon initiated the CANCEL; the 487 to the INVITE is
    // handled separately), so absorb any non-INVITE-CSeq response.
    let response_cseq_method = message
        .headers
        .cseq()
        .and_then(|cseq| cseq.split_whitespace().nth(1).map(str::to_string))
        .unwrap_or_default();
    if response_cseq_method.eq_ignore_ascii_case("CANCEL") {
        debug!(
            call_id = %call_id,
            status = status_code,
            "B2BUA: absorbing 2xx/response to a B-leg CANCEL (not an INVITE answer)"
        );
        return true;
    }
    if absorb_cancelled_branch_response(call_id, branch, message, status_code, state) {
        return true;
    }
    if auto_prack_b_leg(call_id, message, status_code, state, &snapshot) {
        return true;
    }

    // Absorb the B-leg's 200 OK PRACK so it never gets forwarded to the
    // A-leg (the A-leg never sent a PRACK — siphon did, locally). The
    // CSeq method on the response distinguishes it from the INVITE 200.
    if (200..300).contains(&status_code)
        && message
            .headers
            .cseq()
            .and_then(|c| c.split_whitespace().nth(1))
            .map(|m| m.eq_ignore_ascii_case("PRACK"))
            .unwrap_or(false)
    {
        debug!(
            call_id = %call_id,
            "B2BUA: absorbing B-leg 200 OK PRACK"
        );
        return true;
    }
    if absorb_completed_reinvite_retransmit(call_id, message, status_code, state, &snapshot) {
        return true;
    }
    if absorb_completed_update_retransmit(call_id, status_code, &snapshot) {
        return true;
    }
    if absorb_completed_forward_retransmit(call_id, status_code, &snapshot) {
        return true;
    }
    if dispatch_bridge_reinvite_response(call_id, branch, message, status_code, state, &snapshot) {
        return true;
    }
    if absorb_completed_bridge_retransmit(call_id, message, status_code, state, &snapshot) {
        return true;
    }
    if intercept_refresh_offer(
        call_id,
        branch,
        message,
        status_code,
        response_source,
        state,
        &snapshot,
    ) {
        return true;
    }
    if forward_reinvite_response(
        call_id,
        branch,
        message,
        status_code,
        response_source,
        state,
        &snapshot,
    ) {
        return true;
    }
    if forward_update_response(
        call_id,
        message,
        status_code,
        response_source,
        state,
        &snapshot,
    ) {
        return true;
    }
    if forward_transfer_response(call_id, message, status_code, state, &snapshot) {
        return true;
    }
    feed_leg_actor_and_learn_dialog(call_id, message, status_code, state, &snapshot);

    // Event-driven response classification.
    // Classified from the response's OWN status line, never from the actor
    // event.
    //
    // The event is popped from a per-call channel that every leg actor pushes
    // to, and there is no guarantee the one that comes back describes the
    // response in hand. The receiver is taken out of the map to be waited on, so
    // when two responses for a call are processed at once — a 180 and its 200 on
    // different workers, which is the normal shape of an answered call — the
    // second handler finds the receiver gone and classifies by status, while the
    // event its own `try_send` produced stays queued. The stream is then off by
    // one and the next response reads its predecessor's event.
    //
    // Filtering `Terminated` (see `recv_b_leg_classification_event`) fixed one
    // source of that skew; this removes the dependency instead of chasing the
    // rest. A 2xx read as its predecessor's `Provisional` skips `set_winner` and
    // the B-leg ACK, so the callee's 200 is never ACKed and it
    // retransmits until the dialog collapses — measured at 8-15% of plain calls
    // on a loopback B2BUA before this change.
    //
    // The response's status line is unambiguous, always present, and describes
    // exactly the message being handled. The actor is still fed the response so
    // its own state machine advances, and the event is still consumed so the
    // channel drains; only the classification no longer depends on it.
    let Some(class) = classify_b_leg_response(status_code) else {
        return true; // 100 Trying from B-leg — absorb
    };

    // siphon-terminated transfer: intercept EVERY response from a newly-dialed
    // transfer-target leg before the normal answer / provisional / retransmit
    // handling. The referrer's call is already `Answered`, so (a) a provisional
    // here must NOT be forwarded to the referrer (it would look like a fresh
    // call-setup 18x and confuse them) and (b) the 2xx must drive the transfer
    // completion rather than being swallowed by the "200 OK retransmission"
    // absorber below. A transfer target is a b_leg that is not the winner while
    // a siphon-owned REFER subscription is pending.
    if let Some(target_idx) = snapshot.b_leg_index {
        let is_transfer_target = state
            .call_actors
            .get_call(call_id)
            .and_then(|call| {
                let leg_call_id = &call.b_legs.get(target_idx)?.dialog.call_id;
                Some(call.refer_subscriptions.iter().any(|subscription| {
                    subscription.siphon_notifies
                        && subscription.target_leg_call_id.as_deref() == Some(leg_call_id.as_str())
                }))
            })
            .unwrap_or(false);
        if is_transfer_target {
            if (200..300).contains(&status_code) {
                b2bua_complete_terminated_transfer(call_id, target_idx, message, state);
            } else if status_code >= 300 {
                // RFC 3261 §17.1.1.3 — the INVITE client transaction MUST ACK a
                // non-2xx final, on the SAME branch. Nothing else on this path
                // does it: the interception returns before the ordinary B-leg
                // failure handling below, which is where every other B-leg
                // non-2xx is ACKed. Without this the target retransmits its
                // final response for the full 32 s of Timer H — observed on a
                // transfer whose target answered `486 Busy Here` (11 copies at
                // T1-doubling to T2) while siphon had already reported the
                // failure to the referrer and moved on.
                if !ack_b_leg_non2xx(branch, message, state, &snapshot) {
                    warn!(
                        call_id = %call_id,
                        status = status_code,
                        "B2BUA REFER (terminate): transfer target failed but its flow is \
                         unknown — cannot ACK, the target will retransmit until Timer H"
                    );
                }
                b2bua_fail_terminated_transfer(call_id, target_idx, status_code, state);
            } else {
                debug!(
                    call_id = %call_id,
                    status = status_code,
                    "B2BUA REFER (terminate): absorbing transfer-target provisional (not forwarded to the referrer)"
                );
            }
            return true;
        }
    }

    match class {
        ResponseClass::Answered => b_leg_answered(
            call_id,
            message,
            status_code,
            response_source,
            state,
            &snapshot,
        ),
        ResponseClass::Provisional => b_leg_provisional(
            call_id,
            branch,
            message,
            status_code,
            response_source,
            state,
            &snapshot,
        ),
        ResponseClass::Failed => {
            b_leg_failed(call_id, branch, message, status_code, state, &snapshot)
        }
    }
    true
}
