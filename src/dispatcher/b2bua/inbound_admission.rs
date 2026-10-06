//! Admission of an inbound B2BUA INVITE against `b2bua.inbound_limit`.
//!
//! Runs before a call or a script exists. A refused INVITE is answered here,
//! statelessly like every other pre-script rejection on this path, and gets a
//! CDR of its own because no call will ever write one for it.

use crate::admission::refused::RefusedAnswer;
use crate::admission::{is_emergency_service_urn, AdmissionPermit, Refusal};
use crate::dispatcher::*;

/// The `disconnect_initiator` of a call siphon turned away itself. Neither
/// party ended it, and `"callee"` (what a failure code otherwise maps to) would
/// blame a far end that was never dialled.
const DISCONNECT_LOCAL: &str = "local";

/// Decide whether an inbound INVITE becomes a call.
///
/// `Some` is the slot the new call must own. `None` means the INVITE has been
/// answered with a refusal and nothing more is to be done with it.
///
/// `takes_over_dialog` is an INVITE whose `Replaces` matched a dialog this node
/// hosts: it replaces a call that already holds a slot, so it is counted and
/// never refused. The same goes for an emergency call.
pub(in crate::dispatcher) fn admit_inbound_invite(
    inbound: &InboundMessage,
    message: &SipMessage,
    call_id: &str,
    via_branch: &str,
    takes_over_dialog: bool,
    state: &DispatcherState,
) -> Option<AdmissionPermit> {
    if let Some(answer) = state.refused_invites.lookup(call_id, via_branch) {
        debug!(
            call_id = %call_id,
            "B2BUA: re-answering a retransmitted INVITE that was refused"
        );
        send_refusal(inbound, message, answer, state);
        return None;
    }

    if takes_over_dialog || is_emergency_call(message) {
        return Some(state.admission.admit_unrefused());
    }

    match state.admission.admit() {
        Ok(permit) => Some(permit),
        Err(refusal) => {
            let answer = RefusedAnswer {
                reject_code: refusal.reject_code,
                retry_after_secs: refusal.retry_after_secs,
            };
            debug!(
                call_id = %call_id,
                scope = refusal.scope.as_str(),
                reason = refusal.reason.as_str(),
                code = refusal.reject_code,
                "B2BUA: refusing INVITE — inbound limit reached"
            );
            state
                .refused_invites
                .remember(call_id, via_branch, answer, std::time::Instant::now());
            crate::metrics::admission::record_refusal(refusal.reason);
            write_refusal_cdr(inbound, message, &refusal);
            send_refusal(inbound, message, answer, state);
            None
        }
    }
}

/// The caller ACKed a response no transaction or call claims. If it was a
/// refusal from [`admit_inbound_invite`], the INVITE's retransmissions are over
/// and the refusal need not be remembered any longer.
///
/// The ACK for a non-2xx carries the INVITE's own top Via branch (RFC 3261
/// §17.1.1.3), which with the Call-ID is the key the refusal was stored under.
pub(in crate::dispatcher) fn forget_refused_invite(ack: &SipMessage, state: &DispatcherState) {
    if state.refused_invites.is_empty() {
        return;
    }
    let Some(call_id) = ack.headers.get("Call-ID") else {
        return;
    };
    let branch = ack
        .headers
        .get("Via")
        .and_then(|raw| Via::parse_multi(raw).ok())
        .and_then(|vias| vias.into_iter().next())
        .and_then(|via| via.branch)
        .unwrap_or_default();
    state.refused_invites.forget(call_id, &branch);
}

/// Whether the INVITE is addressed to an emergency service (RFC 5031). Read
/// off the request as it arrived: this runs before the script, which is the
/// only thing that could rewrite it.
fn is_emergency_call(message: &SipMessage) -> bool {
    message
        .request_uri()
        .is_some_and(|uri| is_emergency_service_urn(uri.scheme.as_str(), &uri.host))
}

fn send_refusal(
    inbound: &InboundMessage,
    message: &SipMessage,
    answer: RefusedAnswer,
    state: &DispatcherState,
) {
    let mut response = build_response(
        message,
        answer.reject_code,
        best_error_reason(answer.reject_code),
        state.server_header.as_deref(),
        &[],
    );
    if answer.retry_after_secs > 0 {
        response
            .headers
            .set("Retry-After", answer.retry_after_secs.to_string());
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

/// Write the refused call's CDR (`cdr.auto_emit`). Built and written in one
/// step: there is no call to track, so nothing is left in the session map.
fn write_refusal_cdr(inbound: &InboundMessage, message: &SipMessage, refusal: &Refusal) {
    if !crate::cdr::auto_emit_enabled() {
        return;
    }
    let Some((_, mut session)) = cdr_session_from_invite(
        message,
        &inbound.remote_addr.ip().to_string(),
        inbound.client_or_hop_transport().as_scheme(),
        None,
    ) else {
        return;
    };
    session.merge_extra(&std::collections::HashMap::from([
        (
            "refusal_scope".to_string(),
            refusal.scope.as_str().to_string(),
        ),
        (
            "refusal_reason".to_string(),
            refusal.reason.as_str().to_string(),
        ),
    ]));
    crate::cdr::write(session.finalize(DISCONNECT_LOCAL, Some(refusal.reject_code), None));
}
