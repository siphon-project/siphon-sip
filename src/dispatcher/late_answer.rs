//! A 2xx to a proxied INVITE that already has a final response upstream.
//!
//! RFC 3261 §16.7 step 5: "After a final response has been sent on the server
//! transaction, the following responses MUST be forwarded immediately: Any 2xx
//! response to an INVITE request." Step 9: "If the server transaction is no
//! longer available to handle the transmission, the element MUST forward the
//! response statelessly by sending it to the server transport."
//!
//! Such a 2xx comes from a branch the proxy had given up on:
//!
//! * another branch of a fork already answered, or declined with a 6xx;
//! * `reply.reject()` already failed the request;
//! * the caller cancelled, and was answered `487`.
//!
//! and either crossed the branch's CANCEL or came from a branch that never
//! sent the provisional its CANCEL was waiting for (§9.1), so that no CANCEL
//! was ever sent. Either way the callee now holds a dialog. A proxy cannot
//! release it; the caller's user agent can and must: it ACKs every 2xx its
//! INVITE draws and ends a dialog it does not want with a BYE (§13.2.2.4).
//! So the 2xx is handed to the caller, and the ACK and BYE that come back are
//! routed like any other dialog's.
//!
//! It is not the call's answer. The request it answers ended, for the script
//! and for accounting, when its final response went upstream: no
//! `@proxy.on_reply` runs for it, no answer time or destination is stamped on
//! the call's record, and no accounting session is opened.

use super::*;

/// Forward `message`, the response on `client_key`'s branch, if it is a 2xx to
/// an INVITE whose final response has already gone upstream. Returns whether
/// the response was taken.
///
/// `final_response_sent` is the session's own record of that (a reject, the
/// caller's CANCEL); a fork that settled on a 2xx or a 6xx is asked through
/// its aggregator. That costs a fork one lock of its aggregator per 2xx to an
/// INVITE, and every other response nothing.
#[allow(clippy::too_many_arguments)]
pub(super) fn forward_if_late_2xx(
    message: &SipMessage,
    status_code: u16,
    client_key: &TransactionKey,
    session_arc: &Arc<RwLock<ProxySession>>,
    final_response_sent: bool,
    fork_aggregator: Option<&Arc<Mutex<crate::proxy::fork::ForkAggregator>>>,
    branch_index: Option<usize>,
    inbound: &InboundMessage,
    state: &DispatcherState,
) -> bool {
    if !(200..300).contains(&status_code) || client_key.method != Method::Invite {
        return false;
    }
    if !final_response_sent {
        let (Some(aggregator), Some(index)) = (fork_aggregator, branch_index) else {
            return false;
        };
        let action = match aggregator.lock() {
            Ok(mut aggregator) if aggregator.has_settled() => {
                aggregator.on_branch_response(index, status_code)
            }
            Ok(_) => return false,
            Err(_) => {
                error!("fork aggregator lock poisoned");
                return false;
            }
        };
        if action != crate::proxy::fork::ForkAction::ForwardAnother2xx {
            // This branch's own 2xx again: forwarded once already.
            debug!(
                client_key = %client_key,
                "retransmitted 2xx on a branch that already answered — not forwarded twice"
            );
            return true;
        }
    }
    let mut late = message.clone();
    core::strip_top_via(&mut late.headers);
    send_late_2xx_upstream(late, client_key, session_arc, inbound, state);
    true
}

/// Send `message`, a late 2xx with the proxy's own Via already removed, to the
/// caller, and keep the dialog it opens routable for the caller's ACK.
///
/// Through the INVITE server transaction while that can still take a 2xx, and
/// straight to the transport when it cannot (§16.7 step 9).
pub(super) fn send_late_2xx_upstream(
    message: SipMessage,
    client_key: &TransactionKey,
    session_arc: &Arc<RwLock<ProxySession>>,
    inbound: &InboundMessage,
    state: &DispatcherState,
) {
    let (server_key, source_addr, transport, connection_id, inbound_local_addr) = {
        let Ok(session) = session_arc.read() else {
            error!("proxy session lock poisoned while forwarding a late 2xx");
            return;
        };
        (
            session.server_key.clone(),
            session.source_addr,
            session.transport,
            session.connection_id,
            session.inbound_local_addr,
        )
    };
    // The same Contact fixup an ordinary response gets, so the ACK and BYE
    // the caller sends for this dialog reach the callee.
    let message = if state.nat_fix_contact {
        fix_response_contact(message, inbound.remote_addr)
    } else {
        message
    };

    // The caller's ACK for this 2xx is a request of its own, routed by dialog,
    // and the BYE that ends this dialog ends this dialog only.
    state.session_store.keep_dialog_for_late_answer(session_arc);
    state.session_store.note_late_dialog(&message);

    info!(
        client_key = %client_key,
        destination = %source_addr,
        "forwarding a 2xx that arrived after the request's final response (RFC 3261 §16.7 step 5)"
    );
    let mut sent_by_transaction = false;
    if let Ok(actions) = state.transaction_manager.process_server_event(
        &server_key,
        ServerEvent::Ist(IstEvent::Tu2xx(message.clone())),
    ) {
        sent_by_transaction = actions
            .iter()
            .any(|action| matches!(action, Action::SendMessage(_)));
        process_timer_actions(
            &actions,
            &server_key,
            Some(source_addr),
            Some(transport),
            Some(connection_id),
            Some(inbound_local_addr),
            state,
        );
    }
    if !sent_by_transaction {
        send_message_from(
            message,
            transport,
            source_addr,
            connection_id,
            Some(inbound_local_addr),
            state,
        );
    }

    // The branch has its final response.
    state.session_store.remove_client_key(client_key);
}
