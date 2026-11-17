//! The non-INVITE client transactions of the requests siphon originates: the
//! registrant's REGISTERs and what the UAC sender sends for a script
//! (`proxy.send_request`, the NOTIFYs and SUBSCRIBEs of
//! `proxy.subscribe_state`, `presence.notify`).
//!
//! RFC 3261 §17.1.2.2. Such a request opens a transaction in the dispatcher's
//! transaction layer, the one a relayed request runs on: the timer sweep
//! ([`super::timers::fire_expired_timers`]) fires Timer E, which re-sends the
//! octets that went out, to the same address and from the same local socket,
//! and Timer F, which ends an unanswered one; the response path feeds it the
//! answers, and Timer K keeps it for T4 over UDP so a repeat of the final
//! response is absorbed. Over a reliable transport it has Timer F alone.

use super::*;

/// Open a non-INVITE client transaction for `request`, whose wire form is
/// `message`, and arm its timers: Timer F always, Timer E over UDP only
/// (RFC 3261 §17.1.2.2). The first send is the caller's.
pub(super) fn open_client_transaction(
    transactions: &TransactionManager,
    timer_wheel: &DashMap<String, Box<TimerEntry>>,
    request: &SipMessage,
    message: &crate::transport::OutboundMessage,
) -> Result<TransactionKey, String> {
    let (key, actions) = transactions.new_client_transaction(
        request,
        message.data.clone(),
        crate::transaction::state::Transport::from(message.transport),
    )?;
    for action in actions {
        if let Action::StartTimer(name, duration) = action {
            timer_wheel.insert(
                format!("{key}:{name:?}"),
                Box::new(TimerEntry {
                    key: key.clone(),
                    name,
                    fires_at: std::time::Instant::now() + duration,
                    destination: Some(message.destination),
                    transport: Some(message.transport),
                    connection_id: Some(message.connection_id),
                    source_local_addr: message.source_local_addr,
                }),
            );
        }
    }
    Ok(key)
}

/// Feed a response to the client transaction of the request siphon originated
/// on its branch. `false` when the transaction absorbed it (a repeat of the
/// final response it already passed on, RFC 3261 §17.1.2.2 Completed), which
/// must not be acted on twice; `true` otherwise, including for a response
/// with no transaction left.
pub(super) fn drive_client_transaction(
    message: &SipMessage,
    status_code: u16,
    state: &DispatcherState,
) -> bool {
    let Ok(key) = TransactionManager::key_from_message(message) else {
        return true;
    };
    let event = if status_code < 200 {
        NictEvent::Provisional(message.clone())
    } else {
        NictEvent::FinalResponse(message.clone())
    };
    let Ok(actions) = state
        .transaction_manager
        .process_client_event(&key, ClientEvent::Nict(event))
    else {
        return true;
    };
    process_timer_actions(&actions, &key, None, None, None, None, state);
    actions
        .iter()
        .any(|action| matches!(action, Action::PassToTu(_)))
}

/// Take `message` when it answers a request the UAC sender originated: its
/// client transaction sees it first (a final response stops Timer E, a
/// provisional one slows it to T2), then whoever waits on the branch gets it.
/// `true` when the response is consumed here: someone was waiting for it, or
/// it repeats a final response the transaction has already passed on.
pub(super) fn uac_response(
    message: &SipMessage,
    status_code: u16,
    state: &DispatcherState,
) -> bool {
    let Some(branch) = crate::uac::uac_branch(message) else {
        return false;
    };
    if !drive_client_transaction(message, status_code, state) {
        debug!(status_code, %branch, "UAC response repeated, absorbed (RFC 3261 §17.1.2.2)");
        return true;
    }
    let matched = state.uac_sender.deliver_response(&branch, message);
    if matched {
        debug!(status_code, "UAC response matched");
    }
    matched
}

/// The dispatcher's transaction layer as the UAC sender sends under it.
pub(crate) struct UacTransactionLayer {
    transactions: Arc<TransactionManager>,
    timer_wheel: Arc<DashMap<String, Box<TimerEntry>>>,
}

impl UacTransactionLayer {
    pub(crate) fn of(state: &DispatcherState) -> Self {
        Self {
            transactions: Arc::clone(&state.transaction_manager),
            timer_wheel: Arc::clone(&state.timer_wheel),
        }
    }
}

impl crate::uac::UacTransactions for UacTransactionLayer {
    fn open(
        &self,
        request: &SipMessage,
        message: &crate::transport::OutboundMessage,
    ) -> Result<TransactionKey, String> {
        open_client_transaction(&self.transactions, &self.timer_wheel, request, message)
    }

    fn abandon(&self, key: &TransactionKey) {
        self.transactions.remove(key);
        for name in [TimerName::E, TimerName::F, TimerName::K] {
            self.timer_wheel.remove(&format!("{key}:{name:?}"));
        }
    }
}

/// Send every request `state`'s UAC sender originates under a client
/// transaction of `state`'s transaction layer.
pub(super) fn attach_uac_transactions(state: &DispatcherState) {
    state
        .uac_sender
        .attach_transactions(Arc::new(UacTransactionLayer::of(state)));
}

/// Open the client transaction of a request of the UAC sender's that the
/// dispatcher puts on the wire itself, as a frame behind the reply it has to
/// follow (RFC 6665 §4.1.2.3): over UDP that frame is as losable as any
/// other datagram.
///
/// The frame leaves where the reply to `inbound` leaves
/// ([`send_frames_in_order_from`]: the first frame, the reply, decides for the
/// group), so that egress is what the transaction retransmits over: to a UE
/// with a security association, the pair its request came over
/// ([`protected_udp_egress`]), not the set a request of the P-CSCF's own
/// would pick by the time Timer E fires.
pub(super) fn track_reply_followup(
    request: &SipMessage,
    frame: &Bytes,
    inbound: &InboundMessage,
    state: &DispatcherState,
) {
    /// Enough of a reply for [`protected_udp_egress`] to see one.
    const REPLY: &[u8] = b"SIP/2.0 ";
    let (destination, source_local_addr) = protected_udp_egress(
        REPLY,
        inbound.transport,
        inbound.remote_addr,
        Some(inbound.local_addr),
        state,
    );
    state.uac_sender.track_request(
        request,
        &OutboundMessage {
            followups: None,
            connection_id: inbound.connection_id,
            transport: inbound.transport,
            destination,
            data: frame.clone(),
            source_local_addr,
            server_name: None,
            verify_server: None,
        },
    );
}

#[cfg(test)]
#[path = "uac_retransmit_tests.rs"]
mod retransmit_tests;
