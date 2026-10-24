//! Handing a built message to the transport.
//!
//! `send_message_from` has 39 callers — the last step of almost every path in
//! the dispatcher — so it is deliberately thin.

use super::*;

/// Send raw bytes to a specific destination via the outbound channel, with
/// automatic HEP capture, pinning the local egress address when given.  Reply
/// paths set `source_local_addr = Some(inbound.local_addr)` so the
/// response leaves on the same SA's local endpoint that the request
/// arrived on (3GPP TS 33.203 §7.4 — required for IPsec-protected
/// REGISTER cycles).
pub(super) fn send_outbound_from(
    data: Bytes,
    transport: Transport,
    destination: SocketAddr,
    connection_id: ConnectionId,
    source_local_addr: Option<SocketAddr>,
    state: &DispatcherState,
) {
    let (destination, source_local_addr) =
        protected_udp_egress(&data, transport, destination, source_local_addr, state);

    // HEP capture — outbound (sent to network)
    if let Some(ref hep) = state.hep_sender {
        hep.capture_outbound(
            hep_capture_local(state, transport, source_local_addr),
            destination,
            transport,
            &data,
        );
    }

    let outbound_message = OutboundMessage {
        connection_id,
        transport,
        destination,
        data,
        source_local_addr,
        server_name: None,
        verify_server: None,
        followups: None,
    };

    if let Err(error) = state.outbound.send(outbound_message) {
        error!("failed to enqueue outbound message: {error}");
    }
}

/// Where a UDP message really goes: `(destination, source_local_addr)`,
/// readdressed when `destination` is the protected client port of a UE's
/// security association and it leaves from the P-CSCF's protected server port
/// ([`crate::ipsec::pcscf_udp_egress`]).
///
/// 3GPP TS 33.203 clause 7.1, UDP case: the P-CSCF "sends requests and
/// responses protected with ESP to a UE on the port port_pc"; the UE
/// "receives requests and responses protected with ESP on the port port_us".
/// TS 24.229 clause 5.2.2.2 NOTE 3: "in case of UDP the P-CSCF sends the
/// responses to a different UE's port then the one from which the request was
/// received from the UE", which is also why the `rport` of a protected request
/// is ignored, and clause 5.2.2.2 1A a) puts the P-CSCF's own requests on the
/// same flow. Every reply path hands its response here with the request's
/// source as `destination` and the socket it arrived on as
/// `source_local_addr`, and a request sent over a UE's captured flow is
/// addressed the same way, so this one point covers answered, relayed,
/// refused and retransmitted responses and requests alike. Without a P-CSCF
/// setup, a registrant's response is handed to the UE side instead.
///
/// Everything not over UDP is left alone: over TCP the message goes on the
/// connection. Nothing is dropped: a pair that cannot carry UDP is logged and
/// the message goes where it was going.
pub(super) fn protected_udp_egress(
    frame: &[u8],
    transport: Transport,
    destination: SocketAddr,
    source_local_addr: Option<SocketAddr>,
    state: &DispatcherState,
) -> (SocketAddr, Option<SocketAddr>) {
    let unchanged = (destination, source_local_addr);
    if transport != Transport::Udp {
        return unchanged;
    }
    let (Some(manager), Some(config)) =
        (state.ipsec_manager.as_deref(), state.ipsec_config.as_ref())
    else {
        return registrant_udp_response_egress(frame, destination, source_local_addr)
            .unwrap_or(unchanged);
    };
    crate::ipsec::pcscf_udp_egress(
        manager,
        config.pcscf_port_s,
        transport,
        destination,
        source_local_addr,
        crate::ipsec::is_request(frame),
    )
}

/// The UE side of [`protected_udp_egress`]: a UDP response siphon
/// sends as a registrant, from a UE's protected server port to the P-CSCF,
/// leaves from that UE's protected client port for the P-CSCF's protected
/// server port (TS 33.203 clause 7.1, UDP case; see
/// [`crate::registrant::RegistrantManager::ue_udp_response_egress`]). `None`
/// leaves it where it was going: no registrant, no source pin, a request, or
/// no IPsec entry answering from that socket.
fn registrant_udp_response_egress(
    frame: &[u8],
    destination: SocketAddr,
    source_local_addr: Option<SocketAddr>,
) -> Option<(SocketAddr, Option<SocketAddr>)> {
    let local = source_local_addr?;
    let manager = crate::registrant::manager()?;
    if !crate::transport::response_route::is_response(frame) {
        return None;
    }
    let (protected, client) = manager.ue_udp_response_egress(local, destination)?;
    debug!(
        from = %local,
        to = %protected,
        local = %client,
        "IPsec: UDP response from the UE's protected client port (TS 33.203 clause 7.1)"
    );
    Some((protected, Some(client)))
}

/// siphon's own endpoint on the HEP capture of a send leaving from
/// `source_local_addr`: that socket, else the transport's listener, else the
/// default local address, with a wildcard bind replaced by the advertised address
/// ([`DispatcherState::hep_local_addr`]).
fn hep_capture_local(
    state: &DispatcherState,
    transport: Transport,
    source_local_addr: Option<SocketAddr>,
) -> SocketAddr {
    let local = source_local_addr
        .or_else(|| state.listen_addrs.get(&transport).copied())
        .unwrap_or(state.local_addr);
    state.hep_local_addr(local, transport)
}

/// The HEP capture for the messages a spawned task puts on the wire.
///
/// A task that resends a message on a timer (the A-leg 2xx until its ACK, a
/// reliable provisional until its PRACK) holds the outbound channel but no
/// `DispatcherState`, so it cannot capture the way [`send_outbound_from`] does,
/// and those sends used to reach the transport uncaptured. Everything the capture
/// needs is resolved here, once, when the task is armed. Without HEP this is
/// `None`: nothing is cloned or resolved, and the task pays one branch per send.
#[derive(Clone)]
pub(super) struct TaskCapture {
    sender: Arc<HepSender>,
    local: SocketAddr,
}

impl TaskCapture {
    /// The capture for sends on `transport` leaving from `source_local_addr`, or
    /// `None` when HEP capture is off.
    pub(super) fn for_task(
        state: &DispatcherState,
        transport: Transport,
        source_local_addr: Option<SocketAddr>,
    ) -> Option<TaskCapture> {
        let sender = state.hep_sender.as_ref()?;
        Some(TaskCapture {
            sender: Arc::clone(sender),
            local: hep_capture_local(state, transport, source_local_addr),
        })
    }

    /// Capture `data` as sent to `destination`.
    pub(super) fn capture(&self, destination: SocketAddr, transport: Transport, data: &[u8]) {
        self.sender
            .capture_outbound(self.local, destination, transport, data);
    }
}

/// Serialize and enqueue `messages` as ONE outbound unit, so they leave in the
/// given order with nothing interleaved.
///
/// Separate `send_message_from` calls do not order on UDP — the workers share
/// the outbound channel and each owns its own socket, so two enqueues race (see
/// [`OutboundMessage::followups`]). Use this wherever the sequence is part of
/// the protocol rather than an accident of timing.
pub(super) fn send_messages_in_order_from(
    messages: Vec<SipMessage>,
    transport: Transport,
    destination: SocketAddr,
    connection_id: ConnectionId,
    source_local_addr: Option<SocketAddr>,
    state: &DispatcherState,
) {
    let mut frames = messages
        .into_iter()
        .map(|message| Bytes::from(message.to_bytes()));
    let Some(first) = frames.next() else {
        return;
    };
    send_frames_in_order_from(
        first,
        frames.collect(),
        transport,
        destination,
        connection_id,
        source_local_addr,
        state,
    )
}

/// [`send_messages_in_order_from`] for callers that already hold serialized
/// frames — `first` leaves before every entry of `followups`, in order.
#[allow(clippy::too_many_arguments)]
pub(super) fn send_frames_in_order_from(
    first: Bytes,
    followups: Vec<Bytes>,
    transport: Transport,
    destination: SocketAddr,
    connection_id: ConnectionId,
    source_local_addr: Option<SocketAddr>,
    state: &DispatcherState,
) {
    // The frames travel as one unit to one destination, so the first decides.
    let (destination, source_local_addr) =
        protected_udp_egress(&first, transport, destination, source_local_addr, state);

    // HEP sees each frame individually — they are distinct SIP messages on the
    // wire, and a capture that merged them would not decode.
    if let Some(ref hep) = state.hep_sender {
        let local = hep_capture_local(state, transport, source_local_addr);
        hep.capture_outbound(local, destination, transport, &first);
        for frame in &followups {
            hep.capture_outbound(local, destination, transport, frame);
        }
    }

    debug!(
        destination = %destination,
        frames = 1 + followups.len(),
        "sending ordered message group"
    );

    let outbound_message = OutboundMessage {
        connection_id,
        transport,
        destination,
        data: first,
        source_local_addr,
        server_name: None,
        verify_server: None,
        followups: if followups.is_empty() {
            None
        } else {
            Some(followups)
        },
    };

    if let Err(error) = state.outbound.send(outbound_message) {
        error!("failed to enqueue ordered outbound group: {error}");
    }
}

/// Serialize a SIP message and send it to a specific destination, pinning the
/// local egress socket via `source_local_addr`.  Used for reply-direction sends
/// (responses to inbound requests, server-transaction retransmits, and
/// siphon-originated in-dialog requests) so the packet leaves on the same local
/// socket the dialog is anchored on — multi-homed source-port parity, and
/// required by 3GPP TS 33.203 §7.4 for IPsec-protected REGISTER / MO INVITE
/// cycles.  Pass `None` to fall back to the default egress (single-listener
/// hosts / no anchor).
pub(super) fn send_message_from(
    message: SipMessage,
    transport: Transport,
    destination: SocketAddr,
    connection_id: ConnectionId,
    source_local_addr: Option<SocketAddr>,
    state: &DispatcherState,
) {
    let data = Bytes::from(message.to_bytes());
    remember_invite_final(&message, &data, state);

    debug!(
        destination = %destination,
        size = data.len(),
        "sending message"
    );

    send_outbound_from(
        data,
        transport,
        destination,
        connection_id,
        source_local_addr,
        state,
    );
}

/// Drain deferred messages queued by presence.notify() etc. during the handler
/// and send each one via the UacSender.  Called after the reply/relay has been
/// dispatched, so the reply is *enqueued* first (RFC 6665 §4.1.2.3 — the
/// notifier sends the initial NOTIFY after the 200 to the SUBSCRIBE).
///
/// By this point the reply path has already claimed any deferred message going
/// to the *same* peer as the reply and sent it as an ordered followup, so what
/// reaches here is addressed elsewhere and has nothing to be ordered against.
/// Enqueueing is not the same as leaving — on UDP the workers share the outbound
/// channel and each owns its own socket — which is why that ordering is done by
/// pairing the frames rather than by send order (see `OutboundMessage::followups`).
pub(super) fn flush_deferred_sends(_state: &DispatcherState) {
    let deferred = crate::script::api::proxy_utils::drain_deferred_sends();
    if deferred.is_empty() {
        return;
    }
    if let Some(uac_sender) = crate::script::api::proxy_utils::uac_sender() {
        for msg in deferred {
            uac_sender.send_request(msg.message, msg.destination, msg.transport);
        }
    } else {
        warn!("deferred sends queued but UAC sender not available");
    }
}
