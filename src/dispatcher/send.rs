//! Handing a built message to the transport.
//!
//! `send_message_from` has 39 callers — the last step of almost every path in
//! the dispatcher — so it is deliberately thin.

use super::*;

/// Send raw bytes to a specific destination via the outbound channel,
/// with automatic HEP capture.  Used for connection-affine sends (CANCELs,
/// in-dialog ACKs, registrant retries) that must reuse a specific connection.
pub(super) fn send_outbound(
    data: Bytes,
    transport: Transport,
    destination: SocketAddr,
    connection_id: ConnectionId,
    state: &DispatcherState,
) {
    send_outbound_from(data, transport, destination, connection_id, None, state);
}

/// Like [`send_outbound`] but pins the local egress address.  Reply
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
    // HEP capture — outbound (sent to network)
    if let Some(ref hep) = state.hep_sender {
        let local = source_local_addr
            .or_else(|| state.listen_addrs.get(&transport).copied())
            .unwrap_or(state.local_addr);
        hep.capture_outbound(
            state.hep_local_addr(local, transport),
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
        followups: None,
    };

    if let Err(error) = state.outbound.send(outbound_message) {
        error!("failed to enqueue outbound message: {error}");
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
    // HEP sees each frame individually — they are distinct SIP messages on the
    // wire, and a capture that merged them would not decode.
    if let Some(ref hep) = state.hep_sender {
        let local = source_local_addr
            .or_else(|| state.listen_addrs.get(&transport).copied())
            .unwrap_or(state.local_addr);
        let local = state.hep_local_addr(local, transport);
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
