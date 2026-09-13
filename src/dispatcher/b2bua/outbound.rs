//! Sending to a B-leg, and the retransmit timers that back it.
//!
//! `send_b2bua_to_bleg` has 16 callers — every path that puts a message on the
//! B-leg goes through here.

use crate::dispatcher::*;

/// Send a siphon-originated message to a B-leg.
///
/// `source_local_addr` is the leg's anchored egress socket
/// ([`LegTransport::local_addr`]) — set when the leg was dialled over a
/// captured flow (`call.dial(flow=…)`), `None` otherwise.  A flow-dialled leg
/// MUST keep leaving from that socket: on an IPsec sec-agree UE leg it is the
/// protected client port, and the kernel XFRM selector matches nothing else, so
/// a default-listener send goes out unprotected (3GPP TS 33.203 §7.4).  `None`
/// falls back to the default egress, which is what every non-flow leg and every
/// single-listener host has always done.
///
/// The pin is applied to UDP only, where it selects the listener socket to
/// egress from (`udp_by_local`).  On a stream transport the leg is reached over
/// a live connection instead — [`send_to_target`] reuses the accepted
/// TCP/TLS/WS/WSS connection to the destination, and for a client-initiated
/// WS/WSS flow that is the *only* way to reach the peer (RFC 7118 §5) — so
/// handing it a source bind there would dial a fresh connection instead.
pub fn send_b2bua_to_bleg(
    message: SipMessage,
    transport: Transport,
    destination: SocketAddr,
    source_local_addr: Option<SocketAddr>,
    state: &DispatcherState,
) {
    let data = Bytes::from(message.to_bytes());
    let target = RelayTarget {
        address: destination,
        transport: Some(transport),
        server_name: None,
    };
    let send_source = match transport {
        Transport::Udp => source_local_addr,
        _ => None,
    };
    // The schedule has to record the socket the datagram will *actually* leave
    // from, which for an IPsec destination is the auto-source `send_to_target`
    // resolves rather than the pin handed in here.
    arm_b2bua_retransmit(
        &message,
        &data,
        transport,
        destination,
        udp_egress_source(transport, destination, send_source),
        state,
    );
    send_to_target(
        data,
        &target,
        transport,
        ConnectionId::default(),
        send_source,
        state,
    );
}

/// Send siphon-originated messages to a B-leg in the given order, with nothing
/// interleaved.
///
/// [`send_b2bua_to_bleg`] once per message does not order them on UDP: the
/// workers share the outbound channel and each owns its own socket, so two
/// enqueues race to the wire (see [`OutboundMessage::followups`]). An ACK and
/// the BYE that releases the dialog it confirms are such a pair: a callee that
/// gets the BYE first has not yet seen the dialog confirmed (RFC 3261 §13.2.2.4,
/// §15), and a strict one rejects or drops it. Each request's retransmit
/// schedule is armed as usual. Stream transports already keep order on their
/// connection, so there the messages go out one by one.
pub fn send_b2bua_sequence_to_bleg(
    messages: Vec<SipMessage>,
    transport: Transport,
    destination: SocketAddr,
    source_local_addr: Option<SocketAddr>,
    state: &DispatcherState,
) {
    if !matches!(transport, Transport::Udp) {
        for message in messages {
            send_b2bua_to_bleg(message, transport, destination, source_local_addr, state);
        }
        return;
    }
    // The socket every frame leaves from, the same one `send_to_target` would
    // pick: the IPsec auto-source for a protected destination, else the pin.
    let egress = udp_egress_source(transport, destination, source_local_addr);
    let mut frames = Vec::with_capacity(messages.len());
    for message in &messages {
        let data = Bytes::from(message.to_bytes());
        arm_b2bua_retransmit(message, &data, transport, destination, egress, state);
        frames.push(data);
    }
    let mut frames = frames.into_iter();
    let Some(first) = frames.next() else {
        return;
    };
    send_frames_in_order_from(
        first,
        frames.collect(),
        transport,
        destination,
        ConnectionId::default(),
        egress,
        state,
    );
}

/// Arm an RFC 3261 §17.1 retransmit schedule for a siphon-originated B2BUA
/// request, keyed on its own topmost Via branch.
///
/// Only requests qualify, and only those that expect a response:
///
/// * **Responses** also travel through [`send_b2bua_to_bleg`] (the B2BUA relays
///   the far leg's provisionals and finals through it). Response
///   retransmission belongs to the server transaction, never here.
/// * **ACK** is excluded by RFC 3261 §17.1.1.3: an ACK for a non-2xx final is
///   re-emitted only in answer to a retransmitted final, and the 2xx ACK is
///   re-emitted by the TU when the 2xx is retransmitted (which
///   [`crate::b2bua::actor::CallActorStore`] already drives). Putting ACK on a
///   timer would flood the peer.
///
/// A message with no parseable Via branch cannot be correlated to its response,
/// so it is left unarmed rather than retransmitted blindly.
pub fn arm_b2bua_retransmit(
    message: &SipMessage,
    data: &Bytes,
    transport: Transport,
    destination: SocketAddr,
    source_local_addr: Option<SocketAddr>,
    state: &DispatcherState,
) {
    let method = match message.method() {
        Some(method) if *method != crate::sip::message::Method::Ack => method.clone(),
        // A response, or an ACK — see the doc comment.
        _ => return,
    };

    let branch = match message
        .headers
        .get("Via")
        .and_then(|raw| Via::parse_multi(raw).ok())
        .and_then(|vias| vias.first().and_then(|via| via.branch.clone()))
    {
        Some(branch) => branch,
        None => return,
    };

    // RFC 3261 §9.1: a CANCEL abandons the INVITE it shares a branch with, so
    // stop retransmitting that INVITE the moment we cancel it. Doing this here
    // covers every site that emits a CANCEL (answer timeout, LCR ring timeout,
    // upstream CANCEL relay, deferred CANCEL drain) from one place.
    if method == crate::sip::message::Method::Cancel {
        state
            .b2bua_retransmits
            .disarm(&crate::b2bua::retransmit::RetransmitKey::new(
                branch.clone(),
                crate::sip::message::Method::Invite,
            ));
    }

    state.b2bua_retransmits.arm(
        crate::b2bua::retransmit::RetransmitKey::new(branch, method),
        data.clone(),
        crate::b2bua::retransmit::RetransmitTarget {
            destination,
            transport,
            // Schedules exist for UDP only (`B2buaRetransmits::arm` refuses
            // reliable transports), and UDP egress selects its socket from
            // `source_local_addr`, never from the connection id.
            connection_id: ConnectionId::default(),
            source_local_addr,
        },
        std::time::Instant::now(),
    );
}

/// Cancel the retransmit schedule of the request this response answers.
///
/// Reads the branch off the topmost Via and the method off CSeq — the response
/// echoes both, per RFC 3261 §8.2.6.2 — so a CANCEL's 200 stops the CANCEL and
/// leaves the INVITE it shares a branch with alone (§9.1). Called for every
/// inbound response; one that belongs to no B2BUA leg simply misses.
pub fn disarm_b2bua_retransmit_for_response(message: &SipMessage, state: &DispatcherState) {
    // This runs on every inbound response, including the entire proxy datapath
    // where nothing is ever armed. Bail on one relaxed atomic read before
    // building a key — that would otherwise cost a String clone and a shard
    // lock per message at full CPS.
    if !state.b2bua_retransmits.is_armed() {
        return;
    }

    let branch = match message
        .headers
        .get("Via")
        .and_then(|raw| Via::parse_multi(raw).ok())
        .and_then(|vias| vias.first().and_then(|via| via.branch.clone()))
    {
        Some(branch) => branch,
        None => return,
    };
    let method = match message
        .headers
        .get("CSeq")
        .and_then(|raw| crate::sip::headers::cseq::CSeq::parse(raw).ok())
    {
        Some(cseq) => cseq.method,
        None => return,
    };

    state
        .b2bua_retransmits
        .disarm(&crate::b2bua::retransmit::RetransmitKey::new(
            branch, method,
        ));
}
