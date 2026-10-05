//! Shared fixtures for the tests that place calls with `originate` and read
//! what siphon put on the wire.
//!
//! A frame is kept with the socket it was pinned to and the connection it was
//! addressed on, not only its destination: a phone registered over a captured
//! flow is reachable only on that flow, so where an INVITE *left from* is as
//! much the assertion as where it went.

use std::sync::Arc;

use super::test_dispatcher::{test_dispatcher, TestDispatcher};
use super::*;
use crate::rtpengine::test_native_engine::NativeTestEngine;

/// One frame siphon put on the wire.
#[derive(Debug, Clone)]
pub(super) struct Sent {
    pub(super) destination: SocketAddr,
    pub(super) transport: Transport,
    /// The local socket the frame was pinned to, if any.
    pub(super) source: Option<SocketAddr>,
    /// The connection the frame was addressed on.
    pub(super) connection_id: ConnectionId,
    pub(super) message: SipMessage,
}

impl Sent {
    pub(super) fn is(&self, method: Method) -> bool {
        self.message.method() == Some(&method)
    }
}

/// Every frame waiting on `receiver`, in order.
pub(super) fn drain(receiver: &flume::Receiver<OutboundMessage>) -> Vec<Sent> {
    let mut sent = Vec::new();
    while let Ok(outbound) = receiver.try_recv() {
        for frame in outbound.frames() {
            sent.push(Sent {
                destination: outbound.destination,
                transport: outbound.transport,
                source: outbound.source_local_addr,
                connection_id: outbound.connection_id,
                message: crate::sip::parser::parse_sip_message_bytes(frame)
                    .expect("siphon sent a message that parses"),
            });
        }
    }
    sent
}

/// The requests of `method` sent to `destination`.
pub(super) fn requests_to(sent: &[Sent], destination: SocketAddr, method: Method) -> Vec<Sent> {
    sent.iter()
        .filter(|frame| frame.destination == destination && frame.is(method.clone()))
        .cloned()
        .collect()
}

/// A literal socket address.
pub(super) fn socket(text: &str) -> SocketAddr {
    text.parse().expect("a literal socket address")
}

/// A dispatcher whose media is anchored on `engine`, the only backend that can
/// answer an offerless originate's 2xx locally.
pub(super) fn anchored_dispatcher(engine: &NativeTestEngine) -> TestDispatcher {
    let mut dispatcher = test_dispatcher();
    dispatcher.state.rtpengine_set = Some(engine.backend());
    dispatcher.state.rtpengine_profiles = Some(Arc::new(crate::rtpengine::ProfileRegistry::new()));
    dispatcher.state.rtpengine_sessions =
        Some(Arc::new(crate::rtpengine::MediaSessionStore::new()));
    dispatcher
}

/// Replace the dispatcher's egress with fresh channels and return the one the
/// stream transports (TCP, TLS, WS, WSS) write to. `dispatcher.udp` is the new
/// UDP channel.
pub(super) fn with_stream_egress(
    mut dispatcher: TestDispatcher,
) -> (TestDispatcher, flume::Receiver<OutboundMessage>) {
    let (udp_sender, udp) = flume::unbounded();
    let (stream_sender, stream) = flume::unbounded();
    dispatcher.state.outbound = Arc::new(OutboundRouter {
        udp: udp_sender.into(),
        udp_by_local: std::collections::HashMap::new(),
        tcp: stream_sender.clone(),
        tls: stream_sender.clone(),
        ws: stream_sender.clone(),
        wss: stream_sender,
        sctp: None,
    });
    dispatcher.udp = udp;
    (dispatcher, stream)
}

/// What an originate carries when siphon anchors its media: an offerless
/// INVITE to `to`, answered locally on the callee's 2xx offer.
pub(super) fn anchored_params(to: &str) -> OriginateParams {
    OriginateParams {
        to: to.to_string(),
        to_display: None,
        from: Some("sip:1000@siphon.example.com".to_string()),
        from_display: None,
        next_hop: None,
        p_asserted_identity: None,
        privacy: None,
        headers: Vec::new(),
        timeout_secs: 30,
        media: OriginateMedia::Anchor {
            profile: "rtp_passthrough".to_string(),
            ws_uri: None,
        },
        session_timer: None,
    }
}

/// The SDP offer a phone at `host` puts in its 2xx to an offerless INVITE.
pub(super) fn phone_offer(host: &str) -> String {
    format!(
        concat!(
            "v=0\r\n",
            "o=phone 4001 4001 IN IP4 {host}\r\n",
            "s=phone\r\n",
            "c=IN IP4 {host}\r\n",
            "t=0 0\r\n",
            "m=audio 42000 RTP/AVP 0 101\r\n",
            "a=rtpmap:0 PCMU/8000\r\n",
            "a=rtpmap:101 telephone-event/8000\r\n",
            "a=sendrecv\r\n",
        ),
        host = host
    )
}

/// A phone's response to `invite`: `status_code`, tagged `to_tag`, with a
/// Contact at `contact` and `body` as its SDP when there is one.
pub(super) fn phone_response(
    invite: &SipMessage,
    status_code: u16,
    reason: &str,
    to_tag: &str,
    contact: &str,
    body: Option<&str>,
) -> SipMessage {
    let header = |name: &str| {
        invite
            .headers
            .get(name)
            .cloned()
            .unwrap_or_else(|| panic!("the INVITE has a {name}"))
    };
    let (content, length) = match body {
        Some(sdp) => ("Content-Type: application/sdp\r\n".to_string(), sdp.len()),
        None => (String::new(), 0),
    };
    let raw = format!(
        concat!(
            "SIP/2.0 {status} {reason}\r\n",
            "Via: {via}\r\n",
            "From: {from}\r\n",
            "To: {to};tag={to_tag}\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: {cseq}\r\n",
            "Contact: <{contact}>\r\n",
            "{content}",
            "Content-Length: {length}\r\n",
            "\r\n",
            "{body}",
        ),
        status = status_code,
        reason = reason,
        via = header("Via"),
        from = header("From"),
        to = header("To"),
        to_tag = to_tag,
        call_id = header("Call-ID"),
        cseq = header("CSeq"),
        contact = contact,
        content = content,
        length = length,
        body = body.unwrap_or_default(),
    );
    crate::sip::parser::parse_sip_message_bytes(raw.as_bytes())
        .expect("the phone's response parses")
}

/// A phone at `from` sends `response`: it arrives on siphon's UDP listener and
/// goes through the whole response path, branch lookup included.
pub(super) fn phone_sends(state: &DispatcherState, from: SocketAddr, response: &SipMessage) {
    let status_code = response.status_code().expect("a response");
    handle_response(
        InboundMessage {
            client_transport: None,
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: socket("192.0.2.1:5060"),
            remote_addr: from,
            data: Bytes::new(),
        },
        response.clone(),
        status_code,
        state,
    );
}

/// The phone at `phone` takes `invite` with a `100 Trying`: it holds the INVITE
/// and has not alerted anyone yet. Hop by hop, so nobody is told and it is no
/// progress (RFC 3261 §16.7 step 2), but it is a provisional, and a CANCEL for
/// that INVITE has to wait for one (§9.1).
pub(super) fn phone_tries(state: &DispatcherState, phone: &str, invite: &SipMessage) {
    phone_sends(
        state,
        socket(phone),
        &phone_response(
            invite,
            100,
            "Trying",
            "trying",
            &format!("sip:phone@{phone}"),
            None,
        ),
    );
}

/// A profile that pins media ingress to the signalling source on both halves.
pub(super) const PINNED_INGRESS: &str = "pinned_ingress";

/// The built-in profiles plus [`PINNED_INGRESS`].
pub(super) fn pinned_ingress_profiles() -> Arc<crate::rtpengine::ProfileRegistry> {
    let half = crate::config::NgFlagsConfig {
        received_from: true,
        ..Default::default()
    };
    let mut custom = std::collections::HashMap::new();
    custom.insert(
        PINNED_INGRESS.to_string(),
        crate::config::MediaProfileConfig {
            offer: half.clone(),
            answer: half,
        },
    );
    Arc::new(crate::rtpengine::ProfileRegistry::from_config(&custom))
}
