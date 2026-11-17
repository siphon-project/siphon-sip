//! The ACK for a 2xx a P-CSCF relays is the one request the script never
//! sees, so what the script does to every other request in the dialog has to
//! hold for it here.
//!
//! Towards a UE (terminating side): the INVITE left from the Gm socket the
//! script pinned (`send_socket=` or a UDP flow). The ACK left from the default
//! UDP listener, the core side on a multi-homed host, with that listener's
//! address in its Via. A UE without IPsec answers only the address it has been
//! talking to, so it never accepted the ACK and retransmitted its 2xx.
//!
//! From a UE (originating side): an ACK over a protected port still carried the
//! UE's Security-Verify and `sec-agree` option tags (RFC 3329 §2.3.1), which
//! the next hop, and in the end the callee, must never see.

use super::originate_test_harness::{drain, socket, Sent};
use super::test_dispatcher::test_dispatcher;
use super::*;

const CORE: &str = "192.0.2.4:5060";
const GM: &str = "192.0.2.211:5060";
const PHONE: &str = "192.0.2.50:5060";
const CALL_ID: &str = "ack-egress@192.0.2.20";

fn parse(raw: &str) -> SipMessage {
    crate::sip::parser::parse_sip_message_bytes(raw.as_bytes()).expect("the message parses")
}

fn invite() -> SipMessage {
    parse(&format!(
        concat!(
            "INVITE sip:5111@{phone} SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 192.0.2.20:5060;branch=z9hG4bK-egress-invite\r\n",
            "Max-Forwards: 70\r\n",
            "From: <sip:5222@ims.example.test>;tag=caller-tag\r\n",
            "To: <sip:5111@ims.example.test>\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: 1 INVITE\r\n",
            "Contact: <sip:5222@192.0.2.20:5060>\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        phone = PHONE,
        call_id = CALL_ID,
    ))
}

fn ack(extra: &str) -> SipMessage {
    parse(&format!(
        concat!(
            "ACK sip:5111@{phone} SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 192.0.2.20:5060;branch=z9hG4bK-egress-ack\r\n",
            "Max-Forwards: 70\r\n",
            "From: <sip:5222@ims.example.test>;tag=caller-tag\r\n",
            "To: <sip:5111@ims.example.test>;tag=phone-tag\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: 1 ACK\r\n",
            "{extra}",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        phone = PHONE,
        call_id = CALL_ID,
        extra = extra,
    ))
}

fn inbound(message: &SipMessage) -> InboundMessage {
    InboundMessage {
        client_transport: None,
        connection_id: ConnectionId::default(),
        transport: Transport::Udp,
        local_addr: socket(CORE),
        remote_addr: socket("192.0.2.20:5060"),
        data: Bytes::from(message.to_bytes()),
    }
}

fn gm_pin() -> crate::transport::SendSocket {
    crate::transport::SendSocket {
        transport: Transport::Udp,
        addr: socket(GM),
        advertise: None,
    }
}

/// Relay the INVITE (with `pin`, as the script's `send_socket=`) so a session
/// exists, and return the dispatcher and the session.
fn relayed_session(
    pin: Option<&crate::transport::SendSocket>,
) -> (
    super::test_dispatcher::TestDispatcher,
    Arc<RwLock<ProxySession>>,
) {
    let dispatcher = test_dispatcher();
    let state = &dispatcher.state;
    let invite = invite();
    let server_key = TransactionKey::new(
        "z9hG4bK-egress-invite".to_string(),
        Method::Invite,
        "192.0.2.20:5060".to_string(),
    );
    relay_request(
        &invite,
        None,
        false,
        &inbound(&invite),
        Some(&server_key),
        state,
        None,
        None,
        None,
        None,
        None,
        pin,
        &[],
        None,
    );
    let session = state
        .session_store
        .get_by_dialog_key(CALL_ID, "caller-tag")
        .expect("the INVITE's session routes the ACK");
    (dispatcher, session)
}

fn the_ack(dispatcher: &super::test_dispatcher::TestDispatcher) -> Sent {
    let sent = drain(&dispatcher.udp);
    sent.into_iter()
        .find(|frame| frame.is(Method::Ack))
        .expect("an ACK was sent to the phone")
}

#[tokio::test(flavor = "multi_thread")]
async fn an_ack_to_a_ue_leaves_from_the_socket_its_invite_was_pinned_to() {
    let (dispatcher, session) = relayed_session(Some(&gm_pin()));
    let _ = drain(&dispatcher.udp);
    let ack = ack("");
    relay_ack_via_session(ack, session, false, &dispatcher.state);

    let sent = the_ack(&dispatcher);
    assert_eq!(sent.destination, socket(PHONE));
    assert_eq!(sent.source, Some(socket(GM)), "from the Gm socket");
    let via = sent.message.headers.get("Via").expect("a Via");
    assert!(
        via.starts_with("SIP/2.0/UDP 192.0.2.211:5060"),
        "the top Via names the Gm socket: {via}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_ack_for_an_unpinned_invite_is_sent_as_before() {
    let (dispatcher, session) = relayed_session(None);
    let _ = drain(&dispatcher.udp);
    relay_ack_via_session(ack(""), session, false, &dispatcher.state);

    assert_eq!(the_ack(&dispatcher).source, None);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_ack_from_a_protected_ue_leaves_without_its_security_agreement() {
    let (dispatcher, session) = relayed_session(None);
    let _ = drain(&dispatcher.udp);
    let extra = concat!(
        "Require: sec-agree\r\n",
        "Proxy-Require: sec-agree\r\n",
        "Security-Verify: ipsec-3gpp; q=0.1; alg=hmac-sha-1-96; prot=esp; mod=trans; ealg=null; spi-c=1; spi-s=2; port-c=5064; port-s=5066\r\n",
        "Security-Client: ipsec-3gpp; alg=hmac-sha-1-96\r\n",
        "P-Preferred-Identity: <sip:5222@ims.example.test>\r\n",
    );
    relay_ack_via_session(ack(extra), session, true, &dispatcher.state);

    let sent = the_ack(&dispatcher);
    for name in [
        "Require",
        "Proxy-Require",
        "Security-Verify",
        "Security-Client",
        "P-Preferred-Identity",
    ] {
        assert!(
            sent.message.headers.get(name).is_none(),
            "{name} must not reach the next hop: {:?}",
            sent.message.headers.get(name)
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_ack_not_from_a_protected_port_keeps_its_headers() {
    let (dispatcher, session) = relayed_session(None);
    let _ = drain(&dispatcher.udp);
    relay_ack_via_session(
        ack("Proxy-Require: sec-agree\r\n"),
        session,
        false,
        &dispatcher.state,
    );

    assert!(the_ack(&dispatcher)
        .message
        .headers
        .get("Proxy-Require")
        .is_some());
}

/// The capture of a relayed request names the socket it left from, not the
/// first listener of its transport: an operator reading the trace is told which
/// address the peer was spoken to from.
#[tokio::test(flavor = "multi_thread")]
async fn the_capture_of_a_pinned_request_names_the_socket_it_left_from() {
    let collector = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("a collector socket");
    let hep = crate::hep::HepSender::new(&crate::config::HepConfig {
        endpoint: collector.local_addr().expect("an address").to_string(),
        version: 3,
        transport: crate::config::HepTransport::Udp,
        agent_id: None,
        ca_cert: None,
        tls_server_name: None,
        error_log_interval: 30,
    })
    .await
    .expect("a HEP sender");
    let mut dispatcher = test_dispatcher();
    dispatcher.state.hep_sender = Some(Arc::new(hep));
    let invite = invite();
    let server_key = TransactionKey::new(
        "z9hG4bK-egress-invite".to_string(),
        Method::Invite,
        "192.0.2.20:5060".to_string(),
    );
    relay_request(
        &invite,
        None,
        false,
        &inbound(&invite),
        Some(&server_key),
        &dispatcher.state,
        None,
        None,
        None,
        None,
        None,
        Some(&gm_pin()),
        &[],
        None,
    );

    let mut buffer = vec![0u8; 4096];
    let (length, _) = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        collector.recv_from(&mut buffer),
    )
    .await
    .expect("a capture arrives")
    .expect("a datagram");
    let capture = &buffer[..length];
    let gm = [192u8, 0, 2, 211];
    let core = [192u8, 0, 2, 4];
    assert!(
        capture.windows(4).any(|window| window == gm),
        "the capture's source is the Gm socket"
    );
    assert!(!capture.windows(4).any(|window| window == core));
}
