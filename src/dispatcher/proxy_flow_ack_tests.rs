//! A 2xx ACK for an INVITE the script relayed over a captured flow
//! (`request.relay(flow=...)`, RFC 5626 §5.3) goes back over that flow.
//!
//! A phone behind NAT registers over TLS from its public address and puts its
//! private address in the Contact. The INVITE reaches it over the connection it
//! opened; its 2xx Contact, and so the caller's ACK Request-URI (RFC 3261
//! §12.2.1.1), still names the private address. Resolving that Request-URI
//! opened a fresh connection to an address nobody can reach, the ACK never
//! arrived, and the phone retransmitted its 2xx until it gave up on the call.

use super::originate_test_harness::{drain, socket, with_stream_egress, Sent};
use super::test_dispatcher::test_dispatcher;
use super::*;

const CALLER: &str = "192.0.2.10:5060";
const SIPHON: &str = "192.0.2.1:5060";
/// Where the phone's TLS connection comes from: its NAT's public side.
const PHONE_PUBLIC: &str = "203.0.113.37:12104";
/// The phone's Contact: the address it has behind the NAT.
const PHONE_CONTACT: &str = "sip:+15550100001@10.20.30.40:12104;transport=TLS";
const PHONE_CONNECTION: u64 = 77;
const CALL_ID: &str = "flow-ack@192.0.2.10";

fn parse(raw: &str) -> SipMessage {
    crate::sip::parser::parse_sip_message_bytes(raw.as_bytes()).expect("the message parses")
}

fn caller_invite() -> SipMessage {
    parse(&format!(
        concat!(
            "INVITE {contact} SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-flow-ack-invite\r\n",
            "Max-Forwards: 70\r\n",
            "From: <sip:+15550100002@siphon.example.com>;tag=caller-tag\r\n",
            "To: <sip:+15550100001@siphon.example.com>\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: 1 INVITE\r\n",
            "Contact: <sip:+15550100002@192.0.2.10:5060>\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        contact = PHONE_CONTACT,
        call_id = CALL_ID,
    ))
}

fn caller_ack() -> SipMessage {
    parse(&format!(
        concat!(
            "ACK {contact} SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-flow-ack-ack\r\n",
            "Max-Forwards: 70\r\n",
            "From: <sip:+15550100002@siphon.example.com>;tag=caller-tag\r\n",
            "To: <sip:+15550100001@siphon.example.com>;tag=phone-tag\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: 1 ACK\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        contact = PHONE_CONTACT,
        call_id = CALL_ID,
    ))
}

fn from_caller(message: &SipMessage) -> InboundMessage {
    InboundMessage {
        client_transport: None,
        connection_id: ConnectionId::default(),
        transport: Transport::Udp,
        local_addr: socket(SIPHON),
        remote_addr: socket(CALLER),
        data: Bytes::from(message.to_bytes()),
    }
}

fn acks(sent: &[Sent]) -> Vec<&Sent> {
    sent.iter().filter(|frame| frame.is(Method::Ack)).collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_2xx_ack_to_a_phone_behind_nat_goes_over_the_flow_its_invite_took() {
    let (dispatcher, stream) = with_stream_egress(test_dispatcher());
    let state = &dispatcher.state;
    // The phone's TLS connection, registered by the listener that accepted it.
    state.stream_connections.register(
        socket(PHONE_PUBLIC),
        Transport::Tls,
        ConnectionId(PHONE_CONNECTION),
    );
    let flow = crate::script::api::registrar::PyFlow {
        transport: "tls".to_string(),
        source_addr: socket(PHONE_PUBLIC),
        local_addr: socket(SIPHON),
        connection_id: PHONE_CONNECTION,
        kind: crate::script::api::registrar::FlowKind::Inbound,
    };

    let invite = caller_invite();
    let server_key = TransactionKey::new(
        "z9hG4bK-flow-ack-invite".to_string(),
        Method::Invite,
        CALLER.to_string(),
    );
    relay_request(
        &invite,
        None,
        false,
        &from_caller(&invite),
        Some(&server_key),
        state,
        None,
        None,
        None,
        None,
        Some(&flow),
        None,
        &[],
    );
    let invites: Vec<Sent> = drain(&stream)
        .into_iter()
        .filter(|frame| frame.is(Method::Invite))
        .collect();
    assert_eq!(invites.len(), 1, "the INVITE goes over the phone's flow");
    assert_eq!(invites[0].destination, socket(PHONE_PUBLIC));

    // The caller ACKs the phone's 2xx, addressed to the phone's Contact with
    // no Route left: the remote target the INVITE was relayed to.
    let ack = caller_ack();
    let session = state
        .session_store
        .get_by_dialog_key(CALL_ID, "caller-tag")
        .expect("the INVITE's session routes the ACK");
    handle_ack_via_session(from_caller(&ack), ack, session, state);

    let sent = drain(&stream);
    let acks = acks(&sent);
    assert_eq!(acks.len(), 1, "one ACK goes to the phone: {sent:?}");
    assert_eq!(
        acks[0].destination,
        socket(PHONE_PUBLIC),
        "over the phone's flow, never to its private Contact"
    );
    assert_eq!(acks[0].transport, Transport::Tls);
    assert_eq!(acks[0].connection_id, ConnectionId(PHONE_CONNECTION));
}
