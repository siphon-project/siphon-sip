//! The B-leg's answer is ACKed by siphon as its UAC, on arrival and on every
//! retransmission (RFC 3261 §13.2.2.4), whatever the caller's ACK is doing.
//!
//! The caller's ACK confirms a different dialog. Holding the far leg's ACK until
//! it arrives left that leg unconfirmed whenever the caller's ACK was late or
//! never came: the callee retransmitted its 2xx for all of 64*T1 (§13.3.1.4), each
//! copy was absorbed, and a callee that gates its media on the ACK never started
//! it.
//!
//! Driven through the dispatcher: the B-leg is dialled by
//! [`b2bua_send_b_leg_invite`], answers through [`handle_b2bua_response`], and the
//! caller's ACK arrives through [`handle_request`], with everything siphon sends
//! read back off the UDP egress channel.

use super::lcr_ring_timeout_tests::top_via_branch;
use super::test_dispatcher::{test_dispatcher, TestDispatcher};
use super::*;

const CALLER: &str = "192.0.2.10:5060";
const CALLEE: &str = "198.51.100.77:5060";
const CALLER_CALL_ID: &str = "caller-call@192.0.2.10";

/// The callee's remote target: an opaque userpart and parameters whose names are
/// mixed case and whose values carry `_` and `-`. The ACK has to name it exactly
/// (RFC 3261 §12.1.2, §19.1.4).
const CALLEE_TARGET: &str =
    "sip:opaque-7f3a@198.51.100.77:5060;transport=udp;Tk=ab_12;RouteId=9;LegRef=0a0a-0b0b";

/// The caller's INVITE, with an offer in it.
fn caller_invite() -> SipMessage {
    let sdp = concat!(
        "v=0\r\n",
        "o=- 1 1 IN IP4 192.0.2.10\r\n",
        "s=-\r\n",
        "c=IN IP4 192.0.2.10\r\n",
        "t=0 0\r\n",
        "m=audio 40000 RTP/AVP 0 8 101\r\n",
        "a=rtpmap:0 PCMU/8000\r\n",
        "a=rtpmap:8 PCMA/8000\r\n",
        "a=rtpmap:101 telephone-event/8000\r\n",
    );
    let raw = format!(
        concat!(
            "INVITE sip:15550100042@siphon.example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-caller-invite\r\n",
            "Max-Forwards: 70\r\n",
            "From: <sip:15550100001@siphon.example.com>;tag=caller-tag\r\n",
            "To: <sip:15550100042@siphon.example.com>\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: 1 INVITE\r\n",
            "Contact: <sip:15550100001@192.0.2.10:5060>\r\n",
            "Supported: timer\r\n",
            "Content-Type: application/sdp\r\n",
            "Content-Length: {length}\r\n",
            "\r\n",
            "{sdp}",
        ),
        call_id = CALLER_CALL_ID,
        length = sdp.len(),
        sdp = sdp,
    );
    parse_sip_message_bytes(raw.as_bytes()).expect("the caller's INVITE parses")
}

/// One message siphon put on the wire, with the socket it asked to leave from.
struct Sent {
    destination: SocketAddr,
    source_local_addr: Option<SocketAddr>,
    message: SipMessage,
}

impl Sent {
    fn is_ack(&self) -> bool {
        self.message.method() == Some(&Method::Ack)
    }
}

/// A caller's call bridged to one callee through a real dispatcher.
struct Call {
    state: Arc<DispatcherState>,
    udp: flume::Receiver<OutboundMessage>,
    call_id: String,
    invite: SipMessage,
    invite_source: Option<SocketAddr>,
}

impl Call {
    /// The caller's INVITE arrives and siphon dials the callee.
    fn dial() -> Call {
        let TestDispatcher { state, udp } = test_dispatcher();
        let state = Arc::new(state);
        let call_id = state.call_actors.create_call(Leg::new_a_leg(
            CALLER_CALL_ID.to_string(),
            "caller-tag".to_string(),
            "z9hG4bK-caller-invite".to_string(),
            LegTransport {
                remote_addr: CALLER.parse().expect("a literal address"),
                connection_id: ConnectionId::default(),
                transport: Transport::Udp,
                local_addr: None,
            },
        ));
        let a_leg_invite = Arc::new(Mutex::new(caller_invite()));
        state
            .call_actors
            .set_a_leg_invite(&call_id, Arc::clone(&a_leg_invite));
        let dialled = {
            let guard = a_leg_invite.lock().expect("the A-leg INVITE lock");
            b2bua_send_b_leg_invite(
                &call_id,
                "sip:15550100042@198.51.100.77:5060",
                Some("sip:198.51.100.77:5060"),
                None,
                &[],
                None,
                None,
                &guard,
                None,
                None,
                None,
                None,
                &[],
                &state,
            )
        };
        assert!(dialled, "the callee was not dialled");

        let invite = drain(&udp)
            .into_iter()
            .find(|sent| sent.message.method() == Some(&Method::Invite))
            .expect("siphon sent the callee an INVITE");
        Call {
            state,
            udp,
            call_id,
            invite_source: invite.source_local_addr,
            invite: invite.message,
        }
    }

    /// Everything siphon has put on the wire since the last look, in order.
    fn wire(&self) -> Vec<Sent> {
        drain(&self.udp)
    }

    /// The callee sends `response` for the INVITE siphon sent it.
    fn callee_sends(&self, response: &str) {
        let mut message =
            parse_sip_message_bytes(response.as_bytes()).expect("the callee's response parses");
        let status_code = message.status_code().expect("a response");
        let handled = handle_b2bua_response(
            &self.call_id,
            &top_via_branch(&self.invite),
            &mut message,
            status_code,
            CALLEE.parse().expect("a literal address"),
            &self.state,
        );
        assert!(
            handled,
            "the call was gone when the callee's {status_code} arrived"
        );
    }

    /// The callee's response to the INVITE: its Via, From, Call-ID and CSeq, a
    /// tagged To, its remote target, and whatever else `extra` adds.
    fn callee_response(&self, status_line: &str, extra: &str, body: &str) -> String {
        let header = |name: &str| {
            self.invite
                .headers
                .get(name)
                .map(|value| value.to_string())
                .unwrap_or_else(|| panic!("siphon's INVITE has no {name}"))
        };
        let mut raw = format!("SIP/2.0 {status_line}\r\n");
        raw.push_str(&format!("Via: {}\r\n", header("Via")));
        raw.push_str(&format!("From: {}\r\n", header("From")));
        raw.push_str(&format!("To: {};tag=callee-tag\r\n", header("To")));
        raw.push_str(&format!("Call-ID: {}\r\n", header("Call-ID")));
        raw.push_str(&format!("CSeq: {}\r\n", header("CSeq")));
        raw.push_str(&format!("Contact: <{CALLEE_TARGET}>\r\n"));
        raw.push_str(extra);
        if body.is_empty() {
            raw.push_str("Content-Length: 0\r\n\r\n");
        } else {
            raw.push_str("Content-Type: application/sdp\r\n");
            raw.push_str(&format!("Content-Length: {}\r\n\r\n{body}", body.len()));
        }
        raw
    }

    /// The callee rings and answers, with `extra` headers on the 200. Returns the
    /// 200 as sent, for a test to retransmit.
    fn callee_answers(&self, extra: &str) -> String {
        self.callee_sends(&self.callee_response("180 Ringing", "", ""));
        let answer = self.callee_response(
            "200 OK",
            &format!(
                concat!(
                    "Supported: timer\r\n",
                    "Require: timer\r\n",
                    "Session-Expires: 1800;refresher=uac\r\n",
                    "{}",
                ),
                extra
            ),
            concat!(
                "v=0\r\n",
                "o=- 1 1 IN IP4 198.51.100.78\r\n",
                "s=-\r\n",
                "c=IN IP4 198.51.100.78\r\n",
                "t=0 0\r\n",
                "m=audio 30000 RTP/AVP 0 101\r\n",
                "a=rtpmap:0 PCMU/8000\r\n",
                "a=rtpmap:101 telephone-event/8000\r\n",
            ),
        );
        self.callee_sends(&answer);
        answer
    }

    /// The caller ACKs the 200 siphon relayed to it.
    fn caller_acks(&self, relayed_200: &SipMessage) {
        let raw = format!(
            concat!(
                "ACK sip:192.0.2.1:5060;transport=udp SIP/2.0\r\n",
                "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-caller-ack\r\n",
                "Max-Forwards: 70\r\n",
                "From: {from}\r\n",
                "To: {to}\r\n",
                "Call-ID: {call_id}\r\n",
                "CSeq: 1 ACK\r\n",
                "Content-Length: 0\r\n",
                "\r\n",
            ),
            from = relayed_200
                .headers
                .from()
                .expect("the relayed 200 has a From"),
            to = relayed_200.headers.to().expect("the relayed 200 has a To"),
            call_id = CALLER_CALL_ID,
        );
        let message = parse_sip_message_bytes(raw.as_bytes()).expect("the caller's ACK parses");
        handle_request(
            InboundMessage {
                connection_id: ConnectionId::default(),
                transport: Transport::Udp,
                local_addr: "192.0.2.1:5060".parse().expect("a literal address"),
                remote_addr: CALLER.parse().expect("a literal address"),
                data: Bytes::from(raw),
            },
            message,
            "ACK".to_string(),
            &self.state,
        );
    }

    fn callee_leg_acked(&self) -> bool {
        self.state
            .call_actors
            .get_call(&self.call_id)
            .and_then(|call| {
                call.winner
                    .and_then(|index| call.b_legs.get(index).cloned())
            })
            .is_some_and(|leg| leg.initial_acked)
    }
}

/// Everything on `udp` so far, in the order siphon sent it.
fn drain(udp: &flume::Receiver<OutboundMessage>) -> Vec<Sent> {
    let mut sent = Vec::new();
    while let Ok(outbound) = udp.try_recv() {
        sent.push(Sent {
            destination: outbound.destination,
            source_local_addr: outbound.source_local_addr,
            message: parse_sip_message_bytes(&outbound.data)
                .expect("siphon sent a message that parses"),
        });
    }
    sent
}

/// The ACKs among `sent`.
fn acks(sent: &[Sent]) -> Vec<&Sent> {
    sent.iter().filter(|sent| sent.is_ack()).collect()
}

fn request_line(message: &SipMessage) -> String {
    let text = String::from_utf8(message.to_bytes()).expect("serialized SIP is UTF-8");
    text.split("\r\n").next().expect("a start line").to_string()
}

fn caller() -> SocketAddr {
    CALLER.parse().expect("a literal address")
}

fn callee() -> SocketAddr {
    CALLEE.parse().expect("a literal address")
}

/// The failure this exists for. The callee answers and the caller's ACK does not
/// come: the ACK is owed to the callee anyway, the moment its 2xx arrives, and it
/// names the callee's remote target exactly.
#[tokio::test(flavor = "multi_thread")]
async fn the_callee_2xx_is_acked_on_arrival_without_waiting_for_the_caller() {
    let call = Call::dial();
    call.callee_answers("");

    let sent = call.wire();
    assert!(
        sent.iter()
            .any(|sent| sent.destination == caller() && sent.message.status_code() == Some(200)),
        "the answer was relayed to the caller"
    );
    let acks = acks(&sent);
    assert_eq!(
        acks.len(),
        1,
        "one ACK for the one 2xx, before the caller has ACKed anything (RFC 3261 §13.2.2.4)"
    );
    let ack = acks[0];
    assert_eq!(ack.destination, callee());
    // The socket the INVITE left from, so the sent-by below is one the callee
    // has already answered.
    assert_eq!(ack.source_local_addr, call.invite_source);

    // RFC 3261 §13.2.2.4 / §12.1.2: the Request-URI is the 2xx's Contact, byte
    // for byte, parameter names in their own case.
    assert_eq!(
        request_line(&ack.message),
        format!("ACK {CALLEE_TARGET} SIP/2.0")
    );
    let invite_cseq = call
        .invite
        .headers
        .cseq()
        .and_then(|cseq| cseq.split_whitespace().next().map(str::to_string))
        .expect("the INVITE CSeq number");
    assert_eq!(
        ack.message.headers.cseq().cloned(),
        Some(format!("{invite_cseq} ACK"))
    );
    assert_eq!(ack.message.headers.call_id(), call.invite.headers.call_id());
    assert_eq!(ack.message.headers.from(), call.invite.headers.from());
    assert!(ack
        .message
        .headers
        .to()
        .is_some_and(|to| to.ends_with(";tag=callee-tag")));
    assert!(ack.message.headers.get("Route").is_none());
    // A 2xx ACK is a transaction of its own: a new branch on siphon's sent-by.
    let ack_via = Via::parse(ack.message.headers.get("Via").expect("a Via")).expect("a Via");
    let invite_via = Via::parse(call.invite.headers.get("Via").expect("a Via")).expect("a Via");
    assert_eq!(
        (ack_via.host.as_str(), ack_via.port),
        (invite_via.host.as_str(), invite_via.port)
    );
    let branch = ack_via.branch.expect("a branch");
    assert_ne!(Some(branch.as_str()), invite_via.branch.as_deref());
    assert!(TransactionKey::is_rfc3261_branch(&branch));
    assert_eq!(
        ack.message
            .headers
            .get("Content-Length")
            .map(String::as_str),
        Some("0")
    );

    assert!(
        call.callee_leg_acked(),
        "the callee leg is recorded as ACKed"
    );
}

/// RFC 3261 §13.2.2.4: every retransmission of the 2xx is ACKed again, whether
/// or not the caller has ACKed yet, and the caller's ACK owes the callee nothing
/// more.
#[tokio::test(flavor = "multi_thread")]
async fn every_copy_of_the_callee_2xx_draws_an_ack_and_the_caller_ack_sends_nothing() {
    let call = Call::dial();
    let answer = call.callee_answers("");
    let sent = call.wire();
    assert_eq!(acks(&sent).len(), 1);
    let relayed_200 = sent
        .into_iter()
        .find(|sent| sent.destination == caller() && sent.message.status_code() == Some(200))
        .expect("the answer was relayed to the caller")
        .message;

    for copy in 1..=3 {
        call.callee_sends(&answer);
        let sent = call.wire();
        let acks = acks(&sent);
        assert_eq!(
            acks.len(),
            1,
            "retransmission {copy} of the 2xx draws exactly one ACK"
        );
        assert_eq!(acks[0].destination, callee());
        assert_eq!(
            request_line(&acks[0].message),
            format!("ACK {CALLEE_TARGET} SIP/2.0")
        );
        assert!(
            sent.iter().all(
                |sent| sent.destination != caller() || sent.message.status_code() != Some(200)
            ),
            "a retransmission is not relayed to the caller a second time"
        );
    }

    call.caller_acks(&relayed_200);
    assert!(
        acks(&call.wire()).is_empty(),
        "the callee was ACKed already; the caller's ACK sends it nothing"
    );

    // A copy that crosses the caller's ACK is still ACKed.
    call.callee_sends(&answer);
    assert_eq!(acks(&call.wire()).len(), 1);
}

/// RFC 3261 §12.1.2 / §12.2.1.1: when the callee's 2xx is Record-Routed, every
/// ACK for it, the first and each one a retransmission draws, carries the route
/// set and goes to its first hop.
#[tokio::test(flavor = "multi_thread")]
async fn every_ack_for_a_record_routed_2xx_follows_the_route_set() {
    let call = Call::dial();
    let answer = call.callee_answers(concat!(
        "Record-Route: <sip:198.51.100.10;lr;state=outer>\r\n",
        "Record-Route: <sip:198.51.100.20;lr;state=inner>\r\n",
    ));
    let first = call.wire();
    call.callee_sends(&answer);
    let retransmitted = call.wire();

    for (which, sent) in [("first", first), ("retransmission", retransmitted)] {
        let acks = acks(&sent);
        assert_eq!(acks.len(), 1, "{which}: one ACK");
        assert_eq!(
            acks[0].message.headers.get_all("Route").cloned(),
            Some(vec![
                "<sip:198.51.100.20;lr;state=inner>".to_string(),
                "<sip:198.51.100.10;lr;state=outer>".to_string(),
            ]),
            "{which}: the route set is the Record-Route reversed"
        );
        assert_eq!(
            acks[0].destination,
            "198.51.100.20:5060"
                .parse::<SocketAddr>()
                .expect("a literal address"),
            "{which}: the ACK goes to the first hop of the route set"
        );
        assert_eq!(
            request_line(&acks[0].message),
            format!("ACK {CALLEE_TARGET} SIP/2.0")
        );
    }
}
