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
//! read back off the UDP egress channel. The harness is shared with
//! `unacked_answer_tests`, which drives the other half of the same exchange.

use super::lcr_ring_timeout_tests::top_via_branch;
use super::test_dispatcher::{test_dispatcher, test_dispatcher_with_script, TestDispatcher};
use super::*;

const CALLER: &str = "192.0.2.10:5060";
const CALLEE: &str = "198.51.100.77:5060";
pub(super) const CALLER_CALL_ID: &str = "caller-call@192.0.2.10";

/// The callee's remote target: an opaque userpart and parameters whose names are
/// mixed case and whose values carry `_` and `-`. The ACK has to name it exactly
/// (RFC 3261 §12.1.2, §19.1.4).
const CALLEE_TARGET: &str =
    "sip:opaque-7f3a@198.51.100.77:5060;transport=udp;Tk=ab_12;RouteId=9;LegRef=0a0a-0b0b";

/// The caller's INVITE, with an offer in it.
pub(super) fn caller_invite() -> SipMessage {
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

/// The caller's leg, with the dialog state `handle_b2bua_invite` takes off the
/// INVITE: siphon's Contact toward the caller, the caller's Contact as the remote
/// target, and the From/To an in-dialog request from siphon carries (RFC 3261
/// §12.1.1).
pub(super) fn caller_leg() -> Leg {
    let invite = caller_invite();
    let mut leg = Leg::new_a_leg(
        CALLER_CALL_ID.to_string(),
        "caller-tag".to_string(),
        "z9hG4bK-caller-invite".to_string(),
        LegTransport {
            remote_addr: CALLER.parse().expect("a literal address"),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: None,
        },
    );
    leg.dialog.local_contact = Some("<sip:192.0.2.1:5060;transport=udp>".to_string());
    leg.dialog.remote_contact = invite
        .headers
        .get("Contact")
        .map(|contact| crate::b2bua::actor::extract_contact_uri(contact));
    leg.dialog.local_from_uri = invite
        .headers
        .to()
        .map(|to| format!("{to};tag={}", leg.dialog.local_tag));
    leg.dialog.remote_to_uri = invite.headers.from().cloned();
    leg
}

/// One message siphon put on the wire, with the socket it asked to leave from.
pub(super) struct Sent {
    pub(super) destination: SocketAddr,
    source_local_addr: Option<SocketAddr>,
    pub(super) message: SipMessage,
}

impl Sent {
    fn is_ack(&self) -> bool {
        self.message.method() == Some(&Method::Ack)
    }
}

/// A caller's call bridged to one callee through a real dispatcher.
pub(super) struct Call {
    pub(super) state: Arc<DispatcherState>,
    udp: flume::Receiver<OutboundMessage>,
    pub(super) call_id: String,
    invite: SipMessage,
    invite_source: Option<SocketAddr>,
}

impl Call {
    /// The caller's INVITE arrives and siphon dials the callee.
    pub(super) fn dial() -> Call {
        let (state, udp, call_id) = Call::caller_alone();
        let a_leg_invite = state
            .call_actors
            .get_call(&call_id)
            .and_then(|call| call.a_leg_invite.clone())
            .expect("the caller's INVITE is stored on the call");
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

    /// The caller's call bridged to the callee with the B-leg registered exactly
    /// as `b2bua_send_b_leg_invite` registers it, without dialling.
    ///
    /// The dial resolves its next hop with a blocking resolver call, which a
    /// paused-clock (current_thread) runtime refuses, so a test that steps the
    /// clock builds the call this way. Everything after the INVITE — the callee's
    /// responses, the caller's ACK, the teardown — is the same dispatcher code.
    pub(super) fn bridged() -> Call {
        Call::bridged_with(false)
    }

    /// [`Call::bridged`] with the callee's INVITE stored on the leg the way the dial
    /// stores it, and that INVITE carrying no offer: the callee's 2xx then carries
    /// the offer, and its ACK waits for the caller's answer (RFC 3261 §13.2.2.4).
    pub(super) fn bridged_without_an_offer() -> Call {
        Call::bridged_with(true)
    }

    /// [`Call::bridged`] on a dispatcher running `script`.
    pub(super) fn bridged_with_script(script: &str) -> Call {
        Call::bridged_on(test_dispatcher_with_script(script), false)
    }

    fn bridged_with(store_offerless_invite: bool) -> Call {
        Call::bridged_on(test_dispatcher(), store_offerless_invite)
    }

    fn bridged_on(dispatcher: TestDispatcher, store_offerless_invite: bool) -> Call {
        let (state, udp, call_id) = Call::caller_on(dispatcher);
        let invite = Call::callee_invite();
        let mut leg = Leg::new_b_leg(
            "b2b-callee@192.0.2.1".to_string(),
            "sb-callee-leg".to_string(),
            "sip:15550100042@198.51.100.77:5060".to_string(),
            "z9hG4bK-callee-invite".to_string(),
            LegTransport {
                remote_addr: callee(),
                connection_id: ConnectionId::default(),
                transport: Transport::Udp,
                local_addr: None,
            },
        );
        leg.dialog.local_contact = Some("<sip:192.0.2.1:5060;transport=udp>".to_string());
        leg.dialog.local_from_uri = invite.headers.from().cloned();
        leg.dialog.remote_to_uri = invite.headers.to().cloned();
        if store_offerless_invite {
            leg.b_leg_invite = Some(Arc::new(Mutex::new(invite.clone())));
        }
        state.call_actors.add_b_leg(&call_id, leg);
        Call {
            state,
            udp,
            call_id,
            invite_source: None,
            invite,
        }
    }

    /// The INVITE [`Call::bridged`] stands for: what siphon sends the callee.
    fn callee_invite() -> SipMessage {
        let raw = concat!(
            "INVITE sip:15550100042@198.51.100.77:5060 SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-callee-invite\r\n",
            "Max-Forwards: 70\r\n",
            "From: <sip:15550100001@192.0.2.1>;tag=sb-callee-leg\r\n",
            "To: <sip:15550100042@198.51.100.77>\r\n",
            "Call-ID: b2b-callee@192.0.2.1\r\n",
            "CSeq: 1 INVITE\r\n",
            "Contact: <sip:192.0.2.1:5060;transport=udp>\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        );
        parse_sip_message_bytes(raw.as_bytes()).expect("the callee INVITE parses")
    }

    /// The caller's call and nothing dialled: the shape of a call siphon answers
    /// itself. Returns the dispatcher, its UDP egress and the internal call id.
    pub(super) fn caller_alone() -> (
        Arc<DispatcherState>,
        flume::Receiver<OutboundMessage>,
        String,
    ) {
        Call::caller_on(test_dispatcher())
    }

    fn caller_on(
        TestDispatcher { state, udp }: TestDispatcher,
    ) -> (
        Arc<DispatcherState>,
        flume::Receiver<OutboundMessage>,
        String,
    ) {
        let state = Arc::new(state);
        let call_id = state.call_actors.create_call(caller_leg());
        state
            .call_actors
            .set_a_leg_invite(&call_id, Arc::new(Mutex::new(caller_invite())));
        (state, udp, call_id)
    }

    /// Everything siphon has put on the wire since the last look, in order.
    pub(super) fn wire(&self) -> Vec<Sent> {
        drain(&self.udp)
    }

    /// The callee sends `response` for the INVITE siphon sent it.
    pub(super) fn callee_sends(&self, response: &str) {
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
    pub(super) fn callee_answers(&self, extra: &str) -> String {
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
    pub(super) fn caller_acks(&self, relayed_200: &SipMessage) {
        caller_acks(&self.state, relayed_200);
    }

    /// The callee hangs up: a BYE in the dialog its 2xx created, handed to
    /// [`handle_b2bua_bye`] the way the dispatcher's B2BUA gate hands it over.
    pub(super) fn callee_hangs_up(&self) {
        let header = |name: &str| {
            self.invite
                .headers
                .get(name)
                .map(|value| value.to_string())
                .unwrap_or_else(|| panic!("siphon's INVITE has no {name}"))
        };
        let raw = format!(
            concat!(
                "BYE sip:192.0.2.1:5060;transport=udp SIP/2.0\r\n",
                "Via: SIP/2.0/UDP 198.51.100.77:5060;branch=z9hG4bK-callee-bye\r\n",
                "Max-Forwards: 70\r\n",
                "From: {from};tag=callee-tag\r\n",
                "To: {to}\r\n",
                "Call-ID: {call_id}\r\n",
                "CSeq: 1 BYE\r\n",
                "Content-Length: 0\r\n",
                "\r\n",
            ),
            from = header("To"),
            to = header("From"),
            call_id = header("Call-ID"),
        );
        let message = parse_sip_message_bytes(raw.as_bytes()).expect("the callee's BYE parses");
        handle_b2bua_bye(
            InboundMessage {
                client_transport: None,
                connection_id: ConnectionId::default(),
                transport: Transport::Udp,
                local_addr: "192.0.2.1:5060".parse().expect("a literal address"),
                remote_addr: callee(),
                data: Bytes::from(raw),
            },
            message,
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

/// The caller ACKs `relayed_200`, the 2xx siphon sent it (RFC 3261 §13.2.2.4).
pub(super) fn caller_acks(state: &Arc<DispatcherState>, relayed_200: &SipMessage) {
    caller_sends(state, "ACK", "1 ACK", relayed_200);
}

/// The caller hangs up in the dialog `relayed_200` created, through
/// [`handle_request`].
pub(super) fn caller_hangs_up(state: &Arc<DispatcherState>, relayed_200: &SipMessage) {
    caller_sends(state, "BYE", "2 BYE", relayed_200);
}

/// A request from the caller in the dialog `relayed_200` created, through
/// [`handle_request`].
fn caller_sends(state: &Arc<DispatcherState>, method: &str, cseq: &str, relayed_200: &SipMessage) {
    let raw = format!(
        concat!(
            "{method} sip:192.0.2.1:5060;transport=udp SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-caller-{branch}\r\n",
            "Max-Forwards: 70\r\n",
            "From: {from}\r\n",
            "To: {to}\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: {cseq}\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        method = method,
        branch = method.to_ascii_lowercase(),
        cseq = cseq,
        from = relayed_200
            .headers
            .from()
            .expect("the relayed 200 has a From"),
        to = relayed_200.headers.to().expect("the relayed 200 has a To"),
        call_id = CALLER_CALL_ID,
    );
    let message = parse_sip_message_bytes(raw.as_bytes()).expect("the caller's request parses");
    handle_request(
        InboundMessage {
            client_transport: None,
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: "192.0.2.1:5060".parse().expect("a literal address"),
            remote_addr: CALLER.parse().expect("a literal address"),
            data: Bytes::from(raw),
        },
        message,
        method.to_string(),
        state,
    );
}

/// Every frame on `udp` so far, in the order siphon sent it, the followers of an
/// ordered group (an ACK and the BYE right behind it) included.
pub(super) fn drain(udp: &flume::Receiver<OutboundMessage>) -> Vec<Sent> {
    let mut sent = Vec::new();
    while let Ok(outbound) = udp.try_recv() {
        for frame in outbound.frames() {
            sent.push(Sent {
                destination: outbound.destination,
                source_local_addr: outbound.source_local_addr,
                message: parse_sip_message_bytes(frame).expect("siphon sent a message that parses"),
            });
        }
    }
    sent
}

/// The ACKs among `sent`.
fn acks(sent: &[Sent]) -> Vec<&Sent> {
    sent.iter().filter(|sent| sent.is_ack()).collect()
}

pub(super) fn request_line(message: &SipMessage) -> String {
    let text = String::from_utf8(message.to_bytes()).expect("serialized SIP is UTF-8");
    text.split("\r\n").next().expect("a start line").to_string()
}

pub(super) fn caller() -> SocketAddr {
    CALLER.parse().expect("a literal address")
}

pub(super) fn callee() -> SocketAddr {
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

/// The listener the caller's INVITE arrived on in
/// [`Call::bridged_with_caller_rendezvous`]: not the one the callee's requests
/// arrive on, so what siphon sends the two parties leaves on different channels.
const CALLER_LISTENER: &str = "192.0.2.1:5070";

impl Call {
    /// [`Call::bridged`] on a dispatcher whose UDP egress is split by direction.
    /// What siphon sends the caller leaves from the caller's listener and goes to
    /// the returned channel, which has no room: a send to the caller does not
    /// return until the test takes it. Everything else stays on [`Call::wire`].
    fn bridged_with_caller_rendezvous() -> (Call, flume::Receiver<OutboundMessage>) {
        let TestDispatcher { mut state, udp } = test_dispatcher();
        drop(udp);
        let caller_listener: SocketAddr = CALLER_LISTENER.parse().expect("a literal address");
        let (to_caller, caller_channel) = flume::bounded(0);
        let (to_others, others) = flume::unbounded();
        let (to_stream, _) = flume::unbounded();
        state.outbound = Arc::new(OutboundRouter {
            udp: to_others.into(),
            udp_by_local: std::collections::HashMap::from([(caller_listener, to_caller.into())]),
            tcp: to_stream.clone(),
            tls: to_stream.clone(),
            ws: to_stream.clone(),
            wss: to_stream.clone(),
            sctp: to_stream,
        });
        let call = Call::bridged_on(TestDispatcher { state, udp: others }, false);
        if let Some(mut actor) = call.state.call_actors.get_call_mut(&call.call_id) {
            actor.a_leg_local_addr = Some(caller_listener);
        }
        (call, caller_channel)
    }
}

/// The next message siphon hands the transport on `channel`, waiting for it.
fn receive_from(channel: &flume::Receiver<OutboundMessage>) -> SipMessage {
    let outbound = channel
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("siphon sent a message");
    let frame = outbound.frames().next().expect("a frame");
    parse_sip_message_bytes(frame).expect("siphon sent a message that parses")
}

/// The callee BYEs the moment its 2xx is ACKed, as a UAS may, and that BYE is
/// handled on another worker while siphon is still handing the caller its 2xx.
/// The caller's answer is registered as waiting for the caller's ACK before the
/// callee's ACK leaves, so the callee's BYE finds it and the caller's BYE is held
/// until the caller has ACKed (RFC 3261 §15). Registered only after the 2xx went
/// out, the BYE found nothing to wait behind and reached the caller before its ACK.
#[tokio::test(flavor = "multi_thread")]
async fn a_callee_bye_between_its_ack_and_the_callers_2xx_is_held_for_the_callers_ack() {
    let (call, to_caller) = Call::bridged_with_caller_rendezvous();
    let runtime = &tokio::runtime::Handle::current();
    let call = &call;
    std::thread::scope(|scope| {
        let ringing = scope.spawn(move || {
            let _runtime = runtime.enter();
            call.callee_sends(&call.callee_response("180 Ringing", "", ""));
        });
        assert_eq!(receive_from(&to_caller).status_code(), Some(180));
        ringing.join().expect("the callee's 180");
    });

    let answer = call.callee_response(
        "200 OK",
        "",
        concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 198.51.100.78\r\n",
            "s=-\r\n",
            "c=IN IP4 198.51.100.78\r\n",
            "t=0 0\r\n",
            "m=audio 30000 RTP/AVP 0\r\n",
            "a=rtpmap:0 PCMU/8000\r\n",
        ),
    );
    let mut sent = Vec::new();
    let mut registered_when_the_callee_was_acked = false;
    let relayed = std::thread::scope(|scope| {
        let answering = scope.spawn(move || {
            let _runtime = runtime.enter();
            call.callee_sends(&answer);
        });
        // The callee's ACK is out. siphon's thread gets no further than handing
        // the caller its 2xx, which it cannot finish until the test takes it.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !sent.iter().any(Sent::is_ack) {
            assert!(
                std::time::Instant::now() < deadline,
                "the callee's 2xx was never ACKed"
            );
            sent.extend(call.wire());
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        registered_when_the_callee_was_acked =
            call.state.uas_2xx_retransmits.contains_key(CALLER_CALL_ID);
        scope
            .spawn(move || {
                let _runtime = runtime.enter();
                call.callee_hangs_up();
            })
            .join()
            .expect("the callee's BYE");
        let relayed = receive_from(&to_caller);
        answering.join().expect("the callee's 2xx");
        relayed
    });
    assert_eq!(relayed.status_code(), Some(200));
    sent.extend(call.wire());

    let byes_to_caller = |sent: &[Sent]| {
        sent.iter()
            .filter(|sent| {
                sent.destination == caller() && sent.message.method() == Some(&Method::Bye)
            })
            .count()
    };
    assert_eq!(
        byes_to_caller(&sent),
        0,
        "the caller was sent a BYE before it ACKed its 2xx"
    );
    assert!(
        sent.iter()
            .any(|sent| sent.destination == callee() && sent.message.status_code() == Some(200)),
        "the callee's BYE is answered at once"
    );
    assert!(
        registered_when_the_callee_was_acked,
        "the caller's 2xx was not waiting for its ACK when the callee's ACK left"
    );

    call.caller_acks(&relayed);
    assert_eq!(
        byes_to_caller(&call.wire()),
        1,
        "the caller's ACK releases its BYE"
    );
}
