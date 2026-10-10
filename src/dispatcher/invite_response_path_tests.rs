//! Where the responses of a B2BUA call go while its INVITE is pending (RFC 3261
//! §18.2.2, §9.1).
//!
//! A response follows the request it answers: it goes back over the connection
//! the request arrived on, to the source it arrived from. The caller's INVITE
//! and a request the caller sends later on the early dialog are different
//! transactions and need not arrive from the same hop. When the 18x that opened
//! the early dialog gave the caller a shorter route set than the INVITE
//! travelled, a PRACK or UPDATE reaches siphon from a proxy further out, and the
//! proxy that delivered the INVITE never sees it. Each response then goes where
//! its own request came from: the 200 to the UPDATE to the UPDATE's source, every
//! response to the INVITE to the INVITE's.
//!
//! The callee's side mirrors it. A CANCEL goes where the INVITE it cancels went
//! (§9.1), whichever hop an UPDATE on the callee's early dialog came from.
//!
//! Driven through the INVITE handler, the B-leg response handler, the request
//! handler and the response entry point, with every frame siphon sends read back
//! off the UDP egress channel together with the flow it left on.

use super::lcr_ring_timeout_tests::top_via_branch;
use super::test_dispatcher::{test_dispatcher_with_script, TestDispatcher};
use super::*;

/// The proxy that delivered the caller's INVITE.
const INVITE_HOP: &str = "192.0.2.10:5060";
/// The proxy further out, which the caller's later requests arrive from.
const UPDATE_HOP: &str = "192.0.2.20:5060";
const CALLEE: &str = "198.51.100.70:5060";
/// Another hop on the callee's side, which the callee's UPDATE arrives from.
const CALLEE_UPDATE_HOP: &str = "198.51.100.80:5060";
const SIP_CALL_ID: &str = "invite-response-path@192.0.2.30";

/// The flow each hop's datagrams arrive on.
const INVITE_FLOW: ConnectionId = ConnectionId(0x1001);
const UPDATE_FLOW: ConnectionId = ConnectionId(0x2002);
const CALLEE_FLOW: ConnectionId = ConnectionId(0x3003);
const CALLEE_UPDATE_FLOW: ConnectionId = ConnectionId(0x4004);

const OFFER: &str = concat!(
    "v=0\r\n",
    "o=caller 3 3 IN IP4 192.0.2.30\r\n",
    "s=caller session\r\n",
    "c=IN IP4 192.0.2.30\r\n",
    "t=0 0\r\n",
    "m=audio 40000 RTP/AVP 0\r\n",
    "a=rtpmap:0 PCMU/8000\r\n",
);

const ANSWER: &str = concat!(
    "v=0\r\n",
    "o=callee 7 7 IN IP4 198.51.100.71\r\n",
    "s=callee session\r\n",
    "c=IN IP4 198.51.100.71\r\n",
    "t=0 0\r\n",
    "m=audio 30000 RTP/AVP 0\r\n",
    "a=rtpmap:0 PCMU/8000\r\n",
);

const SECOND_OFFER: &str = concat!(
    "v=0\r\n",
    "o=caller 3 4 IN IP4 192.0.2.30\r\n",
    "s=caller session\r\n",
    "c=IN IP4 192.0.2.30\r\n",
    "t=0 0\r\n",
    "m=audio 40002 RTP/AVP 0\r\n",
    "a=rtpmap:0 PCMU/8000\r\n",
);

const SECOND_ANSWER: &str = concat!(
    "v=0\r\n",
    "o=callee 7 8 IN IP4 198.51.100.71\r\n",
    "s=callee session\r\n",
    "c=IN IP4 198.51.100.71\r\n",
    "t=0 0\r\n",
    "m=audio 30002 RTP/AVP 0\r\n",
    "a=rtpmap:0 PCMU/8000\r\n",
);

const DIAL: &str = concat!(
    "from siphon import b2bua\n",
    "\n",
    "@b2bua.on_invite\n",
    "def on_invite(call):\n",
    "    call.dial(\"sip:15550100042@198.51.100.70:5060\")\n",
);

fn address(text: &str) -> SocketAddr {
    text.parse().expect("a literal address")
}

fn parse(raw: &str) -> SipMessage {
    parse_sip_message_bytes(raw.as_bytes()).expect("the test message parses")
}

fn header(message: &SipMessage, name: &str) -> String {
    message
        .headers
        .get(name)
        .cloned()
        .unwrap_or_else(|| panic!("the message has no {name}"))
}

fn cseq_method(message: &SipMessage) -> String {
    message
        .headers
        .cseq()
        .and_then(|cseq| cseq.split_whitespace().nth(1).map(str::to_string))
        .unwrap_or_default()
}

fn push_body(raw: &mut String, body: &str) {
    if body.is_empty() {
        raw.push_str("Content-Length: 0\r\n\r\n");
    } else {
        raw.push_str(&format!(
            "Content-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        ));
    }
}

/// One message siphon put on the wire, and the flow it left on.
struct Sent {
    destination: SocketAddr,
    connection_id: ConnectionId,
    message: SipMessage,
}

impl Sent {
    fn summary(&self) -> String {
        let what = match self.message.status_code() {
            Some(status_code) => format!("{status_code} ({})", cseq_method(&self.message)),
            None => cseq_method(&self.message),
        };
        format!("{what} to {}", self.destination)
    }
}

fn summaries(sent: &[Sent]) -> Vec<String> {
    sent.iter().map(Sent::summary).collect()
}

/// The final or provisional response above 100 to a `method` among `sent`.
fn the_response<'a>(sent: &'a [Sent], method: &str) -> &'a Sent {
    sent.iter()
        .find(|sent| {
            sent.message.status_code().is_some_and(|code| code > 100)
                && cseq_method(&sent.message) == method
        })
        .unwrap_or_else(|| panic!("no response to a {method}: {:?}", summaries(sent)))
}

fn the_request<'a>(sent: &'a [Sent], method: &Method) -> &'a Sent {
    sent.iter()
        .find(|sent| sent.message.method() == Some(method))
        .unwrap_or_else(|| panic!("no {method:?}: {:?}", summaries(sent)))
}

/// A response went back the way its request came: to that hop, on that flow.
#[track_caller]
fn assert_went_to(sent: &Sent, hop: &str, flow: ConnectionId) {
    assert_eq!(sent.destination, address(hop), "{}", sent.summary());
    assert_eq!(sent.connection_id, flow, "{}", sent.summary());
}

/// A caller's call that supports `100rel`, dialled to one callee.
struct PendingCall {
    state: Arc<DispatcherState>,
    udp: flume::Receiver<OutboundMessage>,
    call_id: String,
    callee_invite: SipMessage,
}

impl PendingCall {
    fn place() -> PendingCall {
        let TestDispatcher { state, udp } = test_dispatcher_with_script(DIAL);
        let state = Arc::new(state);
        let mut raw = format!(
            concat!(
                "INVITE sip:15550100042@siphon.example.com SIP/2.0\r\n",
                "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-invite-hop\r\n",
                "Via: SIP/2.0/UDP 192.0.2.20:5060;branch=z9hG4bK-update-hop\r\n",
                "Via: SIP/2.0/UDP 192.0.2.30:5060;branch=z9hG4bK-caller\r\n",
                "Max-Forwards: 68\r\n",
                "From: <sip:15550100001@caller.example.com>;tag=caller-tag\r\n",
                "To: <sip:15550100042@siphon.example.com>\r\n",
                "Call-ID: {call_id}\r\n",
                "CSeq: 1 INVITE\r\n",
                "Contact: <sip:caller@192.0.2.30:5060>\r\n",
                "Supported: 100rel\r\n",
                "Allow: INVITE, ACK, CANCEL, BYE, PRACK, UPDATE\r\n",
            ),
            call_id = SIP_CALL_ID,
        );
        push_body(&mut raw, OFFER);
        let inbound = InboundMessage {
            client_transport: None,
            connection_id: INVITE_FLOW,
            transport: Transport::Udp,
            local_addr: state.local_addr,
            remote_addr: address(INVITE_HOP),
            data: Bytes::from(raw.clone().into_bytes()),
        };
        tokio::task::block_in_place(|| handle_b2bua_invite(inbound, parse(&raw), &state));
        let call_id = state
            .call_actors
            .find_by_sip_call_id(SIP_CALL_ID)
            .expect("the call was placed");
        let callee_invite = the_request(&drain(&udp), &Method::Invite).message.clone();
        PendingCall {
            state,
            udp,
            call_id,
            callee_invite,
        }
    }

    fn wire(&self) -> Vec<Sent> {
        drain(&self.udp)
    }

    /// The callee answers its INVITE with `status_code`, reliably when `rseq` is
    /// given, with `body` as SDP.
    fn callee_responds(&self, status_code: u16, rseq: Option<u32>, body: &str) {
        let invite = &self.callee_invite;
        let mut raw = format!("SIP/2.0 {status_code} Reason\r\n");
        for via in invite.headers.get_all("Via").cloned().unwrap_or_default() {
            raw.push_str(&format!("Via: {via}\r\n"));
        }
        raw.push_str(&format!("From: {}\r\n", header(invite, "From")));
        raw.push_str(&format!("To: {};tag=callee-tag\r\n", header(invite, "To")));
        raw.push_str(&format!("Call-ID: {}\r\n", header(invite, "Call-ID")));
        raw.push_str(&format!("CSeq: {}\r\n", header(invite, "CSeq")));
        raw.push_str("Contact: <sip:callee@198.51.100.70:5060>\r\n");
        raw.push_str("Allow: INVITE, ACK, CANCEL, BYE, PRACK, UPDATE\r\n");
        if let Some(rseq) = rseq {
            raw.push_str(&format!("Require: 100rel\r\nRSeq: {rseq}\r\n"));
        }
        push_body(&mut raw, body);
        let mut response = parse(&raw);
        let handled = tokio::task::block_in_place(|| {
            handle_b2bua_response(
                &self.call_id,
                &top_via_branch(invite),
                &mut response,
                status_code,
                address(CALLEE),
                &self.state,
            )
        });
        assert!(
            handled,
            "the call was gone when the callee's {status_code} arrived"
        );
    }

    /// A request from `hop` on `flow` through the dispatcher's request handler.
    fn receives(&self, hop: &str, flow: ConnectionId, method: &str, raw: String) {
        let inbound = InboundMessage {
            client_transport: None,
            connection_id: flow,
            transport: Transport::Udp,
            local_addr: self.state.local_addr,
            remote_addr: address(hop),
            data: Bytes::from(raw.clone().into_bytes()),
        };
        tokio::task::block_in_place(|| {
            super::request::handle_request(inbound, parse(&raw), method.to_string(), &self.state)
        });
    }

    /// The party behind `hop` answers `request`, one siphon sent it, with 200 and
    /// `body`.
    fn answers(&self, hop: &str, flow: ConnectionId, request: &SipMessage, body: &str) {
        let mut raw = "SIP/2.0 200 OK\r\n".to_string();
        for name in ["Via", "From", "To", "Call-ID", "CSeq"] {
            raw.push_str(&format!("{name}: {}\r\n", header(request, name)));
        }
        push_body(&mut raw, body);
        let inbound = InboundMessage {
            client_transport: None,
            connection_id: flow,
            transport: Transport::Udp,
            local_addr: self.state.local_addr,
            remote_addr: address(hop),
            data: Bytes::from(raw.clone().into_bytes()),
        };
        tokio::task::block_in_place(|| {
            super::response::handle_response(inbound, parse(&raw), 200, &self.state)
        });
    }

    /// The caller's in-dialog `method` numbered `cseq` on the early dialog the
    /// `provisional` opened, as the proxy further out sends it on: the proxy
    /// that delivered the INVITE is not on its path.
    fn caller_request(&self, method: &str, provisional: &SipMessage, cseq: u32) -> String {
        format!(
            concat!(
                "{method} sip:192.0.2.1:5060 SIP/2.0\r\n",
                "Via: SIP/2.0/UDP 192.0.2.20:5060;branch=z9hG4bK-update-hop-{method}-{cseq}\r\n",
                "Via: SIP/2.0/UDP 192.0.2.30:5060;branch=z9hG4bK-caller-{method}-{cseq}\r\n",
                "Max-Forwards: 69\r\n",
                "From: <sip:15550100001@caller.example.com>;tag=caller-tag\r\n",
                "To: {to}\r\n",
                "Call-ID: {call_id}\r\n",
                "CSeq: {cseq} {method}\r\n",
                "Contact: <sip:caller@192.0.2.30:5060>\r\n",
            ),
            method = method,
            cseq = cseq,
            to = header(provisional, "To"),
            call_id = SIP_CALL_ID,
        )
    }

    /// The callee answers reliably with SDP and the caller PRACKs siphon's copy
    /// by way of the proxy further out, which sends siphon's PRACK to the callee:
    /// the INVITE's offer/answer exchange is complete on both dialogs. Returns
    /// siphon's 183.
    fn answered_reliably(&self) -> SipMessage {
        self.callee_responds(183, Some(42), ANSWER);
        let sent = self.wire();
        let progress = the_response(&sent, "INVITE");
        assert_eq!(progress.message.status_code(), Some(183));
        assert_went_to(progress, INVITE_HOP, INVITE_FLOW);
        let progress = progress.message.clone();

        let mut raw = self.caller_request("PRACK", &progress, 2);
        raw.push_str(&format!(
            "RAck: {} 1 INVITE\r\n",
            header(&progress, "RSeq").trim()
        ));
        push_body(&mut raw, "");
        self.receives(UPDATE_HOP, UPDATE_FLOW, "PRACK", raw);
        let sent = self.wire();
        assert_went_to(the_response(&sent, "PRACK"), UPDATE_HOP, UPDATE_FLOW);
        let prack = the_request(&sent, &Method::Prack).message.clone();
        self.answers(CALLEE, CALLEE_FLOW, &prack, "");
        self.wire();
        progress
    }

    /// The caller offers again in an UPDATE by way of the proxy further out, and
    /// the callee answers it. Returns what siphon sent meanwhile.
    fn caller_updates(&self, progress: &SipMessage) -> Vec<Sent> {
        let mut raw = self.caller_request("UPDATE", progress, 3);
        push_body(&mut raw, SECOND_OFFER);
        self.receives(UPDATE_HOP, UPDATE_FLOW, "UPDATE", raw);
        let mut sent = self.wire();
        let update = the_request(&sent, &Method::Update).message.clone();
        self.answers(CALLEE, CALLEE_FLOW, &update, SECOND_ANSWER);
        sent.extend(self.wire());
        sent
    }

    /// The callee offers in an UPDATE on its early dialog, which reaches siphon
    /// from another hop than the one siphon sent the INVITE to.
    fn callee_updates(&self) {
        let invite = &self.callee_invite;
        let mut raw = format!(
            concat!(
                "UPDATE sip:192.0.2.1:5060 SIP/2.0\r\n",
                "Via: SIP/2.0/UDP 198.51.100.80:5060;branch=z9hG4bK-callee-update-hop\r\n",
                "Via: SIP/2.0/UDP 198.51.100.71:5060;branch=z9hG4bK-callee-update\r\n",
                "Max-Forwards: 69\r\n",
                "From: {from};tag=callee-tag\r\n",
                "To: {to}\r\n",
                "Call-ID: {call_id}\r\n",
                "CSeq: 1 UPDATE\r\n",
                "Contact: <sip:callee@198.51.100.70:5060>\r\n",
            ),
            from = header(invite, "To"),
            to = header(invite, "From"),
            call_id = header(invite, "Call-ID"),
        );
        push_body(&mut raw, SECOND_ANSWER);
        self.receives(CALLEE_UPDATE_HOP, CALLEE_UPDATE_FLOW, "UPDATE", raw);
    }
}

fn drain(udp: &flume::Receiver<OutboundMessage>) -> Vec<Sent> {
    let mut sent = Vec::new();
    while let Ok(outbound) = udp.try_recv() {
        for frame in outbound.frames() {
            sent.push(Sent {
                destination: outbound.destination,
                connection_id: outbound.connection_id,
                message: parse_sip_message_bytes(frame).expect("siphon sent a message that parses"),
            });
        }
    }
    sent
}

/// RFC 3261 §18.2.2: "the response MUST be sent using [the] connection to the
/// transport layer of the request", to the source it came from. The 200 to the
/// caller's UPDATE and the 100 before it go to the hop the UPDATE came from.
#[tokio::test(flavor = "multi_thread")]
async fn the_response_to_an_early_update_goes_where_the_update_came_from() {
    let call = PendingCall::place();
    let progress = call.answered_reliably();
    let sent = call.caller_updates(&progress);
    let to_caller: Vec<&Sent> = sent
        .iter()
        .filter(|sent| {
            cseq_method(&sent.message) == "UPDATE" && sent.message.status_code().is_some()
        })
        .collect();
    assert!(
        to_caller
            .iter()
            .any(|sent| sent.message.status_code() == Some(200)),
        "{:?}",
        summaries(&sent)
    );
    for response in to_caller {
        assert_went_to(response, UPDATE_HOP, UPDATE_FLOW);
        assert!(header(&response.message, "Via").contains("z9hG4bK-update-hop-UPDATE-3"));
    }
}

/// The 2xx to the INVITE goes where the INVITE came from, on the INVITE's flow,
/// though the caller's UPDATE arrived from another hop since. It carries the
/// INVITE's Via set, which only the proxy that delivered the INVITE can match
/// to a transaction; sent to the UPDATE's hop it is discarded there, the caller
/// never answers, and the call ends unACKed after 64*T1 (§13.3.1.4).
#[tokio::test(flavor = "multi_thread")]
async fn the_2xx_follows_the_invite_after_an_early_update_from_another_hop() {
    let call = PendingCall::place();
    let progress = call.answered_reliably();
    call.caller_updates(&progress);

    call.callee_responds(180, None, "");
    let sent = call.wire();
    let ringing = the_response(&sent, "INVITE");
    assert_eq!(ringing.message.status_code(), Some(180));
    assert_went_to(ringing, INVITE_HOP, INVITE_FLOW);

    call.callee_responds(200, None, "");
    let sent = call.wire();
    let answer = the_response(&sent, "INVITE");
    assert_eq!(answer.message.status_code(), Some(200));
    assert_went_to(answer, INVITE_HOP, INVITE_FLOW);
    assert!(header(&answer.message, "Via").contains("z9hG4bK-invite-hop"));
}

/// The same for a failure: the callee's 486 reaches the caller as the final
/// response to its INVITE, over the hop the INVITE came from.
#[tokio::test(flavor = "multi_thread")]
async fn a_failure_follows_the_invite_after_an_early_update_from_another_hop() {
    let call = PendingCall::place();
    let progress = call.answered_reliably();
    call.caller_updates(&progress);

    call.callee_responds(486, None, "");
    let sent = call.wire();
    let busy = the_response(&sent, "INVITE");
    assert_eq!(busy.message.status_code(), Some(486));
    assert_went_to(busy, INVITE_HOP, INVITE_FLOW);
}

/// An UPDATE without an offer changes nothing and is answered where it arrived.
/// It moves the INVITE's responses no more than one with an offer does.
#[tokio::test(flavor = "multi_thread")]
async fn an_early_update_without_an_offer_leaves_the_invite_where_it_was() {
    let call = PendingCall::place();
    let progress = call.answered_reliably();
    let mut raw = call.caller_request("UPDATE", &progress, 3);
    push_body(&mut raw, "");
    call.receives(UPDATE_HOP, UPDATE_FLOW, "UPDATE", raw);
    let sent = call.wire();
    let ok = the_response(&sent, "UPDATE");
    assert_eq!(ok.message.status_code(), Some(200));
    assert_went_to(ok, UPDATE_HOP, UPDATE_FLOW);

    call.callee_responds(200, None, "");
    let sent = call.wire();
    assert_went_to(the_response(&sent, "INVITE"), INVITE_HOP, INVITE_FLOW);
}

/// Once the caller has its 2xx the dialog is confirmed and no INVITE is
/// pending: an in-dialog request from another hop moves the leg to the flow it
/// arrived on (RFC 5626 §5.3), as before.
#[tokio::test(flavor = "multi_thread")]
async fn a_request_after_the_answer_still_moves_the_caller_to_its_flow() {
    let call = PendingCall::place();
    let progress = call.answered_reliably();
    call.callee_responds(200, None, "");
    call.wire();
    let mut ack = call.caller_request("ACK", &progress, 1);
    push_body(&mut ack, "");
    call.receives(UPDATE_HOP, UPDATE_FLOW, "ACK", ack);

    let mut raw = call.caller_request("UPDATE", &progress, 3);
    push_body(&mut raw, "");
    call.receives(UPDATE_HOP, UPDATE_FLOW, "UPDATE", raw);
    call.wire();
    let actor = call
        .state
        .call_actors
        .get_call(&call.call_id)
        .expect("the call");
    assert_eq!(actor.a_leg.transport.remote_addr, address(UPDATE_HOP));
    assert_eq!(actor.a_leg.transport.connection_id, UPDATE_FLOW);
}

/// RFC 3261 §9.1: a CANCEL goes to the destination its INVITE went to. The
/// callee's UPDATE on the early dialog arrived from another hop; its 200 goes
/// back there, and the CANCEL of the callee's INVITE still goes where the
/// INVITE did.
#[tokio::test(flavor = "multi_thread")]
async fn a_cancel_follows_the_callees_invite_after_its_early_update_from_another_hop() {
    let call = PendingCall::place();
    call.answered_reliably();

    call.callee_updates();
    let sent = call.wire();
    let update = the_request(&sent, &Method::Update);
    assert_went_to(update, INVITE_HOP, INVITE_FLOW);
    let update = update.message.clone();
    call.answers(INVITE_HOP, INVITE_FLOW, &update, SECOND_OFFER);
    let sent = call.wire();
    let ok = the_response(&sent, "UPDATE");
    assert_eq!(ok.message.status_code(), Some(200));
    assert_eq!(ok.destination, address(CALLEE_UPDATE_HOP));

    let cancel = concat!(
        "CANCEL sip:15550100042@siphon.example.com SIP/2.0\r\n",
        "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-invite-hop\r\n",
        "Max-Forwards: 68\r\n",
        "From: <sip:15550100001@caller.example.com>;tag=caller-tag\r\n",
        "To: <sip:15550100042@siphon.example.com>\r\n",
        "Call-ID: invite-response-path@192.0.2.30\r\n",
        "CSeq: 1 CANCEL\r\n",
        "Content-Length: 0\r\n\r\n",
    );
    call.receives(INVITE_HOP, INVITE_FLOW, "CANCEL", cancel.to_string());
    let sent = call.wire();
    let cancelled = the_request(&sent, &Method::Cancel);
    assert_eq!(cancelled.destination, address(CALLEE));
    assert_eq!(
        top_via_branch(&cancelled.message),
        top_via_branch(&call.callee_invite)
    );
}
