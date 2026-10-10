//! The caller's route set on the early dialog of a B2BUA call (RFC 3261
//! §12.1.1, RFC 3262 §3).
//!
//! siphon is the UAS of the caller's dialog. A provisional above 100 with a To
//! tag establishes that dialog early, so it carries every `Record-Route` value
//! of the caller's INVITE, in order, exactly as the 2xx does: the caller builds
//! the route set its PRACK and UPDATE follow from that response. The callee's
//! own `Record-Route` belongs to the other dialog and never crosses. The same
//! route set is what a request siphon sends the caller before the answer
//! follows (§12.2.1.1).
//!
//! Driven through the INVITE handler, the B-leg response handler and the request
//! handler, with every frame siphon sends read back off the UDP egress channel.

use super::lcr_ring_timeout_tests::{summaries, top_via_branch, Sent};
use super::test_dispatcher::{test_dispatcher_with_script, TestDispatcher};
use super::*;

/// The proxy next to siphon on the caller's side, which delivered the INVITE.
const NEAR_PROXY: &str = "192.0.2.10:5060";
const CALLEE: &str = "198.51.100.70:5060";
const SIP_CALL_ID: &str = "early-route-set@192.0.2.30";

/// The INVITE's `Record-Route` as siphon received it: the proxy next to siphon
/// first, with a parameter no UAS knows, then the one next to the caller.
const NEAR_RECORD_ROUTE: &str = "<sip:192.0.2.10:5060;lr;state=near>";
const FAR_RECORD_ROUTE: &str = "<sip:192.0.2.20:5060;lr>";
/// What a proxy on the callee's side wrote into the callee's responses.
const CALLEE_RECORD_ROUTE: &str = "<sip:198.51.100.90:5060;lr>";

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

/// An offer of the callee's own in an UPDATE on its early dialog.
const CALLEE_OFFER: &str = concat!(
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

/// Every value of a header that lists URIs, one per entry, in wire order.
fn values(message: &SipMessage, name: &str) -> Vec<String> {
    message
        .headers
        .get_all(name)
        .cloned()
        .unwrap_or_default()
        .iter()
        .flat_map(|line| line.split(','))
        .map(|value| value.trim().to_string())
        .collect()
}

fn callers_record_route() -> Vec<String> {
    vec![NEAR_RECORD_ROUTE.to_string(), FAR_RECORD_ROUTE.to_string()]
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

fn cseq_method(message: &SipMessage) -> String {
    message
        .headers
        .cseq()
        .and_then(|cseq| cseq.split_whitespace().nth(1).map(str::to_string))
        .unwrap_or_default()
}

/// A call whose INVITE crossed two record-routing proxies, dialled to one callee.
struct RoutedCall {
    state: Arc<DispatcherState>,
    udp: flume::Receiver<OutboundMessage>,
    call_id: String,
    callee_invite: SipMessage,
}

impl RoutedCall {
    fn place() -> RoutedCall {
        let TestDispatcher { state, udp } = test_dispatcher_with_script(DIAL);
        let state = Arc::new(state);
        let mut raw = format!(
            concat!(
                "INVITE sip:15550100042@siphon.example.com SIP/2.0\r\n",
                "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-near\r\n",
                "Via: SIP/2.0/UDP 192.0.2.20:5060;branch=z9hG4bK-far\r\n",
                "Via: SIP/2.0/UDP 192.0.2.30:5060;branch=z9hG4bK-caller\r\n",
                "Record-Route: {near}\r\n",
                "Record-Route: {far}\r\n",
                "Max-Forwards: 68\r\n",
                "From: <sip:15550100001@caller.example.com>;tag=caller-tag\r\n",
                "To: <sip:15550100042@siphon.example.com>\r\n",
                "Call-ID: {call_id}\r\n",
                "CSeq: 1 INVITE\r\n",
                "Contact: <sip:caller@192.0.2.30:5060>\r\n",
                "Supported: 100rel\r\n",
                "Allow: INVITE, ACK, CANCEL, BYE, PRACK, UPDATE\r\n",
            ),
            near = NEAR_RECORD_ROUTE,
            far = FAR_RECORD_ROUTE,
            call_id = SIP_CALL_ID,
        );
        push_body(&mut raw, OFFER);
        let inbound = InboundMessage {
            client_transport: None,
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: state.local_addr,
            remote_addr: address(NEAR_PROXY),
            data: Bytes::from(raw.clone().into_bytes()),
        };
        tokio::task::block_in_place(|| handle_b2bua_invite(inbound, parse(&raw), &state));
        let call_id = state
            .call_actors
            .find_by_sip_call_id(SIP_CALL_ID)
            .expect("the call was placed");
        let callee_invite = drain(&udp)
            .into_iter()
            .find(|sent| {
                sent.destination == address(CALLEE)
                    && sent.message.method() == Some(&Method::Invite)
            })
            .map(|sent| sent.message)
            .expect("siphon dialled the callee");
        RoutedCall {
            state,
            udp,
            call_id,
            callee_invite,
        }
    }

    fn wire(&self) -> Vec<Sent> {
        drain(&self.udp)
    }

    /// The callee answers its INVITE with `status_code` through a proxy that
    /// record-routes, reliably when `rseq` is given, with `body` as SDP.
    fn callee_responds(&self, status_code: u16, rseq: Option<u32>, body: &str) {
        let invite = &self.callee_invite;
        let mut raw = format!("SIP/2.0 {status_code} Reason\r\n");
        for via in invite.headers.get_all("Via").cloned().unwrap_or_default() {
            raw.push_str(&format!("Via: {via}\r\n"));
        }
        raw.push_str(&format!("Record-Route: {CALLEE_RECORD_ROUTE}\r\n"));
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

    /// A request from `party` through the dispatcher's request handler.
    fn receives(&self, party: &str, method: &str, raw: String) {
        let inbound = InboundMessage {
            client_transport: None,
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: self.state.local_addr,
            remote_addr: address(party),
            data: Bytes::from(raw.clone().into_bytes()),
        };
        tokio::task::block_in_place(|| {
            super::request::handle_request(inbound, parse(&raw), method.to_string(), &self.state)
        });
    }

    /// `party` answers `request`, one siphon sent it, with 200 and no body.
    fn answers(&self, party: &str, request: &SipMessage) {
        let mut raw = "SIP/2.0 200 OK\r\n".to_string();
        for name in ["Via", "From", "To", "Call-ID", "CSeq"] {
            raw.push_str(&format!("{name}: {}\r\n", header(request, name)));
        }
        push_body(&mut raw, "");
        let inbound = InboundMessage {
            client_transport: None,
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: self.state.local_addr,
            remote_addr: address(party),
            data: Bytes::from(raw.clone().into_bytes()),
        };
        tokio::task::block_in_place(|| {
            super::response::handle_response(inbound, parse(&raw), 200, &self.state)
        });
    }

    /// The response to the caller's INVITE among what siphon just sent the
    /// proxy that delivered it.
    fn invite_response(&self) -> SipMessage {
        let sent = self.wire();
        sent.iter()
            .find(|sent| {
                sent.destination == address(NEAR_PROXY)
                    && sent.message.status_code().is_some_and(|code| code > 100)
                    && cseq_method(&sent.message) == "INVITE"
            })
            .map(|sent| sent.message.clone())
            .unwrap_or_else(|| panic!("no response to the INVITE: {:?}", summaries(&sent)))
    }

    /// The callee answers reliably with SDP and the caller PRACKs siphon's copy,
    /// which sends siphon's PRACK to the callee: the INVITE's offer/answer
    /// exchange is complete on both dialogs. Returns siphon's 183.
    fn answered_reliably(&self) -> SipMessage {
        self.callee_responds(183, Some(42), ANSWER);
        let progress = self.invite_response();
        let mut raw = format!(
            concat!(
                "PRACK sip:192.0.2.1:5060 SIP/2.0\r\n",
                "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-near-prack\r\n",
                "Via: SIP/2.0/UDP 192.0.2.30:5060;branch=z9hG4bK-caller-prack\r\n",
                "Max-Forwards: 68\r\n",
                "From: <sip:15550100001@caller.example.com>;tag=caller-tag\r\n",
                "To: {to}\r\n",
                "Call-ID: {call_id}\r\n",
                "CSeq: 2 PRACK\r\n",
                "RAck: {rseq} 1 INVITE\r\n",
            ),
            to = header(&progress, "To"),
            call_id = SIP_CALL_ID,
            rseq = header(&progress, "RSeq").trim(),
        );
        push_body(&mut raw, "");
        self.receives(NEAR_PROXY, "PRACK", raw);
        let sent = self.wire();
        // siphon's PRACK follows the callee's own route set, to the proxy on the
        // callee's side.
        let prack = sent
            .iter()
            .find(|sent| sent.message.method() == Some(&Method::Prack))
            .map(|sent| sent.message.clone())
            .unwrap_or_else(|| panic!("no PRACK to the callee: {:?}", summaries(&sent)));
        self.answers(CALLEE, &prack);
        self.wire();
        progress
    }
}

fn drain(udp: &flume::Receiver<OutboundMessage>) -> Vec<Sent> {
    let mut sent = Vec::new();
    while let Ok(outbound) = udp.try_recv() {
        for frame in outbound.frames() {
            sent.push(Sent {
                destination: outbound.destination,
                message: parse_sip_message_bytes(frame).expect("siphon sent a message that parses"),
            });
        }
    }
    sent
}

/// RFC 3261 §12.1.1: "the UAS MUST copy all Record-Route header field values
/// from the request into the response [...] and MUST maintain the order of those
/// values." A reliable 183 with a To tag establishes the early dialog the
/// caller's PRACK is sent on (RFC 3262 §3), so it carries them, parameters
/// included, and nothing of the callee's.
#[tokio::test(flavor = "multi_thread")]
async fn a_reliable_183_carries_the_callers_record_route_in_order() {
    let call = RoutedCall::place();
    call.callee_responds(183, Some(42), ANSWER);
    let progress = call.invite_response();
    assert_eq!(progress.status_code(), Some(183));
    assert!(header(&progress, "To").contains(";tag="));
    assert!(progress.headers.get("RSeq").is_some());
    assert_eq!(values(&progress, "Record-Route"), callers_record_route());
}

/// The same for a 180 sent unreliably: with a To tag it establishes the early
/// dialog just the same (RFC 3261 §12.1).
#[tokio::test(flavor = "multi_thread")]
async fn a_180_with_a_tag_carries_the_callers_record_route_in_order() {
    let call = RoutedCall::place();
    call.callee_responds(180, None, "");
    let ringing = call.invite_response();
    assert_eq!(ringing.status_code(), Some(180));
    assert!(header(&ringing, "To").contains(";tag="));
    assert_eq!(values(&ringing, "Record-Route"), callers_record_route());
}

/// The 2xx carries the same values as the provisionals before it, so the
/// caller's route set does not change when the dialog is confirmed (RFC 3261
/// §12.1.2), and the callee's `Record-Route` crosses on none of them.
#[tokio::test(flavor = "multi_thread")]
async fn the_2xx_carries_the_route_set_the_provisionals_opened_the_dialog_with() {
    let call = RoutedCall::place();
    call.callee_responds(180, None, "");
    let ringing = call.invite_response();
    call.callee_responds(200, None, ANSWER);
    let answer = call.invite_response();
    assert_eq!(answer.status_code(), Some(200));
    assert_eq!(values(&answer, "Record-Route"), callers_record_route());
    assert_eq!(
        values(&answer, "Record-Route"),
        values(&ringing, "Record-Route")
    );
}

/// The two dialogs are siphon's own on each side: the caller's `Record-Route`
/// and Via reach the callee on nothing siphon sends it.
#[tokio::test(flavor = "multi_thread")]
async fn the_callers_record_route_does_not_reach_the_callee() {
    let call = RoutedCall::place();
    assert_eq!(
        values(&call.callee_invite, "Record-Route"),
        Vec::<String>::new()
    );
    assert_eq!(values(&call.callee_invite, "Route"), Vec::<String>::new());
    assert_eq!(values(&call.callee_invite, "Via").len(), 1);
}

/// RFC 3261 §12.2.1.1: a request within a dialog carries the dialog's route set
/// in `Route` and goes to its first hop. That holds on the early dialog too, so
/// an UPDATE the callee sends before it answers reaches the caller through the
/// proxies its INVITE crossed, the one next to siphon first.
#[tokio::test(flavor = "multi_thread")]
async fn a_request_to_the_caller_before_the_answer_follows_the_route_set() {
    let call = RoutedCall::place();
    call.answered_reliably();
    assert_eq!(
        call.state
            .call_actors
            .get_call(&call.call_id)
            .expect("the call")
            .a_leg
            .dialog
            .route_set,
        callers_record_route(),
        "the caller's dialog has its route set before anybody answers"
    );

    let invite = &call.callee_invite;
    let mut raw = format!(
        concat!(
            "UPDATE sip:192.0.2.1:5060 SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 198.51.100.70:5060;branch=z9hG4bK-callee-update\r\n",
            "Max-Forwards: 70\r\n",
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
    push_body(&mut raw, CALLEE_OFFER);
    call.receives(CALLEE, "UPDATE", raw);

    let sent = call.wire();
    let update = sent
        .iter()
        .find(|sent| sent.message.method() == Some(&Method::Update))
        .unwrap_or_else(|| panic!("no UPDATE to the caller: {:?}", summaries(&sent)));
    assert_eq!(update.destination, address(NEAR_PROXY));
    assert_eq!(values(&update.message, "Route"), callers_record_route());
    assert_eq!(
        values(&update.message, "Record-Route"),
        Vec::<String>::new()
    );
    let StartLine::Request(request_line) = &update.message.start_line else {
        panic!("a request");
    };
    assert_eq!(
        request_line.request_uri.to_string(),
        "sip:caller@192.0.2.30:5060"
    );
}
