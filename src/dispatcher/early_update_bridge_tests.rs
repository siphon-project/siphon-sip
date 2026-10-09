//! An offer in an UPDATE on the early dialog, across the B2BUA (RFC 3311 §5,
//! RFC 3312 §5 and §13.1).
//!
//! A caller that negotiates preconditions sends its INVITE with the offer, gets
//! the answer in a reliable 183, PRACKs it, and once its resources are reserved
//! sends an UPDATE carrying a new offer with the updated current status, all
//! before the callee alerts. Either party may do so (RFC 3311 §5.1). siphon is
//! the UAS of the caller's dialog and the UAC of the callee's, so the UPDATE
//! crosses when the INVITE's own offer/answer exchange is complete on both and
//! no other offer is in flight, and is refused with the status RFC 3311 §5.2
//! names when it is not.
//!
//! Driven through the INVITE handler, the B-leg response handler, the request
//! handler and the response entry point, with every frame siphon sends read back
//! off the UDP egress channel in order.

use super::lcr_ring_timeout_tests::{summaries, top_via_branch, Sent};
use super::test_dispatcher::{test_dispatcher_with_script, TestDispatcher};
use super::*;
use crate::rtpengine::test_engine::TestEngine;

const CALLER: &str = "192.0.2.30:5060";
const CALLEE: &str = "198.51.100.70:5060";
const SIP_CALL_ID: &str = "early-update@192.0.2.30";

/// The caller's offer in its INVITE: no resources reserved yet (RFC 3312 §13.1,
/// SDP1).
const INVITE_OFFER: &str = concat!(
    "v=0\r\n",
    "o=caller 3 3 IN IP4 192.0.2.30\r\n",
    "s=caller session\r\n",
    "c=IN IP4 192.0.2.30\r\n",
    "t=0 0\r\n",
    "m=audio 40000 RTP/AVP 0\r\n",
    "a=rtpmap:0 PCMU/8000\r\n",
    "a=curr:qos e2e none\r\n",
    "a=des:qos mandatory e2e sendrecv\r\n",
);

/// The callee's answer in its reliable 183, asking to be told when the caller's
/// direction is ready (SDP2).
const PROGRESS_ANSWER: &str = concat!(
    "v=0\r\n",
    "o=callee 7 7 IN IP4 198.51.100.71\r\n",
    "s=callee session\r\n",
    "c=IN IP4 198.51.100.71\r\n",
    "t=0 0\r\n",
    "m=audio 30000 RTP/AVP 0\r\n",
    "a=rtpmap:0 PCMU/8000\r\n",
    "a=curr:qos e2e none\r\n",
    "a=des:qos mandatory e2e sendrecv\r\n",
    "a=conf:qos e2e recv\r\n",
);

/// The caller's offer in its UPDATE once it has reserved (SDP3).
const UPDATE_OFFER: &str = concat!(
    "v=0\r\n",
    "o=caller 3 4 IN IP4 192.0.2.30\r\n",
    "s=caller session\r\n",
    "c=IN IP4 192.0.2.30\r\n",
    "t=0 0\r\n",
    "m=audio 40000 RTP/AVP 0\r\n",
    "a=rtpmap:0 PCMU/8000\r\n",
    "a=curr:qos e2e send\r\n",
    "a=des:qos mandatory e2e sendrecv\r\n",
);

/// The callee's answer to it in the 200 to the UPDATE: both directions ready
/// (SDP4).
const UPDATE_ANSWER: &str = concat!(
    "v=0\r\n",
    "o=callee 7 8 IN IP4 198.51.100.71\r\n",
    "s=callee session\r\n",
    "c=IN IP4 198.51.100.71\r\n",
    "t=0 0\r\n",
    "m=audio 30000 RTP/AVP 0\r\n",
    "a=rtpmap:0 PCMU/8000\r\n",
    "a=curr:qos e2e sendrecv\r\n",
    "a=des:qos mandatory e2e sendrecv\r\n",
);

/// An offer of the callee's own in an UPDATE on its early dialog.
const CALLEE_UPDATE_OFFER: &str = concat!(
    "v=0\r\n",
    "o=callee 7 8 IN IP4 198.51.100.71\r\n",
    "s=callee session\r\n",
    "c=IN IP4 198.51.100.71\r\n",
    "t=0 0\r\n",
    "m=audio 30002 RTP/AVP 0\r\n",
    "a=rtpmap:0 PCMU/8000\r\n",
    "a=curr:qos e2e recv\r\n",
    "a=des:qos mandatory e2e sendrecv\r\n",
);

/// The caller's answer to that.
const CALLER_UPDATE_ANSWER: &str = concat!(
    "v=0\r\n",
    "o=caller 3 4 IN IP4 192.0.2.30\r\n",
    "s=caller session\r\n",
    "c=IN IP4 192.0.2.30\r\n",
    "t=0 0\r\n",
    "m=audio 40000 RTP/AVP 0\r\n",
    "a=rtpmap:0 PCMU/8000\r\n",
    "a=curr:qos e2e sendrecv\r\n",
    "a=des:qos mandatory e2e sendrecv\r\n",
);

const DIAL: &str = concat!(
    "from siphon import b2bua\n",
    "\n",
    "@b2bua.on_invite\n",
    "def on_invite(call):\n",
    "    call.dial(\"sip:15550100042@198.51.100.70:5060\")\n",
);

/// The same under the policy that passes preconditions end to end.
const DIAL_INTRA_TRUST_DOMAIN: &str = concat!(
    "from siphon import b2bua\n",
    "\n",
    "@b2bua.on_invite\n",
    "def on_invite(call):\n",
    "    call.dial(\"sip:15550100042@198.51.100.70:5060\",\n",
    "              header_policy=\"ims-intra-trust-domain@2026\")\n",
);

/// The same, dialling a second callee when the first fails.
const DIAL_AGAIN_ON_FAILURE: &str = concat!(
    "from siphon import b2bua\n",
    "\n",
    "@b2bua.on_invite\n",
    "def on_invite(call):\n",
    "    call.dial(\"sip:15550100042@198.51.100.70:5060\")\n",
    "\n",
    "@b2bua.on_failure\n",
    "def on_failure(call, code, reason):\n",
    "    call.dial(\"sip:15550100043@198.51.100.80:5060\")\n",
);

fn address(text: &str) -> SocketAddr {
    text.parse().expect("a literal address")
}

fn parse(raw: &str) -> SipMessage {
    parse_sip_message_bytes(raw.as_bytes()).expect("the test message parses")
}

fn body_text(message: &SipMessage) -> String {
    String::from_utf8(message.body.clone()).expect("an SDP body is UTF-8")
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

fn cseq_number(message: &SipMessage) -> u32 {
    message
        .headers
        .cseq()
        .and_then(|cseq| cseq.split_whitespace().next())
        .and_then(|number| number.parse().ok())
        .expect("a CSeq number")
}

/// The `o=` session id and version of an SDP body.
fn origin(message: &SipMessage) -> (String, u64) {
    let body = body_text(message);
    let line = body
        .lines()
        .find(|line| line.starts_with("o="))
        .unwrap_or_else(|| panic!("no o= line in {body}"));
    let mut fields = line.split_whitespace().skip(1);
    let session_id = fields.next().expect("a session id").to_string();
    let version = fields
        .next()
        .and_then(|version| version.parse().ok())
        .expect("a session version");
    (session_id, version)
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

fn to(sent: &[Sent], party: &str) -> Vec<SipMessage> {
    sent.iter()
        .filter(|sent| sent.destination == address(party))
        .map(|sent| sent.message.clone())
        .collect()
}

fn requests(messages: &[SipMessage], method: &Method) -> Vec<SipMessage> {
    messages
        .iter()
        .filter(|message| message.method() == Some(method))
        .cloned()
        .collect()
}

fn the_response(messages: &[SipMessage], method: &str) -> SipMessage {
    messages
        .iter()
        .find(|message| message.status_code().is_some() && cseq_method(message) == method)
        .cloned()
        .unwrap_or_else(|| panic!("no response to a {method}"))
}

/// The `Retry-After` of a refusal, which RFC 3311 §5.2 has between 0 and 10
/// seconds.
fn retry_after(response: &SipMessage) -> Option<u32> {
    response
        .headers
        .get("Retry-After")
        .and_then(|value| value.trim().parse().ok())
}

/// A caller's call that supports `100rel`, dialled to one callee.
struct EarlyCall {
    state: Arc<DispatcherState>,
    udp: flume::Receiver<OutboundMessage>,
    call_id: String,
    callee_invite: SipMessage,
    /// The CSeq number of the PRACK siphon last sent the callee.
    callee_prack_cseq: std::cell::Cell<u32>,
}

impl EarlyCall {
    fn place(script: &str) -> EarlyCall {
        EarlyCall::place_on(test_dispatcher_with_script(script))
    }

    fn place_on(TestDispatcher { state, udp }: TestDispatcher) -> EarlyCall {
        let state = Arc::new(state);
        let mut raw = format!(
            concat!(
                "INVITE sip:15550100042@siphon.example.com SIP/2.0\r\n",
                "Via: SIP/2.0/UDP 192.0.2.30:5060;branch=z9hG4bK-early-update\r\n",
                "Max-Forwards: 70\r\n",
                "From: <sip:15550100001@caller.example.com>;tag=caller-tag\r\n",
                "To: <sip:15550100042@siphon.example.com>\r\n",
                "Call-ID: {call_id}\r\n",
                "CSeq: 1 INVITE\r\n",
                "Contact: <sip:caller@192.0.2.30:5060>\r\n",
                "Supported: 100rel, precondition\r\n",
                "Allow: INVITE, ACK, CANCEL, BYE, PRACK, UPDATE\r\n",
            ),
            call_id = SIP_CALL_ID,
        );
        push_body(&mut raw, INVITE_OFFER);
        let inbound = InboundMessage {
            client_transport: None,
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: state.local_addr,
            remote_addr: address(CALLER),
            data: Bytes::from(raw.clone().into_bytes()),
        };
        tokio::task::block_in_place(|| handle_b2bua_invite(inbound, parse(&raw), &state));
        let call_id = state
            .call_actors
            .find_by_sip_call_id(SIP_CALL_ID)
            .expect("the call was placed");
        let callee_invite = requests(&to(&drain(&udp), CALLEE), &Method::Invite)
            .into_iter()
            .next()
            .expect("siphon dialled the callee");
        EarlyCall {
            state,
            udp,
            call_id,
            callee_invite,
            callee_prack_cseq: std::cell::Cell::new(0),
        }
    }

    /// The same call with its media anchored on `engine`, whose session names
    /// both parties.
    async fn place_anchored(engine: &TestEngine) -> EarlyCall {
        let TestDispatcher { mut state, udp } = test_dispatcher_with_script(DIAL);
        state.rtpengine_set = Some(engine.backend().await);
        let sessions = Arc::new(crate::rtpengine::MediaSessionStore::new());
        sessions.insert(crate::rtpengine::MediaSession {
            call_id: SIP_CALL_ID.to_string(),
            rtpengine_call_id: SIP_CALL_ID.to_string(),
            from_tag: "caller-tag".to_string(),
            to_tag: Some("callee-tag".to_string()),
            profile: "rtp_passthrough".to_string(),
            ws_uri: None,
            ws_tee: None,
            ws_bridge_attached: false,
            bridge_sides: None,
            created_at: std::time::Instant::now(),
        });
        state.rtpengine_sessions = Some(sessions);
        state.rtpengine_profiles = Some(Arc::new(crate::rtpengine::ProfileRegistry::new()));
        EarlyCall::place_on(TestDispatcher { state, udp })
    }

    fn wire(&self) -> Vec<Sent> {
        drain(&self.udp)
    }

    fn call_is_up(&self) -> bool {
        self.state.call_actors.get_call(&self.call_id).is_some()
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

    /// `party` answers `request`, one siphon sent it, with `status_code`, `body`
    /// and `extra_headers`, through the dispatcher's response entry point.
    fn answers(
        &self,
        party: &str,
        request: &SipMessage,
        status_code: u16,
        body: &str,
        extra_headers: &[(&str, &str)],
    ) {
        let mut raw = format!("SIP/2.0 {status_code} Reason\r\n");
        for name in ["Via", "From", "To", "Call-ID", "CSeq"] {
            raw.push_str(&format!("{name}: {}\r\n", header(request, name)));
        }
        for (name, value) in extra_headers {
            raw.push_str(&format!("{name}: {value}\r\n"));
        }
        push_body(&mut raw, body);
        let inbound = InboundMessage {
            client_transport: None,
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: self.state.local_addr,
            remote_addr: address(party),
            data: Bytes::from(raw.clone().into_bytes()),
        };
        tokio::task::block_in_place(|| {
            super::response::handle_response(inbound, parse(&raw), status_code, &self.state)
        });
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

    /// The caller's in-dialog `method` numbered `cseq`, on the early dialog the
    /// `provisional` siphon sent it opened.
    fn caller_request(&self, method: &str, provisional: &SipMessage, cseq: u32) -> String {
        format!(
            concat!(
                "{method} sip:192.0.2.1:5060 SIP/2.0\r\n",
                "Via: SIP/2.0/UDP 192.0.2.30:5060;branch=z9hG4bK-caller-{method}-{cseq}\r\n",
                "Max-Forwards: 70\r\n",
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

    /// The caller PRACKs `provisional` as its request numbered `cseq`.
    fn caller_pracks(&self, provisional: &SipMessage, cseq: u32, body: &str) {
        let mut raw = self.caller_request("PRACK", provisional, cseq);
        raw.push_str(&format!(
            "RAck: {} 1 INVITE\r\n",
            header(provisional, "RSeq").trim()
        ));
        push_body(&mut raw, body);
        self.receives(CALLER, "PRACK", raw);
    }

    /// The caller sends an UPDATE numbered `cseq` on its early dialog.
    fn caller_updates(&self, provisional: &SipMessage, cseq: u32, body: &str) {
        let mut raw = self.caller_request("UPDATE", provisional, cseq);
        push_body(&mut raw, body);
        self.receives(CALLER, "UPDATE", raw);
    }

    /// The callee sends an UPDATE numbered `cseq` on the early dialog its
    /// provisionals opened.
    fn callee_updates(&self, cseq: u32, body: &str) {
        let invite = &self.callee_invite;
        let mut raw = format!(
            concat!(
                "UPDATE sip:192.0.2.1:5060 SIP/2.0\r\n",
                "Via: SIP/2.0/UDP 198.51.100.70:5060;branch=z9hG4bK-callee-update-{cseq}\r\n",
                "Max-Forwards: 70\r\n",
                "From: {from};tag=callee-tag\r\n",
                "To: {to}\r\n",
                "Call-ID: {call_id}\r\n",
                "CSeq: {cseq} UPDATE\r\n",
                "Contact: <sip:callee@198.51.100.70:5060>\r\n",
            ),
            cseq = cseq,
            from = header(invite, "To"),
            to = header(invite, "From"),
            call_id = header(invite, "Call-ID"),
        );
        push_body(&mut raw, body);
        self.receives(CALLEE, "UPDATE", raw);
    }

    /// The callee answers reliably with `PROGRESS_ANSWER` and the caller PRACKs
    /// siphon's copy, which sends siphon's PRACK to the callee: the INVITE's
    /// offer/answer exchange is complete on both dialogs. Returns siphon's 183.
    fn answered_reliably(&self) -> SipMessage {
        self.callee_responds(183, Some(42), PROGRESS_ANSWER);
        let sent = self.wire();
        let progress = the_response(&to(&sent, CALLER), "INVITE");
        assert_eq!(progress.status_code(), Some(183), "{:?}", summaries(&sent));
        self.caller_pracks(&progress, 2, "");
        let sent = self.wire();
        assert_eq!(
            the_response(&to(&sent, CALLER), "PRACK").status_code(),
            Some(200),
            "{:?}",
            summaries(&sent)
        );
        let prack = requests(&to(&sent, CALLEE), &Method::Prack);
        assert_eq!(prack.len(), 1, "{:?}", summaries(&sent));
        self.callee_prack_cseq.set(cseq_number(&prack[0]));
        self.answers(CALLEE, &prack[0], 200, "", &[]);
        assert_eq!(summaries(&self.wire()), Vec::<String>::new());
        progress
    }
}

/// The precondition flow of RFC 3312 §13.1 across the B2BUA: INVITE with the
/// offer, reliable 183 with the answer, PRACK, UPDATE with the new offer, 200 to
/// the UPDATE with its answer, 180, 200, ACK. Each party sees the other's session
/// description on its own dialog, and siphon's `o=` version rises with each new
/// one it sends a party (RFC 3264 §8).
#[tokio::test(flavor = "multi_thread")]
async fn the_precondition_exchange_crosses_in_an_update_on_the_early_dialog() {
    let call = EarlyCall::place(DIAL);
    let invite = call.callee_invite.clone();
    assert!(body_text(&invite).contains("a=curr:qos e2e none"));
    let progress = call.answered_reliably();
    assert!(body_text(&progress).contains("a=conf:qos e2e recv"));

    call.caller_updates(&progress, 3, UPDATE_OFFER);
    let sent = call.wire();
    let to_caller = to(&sent, CALLER);
    assert!(
        to_caller
            .iter()
            .all(|message| message.status_code() == Some(100)),
        "the caller's UPDATE has no final response yet: {:?}",
        summaries(&sent)
    );
    let update = requests(&to(&sent, CALLEE), &Method::Update);
    assert_eq!(update.len(), 1, "{:?}", summaries(&sent));
    let update = &update[0];
    // On the callee's early dialog (RFC 3261 §12.2.1.1): its Call-ID, siphon's
    // tag and the callee's, the callee's Contact, the next CSeq.
    assert_eq!(header(update, "Call-ID"), header(&invite, "Call-ID"));
    assert_eq!(
        header(update, "From"),
        header(&invite, "From"),
        "siphon's own identity and tag on the callee's dialog"
    );
    assert_eq!(
        header(update, "To"),
        format!("{};tag=callee-tag", header(&invite, "To"))
    );
    let StartLine::Request(request_line) = &update.start_line else {
        panic!("a request");
    };
    assert_eq!(
        request_line.request_uri.to_string(),
        "sip:callee@198.51.100.70:5060"
    );
    // Each request on the dialog is numbered one above the last
    // (RFC 3261 §12.2.1.1): the INVITE, siphon's PRACK, this UPDATE.
    assert_eq!(call.callee_prack_cseq.get(), cseq_number(&invite) + 1);
    assert_eq!(cseq_number(update), call.callee_prack_cseq.get() + 1);
    assert!(!header(update, "Via").contains("192.0.2.30"));
    let offer = body_text(update);
    assert!(offer.contains("a=curr:qos e2e send\r\n"), "{offer}");
    assert!(
        offer.contains("a=des:qos mandatory e2e sendrecv"),
        "{offer}"
    );
    assert!(offer.contains("m=audio 40000 RTP/AVP 0"), "{offer}");
    assert!(!offer.contains("o=caller"), "{offer}");
    let (invite_session, invite_version) = origin(&invite);
    let (update_session, update_version) = origin(update);
    assert_eq!(update_session, invite_session);
    assert!(update_version > invite_version, "{offer}");

    call.answers(CALLEE, update, 200, UPDATE_ANSWER, &[]);
    let sent = call.wire();
    assert!(to(&sent, CALLEE).is_empty(), "{:?}", summaries(&sent));
    let ok = the_response(&to(&sent, CALLER), "UPDATE");
    assert_eq!(ok.status_code(), Some(200));
    assert_eq!(header(&ok, "CSeq"), "3 UPDATE");
    assert_eq!(header(&ok, "Call-ID"), SIP_CALL_ID);
    assert_eq!(header(&ok, "To"), header(&progress, "To"));
    assert_eq!(
        header(&ok, "From"),
        "<sip:15550100001@caller.example.com>;tag=caller-tag"
    );
    assert!(header(&ok, "Via").contains("z9hG4bK-caller-UPDATE-3"));
    let answer = body_text(&ok);
    assert!(answer.contains("a=curr:qos e2e sendrecv"), "{answer}");
    assert!(answer.contains("m=audio 30000 RTP/AVP 0"), "{answer}");
    assert!(!answer.contains("o=callee"), "{answer}");
    let (progress_session, progress_version) = origin(&progress);
    let (answer_session, answer_version) = origin(&ok);
    assert_eq!(answer_session, progress_session);
    assert!(answer_version > progress_version, "{answer}");

    // The session descriptions in force are the ones the UPDATE exchanged.
    {
        let actor = call
            .state
            .call_actors
            .get_call(&call.call_id)
            .expect("the call");
        assert_eq!(
            actor.a_leg.dialog.last_sent_sdp.as_deref(),
            Some(ok.body.as_slice())
        );
        assert_eq!(
            actor.b_legs[0].dialog.last_sent_sdp.as_deref(),
            Some(update.body.as_slice())
        );
        assert_eq!(actor.winner, None, "nobody has answered yet");
    }

    call.callee_responds(180, None, "");
    let sent = call.wire();
    assert_eq!(
        the_response(&to(&sent, CALLER), "INVITE").status_code(),
        Some(180),
        "{:?}",
        summaries(&sent)
    );
    call.callee_responds(200, None, "");
    let sent = call.wire();
    let answered = the_response(&to(&sent, CALLER), "INVITE");
    assert_eq!(answered.status_code(), Some(200), "{:?}", summaries(&sent));
    assert_eq!(header(&answered, "To"), header(&progress, "To"));
    assert_eq!(
        requests(&to(&sent, CALLEE), &Method::Ack).len(),
        1,
        "{:?}",
        summaries(&sent)
    );
    let mut ack = call.caller_request("ACK", &progress, 1);
    push_body(&mut ack, "");
    call.receives(CALLER, "ACK", ack);
    assert!(call.call_is_up());
}

/// RFC 3312 §11 has the offerer list `precondition` in `Require` on an UPDATE
/// whose offer carries mandatory preconditions. Under a policy that passes
/// preconditions end to end the tag crosses on the relayed UPDATE; under one
/// that does not, `Require` stays on the caller's leg as every other tag does.
#[tokio::test(flavor = "multi_thread")]
async fn the_precondition_tag_crosses_on_the_update_where_the_policy_passes_it() {
    for (script, crossed) in [
        (DIAL_INTRA_TRUST_DOMAIN, Some("precondition")),
        (DIAL, None),
    ] {
        let call = EarlyCall::place(script);
        let progress = call.answered_reliably();
        let mut raw = call.caller_request("UPDATE", &progress, 3);
        raw.push_str("Require: precondition\r\nSupported: 100rel, timer\r\n");
        push_body(&mut raw, UPDATE_OFFER);
        call.receives(CALLER, "UPDATE", raw);
        let update = requests(&to(&call.wire(), CALLEE), &Method::Update);
        assert_eq!(update.len(), 1);
        assert_eq!(
            update[0].headers.get("Require").map(String::as_str),
            crossed
        );
        assert_eq!(update[0].headers.get("Supported"), None);
    }
}

/// The callee's side of the same exchange (RFC 3311 §5.1, "MAY be sent by either
/// caller or callee"): an UPDATE with an offer on the callee's early dialog
/// reaches the caller on the caller's, and the caller's answer returns in the 200.
#[tokio::test(flavor = "multi_thread")]
async fn a_callees_update_on_the_early_dialog_reaches_the_caller() {
    let call = EarlyCall::place(DIAL);
    let invite = call.callee_invite.clone();
    let progress = call.answered_reliably();

    call.callee_updates(1, CALLEE_UPDATE_OFFER);
    let sent = call.wire();
    let update = requests(&to(&sent, CALLER), &Method::Update);
    assert_eq!(update.len(), 1, "{:?}", summaries(&sent));
    let update = &update[0];
    assert_eq!(header(update, "Call-ID"), SIP_CALL_ID);
    assert_eq!(header(update, "From"), header(&progress, "To"));
    assert_eq!(
        header(update, "To"),
        "<sip:15550100001@caller.example.com>;tag=caller-tag"
    );
    let StartLine::Request(request_line) = &update.start_line else {
        panic!("a request");
    };
    assert_eq!(
        request_line.request_uri.to_string(),
        "sip:caller@192.0.2.30:5060"
    );
    let offer = body_text(update);
    assert!(offer.contains("a=curr:qos e2e recv"), "{offer}");
    assert!(offer.contains("m=audio 30002 RTP/AVP 0"), "{offer}");
    assert!(!offer.contains("o=callee"), "{offer}");
    let (progress_session, progress_version) = origin(&progress);
    let (offer_session, offer_version) = origin(update);
    assert_eq!(offer_session, progress_session);
    assert!(offer_version > progress_version, "{offer}");

    call.answers(CALLER, update, 200, CALLER_UPDATE_ANSWER, &[]);
    let sent = call.wire();
    assert!(to(&sent, CALLER).is_empty(), "{:?}", summaries(&sent));
    let ok = the_response(&to(&sent, CALLEE), "UPDATE");
    assert_eq!(ok.status_code(), Some(200));
    assert_eq!(header(&ok, "CSeq"), "1 UPDATE");
    assert_eq!(header(&ok, "Call-ID"), header(&invite, "Call-ID"));
    assert_eq!(
        header(&ok, "From"),
        format!("{};tag=callee-tag", header(&invite, "To"))
    );
    assert_eq!(header(&ok, "To"), header(&invite, "From"));
    assert!(header(&ok, "Via").contains("z9hG4bK-callee-update-1"));
    let answer = body_text(&ok);
    assert!(answer.contains("a=curr:qos e2e sendrecv"), "{answer}");
    assert!(!answer.contains("o=caller"), "{answer}");
    let (invite_session, invite_version) = origin(&invite);
    let (answer_session, answer_version) = origin(&ok);
    assert_eq!(answer_session, invite_session);
    assert!(answer_version > invite_version, "{answer}");
    assert!(call.call_is_up());
}

/// An UPDATE without an offer changes nothing about the session, whoever sends
/// it: it is answered 200 on the dialog it arrived on and crosses nowhere.
#[tokio::test(flavor = "multi_thread")]
async fn an_update_without_an_offer_is_answered_on_its_own_dialog() {
    let call = EarlyCall::place(DIAL);
    let progress = call.answered_reliably();

    call.caller_updates(&progress, 3, "");
    let sent = call.wire();
    assert!(to(&sent, CALLEE).is_empty(), "{:?}", summaries(&sent));
    let ok = the_response(&to(&sent, CALLER), "UPDATE");
    assert_eq!(ok.status_code(), Some(200));
    assert!(ok.body.is_empty());

    call.callee_updates(1, "");
    let sent = call.wire();
    assert!(to(&sent, CALLER).is_empty(), "{:?}", summaries(&sent));
    let ok = the_response(&to(&sent, CALLEE), "UPDATE");
    assert_eq!(ok.status_code(), Some(200));
    assert!(ok.body.is_empty());
}

/// Until the caller has PRACKed the reliable provisional that carried its
/// answer, an offer in its UPDATE crosses the INVITE's own: 500 with a
/// Retry-After (RFC 3311 §5.2), and nothing reaches the callee.
#[tokio::test(flavor = "multi_thread")]
async fn an_offer_before_the_prack_of_the_answer_is_refused_500_with_retry_after() {
    let call = EarlyCall::place(DIAL);
    call.callee_responds(183, Some(42), PROGRESS_ANSWER);
    let progress = the_response(&to(&call.wire(), CALLER), "INVITE");

    call.caller_updates(&progress, 2, UPDATE_OFFER);
    let sent = call.wire();
    assert!(to(&sent, CALLEE).is_empty(), "{:?}", summaries(&sent));
    let refusal = the_response(&to(&sent, CALLER), "UPDATE");
    assert_eq!(refusal.status_code(), Some(500));
    assert!(retry_after(&refusal).is_some_and(|seconds| seconds <= 10));
    assert!(call.call_is_up());
}

/// A callee that sent its answer in an unreliable 183 has not answered siphon's
/// offer yet (RFC 3262 §5), though the caller, sent it reliably, has PRACKed its
/// copy. siphon may not offer again on the callee's dialog (RFC 3311 §5.1), so
/// the caller is asked to try again: 500 with a Retry-After.
#[tokio::test(flavor = "multi_thread")]
async fn an_offer_the_callees_dialog_cannot_carry_yet_is_refused_500_with_retry_after() {
    let call = EarlyCall::place(DIAL);
    call.callee_responds(183, None, PROGRESS_ANSWER);
    let progress = the_response(&to(&call.wire(), CALLER), "INVITE");
    assert!(
        progress.headers.get("RSeq").is_some(),
        "reliable to the caller"
    );
    call.caller_pracks(&progress, 2, "");
    call.wire();

    call.caller_updates(&progress, 3, UPDATE_OFFER);
    let sent = call.wire();
    assert!(to(&sent, CALLEE).is_empty(), "{:?}", summaries(&sent));
    let refusal = the_response(&to(&sent, CALLER), "UPDATE");
    assert_eq!(refusal.status_code(), Some(500));
    assert!(retry_after(&refusal).is_some_and(|seconds| seconds <= 10));
    assert!(call.call_is_up());
}

/// A second offer from the caller while the callee still has its first: 500 with
/// a Retry-After (RFC 3311 §5.2), and only the first reaches the callee.
#[tokio::test(flavor = "multi_thread")]
async fn a_second_offer_while_the_first_is_with_the_callee_is_refused_500() {
    let call = EarlyCall::place(DIAL);
    let progress = call.answered_reliably();
    call.caller_updates(&progress, 3, UPDATE_OFFER);
    let first = requests(&to(&call.wire(), CALLEE), &Method::Update);
    assert_eq!(first.len(), 1);

    call.caller_updates(&progress, 4, UPDATE_OFFER);
    let sent = call.wire();
    assert!(to(&sent, CALLEE).is_empty(), "{:?}", summaries(&sent));
    let refusal = the_response(&to(&sent, CALLER), "UPDATE");
    assert_eq!(header(&refusal, "CSeq"), "4 UPDATE");
    assert_eq!(refusal.status_code(), Some(500));
    assert!(retry_after(&refusal).is_some_and(|seconds| seconds <= 10));

    // The first is still answered.
    call.answers(CALLEE, &first[0], 200, UPDATE_ANSWER, &[]);
    let ok = the_response(&to(&call.wire(), CALLER), "UPDATE");
    assert_eq!(header(&ok, "CSeq"), "3 UPDATE");
    assert_eq!(ok.status_code(), Some(200));
}

/// Offers crossing: the callee offers while the caller's offer is with it, or
/// the caller while the callee's is with the caller. siphon has an offer out on
/// the dialog the second one arrives on, so that one is refused 491 (RFC 3311
/// §5.2) and does not cross.
#[tokio::test(flavor = "multi_thread")]
async fn offers_that_cross_are_refused_491() {
    let call = EarlyCall::place(DIAL);
    let progress = call.answered_reliably();
    call.caller_updates(&progress, 3, UPDATE_OFFER);
    let update = requests(&to(&call.wire(), CALLEE), &Method::Update);

    call.callee_updates(1, CALLEE_UPDATE_OFFER);
    let sent = call.wire();
    assert!(
        requests(&to(&sent, CALLER), &Method::Update).is_empty(),
        "{:?}",
        summaries(&sent)
    );
    let refusal = the_response(&to(&sent, CALLEE), "UPDATE");
    assert_eq!(refusal.status_code(), Some(491));
    assert_eq!(retry_after(&refusal), None);

    // The caller's exchange completes, and then the callee's offer crosses.
    call.answers(CALLEE, &update[0], 200, UPDATE_ANSWER, &[]);
    call.wire();
    call.callee_updates(2, CALLEE_UPDATE_OFFER);
    let relayed = requests(&to(&call.wire(), CALLER), &Method::Update);
    assert_eq!(relayed.len(), 1);

    call.caller_updates(&progress, 4, UPDATE_OFFER);
    let sent = call.wire();
    assert!(to(&sent, CALLEE).is_empty(), "{:?}", summaries(&sent));
    let refusal = the_response(&to(&sent, CALLER), "UPDATE");
    assert_eq!(refusal.status_code(), Some(491));
    assert_eq!(retry_after(&refusal), None);
}

/// An offer in the caller's PRACK is with the callee until the 200 to siphon's
/// PRACK answers it (RFC 3262 §5). An UPDATE with another offer from the caller
/// meanwhile is refused 500 with a Retry-After, and one from the callee crosses
/// siphon's own offer on that dialog: 491 (RFC 3311 §5.2).
#[tokio::test(flavor = "multi_thread")]
async fn an_offer_while_one_in_a_prack_is_unanswered_is_refused() {
    let call = EarlyCall::place(DIAL);
    call.callee_responds(183, Some(42), PROGRESS_ANSWER);
    let progress = the_response(&to(&call.wire(), CALLER), "INVITE");
    call.caller_pracks(&progress, 2, UPDATE_OFFER);
    let sent = call.wire();
    let prack = requests(&to(&sent, CALLEE), &Method::Prack);
    assert_eq!(prack.len(), 1, "{:?}", summaries(&sent));
    assert!(
        !prack[0].body.is_empty(),
        "siphon's PRACK carries the offer"
    );

    call.caller_updates(&progress, 3, UPDATE_OFFER);
    let sent = call.wire();
    assert!(to(&sent, CALLEE).is_empty(), "{:?}", summaries(&sent));
    let refusal = the_response(&to(&sent, CALLER), "UPDATE");
    assert_eq!(refusal.status_code(), Some(500));
    assert!(retry_after(&refusal).is_some_and(|seconds| seconds <= 10));

    call.callee_updates(1, CALLEE_UPDATE_OFFER);
    let sent = call.wire();
    assert!(to(&sent, CALLER).is_empty(), "{:?}", summaries(&sent));
    let refusal = the_response(&to(&sent, CALLEE), "UPDATE");
    assert_eq!(refusal.status_code(), Some(491));

    // Once the PRACK's offer is answered, the next one crosses.
    call.answers(CALLEE, &prack[0], 200, UPDATE_ANSWER, &[]);
    call.wire();
    call.caller_updates(&progress, 4, UPDATE_OFFER);
    assert_eq!(
        requests(&to(&call.wire(), CALLEE), &Method::Update).len(),
        1
    );
}

/// siphon gives up on a callee, CANCELling it, while the caller's UPDATE is
/// with it: the UPDATE is answered 500 with a Retry-After, as when the callee
/// fails by itself.
#[tokio::test(flavor = "multi_thread")]
async fn a_callee_cancelled_with_the_update_in_flight_leaves_it_answered() {
    let call = EarlyCall::place(DIAL);
    let progress = call.answered_reliably();
    call.caller_updates(&progress, 3, UPDATE_OFFER);
    assert_eq!(
        requests(&to(&call.wire(), CALLEE), &Method::Update).len(),
        1
    );

    let cancelled = call
        .state
        .call_actors
        .cancel_ringing_branches(&call.call_id);
    assert_eq!(cancelled.len(), 1);
    tokio::task::block_in_place(|| cancel_settled_branches(&call.call_id, &cancelled, &call.state));
    let sent = call.wire();
    let refusal = the_response(&to(&sent, CALLER), "UPDATE");
    assert_eq!(header(&refusal, "CSeq"), "3 UPDATE");
    assert_eq!(refusal.status_code(), Some(500));
    assert!(retry_after(&refusal).is_some_and(|seconds| seconds <= 10));
    assert_eq!(
        requests(&to(&sent, CALLEE), &Method::Cancel).len(),
        1,
        "{:?}",
        summaries(&sent)
    );
    let tracking_left = call.state.call_actors.get_call(&call.call_id).map(|actor| {
        actor
            .b_legs
            .iter()
            .filter(|leg| leg.is_tracking_leg())
            .count()
    });
    assert_eq!(tracking_left, Some(0));
}

/// A callee that offers in an UPDATE before it has answered the offer in
/// siphon's INVITE crosses that offer: 491 (RFC 3311 §5.2).
#[tokio::test(flavor = "multi_thread")]
async fn a_callees_offer_before_it_answered_the_invite_is_refused_491() {
    let call = EarlyCall::place(DIAL);
    call.callee_responds(180, Some(42), "");
    call.wire();

    call.callee_updates(1, CALLEE_UPDATE_OFFER);
    let sent = call.wire();
    assert!(to(&sent, CALLER).is_empty(), "{:?}", summaries(&sent));
    let refusal = the_response(&to(&sent, CALLEE), "UPDATE");
    assert_eq!(refusal.status_code(), Some(491));
    assert!(call.call_is_up());
}

/// The callee's refusal of the offer is the caller's: the status and its
/// Retry-After cross, the session stays as it was (RFC 3311 §5.3), and the call
/// rings on.
#[tokio::test(flavor = "multi_thread")]
async fn the_callees_refusal_of_the_update_reaches_the_caller() {
    for (status_code, extra) in [
        (488, None),
        (491, None),
        (500, Some(("Retry-After", "4"))),
        (504, None),
    ] {
        let call = EarlyCall::place(DIAL);
        let progress = call.answered_reliably();
        let before = call
            .state
            .call_actors
            .get_call(&call.call_id)
            .map(|actor| {
                (
                    actor.a_leg.dialog.last_sent_sdp.clone(),
                    actor.b_legs[0].dialog.last_sent_sdp.clone(),
                )
            })
            .expect("the call");
        call.caller_updates(&progress, 3, UPDATE_OFFER);
        let update = requests(&to(&call.wire(), CALLEE), &Method::Update);
        let extra: Vec<(&str, &str)> = extra.into_iter().collect();
        call.answers(CALLEE, &update[0], status_code, "", &extra);
        let refusal = the_response(&to(&call.wire(), CALLER), "UPDATE");
        assert_eq!(refusal.status_code(), Some(status_code));
        assert_eq!(
            refusal.headers.get("Retry-After").map(String::as_str),
            extra.first().map(|(_, value)| *value),
            "callee {status_code}"
        );
        let after = call
            .state
            .call_actors
            .get_call(&call.call_id)
            .map(|actor| {
                (
                    actor.a_leg.dialog.last_sent_sdp.clone(),
                    actor.b_legs[0].dialog.last_sent_sdp.clone(),
                )
            })
            .expect("the call");
        assert_eq!(after, before, "callee {status_code}");
        assert!(call.call_is_up(), "callee {status_code}");
    }
}

/// A 481 or a 408 says the callee's early dialog is gone. The caller's is not:
/// its INVITE is still pending and may yet be answered by another callee. Relayed
/// as it is, the caller would end its own dialog over it (RFC 3311 §5.3), so the
/// caller is asked to try again instead: 500 with a Retry-After.
#[tokio::test(flavor = "multi_thread")]
async fn a_callee_dialog_that_is_gone_does_not_end_the_callers() {
    for status_code in [481, 408] {
        let call = EarlyCall::place(DIAL);
        let progress = call.answered_reliably();
        call.caller_updates(&progress, 3, UPDATE_OFFER);
        let update = requests(&to(&call.wire(), CALLEE), &Method::Update);
        call.answers(CALLEE, &update[0], status_code, "", &[]);
        let refusal = the_response(&to(&call.wire(), CALLER), "UPDATE");
        assert_eq!(refusal.status_code(), Some(500), "callee {status_code}");
        assert!(
            retry_after(&refusal).is_some_and(|seconds| seconds <= 10),
            "callee {status_code}"
        );
        assert!(call.call_is_up(), "callee {status_code}");
    }
}

/// The callee fails its INVITE while the caller's UPDATE is with it and never
/// answers the UPDATE. The caller's UPDATE is answered 500 with a Retry-After
/// before the script dials the next callee, so its transaction does not run out
/// and take the caller's dialog with it (RFC 3311 §5.3), and a late answer from
/// the failed callee reaches nobody.
#[tokio::test(flavor = "multi_thread")]
async fn a_callee_that_fails_with_the_update_in_flight_leaves_it_answered() {
    let call = EarlyCall::place(DIAL_AGAIN_ON_FAILURE);
    let progress = call.answered_reliably();
    call.caller_updates(&progress, 3, UPDATE_OFFER);
    let update = requests(&to(&call.wire(), CALLEE), &Method::Update);
    assert_eq!(update.len(), 1);

    call.callee_responds(480, None, "");
    let sent = call.wire();
    let refusal = the_response(&to(&sent, CALLER), "UPDATE");
    assert_eq!(header(&refusal, "CSeq"), "3 UPDATE");
    assert_eq!(refusal.status_code(), Some(500));
    assert!(retry_after(&refusal).is_some_and(|seconds| seconds <= 10));
    assert_eq!(header(&refusal, "To"), header(&progress, "To"));
    assert!(header(&refusal, "Via").contains("z9hG4bK-caller-UPDATE-3"));
    assert_eq!(
        requests(&to(&sent, "198.51.100.80:5060"), &Method::Invite).len(),
        1,
        "the script dialled the next callee: {:?}",
        summaries(&sent)
    );
    assert!(call.call_is_up());

    call.answers(CALLEE, &update[0], 200, UPDATE_ANSWER, &[]);
    assert_eq!(summaries(&call.wire()), Vec::<String>::new());

    // The next callee has not answered the offer in its INVITE: an offer from
    // the caller waits for it.
    call.caller_updates(&progress, 4, UPDATE_OFFER);
    let sent = call.wire();
    let refusal = the_response(&to(&sent, CALLER), "UPDATE");
    assert_eq!(refusal.status_code(), Some(500));
    assert!(retry_after(&refusal).is_some());
    assert!(
        requests(&to(&sent, "198.51.100.80:5060"), &Method::Update).is_empty(),
        "{:?}",
        summaries(&sent)
    );
}

/// On an anchored call the offer goes to the media engine as a re-offer from the
/// offering party's side and its answer as the `answer` completing it, as a
/// re-INVITE's do, so neither party's media address crosses.
#[tokio::test(flavor = "multi_thread")]
async fn an_anchored_early_update_crosses_the_media_engine_both_ways() {
    let engine = TestEngine::start(false).await;
    let call = EarlyCall::place_anchored(&engine).await;
    let progress = call.answered_reliably();
    let offers_before = engine.commands("offer").len();
    let answers_before = engine.commands("answer").len();

    call.caller_updates(&progress, 3, UPDATE_OFFER);
    let update = requests(&to(&call.wire(), CALLEE), &Method::Update);
    assert_eq!(update.len(), 1);
    let offer = body_text(&update[0]);
    assert!(offer.contains("c=IN IP4 203.0.113.50"), "{offer}");
    assert!(!offer.contains("192.0.2.30"), "{offer}");
    let offers = engine.commands("offer");
    assert_eq!(offers.len(), offers_before + 1);
    let reoffer = offers.last().expect("the re-offer");
    assert_eq!(reoffer.from_tag.as_deref(), Some("caller-tag"));
    assert!(reoffer
        .sdp
        .as_deref()
        .is_some_and(|sdp| sdp.contains("a=curr:qos e2e send\r\n")));

    call.answers(CALLEE, &update[0], 200, UPDATE_ANSWER, &[]);
    let ok = the_response(&to(&call.wire(), CALLER), "UPDATE");
    let answer = body_text(&ok);
    assert!(answer.contains("c=IN IP4 203.0.113.50"), "{answer}");
    assert!(!answer.contains("198.51.100.71"), "{answer}");
    let answers = engine.commands("answer");
    assert_eq!(answers.len(), answers_before + 1);
    let answered = answers.last().expect("the answer");
    assert_eq!(answered.from_tag.as_deref(), Some("caller-tag"));
    assert_eq!(answered.to_tag.as_deref(), Some("callee-tag"));
    assert!(answered.sdp.as_deref().is_some_and(|sdp| {
        sdp.contains("c=IN IP4 198.51.100.71") && sdp.contains("a=curr:qos e2e sendrecv")
    }));
}
