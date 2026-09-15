//! Offer and answer in PRACK across the B2BUA (RFC 3262 §5, RFC 3264).
//!
//! A reliable provisional from the callee that reaches the caller reliably is
//! PRACKed by siphon only once the caller has PRACKed siphon's copy of it, so a
//! body the caller's PRACK carries rides on siphon's PRACK to the callee: the
//! answer to an offer the callee made in that provisional, or a new offer, whose
//! answer the callee returns in the 200 to siphon's PRACK and siphon returns in
//! the 200 to the caller's.
//!
//! Driven through the INVITE handler, the B-leg response handler, the request
//! handler and the response entry point, with every frame siphon sends read back
//! off the UDP egress channel in order.

use super::lcr_ring_timeout_tests::{summaries, top_via_branch, Sent};
use super::test_dispatcher::{test_dispatcher_with_script, TestDispatcher};
use super::*;
use crate::rtpengine::test_engine::TestEngine;
use std::time::{Duration, Instant};

const CALLER: &str = "192.0.2.30:5060";
const CALLEE: &str = "198.51.100.70:5060";
const SIP_CALL_ID: &str = "prack-offer@192.0.2.30";

/// The callee's offer, in a reliable 183 to an INVITE that carried none.
const CALLEE_OFFER: &str = concat!(
    "v=0\r\n",
    "o=callee 7 7 IN IP4 198.51.100.71\r\n",
    "s=callee session\r\n",
    "c=IN IP4 198.51.100.71\r\n",
    "t=0 0\r\n",
    "m=audio 30000 RTP/AVP 0\r\n",
    "a=rtpmap:0 PCMU/8000\r\n",
);

/// The caller's answer to it, in its PRACK, with an attribute
/// `media.sdp_strip_attributes` names.
const CALLER_ANSWER: &str = concat!(
    "v=0\r\n",
    "o=caller 3 3 IN IP4 192.0.2.30\r\n",
    "s=caller session\r\n",
    "c=IN IP4 192.0.2.30\r\n",
    "t=0 0\r\n",
    "a=x-hidden\r\n",
    "m=audio 40000 RTP/AVP 0\r\n",
    "a=rtpmap:0 PCMU/8000\r\n",
);

/// The caller's offer, in its INVITE.
const CALLER_OFFER: &str = concat!(
    "v=0\r\n",
    "o=caller 3 3 IN IP4 192.0.2.30\r\n",
    "s=caller session\r\n",
    "c=IN IP4 192.0.2.30\r\n",
    "t=0 0\r\n",
    "m=audio 40000 RTP/AVP 0\r\n",
    "a=rtpmap:0 PCMU/8000\r\n",
);

/// The callee's answer to it, in a reliable 183.
const CALLEE_ANSWER: &str = concat!(
    "v=0\r\n",
    "o=callee 7 7 IN IP4 198.51.100.71\r\n",
    "s=callee session\r\n",
    "c=IN IP4 198.51.100.71\r\n",
    "t=0 0\r\n",
    "m=audio 30000 RTP/AVP 0\r\n",
    "a=rtpmap:0 PCMU/8000\r\n",
);

/// A new offer from the caller, in its PRACK: a different port.
const CALLER_NEW_OFFER: &str = concat!(
    "v=0\r\n",
    "o=caller 3 4 IN IP4 192.0.2.30\r\n",
    "s=caller session\r\n",
    "c=IN IP4 192.0.2.30\r\n",
    "t=0 0\r\n",
    "m=audio 40002 RTP/AVP 0\r\n",
    "a=rtpmap:0 PCMU/8000\r\n",
);

/// The callee's answer to that, in the 200 to siphon's PRACK.
const CALLEE_NEW_ANSWER: &str = concat!(
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

fn body_text(message: &SipMessage) -> String {
    String::from_utf8(message.body.clone()).expect("an SDP body is UTF-8")
}

fn cseq_method(message: &SipMessage) -> String {
    message
        .headers
        .cseq()
        .and_then(|cseq| cseq.split_whitespace().nth(1).map(str::to_string))
        .unwrap_or_default()
}

fn caller_invite(offer: Option<&str>) -> String {
    let mut raw = format!(
        concat!(
            "INVITE sip:15550100042@siphon.example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 192.0.2.30:5060;branch=z9hG4bK-prack-offer\r\n",
            "Max-Forwards: 70\r\n",
            "From: <sip:15550100001@caller.example.com>;tag=caller-tag\r\n",
            "To: <sip:15550100042@siphon.example.com>\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: 1 INVITE\r\n",
            "Contact: <sip:caller@192.0.2.30:5060>\r\n",
            "Supported: 100rel, timer\r\n",
        ),
        call_id = SIP_CALL_ID,
    );
    match offer {
        Some(sdp) => raw.push_str(&format!(
            "Content-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{sdp}",
            sdp.len()
        )),
        None => raw.push_str("Content-Length: 0\r\n\r\n"),
    }
    raw
}

/// What the callee lists in `Allow` unless a test says otherwise: UPDATE among
/// it, so siphon may carry an offer to it in one (RFC 3311 §4).
const CALLEE_ALLOW: &str = "INVITE, ACK, CANCEL, BYE, PRACK, UPDATE";

/// A caller's call that supports `100rel`, dialled to one callee.
struct PrackCall {
    state: Arc<DispatcherState>,
    udp: flume::Receiver<OutboundMessage>,
    call_id: String,
    callee_invite: SipMessage,
    /// The `Allow` every response of the callee's to the INVITE carries, when any.
    callee_allow: Option<String>,
}

impl PrackCall {
    fn place(offer: Option<&str>) -> PrackCall {
        PrackCall::place_on(test_dispatcher_with_script(DIAL), offer)
    }

    fn place_on(TestDispatcher { state, udp }: TestDispatcher, offer: Option<&str>) -> PrackCall {
        let state = Arc::new(state);
        let raw = caller_invite(offer);
        let inbound = InboundMessage {
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
        let callee_invite = drain(&udp)
            .into_iter()
            .find(|sent| sent.message.method() == Some(&Method::Invite))
            .expect("siphon dialled the callee")
            .message;
        PrackCall {
            state,
            udp,
            call_id,
            callee_invite,
            callee_allow: Some(CALLEE_ALLOW.to_string()),
        }
    }

    /// An offerless call with media anchored on `engine`, and the session
    /// `rtpengine.answer` records for an 18x that carries the offer: the callee as
    /// offerer, no answerer yet.
    async fn place_anchored(engine: &TestEngine) -> PrackCall {
        PrackCall::place_anchored_with(engine, None, "callee-tag", None).await
    }

    /// A call placed with `offer`, media anchored on `engine`, and an engine
    /// session whose offerer is `from_tag` and answerer `to_tag`.
    async fn place_anchored_with(
        engine: &TestEngine,
        offer: Option<&str>,
        from_tag: &str,
        to_tag: Option<&str>,
    ) -> PrackCall {
        let TestDispatcher { mut state, udp } = test_dispatcher_with_script(DIAL);
        state.rtpengine_set = Some(engine.backend().await);
        let sessions = Arc::new(crate::rtpengine::MediaSessionStore::new());
        sessions.insert(crate::rtpengine::MediaSession {
            call_id: SIP_CALL_ID.to_string(),
            rtpengine_call_id: SIP_CALL_ID.to_string(),
            from_tag: from_tag.to_string(),
            to_tag: to_tag.map(str::to_string),
            profile: "rtp_passthrough".to_string(),
            ws_uri: None,
            ws_tee: None,
            ws_bridge_attached: false,
            created_at: std::time::Instant::now(),
        });
        state.rtpengine_sessions = Some(sessions);
        state.rtpengine_profiles = Some(Arc::new(crate::rtpengine::ProfileRegistry::new()));
        PrackCall::place_on(TestDispatcher { state, udp }, offer)
    }

    fn wire(&self) -> Vec<Sent> {
        drain(&self.udp)
    }

    /// The callee answers its INVITE with `status_code`, reliably when `rseq` is
    /// given, with `body` as SDP.
    fn callee_responds(&self, status_code: u16, reason: &str, rseq: Option<u32>, body: &str) {
        let mut response = self.callee_response(status_code, reason, rseq, body);
        let handled = tokio::task::block_in_place(|| {
            handle_b2bua_response(
                &self.call_id,
                &top_via_branch(&self.callee_invite),
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

    /// The callee's response to its INVITE, as `callee_responds` sends it.
    fn callee_response(
        &self,
        status_code: u16,
        reason: &str,
        rseq: Option<u32>,
        body: &str,
    ) -> SipMessage {
        let invite = &self.callee_invite;
        let header = |name: &str| {
            invite
                .headers
                .get(name)
                .cloned()
                .unwrap_or_else(|| panic!("the callee INVITE has no {name}"))
        };
        let mut raw = format!("SIP/2.0 {status_code} {reason}\r\n");
        for via in invite.headers.get_all("Via").cloned().unwrap_or_default() {
            raw.push_str(&format!("Via: {via}\r\n"));
        }
        raw.push_str(&format!("From: {}\r\n", header("From")));
        raw.push_str(&format!("To: {};tag=callee-tag\r\n", header("To")));
        raw.push_str(&format!("Call-ID: {}\r\n", header("Call-ID")));
        raw.push_str(&format!("CSeq: {}\r\n", header("CSeq")));
        raw.push_str("Contact: <sip:callee@198.51.100.70:5060>\r\n");
        if let Some(allow) = &self.callee_allow {
            raw.push_str(&format!("Allow: {allow}\r\n"));
        }
        if let Some(rseq) = rseq {
            raw.push_str(&format!("Require: 100rel\r\nRSeq: {rseq}\r\n"));
        }
        push_body(&mut raw, body);
        parse(&raw)
    }

    /// The callee answers siphon's `prack` with `status_code` and `body`, through
    /// the dispatcher's response entry point.
    fn callee_answers_prack(&self, prack: &SipMessage, status_code: u16, body: &str) {
        self.callee_answers_request(prack, status_code, body, &[]);
    }

    /// The callee answers siphon's `request`, a PRACK or an UPDATE, with
    /// `status_code`, `body` and `extra_headers`, through the dispatcher's
    /// response entry point.
    fn callee_answers_request(
        &self,
        request: &SipMessage,
        status_code: u16,
        body: &str,
        extra_headers: &[(&str, &str)],
    ) {
        let header = |name: &str| {
            request
                .headers
                .get(name)
                .cloned()
                .unwrap_or_else(|| panic!("siphon's request has no {name}"))
        };
        let mut raw = format!("SIP/2.0 {status_code} Reason\r\n");
        raw.push_str(&format!("Via: {}\r\n", header("Via")));
        raw.push_str(&format!("From: {}\r\n", header("From")));
        raw.push_str(&format!("To: {}\r\n", header("To")));
        raw.push_str(&format!("Call-ID: {}\r\n", header("Call-ID")));
        raw.push_str(&format!("CSeq: {}\r\n", header("CSeq")));
        for (name, value) in extra_headers {
            raw.push_str(&format!("{name}: {value}\r\n"));
        }
        push_body(&mut raw, body);
        let inbound = InboundMessage {
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: self.state.local_addr,
            remote_addr: address(CALLEE),
            data: Bytes::from(raw.clone().into_bytes()),
        };
        tokio::task::block_in_place(|| {
            super::response::handle_response(inbound, parse(&raw), status_code, &self.state)
        });
    }

    /// The caller PRACKs `provisional` as its request with CSeq `cseq`, `body` as
    /// SDP. Sent again with the same `cseq`, it is a retransmission.
    fn caller_pracks(&self, provisional: &SipMessage, cseq: u32, body: &str) {
        let rseq = provisional
            .headers
            .get("RSeq")
            .map(|value| value.trim().to_string())
            .expect("a reliable provisional");
        let mut raw = format!(
            concat!(
                "PRACK sip:192.0.2.1:5060 SIP/2.0\r\n",
                "Via: SIP/2.0/UDP 192.0.2.30:5060;branch=z9hG4bK-caller-prack-{cseq}\r\n",
                "Max-Forwards: 70\r\n",
                "From: <sip:15550100001@caller.example.com>;tag=caller-tag\r\n",
                "To: {to}\r\n",
                "Call-ID: {call_id}\r\n",
                "CSeq: {cseq} PRACK\r\n",
                "RAck: {rseq} 1 INVITE\r\n",
            ),
            cseq = cseq,
            to = provisional.headers.get("To").expect("a To"),
            call_id = SIP_CALL_ID,
            rseq = rseq,
        );
        push_body(&mut raw, body);
        let inbound = InboundMessage {
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: self.state.local_addr,
            remote_addr: address(CALLER),
            data: Bytes::from(raw.clone().into_bytes()),
        };
        tokio::task::block_in_place(|| {
            super::request::handle_request(inbound, parse(&raw), "PRACK".to_string(), &self.state)
        });
    }

    fn call_is_up(&self) -> bool {
        self.state.call_actors.get_call(&self.call_id).is_some()
    }
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

fn pracks(messages: &[SipMessage]) -> Vec<SipMessage> {
    messages
        .iter()
        .filter(|message| message.method() == Some(&Method::Prack))
        .cloned()
        .collect()
}

fn the_183(messages: &[SipMessage]) -> SipMessage {
    messages
        .iter()
        .find(|message| message.status_code() == Some(183))
        .cloned()
        .expect("a 183 to the caller")
}

/// The callee offers in a reliable 183 to an INVITE that carried none. siphon's
/// PRACK waits for the caller's, the callee's retransmissions of the 183 are
/// absorbed meanwhile, and the PRACK carries the caller's answer with siphon's
/// own identity and the configured attributes stripped.
#[tokio::test(flavor = "multi_thread")]
async fn the_prack_to_a_callee_that_offered_carries_the_callers_answer() {
    let mut dispatcher = test_dispatcher_with_script(DIAL);
    dispatcher.state.sdp_strip_attributes = vec!["x-hidden".to_string()];
    let call = PrackCall::place_on(dispatcher, None);

    call.callee_responds(183, "Session Progress", Some(42), CALLEE_OFFER);
    let sent = call.wire();
    let progress = the_183(&to(&sent, CALLER));
    assert!(
        body_text(&progress).contains("m=audio"),
        "the caller gets the offer"
    );
    assert_eq!(
        pracks(&to(&sent, CALLEE)).len(),
        0,
        "{:?}",
        summaries(&sent)
    );

    call.callee_responds(183, "Session Progress", Some(42), CALLEE_OFFER);
    assert_eq!(
        summaries(&call.wire()),
        Vec::<String>::new(),
        "the retransmission is absorbed"
    );

    call.caller_pracks(&progress, 2, CALLER_ANSWER);
    let sent = call.wire();
    let to_caller = to(&sent, CALLER);
    assert!(
        to_caller
            .iter()
            .any(|message| message.status_code() == Some(200) && cseq_method(message) == "PRACK"),
        "{:?}",
        summaries(&sent)
    );
    let prack = pracks(&to(&sent, CALLEE));
    assert_eq!(prack.len(), 1, "{:?}", summaries(&sent));
    assert_eq!(
        prack[0].headers.get("RAck").map(String::as_str),
        Some("42 1 INVITE")
    );
    let answer = body_text(&prack[0]);
    assert!(answer.contains("m=audio 40000 RTP/AVP 0"), "{answer}");
    assert!(!answer.contains("o=caller"), "siphon's origin:\n{answer}");
    assert!(!answer.contains("x-hidden"), "stripped:\n{answer}");
    assert_eq!(
        prack[0].headers.get("Content-Type").map(String::as_str),
        Some("application/sdp")
    );
}

/// On an anchored call the callee's early offer went to the media engine, and the
/// caller's answer in its PRACK goes there as the `answer` that completes it: the
/// callee's PRACK carries the engine's SDP, never the caller's address.
#[tokio::test(flavor = "multi_thread")]
async fn an_anchored_early_offer_is_answered_through_the_media_engine() {
    let engine = TestEngine::start(false).await;
    let call = PrackCall::place_anchored(&engine).await;
    call.callee_responds(183, "Session Progress", Some(42), CALLEE_OFFER);
    let progress = the_183(&to(&call.wire(), CALLER));

    call.caller_pracks(&progress, 2, CALLER_ANSWER);
    let sent = call.wire();
    let prack = pracks(&to(&sent, CALLEE));
    assert_eq!(prack.len(), 1, "{:?}", summaries(&sent));
    let answer = body_text(&prack[0]);
    assert!(answer.contains("c=IN IP4 203.0.113.50"), "{answer}");
    assert!(!answer.contains("192.0.2.30"), "{answer}");

    let answers = engine.commands("answer");
    assert_eq!(answers.len(), 1);
    assert_eq!(answers[0].from_tag.as_deref(), Some("callee-tag"));
    assert_eq!(answers[0].to_tag.as_deref(), Some("caller-tag"));
    assert_eq!(answers[0].sdp.as_deref(), Some(CALLER_ANSWER));
}

/// A caller that PRACKs the callee's offer without an answer breaks the exchange
/// (RFC 3262 §5). siphon still owes the callee a PRACK with a valid answer, every
/// stream rejected, and then cancels it; the caller's PRACK is answered and its
/// INVITE refused.
#[tokio::test(flavor = "multi_thread")]
async fn a_caller_that_does_not_answer_the_early_offer_ends_the_call() {
    let call = PrackCall::place(None);
    call.callee_responds(183, "Session Progress", Some(42), CALLEE_OFFER);
    let progress = the_183(&to(&call.wire(), CALLER));

    call.caller_pracks(&progress, 2, "");
    let sent = call.wire();
    let to_callee = to(&sent, CALLEE);
    let prack = pracks(&to_callee);
    assert_eq!(prack.len(), 1, "{:?}", summaries(&sent));
    assert!(
        body_text(&prack[0]).contains("m=audio 0 RTP/AVP 0"),
        "every stream rejected"
    );
    assert!(
        to_callee
            .iter()
            .any(|message| message.method() == Some(&Method::Cancel)),
        "{:?}",
        summaries(&sent)
    );
    let to_caller = to(&sent, CALLER);
    assert!(to_caller
        .iter()
        .any(|message| message.status_code() == Some(200)));
    assert!(to_caller
        .iter()
        .any(|message| message.status_code() == Some(488)));
    assert!(!call.call_is_up());
}

/// A PRACK without a body releases siphon's PRACK to the callee at once, without
/// one either, and the caller's 200 does not wait for the callee.
#[tokio::test(flavor = "multi_thread")]
async fn a_bodyless_caller_prack_releases_a_bodyless_prack_to_the_callee() {
    let call = PrackCall::place(Some(CALLER_OFFER));
    call.callee_responds(183, "Session Progress", Some(42), CALLEE_ANSWER);
    let sent = call.wire();
    assert_eq!(
        pracks(&to(&sent, CALLEE)).len(),
        0,
        "{:?}",
        summaries(&sent)
    );
    let progress = the_183(&to(&sent, CALLER));

    call.caller_pracks(&progress, 2, "");
    let sent = call.wire();
    let prack = pracks(&to(&sent, CALLEE));
    assert_eq!(prack.len(), 1, "{:?}", summaries(&sent));
    assert!(prack[0].body.is_empty());
    assert!(to(&sent, CALLER)
        .iter()
        .any(|message| message.status_code() == Some(200) && cseq_method(message) == "PRACK"));
}

/// An offer in the caller's PRACK goes to the callee in siphon's PRACK, and the
/// callee's answer in the 200 to that PRACK comes back in the 200 to the caller's
/// (RFC 3262 §5). Until then the caller's PRACK is not answered, and its
/// retransmission is absorbed.
#[tokio::test(flavor = "multi_thread")]
async fn an_offer_in_the_callers_prack_is_answered_by_the_callee_through_siphons_prack() {
    let call = PrackCall::place(Some(CALLER_OFFER));
    call.callee_responds(183, "Session Progress", Some(42), CALLEE_ANSWER);
    let progress = the_183(&to(&call.wire(), CALLER));

    call.caller_pracks(&progress, 2, CALLER_NEW_OFFER);
    let sent = call.wire();
    assert_eq!(to(&sent, CALLER).len(), 0, "{:?}", summaries(&sent));
    let prack = pracks(&to(&sent, CALLEE));
    assert_eq!(prack.len(), 1, "{:?}", summaries(&sent));
    let offer = body_text(&prack[0]);
    assert!(offer.contains("m=audio 40002 RTP/AVP 0"), "{offer}");
    assert!(!offer.contains("o=caller"), "{offer}");

    call.caller_pracks(&progress, 2, CALLER_NEW_OFFER);
    assert_eq!(
        summaries(&call.wire()),
        Vec::<String>::new(),
        "the retransmission is absorbed"
    );

    call.callee_answers_prack(&prack[0], 200, CALLEE_NEW_ANSWER);
    let sent = call.wire();
    let to_caller = to(&sent, CALLER);
    assert_eq!(to_caller.len(), 1, "{:?}", summaries(&sent));
    assert_eq!(to_caller[0].status_code(), Some(200));
    assert_eq!(cseq_method(&to_caller[0]), "PRACK");
    let answer = body_text(&to_caller[0]);
    assert!(answer.contains("m=audio 30002 RTP/AVP 0"), "{answer}");
    assert!(!answer.contains("o=callee"), "{answer}");
    assert!(call.call_is_up());
}

/// A callee that refuses the offer siphon's PRACK carried leaves the caller's
/// offer unanswerable. The caller's PRACK is answered, every stream rejected, and
/// the call fails: the callee is cancelled and the caller's INVITE refused.
#[tokio::test(flavor = "multi_thread")]
async fn a_callee_that_refuses_the_offer_in_the_prack_fails_the_call() {
    let call = PrackCall::place(Some(CALLER_OFFER));
    call.callee_responds(183, "Session Progress", Some(42), CALLEE_ANSWER);
    let progress = the_183(&to(&call.wire(), CALLER));
    call.caller_pracks(&progress, 2, CALLER_NEW_OFFER);
    let prack = pracks(&to(&call.wire(), CALLEE));

    call.callee_answers_prack(&prack[0], 488, "");
    let sent = call.wire();
    let to_caller = to(&sent, CALLER);
    let prack_answer = to_caller
        .iter()
        .find(|message| cseq_method(message) == "PRACK")
        .expect("the caller's PRACK is answered");
    assert_eq!(prack_answer.status_code(), Some(200));
    assert!(body_text(prack_answer).contains("m=audio 0 RTP/AVP 0"));
    assert!(to_caller
        .iter()
        .any(|message| cseq_method(message) == "INVITE" && message.status_code() == Some(500)));
    assert!(to(&sent, CALLEE)
        .iter()
        .any(|message| message.method() == Some(&Method::Cancel)));
    assert!(!call.call_is_up());
}

/// A callee that never answers siphon's PRACK with the caller's offer fails the
/// call the same way, once 64*T1 has passed.
#[tokio::test(flavor = "multi_thread")]
async fn a_callee_that_never_answers_the_offer_in_the_prack_fails_the_call() {
    let call = PrackCall::place(Some(CALLER_OFFER));
    call.callee_responds(183, "Session Progress", Some(42), CALLEE_ANSWER);
    let progress = the_183(&to(&call.wire(), CALLER));
    call.caller_pracks(&progress, 2, CALLER_NEW_OFFER);
    call.wire();

    check_b2bua_prack_timeouts_at(&call.state, Instant::now() + Duration::from_secs(33));
    let sent = call.wire();
    let to_caller = to(&sent, CALLER);
    assert!(
        to_caller
            .iter()
            .any(|message| cseq_method(message) == "PRACK" && message.status_code() == Some(200)),
        "{:?}",
        summaries(&sent)
    );
    assert!(to_caller
        .iter()
        .any(|message| cseq_method(message) == "INVITE" && message.status_code() == Some(500)));
    assert!(to(&sent, CALLEE)
        .iter()
        .any(|message| message.method() == Some(&Method::Cancel)));
    assert!(!call.call_is_up());
}

/// That timeout is a teardown like any other: a call another teardown already has
/// is left to it.
#[tokio::test(flavor = "multi_thread")]
async fn the_prack_offer_timeout_leaves_a_call_another_teardown_has_claimed() {
    let call = PrackCall::place(Some(CALLER_OFFER));
    call.callee_responds(183, "Session Progress", Some(42), CALLEE_ANSWER);
    let progress = the_183(&to(&call.wire(), CALLER));
    call.caller_pracks(&progress, 2, CALLER_NEW_OFFER);
    call.wire();
    assert!(call.state.call_actors.claim_teardown(&call.call_id));

    check_b2bua_prack_timeouts_at(&call.state, Instant::now() + Duration::from_secs(33));
    assert_eq!(summaries(&call.wire()), Vec::<String>::new());
    assert!(call.call_is_up());
}

/// The 200 that carried the callee's answer is lost: the caller retransmits its
/// PRACK and gets that same 200 again, answer included, and nothing reaches the
/// callee a second time.
#[tokio::test(flavor = "multi_thread")]
async fn a_retransmitted_prack_gets_the_200_that_carried_the_callees_answer() {
    let call = PrackCall::place(Some(CALLER_OFFER));
    call.callee_responds(183, "Session Progress", Some(42), CALLEE_ANSWER);
    let progress = the_183(&to(&call.wire(), CALLER));
    call.caller_pracks(&progress, 2, CALLER_NEW_OFFER);
    let prack = pracks(&to(&call.wire(), CALLEE));
    assert_eq!(prack.len(), 1);
    call.callee_answers_prack(&prack[0], 200, CALLEE_NEW_ANSWER);
    let first = to(&call.wire(), CALLER);
    assert_eq!(first.len(), 1);

    call.caller_pracks(&progress, 2, CALLER_NEW_OFFER);
    let sent = call.wire();
    let again = to(&sent, CALLER);
    assert_eq!(again.len(), 1, "{:?}", summaries(&sent));
    assert_eq!(again[0].status_code(), Some(200));
    assert_eq!(body_text(&again[0]), body_text(&first[0]));
    assert!(to(&sent, CALLEE).is_empty(), "{:?}", summaries(&sent));
}

/// RFC 3262 §4: once a reliable provisional is received, its retransmissions are
/// discarded, after siphon's PRACK for it went out as much as before.
#[tokio::test(flavor = "multi_thread")]
async fn retransmissions_of_a_pracked_provisional_are_discarded() {
    let call = PrackCall::place(Some(CALLER_OFFER));
    call.callee_responds(183, "Session Progress", Some(42), CALLEE_ANSWER);
    let progress = the_183(&to(&call.wire(), CALLER));
    call.caller_pracks(&progress, 2, "");
    assert_eq!(pracks(&to(&call.wire(), CALLEE)).len(), 1);

    call.callee_responds(183, "Session Progress", Some(42), CALLEE_ANSWER);
    assert_eq!(summaries(&call.wire()), Vec::<String>::new());
}

/// A reliable provisional racing the callee's 2xx on another worker: its PRACK is
/// already held for the caller's when the 2xx marks the call answered, so the
/// provisional is dropped instead of relayed and the caller never PRACKs it.
/// siphon's PRACK for it still goes to the callee (RFC 3262 §4).
#[tokio::test(flavor = "multi_thread")]
async fn a_provisional_the_answer_overtook_still_gets_its_prack() {
    let call = PrackCall::place(Some(CALLER_OFFER));
    let branch = top_via_branch(&call.callee_invite);
    let mut response = call.callee_response(183, "Session Progress", Some(42), "");
    let snapshot =
        b_leg_response_snapshot(&call.call_id, &branch, &call.state).expect("the callee's leg");
    let discarded = tokio::task::block_in_place(|| {
        auto_prack_b_leg(&call.call_id, &mut response, 183, &call.state, &snapshot)
    });
    assert!(!discarded);
    let sent = call.wire();
    assert!(
        pracks(&to(&sent, CALLEE)).is_empty(),
        "held for the caller's PRACK: {:?}",
        summaries(&sent)
    );

    call.state
        .call_actors
        .get_call_mut(&call.call_id)
        .expect("the call")
        .state = crate::b2bua::actor::CallState::Answered;
    tokio::task::block_in_place(|| {
        b_leg_provisional(
            &call.call_id,
            &branch,
            &mut response,
            183,
            address(CALLEE),
            &call.state,
            &snapshot,
        )
    });
    let sent = call.wire();
    assert!(to(&sent, CALLER).is_empty(), "{:?}", summaries(&sent));
    let prack = pracks(&to(&sent, CALLEE));
    assert_eq!(prack.len(), 1, "{:?}", summaries(&sent));
    assert_eq!(
        prack[0].headers.get("RAck").map(String::as_str),
        Some("42 1 INVITE")
    );
}

/// The callee's 2xx that arrives while the caller's PRACK offer is still with the
/// callee waits: the caller gets the 200 carrying the answer to its PRACK first,
/// then the 2xx, so no final response lands on an offer it has no answer to.
#[tokio::test(flavor = "multi_thread")]
async fn the_callees_2xx_follows_the_200_that_answers_the_callers_prack_offer() {
    let call = PrackCall::place(Some(CALLER_OFFER));
    call.callee_responds(183, "Session Progress", Some(42), CALLEE_ANSWER);
    let progress = the_183(&to(&call.wire(), CALLER));
    call.caller_pracks(&progress, 2, CALLER_NEW_OFFER);
    let prack = pracks(&to(&call.wire(), CALLEE));
    assert_eq!(prack.len(), 1);

    call.callee_responds(200, "OK", None, "");
    let sent = call.wire();
    assert!(
        to(&sent, CALLER)
            .iter()
            .all(|message| cseq_method(message) != "INVITE"),
        "the 2xx waits: {:?}",
        summaries(&sent)
    );

    call.callee_answers_prack(&prack[0], 200, CALLEE_NEW_ANSWER);
    let sent = call.wire();
    let to_caller: Vec<(Option<u16>, String)> = to(&sent, CALLER)
        .iter()
        .map(|message| (message.status_code(), cseq_method(message)))
        .collect();
    assert_eq!(
        to_caller,
        [
            (Some(200), "PRACK".to_string()),
            (Some(200), "INVITE".to_string())
        ],
        "{:?}",
        summaries(&sent)
    );
}

/// A callee may send its 2xx before the PRACK of a reliable provisional without
/// SDP (RFC 3262 §3), and the caller's 2xx then goes out without waiting either.
/// siphon's copy of that provisional stops being retransmitted, so the caller may
/// never PRACK it, but siphon still owes the callee its PRACK (§4): the PRACK held
/// for the caller's goes to the callee with the caller's 2xx, and a late PRACK
/// from the caller is answered without sending the callee a second one.
#[tokio::test(flavor = "multi_thread")]
async fn a_prack_still_held_goes_to_the_callee_with_the_callers_2xx() {
    let call = PrackCall::place(Some(CALLER_OFFER));
    call.callee_responds(180, "Ringing", Some(42), "");
    let sent = call.wire();
    let ringing = to(&sent, CALLER)
        .into_iter()
        .find(|message| message.status_code() == Some(180))
        .expect("a 180 to the caller");
    assert!(
        ringing.headers.get("RSeq").is_some(),
        "the callee's reliable 180 reaches a caller that supports 100rel reliably"
    );
    assert!(
        pracks(&to(&sent, CALLEE)).is_empty(),
        "{:?}",
        summaries(&sent)
    );

    call.callee_responds(200, "OK", None, CALLEE_ANSWER);
    let sent = call.wire();
    assert!(
        to(&sent, CALLER)
            .iter()
            .any(|message| message.status_code() == Some(200) && cseq_method(message) == "INVITE"),
        "the 2xx does not wait for the PRACK of a provisional without SDP: {:?}",
        summaries(&sent)
    );
    let prack = pracks(&to(&sent, CALLEE));
    assert_eq!(prack.len(), 1, "{:?}", summaries(&sent));
    assert_eq!(
        prack[0].headers.get("RAck").map(String::as_str),
        Some("42 1 INVITE")
    );
    assert!(prack[0].body.is_empty());

    call.caller_pracks(&ringing, 2, "");
    let sent = call.wire();
    assert!(
        to(&sent, CALLER)
            .iter()
            .any(|message| message.status_code() == Some(200) && cseq_method(message) == "PRACK"),
        "{:?}",
        summaries(&sent)
    );
    assert!(
        pracks(&to(&sent, CALLEE)).is_empty(),
        "{:?}",
        summaries(&sent)
    );
}

/// On an anchored call the caller's offer in its PRACK goes to the media engine as
/// a re-offer from the caller's side, siphon's PRACK carries the engine's SDP, and
/// the callee's answer goes to the engine as the `answer` completing it before the
/// 200 to the caller's PRACK carries the engine's SDP back. Neither party's address
/// crosses.
#[tokio::test(flavor = "multi_thread")]
async fn an_anchored_offer_in_the_callers_prack_crosses_the_media_engine_both_ways() {
    let engine = TestEngine::start(false).await;
    let call = PrackCall::place_anchored_with(
        &engine,
        Some(CALLER_OFFER),
        "caller-tag",
        Some("callee-tag"),
    )
    .await;
    call.callee_responds(183, "Session Progress", Some(42), CALLEE_ANSWER);
    let progress = the_183(&to(&call.wire(), CALLER));

    call.caller_pracks(&progress, 2, CALLER_NEW_OFFER);
    let sent = call.wire();
    let prack = pracks(&to(&sent, CALLEE));
    assert_eq!(prack.len(), 1, "{:?}", summaries(&sent));
    let offer = body_text(&prack[0]);
    assert!(offer.contains("c=IN IP4 203.0.113.50"), "{offer}");
    assert!(!offer.contains("192.0.2.30"), "{offer}");
    let offers = engine.commands("offer");
    assert_eq!(offers.len(), 1);
    assert_eq!(offers[0].from_tag.as_deref(), Some("caller-tag"));
    assert_eq!(offers[0].sdp.as_deref(), Some(CALLER_NEW_OFFER));

    call.callee_answers_prack(&prack[0], 200, CALLEE_NEW_ANSWER);
    let sent = call.wire();
    let to_caller = to(&sent, CALLER);
    assert_eq!(to_caller.len(), 1, "{:?}", summaries(&sent));
    assert_eq!(cseq_method(&to_caller[0]), "PRACK");
    let answer = body_text(&to_caller[0]);
    assert!(answer.contains("c=IN IP4 203.0.113.50"), "{answer}");
    assert!(!answer.contains("198.51.100.71"), "{answer}");
    let answers = engine.commands("answer");
    assert_eq!(answers.len(), 1);
    assert_eq!(answers[0].from_tag.as_deref(), Some("caller-tag"));
    assert_eq!(answers[0].to_tag.as_deref(), Some("callee-tag"));
    assert_eq!(answers[0].sdp.as_deref(), Some(CALLEE_NEW_ANSWER));
}

/// The session descriptions siphon has in force on each dialog, and the callee's
/// own last SDP, as a session refresh and a siphon-terminated transfer read them.
struct SessionsInForce {
    caller_session: Option<Vec<u8>>,
    callee_session: Option<Vec<u8>>,
    callee_sdp: Option<Vec<u8>>,
}

fn sessions_in_force(call: &PrackCall) -> SessionsInForce {
    call.state
        .call_actors
        .get_call(&call.call_id)
        .map(|actor| {
            let callee = actor.b_legs.first();
            SessionsInForce {
                caller_session: actor.a_leg.dialog.last_sent_sdp.clone(),
                callee_session: callee.and_then(|leg| leg.dialog.last_sent_sdp.clone()),
                callee_sdp: callee.and_then(|leg| leg.last_sdp.clone()),
            }
        })
        .expect("the call")
}

/// The callee offered in its reliable 183 to an INVITE siphon sent without SDP,
/// and the caller answered in its PRACK. The answer siphon's PRACK carried is the
/// session description in force on the callee's dialog, so once the call is up a
/// session refresh offers it again, unchanged (RFC 4028 §7.4, RFC 3264 §8), and
/// the callee's offer is its own last SDP.
#[tokio::test(flavor = "multi_thread")]
async fn a_session_refresh_after_an_early_offer_answered_in_prack_offers_that_answer() {
    let call = PrackCall::place(None);
    call.callee_responds(183, "Session Progress", Some(42), CALLEE_OFFER);
    let progress = the_183(&to(&call.wire(), CALLER));
    call.caller_pracks(&progress, 2, CALLER_ANSWER);
    let prack = pracks(&to(&call.wire(), CALLEE));
    assert_eq!(prack.len(), 1);
    call.callee_responds(200, "OK", None, "");
    call.wire();

    let sessions = sessions_in_force(&call);
    assert_eq!(sessions.callee_session, Some(prack[0].body.clone()));
    assert_eq!(sessions.callee_sdp, Some(CALLEE_OFFER.as_bytes().to_vec()));

    // The callee's 2xx named siphon the refresher of the callee's dialog.
    call.state.call_actors.set_leg_session_timer(
        &call.call_id,
        false,
        Some(crate::b2bua::actor::SessionTimerState::new(
            1800,
            true,
            90,
            Instant::now(),
        )),
    );
    b2bua_send_session_refresh(&call.call_id, false, &call.state);
    let sent = call.wire();
    let refresh: Vec<SipMessage> = to(&sent, CALLEE)
        .into_iter()
        .filter(|message| message.method() == Some(&Method::Invite))
        .collect();
    assert_eq!(refresh.len(), 1, "{:?}", summaries(&sent));
    assert_eq!(body_text(&refresh[0]), body_text(&prack[0]));
}

/// An offer in the caller's PRACK is in force on the callee's dialog once the
/// callee answers it, and the answer siphon returns in the 200 to the caller's
/// PRACK is in force on the caller's: the rule an UPDATE's offer and answer
/// follow. Until the callee answers, the INVITE's offer stays in force there.
#[tokio::test(flavor = "multi_thread")]
async fn an_offer_in_the_callers_prack_is_in_force_on_both_dialogs_once_the_callee_answers() {
    let call = PrackCall::place(Some(CALLER_OFFER));
    call.callee_responds(183, "Session Progress", Some(42), CALLEE_ANSWER);
    let progress = the_183(&to(&call.wire(), CALLER));
    call.caller_pracks(&progress, 2, CALLER_NEW_OFFER);
    let prack = pracks(&to(&call.wire(), CALLEE));
    assert_eq!(prack.len(), 1);
    assert_eq!(
        sessions_in_force(&call).callee_session,
        Some(call.callee_invite.body.clone()),
        "the INVITE's offer, until the callee answers"
    );

    call.callee_answers_prack(&prack[0], 200, CALLEE_NEW_ANSWER);
    let to_caller = to(&call.wire(), CALLER);
    assert_eq!(to_caller.len(), 1);
    let sessions = sessions_in_force(&call);
    assert_eq!(sessions.callee_session, Some(prack[0].body.clone()));
    assert_eq!(sessions.caller_session, Some(to_caller[0].body.clone()));
    assert_eq!(
        sessions.callee_sdp,
        Some(CALLEE_NEW_ANSWER.as_bytes().to_vec())
    );
}

/// A call placed with `offer` on a dispatcher whose UDP egress is split by
/// direction. What siphon sends the caller leaves from the listener the caller's
/// INVITE arrived on and stays on [`PrackCall::udp`]. What it sends the callee
/// names no listener and goes to the returned channel, which has no room: a send
/// to the callee does not return until the test takes it, so the test decides
/// what happens while siphon is still handing a request to the callee.
fn place_with_callee_rendezvous(
    offer: Option<&str>,
) -> (PrackCall, flume::Receiver<OutboundMessage>) {
    place_with_split_egress(offer, Some(0))
}

/// [`place_with_callee_rendezvous`] with room for `callee_capacity` messages to
/// the callee, `None` for as many as siphon sends.
fn place_with_split_egress(
    offer: Option<&str>,
    callee_capacity: Option<usize>,
) -> (PrackCall, flume::Receiver<OutboundMessage>) {
    let TestDispatcher { mut state, udp } = test_dispatcher_with_script(DIAL);
    drop(udp);
    let (to_callee, callee) = match callee_capacity {
        Some(capacity) => flume::bounded(capacity),
        None => flume::unbounded(),
    };
    let (to_caller, caller) = flume::unbounded();
    let (to_stream, _) = flume::unbounded();
    state.outbound = Arc::new(OutboundRouter {
        udp: to_callee.into(),
        udp_by_local: std::collections::HashMap::from([(state.local_addr, to_caller.into())]),
        tcp: to_stream.clone(),
        tls: to_stream.clone(),
        ws: to_stream.clone(),
        wss: to_stream.clone(),
        sctp: to_stream,
    });
    let state = Arc::new(state);
    let raw = caller_invite(offer);
    let inbound = InboundMessage {
        connection_id: ConnectionId::default(),
        transport: Transport::Udp,
        local_addr: state.local_addr,
        remote_addr: address(CALLER),
        data: Bytes::from(raw.clone().into_bytes()),
    };
    let runtime = tokio::runtime::Handle::current();
    let callee_invite = std::thread::scope(|scope| {
        let dialling = scope.spawn(|| {
            let _runtime = runtime.enter();
            handle_b2bua_invite(inbound, parse(&raw), &state);
        });
        let invite = receive_from(&callee);
        dialling.join().expect("the INVITE handler");
        invite
    });
    assert_eq!(callee_invite.method(), Some(&Method::Invite));
    let call_id = state
        .call_actors
        .find_by_sip_call_id(SIP_CALL_ID)
        .expect("the call was placed");
    let call = PrackCall {
        state,
        udp: caller,
        call_id,
        callee_invite,
        callee_allow: Some(CALLEE_ALLOW.to_string()),
    };
    (call, callee)
}

/// The next message siphon hands the transport on `channel`, waiting for it.
fn receive_from(channel: &flume::Receiver<OutboundMessage>) -> SipMessage {
    let outbound = channel
        .recv_timeout(Duration::from_secs(5))
        .expect("siphon sent a message");
    let frame = outbound.frames().next().expect("a frame");
    parse_sip_message_bytes(frame).expect("siphon sent a message that parses")
}

/// siphon's PRACK to the callee as its retransmission schedule holds it, once armed:
/// armed right before the PRACK is handed to the transport, so from then on the
/// PRACK is on its way and nothing before the send is still to run.
fn armed_prack(call: &PrackCall, armed_before: usize) -> SipMessage {
    let deadline = Instant::now() + Duration::from_secs(5);
    while call.state.b2bua_retransmits.len() <= armed_before {
        assert!(Instant::now() < deadline, "siphon never armed its PRACK");
        std::thread::sleep(Duration::from_millis(1));
    }
    call.state
        .b2bua_retransmits
        .due(Instant::now() + Duration::from_secs(1))
        .into_iter()
        .find_map(|due| match due {
            crate::b2bua::retransmit::Due::Send { key, data, .. }
                if key.method == Method::Prack =>
            {
                Some(parse_sip_message_bytes(&data).expect("the armed PRACK parses"))
            }
            _ => None,
        })
        .expect("the armed PRACK")
}

/// The callee answers the offer siphon's PRACK carries the moment the PRACK
/// reaches it, before siphon's thread has returned from handing the PRACK over.
/// The offer is registered before the PRACK goes out, so that answer finds it,
/// and the caller's PRACK gets its 200 with the answer (RFC 3262 §5). Registered
/// after the send, the answer found nothing, was absorbed, and the caller's PRACK
/// was never answered.
#[tokio::test(flavor = "multi_thread")]
async fn a_callee_answer_to_the_prack_offer_that_arrives_during_the_send_reaches_the_caller() {
    let (call, callee) = place_with_callee_rendezvous(Some(CALLER_OFFER));
    call.callee_responds(183, "Session Progress", Some(42), CALLEE_ANSWER);
    let progress = the_183(&to(&call.wire(), CALLER));
    let armed_before = call.state.b2bua_retransmits.len();

    let runtime = &tokio::runtime::Handle::current();
    let call = &call;
    std::thread::scope(|scope| {
        let pracking = scope.spawn(|| {
            let _runtime = runtime.enter();
            call.caller_pracks(&progress, 2, CALLER_NEW_OFFER);
        });
        // siphon's thread is now handing its PRACK to the callee, and cannot get
        // past that until the test takes it.
        let prack = armed_prack(call, armed_before);
        assert!(
            body_text(&prack).contains("m=audio 40002"),
            "{}",
            body_text(&prack)
        );
        scope
            .spawn(move || {
                let _runtime = runtime.enter();
                call.callee_answers_prack(&prack, 200, CALLEE_NEW_ANSWER);
            })
            .join()
            .expect("the callee's answer");
        assert_eq!(receive_from(&callee).method(), Some(&Method::Prack));
        pracking.join().expect("the caller's PRACK");
    });

    let to_caller = to(&call.wire(), CALLER);
    let answer = to_caller
        .iter()
        .find(|message| message.status_code() == Some(200) && cseq_method(message) == "PRACK")
        .unwrap_or_else(|| panic!("the caller's PRACK was never answered: {to_caller:?}"));
    assert!(
        body_text(answer).contains("m=audio 30002"),
        "{}",
        body_text(answer)
    );
    assert!(call.call_is_up());
}

/// siphon's PRACK carrying the caller's offer cannot be handed to the transport.
/// Nothing reaches the callee, so nothing will answer the offer: it is not left
/// registered, and the caller's PRACK is answered at once with every stream
/// rejected, the call refused as when the callee refuses the offer.
#[tokio::test(flavor = "multi_thread")]
async fn a_prack_offer_that_cannot_be_sent_is_not_left_waiting_for_an_answer() {
    let (call, callee) = place_with_callee_rendezvous(Some(CALLER_OFFER));
    call.callee_responds(183, "Session Progress", Some(42), CALLEE_ANSWER);
    let progress = the_183(&to(&call.wire(), CALLER));
    drop(callee);

    call.caller_pracks(&progress, 2, CALLER_NEW_OFFER);

    let pending = call
        .state
        .call_actors
        .get_call(&call.call_id)
        .is_some_and(|actor| actor.prack_bridge.offer_pending());
    assert!(
        !pending,
        "an offer nobody was sent is still waiting for its answer"
    );
    let to_caller = to(&call.wire(), CALLER);
    let answer = to_caller
        .iter()
        .find(|message| message.status_code() == Some(200) && cseq_method(message) == "PRACK")
        .unwrap_or_else(|| panic!("the caller's PRACK was never answered: {to_caller:?}"));
    assert!(
        body_text(answer).contains("m=audio 0 "),
        "{}",
        body_text(answer)
    );
    assert!(
        to_caller
            .iter()
            .any(|message| message.status_code() == Some(500) && cseq_method(message) == "INVITE"),
        "{to_caller:?}"
    );
}

/// The answer siphon sends the caller in a reliable 18x is the session
/// description in force on the caller's dialog as it goes, as an answer in a 2xx
/// is (RFC 3262 §5).
#[tokio::test(flavor = "multi_thread")]
async fn an_answer_in_a_reliable_18x_is_in_force_on_the_callers_dialog() {
    let call = PrackCall::place(Some(CALLER_OFFER));
    assert_eq!(sessions_in_force(&call).caller_session, None);
    call.callee_responds(183, "Session Progress", Some(42), CALLEE_ANSWER);
    let progress = the_183(&to(&call.wire(), CALLER));
    assert!(progress.headers.get("RSeq").is_some(), "sent reliably");
    assert_eq!(
        sessions_in_force(&call).caller_session,
        Some(progress.body.clone())
    );
}

/// An offer siphon sends the caller in a reliable 18x, to an INVITE without SDP,
/// is in force on the caller's dialog once the caller's PRACK answers it, and not
/// before.
#[tokio::test(flavor = "multi_thread")]
async fn an_early_offer_in_a_reliable_18x_is_in_force_on_the_callers_dialog_once_answered() {
    let call = PrackCall::place(None);
    call.callee_responds(183, "Session Progress", Some(42), CALLEE_OFFER);
    let progress = the_183(&to(&call.wire(), CALLER));
    assert_eq!(sessions_in_force(&call).caller_session, None);

    call.caller_pracks(&progress, 2, CALLER_ANSWER);
    call.wire();
    assert_eq!(
        sessions_in_force(&call).caller_session,
        Some(progress.body.clone())
    );
}

fn updates(messages: &[SipMessage]) -> Vec<SipMessage> {
    messages
        .iter()
        .filter(|message| message.method() == Some(&Method::Update))
        .cloned()
        .collect()
}

/// The one response to the caller's PRACK among `messages`.
fn prack_response(messages: &[SipMessage]) -> SipMessage {
    let responses: Vec<&SipMessage> = messages
        .iter()
        .filter(|message| message.status_code().is_some() && cseq_method(message) == "PRACK")
        .collect();
    assert_eq!(responses.len(), 1, "one response to the PRACK");
    responses[0].clone()
}

impl PrackCall {
    /// Whether a teardown has taken the call, or it is gone.
    fn is_ending(&self) -> bool {
        self.state
            .call_actors
            .get_call(&self.call_id)
            .map_or(true, |actor| actor.teardown_claimed)
    }
}

/// A caller that supports `100rel` whose callee, listing `allow`, sends a reliable
/// 180 without SDP and answers the INVITE's offer at once. The caller has its 2xx
/// without having PRACKed the 180, and siphon's PRACK went to the callee with that
/// 2xx. Returns the call and the caller's copy of the 180.
fn answered_before_the_callers_prack(allow: Option<&str>) -> (PrackCall, SipMessage) {
    let mut call = PrackCall::place(Some(CALLER_OFFER));
    call.callee_allow = allow.map(str::to_string);
    call.callee_responds(180, "Ringing", Some(42), "");
    let ringing = to(&call.wire(), CALLER)
        .into_iter()
        .find(|message| message.status_code() == Some(180))
        .expect("a 180 to the caller");
    assert!(ringing.headers.get("RSeq").is_some(), "sent reliably");

    call.callee_responds(200, "OK", None, CALLEE_ANSWER);
    let sent = call.wire();
    assert!(
        to(&sent, CALLER)
            .iter()
            .any(|message| message.status_code() == Some(200) && cseq_method(message) == "INVITE"),
        "{:?}",
        summaries(&sent)
    );
    assert_eq!(
        pracks(&to(&sent, CALLEE)).len(),
        1,
        "{:?}",
        summaries(&sent)
    );
    (call, ringing)
}

/// An offer in a PRACK that arrives once the caller has its 2xx, when siphon's
/// PRACK already went to the callee, goes to the callee in an UPDATE on its dialog
/// (RFC 3311). The callee's answer comes back in the 200 to the caller's PRACK
/// (RFC 3262 §5), and both are the session in force on their dialogs. The caller's
/// PRACK is not answered before, and a retransmission of it gets that 200 again.
#[tokio::test(flavor = "multi_thread")]
async fn a_late_offer_in_the_callers_prack_reaches_the_callee_in_an_update() {
    let (call, ringing) = answered_before_the_callers_prack(Some(CALLEE_ALLOW));

    call.caller_pracks(&ringing, 2, CALLER_NEW_OFFER);
    let sent = call.wire();
    assert!(to(&sent, CALLER).is_empty(), "{:?}", summaries(&sent));
    let update = updates(&to(&sent, CALLEE));
    assert_eq!(update.len(), 1, "{:?}", summaries(&sent));
    let offer = body_text(&update[0]);
    assert!(offer.contains("m=audio 40002 RTP/AVP 0"), "{offer}");
    assert!(!offer.contains("o=caller"), "siphon's origin:\n{offer}");
    assert!(
        update[0].headers.get("Contact").is_some(),
        "a target refresh"
    );
    assert_eq!(
        update[0].headers.get("Content-Type").map(String::as_str),
        Some("application/sdp")
    );

    call.caller_pracks(&ringing, 2, CALLER_NEW_OFFER);
    assert_eq!(
        summaries(&call.wire()),
        Vec::<String>::new(),
        "absorbed while the UPDATE is out"
    );

    call.callee_answers_prack(&update[0], 200, CALLEE_NEW_ANSWER);
    let sent = call.wire();
    let answer = prack_response(&to(&sent, CALLER));
    assert_eq!(answer.status_code(), Some(200));
    let answer_sdp = body_text(&answer);
    assert!(
        answer_sdp.contains("m=audio 30002 RTP/AVP 0"),
        "{answer_sdp}"
    );
    assert!(!answer_sdp.contains("o=callee"), "{answer_sdp}");
    assert!(call.call_is_up());

    let sessions = sessions_in_force(&call);
    assert_eq!(sessions.callee_session, Some(update[0].body.clone()));
    assert_eq!(sessions.caller_session, Some(answer.body.clone()));
    assert_eq!(
        sessions.callee_sdp,
        Some(CALLEE_NEW_ANSWER.as_bytes().to_vec())
    );

    call.caller_pracks(&ringing, 2, CALLER_NEW_OFFER);
    let sent = call.wire();
    let again = prack_response(&to(&sent, CALLER));
    assert_eq!(body_text(&again), answer_sdp);
    assert!(to(&sent, CALLEE).is_empty(), "{:?}", summaries(&sent));
}

/// A callee that refuses the UPDATE leaves the session as it was (RFC 3311 §5.3),
/// so the caller's offer is refused the same way and the call carries on:
/// 488 and 606 refuse the offer itself (488), 491 is glare and 504 an answer
/// that needs the user, both passed on as they are, and anything else is a failure
/// that is not the offer's (500).
#[tokio::test(flavor = "multi_thread")]
async fn a_callee_that_refuses_the_update_refuses_the_late_offer_and_keeps_the_call() {
    for (callee_status, caller_status) in [
        (488, 488),
        (606, 488),
        (491, 491),
        (504, 504),
        (403, 500),
        (503, 500),
    ] {
        let (call, ringing) = answered_before_the_callers_prack(Some(CALLEE_ALLOW));
        let before = sessions_in_force(&call);
        call.caller_pracks(&ringing, 2, CALLER_NEW_OFFER);
        let update = updates(&to(&call.wire(), CALLEE));
        assert_eq!(update.len(), 1, "callee {callee_status}");

        call.callee_answers_prack(&update[0], callee_status, "");
        let sent = call.wire();
        let refusal = prack_response(&to(&sent, CALLER));
        assert_eq!(
            refusal.status_code(),
            Some(caller_status),
            "callee {callee_status}"
        );
        assert!(refusal.body.is_empty(), "callee {callee_status}");
        assert!(
            to(&sent, CALLEE)
                .iter()
                .all(|message| message.method() != Some(&Method::Bye)),
            "callee {callee_status}: {:?}",
            summaries(&sent)
        );
        assert!(!call.is_ending(), "callee {callee_status}");
        let after = sessions_in_force(&call);
        assert_eq!(after.caller_session, before.caller_session);
        assert_eq!(after.callee_session, before.callee_session);
    }
}

/// A callee with an offer of its own unanswered refuses the UPDATE 500 with a
/// Retry-After (RFC 3311 §5.2), and the caller gets both, so it can offer again.
#[tokio::test(flavor = "multi_thread")]
async fn a_500_with_retry_after_for_the_update_reaches_the_caller_with_it() {
    let (call, ringing) = answered_before_the_callers_prack(Some(CALLEE_ALLOW));
    call.caller_pracks(&ringing, 2, CALLER_NEW_OFFER);
    let update = updates(&to(&call.wire(), CALLEE));
    call.callee_answers_request(&update[0], 500, "", &[("Retry-After", "4")]);
    let refusal = prack_response(&to(&call.wire(), CALLER));
    assert_eq!(refusal.status_code(), Some(500));
    assert_eq!(
        refusal.headers.get("Retry-After").map(String::as_str),
        Some("4")
    );
    assert!(!call.is_ending());
}

/// A 481 or a 408 for the UPDATE means the callee's dialog is gone, and RFC 3311
/// §5.3 has the UAC terminate it: the caller's PRACK is refused 500 and the call
/// ends, the callee getting a BYE.
#[tokio::test(flavor = "multi_thread")]
async fn a_callee_dialog_that_is_gone_ends_the_call_on_the_late_offer() {
    for callee_status in [481, 408] {
        let (call, ringing) = answered_before_the_callers_prack(Some(CALLEE_ALLOW));
        call.caller_pracks(&ringing, 2, CALLER_NEW_OFFER);
        let update = updates(&to(&call.wire(), CALLEE));
        call.callee_answers_prack(&update[0], callee_status, "");
        let sent = call.wire();
        assert_eq!(
            prack_response(&to(&sent, CALLER)).status_code(),
            Some(500),
            "callee {callee_status}"
        );
        assert!(
            to(&sent, CALLEE)
                .iter()
                .any(|message| message.method() == Some(&Method::Bye)),
            "callee {callee_status}: {:?}",
            summaries(&sent)
        );
        assert!(call.is_ending(), "callee {callee_status}");
    }
}

/// No response to the UPDATE in 64*T1 ends the call the same way (RFC 3311 §5.3).
#[tokio::test(flavor = "multi_thread")]
async fn an_update_the_callee_never_answers_ends_the_call() {
    let (call, ringing) = answered_before_the_callers_prack(Some(CALLEE_ALLOW));
    call.caller_pracks(&ringing, 2, CALLER_NEW_OFFER);
    assert_eq!(updates(&to(&call.wire(), CALLEE)).len(), 1);

    check_b2bua_prack_timeouts_at(&call.state, Instant::now() + Duration::from_secs(33));
    let sent = call.wire();
    assert_eq!(prack_response(&to(&sent, CALLER)).status_code(), Some(500));
    assert!(
        to(&sent, CALLEE)
            .iter()
            .any(|message| message.method() == Some(&Method::Bye)),
        "{:?}",
        summaries(&sent)
    );
    assert!(call.is_ending());
}

/// A callee that did not list UPDATE in Allow is sent none (RFC 3311 §4), and a
/// re-INVITE would let it wait for its user (§5.1), which the PRACK cannot: the caller's
/// offer is refused 488, the session stays, and the caller may offer again on its
/// own dialog. The same without any Allow.
#[tokio::test(flavor = "multi_thread")]
async fn a_late_offer_to_a_callee_without_update_is_refused_488() {
    for allow in [Some("INVITE, ACK, CANCEL, BYE, PRACK"), None] {
        let (call, ringing) = answered_before_the_callers_prack(allow);
        call.caller_pracks(&ringing, 2, CALLER_NEW_OFFER);
        let sent = call.wire();
        assert_eq!(
            prack_response(&to(&sent, CALLER)).status_code(),
            Some(488),
            "allow {allow:?}"
        );
        assert!(to(&sent, CALLEE).is_empty(), "{:?}", summaries(&sent));
        assert!(!call.is_ending(), "allow {allow:?}");
    }
}

/// A caller that still owes the answer to the callee's offer in the 2xx (a delayed
/// offer, answered in the ACK) and offers in a PRACK meanwhile has two offers
/// crossing: refused 491 (RFC 3311 §5.2), with nothing sent to the callee.
#[tokio::test(flavor = "multi_thread")]
async fn a_late_offer_while_the_caller_owes_an_answer_is_refused_491() {
    let call = PrackCall::place(None);
    call.callee_responds(180, "Ringing", Some(42), "");
    let ringing = to(&call.wire(), CALLER)
        .into_iter()
        .find(|message| message.status_code() == Some(180))
        .expect("a 180 to the caller");
    call.callee_responds(200, "OK", None, CALLEE_OFFER);
    call.wire();

    call.caller_pracks(&ringing, 2, CALLER_NEW_OFFER);
    let sent = call.wire();
    assert_eq!(prack_response(&to(&sent, CALLER)).status_code(), Some(491));
    assert!(
        updates(&to(&sent, CALLEE)).is_empty(),
        "{:?}",
        summaries(&sent)
    );
    assert!(!call.is_ending());
}

/// An UPDATE carrying a late offer that the transport refuses reaches nobody, so
/// nothing will answer the offer: it is taken back rather than left to wait out
/// 64*T1, and the caller's PRACK is refused 500 at once, as a 503 from the callee
/// would have it (RFC 3261 §8.1.3.1). The session and the call stay as they were
/// (RFC 3311 §5.3).
#[tokio::test(flavor = "multi_thread")]
async fn a_late_offer_whose_update_the_transport_refuses_is_refused_500_and_not_left_waiting() {
    let (call, callee) = place_with_split_egress(Some(CALLER_OFFER), None);
    call.callee_responds(180, "Ringing", Some(42), "");
    let ringing = to(&call.wire(), CALLER)
        .into_iter()
        .find(|message| message.status_code() == Some(180))
        .expect("a 180 to the caller");
    call.callee_responds(200, "OK", None, CALLEE_ANSWER);
    assert!(
        to(&call.wire(), CALLER)
            .iter()
            .any(|message| message.status_code() == Some(200) && cseq_method(message) == "INVITE"),
        "the caller has its 2xx"
    );
    drop(callee);

    call.caller_pracks(&ringing, 2, CALLER_NEW_OFFER);

    let pending = call
        .state
        .call_actors
        .get_call(&call.call_id)
        .is_some_and(|actor| actor.prack_bridge.offer_pending());
    assert!(
        !pending,
        "an offer nobody was sent is still waiting for its answer"
    );
    let refusal = prack_response(&to(&call.wire(), CALLER));
    assert_eq!(refusal.status_code(), Some(500));
    assert!(refusal.body.is_empty());
    assert!(!call.is_ending());
}

/// A new PRACK from the caller with another offer while the UPDATE carrying its
/// first is still out is not a retransmission to absorb: two offers cross on the
/// callee's dialog, so it is refused 500 with a Retry-After of at most 10 seconds
/// (RFC 3311 §5.2), nothing more goes to the callee, and the first offer's answer
/// still reaches the caller.
#[tokio::test(flavor = "multi_thread")]
async fn a_new_prack_with_an_offer_while_the_update_is_out_is_refused_500_with_retry_after() {
    let (call, ringing) = answered_before_the_callers_prack(Some(CALLEE_ALLOW));
    call.caller_pracks(&ringing, 2, CALLER_NEW_OFFER);
    let update = updates(&to(&call.wire(), CALLEE));
    assert_eq!(update.len(), 1);

    call.caller_pracks(&ringing, 3, CALLER_NEW_OFFER);
    let sent = call.wire();
    let refusal = prack_response(&to(&sent, CALLER));
    assert_eq!(refusal.status_code(), Some(500), "{:?}", summaries(&sent));
    assert_eq!(refusal.headers.cseq().map(String::as_str), Some("3 PRACK"));
    let retry_after: u32 = refusal
        .headers
        .get("Retry-After")
        .and_then(|value| value.trim().parse().ok())
        .expect("a Retry-After in seconds");
    assert!(retry_after <= 10, "{retry_after}");
    assert!(to(&sent, CALLEE).is_empty(), "{:?}", summaries(&sent));

    call.callee_answers_prack(&update[0], 200, CALLEE_NEW_ANSWER);
    let answer = prack_response(&to(&call.wire(), CALLER));
    assert_eq!(answer.status_code(), Some(200));
    assert_eq!(answer.headers.cseq().map(String::as_str), Some("2 PRACK"));
    assert!(!call.is_ending());
}

/// A caller refused 500 with a Retry-After offers again in a new PRACK, as that
/// Retry-After invites: the new offer goes to the callee in an UPDATE of its own and
/// the callee's answer comes back in the 200 to that PRACK. An offer in a PRACK is
/// never answered with a 200 that carries no answer (RFC 3262 §5).
#[tokio::test(flavor = "multi_thread")]
async fn an_offer_in_a_new_prack_after_a_refusal_reaches_the_callee_in_an_update() {
    let (call, ringing) = answered_before_the_callers_prack(Some(CALLEE_ALLOW));
    call.caller_pracks(&ringing, 2, CALLER_NEW_OFFER);
    let update = updates(&to(&call.wire(), CALLEE));
    call.callee_answers_request(&update[0], 500, "", &[("Retry-After", "1")]);
    assert_eq!(
        prack_response(&to(&call.wire(), CALLER)).status_code(),
        Some(500)
    );

    call.caller_pracks(&ringing, 3, CALLER_NEW_OFFER);
    let sent = call.wire();
    assert!(to(&sent, CALLER).is_empty(), "{:?}", summaries(&sent));
    let update = updates(&to(&sent, CALLEE));
    assert_eq!(update.len(), 1, "{:?}", summaries(&sent));

    call.callee_answers_prack(&update[0], 200, CALLEE_NEW_ANSWER);
    let answer = prack_response(&to(&call.wire(), CALLER));
    assert_eq!(answer.status_code(), Some(200));
    assert_eq!(answer.headers.cseq().map(String::as_str), Some("3 PRACK"));
    assert!(
        body_text(&answer).contains("m=audio 30002 RTP/AVP 0"),
        "{}",
        body_text(&answer)
    );
    assert_eq!(
        sessions_in_force(&call).callee_session,
        Some(update[0].body.clone())
    );
    assert!(call.call_is_up());
}

/// A retransmission of a PRACK whose offer was refused gets that refusal again,
/// with nothing sent to the callee (RFC 3261 §17.2.2), and a new PRACK without the
/// offer, which RFC 6337 §2.3 has the caller send after a 488, gets a 200 of its
/// own.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_prack_is_refused_again_and_a_new_one_without_the_offer_gets_200() {
    let (call, ringing) = answered_before_the_callers_prack(Some(CALLEE_ALLOW));
    call.caller_pracks(&ringing, 2, CALLER_NEW_OFFER);
    let update = updates(&to(&call.wire(), CALLEE));
    call.callee_answers_prack(&update[0], 488, "");
    assert_eq!(
        prack_response(&to(&call.wire(), CALLER)).status_code(),
        Some(488)
    );

    call.caller_pracks(&ringing, 2, CALLER_NEW_OFFER);
    let sent = call.wire();
    assert_eq!(prack_response(&to(&sent, CALLER)).status_code(), Some(488));
    assert!(to(&sent, CALLEE).is_empty(), "{:?}", summaries(&sent));

    call.caller_pracks(&ringing, 3, "");
    let sent = call.wire();
    let ok = prack_response(&to(&sent, CALLER));
    assert_eq!(ok.status_code(), Some(200));
    assert!(ok.body.is_empty());
    assert!(to(&sent, CALLEE).is_empty(), "{:?}", summaries(&sent));
    assert!(!call.is_ending());
}

/// The caller's own SDP, which siphon keeps for a transfer that offers the caller's
/// media to someone else.
fn caller_sdp(call: &PrackCall) -> Option<Vec<u8>> {
    call.state
        .call_actors
        .clone_leg(&call.call_id, true)
        .and_then(|leg| leg.last_sdp)
}

/// A late offer the callee refuses changes neither party's session (RFC 3311
/// §5.3), so the caller's own SDP stays what its INVITE offered; an offer the callee
/// accepts replaces it.
#[tokio::test(flavor = "multi_thread")]
async fn only_a_late_offer_the_callee_accepts_becomes_the_callers_own_sdp() {
    for (callee_status, body, callers_sdp) in [
        (488, "", CALLER_OFFER),
        (200, CALLEE_NEW_ANSWER, CALLER_NEW_OFFER),
    ] {
        let (call, ringing) = answered_before_the_callers_prack(Some(CALLEE_ALLOW));
        assert_eq!(
            caller_sdp(&call).as_deref(),
            Some(CALLER_OFFER.as_bytes()),
            "callee {callee_status}"
        );
        call.caller_pracks(&ringing, 2, CALLER_NEW_OFFER);
        let update = updates(&to(&call.wire(), CALLEE));
        assert_eq!(update.len(), 1, "callee {callee_status}");
        call.callee_answers_prack(&update[0], callee_status, body);
        call.wire();
        assert_eq!(
            caller_sdp(&call).as_deref(),
            Some(callers_sdp.as_bytes()),
            "callee {callee_status}"
        );
    }
}

// ---------------------------------------------------------------------------
// A session refresh toward the caller
// ---------------------------------------------------------------------------

/// The re-INVITE siphon sends the caller when it refreshes the session on the
/// caller's dialog as its refresher.
fn refresh_toward_the_caller(call: &PrackCall) -> SipMessage {
    call.wire();
    call.state.call_actors.set_leg_session_timer(
        &call.call_id,
        true,
        Some(crate::b2bua::actor::SessionTimerState::new(
            1800,
            true,
            90,
            Instant::now(),
        )),
    );
    b2bua_send_session_refresh(&call.call_id, true, &call.state);
    let sent = call.wire();
    let refresh: Vec<SipMessage> = to(&sent, CALLER)
        .into_iter()
        .filter(|message| message.method() == Some(&Method::Invite))
        .collect();
    assert_eq!(refresh.len(), 1, "{:?}", summaries(&sent));
    refresh[0].clone()
}

/// The callee answered the caller's offer in a reliable 183 and its 2xx carried no
/// SDP. A refresh of the caller's dialog offers that answer again as it went, `o=`
/// line and all, so the caller sees the session unchanged (RFC 4028 §7.4, RFC 3264
/// §8), not a new session id at a version it never saw.
#[tokio::test(flavor = "multi_thread")]
async fn a_refresh_toward_the_caller_offers_the_answer_its_reliable_183_carried() {
    let call = PrackCall::place(Some(CALLER_OFFER));
    call.callee_responds(183, "Session Progress", Some(42), CALLEE_ANSWER);
    let progress = the_183(&to(&call.wire(), CALLER));
    call.caller_pracks(&progress, 2, "");
    call.wire();
    call.callee_responds(200, "OK", None, "");

    let refresh = refresh_toward_the_caller(&call);
    assert_eq!(body_text(&refresh), body_text(&progress));
}

/// The same for siphon's offer in a reliable 183 to an INVITE without SDP, once the
/// caller's PRACK answered it.
#[tokio::test(flavor = "multi_thread")]
async fn a_refresh_toward_the_caller_offers_the_early_offer_its_prack_answered() {
    let call = PrackCall::place(None);
    call.callee_responds(183, "Session Progress", Some(42), CALLEE_OFFER);
    let progress = the_183(&to(&call.wire(), CALLER));
    call.caller_pracks(&progress, 2, CALLER_ANSWER);
    call.wire();
    call.callee_responds(200, "OK", None, "");

    let refresh = refresh_toward_the_caller(&call);
    assert_eq!(body_text(&refresh), body_text(&progress));
}
