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

/// A caller's call that supports `100rel`, dialled to one callee.
struct PrackCall {
    state: Arc<DispatcherState>,
    udp: flume::Receiver<OutboundMessage>,
    call_id: String,
    callee_invite: SipMessage,
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
        if let Some(rseq) = rseq {
            raw.push_str(&format!("Require: 100rel\r\nRSeq: {rseq}\r\n"));
        }
        push_body(&mut raw, body);
        parse(&raw)
    }

    /// The callee answers siphon's `prack` with `status_code` and `body`, through
    /// the dispatcher's response entry point.
    fn callee_answers_prack(&self, prack: &SipMessage, status_code: u16, body: &str) {
        let header = |name: &str| {
            prack
                .headers
                .get(name)
                .cloned()
                .unwrap_or_else(|| panic!("siphon's PRACK has no {name}"))
        };
        let mut raw = format!("SIP/2.0 {status_code} Reason\r\n");
        raw.push_str(&format!("Via: {}\r\n", header("Via")));
        raw.push_str(&format!("From: {}\r\n", header("From")));
        raw.push_str(&format!("To: {}\r\n", header("To")));
        raw.push_str(&format!("Call-ID: {}\r\n", header("Call-ID")));
        raw.push_str(&format!("CSeq: {}\r\n", header("CSeq")));
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
