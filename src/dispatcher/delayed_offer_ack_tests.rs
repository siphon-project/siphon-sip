//! A B-leg INVITE that went out without an offer draws the offer in the callee's
//! 2xx, and the ACK is where the answer goes (RFC 3261 §13.2.2.4, RFC 3264 §4).
//! siphon has no answer of its own to give: the caller has it, in the ACK for the
//! 2xx siphon relayed. So for this call alone siphon's ACK to the callee waits for
//! the caller's and carries its answer. Every other call is ACKed on arrival.
//!
//! A call that ends before the caller answers still owes the callee that ACK, with
//! a valid answer: every stream rejected (RFC 3264 §6), then the BYE.
//!
//! Driven through the dispatcher: the callee is dialled by
//! [`b2bua_send_b_leg_invite`], its responses arrive through
//! [`handle_b2bua_response`], the caller's ACK through [`handle_request`] and its
//! BYE through [`handle_b2bua_bye`], with every frame siphon sends read back off
//! the UDP egress channel in order, the followers of an ordered group included.

use super::lcr_ring_timeout_tests::top_via_branch;
use super::test_dispatcher::{test_dispatcher_with_script, TestDispatcher};
use super::*;
use crate::rtpengine::test_engine::TestEngine;

const CALLER: &str = "192.0.2.20:5060";
const CALLEE: &str = "198.51.100.90:5060";
const CALLER_CALL_ID: &str = "offerless-call@192.0.2.20";
const NO_ANSWER_REASON: &str = "Q.850;cause=111;text=\"No SDP answer in ACK\"";
const MEDIA_ANCHOR_FAILED_REASON: &str = "Q.850;cause=47;text=\"Media anchor failed\"";

/// An anchored call with a delayed offer. `rtpengine.answer` sent the callee's
/// offer to the media engine, so the caller's answer in its ACK has to go through
/// the engine as the `answer` that completes it. The callee's ACK carries the
/// engine's SDP, never the caller's own address.
#[tokio::test(flavor = "multi_thread")]
async fn an_anchored_delayed_offer_is_answered_through_the_media_engine() {
    let engine = TestEngine::start(false).await;
    let call = OfferlessCall::dial_anchored(&engine).await;
    call.callee_answers_with_an_offer();
    let relayed = relayed_answer(&call.wire());

    call.caller_acks(&relayed, Some(CALLER_ANSWER));
    let sent = call.wire();
    let callee_acks: Vec<&Sent> = to_callee(&sent)
        .into_iter()
        .filter(|sent| sent.is(Method::Ack))
        .collect();
    assert_eq!(callee_acks.len(), 1, "the callee is ACKed once");
    let answer = body_text(&callee_acks[0].message);
    assert!(
        answer.contains("c=IN IP4 203.0.113.50"),
        "the callee gets the answer the engine rewrote:\n{answer}"
    );
    assert!(
        !answer.contains("192.0.2.20"),
        "the caller's own address never reaches the callee:\n{answer}"
    );

    let answers = engine.commands("answer");
    assert_eq!(answers.len(), 1, "the engine is sent the caller's answer");
    assert_eq!(answers[0].call_id.as_deref(), Some(CALLER_CALL_ID));
    assert_eq!(
        answers[0].from_tag.as_deref(),
        Some("callee-tag"),
        "answering the callee's offer"
    );
    assert_eq!(answers[0].to_tag.as_deref(), Some("caller-tag"));
    assert_eq!(answers[0].sdp.as_deref(), Some(CALLER_ANSWER));
    let session = call
        .state
        .rtpengine_sessions
        .as_ref()
        .and_then(|sessions| sessions.get(CALLER_CALL_ID))
        .expect("the media session");
    assert_eq!(session.to_tag.as_deref(), Some("caller-tag"));
    assert!(call.call_is_up());
}

/// The engine refusing the caller's answer leaves the callee's anchored offer with
/// no answer to give. The call ends the way a caller ACK with no answer ends it:
/// the callee ACKed with every stream rejected, then a BYE to both legs.
#[tokio::test(flavor = "multi_thread")]
async fn an_anchored_delayed_offer_the_engine_cannot_answer_ends_the_call() {
    let engine = TestEngine::start(true).await;
    let call = OfferlessCall::dial_anchored(&engine).await;
    call.callee_answers_with_an_offer();
    let relayed = relayed_answer(&call.wire());

    call.caller_acks(&relayed, Some(CALLER_ANSWER));
    let sent = call.wire();
    let (_, bye) = assert_rejecting_ack_then_bye(&sent);
    assert_eq!(
        bye.headers.get("Reason").map(String::as_str),
        Some(MEDIA_ANCHOR_FAILED_REASON)
    );
    assert!(to_caller(&sent).iter().any(|sent| sent.is(Method::Bye)));
    assert!(!call.call_is_up());
}

/// The offer the callee puts in its 2xx: an audio and a video stream.
const CALLEE_OFFER: &str = concat!(
    "v=0\r\n",
    "o=callee 7 7 IN IP4 198.51.100.91\r\n",
    "s=-\r\n",
    "c=IN IP4 198.51.100.91\r\n",
    "t=0 0\r\n",
    "m=audio 30000 RTP/AVP 0 101\r\n",
    "a=rtpmap:0 PCMU/8000\r\n",
    "a=rtpmap:101 telephone-event/8000\r\n",
    "m=video 30002 RTP/AVP 96\r\n",
    "a=rtpmap:96 H264/90000\r\n",
);

/// The caller's answer, in its ACK: audio accepted, video declined.
const CALLER_ANSWER: &str = concat!(
    "v=0\r\n",
    "o=caller 3 3 IN IP4 192.0.2.20\r\n",
    "s=-\r\n",
    "c=IN IP4 192.0.2.20\r\n",
    "t=0 0\r\n",
    "m=audio 40000 RTP/AVP 0 101\r\n",
    "a=rtpmap:0 PCMU/8000\r\n",
    "a=rtpmap:101 telephone-event/8000\r\n",
    "m=video 0 RTP/AVP 96\r\n",
);

fn address(text: &str) -> SocketAddr {
    text.parse().expect("a literal address")
}

/// The caller's INVITE, with no offer in it.
fn caller_invite() -> SipMessage {
    let raw = format!(
        concat!(
            "INVITE sip:15550100042@siphon.example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 192.0.2.20:5060;branch=z9hG4bK-offerless-invite\r\n",
            "Max-Forwards: 70\r\n",
            "From: <sip:15550100001@siphon.example.com>;tag=caller-tag\r\n",
            "To: <sip:15550100042@siphon.example.com>\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: 1 INVITE\r\n",
            "Contact: <sip:15550100001@192.0.2.20:5060>\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        call_id = CALLER_CALL_ID,
    );
    parse_sip_message_bytes(raw.as_bytes()).expect("the caller's INVITE parses")
}

/// The caller's leg, with the dialog state `handle_b2bua_invite` takes off the
/// INVITE (RFC 3261 §12.1.1).
fn caller_leg() -> Leg {
    let invite = caller_invite();
    let mut leg = Leg::new_a_leg(
        CALLER_CALL_ID.to_string(),
        "caller-tag".to_string(),
        "z9hG4bK-offerless-invite".to_string(),
        LegTransport {
            remote_addr: address(CALLER),
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

/// One frame siphon put on the wire.
struct Sent {
    destination: SocketAddr,
    message: SipMessage,
}

impl Sent {
    fn is(&self, method: Method) -> bool {
        self.message.method() == Some(&method)
    }
}

/// A caller's offerless call bridged to one callee through a real dispatcher.
struct OfferlessCall {
    state: Arc<DispatcherState>,
    udp: flume::Receiver<OutboundMessage>,
    call_id: String,
    invite: SipMessage,
}

impl OfferlessCall {
    /// The caller's INVITE arrives and siphon dials the callee, with `script`
    /// running.
    fn dial(script: &str) -> OfferlessCall {
        OfferlessCall::dial_on(test_dispatcher_with_script(script))
    }

    /// [`OfferlessCall::dial`] with media anchored on `engine`, and the session
    /// `rtpengine.answer` records for a 2xx that carries the offer: the callee as
    /// offerer, no answerer yet.
    async fn dial_anchored(engine: &TestEngine) -> OfferlessCall {
        let TestDispatcher { mut state, udp } = test_dispatcher_with_script("");
        state.rtpengine_set = Some(engine.backend().await);
        let sessions = Arc::new(crate::rtpengine::MediaSessionStore::new());
        sessions.insert(crate::rtpengine::MediaSession {
            call_id: CALLER_CALL_ID.to_string(),
            rtpengine_call_id: CALLER_CALL_ID.to_string(),
            from_tag: "callee-tag".to_string(),
            to_tag: None,
            profile: "rtp_passthrough".to_string(),
            ws_uri: None,
            ws_tee: None,
            ws_bridge_attached: false,
            created_at: std::time::Instant::now(),
        });
        state.rtpengine_sessions = Some(sessions);
        state.rtpengine_profiles = Some(Arc::new(crate::rtpengine::ProfileRegistry::new()));
        OfferlessCall::dial_on(TestDispatcher { state, udp })
    }

    /// [`OfferlessCall::dial`] with `media.sdp_strip_attributes` set to `names`.
    fn dial_stripping(names: &[&str]) -> OfferlessCall {
        let mut dispatcher = test_dispatcher_with_script("");
        dispatcher.state.sdp_strip_attributes = names.iter().map(|name| name.to_string()).collect();
        OfferlessCall::dial_on(dispatcher)
    }

    fn dial_on(TestDispatcher { state, udp }: TestDispatcher) -> OfferlessCall {
        let state = Arc::new(state);
        let call_id = state.call_actors.create_call(caller_leg());
        let a_leg_invite = Arc::new(Mutex::new(caller_invite()));
        state
            .call_actors
            .set_a_leg_invite(&call_id, Arc::clone(&a_leg_invite));
        let dialled = {
            let guard = a_leg_invite.lock().expect("the A-leg INVITE lock");
            b2bua_send_b_leg_invite(
                &call_id,
                "sip:15550100042@198.51.100.90:5060",
                Some("sip:198.51.100.90:5060"),
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
            .find(|sent| sent.is(Method::Invite))
            .expect("siphon sent the callee an INVITE")
            .message;
        OfferlessCall {
            state,
            udp,
            call_id,
            invite,
        }
    }

    fn wire(&self) -> Vec<Sent> {
        drain(&self.udp)
    }

    fn callee_sends(&self, response: &str) {
        let mut message =
            parse_sip_message_bytes(response.as_bytes()).expect("the callee's response parses");
        let status_code = message.status_code().expect("a response");
        let handled = handle_b2bua_response(
            &self.call_id,
            &top_via_branch(&self.invite),
            &mut message,
            status_code,
            address(CALLEE),
            &self.state,
        );
        assert!(
            handled,
            "the call was gone when the callee's {status_code} arrived"
        );
    }

    fn callee_response(&self, status_line: &str, body: &str) -> String {
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
        raw.push_str("Contact: <sip:callee@198.51.100.90:5060>\r\n");
        if body.is_empty() {
            raw.push_str("Content-Length: 0\r\n\r\n");
        } else {
            raw.push_str("Content-Type: application/sdp\r\n");
            raw.push_str(&format!("Content-Length: {}\r\n\r\n{body}", body.len()));
        }
        raw
    }

    /// The callee rings, then answers with an offer. Returns the 2xx as sent.
    fn callee_answers_with_an_offer(&self) -> String {
        self.callee_sends(&self.callee_response("180 Ringing", ""));
        let answer = self.callee_response("200 OK", CALLEE_OFFER);
        self.callee_sends(&answer);
        answer
    }

    /// A request from the caller in the dialog `relayed_200` created.
    fn caller_request(
        &self,
        method: &str,
        cseq: &str,
        relayed_200: &SipMessage,
        body: Option<&str>,
    ) -> (InboundMessage, SipMessage) {
        let mut raw = format!(
            concat!(
                "{method} sip:192.0.2.1:5060;transport=udp SIP/2.0\r\n",
                "Via: SIP/2.0/UDP 192.0.2.20:5060;branch=z9hG4bK-caller-{branch}\r\n",
                "Max-Forwards: 70\r\n",
                "From: {from}\r\n",
                "To: {to}\r\n",
                "Call-ID: {call_id}\r\n",
                "CSeq: {cseq}\r\n",
            ),
            method = method,
            branch = uuid::Uuid::new_v4().simple(),
            from = relayed_200
                .headers
                .from()
                .expect("the relayed 200 has a From"),
            to = relayed_200.headers.to().expect("the relayed 200 has a To"),
            call_id = CALLER_CALL_ID,
            cseq = cseq,
        );
        match body {
            Some(body) => {
                raw.push_str("Content-Type: application/sdp\r\n");
                raw.push_str(&format!("Content-Length: {}\r\n\r\n{body}", body.len()));
            }
            None => raw.push_str("Content-Length: 0\r\n\r\n"),
        }
        let message = parse_sip_message_bytes(raw.as_bytes()).expect("the caller's request parses");
        let inbound = InboundMessage {
            client_transport: None,
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: address("192.0.2.1:5060"),
            remote_addr: address(CALLER),
            data: Bytes::from(raw),
        };
        (inbound, message)
    }

    fn caller_acks(&self, relayed_200: &SipMessage, answer: Option<&str>) {
        let (inbound, message) = self.caller_request("ACK", "1 ACK", relayed_200, answer);
        handle_request(inbound, message, "ACK".to_string(), &self.state);
    }

    fn caller_hangs_up(&self, relayed_200: &SipMessage) {
        let (inbound, message) = self.caller_request("BYE", "2 BYE", relayed_200, None);
        handle_b2bua_bye(inbound, message, &self.state);
    }

    fn call_is_up(&self) -> bool {
        self.state.call_actors.get_call(&self.call_id).is_some()
    }
}

/// Every frame on `udp` so far, in the order siphon sent it.
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

fn to_callee(sent: &[Sent]) -> Vec<&Sent> {
    sent.iter()
        .filter(|sent| sent.destination == address(CALLEE))
        .collect()
}

fn to_caller(sent: &[Sent]) -> Vec<&Sent> {
    sent.iter()
        .filter(|sent| sent.destination == address(CALLER))
        .collect()
}

fn acks(sent: &[Sent]) -> Vec<&Sent> {
    sent.iter().filter(|sent| sent.is(Method::Ack)).collect()
}

fn relayed_answer(sent: &[Sent]) -> SipMessage {
    to_caller(sent)
        .into_iter()
        .find(|sent| sent.message.status_code() == Some(200))
        .expect("the 2xx was relayed to the caller")
        .message
        .clone()
}

fn body_text(message: &SipMessage) -> String {
    String::from_utf8(message.body.clone()).expect("an SDP body is UTF-8")
}

fn request_line(message: &SipMessage) -> String {
    let text = String::from_utf8(message.to_bytes()).expect("serialized SIP is UTF-8");
    text.split("\r\n").next().expect("a start line").to_string()
}

/// What the callee is sent when the call ends before the caller answered: the
/// ACK the 2xx is owed, answering every stream with port 0, and then the BYE, as
/// consecutive frames.
fn assert_rejecting_ack_then_bye(sent: &[Sent]) -> (SipMessage, SipMessage) {
    let callee = to_callee(sent);
    let ack_at = callee
        .iter()
        .position(|sent| sent.is(Method::Ack))
        .expect("the callee is sent the ACK its 2xx is owed");
    let bye_at = callee
        .iter()
        .position(|sent| sent.is(Method::Bye))
        .expect("the callee is sent a BYE");
    assert_eq!(bye_at, ack_at + 1, "the ACK goes out right before the BYE");
    let ack = callee[ack_at].message.clone();
    assert_eq!(
        ack.headers.get("Content-Type").map(String::as_str),
        Some("application/sdp"),
        "RFC 3261 §13.2.2.4: the ACK to a 2xx offer carries an answer"
    );
    let answer = body_text(&ack);
    assert!(
        answer.contains("m=audio 0 RTP/AVP 0\r\n"),
        "audio rejected:\n{answer}"
    );
    assert!(
        answer.contains("m=video 0 RTP/AVP 96\r\n"),
        "video rejected:\n{answer}"
    );
    assert_eq!(
        ack.headers.get("Content-Length").map(String::as_str),
        Some(ack.body.len().to_string().as_str())
    );
    (ack, callee[bye_at].message.clone())
}

/// The caller's answer carrying attributes `media.sdp_strip_attributes` names, next
/// to ones that stay: `msid-semantic` shares a prefix with `msid`.
const CALLER_ANSWER_WITH_HIDDEN_ATTRIBUTES: &str = concat!(
    "v=0\r\n",
    "o=caller 3 3 IN IP4 192.0.2.20\r\n",
    "s=caller session\r\n",
    "c=IN IP4 192.0.2.20\r\n",
    "t=0 0\r\n",
    "a=x-hidden\r\n",
    "a=msid-semantic: WMS stream-a\r\n",
    "m=audio 40000 RTP/AVP 0 101\r\n",
    "a=rtpmap:0 PCMU/8000\r\n",
    "a=MSID:stream-a track-a\r\n",
    "a=X-Hidden:detail\r\n",
    "a=rtpmap:101 telephone-event/8000\r\n",
    "m=video 0 RTP/AVP 96\r\n",
);

/// The callee's ACK carries SDP the caller wrote, so it gets what every SDP
/// relayed toward a leg gets: siphon's `o=` and `s=` in place of the caller's,
/// and the configured attributes stripped, at session and media level.
#[tokio::test(flavor = "multi_thread")]
async fn the_answer_in_the_callee_ack_is_hidden_and_stripped_like_any_relayed_sdp() {
    let call = OfferlessCall::dial_stripping(&["msid", "x-hidden"]);
    call.callee_answers_with_an_offer();
    let relayed = relayed_answer(&call.wire());

    call.caller_acks(&relayed, Some(CALLER_ANSWER_WITH_HIDDEN_ATTRIBUTES));
    let sent = call.wire();
    let acks_sent = acks(&sent);
    assert_eq!(acks_sent.len(), 1, "one ACK, once the caller has answered");
    let ack = &acks_sent[0].message;
    let carried = body_text(ack);
    assert!(
        carried.contains("o=siphon ") && carried.contains("s=siphon\r\n"),
        "siphon's o= and s= toward the callee:\n{carried}"
    );
    assert!(
        !carried.contains("o=caller") && !carried.contains("s=caller"),
        "{carried}"
    );
    assert!(
        !carried.to_ascii_lowercase().contains("a=msid:")
            && !carried.to_ascii_lowercase().contains("a=x-hidden"),
        "the configured attributes are stripped:\n{carried}"
    );
    assert!(
        carried.contains("a=msid-semantic: WMS stream-a"),
        "{carried}"
    );
    assert!(
        carried.contains("a=rtpmap:101 telephone-event/8000"),
        "{carried}"
    );
    assert!(carried.contains("m=video 0 RTP/AVP 96"), "{carried}");
    assert_eq!(
        ack.headers.get("Content-Length").map(String::as_str),
        Some(ack.body.len().to_string().as_str())
    );
}

/// The case this exists for. The callee's ACK waits for the caller's, carries
/// the caller's answer, and is sent again, body and all, for every later copy of
/// the 2xx.
#[tokio::test(flavor = "multi_thread")]
async fn an_offerless_invite_holds_the_callee_ack_until_the_caller_answers() {
    let call = OfferlessCall::dial("");
    assert!(
        call.invite.body.is_empty(),
        "the callee INVITE carries no offer"
    );
    let answer = call.callee_answers_with_an_offer();

    let sent = call.wire();
    let relayed = relayed_answer(&sent);
    assert!(
        body_text(&relayed).contains("m=audio 30000 RTP/AVP 0 101"),
        "the caller is relayed the callee's offer"
    );
    assert!(
        acks(&sent).is_empty(),
        "no ACK before the caller's answer: the ACK is where the answer goes"
    );
    for copy in 1..=2 {
        call.callee_sends(&answer);
        assert!(
            acks(&call.wire()).is_empty(),
            "retransmission {copy} of the 2xx is absorbed while the ACK waits"
        );
    }

    call.caller_acks(&relayed, Some(CALLER_ANSWER));
    let sent = call.wire();
    let acks_sent = acks(&sent);
    assert_eq!(acks_sent.len(), 1, "one ACK, once the caller has answered");
    assert_eq!(acks_sent[0].destination, address(CALLEE));
    let ack = acks_sent[0].message.clone();
    assert_eq!(
        request_line(&ack),
        "ACK sip:callee@198.51.100.90:5060 SIP/2.0"
    );
    assert_eq!(
        ack.headers.get("Content-Type").map(String::as_str),
        Some("application/sdp")
    );
    let carried = body_text(&ack);
    assert!(carried.contains("m=audio 40000 RTP/AVP 0 101"), "{carried}");
    assert!(carried.contains("m=video 0 RTP/AVP 96"), "{carried}");
    assert!(
        carried.contains("o=siphon "),
        "siphon's own origin toward the callee:\n{carried}"
    );
    assert!(!carried.contains("o=caller"), "{carried}");
    assert_eq!(
        ack.headers.get("Content-Length").map(String::as_str),
        Some(ack.body.len().to_string().as_str())
    );

    call.callee_sends(&answer);
    let again = call.wire();
    let again = acks(&again);
    assert_eq!(again.len(), 1, "a later copy of the 2xx is ACKed");
    assert_eq!(
        again[0].message.to_bytes(),
        ack.to_bytes(),
        "with the same ACK, answer included"
    );

    call.caller_acks(&relayed, Some(CALLER_ANSWER));
    assert!(
        acks(&call.wire()).is_empty(),
        "the caller's retransmitted ACK sends nothing more"
    );
    assert!(call.call_is_up());
}

/// The answer siphon puts in the callee's ACK is the session description in force
/// on the callee's dialog, the one a session refresh there offers again.
#[tokio::test(flavor = "multi_thread")]
async fn the_answer_in_the_callee_ack_is_the_session_in_force_on_its_dialog() {
    let call = OfferlessCall::dial("");
    call.callee_answers_with_an_offer();
    let relayed = relayed_answer(&call.wire());

    call.caller_acks(&relayed, Some(CALLER_ANSWER));

    let sent = call.wire();
    let ack = acks(&sent)
        .first()
        .map(|sent| sent.message.clone())
        .expect("the callee's ACK");
    assert_eq!(callee_session_in_force(&call), Some(ack.body.clone()));
}

/// The ACK a dialog ending before the caller answered still owes the callee
/// carries siphon's rejecting answer, and that answer is what siphon last sent
/// the callee's dialog.
#[tokio::test(flavor = "multi_thread")]
async fn the_rejecting_answer_in_a_held_ack_is_the_session_in_force_on_its_dialog() {
    let call = OfferlessCall::dial("");
    call.callee_answers_with_an_offer();
    let callee = call
        .state
        .call_actors
        .clone_leg(&call.call_id, false)
        .expect("the callee's leg");

    let held = take_held_ack_rejecting_offer(&call.call_id, &callee, &call.state)
        .expect("the ACK held for the caller's answer");

    assert_eq!(callee_session_in_force(&call), Some(held.ack.body.clone()));
}

/// The session description siphon has in force on the callee's dialog.
fn callee_session_in_force(call: &OfferlessCall) -> Option<Vec<u8>> {
    call.state
        .call_actors
        .clone_leg(&call.call_id, false)
        .and_then(|leg| leg.dialog.last_sent_sdp)
}

/// A caller that ACKs the offer without an answer leaves nothing to put in the
/// callee's ACK. The callee is ACKed with every stream rejected, and the call is
/// ended: a session with no media agreed on either leg carries nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_caller_ack_without_an_answer_rejects_every_stream_and_ends_the_call() {
    let call = OfferlessCall::dial("");
    call.callee_answers_with_an_offer();
    let relayed = relayed_answer(&call.wire());

    call.caller_acks(&relayed, None);
    let sent = call.wire();
    let (_, bye) = assert_rejecting_ack_then_bye(&sent);
    assert_eq!(
        bye.headers.get("Reason").map(String::as_str),
        Some(NO_ANSWER_REASON)
    );
    let caller_bye = to_caller(&sent)
        .into_iter()
        .find(|sent| sent.is(Method::Bye))
        .expect("the caller is sent a BYE");
    assert_eq!(
        caller_bye.message.headers.get("Reason").map(String::as_str),
        Some(NO_ANSWER_REASON)
    );
    assert!(!call.call_is_up());
}

/// A call ended by siphon while the callee's ACK waits still owes that ACK: sent
/// with every stream rejected, right before the BYE (RFC 3261 §13.2.2.4, §15).
/// The caller has not ACKed either, so its own BYE waits for its ACK, and that ACK
/// sends the callee nothing more.
#[tokio::test(flavor = "multi_thread")]
async fn ending_the_call_while_the_ack_is_held_sends_it_rejecting_the_offer_before_the_bye() {
    let call = OfferlessCall::dial("");
    call.callee_answers_with_an_offer();
    let relayed = relayed_answer(&call.wire());

    assert!(b2bua_terminate_call_inner(
        &call.call_id,
        Some("Q.850;cause=16;text=\"Normal Clearing\""),
        "b2bua",
        &call.state,
    ));
    let sent = call.wire();
    assert_rejecting_ack_then_bye(&sent);
    assert!(
        !to_caller(&sent).iter().any(|sent| sent.is(Method::Bye)),
        "the caller's BYE waits for its ACK"
    );
    assert!(!call.call_is_up());

    call.caller_acks(&relayed, Some(CALLER_ANSWER));
    let sent = call.wire();
    assert_eq!(
        to_caller(&sent)
            .iter()
            .filter(|sent| sent.is(Method::Bye))
            .count(),
        1,
        "the caller's ACK releases its BYE"
    );
    assert!(
        to_callee(&sent).is_empty(),
        "the callee was ACKed and BYEd already"
    );
    assert!(call.state.held_byes.is_empty());
}

/// The caller hangs up before it ACKs: the held ACK goes to the callee, offer
/// rejected, right before the BYE siphon sends it.
#[tokio::test(flavor = "multi_thread")]
async fn a_caller_bye_before_its_ack_sends_the_held_ack_rejecting_the_offer_first() {
    let call = OfferlessCall::dial("");
    call.callee_answers_with_an_offer();
    let relayed = relayed_answer(&call.wire());

    call.caller_hangs_up(&relayed);
    let sent = call.wire();
    assert!(
        to_caller(&sent)
            .iter()
            .any(|sent| sent.message.status_code() == Some(200)),
        "the caller's BYE is answered"
    );
    assert_rejecting_ack_then_bye(&sent);
    assert!(!call.call_is_up());
}

/// A call whose `@b2bua.on_answer` raised is failed toward the caller and its
/// callee released with an ACK and a BYE. Against an offer, that ACK carries every
/// stream rejected.
#[tokio::test(flavor = "multi_thread")]
async fn a_failed_answer_handler_acks_the_offer_rejected_before_its_bye() {
    let call = OfferlessCall::dial(concat!(
        "from siphon import b2bua\n",
        "\n",
        "@b2bua.on_answer\n",
        "def answered(call, reply):\n",
        "    raise RuntimeError(\"no media path\")\n",
    ));
    call.callee_answers_with_an_offer();
    let sent = call.wire();
    assert_rejecting_ack_then_bye(&sent);
}
