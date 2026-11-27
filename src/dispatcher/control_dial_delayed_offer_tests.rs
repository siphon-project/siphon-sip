//! A controller `dial` with a media profile, for a caller whose INVITE carries
//! no SDP (RFC 3261 §13.2.1, RFC 3725 flow I).
//!
//! The caller's offer is the 2xx's, and its answer the ACK's. So siphon relays
//! the INVITE to the phone offerless, anchors the phone's offer from its 2xx
//! under the profile's `answer` half (the half that faces the caller), puts the
//! engine's offer in the caller's 2xx, and completes the exchange with the
//! caller's answer from its ACK, which the phone is sent as the engine
//! rewrote it under the `offer` half.
//!
//! Driven through the dispatcher on the in-process rtpengine, with every frame
//! siphon sends read back off the UDP egress channel.

use super::lcr_ring_timeout_tests::top_via_branch;
use super::test_dispatcher::{test_dispatcher, TestDispatcher};
use super::*;
use crate::rtpengine::test_engine::TestEngine;

const CALLER: &str = "192.0.2.10:5060";
const CALLER_CALL_ID: &str = "delayed-dial@example.com";
const PHONE: &str = "198.51.100.7:5060";
const PHONE_OFFER: &str = concat!(
    "v=0\r\n",
    "o=phone 7 7 IN IP4 198.51.100.7\r\n",
    "s=-\r\n",
    "c=IN IP4 198.51.100.7\r\n",
    "t=0 0\r\n",
    "m=audio 30000 RTP/AVP 0 101\r\n",
    "a=rtpmap:0 PCMU/8000\r\n",
    "a=rtpmap:101 telephone-event/8000\r\n",
);
pub(super) const CALLER_ANSWER: &str = concat!(
    "v=0\r\n",
    "o=caller 3 3 IN IP4 192.0.2.10\r\n",
    "s=-\r\n",
    "c=IN IP4 192.0.2.10\r\n",
    "t=0 0\r\n",
    "m=audio 40000 RTP/AVP 0 101\r\n",
    "a=rtpmap:0 PCMU/8000\r\n",
    "a=rtpmap:101 telephone-event/8000\r\n",
);

fn address(text: &str) -> SocketAddr {
    text.parse().expect("a literal address")
}

/// The caller's INVITE, with no offer in it.
fn offerless_invite() -> SipMessage {
    parse_sip_message_bytes(
        format!(
            concat!(
                "INVITE sip:201@example.com SIP/2.0\r\n",
                "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-delayed\r\n",
                "Max-Forwards: 70\r\n",
                "From: <sip:caller@example.com>;tag=caller-tag\r\n",
                "To: <sip:201@example.com>\r\n",
                "Call-ID: {}\r\n",
                "CSeq: 1 INVITE\r\n",
                "Contact: <sip:caller@192.0.2.10:5060>\r\n",
                "Content-Length: 0\r\n\r\n"
            ),
            CALLER_CALL_ID
        )
        .as_bytes(),
    )
    .expect("the caller's INVITE parses")
}

pub(super) struct Sent {
    pub(super) destination: SocketAddr,
    pub(super) message: SipMessage,
}

impl Sent {
    pub(super) fn is(&self, method: Method) -> bool {
        self.message.method() == Some(&method)
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

fn body_text(message: &SipMessage) -> String {
    String::from_utf8(message.body.clone()).expect("an SDP body is UTF-8")
}

/// A parked, offerless call whose controller dials one phone with a profile.
pub(super) struct DelayedDial {
    pub(super) state: Arc<DispatcherState>,
    pub(super) udp: flume::Receiver<OutboundMessage>,
    pub(super) engine: TestEngine,
    pub(super) sessions: Arc<crate::rtpengine::MediaSessionStore>,
    pub(super) call_id: String,
    /// The INVITEs siphon sent the phones, one per branch.
    pub(super) invites: Vec<SipMessage>,
}

impl DelayedDial {
    /// Park the call and dial `phones` in parallel with `profile`.
    pub(super) async fn dial(phones: &[&str], profile: &str) -> DelayedDial {
        Self::dial_with(phones, profile, true).await
    }

    async fn dial_refusing_answers(phones: &[&str], profile: &str) -> DelayedDial {
        Self::dial_on(TestEngine::start(true).await, phones, profile, true).await
    }

    async fn dial_with(phones: &[&str], profile: &str, parallel: bool) -> DelayedDial {
        Self::dial_on(TestEngine::start(false).await, phones, profile, parallel).await
    }

    async fn dial_on(
        engine: TestEngine,
        phones: &[&str],
        profile: &str,
        parallel: bool,
    ) -> DelayedDial {
        let TestDispatcher { mut state, udp } = test_dispatcher();
        state.rtpengine_set = Some(engine.backend().await);
        let sessions = Arc::new(crate::rtpengine::MediaSessionStore::new());
        state.rtpengine_sessions = Some(sessions.clone());
        state.rtpengine_profiles = Some(Arc::new(crate::rtpengine::ProfileRegistry::new()));
        let state = Arc::new(state);
        let call_id = park(&state);
        let outcome = b2bua_dial_call_with_state(
            CALLER_CALL_ID,
            phones
                .iter()
                .map(|phone| DialTarget {
                    uri: format!("sip:201@{phone}"),
                    ..Default::default()
                })
                .collect(),
            parallel,
            30,
            &[],
            &DialShaping {
                profile: Some(profile.to_string()),
                ..Default::default()
            },
            &state,
        );
        assert!(outcome.expect("the dial is placed"));
        let invites = drain(&udp)
            .into_iter()
            .filter(|sent| sent.is(Method::Invite))
            .map(|sent| sent.message)
            .collect();
        DelayedDial {
            state,
            udp,
            engine,
            sessions,
            call_id,
            invites,
        }
    }

    pub(super) fn wire(&self) -> Vec<Sent> {
        drain(&self.udp)
    }

    /// The response the phone that was sent `invite` sends, with `body` as its
    /// SDP when there is one.
    fn phone_response(&self, invite: &SipMessage, status_line: &str, body: &str) -> SipMessage {
        let header = |name: &str| invite.headers.get(name).expect("a header").to_string();
        let mut raw = format!("SIP/2.0 {status_line}\r\n");
        raw.push_str(&format!("Via: {}\r\n", header("Via")));
        raw.push_str(&format!("From: {}\r\n", header("From")));
        raw.push_str(&format!("To: {};tag=phone-tag\r\n", header("To")));
        raw.push_str(&format!("Call-ID: {}\r\n", header("Call-ID")));
        raw.push_str(&format!("CSeq: {}\r\n", header("CSeq")));
        raw.push_str("Contact: <sip:201@198.51.100.7:5060>\r\n");
        if body.is_empty() {
            raw.push_str("Content-Length: 0\r\n\r\n");
        } else {
            raw.push_str("Content-Type: application/sdp\r\n");
            raw.push_str(&format!("Content-Length: {}\r\n\r\n{body}", body.len()));
        }
        parse_sip_message_bytes(raw.as_bytes()).expect("the phone's response parses")
    }

    fn phone_sends(&self, invite: &SipMessage, mut response: SipMessage) {
        let status_code = response.status_code().expect("a response");
        assert!(handle_b2bua_response(
            &self.call_id,
            &top_via_branch(invite),
            &mut response,
            status_code,
            address(PHONE),
            &self.state,
        ));
    }

    pub(super) fn phone_answers_with_an_offer(&self) -> SipMessage {
        let invite = self.invites[0].clone();
        self.phone_sends(&invite, self.phone_response(&invite, "200 OK", PHONE_OFFER));
        invite
    }

    pub(super) fn caller_request(
        &self,
        method: &str,
        cseq: &str,
        relayed_200: &SipMessage,
        body: Option<&str>,
    ) -> (InboundMessage, SipMessage) {
        let mut raw = format!(
            concat!(
                "{method} sip:192.0.2.1:5060;transport=udp SIP/2.0\r\n",
                "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-caller-{branch}\r\n",
                "Max-Forwards: 70\r\n",
                "From: {from}\r\n",
                "To: {to}\r\n",
                "Call-ID: {call_id}\r\n",
                "CSeq: {cseq}\r\n",
                "Contact: <sip:caller@192.0.2.10:5060>\r\n",
            ),
            method = method,
            branch = uuid::Uuid::new_v4().simple(),
            from = relayed_200.headers.from().expect("a From"),
            to = relayed_200.headers.to().expect("a To"),
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
        let message = parse_sip_message_bytes(raw.as_bytes()).expect("the request parses");
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

    pub(super) fn caller_acks(&self, relayed_200: &SipMessage, answer: Option<&str>) {
        let (inbound, message) = self.caller_request("ACK", "1 ACK", relayed_200, answer);
        handle_request(inbound, message, "ACK".to_string(), &self.state);
    }

    pub(super) fn call_is_up(&self) -> bool {
        self.state.call_actors.get_call(&self.call_id).is_some()
    }

    /// Wait until the engine has been sent `count` `delete`s.
    pub(super) async fn deleted(&self, count: usize) {
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while self.engine.commands("delete").len() < count {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the engine was told to delete the call");
    }
}

fn park(state: &DispatcherState) -> String {
    let call_id = state.call_actors.create_call(Leg::new_a_leg(
        CALLER_CALL_ID.into(),
        "caller-tag".into(),
        "z9hG4bK-delayed".into(),
        LegTransport {
            remote_addr: address(CALLER),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: None,
        },
    ));
    state.call_actors.set_a_leg_invite(
        &call_id,
        Arc::new(std::sync::Mutex::new(offerless_invite())),
    );
    call_id
}

pub(super) fn to_phone(sent: &[Sent]) -> Vec<&Sent> {
    sent.iter()
        .filter(|sent| sent.destination == address(PHONE))
        .collect()
}

pub(super) fn to_caller(sent: &[Sent]) -> Vec<&Sent> {
    sent.iter()
        .filter(|sent| sent.destination == address(CALLER))
        .collect()
}

pub(super) fn relayed_200(sent: &[Sent]) -> SipMessage {
    to_caller(sent)
        .into_iter()
        .find(|sent| sent.message.status_code() == Some(200))
        .expect("the 2xx was relayed to the caller")
        .message
        .clone()
}

/// The phone's INVITE carries no offer and nothing is allocated yet: there is
/// no SDP to anchor until the phone offers in its 2xx.
#[tokio::test(flavor = "multi_thread")]
async fn a_profiled_dial_on_a_delayed_offer_relays_the_invite_offerless() {
    let dial = DelayedDial::dial(&[PHONE], "rtp_to_srtp").await;
    assert_eq!(dial.invites.len(), 1, "the phone is rung");
    assert!(
        dial.invites[0].body.is_empty(),
        "the phone's INVITE carries no offer either (RFC 3261 §13.2.1)"
    );
    assert!(
        dial.engine.all_commands().is_empty(),
        "nothing to anchor yet"
    );
    assert_eq!(dial.sessions.len(), 0);
    assert!(
        dial.wire()
            .iter()
            .all(|sent| sent.destination != address(CALLER)),
        "the caller stays unanswered"
    );
}

/// The phone's offer is anchored under the `answer` half (the half that faces
/// the caller) and the engine's offer is the caller's 2xx. The phone's ACK waits
/// for the caller's answer.
#[tokio::test(flavor = "multi_thread")]
async fn the_phones_offer_is_anchored_and_the_engines_offer_answers_the_caller() {
    let dial = DelayedDial::dial(&[PHONE], "rtp_to_srtp").await;
    dial.phone_answers_with_an_offer();

    let offers = dial.engine.commands("offer");
    assert_eq!(offers.len(), 1, "the phone's offer is anchored once");
    assert_eq!(offers[0].from_tag.as_deref(), Some("phone-tag"));
    assert_eq!(offers[0].sdp.as_deref(), Some(PHONE_OFFER));
    assert_eq!(
        offers[0].transport_protocol.as_deref(),
        Some("RTP/AVP"),
        "shaped for the caller by the profile's answer half"
    );
    assert_ne!(
        offers[0].call_id.as_deref(),
        Some(CALLER_CALL_ID),
        "an engine call-id of its own, so a failed dial cannot delete a later anchor"
    );

    let sent = dial.wire();
    let caller_200 = relayed_200(&sent);
    assert!(
        body_text(&caller_200).contains("c=IN IP4 203.0.113.50"),
        "the caller's 2xx carries the engine's offer, never the phone's address:\n{}",
        body_text(&caller_200)
    );
    assert!(
        to_phone(&sent).iter().all(|sent| !sent.is(Method::Ack)),
        "the phone's ACK waits for the caller's answer (RFC 3261 §13.2.2.4)"
    );
    let session = dial
        .sessions
        .get(CALLER_CALL_ID)
        .expect("the media session");
    assert_eq!(session.from_tag, "phone-tag");
    assert_eq!(session.to_tag, None);
    assert_eq!(session.profile, "rtp_to_srtp");
}

/// The caller's answer completes the engine exchange and the phone's ACK carries
/// what the engine returns for it, shaped by the `offer` half.
#[tokio::test(flavor = "multi_thread")]
async fn the_callers_answer_in_its_ack_completes_the_exchange_and_goes_to_the_phone_through_the_engine(
) {
    let dial = DelayedDial::dial(&[PHONE], "rtp_to_srtp").await;
    dial.phone_answers_with_an_offer();
    let caller_200 = relayed_200(&dial.wire());

    dial.caller_acks(&caller_200, Some(CALLER_ANSWER));
    let sent = dial.wire();
    let acks: Vec<&Sent> = to_phone(&sent)
        .into_iter()
        .filter(|sent| sent.is(Method::Ack))
        .collect();
    assert_eq!(acks.len(), 1, "the phone is ACKed once");
    let answer = body_text(&acks[0].message);
    assert!(answer.contains("c=IN IP4 203.0.113.50"), "{answer}");
    assert!(
        !answer.contains("192.0.2.10"),
        "the caller's own address never reaches the phone:\n{answer}"
    );

    let answers = dial.engine.commands("answer");
    assert_eq!(answers.len(), 1);
    assert_eq!(answers[0].from_tag.as_deref(), Some("phone-tag"));
    assert_eq!(answers[0].to_tag.as_deref(), Some("caller-tag"));
    assert_eq!(answers[0].sdp.as_deref(), Some(CALLER_ANSWER));
    assert_eq!(
        answers[0].transport_protocol.as_deref(),
        Some("RTP/SAVP"),
        "shaped for the phone by the profile's offer half"
    );
    assert!(dial.call_is_up());
    let session = dial
        .sessions
        .get(CALLER_CALL_ID)
        .expect("the media session");
    assert_eq!(session.to_tag.as_deref(), Some("phone-tag"), "answered");
}

/// An ACK that carries no answer (RFC 3264 §4): the call is ended, the phone is
/// ACKed with its stream rejected and BYEd, the caller is BYEd, and the engine
/// call is deleted.
#[tokio::test(flavor = "multi_thread")]
async fn an_ack_with_no_answer_ends_the_call_and_frees_the_media() {
    let dial = DelayedDial::dial(&[PHONE], "rtp_to_srtp").await;
    dial.phone_answers_with_an_offer();
    let caller_200 = relayed_200(&dial.wire());

    dial.caller_acks(&caller_200, None);
    let sent = dial.wire();
    let phone = to_phone(&sent);
    assert!(phone.iter().any(|sent| sent.is(Method::Ack)));
    assert!(phone.iter().any(|sent| sent.is(Method::Bye)));
    assert!(to_caller(&sent).iter().any(|sent| sent.is(Method::Bye)));
    assert!(!dial.call_is_up());
    dial.deleted(1).await;
    assert_eq!(dial.sessions.len(), 0, "the media is released");
}

/// A caller that never ACKs: at 64*T1 the call ends with a BYE to both parties,
/// the engine call is deleted and nothing is left held.
#[tokio::test(flavor = "multi_thread")]
async fn a_caller_that_never_acks_ends_the_call_at_timer_h_and_frees_the_media() {
    let dial = DelayedDial::dial(&[PHONE], "rtp_to_srtp").await;
    dial.phone_answers_with_an_offer();
    dial.wire();

    // 64*T1 elapsed: re-arm the caller's 2xx with a deadline already past.
    let keys: Vec<String> = dial
        .state
        .uas_2xx_retransmits
        .iter()
        .map(|entry| entry.key().clone())
        .collect();
    assert_eq!(keys.len(), 1, "the caller's 2xx waits for its ACK");
    for key in keys {
        let (_, armed) = dial.state.uas_2xx_retransmits.remove(&key).expect("armed");
        armed.cancel.notify_one();
        dial.state.uas_2xx_retransmits.insert(
            key,
            Arc::new(UnackedAnswer {
                cancel: tokio::sync::Notify::new(),
                deadline: tokio::time::Instant::now() - std::time::Duration::from_secs(1),
                internal_call_id: armed.internal_call_id.clone(),
            }),
        );
    }
    tokio::task::block_in_place(|| sweep_unacked_uas_2xx(&dial.state));

    let sent = dial.wire();
    assert!(to_caller(&sent).iter().any(|sent| sent.is(Method::Bye)));
    assert!(to_phone(&sent).iter().any(|sent| sent.is(Method::Bye)));
    assert!(!dial.call_is_up());
    dial.deleted(1).await;
    assert_eq!(dial.sessions.len(), 0);
    assert!(dial.state.uas_2xx_retransmits.is_empty());
}

/// The caller cancels while the phone rings: nothing was allocated, nothing is
/// left, and the phone is cancelled.
#[tokio::test(flavor = "multi_thread")]
async fn a_cancel_before_the_phone_answers_leaves_no_media_behind() {
    let dial = DelayedDial::dial(&[PHONE], "rtp_to_srtp").await;
    let invite = dial.invites[0].clone();
    dial.phone_sends(&invite, dial.phone_response(&invite, "180 Ringing", ""));
    assert!(report_control_dial_failure(
        &dial.call_id,
        487,
        "Request Terminated",
        false,
        &dial.state
    ));
    assert_eq!(dial.sessions.len(), 0);
    assert!(dial.engine.commands("offer").is_empty());
}

/// An offer in an unreliable 18x cannot be answered by a caller that has not
/// been given one: the SDP is dropped and the provisional is relayed as ringing.
#[tokio::test(flavor = "multi_thread")]
async fn an_offer_in_an_unreliable_provisional_is_not_anchored_and_not_relayed() {
    let dial = DelayedDial::dial(&[PHONE], "rtp_to_srtp").await;
    let invite = dial.invites[0].clone();
    dial.phone_sends(
        &invite,
        dial.phone_response(&invite, "183 Session Progress", PHONE_OFFER),
    );
    let sent = dial.wire();
    let progress = to_caller(&sent)
        .into_iter()
        .find(|sent| sent.message.status_code() == Some(183))
        .expect("the progress is relayed to the caller");
    assert!(
        progress.message.body.is_empty(),
        "the phone's offer is not shown to a caller that has to offer first"
    );
    assert!(dial.engine.commands("offer").is_empty());
    assert_eq!(dial.sessions.len(), 0);
    assert!(dial.call_is_up());
}

/// A reliable provisional with an offer needs an answer in the PRACK that the
/// caller cannot give: the dial fails with a media error and the branch is
/// cancelled, as any media failure on a profiled dial.
#[tokio::test(flavor = "multi_thread")]
async fn an_offer_in_a_reliable_provisional_fails_the_dial_without_anchoring_it() {
    let dial = DelayedDial::dial(&[PHONE], "rtp_to_srtp").await;
    let invite = dial.invites[0].clone();
    let mut response = dial.phone_response(&invite, "183 Session Progress", PHONE_OFFER);
    response.headers.set("Require", "100rel".to_string());
    response.headers.set("RSeq", "1".to_string());
    dial.phone_sends(&invite, response);
    let sent = dial.wire();
    assert!(
        to_caller(&sent)
            .iter()
            .all(|sent| sent.message.status_code() != Some(183)),
        "the offer is not relayed"
    );
    assert!(to_phone(&sent).iter().any(|sent| sent.is(Method::Cancel)));
    assert!(dial.engine.commands("offer").is_empty());
    assert_eq!(dial.sessions.len(), 0);
}

/// A ring group: every phone is rung offerless, whichever answers is anchored
/// and the others are not.
#[tokio::test(flavor = "multi_thread")]
async fn a_fork_anchors_only_the_phone_that_answers() {
    let dial = DelayedDial::dial(&[PHONE, "198.51.100.8:5060"], "rtp_to_srtp").await;
    assert_eq!(dial.invites.len(), 2);
    assert!(dial.invites.iter().all(|invite| invite.body.is_empty()));
    let winner = dial.invites[1].clone();
    let mut response = dial.phone_response(&winner, "200 OK", PHONE_OFFER);
    response
        .headers
        .set("Contact", "<sip:201@198.51.100.8:5060>".to_string());
    let status_code = 200;
    assert!(handle_b2bua_response(
        &dial.call_id,
        &top_via_branch(&winner),
        &mut response,
        status_code,
        address("198.51.100.8:5060"),
        &dial.state,
    ));
    assert_eq!(dial.engine.commands("offer").len(), 1);
    assert!(body_text(&relayed_200(&dial.wire())).contains("c=IN IP4 203.0.113.50"));
    assert_eq!(dial.sessions.len(), 1);
}

/// A phone that answers an offerless INVITE without an offer has nothing to
/// anchor: the dial fails, nothing is sent to the caller as an answer.
#[tokio::test(flavor = "multi_thread")]
async fn a_phone_that_answers_with_no_offer_fails_the_dial() {
    let dial = DelayedDial::dial(&[PHONE], "rtp_to_srtp").await;
    let invite = dial.invites[0].clone();
    dial.phone_sends(&invite, dial.phone_response(&invite, "200 OK", ""));
    let sent = dial.wire();
    assert!(
        to_caller(&sent)
            .iter()
            .all(|sent| sent.message.status_code() != Some(200)),
        "no 2xx without an offer is relayed"
    );
    assert_eq!(dial.sessions.len(), 0);
}

/// The engine refusing the caller's answer leaves the phone's anchored offer
/// with no answer to give: the call ends and the media is released.
#[tokio::test(flavor = "multi_thread")]
async fn the_engine_refusing_the_callers_answer_ends_the_call() {
    let dial = DelayedDial::dial_refusing_answers(&[PHONE], "rtp_to_srtp").await;
    dial.phone_answers_with_an_offer();
    let caller_200 = relayed_200(&dial.wire());
    dial.caller_acks(&caller_200, Some(CALLER_ANSWER));
    let sent = dial.wire();
    assert!(to_phone(&sent).iter().any(|sent| sent.is(Method::Bye)));
    assert!(to_caller(&sent).iter().any(|sent| sent.is(Method::Bye)));
    assert!(!dial.call_is_up());
    dial.deleted(1).await;
    assert_eq!(dial.sessions.len(), 0);
}

/// The two ends of the call's life leave nothing behind: N dials that complete
/// and N that fail all drain the media store, the held ACKs and the engine.
#[tokio::test(flavor = "multi_thread")]
async fn completed_and_failed_delayed_offer_dials_drain_to_baseline() {
    const CALLS: usize = 8;
    for completed in [true, false] {
        for _ in 0..CALLS {
            let dial = DelayedDial::dial(&[PHONE], "rtp_to_srtp").await;
            dial.phone_answers_with_an_offer();
            let caller_200 = relayed_200(&dial.wire());
            if completed {
                dial.caller_acks(&caller_200, Some(CALLER_ANSWER));
                dial.wire();
                b2bua_terminate_call_inner(&dial.call_id, None, "b2bua", &dial.state);
            } else {
                dial.caller_acks(&caller_200, None);
            }
            dial.wire();
            dial.deleted(1).await;
            assert_eq!(dial.sessions.len(), 0, "completed={completed}");
            assert!(!dial.call_is_up(), "completed={completed}");
            assert!(dial.state.held_byes.is_empty(), "completed={completed}");
        }
    }
}

/// A re-INVITE with no SDP on the connected call (RFC 3261 §14.2, §13.2.1): the
/// 200 offers, from the session in force toward the caller, and the ACK answers
/// it. Nothing goes to the phone and the engine is not asked: the session does
/// not change, and a phone's own offer relayed to the caller would be taken to
/// the engine as an answer to nothing.
#[tokio::test(flavor = "multi_thread")]
async fn an_offerless_reinvite_after_a_delayed_offer_dial_is_answered_from_the_session_in_force() {
    let dial = DelayedDial::dial(&[PHONE], "rtp_to_srtp").await;
    dial.phone_answers_with_an_offer();
    let caller_200 = relayed_200(&dial.wire());
    dial.caller_acks(&caller_200, Some(CALLER_ANSWER));
    dial.wire();
    let engine_commands = dial.engine.all_commands().len();

    let (arrived, reinvite) = dial.caller_request("INVITE", "2 INVITE", &caller_200, None);
    handle_b2bua_reinvite(arrived, reinvite, &dial.state);
    let sent = dial.wire();
    assert!(
        to_phone(&sent).is_empty(),
        "the refresh is not relayed to the phone"
    );
    let refreshed = relayed_200(&sent);
    assert_eq!(
        body_text(&refreshed),
        body_text(&caller_200),
        "the 200 offers the media the caller already holds"
    );
    assert_eq!(
        dial.engine.all_commands().len(),
        engine_commands,
        "the engine is not asked"
    );

    // The caller answers in its ACK; that changes nothing on the phone's side.
    let (inbound, ack) = dial.caller_request("ACK", "2 ACK", &refreshed, Some(CALLER_ANSWER));
    handle_request(inbound, ack, "ACK".to_string(), &dial.state);
    assert!(to_phone(&dial.wire()).is_empty());
    assert!(dial.call_is_up());
}

/// The `200` to an offerless re-INVITE repeats the session in force, which is
/// a new offer (RFC 3261 §14.1, RFC 3264 §4): the caller's ACK answers it, and
/// where that answer moved the caller's media the engine has to be told.
#[tokio::test(flavor = "multi_thread")]
async fn the_acks_answer_to_an_offerless_refresh_reaches_the_engine() {
    let dial = DelayedDial::dial(&[PHONE], "rtp_to_srtp").await;
    dial.phone_answers_with_an_offer();
    let caller_200 = relayed_200(&dial.wire());
    dial.caller_acks(&caller_200, Some(CALLER_ANSWER));
    dial.wire();
    let (arrived, reinvite) = dial.caller_request("INVITE", "2 INVITE", &caller_200, None);
    handle_b2bua_reinvite(arrived, reinvite, &dial.state);
    let refreshed = relayed_200(&dial.wire());
    let offers = dial.engine.commands("offer").len();

    let moved = CALLER_ANSWER.replace("m=audio 40000", "m=audio 41000");
    let (inbound, ack) = dial.caller_request("ACK", "2 ACK", &refreshed, Some(&moved));
    handle_request(inbound, ack, "ACK".to_string(), &dial.state);

    let after = dial.engine.commands("offer");
    assert_eq!(
        after.len(),
        offers + 1,
        "the engine is told the caller's new media"
    );
    assert_eq!(after[offers].sdp.as_deref(), Some(moved.as_str()));
    assert_eq!(after[offers].from_tag.as_deref(), Some("caller-tag"));
    assert!(
        to_phone(&dial.wire()).is_empty(),
        "nothing is relayed to the phone"
    );
    assert!(dial.call_is_up());

    // A retransmitted ACK has nothing left to answer.
    let (inbound, ack) = dial.caller_request("ACK", "2 ACK", &refreshed, Some(&moved));
    handle_request(inbound, ack, "ACK".to_string(), &dial.state);
    assert_eq!(dial.engine.commands("offer").len(), offers + 1);
}

/// An ACK that answers the refresh's offer with nothing breaks the exchange
/// (RFC 3264 §4): the call is ended and the engine call deleted.
#[tokio::test(flavor = "multi_thread")]
async fn an_ack_with_no_answer_to_an_offerless_refresh_ends_the_call() {
    let dial = DelayedDial::dial(&[PHONE], "rtp_to_srtp").await;
    dial.phone_answers_with_an_offer();
    let caller_200 = relayed_200(&dial.wire());
    dial.caller_acks(&caller_200, Some(CALLER_ANSWER));
    dial.wire();
    let (arrived, reinvite) = dial.caller_request("INVITE", "2 INVITE", &caller_200, None);
    handle_b2bua_reinvite(arrived, reinvite, &dial.state);
    let refreshed = relayed_200(&dial.wire());

    let (inbound, ack) = dial.caller_request("ACK", "2 ACK", &refreshed, None);
    handle_request(inbound, ack, "ACK".to_string(), &dial.state);

    assert!(
        to_caller(&dial.wire())
            .iter()
            .any(|sent| sent.is(Method::Bye)),
        "the caller is sent a BYE"
    );
    dial.deleted(1).await;
    assert!(!dial.call_is_up());
}

/// A connected delayed-offer dial whose caller has sent an offerless re-INVITE
/// (`cseq`), and the `200` siphon answered it with. The wire is drained.
pub(super) async fn refreshed_dial(cseq: &str) -> (DelayedDial, SipMessage, SipMessage) {
    let dial = DelayedDial::dial(&[PHONE], "rtp_to_srtp").await;
    dial.phone_answers_with_an_offer();
    let caller_200 = relayed_200(&dial.wire());
    dial.caller_acks(&caller_200, Some(CALLER_ANSWER));
    dial.wire();
    let refreshed = dial.refresh(cseq, &caller_200);
    (dial, caller_200, refreshed)
}

impl DelayedDial {
    /// The caller's offerless re-INVITE (`cseq`, as `"3 INVITE"`); returns the
    /// `200` siphon answers it with.
    pub(super) fn refresh(&self, cseq: &str, caller_200: &SipMessage) -> SipMessage {
        let (arrived, reinvite) = self.caller_request("INVITE", cseq, caller_200, None);
        handle_b2bua_reinvite(arrived, reinvite, &self.state);
        relayed_200(&self.wire())
    }
}
