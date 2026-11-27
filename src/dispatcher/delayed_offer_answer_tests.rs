//! An anchored `answer` on a caller's INVITE with no SDP (RFC 3261 §13.2.1):
//! the media engine makes the offer (`offer_local`), siphon puts it in its 2xx,
//! and the caller's answer in its ACK completes the engine call (`answer`).
//!
//! Driven through the dispatcher on the in-process native engine, with every
//! frame siphon sends read back off the UDP egress and every command the engine
//! was sent read off its log.

use super::dial_bridge_test_harness::caller_invite;
use super::originate_test_harness::{anchored_dispatcher, drain, socket, Sent};
use super::*;
use crate::rtpengine::test_native_engine::{
    NativeTestEngine, NATIVE_ENGINE_ANSWER_REFUSALS, NATIVE_ENGINE_LOCAL_OFFER,
};

const CALLER: &str = "192.0.2.40:5060";
const CALLER_ANSWER: &str = concat!(
    "v=0\r\n",
    "o=caller 3 3 IN IP4 192.0.2.40\r\n",
    "s=-\r\n",
    "c=IN IP4 192.0.2.40\r\n",
    "t=0 0\r\n",
    "m=audio 40000 RTP/AVP 0 101\r\n",
    "a=rtpmap:0 PCMU/8000\r\n",
    "a=rtpmap:101 telephone-event/8000\r\n",
);

/// A caller whose INVITE carries no SDP, parked on a dispatcher whose media
/// is `engine`.
pub(super) struct OfferlessCall {
    pub(super) state: Arc<DispatcherState>,
    pub(super) udp: flume::Receiver<OutboundMessage>,
    pub(super) engine: Arc<NativeTestEngine>,
    pub(super) call_id: String,
    pub(super) sip_call_id: String,
    pub(super) invite: SipMessage,
}

impl OfferlessCall {
    pub(super) fn park(engine: NativeTestEngine, sip_call_id: &str) -> OfferlessCall {
        Self::park_on(&Arc::new(engine), sip_call_id)
    }

    /// A caller parked on a dispatcher of its own whose media is the shared
    /// `engine`.
    pub(super) fn park_on(engine: &Arc<NativeTestEngine>, sip_call_id: &str) -> OfferlessCall {
        let dispatcher = anchored_dispatcher(engine);
        let udp = dispatcher.udp.clone();
        let state = Arc::new(dispatcher.state);
        let mut invite = caller_invite(sip_call_id, CALLER);
        invite.body.clear();
        invite.headers.remove("Content-Type");
        invite.headers.set("Content-Length", "0".to_string());
        let mut leg = Leg::new_a_leg(
            sip_call_id.to_string(),
            "caller-tag".to_string(),
            format!("z9hG4bK-{sip_call_id}"),
            LegTransport {
                remote_addr: socket(CALLER),
                connection_id: ConnectionId::default(),
                transport: Transport::Udp,
                local_addr: None,
            },
        );
        leg.dialog.local_contact = Some("<sip:192.0.2.1:5060;transport=udp>".to_string());
        let call_id = state.call_actors.create_call(leg);
        state
            .call_actors
            .set_a_leg_invite(&call_id, Arc::new(std::sync::Mutex::new(invite.clone())));
        OfferlessCall {
            state,
            udp,
            engine: Arc::clone(engine),
            call_id,
            sip_call_id: sip_call_id.to_string(),
            invite,
        }
    }

    /// The controller's anchored `answer`.
    pub(super) fn answer(&self, profile: &str, ws_uri: Option<&str>) -> Result<(), String> {
        answer_first_anchor(
            &self.call_id,
            &self.invite,
            socket(CALLER).ip(),
            200,
            "OK",
            Some(profile),
            ws_uri,
            None,
            &[],
            &self.state,
        )
    }

    pub(super) fn wire(&self) -> Vec<Sent> {
        drain(&self.udp)
    }

    /// The 2xx siphon sent the caller.
    pub(super) fn two_xx(&self) -> SipMessage {
        self.wire()
            .into_iter()
            .find(|sent| sent.message.status_code() == Some(200))
            .expect("siphon sent the 2xx")
            .message
    }

    /// The caller's request in the dialog the 2xx established.
    pub(super) fn caller_request(&self, method: &str, two_xx: &SipMessage, body: Option<&str>) {
        let mut raw = format!(
            concat!(
                "{method} sip:192.0.2.1:5060;transport=udp SIP/2.0\r\n",
                "Via: SIP/2.0/UDP 192.0.2.40:5060;branch=z9hG4bK-caller-{branch}\r\n",
                "Max-Forwards: 70\r\n",
                "From: {from}\r\n",
                "To: {to}\r\n",
                "Call-ID: {call_id}\r\n",
                "CSeq: {cseq} {method}\r\n",
                "Contact: <sip:15550100001@192.0.2.40:5060>\r\n",
            ),
            method = method,
            branch = uuid::Uuid::new_v4().simple(),
            from = two_xx.headers.from().expect("a From"),
            to = two_xx.headers.to().expect("a To"),
            call_id = self.sip_call_id,
            cseq = if method == "ACK" { 1 } else { 2 },
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
            local_addr: socket("192.0.2.1:5060"),
            remote_addr: socket(CALLER),
            data: Bytes::from(raw),
        };
        // Where the request path hands a BYE for a B2BUA call over.
        match method {
            "BYE" => tokio::task::block_in_place(|| {
                handle_b2bua_bye(inbound, message, &self.state);
            }),
            _ => handle_request(inbound, message, method.to_string(), &self.state),
        }
    }

    pub(super) fn acks(&self, two_xx: &SipMessage, answer: Option<&str>) {
        self.caller_request("ACK", two_xx, answer);
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

fn to_tag(message: &SipMessage) -> String {
    crate::sip::headers::nameaddr::NameAddr::parse(message.headers.to().expect("a To"))
        .ok()
        .and_then(|to| to.tag)
        .expect("the 2xx carries a To tag")
}

/// The caller's INVITE carries no offer, so the 2xx carries the engine's.
#[tokio::test(flavor = "multi_thread")]
async fn an_offerless_invite_is_answered_with_the_engines_offer_in_the_2xx() {
    let call = OfferlessCall::park(NativeTestEngine::start_with_offer_local().await, "dly-1");
    call.answer("rtp_passthrough", None).expect("answered");
    let two_xx = call.two_xx();
    assert_eq!(
        String::from_utf8(two_xx.body.clone()).expect("an SDP"),
        NATIVE_ENGINE_LOCAL_OFFER
    );
    let offers = call.engine.commands("offer_local");
    assert_eq!(offers.len(), 1);
    assert_eq!(offers[0].call_id, "dly-1");
    assert_eq!(offers[0].from_tag, "caller-tag");
    assert_eq!(offers[0].sip_call_id.as_deref(), Some("dly-1"));
    assert!(call.engine.commands("answer_local").is_empty());
    assert!(
        call.engine.commands("answer").is_empty(),
        "nothing to answer until the ACK"
    );
    assert_eq!(call.state.call_actors.pending_local_offer_count(), 1);
}

/// The ACK's SDP reaches `answer` with the caller's tag and the 2xx's.
#[tokio::test(flavor = "multi_thread")]
async fn the_acks_answer_completes_the_engine_call_with_the_right_tags() {
    let call = OfferlessCall::park(NativeTestEngine::start_with_offer_local().await, "dly-2");
    call.answer("rtp_passthrough", None).expect("answered");
    let two_xx = call.two_xx();
    call.acks(&two_xx, Some(CALLER_ANSWER));
    let answers = call.engine.commands("answer");
    assert_eq!(answers.len(), 1);
    assert_eq!(answers[0].call_id, "dly-2");
    assert_eq!(answers[0].from_tag, "caller-tag");
    assert_eq!(answers[0].detail.as_deref(), Some(to_tag(&two_xx).as_str()));
    assert!(!answers[0].refused);
    assert_eq!(call.state.call_actors.pending_local_offer_count(), 0);
    assert_eq!(call.engine.offer_local_pending_count(), 0);
    assert!(call.call_is_up(), "the call carries on");
    assert!(
        call.engine.commands("delete").is_empty(),
        "nothing is torn down"
    );
    // It behaves as an answer_local call from here on: the engine's offer is
    // the session description in force, for a callee dialled behind it.
    let sessions = call.state.rtpengine_sessions.as_ref().expect("sessions");
    assert_eq!(
        sessions.local_answer("dly-2").as_deref(),
        Some(NATIVE_ENGINE_LOCAL_OFFER)
    );
    // A retransmitted ACK completes nothing twice.
    call.acks(&two_xx, Some(CALLER_ANSWER));
    assert_eq!(call.engine.commands("answer").len(), 1);
}

/// The caller's answer is the SDP its leg holds from here on, which a later
/// `bridge` reads: its INVITE had none to keep.
#[tokio::test(flavor = "multi_thread")]
async fn the_acks_answer_is_kept_as_the_callers_sdp_and_a_bridge_can_read_it() {
    let call = OfferlessCall::park(NativeTestEngine::start_with_offer_local().await, "dly-9");
    call.answer("rtp_passthrough", None).expect("answered");
    let two_xx = call.two_xx();
    call.acks(&two_xx, Some(CALLER_ANSWER));
    let leg = crate::dispatcher::bridge_leg_snapshot(&call.state, "dly-9", "anchor")
        .expect("the leg resolves");
    assert_eq!(leg.last_sdp, CALLER_ANSWER.as_bytes());
    crate::dispatcher::bridge_leg_validate(&leg).expect("the leg can be bridged");
}

/// Every answer the engine refuses ends the call and deletes its engine call,
/// which the refusal left pending.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_answer_sends_a_bye_and_deletes_the_engine_call() {
    for token in NATIVE_ENGINE_ANSWER_REFUSALS {
        let call = OfferlessCall::park(
            NativeTestEngine::start_with_offer_local().await,
            &format!("dly-refused-{token}"),
        );
        call.answer("rtp_passthrough", None).expect("answered");
        let two_xx = call.two_xx();
        let refused = format!("{CALLER_ANSWER}a=x-test-answer-{token}\r\n");
        call.acks(&two_xx, Some(&refused));
        let answers = call.engine.commands("answer");
        assert_eq!(answers.len(), 1, "{token}");
        assert!(!answers[0].refused, "{token}: the engine knew the call");
        call.deleted(1).await;
        let wire = call.wire();
        let bye = wire
            .iter()
            .find(|sent| sent.message.method() == Some(&Method::Bye))
            .unwrap_or_else(|| panic!("{token}: the caller is sent a BYE"));
        assert_eq!(bye.destination, socket(CALLER), "{token}");
        assert_eq!(call.engine.offer_local_pending_count(), 0, "{token}");
        assert!(!call.call_is_up(), "{token}");
        assert_eq!(call.state.call_actors.pending_local_offer_count(), 0);
    }
}

/// An ACK that answers nothing breaks the exchange (RFC 3264 §4): BYE, delete,
/// and no `answer` sent.
#[tokio::test(flavor = "multi_thread")]
async fn an_ack_with_no_sdp_sends_a_bye_and_deletes_the_engine_call() {
    let call = OfferlessCall::park(NativeTestEngine::start_with_offer_local().await, "dly-3");
    call.answer("rtp_passthrough", None).expect("answered");
    let two_xx = call.two_xx();
    call.acks(&two_xx, None);
    assert!(call.engine.commands("answer").is_empty());
    call.deleted(1).await;
    let wire = call.wire();
    assert!(
        wire.iter()
            .any(|sent| sent.message.method() == Some(&Method::Bye)
                && sent.destination == socket(CALLER)),
        "the caller is sent a BYE"
    );
    assert_eq!(call.engine.offer_local_pending_count(), 0);
    assert!(!call.call_is_up());
}

/// An engine that does not list `offer_local` cannot make the offer: the answer
/// is refused (a control `answer` replies `unavailable` with this message), no
/// 2xx goes out, nothing reaches the engine and the call stays parked.
#[tokio::test(flavor = "multi_thread")]
async fn an_engine_without_offer_local_refuses_the_answer_clearly() {
    let call = OfferlessCall::park(NativeTestEngine::start().await, "dly-4");
    let refusal = call.answer("rtp_passthrough", None).expect_err("refused");
    assert!(
        refusal.contains("no SDP") && refusal.contains("offer_local"),
        "{refusal}"
    );
    assert!(call.wire().is_empty(), "no 2xx");
    assert!(call.engine.commands("offer_local").is_empty());
    assert!(call.engine.commands("answer_local").is_empty());
    assert!(call.call_is_up(), "the call is still parked");
    assert_eq!(call.state.call_actors.pending_local_offer_count(), 0);
    let sessions = call.state.rtpengine_sessions.as_ref().expect("sessions");
    assert!(sessions.get("dly-4").is_none());
}

/// Early media would put the offer in an 18x, which only a PRACK could answer.
#[tokio::test(flavor = "multi_thread")]
async fn early_media_on_an_offerless_invite_is_refused() {
    let call = OfferlessCall::park(NativeTestEngine::start_with_offer_local().await, "dly-5");
    let refusal = anchor_a_leg(
        &call.invite,
        socket(CALLER).ip(),
        Some("rtp_passthrough"),
        None,
        None,
        &call.state,
    )
    .expect_err("refused");
    assert!(refusal.contains("no SDP"), "{refusal}");
    assert!(call.engine.commands("offer_local").is_empty());
}

/// A bot takeover on an offerless INVITE: the `ws_uri` rides in the
/// `offer_local` profile and the engine dials the bot when the answer arrives.
/// A second attach would re-point a live takeover and dial the bot twice, so
/// the bot is named exactly once and no attach is sent.
#[tokio::test(flavor = "multi_thread")]
async fn a_ws_uri_takeover_dials_the_bot_once_with_the_answer() {
    let call = OfferlessCall::park(NativeTestEngine::start_with_offer_local().await, "dly-6");
    call.answer("voice_ai", Some("wss://bot.example.net/stream"))
        .expect("answered");
    let offers = call.engine.commands("offer_local");
    assert_eq!(offers.len(), 1);
    assert_eq!(
        offers[0].ws_uri.as_deref(),
        Some("wss://bot.example.net/stream"),
        "the takeover is in the offer's profile"
    );
    let two_xx = call.two_xx();
    call.acks(&two_xx, Some(CALLER_ANSWER));
    let answers = call.engine.commands("answer");
    assert_eq!(answers.len(), 1);
    assert_eq!(answers[0].ws_uri, None, "the answer does not name it again");
    assert!(call.engine.commands("attach_ws_bridge").is_empty());
    let naming_the_bot = call
        .engine
        .all_commands()
        .into_iter()
        .filter(|command| command.ws_uri.is_some())
        .count();
    assert_eq!(naming_the_bot, 1, "the bot is dialled exactly once");
    // No far side behind a takeover.
    let sessions = call.state.rtpengine_sessions.as_ref().expect("sessions");
    assert!(sessions.local_answer("dly-6").is_none());
}

/// The caller hanging up before its ACK ends the call and deletes the engine
/// call; nothing stays pending.
#[tokio::test(flavor = "multi_thread")]
async fn a_caller_that_hangs_up_before_its_ack_leaves_nothing_behind() {
    let call = OfferlessCall::park(NativeTestEngine::start_with_offer_local().await, "dly-7");
    call.answer("rtp_passthrough", None).expect("answered");
    let two_xx = call.two_xx();
    call.caller_request("BYE", &two_xx, None);
    call.deleted(1).await;
    assert!(call.engine.commands("answer").is_empty());
    assert_eq!(call.state.call_actors.pending_local_offer_count(), 0);
    assert_eq!(call.engine.offer_local_pending_count(), 0);
    assert!(!call.call_is_up());
}

/// A verb that needs the engine call waits for the answer, and is woken when
/// the ACK has applied it.
#[tokio::test(flavor = "multi_thread")]
async fn a_verb_waits_for_the_answer_and_is_woken_by_the_ack() {
    let call = OfferlessCall::park(NativeTestEngine::start_with_offer_local().await, "dly-8");
    assert!(
        call.state
            .call_actors
            .pending_local_offer_wait(&call.call_id)
            .is_none(),
        "nothing pending before the answer"
    );
    call.answer("rtp_passthrough", None).expect("answered");
    let mut waiting = call
        .state
        .call_actors
        .pending_local_offer_wait(&call.call_id)
        .expect("the call waits for its answer");
    let two_xx = call.two_xx();
    let state = Arc::clone(&call.state);
    let call_id = call.call_id.clone();
    let woken = tokio::spawn(async move {
        let _ = waiting.changed().await;
        state
            .call_actors
            .pending_local_offer_wait(&call_id)
            .is_none()
    });
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    assert!(!woken.is_finished(), "still waiting for the ACK");
    call.acks(&two_xx, Some(CALLER_ANSWER));
    let answered = tokio::time::timeout(std::time::Duration::from_secs(2), woken)
        .await
        .expect("woken by the ACK")
        .expect("the waiter ran");
    assert!(answered);
}

/// Pending state drains: after calls that were answered, refused and never
/// ACKed, no call and no engine call is left waiting.
#[tokio::test(flavor = "multi_thread")]
async fn answered_refused_and_unacked_calls_drain_the_pending_state() {
    let engine = Arc::new(NativeTestEngine::start_with_offer_local().await);
    let calls: Vec<OfferlessCall> = (0..9)
        .map(|index| {
            let call = OfferlessCall::park_on(&engine, &format!("dly-leak-{index}"));
            call.answer("rtp_passthrough", None).expect("answered");
            call
        })
        .collect();
    assert_eq!(engine.offer_local_pending_count(), 9);
    for (index, call) in calls.iter().enumerate() {
        let two_xx = call.two_xx();
        match index % 3 {
            0 => call.acks(&two_xx, Some(CALLER_ANSWER)),
            1 => call.acks(
                &two_xx,
                Some(&format!(
                    "{CALLER_ANSWER}a=x-test-answer-{}\r\n",
                    NATIVE_ENGINE_ANSWER_REFUSALS[0]
                )),
            ),
            // The 64*T1 sweep, which ends a call whose 2xx was never ACKed.
            _ => {
                assert!(b2bua_unacked_answer_terminate(&call.call_id, &call.state));
            }
        }
    }
    // The answered calls are still up; end them as a caller does.
    for (index, call) in calls.iter().enumerate() {
        if index % 3 == 0 {
            assert!(call.call_is_up());
            assert!(b2bua_terminate_call_inner(
                &call.call_id,
                None,
                "b2bua",
                &call.state
            ));
        }
    }
    for call in &calls {
        assert_eq!(call.state.call_actors.pending_local_offer_count(), 0);
        assert!(!call.call_is_up());
    }
    // Every call's engine call was deleted, the pending ones too.
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        while engine.commands("delete").len() < 9 {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("every engine call was deleted");
    assert_eq!(engine.offer_local_pending_count(), 0);
}

/// A BYE that lands while the caller's answer is with the engine removes the
/// session. The answer then completes: nothing may be recorded for the call
/// that is gone.
#[tokio::test(flavor = "multi_thread")]
async fn a_bye_while_the_acks_answer_is_in_flight_leaves_no_orphan_record() {
    let call = Arc::new(OfferlessCall::park(
        NativeTestEngine::start_with_offer_local().await,
        "dly-race-4",
    ));
    call.answer("rtp_passthrough", None).expect("answered");
    let two_xx = call.two_xx();
    call.engine.hold_answers();
    let acking = {
        let call = Arc::clone(&call);
        let two_xx = two_xx.clone();
        tokio::task::spawn_blocking(move || call.acks(&two_xx, Some(CALLER_ANSWER)))
    };
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while call.engine.commands("answer").is_empty() {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the engine was sent the answer");
    call.caller_request("BYE", &two_xx, None);
    call.engine.release_answers();
    acking.await.expect("the ACK ran");
    let sessions = call.state.rtpengine_sessions.as_ref().expect("sessions");
    assert!(sessions.get("dly-race-4").is_none());
    assert!(
        sessions.local_answer("dly-race-4").is_none(),
        "no record is left for a call that is gone"
    );
    assert_eq!(call.state.call_actors.pending_local_offer_count(), 0);
}
