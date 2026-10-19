//! A dial behind an answer siphon already gave the caller in early media: the
//! media engine answered the caller itself (`answer_local`), siphon sent that
//! answer in its own 183, and the script then dials the callee.
//!
//! The caller's answer must never change (RFC 3261 §13.2.1, RFC 6337 §3.1.1,
//! RFC 3264 §8). So the callee is offered the engine's far leg, never the
//! caller's own offer, the callee's SDP goes to the engine as that leg's
//! answer, and every SDP the caller sees afterwards is the one it already has,
//! byte for byte. Read off the UDP egress and the commands an in-process native
//! engine records.

use super::lcr_ring_timeout_tests::{
    carrier_response, invite_to, summaries, top_via_branch, Sequence, CALLER, FIRST_CARRIER,
    SECOND_CARRIER,
};
use super::*;
use crate::rtpengine::test_native_engine::{
    NativeTestEngine, NATIVE_ENGINE_ANSWER, NATIVE_ENGINE_FAR_OFFER, NATIVE_ENGINE_UNOFFERED_CODEC,
};

const SIP_CALL_ID: &str = "lcr-policy@192.0.2.10";

const MARK_FAILURES: &str = r#"
from siphon import b2bua

@b2bua.on_failure
def failed(call, code, reason):
    seen = call.get_header("X-Test-Failures") or ""
    call.set_header("X-Test-Failures", seen + str(code) + ";")
"#;

/// The caller's offer.
const CALLER_OFFER: &str = concat!(
    "v=0\r\n",
    "o=caller 7 8 IN IP4 192.0.2.10\r\n",
    "s=-\r\n",
    "c=IN IP4 192.0.2.10\r\n",
    "t=0 0\r\n",
    "m=audio 40000 RTP/AVP 0 8 101\r\n",
    "a=rtpmap:101 telephone-event/8000\r\n",
    "a=sendrecv\r\n",
);

/// The callee's answer to the far offer, on a codec the offer listed.
const CALLEE_ANSWER: &str = concat!(
    "v=0\r\n",
    "o=callee 31 31 IN IP4 198.51.100.7\r\n",
    "s=-\r\n",
    "c=IN IP4 198.51.100.7\r\n",
    "t=0 0\r\n",
    "m=audio 46000 RTP/AVP 8 101\r\n",
    "a=rtpmap:8 PCMA/8000\r\n",
    "a=rtpmap:101 telephone-event/8000\r\n",
    "a=sendrecv\r\n",
);

/// A caller's call the engine answered itself, with `answer_local` on `engine`
/// and the session recorded as the script API records it.
async fn answered_locally(engine: &NativeTestEngine, script: &str) -> Sequence {
    let sequence = Sequence::new_call(script);
    {
        let mut invite = sequence.invite.lock().expect("the A-leg INVITE lock");
        invite.body = CALLER_OFFER.as_bytes().to_vec();
        invite
            .headers
            .set("Content-Type", "application/sdp".to_string());
        invite
            .headers
            .set("Content-Length", CALLER_OFFER.len().to_string());
    }
    let backend = engine.backend();
    let answer = backend
        .answer_local(
            SIP_CALL_ID,
            "caller-tag",
            CALLER_OFFER,
            &crate::rtpengine::profile::NgFlags::default(),
        )
        .await
        .expect("the engine answers the caller");
    let sessions = Arc::new(crate::rtpengine::MediaSessionStore::new());
    sessions.insert(crate::rtpengine::MediaSession {
        call_id: SIP_CALL_ID.to_string(),
        rtpengine_call_id: SIP_CALL_ID.to_string(),
        from_tag: "caller-tag".to_string(),
        to_tag: None,
        profile: "rtp_passthrough".to_string(),
        ws_uri: None,
        ws_tee: None,
        ws_bridge_attached: false,
        bridge_sides: None,
        created_at: std::time::Instant::now(),
    });
    sessions.record_local_answer(SIP_CALL_ID, &answer);
    sequence.with_media(backend, sessions)
}

impl Sequence {
    /// Put the engine and its session store on the dispatcher.
    fn with_media(
        mut self,
        backend: Arc<crate::rtpengine::MediaBackend>,
        sessions: Arc<crate::rtpengine::MediaSessionStore>,
    ) -> Sequence {
        self.dispatcher.state.rtpengine_set = Some(backend);
        self.dispatcher.state.rtpengine_profiles =
            Some(Arc::new(crate::rtpengine::ProfileRegistry::new()));
        self.dispatcher.state.rtpengine_sessions = Some(sessions);
        self
    }

    /// siphon sends the caller its own 183 carrying `body`.
    fn early_media(&self, body: &str) -> SipMessage {
        let state = &self.dispatcher.state;
        let invite = self.invite.lock().expect("the A-leg INVITE lock").clone();
        let sent = tokio::task::block_in_place(|| {
            send_uas_response(
                state,
                &self.call_id,
                &invite,
                183,
                "Session Progress",
                Some(body.as_bytes().to_vec()),
                Some("application/sdp"),
                false,
                &[],
            )
        });
        assert!(sent, "siphon's 183 went out");
        self.to_caller(183)
    }

    /// Dial the first carrier, as `call.dial()` does.
    fn dial(&self) {
        let reply_to = InboundMessage {
            client_transport: None,
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: "192.0.2.1:5060".parse().expect("a literal address"),
            remote_addr: CALLER.parse().expect("a literal address"),
            data: Bytes::new(),
        };
        let action = CallAction::Dial {
            target: format!("sip:15550100042@{FIRST_CARRIER}"),
            next_hop: Some(format!("sip:{FIRST_CARRIER}")),
            flow: None,
            route: Vec::new(),
            send_socket: None,
            timeout: 30,
        };
        tokio::task::block_in_place(|| {
            apply_routing_action(
                &self.call_id,
                action,
                &self.invite,
                &reply_to,
                &self.dispatcher.state,
            )
        });
    }

    /// The carrier at `address` answers `invite` with `status_code` and `sdp`.
    fn carrier_sends(
        &self,
        address: &str,
        invite: &SipMessage,
        status_code: u16,
        sdp: Option<&str>,
    ) {
        let mut response = carrier_response(invite, status_code, "Callee");
        if status_code > 100 {
            response
                .headers
                .set("Contact", "<sip:callee@198.51.100.7:5060>".to_string());
        }
        if let Some(sdp) = sdp {
            response.body = sdp.as_bytes().to_vec();
            response
                .headers
                .set("Content-Type", "application/sdp".to_string());
            response
                .headers
                .set("Content-Length", sdp.len().to_string());
        }
        tokio::task::block_in_place(|| {
            handle_b2bua_response(
                &self.call_id,
                &top_via_branch(invite),
                &mut response,
                status_code,
                address.parse().expect("a literal address"),
                &self.dispatcher.state,
            )
        });
    }

    /// The one response with `status_code` siphon sent the caller since the
    /// last look.
    fn to_caller(&self, status_code: u16) -> SipMessage {
        let sent = self.wire();
        let listed = summaries(&sent);
        sent.into_iter()
            .find(|sent| {
                sent.destination.to_string() == CALLER
                    && matches!(&sent.message.start_line, StartLine::Response(status) if status.status_code == status_code)
            })
            .map(|sent| sent.message)
            .unwrap_or_else(|| panic!("no {status_code} to the caller, sent: {listed:?}"))
    }
}

fn body_text(message: &SipMessage) -> String {
    String::from_utf8_lossy(&message.body).into_owned()
}

/// An SDP from its `c=` line on: what siphon relays toward a B-leg unchanged,
/// past the `o=` / `s=` it owns there (topology hiding).
fn media_of(sdp: &str) -> &str {
    sdp.find("c=").map_or(sdp, |at| &sdp[at..])
}

#[tokio::test(flavor = "multi_thread")]
async fn the_callee_is_offered_the_engines_far_leg_and_the_caller_keeps_its_answer() {
    let engine = NativeTestEngine::start().await;
    let sequence = answered_locally(&engine, "").await;
    let early = sequence.early_media(NATIVE_ENGINE_ANSWER);
    assert_eq!(body_text(&early), NATIVE_ENGINE_ANSWER);

    sequence.dial();
    let invite = invite_to(sequence.wire(), FIRST_CARRIER);
    assert_eq!(
        media_of(&body_text(&invite)),
        media_of(NATIVE_ENGINE_FAR_OFFER),
        "the callee gets the engine's far-leg offer, never the caller's own"
    );
    assert_eq!(engine.commands("offer_far").len(), 1);

    // The callee's early media completes the far leg; the caller is shown the
    // answer it already holds, not the callee's.
    sequence.carrier_sends(FIRST_CARRIER, &invite, 183, Some(CALLEE_ANSWER));
    let relayed = sequence.to_caller(183);
    assert_eq!(body_text(&relayed), NATIVE_ENGINE_ANSWER);
    let answers = engine.commands("answer");
    assert_eq!(
        answers.len(),
        1,
        "the callee's first SDP goes to the engine once"
    );
    assert_eq!(answers[0].detail.as_deref(), Some("carrier-tag"));

    // The 2xx repeats it byte for byte, o= included (RFC 6337 §3.1.1).
    sequence.carrier_sends(FIRST_CARRIER, &invite, 200, Some(CALLEE_ANSWER));
    let answered = sequence.to_caller(200);
    assert_eq!(body_text(&answered), NATIVE_ENGINE_ANSWER);
    assert_eq!(
        engine.commands("answer").len(),
        1,
        "the 2xx asks the engine nothing more"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_bare_2xx_completes_the_far_leg_with_its_own_sdp() {
    let engine = NativeTestEngine::start().await;
    let sequence = answered_locally(&engine, "").await;
    sequence.early_media(NATIVE_ENGINE_ANSWER);
    sequence.dial();
    let invite = invite_to(sequence.wire(), FIRST_CARRIER);
    sequence.carrier_sends(FIRST_CARRIER, &invite, 180, None);
    let ringing = sequence.to_caller(180);
    assert!(ringing.body.is_empty() || body_text(&ringing) == NATIVE_ENGINE_ANSWER);
    sequence.carrier_sends(FIRST_CARRIER, &invite, 200, Some(CALLEE_ANSWER));
    assert_eq!(body_text(&sequence.to_caller(200)), NATIVE_ENGINE_ANSWER);
    assert_eq!(engine.commands("answer").len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_caller_holding_the_answer_reliably_gets_the_callees_18x_without_sdp() {
    let engine = NativeTestEngine::start().await;
    let sequence = answered_locally(&engine, "").await;
    if let Some(mut call) = sequence
        .dispatcher
        .state
        .call_actors
        .get_call_mut(&sequence.call_id)
    {
        call.a_leg_supports_100rel = true;
    }
    let early = sequence.early_media(NATIVE_ENGINE_ANSWER);
    assert!(
        early.headers.get("RSeq").is_some(),
        "siphon's 183 went reliably"
    );
    sequence.dial();
    let invite = invite_to(sequence.wire(), FIRST_CARRIER);
    sequence.carrier_sends(FIRST_CARRIER, &invite, 183, Some(CALLEE_ANSWER));
    // Held behind the unacknowledged reliable 183, or sent without SDP: never
    // with the callee's SDP, and never the answer again in a provisional.
    for sent in sequence.wire() {
        if sent.destination.to_string() == CALLER {
            assert!(sent.message.body.is_empty(), "{}", body_text(&sent.message));
        }
    }
    assert_eq!(engine.commands("answer").len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_callee_refusal_releases_the_far_leg_and_runs_on_failure() {
    let engine = NativeTestEngine::start().await;
    let sequence = answered_locally(&engine, MARK_FAILURES).await;
    sequence.early_media(NATIVE_ENGINE_ANSWER);
    sequence.dial();
    let invite = invite_to(sequence.wire(), FIRST_CARRIER);
    sequence.carrier_sends(FIRST_CARRIER, &invite, 486, None);
    let released = engine.commands("delete_far_leg");
    assert_eq!(released.len(), 1, "the far leg goes before on_failure runs");
    assert_eq!(sequence.failures_seen().as_deref(), Some("486;"));
    let _ = sequence.to_caller(486);
    // Released from a spawned task once the call has its failure.
    for _ in 0..100 {
        if !engine.commands("delete").is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(
        engine.commands("delete").len(),
        1,
        "the call's media goes with it"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_callee_answering_a_codec_it_was_not_offered_is_released_and_the_call_fails_488() {
    let engine = NativeTestEngine::start().await;
    let sequence = answered_locally(&engine, MARK_FAILURES).await;
    sequence.early_media(NATIVE_ENGINE_ANSWER);
    sequence.dial();
    let invite = invite_to(sequence.wire(), FIRST_CARRIER);
    let unoffered = CALLEE_ANSWER
        .replace("RTP/AVP 8 101", "RTP/AVP 18 101")
        .replace("PCMA/8000", NATIVE_ENGINE_UNOFFERED_CODEC)
        .replace("rtpmap:8", "rtpmap:18");
    sequence.carrier_sends(FIRST_CARRIER, &invite, 200, Some(&unoffered));
    let sent = sequence.wire();
    let listed = summaries(&sent);
    assert!(
        listed.contains(&format!("ACK to {FIRST_CARRIER}")),
        "{listed:?}"
    );
    // The BYE leaves with the ACK as one ordered group
    // (`send_b2bua_sequence_to_bleg`); the test egress shows its first frame.
    assert!(listed.contains(&format!("488 to {CALLER}")), "{listed:?}");
    assert_eq!(sequence.failures_seen().as_deref(), Some("488;"));
    assert_eq!(engine.commands("delete_far_leg").len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_sequential_route_offers_each_carrier_the_far_leg() {
    let engine = NativeTestEngine::start().await;
    let mut sequence = answered_locally(&engine, MARK_FAILURES).await;
    sequence.early_media(NATIVE_ENGINE_ANSWER);
    let advance = sequence.start_routes(
        vec![
            super::lcr_ring_timeout_tests::carrier("first", FIRST_CARRIER, 30),
            super::lcr_ring_timeout_tests::carrier("second", SECOND_CARRIER, 30),
        ],
        60,
    );
    assert!(advance.dialed);
    let first = invite_to(sequence.wire(), FIRST_CARRIER);
    assert_eq!(
        media_of(&body_text(&first)),
        media_of(NATIVE_ENGINE_FAR_OFFER)
    );
    // The first carrier's early SDP takes the far leg, then it fails: the
    // second carrier is offered a fresh one.
    sequence.carrier_sends(FIRST_CARRIER, &first, 183, Some(CALLEE_ANSWER));
    let _ = sequence.wire();
    sequence.carrier_sends(FIRST_CARRIER, &first, 503, None);
    let second = invite_to(sequence.wire(), SECOND_CARRIER);
    assert_eq!(
        media_of(&body_text(&second)),
        media_of(NATIVE_ENGINE_FAR_OFFER)
    );
    assert_eq!(engine.commands("delete_far_leg").len(), 1);
    assert_eq!(engine.commands("offer_far").len(), 2);
    sequence.carrier_sends(SECOND_CARRIER, &second, 200, Some(CALLEE_ANSWER));
    assert_eq!(body_text(&sequence.to_caller(200)), NATIVE_ENGINE_ANSWER);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_dial_behind_an_answer_that_is_not_the_engines_is_refused() {
    let engine = NativeTestEngine::start().await;
    let sequence = answered_locally(&engine, MARK_FAILURES).await;
    let foreign = CALLEE_ANSWER.replace("o=callee", "o=elsewhere");
    sequence.early_media(&foreign);
    let state = &sequence.dispatcher.state;
    assert!(dial_refusal(state, &sequence.call_id, false).is_some());
    sequence.dial();
    let sent = sequence.wire();
    let listed = summaries(&sent);
    assert!(
        !listed.iter().any(|line| line.starts_with("INVITE")),
        "nothing is dialled: {listed:?}"
    );
    assert!(listed.contains(&format!("500 to {CALLER}")), "{listed:?}");
    assert!(engine.commands("offer_far").is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_parallel_fork_behind_the_engines_answer_is_refused() {
    let engine = NativeTestEngine::start().await;
    let sequence = answered_locally(&engine, "").await;
    sequence.early_media(NATIVE_ENGINE_ANSWER);
    let state = &sequence.dispatcher.state;
    assert!(dial_refusal(state, &sequence.call_id, true).is_some());
    assert!(dial_refusal(state, &sequence.call_id, false).is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_call_without_early_media_dials_the_callers_own_offer() {
    let engine = NativeTestEngine::start().await;
    let sequence = answered_locally(&engine, "").await;
    sequence.dial();
    let invite = invite_to(sequence.wire(), FIRST_CARRIER);
    assert!(
        body_text(&invite).contains("m=audio 40000 "),
        "{}",
        body_text(&invite)
    );
    assert!(engine.commands("offer_far").is_empty());
}
