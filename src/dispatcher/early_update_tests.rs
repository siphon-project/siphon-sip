//! An UPDATE from the caller of a call that is still ringing (RFC 3311).
//!
//! The call's media is anchored: the caller's offer is on the engine and out
//! to the callee, and nothing has answered it. siphon is the UAS of the
//! caller's dialog, so RFC 3311 §5.2 says what an UPDATE there gets:
//!
//! * with no offer it changes nothing about the session and is answered 200;
//! * with an offer while the INVITE's own offer has no answer yet, "the UAS
//!   MUST reject the UPDATE with a 500 response, and MUST include a
//!   Retry-After header field with a randomly chosen value between 0 and 10
//!   seconds";
//! * with an offer once the caller has its answer in a reliable provisional,
//!   the change would need the callee, which siphon cannot ask on a dialog it
//!   has not confirmed: 504.
//!
//! None of them asks the engine to answer for the callee. Read off the UDP
//! egress and the commands an in-process native engine records.

use super::lcr_ring_timeout_tests::{invite_to, summaries, Sequence, CALLER, FIRST_CARRIER};
use super::*;
use crate::rtpengine::test_native_engine::NativeTestEngine;

const OFFER: &str = concat!(
    "v=0\r\n",
    "o=caller 7 8 IN IP4 192.0.2.10\r\n",
    "s=-\r\n",
    "c=IN IP4 192.0.2.10\r\n",
    "t=0 0\r\n",
    "m=audio 40000 RTP/AVP 0\r\n",
    "a=sendonly\r\n",
);

/// A caller's call ringing one callee, with the caller's offer on `engine`
/// and no answer to it.
async fn ringing_and_anchored(engine: &NativeTestEngine) -> Sequence {
    let mut sequence = Sequence::new_call("");
    let backend = engine.backend();
    backend
        .offer(
            "lcr-policy@192.0.2.10",
            "caller-tag",
            OFFER.replace("a=sendonly", "a=sendrecv").as_bytes(),
            &crate::rtpengine::profile::NgFlags::default(),
        )
        .await
        .expect("the engine takes the caller's offer");
    let sessions = Arc::new(crate::rtpengine::MediaSessionStore::new());
    sessions.insert(crate::rtpengine::MediaSession {
        call_id: "lcr-policy@192.0.2.10".to_string(),
        rtpengine_call_id: "lcr-policy@192.0.2.10".to_string(),
        from_tag: "caller-tag".to_string(),
        to_tag: None,
        profile: "rtp_passthrough".to_string(),
        ws_uri: None,
        ws_tee: None,
        ws_bridge_attached: false,
        bridge_sides: None,
        created_at: std::time::Instant::now(),
    });
    sequence.dispatcher.state.rtpengine_set = Some(backend);
    sequence.dispatcher.state.rtpengine_profiles =
        Some(Arc::new(crate::rtpengine::ProfileRegistry::new()));
    sequence.dispatcher.state.rtpengine_sessions = Some(sessions);
    let dialled = {
        let guard = sequence.invite.lock().expect("the A-leg INVITE lock");
        b2bua_send_b_leg_invite(
            &sequence.call_id,
            &format!("sip:15550100042@{FIRST_CARRIER}"),
            Some(format!("sip:{FIRST_CARRIER}").as_str()),
            None,
            &[],
            None,
            None,
            &guard,
            None,
            None,
            None,
            None,
            None,
            None,
            &[],
            &sequence.dispatcher.state,
        )
    };
    assert!(dialled);
    let invite = invite_to(sequence.wire(), FIRST_CARRIER);
    sequence.carrier_answers(FIRST_CARRIER, &invite, 180, "Ringing");
    let _ = sequence.wire();
    sequence
}

/// The caller's UPDATE numbered `cseq` in its early dialog, with `body`.
fn caller_updates(sequence: &Sequence, cseq: u32, body: Option<&str>) -> Vec<SipMessage> {
    let state = &sequence.dispatcher.state;
    let local_tag = state
        .call_actors
        .get_call(&sequence.call_id)
        .map(|call| call.a_leg.dialog.local_tag.clone())
        .expect("the call");
    let content = match body {
        Some(body) => format!(
            "Content-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        ),
        None => "Content-Length: 0\r\n\r\n".to_string(),
    };
    let raw = format!(
        concat!(
            "UPDATE sip:192.0.2.1:5060 SIP/2.0\r\n",
            "Via: SIP/2.0/UDP {caller};branch=z9hG4bK-early-update-{cseq}\r\n",
            "Max-Forwards: 70\r\n",
            "From: <sip:15550100001@caller.example.com>;tag=caller-tag\r\n",
            "To: <sip:15550100042@siphon.example.com>;tag={local_tag}\r\n",
            "Call-ID: lcr-policy@192.0.2.10\r\n",
            "CSeq: {cseq} UPDATE\r\n",
            "Contact: <sip:caller@{caller}>\r\n",
            "{content}",
        ),
        caller = CALLER,
        cseq = cseq,
        local_tag = local_tag,
        content = content,
    );
    let message = parse_sip_message_bytes(raw.as_bytes()).expect("the UPDATE parses");
    let inbound = InboundMessage {
        client_transport: None,
        connection_id: ConnectionId::default(),
        transport: Transport::Udp,
        local_addr: "192.0.2.1:5060".parse().expect("a literal address"),
        remote_addr: CALLER.parse().expect("a literal address"),
        data: Bytes::from(raw),
    };
    tokio::task::block_in_place(|| handle_b2bua_update(inbound, message, state));
    let sent = sequence.wire();
    assert!(
        summaries(&sent)
            .iter()
            .all(|line| line.ends_with(&format!("to {CALLER}"))),
        "nothing goes to the callee: {:?}",
        summaries(&sent)
    );
    sent.into_iter().map(|sent| sent.message).collect()
}

/// Every command the engine has been sent, by kind.
fn engine_commands(engine: &NativeTestEngine) -> Vec<usize> {
    ["offer", "reoffer", "answer", "answer_local", "delete"]
        .into_iter()
        .map(|name| engine.commands(name).len())
        .collect()
}

fn session_after(sequence: &Sequence) -> (String, Option<String>) {
    let session = sequence
        .dispatcher
        .state
        .rtpengine_sessions
        .as_ref()
        .and_then(|sessions| sessions.get("lcr-policy@192.0.2.10"))
        .expect("the media session");
    (session.from_tag, session.to_tag)
}

/// An offer in an UPDATE while the INVITE's own offer is unanswered is refused
/// `500` with a `Retry-After` of 0 to 10 seconds (RFC 3311 §5.2). The engine is
/// sent nothing, the callee nothing, the offer is not taken for the caller's
/// media, and the call rings on.
#[tokio::test(flavor = "multi_thread")]
async fn an_early_update_with_an_offer_is_refused_while_the_invites_offer_is_unanswered() {
    let engine = NativeTestEngine::start().await;
    let sequence = ringing_and_anchored(&engine).await;
    let state = &sequence.dispatcher.state;
    let before = engine_commands(&engine);
    let media_before = state
        .call_actors
        .get_call(&sequence.call_id)
        .and_then(|call| call.a_leg.last_sdp.clone());

    let sent = caller_updates(&sequence, 2, Some(OFFER));
    assert_eq!(sent.len(), 1, "one final response");
    assert_eq!(sent[0].status_code(), Some(500));
    let retry_after = sent[0]
        .headers
        .get("Retry-After")
        .and_then(|value| value.trim().parse::<u32>().ok())
        .expect("a Retry-After in seconds");
    assert!(retry_after <= 10, "{retry_after}");
    assert!(sent[0].body.is_empty());

    assert_eq!(
        engine_commands(&engine),
        before,
        "the engine is not asked to answer for a callee that has not: {:?}",
        engine.commands("answer_local")
    );
    assert_eq!(
        session_after(&sequence),
        ("caller-tag".to_string(), None),
        "the session still waits for the callee's answer"
    );
    let media_after = state
        .call_actors
        .get_call(&sequence.call_id)
        .and_then(|call| call.a_leg.last_sdp.clone());
    assert_eq!(media_after, media_before, "the refused offer is not kept");
    assert!(!sequence.call_is_gone(), "the call rings on");
}

/// An UPDATE with no offer changes nothing about the session: it is answered
/// `200` with no body, and the engine is sent nothing.
#[tokio::test(flavor = "multi_thread")]
async fn an_early_update_without_an_offer_is_answered_and_touches_no_media() {
    let engine = NativeTestEngine::start().await;
    let sequence = ringing_and_anchored(&engine).await;
    let before = engine_commands(&engine);

    let sent = caller_updates(&sequence, 2, None);
    assert_eq!(sent.len(), 1, "one final response");
    assert_eq!(sent[0].status_code(), Some(200));
    assert!(sent[0].body.is_empty(), "no offer, so no answer");
    assert_eq!(engine_commands(&engine), before);
    assert_eq!(session_after(&sequence), ("caller-tag".to_string(), None));
}

/// Once the caller has its answer in a reliable provisional it acknowledged,
/// the offer in its UPDATE is one siphon could only take by asking the callee,
/// on a dialog it has not confirmed. It is refused `504` (RFC 3311 §5.2), again
/// with nothing sent to the engine or the callee.
#[tokio::test(flavor = "multi_thread")]
async fn an_early_update_with_an_offer_after_a_reliable_answer_is_refused_504() {
    let engine = NativeTestEngine::start().await;
    let sequence = ringing_and_anchored(&engine).await;
    let state = &sequence.dispatcher.state;
    // The caller was sent an answer in a reliable 183 and has PRACKed it.
    {
        let mut call = state
            .call_actors
            .get_call_mut(&sequence.call_id)
            .expect("the call");
        let mut early = build_response(
            &sequence.invite.lock().expect("the A-leg INVITE lock"),
            183,
            "Session Progress",
            None,
            &[],
        );
        set_sdp_body(&mut early, OFFER.as_bytes().to_vec(), "application/sdp");
        let now = tokio::time::Instant::now().into_std();
        let crate::b2bua::actor::Offered::Send(sent) =
            call.a_leg_reliability.offer(early, true, None, now)
        else {
            panic!("the first reliable provisional goes out at once");
        };
        let rseq = sent.rseq.expect("sent reliably");
        assert!(!call.a_leg_reliability.answer_acknowledged());
        let _ = call.a_leg_reliability.acknowledge(rseq, 1, now);
        assert!(call.a_leg_reliability.answer_acknowledged());
    }
    let before = engine_commands(&engine);

    let sent = caller_updates(&sequence, 2, Some(OFFER));
    assert_eq!(sent.len(), 1, "one final response");
    assert_eq!(sent[0].status_code(), Some(504));
    assert!(sent[0].headers.get("Retry-After").is_none());
    assert_eq!(engine_commands(&engine), before);
    assert_eq!(session_after(&sequence), ("caller-tag".to_string(), None));
    assert!(!sequence.call_is_gone());
}
