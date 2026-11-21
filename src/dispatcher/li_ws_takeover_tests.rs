//! Content delivery on a call handed to a bot.
//!
//! `call.handover(app, answer=True, ws_uri=...)` has the engine answer the
//! caller itself, with a WebSocket server as its far side. A siphon-rtp that
//! lists `x3_ws_takeover` (0.26.0 and later) takes an interception on such a
//! call, the server standing in for the callee; one before that refuses it,
//! and that refusal is reported to the ADMF.
//!
//! Driven as [`super::li_multi_delivery_tests`] drives a call, against the
//! in-process native engine as either of the two.

use super::li_session_tests::{
    arrives, attach_outcomes, backend_of, capture_log, engine_events, engine_reports,
    faults_reported, intercepting_on_the_engine, CALLER, CALLER_ACK, CALLER_INVITE,
};
use super::*;
use crate::rtpengine::test_native_engine::{
    NativeTestEngine, NATIVE_ENGINE_X3_AT_OFFER, NATIVE_ENGINE_X3_WS_TAKEOVER,
};
use crate::rtpengine::NgFlags;

const BASE_CALL_ID: &str = "caller-call@192.0.2.10";
const BOT: &str = "wss://bot.example.net/media";

/// `raw`, a message of the shared caller dialog, on the dialog `call_id`.
fn on_call(raw: &str, call_id: &str) -> String {
    raw.replace(BASE_CALL_ID, call_id)
}

/// The answer half of a profile that sends the caller's audio to a bot.
fn into_the_bot(call_id: &str) -> NgFlags {
    let mut flags = NgFlags {
        ws_uri: Some(BOT.to_string()),
        ..NgFlags::default()
    };
    flags.stamp_sip_call_id(call_id);
    flags
}

/// The caller's INVITE on `call_id`, with an SDP offer.
fn invite_with_offer(call_id: &str) -> String {
    let sdp = concat!(
        "v=0\r\n",
        "o=- 1 1 IN IP4 192.0.2.10\r\n",
        "s=-\r\n",
        "c=IN IP4 192.0.2.10\r\n",
        "t=0 0\r\n",
        "m=audio 40000 RTP/AVP 0\r\n",
        "a=rtpmap:0 PCMU/8000\r\n",
    );
    on_call(CALLER_INVITE, call_id).replace(
        "Content-Length: 0\r\n\r\n",
        &format!(
            "Content-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{sdp}",
            sdp.len()
        ),
    )
}

/// An intercepted call handed to a bot is anchored as the hand-over anchors
/// it: the engine answers the caller's own offer into the WebSocket server.
/// On an engine that lists `x3_ws_takeover` its content is asked for at that
/// answer, under the caller's Call-ID and the caller's tag, with the caller as
/// the target leg, and the engine takes it. The ACK asks for nothing more.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_call_handed_to_a_bot_is_attached_under_the_callers_call_id_and_tag() {
    const CALL: &str = "takeover-handover@192.0.2.10";
    let (state, engine, li, _iri, mut audit) =
        intercepting_on_the_engine(NativeTestEngine::start_with_x3_026().await).await;
    let raw = invite_with_offer(CALL);
    arrives(&state, CALLER, &raw);
    let invite = parse_sip_message_bytes(raw.as_bytes()).expect("the INVITE parses");

    let anchor = anchor_a_leg(
        &invite,
        "192.0.2.10".parse().expect("a literal address"),
        Some("voice_ai"),
        Some(BOT),
        None,
        &state,
    )
    .expect("the engine answers the caller into the bot");
    assert!(!anchor.engine, "the bot is the far side, not the engine");
    let answered = engine.commands("answer_local");
    assert_eq!(answered.len(), 1);
    assert_eq!(answered[0].ws_uri.as_deref(), Some(BOT));

    assert_eq!(
        attach_outcomes(&mut audit).await,
        (1, 0),
        "attached at the answer, and taken"
    );
    let attached = engine.commands("attach_x3");
    assert_eq!(attached.len(), 1);
    assert_eq!(
        (attached[0].call_id.as_str(), attached[0].from_tag.as_str()),
        (CALL, "caller-tag"),
        "the engine call the answer made, under the tag it was made under"
    );
    assert_eq!(
        attached[0].detail.as_deref(),
        Some("caller"),
        "the warrant names the caller: what it sends is from the target"
    );
    assert!(!attached[0].refused);
    assert_eq!(engine.x3_delivery_count(), 1);

    arrives(&state, CALLER, &on_call(CALLER_ACK, CALL));
    assert_eq!(attach_outcomes(&mut audit).await, (0, 0));
    assert_eq!(engine.commands("attach_x3").len(), 1, "one interception");
    assert_eq!(li.x3_attachments_for(CALL).len(), 1);
    backend_of(&state)
        .delete(CALL, "caller-tag")
        .await
        .expect("released");
}

/// An engine before 0.26.0 refuses an interception on a call whose audio goes
/// to a WebSocket server. It is asked as it always was, and its refusal is
/// the fault it always was: warranted content is not being delivered. Asked
/// and reported once.
#[tokio::test]
async fn without_the_feature_a_call_handed_to_a_bot_is_a_refused_attach_and_a_fault() {
    const CALL: &str = "takeover-refused@192.0.2.10";
    let (log, _guard) = capture_log();
    let (state, engine, li, _iri, mut audit) =
        intercepting_on_the_engine(NativeTestEngine::start_with_x3().await).await;
    arrives(&state, CALLER, &on_call(CALLER_INVITE, CALL));
    backend_of(&state)
        .answer_local(CALL, "caller-tag", "v=0\r\n", &into_the_bot(CALL))
        .await
        .expect("the engine answers the caller into the bot");

    assert_eq!(
        attach_outcomes(&mut audit).await,
        (1, 1),
        "asked, and refused"
    );
    let rendered = log.rendered();
    assert_eq!(faults_reported(&log), 1, "{rendered}");
    assert!(
        rendered.contains("a WebSocket-takeover call (ws_uri) has no relayed second party"),
        "the engine's own refusal is what is reported:\n{rendered}"
    );
    assert!(li.x3_attachments_for(CALL).is_empty(), "nothing on record");

    arrives(&state, CALLER, &on_call(CALLER_ACK, CALL));
    assert_eq!(attach_outcomes(&mut audit).await, (0, 0));
    assert_eq!(engine.commands("attach_x3").len(), 1, "not asked again");
    assert_eq!(faults_reported(&log), 1);
    backend_of(&state)
        .delete(CALL, "caller-tag")
        .await
        .expect("released");
}

/// What decides is the feature for the shape the call has. An engine that
/// lists `x3_ws_takeover` is asked at the answer of a call handed to a bot
/// whatever else it lists, and is not asked at the answer of a call it
/// answers as itself unless it lists `x3_single_leg` too.
#[tokio::test]
async fn the_takeover_feature_decides_for_a_call_handed_to_a_bot() {
    const BOT_CALL: &str = "takeover-feature-bot@192.0.2.10";
    const PLAIN_CALL: &str = "takeover-feature-plain@192.0.2.10";
    let engine = NativeTestEngine::start_with_features(&[
        "relay",
        "scope",
        NATIVE_ENGINE_X3_AT_OFFER,
        NATIVE_ENGINE_X3_WS_TAKEOVER,
    ])
    .await;
    let (state, engine, _li, _iri, mut audit) = intercepting_on_the_engine(engine).await;
    let backend = backend_of(&state);

    arrives(&state, CALLER, &on_call(CALLER_INVITE, BOT_CALL));
    backend
        .answer_local(BOT_CALL, "caller-tag", "v=0\r\n", &into_the_bot(BOT_CALL))
        .await
        .expect("answered into the bot");
    assert_eq!(
        attach_outcomes(&mut audit).await,
        (1, 0),
        "asked at the answer"
    );
    assert_eq!(engine.commands("attach_x3")[0].call_id, BOT_CALL);

    arrives(&state, CALLER, &on_call(CALLER_INVITE, PLAIN_CALL));
    let mut plain = NgFlags::default();
    plain.stamp_sip_call_id(PLAIN_CALL);
    backend
        .answer_local(PLAIN_CALL, "caller-tag", "v=0\r\n", &plain)
        .await
        .expect("answered by the engine itself");
    assert_eq!(
        attach_outcomes(&mut audit).await,
        (0, 0),
        "an engine that does not list x3_single_leg is asked at the ACK"
    );
    for call in [BOT_CALL, PLAIN_CALL] {
        backend.delete(call, "caller-tag").await.expect("released");
    }
}

/// An interception the call already has is carried onto the bridge by the
/// engine: a call the engine answered itself and is then answered again into
/// a bot, and a call attached at its offer whose answer names the bot. siphon
/// has it on record and asks for nothing a second time, and the delivery ends
/// with the call's `delete`, cleanly.
#[tokio::test]
async fn an_interception_attached_before_the_takeover_is_not_asked_for_again() {
    const ANSWERED: &str = "takeover-re-answer@192.0.2.10";
    const OFFERED: &str = "takeover-offered@192.0.2.10";
    let (log, _guard) = capture_log();
    let (state, engine, li, _iri, mut audit) =
        intercepting_on_the_engine(NativeTestEngine::start_with_x3_026().await).await;
    let events = engine_events(&state);
    let backend = backend_of(&state);

    // Answered by the engine (an announcement), then handed to the bot.
    arrives(&state, CALLER, &on_call(CALLER_INVITE, ANSWERED));
    let mut plain = NgFlags::default();
    plain.stamp_sip_call_id(ANSWERED);
    backend
        .answer_local(ANSWERED, "caller-tag", "v=0\r\n", &plain)
        .await
        .expect("answered by the engine itself");
    assert_eq!(attach_outcomes(&mut audit).await, (1, 0));
    backend
        .answer_local(ANSWERED, "caller-tag", "v=0\r\n", &into_the_bot(ANSWERED))
        .await
        .expect("the same dialog is answered again, into the bot");
    assert_eq!(attach_outcomes(&mut audit).await, (0, 0));

    // Attached at the offer, and the answer names the bot.
    arrives(&state, CALLER, &on_call(CALLER_INVITE, OFFERED));
    let mut offer = NgFlags::default();
    offer.stamp_sip_call_id(OFFERED);
    backend
        .offer(OFFERED, "caller-tag", b"v=0\r\n", &offer)
        .await
        .expect("offered");
    assert_eq!(attach_outcomes(&mut audit).await, (1, 0));
    backend
        .answer(
            OFFERED,
            "caller-tag",
            "bot-tag",
            b"v=0\r\n",
            &into_the_bot(OFFERED),
        )
        .await
        .expect("answered into the bot");
    arrives(&state, CALLER, &on_call(CALLER_ACK, OFFERED));
    assert_eq!(attach_outcomes(&mut audit).await, (0, 0));

    assert_eq!(
        engine.commands("attach_x3").len(),
        2,
        "one attach for each call"
    );
    assert_eq!(engine.x3_delivery_count(), 2);
    assert!(engine.commands("detach_x3").is_empty());
    assert!(
        engine.take_x3_ends().is_empty(),
        "nothing was replaced at the engine"
    );

    for call in [ANSWERED, OFFERED] {
        assert_eq!(li.x3_attachments_for(call).len(), 1);
        backend.delete(call, "caller-tag").await.expect("released");
    }
    for end in engine.take_x3_ends() {
        engine_reports(&events, end).await;
    }
    assert_eq!(faults_reported(&log), 0, "{}", log.rendered());
    assert_eq!(li.x3_attachment_count(), 0);
}
