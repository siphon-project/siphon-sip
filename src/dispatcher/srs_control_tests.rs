//! A recording session offered to a control application (`srs.app`): the
//! `StasisStart` it gets, its `accept` and `reject`, the deadline, and a
//! `hangup` of an accepted session.
//!
//! The SRC's requests go through the dispatcher's request path; the
//! application is a connection on a real control bus, whose verbs are applied
//! as the SIP adapter applies them for a recording channel.

use std::time::Duration;

use super::srs_handshake_tests::{
    await_response, count, eventually, request, send, siprec_invite, srs, srs_state, to_tag, SRC,
};
use super::*;
use crate::control::channel_event_capture;
use crate::control::protocol::{ControlResult, EventFrame};
use crate::control::{ConnHandle, ControlBus, OutboundFrame, SlowConsumerPolicy};
use crate::rtpengine::test_native_engine::NativeTestEngine;

const APP: &str = "recorder";

/// A bus serving [`APP`], with a handoff deadline of `deadline_ms`.
fn bus(deadline_ms: u64) -> Arc<ControlBus> {
    let (command_tx, _command_rx) = flume::unbounded();
    ControlBus::new(
        command_tx,
        vec![crate::config::ControlAppConfig {
            name: APP.to_string(),
            token: "t".to_string(),
            per_call_connect: false,
            connect_url: None,
            on_lost: Some("hangup".to_string()),
            ca_file: None,
            events: Vec::new(),
        }],
        64,
        SlowConsumerPolicy::DropOldest,
        10,
        deadline_ms,
    )
}

/// A dispatcher whose SRS offers every session to [`APP`] on `bus`.
fn controlled(
    engine: &NativeTestEngine,
    directory: &std::path::Path,
    bus: &Arc<ControlBus>,
) -> (Arc<DispatcherState>, flume::Receiver<OutboundMessage>) {
    let (state, udp) = srs_state(engine, directory);
    let mut config = srs(&state).config().clone();
    config.app = Some(APP.to_string());
    let manager = crate::srs::SrsManager::new(config);
    manager.use_control_bus(Arc::clone(bus));
    let mut state = Arc::try_unwrap(state).unwrap_or_else(|_| panic!("the only reference"));
    state.srs_manager = Some(Arc::new(manager));
    (Arc::new(state), udp)
}

/// The next `StasisStart` the application's connection is sent.
async fn stasis_start(connection: &Arc<ConnHandle>) -> EventFrame {
    for _ in 0..200 {
        let frames = tokio::time::timeout(Duration::from_millis(10), connection.events.recv_many())
            .await
            .unwrap_or_default();
        if let Some(event) = frames.into_iter().find_map(|frame| match frame {
            OutboundFrame::Event(event) if event.event == "StasisStart" => Some(event),
            _ => None,
        }) {
            return event;
        }
    }
    panic!("no StasisStart");
}

fn verb(
    state: &Arc<DispatcherState>,
    call_id: &str,
    verb: &str,
    args: serde_json::Value,
) -> ControlResult {
    crate::dispatcher::srs::srs_control_verb_in(state, call_id, verb, &args)
}

fn ok(result: ControlResult) -> serde_json::Value {
    match result {
        ControlResult::Ok(value) => value,
        ControlResult::Error { message, .. } => panic!("refused: {message}"),
    }
}

/// The application is offered the session before anything is answered or
/// anchored: the request as received, the SRC's address and the metadata.
/// Its `accept` is what answers 200 and starts the recordings, as it asked.
#[tokio::test(flavor = "multi_thread")]
async fn the_application_is_offered_the_session_and_its_accept_records_it() {
    // An engine that writes Ogg Opus, as the accept below asks for.
    let engine = NativeTestEngine::start_with_features(&[
        "relay",
        "scope",
        "conference_seat",
        "record_ogg_opus",
    ])
    .await;
    let directory = super::srs_handshake_tests::scratch_dir("accept");
    let bus = bus(3000);
    let connection = bus.register_connection(APP);
    let (state, udp) = controlled(&engine, &directory, &bus);
    let call_id = "accept@198.51.100.20";

    send(&state, &siprec_invite(call_id, 2, true));
    let offered = stasis_start(&connection).await;
    assert_eq!(offered.app.as_deref(), Some(APP));
    assert_eq!(offered.sip_call_id.as_deref(), Some(call_id));
    let payload = &offered.payload;
    assert_eq!(payload["kind"], "siprec");
    assert_eq!(payload["invite"]["ruri"], "sip:srs@192.0.2.1:5060");
    assert_eq!(payload["source_ip"], SRC.split(':').next().unwrap());
    assert_eq!(payload["source_port"], 5060);
    assert_eq!(payload["transport"], "udp");
    assert_eq!(payload["recording_session"]["session_id"], "rs-shared");
    assert_eq!(
        payload["recording_session"]["participant_stream"]
            .as_array()
            .map(Vec::len),
        Some(2)
    );

    // Nothing is answered or anchored while the application decides.
    let mut seen = Vec::new();
    await_response(&udp, &mut seen, 100, "INVITE").await;
    assert_eq!(count(&seen, 200, "INVITE"), 0);
    assert!(engine.commands("answer_local").is_empty());

    let elsewhere = super::srs_handshake_tests::scratch_dir("accept-path");
    let reply = ok(verb(
        &state,
        call_id,
        "accept",
        serde_json::json!({ "format": "ogg_opus", "path": elsewhere.display().to_string() }),
    ));
    assert_eq!(reply["state"], "accepted");
    await_response(&udp, &mut seen, 200, "INVITE").await;
    let recordings = engine.commands("start_recording");
    assert_eq!(recordings.len(), 2);
    for recording in recordings {
        let path = recording.detail.expect("a file");
        assert!(path.starts_with(&elsewhere.display().to_string()), "{path}");
        assert!(path.ends_with(".ogg"), "{path}");
    }
    assert!(
        matches!(
            verb(&state, call_id, "accept", serde_json::json!({})),
            ControlResult::Error { .. }
        ),
        "one decision per session"
    );
    let _ = std::fs::remove_dir_all(directory);
    let _ = std::fs::remove_dir_all(elsewhere);
}

/// `reject` is that final response, with nothing anchored, and ends the
/// channel with the status.
#[tokio::test(flavor = "multi_thread")]
async fn a_rejected_session_gets_the_status_and_nothing_is_anchored() {
    let engine = NativeTestEngine::start().await;
    let directory = super::srs_handshake_tests::scratch_dir("reject");
    let bus = bus(3000);
    let connection = bus.register_connection(APP);
    let (state, udp) = controlled(&engine, &directory, &bus);
    let call_id = "reject@198.51.100.20";
    channel_event_capture::watch(call_id);

    send(&state, &siprec_invite(call_id, 2, true));
    stasis_start(&connection).await;
    ok(verb(
        &state,
        call_id,
        "reject",
        serde_json::json!({ "code": 404, "reason": "No Such Tenant" }),
    ));
    let mut seen = Vec::new();
    let refused = await_response(&udp, &mut seen, 404, "INVITE").await;
    let crate::sip::message::StartLine::Response(status) = &refused.start_line else {
        panic!("a response");
    };
    assert_eq!(status.reason_phrase, "No Such Tenant");
    assert!(engine.commands("answer_local").is_empty());
    assert!(eventually(|| srs(&state).session_count() == 0).await);
    let ended: Vec<_> = channel_event_capture::take(call_id)
        .into_iter()
        .filter(|(event, _)| event == "StasisEnd")
        .collect();
    assert_eq!(ended.len(), 1, "{ended:?}");
    assert_eq!(ended[0].1["reason"], "rejected");
    assert_eq!(ended[0].1["code"], 404);
    assert!(matches!(
        verb(
            &state,
            call_id,
            "reject",
            serde_json::json!({ "code": 200 })
        ),
        ControlResult::Error { .. }
    ));
    let _ = std::fs::remove_dir_all(directory);
}

/// No decision within the handoff deadline refuses the session: a recording
/// nobody claimed is never answered 200.
#[tokio::test(flavor = "multi_thread")]
async fn no_decision_by_the_deadline_refuses_the_session() {
    let engine = NativeTestEngine::start().await;
    let directory = super::srs_handshake_tests::scratch_dir("deadline");
    let bus = bus(100);
    let connection = bus.register_connection(APP);
    let (state, udp) = controlled(&engine, &directory, &bus);
    let call_id = "deadline@198.51.100.20";

    send(&state, &siprec_invite(call_id, 2, true));
    stasis_start(&connection).await;
    let mut seen = Vec::new();
    await_response(&udp, &mut seen, 503, "INVITE").await;
    assert_eq!(count(&seen, 200, "INVITE"), 0);
    assert!(engine.commands("answer_local").is_empty());
    assert!(eventually(|| srs(&state).session_count() == 0).await);
    assert!(
        !srs(&state).is_awaiting_decision(call_id),
        "nothing left waiting"
    );
    let _ = std::fs::remove_dir_all(directory);
}

/// No connection of the application to offer it to: refused at once.
#[tokio::test(flavor = "multi_thread")]
async fn no_controller_refuses_the_session_at_once() {
    let engine = NativeTestEngine::start().await;
    let directory = super::srs_handshake_tests::scratch_dir("no-controller");
    let bus = bus(3000);
    let (state, udp) = controlled(&engine, &directory, &bus);
    send(&state, &siprec_invite("nobody@198.51.100.20", 2, true));
    let mut seen = Vec::new();
    await_response(&udp, &mut seen, 503, "INVITE").await;
    assert!(engine.commands("answer_local").is_empty());
    assert_eq!(srs(&state).session_count(), 0);
    let _ = std::fs::remove_dir_all(directory);
}

/// The application's `hangup` on an accepted session BYEs the SRC and ends the
/// recording; before its decision it is refused.
#[tokio::test(flavor = "multi_thread")]
async fn hangup_ends_an_accepted_session_with_a_bye() {
    let engine = NativeTestEngine::start().await;
    let directory = super::srs_handshake_tests::scratch_dir("hangup");
    let bus = bus(3000);
    let connection = bus.register_connection(APP);
    let (state, udp) = controlled(&engine, &directory, &bus);
    let call_id = "hangup@198.51.100.20";
    channel_event_capture::watch(call_id);

    send(&state, &siprec_invite(call_id, 2, true));
    stasis_start(&connection).await;
    assert!(matches!(
        verb(&state, call_id, "hangup", serde_json::json!({})),
        ControlResult::Error { .. }
    ));
    ok(verb(&state, call_id, "accept", serde_json::json!({})));
    let mut seen = Vec::new();
    let answered = await_response(&udp, &mut seen, 200, "INVITE").await;
    let tag = to_tag(&answered);
    send(
        &state,
        &request("ACK", call_id, "z9hG4bK-ack", 1, Some(&tag), None, "", true),
    );

    let streams = srs(&state).streams(call_id).expect("the session");
    ok(verb(&state, call_id, "hangup", serde_json::json!({})));
    seen.extend(super::srs_handshake_tests::drain(&udp));
    let bye = seen
        .iter()
        .find(|message| message.method() == Some(&crate::sip::message::Method::Bye))
        .expect("a BYE to the SRC");
    assert!(bye.headers.from().is_some_and(|from| from.contains(&tag)));
    assert!(eventually(|| engine.held_count() == 0).await);
    assert_eq!(srs(&state).session_count(), 0);
    files_close(&state, &streams).await;
    let ended = stasis_ends(call_id).await;
    assert_eq!(ended.len(), 1, "{ended:?}");
    assert_eq!(ended[0]["reason"], "hangup");
    let _ = std::fs::remove_dir_all(directory);
}

/// The SRC's BYE ends the channel too.
#[tokio::test(flavor = "multi_thread")]
async fn the_srcs_bye_ends_the_channel() {
    let engine = NativeTestEngine::start().await;
    let directory = super::srs_handshake_tests::scratch_dir("src-bye");
    let bus = bus(3000);
    let connection = bus.register_connection(APP);
    let (state, udp) = controlled(&engine, &directory, &bus);
    let call_id = "src-bye@198.51.100.20";
    channel_event_capture::watch(call_id);

    send(&state, &siprec_invite(call_id, 2, true));
    stasis_start(&connection).await;
    ok(verb(&state, call_id, "accept", serde_json::json!({})));
    let mut seen = Vec::new();
    let answered = await_response(&udp, &mut seen, 200, "INVITE").await;
    let tag = to_tag(&answered);
    let streams = srs(&state).streams(call_id).expect("the session");
    send(
        &state,
        &request("BYE", call_id, "z9hG4bK-bye", 2, Some(&tag), None, "", true),
    );
    await_response(&udp, &mut seen, 200, "BYE").await;
    files_close(&state, &streams).await;
    let ended = stasis_ends(call_id).await;
    assert_eq!(ended.len(), 1, "{ended:?}");
    assert_eq!(ended[0]["reason"], "bye");
    assert!(eventually(|| engine.held_count() == 0).await);
    let _ = std::fs::remove_dir_all(directory);
}

/// The engine reports every file of `streams` closed, as it does once their
/// calls are deleted.
async fn files_close(state: &DispatcherState, streams: &[crate::srs::SrsStream]) {
    for stream in streams {
        if let (Some(engine_call_id), Some(recording_id)) =
            (&stream.engine_call_id, &stream.recording_id)
        {
            super::rtpengine_events::on_recording_finished(
                state,
                crate::rtpengine::events::RecordingFinished {
                    call_id: engine_call_id.clone(),
                    from_tag: "src-tag".to_string(),
                    recording_id: recording_id.clone(),
                    path: None,
                    reason: "call_ended",
                    duration_ms: 1000,
                },
                None,
            )
            .await;
        }
    }
}

/// The `StasisEnd`s the channel of `call_id` got, once there is one: it comes
/// after the session's files are closed.
async fn stasis_ends(call_id: &str) -> Vec<serde_json::Value> {
    let collected = std::sync::Mutex::new(Vec::new());
    eventually(|| {
        let mut collected = collected.lock().expect("the collected events");
        collected.extend(
            channel_event_capture::take(call_id)
                .into_iter()
                .filter(|(event, _)| event == "StasisEnd")
                .map(|(_, payload)| payload),
        );
        !collected.is_empty()
    })
    .await;
    collected.into_inner().expect("the collected events")
}

/// A verb on a recording channel reaches the SRS, never the B2BUA: the SIP
/// adapter routes by the channel's call-actor id.
#[test]
fn an_srs_channel_verb_is_routed_to_the_srs() {
    assert_eq!(crate::dispatcher::srs::SRS_ACTOR_PREFIX, "srs:");
    let result = crate::dispatcher::srs::srs_control_verb(
        "no-such@198.51.100.20",
        "accept",
        &serde_json::json!({}),
    );
    assert!(matches!(result, ControlResult::Error { .. }));
}
