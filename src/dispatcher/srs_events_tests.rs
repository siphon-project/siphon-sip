//! What a recording session reports while it records and once it ends (#889):
//! `RecordingFinished` per file with its SIPREC context, `RecordingMetadataUpdated`,
//! and `RecordingSessionEnded` only once every file is closed, ahead of
//! `StasisEnd`.
//!
//! The SRC's requests go through the dispatcher's request path; the engine's
//! `recording_finished` events enter where the event driver hands them in.

use super::srs_handshake_tests::{
    await_response, eventually, request, scratch_dir, send, siprec_invite, srs, srs_state, to_tag,
};
use super::*;
use crate::control::channel_event_capture;
use crate::rtpengine::test_native_engine::NativeTestEngine;

/// The engine reports `recording_id` on `engine_call_id` closed.
async fn engine_closes(state: &DispatcherState, engine_call_id: &str, recording_id: &str) {
    super::rtpengine_events::on_recording_finished(
        state,
        crate::rtpengine::events::RecordingFinished {
            call_id: engine_call_id.to_string(),
            from_tag: "src-tag".to_string(),
            recording_id: recording_id.to_string(),
            path: Some(format!("/rec/{recording_id}.wav")),
            reason: "call_ended",
            duration_ms: 4200,
        },
        None,
    )
    .await;
}

fn events(call_id: &str) -> Vec<(String, serde_json::Value)> {
    channel_event_capture::take(call_id)
}

/// Each file closes with the streams and participants it holds; the session
/// end is reported once both are closed, then the channel ends.
#[tokio::test(flavor = "multi_thread")]
async fn a_session_reports_each_file_then_its_end_then_stasis_end() {
    let engine = NativeTestEngine::start().await;
    let directory = scratch_dir("events");
    let (state, udp) = srs_state(&engine, &directory);
    let call_id = "events@198.51.100.20";
    channel_event_capture::watch(call_id);

    send(&state, &siprec_invite(call_id, 2, true));
    let mut seen = Vec::new();
    let answered = await_response(&udp, &mut seen, 200, "INVITE").await;
    let tag = to_tag(&answered);
    let streams = srs(&state).streams(call_id).expect("the session");
    let recordings: Vec<(String, String)> = streams
        .iter()
        .map(|stream| {
            (
                stream.engine_call_id.clone().expect("an engine call"),
                stream.recording_id.clone().expect("a recording"),
            )
        })
        .collect();

    send(
        &state,
        &request("BYE", call_id, "z9hG4bK-bye", 2, Some(&tag), None, "", true),
    );
    await_response(&udp, &mut seen, 200, "BYE").await;
    assert!(eventually(|| engine.commands("delete").len() == 2).await);
    let early = events(call_id);
    assert!(
        early.iter().all(|(event, _)| event != "StasisEnd"),
        "no StasisEnd while files are open: {early:?}"
    );

    engine_closes(&state, &recordings[0].0, &recordings[0].1).await;
    engine_closes(&state, &recordings[1].0, &recordings[1].1).await;
    let collected = std::sync::Mutex::new(Vec::new());
    assert!(
        eventually(|| {
            let mut collected = collected.lock().expect("the collected events");
            collected.extend(events(call_id));
            collected.iter().any(|(event, _)| event == "StasisEnd")
        })
        .await
    );
    let reported = collected.into_inner().expect("the collected events");
    let names: Vec<&str> = reported.iter().map(|(event, _)| event.as_str()).collect();
    assert_eq!(
        names,
        [
            "RecordingFinished",
            "RecordingFinished",
            "RecordingSessionEnded",
            "StasisEnd"
        ]
    );

    let first = &reported[0].1;
    assert_eq!(first["recording_id"], recordings[0].1);
    assert_eq!(first["path"], format!("/rec/{}.wav", recordings[0].1));
    assert_eq!(first["format"], "wav");
    assert_eq!(first["label"], "1");
    assert_eq!(first["stream_ids"], serde_json::json!(["s-0"]));
    assert_eq!(first["participant_ids"], serde_json::json!(["p-a"]));
    assert_eq!(first["duration_ms"], 4200);
    assert_eq!(first["reason"], "call_ended");
    assert_eq!(reported[1].1["participant_ids"], serde_json::json!(["p-b"]));

    let ended = &reported[2].1;
    assert_eq!(ended["reason"], "bye");
    assert_eq!(ended["session_id"], "rs-shared");
    assert_eq!(
        ended["sip_session_ids"],
        serde_json::json!(["orig@example.com"])
    );
    assert_eq!(ended["recordings"].as_array().map(Vec::len), Some(2));
    assert_eq!(
        ended["metadata"]["participant_stream"]
            .as_array()
            .map(Vec::len),
        Some(2)
    );
    assert_eq!(reported[3].1["reason"], "bye");
    assert_eq!(
        srs(&state).tracked_counts(),
        (0, 0),
        "recordings and closing sessions drain"
    );
    let _ = std::fs::remove_dir_all(directory);
}

/// A partial update in an UPDATE is reported as the merged snapshot.
#[tokio::test(flavor = "multi_thread")]
async fn a_metadata_update_reports_the_merged_snapshot() {
    let engine = NativeTestEngine::start().await;
    let directory = scratch_dir("meta-event");
    let (state, udp) = srs_state(&engine, &directory);
    let call_id = "meta-event@198.51.100.20";
    channel_event_capture::watch(call_id);
    send(&state, &siprec_invite(call_id, 2, true));
    let mut seen = Vec::new();
    let answered = await_response(&udp, &mut seen, 200, "INVITE").await;
    let tag = to_tag(&answered);

    let partial = concat!(
        "<recording xmlns=\"urn:ietf:params:xml:ns:recording:1\">",
        "<datamode>partial</datamode>",
        "<participant participant_id=\"p-c\"><nameID aor=\"sip:carol@example.com\"/></participant>",
        "</recording>",
    );
    send(
        &state,
        &request(
            "UPDATE",
            call_id,
            "z9hG4bK-up",
            2,
            Some(&tag),
            Some("application/rs-metadata+xml"),
            partial,
            true,
        ),
    );
    await_response(&udp, &mut seen, 200, "UPDATE").await;
    let updated: Vec<_> = events(call_id)
        .into_iter()
        .filter(|(event, _)| event == "RecordingMetadataUpdated")
        .collect();
    assert_eq!(updated.len(), 1, "{updated:?}");
    let payload = &updated[0].1;
    assert_eq!(payload["datamode"], "partial");
    assert_eq!(payload["session_id"], "rs-shared");
    assert_eq!(
        payload["metadata"]["participants"].as_array().map(Vec::len),
        Some(3),
        "the merged snapshot, not the update"
    );
    let _ = std::fs::remove_dir_all(directory);
}

/// A recording the engine closes mid-session (a stream re-answered) reports
/// on its own and is not waited for at the end.
#[tokio::test(flavor = "multi_thread")]
async fn a_file_closed_mid_session_is_reported_at_once() {
    let engine = NativeTestEngine::start().await;
    let directory = scratch_dir("mid");
    let (state, udp) = srs_state(&engine, &directory);
    let call_id = "mid@198.51.100.20";
    channel_event_capture::watch(call_id);
    send(&state, &siprec_invite(call_id, 2, true));
    let mut seen = Vec::new();
    await_response(&udp, &mut seen, 200, "INVITE").await;
    let stream = srs(&state).streams(call_id).expect("the session")[0].clone();
    engine_closes(
        &state,
        stream.engine_call_id.as_deref().expect("an engine call"),
        stream.recording_id.as_deref().expect("a recording"),
    )
    .await;
    let reported = events(call_id);
    assert_eq!(reported.len(), 1, "{reported:?}");
    assert_eq!(reported[0].0, "RecordingFinished");
    assert_eq!(
        srs(&state).tracked_counts(),
        (1, 0),
        "the other is still open"
    );
    let _ = std::fs::remove_dir_all(directory);
}

/// A recording that is not the SRS's goes the ordinary way.
#[tokio::test(flavor = "multi_thread")]
async fn a_recording_of_no_session_is_not_the_srss() {
    let engine = NativeTestEngine::start().await;
    let directory = scratch_dir("foreign");
    let (state, _udp) = srs_state(&engine, &directory);
    assert!(!crate::dispatcher::srs::srs_recording_finished(
        &state,
        &crate::rtpengine::events::RecordingFinished {
            call_id: "a-call".to_string(),
            from_tag: "t".to_string(),
            recording_id: "rec-x".to_string(),
            path: None,
            reason: "stopped",
            duration_ms: 0,
        },
    ));
    let _ = std::fs::remove_dir_all(directory);
}
