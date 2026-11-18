//! An accepted recording session streamed live to a WebSocket (#891): one tee
//! over every live stream, the first participant's first, through the same
//! `stream_start` / `stream_stop` a call takes; nothing else applies to it.

use super::srs_handshake_tests::{await_response, scratch_dir, send, siprec_invite, srs_state};
use super::*;
use crate::control::protocol::ControlResult;
use crate::control::ChannelRef;
use crate::rtpengine::test_native_engine::NativeTestEngine;

fn recording_channel(call_id: &str) -> ChannelRef {
    ChannelRef {
        channel_id: "srs-test".to_string(),
        call_actor_id: format!("{}{call_id}", crate::dispatcher::srs::SRS_ACTOR_PREFIX),
        sip_call_id: call_id.to_string(),
        app: "recorder".to_string(),
    }
}

/// A recording session with `streams` streams, answered.
async fn session(
    engine: &NativeTestEngine,
    name: &str,
    streams: usize,
) -> (Arc<DispatcherState>, String, std::path::PathBuf) {
    let directory = scratch_dir(name);
    let (state, udp) = srs_state(engine, &directory);
    let call_id = format!("{name}@198.51.100.20");
    send(&state, &siprec_invite(&call_id, streams, true));
    let mut seen = Vec::new();
    await_response(&udp, &mut seen, 200, "INVITE").await;
    (state, call_id, directory)
}

async fn multi_source_engine() -> NativeTestEngine {
    NativeTestEngine::start_with_features(&["relay", "scope", "ws_tee_multi_source"]).await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_two_stream_session_is_one_tee_over_both_streams() {
    let engine = multi_source_engine().await;
    let (state, call_id, directory) = session(&engine, "tee-two", 2).await;
    let result = crate::control::sip_adapter::recording_stream_start_on(
        &recording_channel(&call_id),
        &call_id,
        &serde_json::json!({ "mode": "tee", "ws_uri": "wss://asr.example.com/{call_id}", "sample_rate": 16000 }),
        crate::dispatcher::srs::srs_media_target_in(&state, &call_id),
    )
    .await;
    let ControlResult::Ok(reply) = result else {
        panic!("refused: {result:?}");
    };
    assert_eq!(reply["state"], "streaming");
    assert_eq!(reply["sources"], 2);
    let tees = engine.commands("attach_ws_tee");
    assert_eq!(tees.len(), 1);
    assert_eq!(
        tees[0].call_id,
        format!("{call_id}~0"),
        "the first participant's stream first"
    );
    assert_eq!(tees[0].sources, [format!("{call_id}~1")]);
    assert_eq!(
        tees[0].detail.as_deref(),
        Some(format!("wss://asr.example.com/{}", call_id.replace('@', "%40")).as_str()),
        "the template expands with the recording dialog's Call-ID, encoded as for a call"
    );

    let stopped = crate::control::sip_adapter::recording_stream_stop_on(
        &recording_channel(&call_id),
        &serde_json::json!({ "mode": "tee" }),
        crate::dispatcher::srs::srs_media_target_in(&state, &call_id),
    )
    .await;
    assert!(matches!(stopped, ControlResult::Ok(_)), "{stopped:?}");
    assert!(engine
        .commands("detach_ws_tee")
        .iter()
        .any(|detach| detach.call_id == format!("{call_id}~0")));
    let _ = std::fs::remove_dir_all(directory);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_one_stream_session_is_an_ordinary_tee() {
    let engine = NativeTestEngine::start().await;
    let (state, call_id, directory) = session(&engine, "tee-one", 1).await;
    let result = crate::control::sip_adapter::recording_stream_start_on(
        &recording_channel(&call_id),
        &call_id,
        &serde_json::json!({ "ws_uri": "wss://asr.example.com/x" }),
        crate::dispatcher::srs::srs_media_target_in(&state, &call_id),
    )
    .await;
    assert!(matches!(result, ControlResult::Ok(_)), "{result:?}");
    let tees = engine.commands("attach_ws_tee");
    assert_eq!(tees.len(), 1);
    assert!(tees[0].sources.is_empty());
    let _ = std::fs::remove_dir_all(directory);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_engine_without_multi_source_refuses_a_two_stream_tee() {
    let engine = NativeTestEngine::start().await;
    let (state, call_id, directory) = session(&engine, "tee-old", 2).await;
    let result = crate::control::sip_adapter::recording_stream_start_on(
        &recording_channel(&call_id),
        &call_id,
        &serde_json::json!({ "ws_uri": "wss://asr.example.com/x" }),
        crate::dispatcher::srs::srs_media_target_in(&state, &call_id),
    )
    .await;
    assert!(matches!(result, ControlResult::Error { .. }), "{result:?}");
    assert!(
        engine.commands("attach_ws_tee").is_empty(),
        "nothing half-attached"
    );
    let _ = std::fs::remove_dir_all(directory);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_bridge_or_callee_audio_is_refused() {
    let engine = multi_source_engine().await;
    let (state, call_id, directory) = session(&engine, "tee-refused", 2).await;
    for args in [
        serde_json::json!({ "mode": "bridge", "ws_uri": "wss://x" }),
        serde_json::json!({ "direction": "callee", "ws_uri": "wss://x" }),
        serde_json::json!({ "mode": "tee" }),
    ] {
        let result = crate::control::sip_adapter::recording_stream_start_on(
            &recording_channel(&call_id),
            &call_id,
            &args,
            crate::dispatcher::srs::srs_media_target_in(&state, &call_id),
        )
        .await;
        assert!(
            matches!(result, ControlResult::Error { .. }),
            "{args}: {result:?}"
        );
    }
    assert!(engine.commands("attach_ws_tee").is_empty());
    let _ = std::fs::remove_dir_all(directory);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_tees_events_reach_the_recording_channel() {
    let engine = multi_source_engine().await;
    let (state, call_id, directory) = session(&engine, "tee-events", 2).await;
    assert_eq!(
        super::engine_channel_events::engine_event_channel(
            &state,
            &format!("{call_id}~0"),
            "src-tag"
        )
        .as_deref(),
        Some(call_id.as_str())
    );
    let _ = std::fs::remove_dir_all(directory);
}
