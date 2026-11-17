//! A two-stream recording session written as one stereo file (#890): left and
//! right follow `participantstreamassoc`, the file is reported once with both
//! streams, and anything that cannot be one stereo file is a file per stream.

use super::srs_control_tests::{bus, controlled, ok, stasis_start, verb, APP};
use super::srs_handshake_tests::{
    await_response, metadata, multipart, offer, request, scratch_dir, send, srs, to_tag,
};
use super::*;
use crate::control::channel_event_capture;
use crate::rtpengine::test_native_engine::NativeTestEngine;

/// An engine that records several calls into one file.
async fn multi_source_engine() -> NativeTestEngine {
    NativeTestEngine::start_with_features(&[
        "relay",
        "scope",
        "conference_seat",
        "record_multi_source",
        "ws_tee_multi_source",
    ])
    .await
}

/// A SIPREC INVITE for `streams` streams whose metadata is `xml`.
fn invite_with(call_id: &str, streams: usize, xml: &str) -> String {
    request(
        "INVITE",
        call_id,
        &format!("z9hG4bK-{call_id}"),
        1,
        None,
        Some("multipart/mixed;boundary=srs-boundary"),
        &multipart(&offer(streams), xml),
        true,
    )
}

/// Offer `call_id`, accept it stereo, and wait for the 200.
async fn accepted_stereo(
    engine: &NativeTestEngine,
    directory: &std::path::Path,
    call_id: &str,
    streams: usize,
    xml: &str,
) -> (
    Arc<DispatcherState>,
    flume::Receiver<OutboundMessage>,
    SipMessage,
) {
    let bus = bus(3000);
    let connection = bus.register_connection(APP);
    let (state, udp) = controlled(engine, directory, &bus);
    send(&state, &invite_with(call_id, streams, xml));
    stasis_start(&connection).await;
    ok(verb(
        &state,
        call_id,
        "accept",
        serde_json::json!({ "channels": "stereo" }),
    ));
    let mut seen = Vec::new();
    let answered = await_response(&udp, &mut seen, 200, "INVITE").await;
    (state, udp, answered)
}

#[tokio::test(flavor = "multi_thread")]
async fn two_streams_are_one_stereo_file_left_the_first_participants() {
    let engine = multi_source_engine().await;
    let directory = scratch_dir("stereo");
    let call_id = "stereo@198.51.100.20";
    let (state, _udp, _) = accepted_stereo(&engine, &directory, call_id, 2, &metadata(2)).await;

    let recordings = engine.commands("start_recording");
    assert_eq!(recordings.len(), 1, "one file for the session");
    let file = &recordings[0];
    assert_eq!(
        file.call_id,
        format!("{call_id}~0"),
        "left: the stream p-a sends"
    );
    assert_eq!(file.sources, [format!("{call_id}~1")], "right");
    assert_eq!(file.channels.as_deref(), Some("stereo"));
    let streams = srs(&state).streams(call_id).expect("the session");
    assert_eq!(streams[0].recording_id, streams[1].recording_id);
    assert_eq!(
        (streams[0].recording_channel, streams[1].recording_channel),
        (0, 1)
    );
    let _ = std::fs::remove_dir_all(directory);
}

#[tokio::test(flavor = "multi_thread")]
async fn left_follows_participantstreamassoc_not_stream_order() {
    let engine = multi_source_engine().await;
    let directory = scratch_dir("stereo-order");
    let call_id = "stereo-order@198.51.100.20";
    // p-b, who sends the second stream, is listed first.
    let xml = metadata(2).replace(
        "<participantstreamassoc participant_id=\"p-a\"><send>s-0</send><recv>s-1</recv></participantstreamassoc>\r\n<participantstreamassoc participant_id=\"p-b\"><send>s-1</send><recv>s-0</recv></participantstreamassoc>\r\n",
        "<participantstreamassoc participant_id=\"p-b\"><send>s-1</send><recv>s-0</recv></participantstreamassoc>\r\n<participantstreamassoc participant_id=\"p-a\"><send>s-0</send><recv>s-1</recv></participantstreamassoc>\r\n",
    );
    assert_ne!(xml, metadata(2), "the associations were swapped");
    accepted_stereo(&engine, &directory, call_id, 2, &xml).await;
    let file = &engine.commands("start_recording")[0];
    assert_eq!(
        file.call_id,
        format!("{call_id}~1"),
        "left: the stream p-b sends"
    );
    assert_eq!(file.sources, [format!("{call_id}~0")]);
    let _ = std::fs::remove_dir_all(directory);
}

/// The stereo file closes once and is reported with both streams, both
/// participants, and as the session's one recording.
#[tokio::test(flavor = "multi_thread")]
async fn the_stereo_file_is_reported_once_with_both_streams() {
    let engine = multi_source_engine().await;
    let directory = scratch_dir("stereo-report");
    let call_id = "stereo-report@198.51.100.20";
    channel_event_capture::watch(call_id);
    let (state, udp, answered) =
        accepted_stereo(&engine, &directory, call_id, 2, &metadata(2)).await;
    let tag = to_tag(&answered);
    let streams = srs(&state).streams(call_id).expect("the session");
    send(
        &state,
        &request("BYE", call_id, "z9hG4bK-bye", 2, Some(&tag), None, "", true),
    );
    let mut seen = Vec::new();
    await_response(&udp, &mut seen, 200, "BYE").await;
    // The engine reports the one file, under its first source.
    super::srs_control_tests::files_close(&state, &streams[..1]).await;

    let collected = std::sync::Mutex::new(Vec::new());
    super::srs_handshake_tests::eventually(|| {
        let mut collected = collected.lock().expect("the events");
        collected.extend(channel_event_capture::take(call_id));
        collected.iter().any(|(event, _)| event == "StasisEnd")
    })
    .await;
    let reported = collected.into_inner().expect("the events");
    let finished: Vec<_> = reported
        .iter()
        .filter(|(event, _)| event == "RecordingFinished")
        .collect();
    assert_eq!(finished.len(), 1, "{reported:?}");
    let file = &finished[0].1;
    assert_eq!(file["channels"], "stereo");
    assert_eq!(file["stream_ids"], serde_json::json!(["s-0", "s-1"]));
    assert_eq!(file["participant_ids"], serde_json::json!(["p-a", "p-b"]));
    let ended = reported
        .iter()
        .find(|(event, _)| event == "RecordingSessionEnded")
        .expect("the session end");
    assert_eq!(ended.1["recordings"].as_array().map(Vec::len), Some(1));
    assert_eq!(srs(&state).tracked_counts(), (0, 0));
    let _ = std::fs::remove_dir_all(directory);
}

/// An engine that cannot record two calls into one file still gets every
/// stream recorded, a file each: never a 200 for media not recorded.
#[tokio::test(flavor = "multi_thread")]
async fn an_engine_without_multi_source_records_a_file_per_stream() {
    let engine = NativeTestEngine::start().await;
    let directory = scratch_dir("stereo-fallback");
    let call_id = "stereo-fallback@198.51.100.20";
    accepted_stereo(&engine, &directory, call_id, 2, &metadata(2)).await;
    let recordings = engine.commands("start_recording");
    assert_eq!(recordings.len(), 2, "{recordings:?}");
    assert!(recordings.iter().all(|file| file.sources.is_empty()));
    let _ = std::fs::remove_dir_all(directory);
}

/// Stereo is a two-stream shape: three streams are three files.
#[tokio::test(flavor = "multi_thread")]
async fn three_streams_are_three_files_even_in_stereo() {
    let engine = multi_source_engine().await;
    let directory = scratch_dir("stereo-three");
    let call_id = "stereo-three@198.51.100.20";
    accepted_stereo(&engine, &directory, call_id, 3, &metadata(3)).await;
    let recordings = engine.commands("start_recording");
    assert_eq!(recordings.len(), 3);
    assert!(recordings.iter().all(|file| file.sources.is_empty()));
    let _ = std::fs::remove_dir_all(directory);
}
