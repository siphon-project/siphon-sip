//! A newer engine's end reason must still arrive as an event, spelled
//! `unknown`, never panic and never drop the event.

use super::events::convert_event;
use crate::rtpengine::events::{PlayEndReason, RtpEngineEvent, WsBridgeEndReason, WsTeeEndReason};
use siphon_rtp_proto::Event;

const FUTURE: &str = "a_reason_added_by_a_newer_engine";

fn decode(frame: &str) -> RtpEngineEvent {
    let event: Event = serde_json::from_str(frame).expect("frame decodes");
    convert_event(event)
}

#[test]
fn tee_end_with_unknown_reason_reaches_scripts_as_unknown() {
    let event = decode(&format!(
        r#"{{"event":"ws_tee_ended","call_id":"c","from_tag":"f","stream_id":"s","reason":"{FUTURE}"}}"#
    ));
    let RtpEngineEvent::WsTeeEnded(ended) = event else {
        panic!("a ws_tee_ended event");
    };
    assert_eq!(ended.reason, WsTeeEndReason::Other("unknown"));
    assert_eq!(ended.reason.as_str(), "unknown");
    assert!(ended.reason.is_unexpected());
}

#[test]
fn bridge_end_with_unknown_reason_reaches_scripts_as_unknown() {
    let event = decode(&format!(
        r#"{{"event":"ws_bridge_ended","call_id":"c","from_tag":"f","stream_id":"s","reason":"{FUTURE}"}}"#
    ));
    let RtpEngineEvent::WsBridgeEnded(ended) = event else {
        panic!("a ws_bridge_ended event");
    };
    assert_eq!(ended.reason, WsBridgeEndReason::Other("unknown"));
    assert_eq!(ended.reason.as_str(), "unknown");
    assert!(ended.reason.is_unexpected());
}

#[test]
fn split_end_with_unknown_reason_reaches_scripts_as_unknown() {
    let event = decode(&format!(
        r#"{{"event":"ws_split_ended","call_id":"c","from_tag":"f","stream_id":"s","reason":"{FUTURE}"}}"#
    ));
    let RtpEngineEvent::WsSplitEnded(ended) = event else {
        panic!("a ws_split_ended event");
    };
    assert_eq!(ended.reason, "unknown");
}

#[test]
fn play_finished_with_unknown_reason_is_not_completed() {
    let event = decode(&format!(
        r#"{{"event":"play_finished","call_id":"c","from_tag":"f","play_id":3,"reason":"{FUTURE}"}}"#
    ));
    let RtpEngineEvent::PlayFinished(finished) = event else {
        panic!("a play_finished event");
    };
    assert_eq!(finished.reason, PlayEndReason::Other("unknown"));
    assert_eq!(finished.reason.as_str(), "unknown");
    assert!(!finished.reason.is_completed());
}

#[test]
fn media_timeout_with_unknown_reason_reaches_scripts_as_unknown() {
    let event = decode(&format!(
        r#"{{"event":"media_timeout","call_id":"c","from_tag":"f","reason":"{FUTURE}"}}"#
    ));
    let RtpEngineEvent::MediaTimeout { reason, .. } = event else {
        panic!("a media_timeout event");
    };
    assert_eq!(reason, "unknown");
}

#[test]
fn x3_end_with_unknown_reason_is_unknown_and_not_orderly() {
    let event = decode(&format!(
        r#"{{"event":"x3_ended","call_id":"c","from_tag":"f","reason":"{FUTURE}","delivered":3,"dropped":0}}"#
    ));
    let RtpEngineEvent::X3Ended(ended) = event else {
        panic!("an x3_ended event");
    };
    assert_eq!(ended.reason, "unknown");
    assert!(!ended.orderly);
}

#[test]
fn recording_finished_with_unknown_reason_reaches_scripts_as_unknown() {
    let event = decode(&format!(
        r#"{{"event":"recording_finished","call_id":"c","from_tag":"f","recording_id":"r","duration_ms":10,"reason":"{FUTURE}"}}"#
    ));
    let RtpEngineEvent::RecordingFinished(finished) = event else {
        panic!("a recording_finished event");
    };
    assert_eq!(finished.reason, "unknown");
}
