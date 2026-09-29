//! The media engine's end-of-call summary on the control rail: `MediaSummary`
//! on the channel that owns the call, keyed by its SIP Call-ID the way every
//! other engine event reaches a channel.

use std::collections::HashMap;
use std::sync::Arc;

use super::*;
use crate::control::{ControlBus, OutboundFrame, SlowConsumerPolicy};
use crate::rtpengine::events::{CallLegSummary, CallSummary, TextStreamStats};

/// A leg a userspace actor measured: counters and quality.
fn measured_leg() -> CallLegSummary {
    CallLegSummary {
        tag: "caller-tag".to_string(),
        codec: Some("PCMU".to_string()),
        packets_in: 2100,
        bytes_in: 336_000,
        packets_out: 2098,
        bytes_out: 335_680,
        packets_dropped: 2,
        ssrc: Some(0x0102_0304),
        packets_lost: Some(6),
        loss_percent: Some(0.25),
        jitter_ms: Some(4.5),
        rtt_ms: Some(21.0),
        mos_average: Some(4.25),
        mos_min: Some(3.5),
        mos_max: Some(4.5),
        mos_basis: Some("full".to_string()),
        text: Some(TextStreamStats {
            packets: 40,
            characters: 120,
            missing_markers: 1,
            recovered_from_redundancy: 3,
        }),
        local_address: Some("192.0.2.10:30000".parse().expect("an address")),
        remote_address: Some("198.51.100.20:40000".parse().expect("an address")),
        egress_ssrc: Some(0x0506_0708),
        payload_type: Some(0),
    }
}

/// A leg on the in-kernel relay: counters only, nothing measured.
fn counters_only_leg() -> CallLegSummary {
    CallLegSummary {
        tag: "phone-tag".to_string(),
        codec: None,
        packets_in: 2099,
        bytes_in: 335_840,
        packets_out: 2100,
        bytes_out: 336_000,
        packets_dropped: 0,
        ssrc: None,
        packets_lost: None,
        loss_percent: None,
        jitter_ms: None,
        rtt_ms: None,
        mos_average: None,
        mos_min: None,
        mos_max: None,
        mos_basis: None,
        text: None,
        local_address: None,
        remote_address: None,
        egress_ssrc: None,
        payload_type: None,
    }
}

fn summary(call_id: &str) -> CallSummary {
    CallSummary {
        call_id: call_id.to_string(),
        reason: "media_timeout".to_string(),
        duration_ms: 42_000,
        legs: vec![measured_leg(), counters_only_leg()],
    }
}

/// Every counter and quality figure the summary carries is in the payload; a
/// figure the engine did not measure is absent, not zero, so "counters only"
/// reads differently from "measured and perfect".
#[test]
fn the_payload_carries_each_legs_counters_and_quality() {
    let payload = media_summary_payload(&summary("ms-payload@example.test"));
    assert_eq!(payload["reason"], "media_timeout");
    assert_eq!(payload["duration_ms"], 42_000);
    let legs = payload["legs"].as_array().expect("a legs array");
    assert_eq!(legs.len(), 2);

    let measured = &legs[0];
    assert_eq!(measured["tag"], "caller-tag");
    assert_eq!(measured["codec"], "PCMU");
    assert_eq!(measured["packets_in"], 2100);
    assert_eq!(measured["bytes_in"], 336_000);
    assert_eq!(measured["packets_out"], 2098);
    assert_eq!(measured["bytes_out"], 335_680);
    assert_eq!(measured["packets_dropped"], 2);
    assert_eq!(measured["ssrc"], 0x0102_0304);
    assert_eq!(measured["packets_lost"], 6);
    assert_eq!(measured["loss_percent"], 0.25);
    assert_eq!(measured["jitter_ms"], 4.5);
    assert_eq!(measured["rtt_ms"], 21.0);
    assert_eq!(measured["mos_average"], 4.25);
    assert_eq!(measured["mos_min"], 3.5);
    assert_eq!(measured["mos_max"], 4.5);
    assert_eq!(measured["mos_basis"], "full");
    assert_eq!(measured["text"]["characters"], 120);
    assert_eq!(measured["text"]["recovered_from_redundancy"], 3);
    assert_eq!(measured["local_address"], "192.0.2.10:30000");
    assert_eq!(measured["remote_address"], "198.51.100.20:40000");
    assert_eq!(measured["egress_ssrc"], 0x0506_0708);
    assert_eq!(measured["payload_type"], 0);

    let counters_only = legs[1].as_object().expect("a leg object");
    assert_eq!(counters_only["packets_in"], 2099);
    assert_eq!(counters_only["packets_dropped"], 0);
    for absent in [
        "codec",
        "ssrc",
        "packets_lost",
        "loss_percent",
        "jitter_ms",
        "rtt_ms",
        "mos_average",
        "mos_min",
        "mos_max",
        "mos_basis",
        "text",
        "local_address",
        "remote_address",
        "egress_ssrc",
        "payload_type",
    ] {
        assert!(
            !counters_only.contains_key(absent),
            "{absent} was not measured"
        );
    }
}

/// The engine's summary is published as `MediaSummary` for the call it names,
/// on the rail every other engine event takes to a channel.
#[test]
fn a_summary_is_published_for_its_sip_call_id() {
    let call_id = "ms-published@example.test";
    crate::control::channel_event_capture::watch(call_id);
    publish_media_summary(
        &super::test_dispatcher::test_dispatcher().state,
        &summary(call_id),
    );
    let captured = crate::control::channel_event_capture::take(call_id);
    assert_eq!(captured.len(), 1, "{captured:?}");
    assert_eq!(captured[0].0, "MediaSummary");
    assert_eq!(
        captured[0].1,
        media_summary_payload(&summary(call_id)),
        "the payload is the summary's"
    );
}

/// Wired end to end: a summary on the media backend's event stream reaches
/// the control rail through the dispatcher's event loop, not only through the
/// function the loop calls.
#[tokio::test]
async fn the_engine_event_stream_publishes_the_summary() {
    let call_id = "ms-stream@example.test";
    crate::control::channel_event_capture::watch(call_id);
    let state = Arc::new(super::test_dispatcher::test_dispatcher().state);
    let (events, receiver) = tokio::sync::mpsc::channel(4);
    spawn_rtpengine_events(&state, receiver);
    events
        .send(crate::rtpengine::events::RtpEngineEvent::CallSummary(
            summary(call_id),
        ))
        .await
        .expect("the event loop is running");
    let mut captured = Vec::new();
    for _ in 0..100 {
        captured.extend(crate::control::channel_event_capture::take(call_id));
        if !captured.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(captured.len(), 1, "{captured:?}");
    assert_eq!(captured[0].0, "MediaSummary");
    assert_eq!(captured[0].1["legs"][1]["tag"], "phone-tag");
}

fn bus() -> Arc<ControlBus> {
    let (command_tx, _commands) = flume::unbounded();
    ControlBus::new(
        command_tx,
        vec![crate::config::ControlAppConfig {
            name: "media-app".to_string(),
            token: "token".to_string(),
            per_call_connect: false,
            connect_url: None,
            on_lost: None,
            ca_file: None,
            events: Vec::new(),
        }],
        16,
        SlowConsumerPolicy::DropOldest,
        10,
        3000,
    )
}

/// On the bus: a controlled call's owner gets the summary on its channel, and a
/// call nobody controls publishes nothing and does not fail.
#[tokio::test]
async fn only_the_owning_channel_hears_a_summary() {
    let bus = bus();
    let connection = bus.register_connection("media-app");
    bus.register_channel(
        "ch-media",
        &connection,
        "actor-media",
        "ms-owned@example.test",
        "hangup",
        HashMap::new(),
    );

    assert!(bus.forward_channel_event(
        "ms-owned@example.test",
        "MediaSummary",
        media_summary_payload(&summary("ms-owned@example.test")),
    ));
    let frames = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        connection.events.recv_many(),
    )
    .await
    .expect("a frame for the owner");
    let event = frames
        .into_iter()
        .find_map(|frame| match frame {
            OutboundFrame::Event(event) if event.event == "MediaSummary" => Some(event),
            _ => None,
        })
        .expect("MediaSummary reaches the owner");
    assert_eq!(event.channel.as_deref(), Some("ch-media"));
    assert_eq!(event.sip_call_id.as_deref(), Some("ms-owned@example.test"));
    assert_eq!(event.payload["legs"][0]["mos_average"], 4.25);

    // Nobody controls this call: nothing is published, and nothing fails.
    assert!(!bus.forward_channel_event(
        "ms-uncontrolled@example.test",
        "MediaSummary",
        media_summary_payload(&summary("ms-uncontrolled@example.test")),
    ));

    // After StasisEnd the channel is gone, but its owner still gets the
    // summary, under the channel id the call had.
    bus.on_call_terminated("ms-owned@example.test", "bye");
    assert!(!bus.forward_channel_event(
        "ms-owned@example.test",
        "MediaSummary",
        media_summary_payload(&summary("ms-owned@example.test")),
    ));
    assert!(bus.forward_media_summary(
        "ms-owned@example.test",
        media_summary_payload(&summary("ms-owned@example.test")),
    ));
    let frames = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        connection.events.recv_many(),
    )
    .await
    .expect("frames for the owner");
    let names: Vec<(String, Option<String>)> = frames
        .into_iter()
        .filter_map(|frame| match frame {
            OutboundFrame::Event(event) => Some((event.event, event.channel)),
            OutboundFrame::Reply(_) => None,
        })
        .collect();
    assert_eq!(
        names,
        [
            ("StasisEnd".to_string(), Some("ch-media".to_string())),
            ("MediaSummary".to_string(), Some("ch-media".to_string())),
        ]
    );
}
