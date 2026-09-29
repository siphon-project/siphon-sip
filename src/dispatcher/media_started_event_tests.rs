//! The media engine's first-packet report on the control rail: `MediaStarted`
//! on the channel of the party whose leg it names, once per leg.

use std::collections::HashMap;
use std::sync::Arc;

use super::*;
use crate::control::{ControlBus, OutboundFrame, SlowConsumerPolicy};
use crate::rtpengine::events::{MediaLeg, MediaStartedEvent, RtpEngineEvent};

fn started(
    call_id: &str,
    leg: MediaLeg,
    source: Option<&str>,
    signalled: Option<&str>,
) -> MediaStartedEvent {
    MediaStartedEvent {
        call_id: call_id.to_string(),
        from_tag: "caller-tag".to_string(),
        to_tag: Some("phone-tag".to_string()),
        leg,
        source: source.map(|address| address.parse().expect("an address")),
        signalled: signalled.map(|address| address.parse().expect("an address")),
    }
}

/// An ordinary call: each leg's report reaches the call's channel once, in the
/// order the engine sent them, carrying the leg it names.
#[test]
fn each_leg_of_an_ordinary_call_publishes_once() {
    let call_id = "mst-ordinary@example.test";
    crate::control::channel_event_capture::watch(call_id);
    let state = super::test_dispatcher::test_dispatcher().state;
    let signalled = Some("192.0.2.10:4000");
    publish_media_started(
        &state,
        &started(call_id, MediaLeg::Near, signalled, signalled),
    );
    publish_media_started(
        &state,
        &started(
            call_id,
            MediaLeg::Far,
            Some("198.51.100.20:40000"),
            Some("198.51.100.20:40000"),
        ),
    );
    let captured = crate::control::channel_event_capture::take(call_id);
    let names: Vec<&str> = captured.iter().map(|(event, _)| event.as_str()).collect();
    assert_eq!(names, ["MediaStarted", "MediaStarted"]);
    assert_eq!(captured[0].1["leg"], "near");
    assert_eq!(captured[1].1["leg"], "far");
    assert_eq!(captured[0].1["from_tag"], "caller-tag");
    assert_eq!(captured[0].1["to_tag"], "phone-tag");
}

/// `nat_rewritten` says whether the latched source differs from the signalled
/// address, and is absent when the engine did not report both; an unreported
/// address is absent rather than null.
#[test]
fn the_payload_says_whether_a_nat_rewrote_the_source() {
    let behind_nat = media_started_payload(&started(
        "c",
        MediaLeg::Near,
        Some("203.0.113.7:40000"),
        Some("192.0.2.10:4000"),
    ));
    assert_eq!(behind_nat["source"], "203.0.113.7:40000");
    assert_eq!(behind_nat["signalled"], "192.0.2.10:4000");
    assert_eq!(behind_nat["nat_rewritten"], true);

    let direct = media_started_payload(&started(
        "c",
        MediaLeg::Far,
        Some("192.0.2.10:4000"),
        Some("192.0.2.10:4000"),
    ));
    assert_eq!(direct["nat_rewritten"], false);

    let unlatched = media_started_payload(&MediaStartedEvent {
        to_tag: None,
        ..started("c", MediaLeg::Near, None, Some("192.0.2.10:4000"))
    });
    let fields = unlatched.as_object().expect("an object");
    assert!(!fields.contains_key("source"), "{unlatched}");
    assert!(!fields.contains_key("nat_rewritten"), "{unlatched}");
    assert!(!fields.contains_key("to_tag"), "{unlatched}");
    assert_eq!(unlatched["signalled"], "192.0.2.10:4000");
}

/// Wired end to end: a report on the media backend's event stream reaches the
/// control rail through the dispatcher's event loop.
#[tokio::test]
async fn the_engine_event_stream_publishes_media_started() {
    let call_id = "mst-stream@example.test";
    crate::control::channel_event_capture::watch(call_id);
    let state = Arc::new(super::test_dispatcher::test_dispatcher().state);
    let (events, receiver) = tokio::sync::mpsc::channel(4);
    spawn_rtpengine_events(&state, receiver);
    events
        .send(RtpEngineEvent::MediaStarted(started(
            call_id,
            MediaLeg::Far,
            Some("203.0.113.7:40000"),
            Some("192.0.2.10:4000"),
        )))
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
    assert_eq!(captured[0].0, "MediaStarted");
    assert_eq!(captured[0].1["nat_rewritten"], true);
}

fn bus() -> Arc<ControlBus> {
    let (command_tx, _commands) = flume::unbounded();
    ControlBus::new(
        command_tx,
        vec![crate::config::ControlAppConfig {
            name: "media-started-app".to_string(),
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

/// On the bus: the owner of a controlled call gets `MediaStarted` on its
/// channel, and a call nobody controls publishes nothing.
#[tokio::test]
async fn only_the_owning_channel_hears_media_started() {
    let bus = bus();
    let connection = bus.register_connection("media-started-app");
    bus.register_channel(
        "ch-started",
        &connection,
        "actor-started",
        "mst-owned@example.test",
        "hangup",
        HashMap::new(),
    );
    let payload = media_started_payload(&started(
        "mst-owned@example.test",
        MediaLeg::Near,
        Some("203.0.113.7:40000"),
        Some("192.0.2.10:4000"),
    ));
    assert!(bus.forward_channel_event("mst-owned@example.test", "MediaStarted", payload.clone()));
    let frames = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        connection.events.recv_many(),
    )
    .await
    .expect("a frame for the owner");
    let event = frames
        .into_iter()
        .find_map(|frame| match frame {
            OutboundFrame::Event(event) if event.event == "MediaStarted" => Some(event),
            _ => None,
        })
        .expect("MediaStarted reaches the owner");
    assert_eq!(event.channel.as_deref(), Some("ch-started"));
    assert_eq!(event.payload["leg"], "near");

    assert!(!bus.forward_channel_event("mst-uncontrolled@example.test", "MediaStarted", payload,));
}
