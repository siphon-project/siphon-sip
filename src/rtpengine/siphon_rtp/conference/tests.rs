//! The conference frames, checked against the JSON the engine documents
//! (siphon-rtp 0.14.0, `docs/cookbook/conferencing.md` and the "Conferencing"
//! part of `docs/control/json.md`), written out here by hand rather than built
//! from the protocol crate, so a shared misreading cannot pass both sides.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use siphon_rtp_proto::{BridgeDirection, ConferenceRole, PlayRepeat};
use tokio::sync::mpsc;

use super::super::{SiphonRtpClient, SiphonRtpClientSet};
use crate::rtpengine::client::PlayMediaSource;
use crate::rtpengine::error::RtpEngineError;
use crate::rtpengine::events::RtpEngineEvent;
use crate::rtpengine::profile::NgFlags;
use crate::rtpengine::test_conference_engine::{accept, FakeEngine, ANSWER, OFFER};

fn client(engine: &FakeEngine) -> (Arc<SiphonRtpClient>, mpsc::Receiver<RtpEngineEvent>) {
    let (event_tx, event_rx) = mpsc::channel(16);
    (
        SiphonRtpClient::new(engine.address(), None, 2000, 5_000, event_tx),
        event_rx,
    )
}

/// `frame` without its `profile` object, which the documented examples leave
/// out (the engine defaults it).
fn without_profile(mut frame: Value) -> Value {
    if let Some(fields) = frame.as_object_mut() {
        fields.remove("profile");
    }
    frame
}

#[tokio::test]
async fn a_join_is_the_documented_frame_and_resolves_to_the_answer() {
    let engine = FakeEngine::start(accept, Vec::new()).await;
    let (client, _events) = client(&engine);

    let answer = client
        .conference_join(
            "room-1",
            "alice",
            OFFER,
            ConferenceRole::Talker,
            &NgFlags::default(),
        )
        .await
        .expect("seated");

    assert_eq!(answer, ANSWER);
    let joins = engine.frames("conference_join");
    assert_eq!(joins.len(), 1);
    assert_eq!(
        without_profile(joins[0].clone()),
        json!({
            "command": "conference_join",
            "conference_id": "room-1",
            "from_tag": "alice",
            "role": { "role": "talker" },
            "sdp": OFFER,
        })
    );
}

#[tokio::test]
async fn a_join_carries_the_profile_the_engine_reads_for_a_seat() {
    let engine = FakeEngine::start(accept, Vec::new()).await;
    let (client, _events) = client(&engine);
    let flags = NgFlags {
        direction: vec!["internal".into(), "external".into()],
        flags: vec!["symmetric".into()],
        sip_call_id: Some("a84b4c76e66710@pc33.example.com".into()),
        ..NgFlags::default()
    };

    client
        .conference_join("room-1", "alice", OFFER, ConferenceRole::Listener, &flags)
        .await
        .expect("seated");

    let join = &engine.frames("conference_join")[0];
    assert_eq!(join["role"], json!({ "role": "listener" }));
    assert_eq!(
        join["profile"]["direction"],
        json!(["internal", "external"])
    );
    assert_eq!(join["profile"]["flags"], json!(["symmetric"]));
    assert_eq!(
        join["profile"]["sip_call_id"],
        json!("a84b4c76e66710@pc33.example.com")
    );
}

#[tokio::test]
async fn leave_route_and_bridge_are_the_documented_frames() {
    let engine = FakeEngine::start(accept, Vec::new()).await;
    let (client, _events) = client(&engine);

    client
        .conference_leave("room-1", "alice")
        .await
        .expect("left");
    client
        .conference_route("room-1", "bob", ConferenceRole::Muted)
        .await
        .expect("muted");
    client
        .conference_route(
            "room-1",
            "supervisor",
            ConferenceRole::Whisper {
                target: "agent-a".into(),
            },
        )
        .await
        .expect("whispering");
    client
        .conference_route(
            "room-1",
            "supervisor",
            ConferenceRole::Monitor {
                target: "agent-a".into(),
                whisper_target: Some("agent-a".into()),
            },
        )
        .await
        .expect("monitoring");
    client
        .conference_bridge("room-1", "room-2", BridgeDirection::Both)
        .await
        .expect("bridged");
    client
        .conference_bridge("room-1", "room-2", BridgeDirection::AToB)
        .await
        .expect("bridged one way");

    assert_eq!(
        engine.frames("conference_leave"),
        vec![
            json!({ "command": "conference_leave", "conference_id": "room-1", "from_tag": "alice" })
        ]
    );
    assert_eq!(
        engine.frames("conference_route"),
        vec![
            json!({ "command": "conference_route", "conference_id": "room-1", "from_tag": "bob",
                    "role": { "role": "muted" } }),
            json!({ "command": "conference_route", "conference_id": "room-1", "from_tag": "supervisor",
                    "role": { "role": "whisper", "target": "agent-a" } }),
            json!({ "command": "conference_route", "conference_id": "room-1", "from_tag": "supervisor",
                    "role": { "role": "monitor", "target": "agent-a", "whisper_target": "agent-a" } }),
        ]
    );
    assert_eq!(
        engine.frames("conference_bridge"),
        vec![
            json!({ "command": "conference_bridge", "conference_id_a": "room-1",
                    "conference_id_b": "room-2", "direction": "both" }),
            json!({ "command": "conference_bridge", "conference_id_a": "room-1",
                    "conference_id_b": "room-2", "direction": "a_to_b" }),
        ]
    );
}

#[tokio::test]
async fn a_room_playback_is_the_documented_frame_and_returns_its_play_id() {
    let engine = FakeEngine::start(accept, Vec::new()).await;
    let (client, _events) = client(&engine);

    let outcome = client
        .conference_play(
            "bridge-4412",
            &PlayMediaSource::Tone("425/200,0/200*2".into()),
            None,
            None,
            None,
            Some(-6),
        )
        .await
        .expect("playing");
    client
        .conference_play(
            "bridge-4412",
            &PlayMediaSource::File("/var/spool/prompts/joined.wav".into()),
            Some(PlayRepeat::Forever),
            Some(500),
            Some(30_000),
            None,
        )
        .await
        .expect("playing a file");
    client
        .conference_set_play_gain("bridge-4412", 12, -20)
        .await
        .expect("ducked");
    client
        .conference_stop_play("bridge-4412", Some(12))
        .await
        .expect("stopped one");
    client
        .conference_stop_play("bridge-4412", None)
        .await
        .expect("stopped all");

    assert_eq!(outcome.play_id, Some(12));
    assert_eq!(outcome.duration_ms, Some(800));
    assert_eq!(
        engine.frames("conference_play"),
        vec![
            json!({ "command": "conference_play", "conference_id": "bridge-4412",
                    "source": {"source": "tone", "tone": "425/200,0/200*2"}, "gain_decibels": -6 }),
            json!({ "command": "conference_play", "conference_id": "bridge-4412",
                    "source": {"source": "file", "path": "/var/spool/prompts/joined.wav"},
                    "repeat_times": "inf", "start_pos_ms": 500, "duration_ms": 30000 }),
        ]
    );
    assert_eq!(
        engine.frames("conference_set_play_gain"),
        vec![
            json!({ "command": "conference_set_play_gain", "conference_id": "bridge-4412",
                     "play_id": 12, "gain_decibels": -20 })
        ]
    );
    assert_eq!(
        engine.frames("conference_stop_play"),
        vec![
            json!({ "command": "conference_stop_play", "conference_id": "bridge-4412", "play_id": 12 }),
            json!({ "command": "conference_stop_play", "conference_id": "bridge-4412" }),
        ]
    );
}

#[tokio::test]
async fn a_room_recording_is_the_documented_frame_and_its_end_resolves_the_waiter() {
    let finished = vec![json!({
        "event": "recording_finished", "call_id": "", "conference_id": "msml-4412",
        "from_tag": "", "recording_id": "rec-7", "path": "/var/spool/rec/rec-7.wav",
        "duration_ms": 3000, "reason": "max_duration"
    })];
    let engine = FakeEngine::start(accept, finished).await;
    let (event_tx, _events) = mpsc::channel(16);
    let set = SiphonRtpClientSet::new(vec![(engine.address(), 2000, 1)], None, 5_000, event_tx)
        .expect("a set");

    let recording_id = set
        .conference_start_recording(
            "msml-4412",
            Some("/var/spool/rec/rec-7.wav"),
            Some(3000),
            Some(5000),
        )
        .await
        .expect("recording");
    let ended = set
        .conference_wait_recording("msml-4412", &recording_id, Duration::from_secs(2))
        .await
        .expect("the end in time");
    set.conference_stop_recording("msml-4412", Some("rec-7"))
        .await
        .expect("stopped one");
    set.conference_stop_recording("msml-4412", None)
        .await
        .expect("stopped all");

    assert_eq!(recording_id, "rec-7");
    assert_eq!(ended.path.as_deref(), Some("/var/spool/rec/rec-7.wav"));
    assert_eq!(ended.duration_ms, 3000);
    assert_eq!(ended.reason, "max_duration");
    assert_eq!(
        engine.frames("conference_start_recording"),
        vec![
            json!({ "command": "conference_start_recording", "conference_id": "msml-4412",
                     "path": "/var/spool/rec/rec-7.wav", "max_duration_ms": 3000,
                     "silence_ms": 5000 })
        ]
    );
    assert_eq!(
        engine.frames("conference_stop_recording"),
        vec![
            json!({ "command": "conference_stop_recording", "conference_id": "msml-4412",
                     "recording_id": "rec-7" }),
            json!({ "command": "conference_stop_recording", "conference_id": "msml-4412" }),
        ]
    );
}

#[tokio::test]
async fn a_room_recording_accept_without_an_id_is_a_protocol_error() {
    fn idless(_: &Value) -> Value {
        json!({"result": "ok"})
    }
    let engine = FakeEngine::start(idless, Vec::new()).await;
    let (client, _events) = client(&engine);

    let started = client
        .conference_start_recording("room-1", None, None, None)
        .await;

    assert!(
        matches!(started, Err(RtpEngineError::Protocol(_))),
        "{started:?}"
    );
}

#[tokio::test]
async fn a_refusal_comes_back_as_the_engines_reason() {
    fn refuse(request: &Value) -> Value {
        match request["command"].as_str() {
            Some("conference_join") => json!({"result": "error", "reason":
                "conference_join: codec opus has no encoder, so the room mix cannot be sent to this participant"}),
            _ => {
                json!({"result": "error", "reason": "conference_leave: no such conference participant"})
            }
        }
    }
    let engine = FakeEngine::start(refuse, Vec::new()).await;
    let (client, _events) = client(&engine);

    let joined = client
        .conference_join(
            "room-1",
            "alice",
            OFFER,
            ConferenceRole::Talker,
            &NgFlags::default(),
        )
        .await;
    let left = client.conference_leave("room-1", "alice").await;

    assert!(
        matches!(&joined, Err(RtpEngineError::EngineError(reason)) if reason.contains("has no encoder")),
        "{joined:?}"
    );
    assert!(
        matches!(&left, Err(RtpEngineError::EngineError(reason)) if reason.contains("no such conference participant")),
        "{left:?}"
    );
}

#[tokio::test]
async fn a_play_accept_without_a_play_id_is_a_protocol_error() {
    fn idless(_: &Value) -> Value {
        json!({"result": "ok"})
    }
    let engine = FakeEngine::start(idless, Vec::new()).await;
    let (client, _events) = client(&engine);

    let played = client
        .conference_play(
            "room-1",
            &PlayMediaSource::Tone("ringback_eu".into()),
            None,
            None,
            None,
            None,
        )
        .await;

    assert!(
        matches!(played, Err(RtpEngineError::Protocol(_))),
        "{played:?}"
    );
}

/// Wait for the next event the client forwards.
async fn next_event(events: &mut mpsc::Receiver<RtpEngineEvent>) -> RtpEngineEvent {
    tokio::time::timeout(Duration::from_secs(2), events.recv())
        .await
        .expect("an event in time")
        .expect("the event channel open")
}

#[tokio::test]
async fn the_rooms_events_reach_the_event_channel_keyed_by_the_room() {
    // As the engine pushes them: the documented forms, with `from_tag` present
    // and empty on a room playback because the protocol type always carries it.
    let events = vec![
        json!({ "event": "active_speaker", "conference_id": "room-1", "from_tag": "alice" }),
        json!({ "event": "active_speaker", "conference_id": "room-1" }),
        json!({ "event": "dtmf", "call_id": "room-1", "from_tag": "bob", "digit": "5",
                "duration_ms": 120, "volume": -8 }),
        json!({"event": "play_finished", "call_id": "", "conference_id": "bridge-4412", "from_tag": "",
               "play_id": 12, "reason": "completed", "played_ms": 800}),
    ];
    let engine = FakeEngine::start(accept, events).await;
    let (client, mut events) = client(&engine);
    client
        .conference_leave("room-1", "nobody")
        .await
        .expect("a frame to start the events");

    match next_event(&mut events).await {
        RtpEngineEvent::ActiveSpeaker(speaker) => {
            assert_eq!(speaker.conference_id, "room-1");
            assert_eq!(speaker.from_tag.as_deref(), Some("alice"));
        }
        other => panic!("expected active_speaker, got {other:?}"),
    }
    match next_event(&mut events).await {
        RtpEngineEvent::ActiveSpeaker(speaker) => {
            assert_eq!(speaker.conference_id, "room-1");
            assert_eq!(speaker.from_tag, None, "the floor went silent");
        }
        other => panic!("expected active_speaker, got {other:?}"),
    }
    match next_event(&mut events).await {
        RtpEngineEvent::Dtmf(dtmf) => {
            assert_eq!(dtmf.call_id, "room-1", "the room id arrives as the call-id");
            assert_eq!(dtmf.from_tag, "bob");
            assert_eq!(dtmf.digit, "5");
        }
        other => panic!("expected dtmf, got {other:?}"),
    }
    match next_event(&mut events).await {
        RtpEngineEvent::PlayFinished(play) => {
            assert_eq!(play.call_id, "bridge-4412", "keyed by the room, as dtmf is");
            assert_eq!(play.from_tag, "");
            assert_eq!(play.play_id, 12);
            assert_eq!(play.played_ms, Some(800));
        }
        other => panic!("expected play_finished, got {other:?}"),
    }
}

#[tokio::test]
async fn every_verb_of_a_room_reaches_the_instance_its_first_seat_went_to() {
    let first = FakeEngine::start(accept, Vec::new()).await;
    let second = FakeEngine::start(accept, Vec::new()).await;
    let (event_tx, _events) = mpsc::channel(16);
    let set = SiphonRtpClientSet::new(
        vec![(first.address(), 2000, 1), (second.address(), 2000, 1)],
        None,
        5_000,
        event_tx,
    )
    .expect("a set");

    for tag in ["alice", "bob", "carol"] {
        set.conference_join(
            "room-1",
            tag,
            OFFER,
            ConferenceRole::Talker,
            &NgFlags::default(),
        )
        .await
        .expect("seated");
    }
    set.conference_route("room-1", "bob", ConferenceRole::Muted)
        .await
        .expect("muted");
    set.conference_play(
        "room-1",
        &PlayMediaSource::Tone("ringback_eu".into()),
        None,
        None,
        None,
        None,
    )
    .await
    .expect("playing");
    set.conference_leave("room-1", "alice").await.expect("left");

    let on = |engine: &FakeEngine| {
        [
            "conference_join",
            "conference_route",
            "conference_play",
            "conference_leave",
        ]
        .iter()
        .map(|command| engine.frames(command).len())
        .sum::<usize>()
    };
    let (on_first, on_second) = (on(&first), on(&second));
    assert_eq!(on_first + on_second, 6);
    assert!(
        on_first == 0 || on_second == 0,
        "the room was split across instances: {on_first} and {on_second} frames"
    );

    set.forget_room("room-1");
    assert!(
        set.affinity.is_empty(),
        "a forgotten room leaves no affinity behind"
    );
}

/// An engine whose `node_info` lists `features`; everything else as `accept`.
fn listing(request: &Value, features: &[&str]) -> Value {
    if request["command"] == "node_info" {
        return json!({
            "result": "node_info",
            "node": {
                "node_id": "engine-1",
                "version": "0.15.5",
                "media_addresses": [],
                "codecs": [],
                "features": features,
                "max_sessions": 0,
                "draining": false,
            },
        });
    }
    accept(request)
}

fn lists_received_from(request: &Value) -> Value {
    listing(request, &["conference_seat", "conference_received_from"])
}

fn lacks_received_from(request: &Value) -> Value {
    listing(request, &["conference_seat"])
}

fn nat_address() -> std::net::IpAddr {
    "198.51.100.20".parse().expect("an address")
}

fn behind_nat() -> NgFlags {
    NgFlags {
        received_from: Some(nat_address()),
        ..NgFlags::default()
    }
}

/// A participant behind NAT advertises a private `c=`, and only the address its
/// request came from reaches it. An engine that does not seat on that address
/// would drop everything the participant sends and mix to nowhere, so the seat
/// is refused before a frame goes out, never made silently.
#[tokio::test]
async fn a_seat_behind_nat_is_refused_by_an_engine_that_ignores_received_from() {
    let engine = FakeEngine::start(lacks_received_from, Vec::new()).await;
    let (client, _events) = client(&engine);

    let joined = client
        .conference_join(
            "room-1",
            "alice",
            OFFER,
            ConferenceRole::Talker,
            &behind_nat(),
        )
        .await
        .expect_err("refused");
    assert!(
        matches!(joined, RtpEngineError::Unsupported { .. }),
        "{joined}"
    );
    let answered = client
        .conference_answer("room-1", "bob", ANSWER, Some(nat_address()))
        .await
        .expect_err("refused");
    assert!(
        matches!(answered, RtpEngineError::Unsupported { .. }),
        "{answered}"
    );
    assert!(engine.frames("conference_join").is_empty());
    assert!(engine.frames("conference_answer").is_empty());
}

/// A called-out participant's address arrives with its answer, so it rides
/// on `conference_answer` itself to an engine that honours it.
#[tokio::test]
async fn an_answered_seat_behind_nat_carries_received_from_on_the_answer() {
    let engine = FakeEngine::start(lists_received_from, Vec::new()).await;
    let (client, _events) = client(&engine);

    client
        .conference_answer("room-1", "bob", ANSWER, Some(nat_address()))
        .await
        .expect("seated");
    let answers = engine.frames("conference_answer");
    assert_eq!(answers.len(), 1);
    assert_eq!(answers[0]["received_from"], json!("198.51.100.20"));

    client
        .conference_answer("room-1", "carol", ANSWER, None)
        .await
        .expect("seated");
    assert!(
        engine.frames("conference_answer")[1]
            .get("received_from")
            .is_none(),
        "absent, not null, without an address"
    );
}

/// An engine that lists `conference_received_from` is sent the seat with the
/// address in its profile, the same key a two-party answer carries.
#[tokio::test]
async fn a_seat_behind_nat_carries_received_from_to_an_engine_that_honours_it() {
    let engine = FakeEngine::start(lists_received_from, Vec::new()).await;
    let (client, _events) = client(&engine);

    client
        .conference_join(
            "room-1",
            "alice",
            OFFER,
            ConferenceRole::Talker,
            &behind_nat(),
        )
        .await
        .expect("seated");

    let joins = engine.frames("conference_join");
    assert_eq!(joins.len(), 1);
    assert_eq!(joins[0]["profile"]["received_from"], json!("198.51.100.20"));
}

/// A seat with no received-from address asks the engine nothing first.
#[tokio::test]
async fn a_seat_without_received_from_needs_no_feature_check() {
    let engine = FakeEngine::start(lacks_received_from, Vec::new()).await;
    let (client, _events) = client(&engine);

    client
        .conference_join(
            "room-1",
            "alice",
            OFFER,
            ConferenceRole::Talker,
            &NgFlags::default(),
        )
        .await
        .expect("seated");
    assert!(engine.frames("node_info").is_empty());
    assert_eq!(engine.frames("conference_join").len(), 1);
}
