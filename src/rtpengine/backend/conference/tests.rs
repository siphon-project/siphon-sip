//! Seats as the backend keeps them: what a teardown that names a call does to
//! a seated one, and what a backend without a mixer answers.

use serde_json::{json, Value};

use super::super::MediaBackend;
use super::{BridgeDirection, ConferenceRole, ConferenceSeat};
use crate::rtpengine::client::PlayMediaSource;
use crate::rtpengine::error::RtpEngineError;
use crate::rtpengine::profile::NgFlags;
use crate::rtpengine::test_conference_engine::{accept, FakeEngine, OFFER};
use crate::rtpengine::test_engine::TestEngine;

fn seat(conference_id: &str, from_tag: &str) -> ConferenceSeat {
    ConferenceSeat {
        conference_id: conference_id.to_string(),
        from_tag: from_tag.to_string(),
    }
}

async fn join(backend: &MediaBackend, call_id: &str, seat: ConferenceSeat) {
    backend
        .conference_join(
            call_id,
            seat,
            OFFER,
            ConferenceRole::Talker,
            &NgFlags::default(),
        )
        .await
        .expect("seated");
}

#[tokio::test]
async fn deleting_a_seated_call_leaves_its_room_instead() {
    let engine = FakeEngine::start(accept, Vec::new()).await;
    let backend = engine.backend();
    join(
        &backend,
        "seated-delete@example.com",
        seat("room-d", "alice"),
    )
    .await;
    assert_eq!(
        MediaBackend::conference_seat("seated-delete@example.com"),
        Some(seat("room-d", "alice"))
    );

    backend
        .delete("seated-delete@example.com", "alice")
        .await
        .expect("left");

    assert_eq!(
        engine.frames("conference_leave"),
        vec![
            json!({"command": "conference_leave", "conference_id": "room-d", "from_tag": "alice"})
        ]
    );
    // The engine's call registry never held the seat, so a `delete` would only
    // have been answered `unknown call`.
    assert!(
        engine.frames("delete").is_empty(),
        "{:?}",
        engine.commands()
    );
    assert_eq!(
        MediaBackend::conference_seat("seated-delete@example.com"),
        None
    );

    // The seat is gone: the next delete is an ordinary one.
    backend
        .delete("seated-delete@example.com", "alice")
        .await
        .expect("deleted");
    assert_eq!(engine.frames("delete").len(), 1);
    assert_eq!(engine.frames("conference_leave").len(), 1);
}

#[tokio::test]
async fn a_seated_call_with_an_engine_call_of_its_own_gets_both_released() {
    let engine = FakeEngine::start(accept, Vec::new()).await;
    let backend = engine.backend();
    backend
        .answer_local("both@example.com", "alice", OFFER, &NgFlags::default())
        .await
        .expect("answered");
    join(&backend, "both@example.com", seat("room-b", "alice")).await;

    backend
        .delete("both@example.com", "alice")
        .await
        .expect("released");

    assert_eq!(
        engine.commands(),
        vec![
            "answer_local",
            "conference_join",
            "conference_leave",
            "delete"
        ]
    );
}

#[tokio::test]
async fn a_seat_the_engine_reaped_has_left_and_an_unknown_one_has_not() {
    fn reaped(request: &Value) -> Value {
        match request["command"].as_str() {
            Some("conference_leave") => {
                json!({"result": "error", "reason": "conference_leave: no such conference participant"})
            }
            _ => accept(request),
        }
    }
    let engine = FakeEngine::start(reaped, Vec::new()).await;
    let backend = engine.backend();
    join(&backend, "reaped@example.com", seat("room-r", "alice")).await;

    backend
        .conference_leave("reaped@example.com", &seat("room-r", "alice"))
        .await
        .expect("a recorded seat the engine already freed has left");
    assert_eq!(MediaBackend::conference_seat("reaped@example.com"), None);

    let unknown = backend
        .conference_leave("never-seated@example.com", &seat("room-r", "mallory"))
        .await;
    assert!(
        matches!(&unknown, Err(RtpEngineError::EngineError(reason)) if reason.contains("no such conference participant")),
        "{unknown:?}"
    );
}

#[tokio::test]
async fn a_failed_leave_keeps_the_seat_for_the_next_teardown() {
    fn unreachable(request: &Value) -> Value {
        match request["command"].as_str() {
            Some("conference_leave") => {
                json!({"result": "error", "reason": "conference actor closed"})
            }
            _ => accept(request),
        }
    }
    let engine = FakeEngine::start(unreachable, Vec::new()).await;
    let backend = engine.backend();
    join(&backend, "kept@example.com", seat("room-k", "alice")).await;

    let failed = backend.delete("kept@example.com", "alice").await;

    assert!(
        matches!(failed, Err(RtpEngineError::EngineError(_))),
        "{failed:?}"
    );
    assert_eq!(
        MediaBackend::conference_seat("kept@example.com"),
        Some(seat("room-k", "alice"))
    );
}

#[tokio::test]
async fn a_backend_without_a_mixer_refuses_every_conference_verb() {
    let engine = TestEngine::start(false).await;
    let backend = engine.backend().await;
    let unsupported = |result: Result<(), RtpEngineError>, operation: &str| match result {
        Err(RtpEngineError::Unsupported {
            operation: refused,
            backend: "rtpengine",
        }) => assert_eq!(refused, operation),
        other => panic!("{operation}: expected unsupported, got {other:?}"),
    };

    unsupported(
        backend
            .conference_join(
                "no-mixer@example.com",
                seat("room-n", "alice"),
                OFFER,
                ConferenceRole::Talker,
                &NgFlags::default(),
            )
            .await
            .map(|_| ()),
        "conference_join",
    );
    unsupported(
        backend
            .conference_leave("no-mixer@example.com", &seat("room-n", "alice"))
            .await,
        "conference_leave",
    );
    unsupported(
        backend
            .conference_route(&seat("room-n", "alice"), ConferenceRole::Muted)
            .await,
        "conference_route",
    );
    unsupported(
        backend
            .conference_bridge("room-n", "room-m", BridgeDirection::Both)
            .await,
        "conference_bridge",
    );
    unsupported(
        backend
            .conference_play(
                "room-n",
                &PlayMediaSource::Tone("ringback_eu".into()),
                None,
                None,
                None,
                None,
            )
            .await
            .map(|_| ()),
        "conference_play",
    );
    unsupported(
        backend.conference_stop_play("room-n", None).await,
        "conference_stop_play",
    );
    unsupported(
        backend.conference_set_play_gain("room-n", 1, -6).await,
        "conference_set_play_gain",
    );
    assert!(
        engine.all_commands().is_empty(),
        "nothing reached the engine"
    );
    assert_eq!(MediaBackend::conference_seat("no-mixer@example.com"), None);
}
