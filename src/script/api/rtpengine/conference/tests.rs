//! The conference verbs as a script calls them: through the real Python
//! methods, awaited from a coroutine, against an engine that records the raw
//! frames it is sent.

use std::ffi::CString;
use std::sync::{Arc, Mutex};

use pyo3::types::{PyDict, PyTuple};
use serde_json::{json, Value};

use super::super::{PyCall, PyRtpEngine};
use super::{join_failure, parse_direction, parse_role};
use crate::rtpengine::backend::{BridgeDirection, ConferenceRole};
use crate::rtpengine::profile::ProfileRegistry;
use crate::rtpengine::test_conference_engine::{accept, FakeEngine, ANSWER, OFFER};
use crate::rtpengine::test_engine::TestEngine;
use crate::rtpengine::{MediaBackend, MediaSessionStore};
use crate::sip::message::SipMessage;
use pyo3::prelude::*;

/// A participant's INVITE carrying the cookbook's offer.
fn invite(call_id: &str, from_tag: &str) -> Arc<Mutex<SipMessage>> {
    let raw = format!(
        "INVITE sip:room-1@conference.example.com SIP/2.0\r\n\
         Via: SIP/2.0/UDP 198.51.100.10:5060;branch=z9hG4bK-{from_tag}\r\n\
         From: <sip:{from_tag}@example.com>;tag={from_tag}\r\n\
         To: <sip:room-1@conference.example.com>\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: 1 INVITE\r\n\
         Content-Type: application/sdp\r\n\
         Content-Length: {}\r\n\r\n{OFFER}",
        OFFER.len()
    );
    let (_, message) = crate::sip::parser::parse_sip_message(&raw).expect("an INVITE");
    Arc::new(Mutex::new(message))
}

fn namespace(backend: Arc<MediaBackend>, registry: ProfileRegistry) -> PyRtpEngine {
    PyRtpEngine::new(
        backend,
        Arc::new(MediaSessionStore::new()),
        Arc::new(registry),
    )
}

/// Run `body` attached to Python on a blocking thread, where a script handler
/// runs, with the namespace bound for it.
async fn with_namespace<T: Send + 'static>(
    namespace: PyRtpEngine,
    body: impl FnOnce(Python<'_>, &Bound<'_, PyRtpEngine>) -> T + Send + 'static,
) -> T {
    tokio::task::spawn_blocking(move || {
        Python::attach(|python| {
            let namespace = Bound::new(python, namespace).expect("bound");
            body(python, &namespace)
        })
    })
    .await
    .expect("the blocking task")
}

/// `await rtpengine.<verb>(*args, **kwargs)` from inside a coroutine, the way
/// a script does it.
fn call(
    python: Python<'_>,
    namespace: &Bound<'_, PyRtpEngine>,
    verb: &str,
    args: &Bound<'_, PyTuple>,
    kwargs: &Bound<'_, PyDict>,
) -> PyResult<Py<PyAny>> {
    let code = CString::new(format!(
        "async def run(rtpengine, args, kwargs):\n    return await rtpengine.{verb}(*args, **kwargs)\n"
    ))
    .expect("source");
    let globals = PyDict::new(python);
    python.run(code.as_c_str(), Some(&globals), None)?;
    let run = globals.get_item("run")?.expect("run defined");
    let coroutine = run.call1((namespace, args, kwargs))?;
    crate::script::engine::run_coroutine_value(python, &coroutine)
}

fn participant<'py>(python: Python<'py>, call_id: &str, from_tag: &str) -> Bound<'py, PyAny> {
    let call = PyCall::new(
        "id-1".to_string(),
        invite(call_id, from_tag),
        "198.51.100.10".to_string(),
        "udp".to_string(),
    );
    Bound::new(python, call).expect("a call").into_any()
}

#[test]
fn a_role_is_read_with_the_target_it_needs_and_nothing_it_does_not() {
    Python::initialize();
    let role = |role: &str, target: Option<&str>, whisper: Option<&str>| {
        parse_role(
            role,
            target.map(str::to_string),
            whisper.map(str::to_string),
        )
    };
    assert_eq!(
        role("talker", None, None).ok(),
        Some(ConferenceRole::Talker)
    );
    assert_eq!(
        role("listener", None, None).ok(),
        Some(ConferenceRole::Listener)
    );
    assert_eq!(role("muted", None, None).ok(), Some(ConferenceRole::Muted));
    assert_eq!(
        role("whisper", Some("agent-a"), None).ok(),
        Some(ConferenceRole::Whisper {
            target: "agent-a".into()
        })
    );
    assert_eq!(
        role("monitor", Some("agent-a"), Some("agent-a")).ok(),
        Some(ConferenceRole::Monitor {
            target: "agent-a".into(),
            whisper_target: Some("agent-a".into())
        })
    );
    for (name, target, whisper) in [
        ("whisper", None, None),
        ("monitor", None, Some("agent-a")),
        ("talker", Some("agent-a"), None),
        ("muted", None, Some("agent-a")),
        ("whisper", Some("agent-a"), Some("agent-b")),
        ("speaker", None, None),
    ] {
        assert!(
            role(name, target, whisper).is_err(),
            "{name} {target:?} {whisper:?} must be refused"
        );
    }
    assert_eq!(parse_direction("both").ok(), Some(BridgeDirection::Both));
    assert_eq!(parse_direction("a_to_b").ok(), Some(BridgeDirection::AToB));
    assert_eq!(parse_direction("b_to_a").ok(), Some(BridgeDirection::BToA));
    assert!(parse_direction("sideways").is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_join_answers_the_participants_offer_and_seats_it_by_its_from_tag() {
    let engine = FakeEngine::start(accept, Vec::new()).await;
    let namespace = namespace(engine.backend(), ProfileRegistry::new());

    let answer = with_namespace(namespace, |python, namespace| {
        let call = participant(python, "join-1@example.com", "alice");
        let args = PyTuple::new(python, [python_str(python, "room-1"), call]).expect("args");
        let kwargs = PyDict::new(python);
        kwargs.set_item("role", "listener").expect("role");
        call_verb(python, namespace, "conference_join", &args, &kwargs)
    })
    .await;

    assert_eq!(answer.expect("seated").as_deref(), Some(ANSWER));
    let join = &engine.frames("conference_join")[0];
    assert_eq!(join["conference_id"], json!("room-1"));
    assert_eq!(join["from_tag"], json!("alice"));
    assert_eq!(join["role"], json!({"role": "listener"}));
    assert_eq!(join["sdp"], json!(OFFER));
    assert_eq!(join["profile"]["sip_call_id"], json!("join-1@example.com"));
    assert_eq!(
        MediaBackend::conference_seat("join-1@example.com").map(|seat| seat.from_tag),
        Some("alice".to_string())
    );
}

/// A str argument, for the positional tuples below.
fn python_str<'py>(python: Python<'py>, value: &str) -> Bound<'py, PyAny> {
    pyo3::types::PyString::new(python, value).into_any()
}

/// Await `verb` and read its result back as an optional string.
fn call_verb(
    python: Python<'_>,
    namespace: &Bound<'_, PyRtpEngine>,
    verb: &str,
    args: &Bound<'_, PyTuple>,
    kwargs: &Bound<'_, PyDict>,
) -> Result<Option<String>, String> {
    call(python, namespace, verb, args, kwargs)
        .map(|value| {
            value
                .bind(python)
                .extract::<Option<String>>()
                .unwrap_or(None)
        })
        .map_err(|error| {
            format!(
                "{}: {}",
                error
                    .get_type(python)
                    .name()
                    .map(|name| name.to_string())
                    .unwrap_or_default(),
                error.value(python)
            )
        })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_seat_for_one_call_is_refused_before_the_engine_sees_it() {
    let engine = FakeEngine::start(accept, Vec::new()).await;
    let namespace = namespace(engine.backend(), ProfileRegistry::new());

    let outcomes = with_namespace(namespace, |python, namespace| {
        let mut outcomes = Vec::new();
        for room in ["room-twice", "room-other"] {
            let call = participant(python, "twice@example.com", "alice");
            let args = PyTuple::new(python, [python_str(python, room), call]).expect("args");
            outcomes.push(call_verb(
                python,
                namespace,
                "conference_join",
                &args,
                &PyDict::new(python),
            ));
        }
        outcomes
    })
    .await;

    assert!(outcomes[0].is_ok(), "{:?}", outcomes[0]);
    let refused = outcomes[1].as_ref().expect_err("a second seat");
    assert!(
        refused.starts_with("ValueError") && refused.contains("room-twice"),
        "{refused}"
    );
    assert_eq!(engine.frames("conference_join").len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_codec_the_room_cannot_encode_is_a_value_error() {
    fn opus_only(request: &Value) -> Value {
        match request["command"].as_str() {
            Some("conference_join") => json!({"result": "error", "reason":
                "conference_join: codec opus has no encoder, so the room mix cannot be sent to this participant (AMR-WB / AMR-NB need the `amr` build feature)"}),
            _ => accept(request),
        }
    }
    let engine = FakeEngine::start(opus_only, Vec::new()).await;
    let namespace = namespace(engine.backend(), ProfileRegistry::new());

    let outcome = with_namespace(namespace, |python, namespace| {
        let call = participant(python, "opus@example.com", "alice");
        let args = PyTuple::new(python, [python_str(python, "room-1"), call]).expect("args");
        call_verb(
            python,
            namespace,
            "conference_join",
            &args,
            &PyDict::new(python),
        )
    })
    .await;

    let refused = outcome.expect_err("refused");
    assert!(
        refused.starts_with("ValueError") && refused.contains("has no encoder"),
        "{refused}"
    );
    assert_eq!(MediaBackend::conference_seat("opus@example.com"), None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_profile_whose_policy_a_seat_would_not_get_is_refused() {
    let engine = FakeEngine::start(accept, Vec::new()).await;
    let half = crate::config::NgFlagsConfig {
        codec: crate::config::CodecFlagsConfig {
            mask: vec!["AMR-WB".into(), "AMR".into()],
            ..Default::default()
        },
        ..Default::default()
    };
    let mut custom = std::collections::HashMap::new();
    custom.insert(
        "no_amr".to_string(),
        crate::config::MediaProfileConfig {
            offer: half.clone(),
            answer: half,
        },
    );
    let namespace = namespace(engine.backend(), ProfileRegistry::from_config(&custom));

    let outcome = with_namespace(namespace, |python, namespace| {
        let call = participant(python, "policy@example.com", "alice");
        let args = PyTuple::new(python, [python_str(python, "room-1"), call]).expect("args");
        let kwargs = PyDict::new(python);
        kwargs.set_item("profile", "no_amr").expect("profile");
        call_verb(python, namespace, "conference_join", &args, &kwargs)
    })
    .await;

    let refused = outcome.expect_err("refused");
    assert!(
        refused.starts_with("ValueError") && refused.contains("a codec policy"),
        "{refused}"
    );
    assert!(engine.frames("conference_join").is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn leave_route_bridge_and_play_reach_the_engine_and_delete_leaves_a_seat() {
    let engine = FakeEngine::start(accept, Vec::new()).await;
    let namespace = namespace(engine.backend(), ProfileRegistry::new());

    let outcomes = with_namespace(namespace, |python, namespace| {
        let none = PyDict::new(python);
        let mut outcomes = Vec::new();
        for (call_id, tag) in [
            ("five-a@example.com", "alice"),
            ("five-b@example.com", "bob"),
        ] {
            let call = participant(python, call_id, tag);
            let args = PyTuple::new(python, [python_str(python, "room-5"), call]).expect("args");
            outcomes
                .push(call_verb(python, namespace, "conference_join", &args, &none).map(|_| None));
        }
        // An event handler holds a (call_id, from_tag) pair rather than a call.
        let pair = ("five-b@example.com", "bob")
            .into_pyobject(python)
            .expect("pair")
            .into_any();
        let args = PyTuple::new(python, [python_str(python, "room-5"), pair]).expect("args");
        let kwargs = PyDict::new(python);
        kwargs.set_item("role", "muted").expect("role");
        outcomes
            .push(call_verb(python, namespace, "conference_route", &args, &kwargs).map(|_| None));

        let args = PyTuple::new(python, ["room-5", "room-6"]).expect("args");
        let kwargs = PyDict::new(python);
        kwargs.set_item("direction", "a_to_b").expect("direction");
        outcomes
            .push(call_verb(python, namespace, "conference_bridge", &args, &kwargs).map(|_| None));

        let args = PyTuple::new(python, ["room-5"]).expect("args");
        let kwargs = PyDict::new(python);
        kwargs.set_item("tone", "425/200,0/200*2").expect("tone");
        kwargs.set_item("gain_decibels", -6).expect("gain");
        let play_id = call(python, namespace, "conference_play", &args, &kwargs)
            .map(|value| {
                value
                    .bind(python)
                    .extract::<u64>()
                    .ok()
                    .map(|id| id.to_string())
            })
            .map_err(|error| error.to_string());
        outcomes.push(play_id);

        // A bare string names no seat.
        let args = PyTuple::new(python, ["room-5", "five-a@example.com"]).expect("args");
        outcomes.push(call_verb(
            python,
            namespace,
            "conference_leave",
            &args,
            &none,
        ));

        // `rtpengine.delete(call)` on a seated call leaves its room.
        let call = participant(python, "five-a@example.com", "alice");
        let args = PyTuple::new(python, [call]).expect("args");
        outcomes.push(call_verb(python, namespace, "delete", &args, &none).map(|_| None));
        outcomes
    })
    .await;

    assert!(outcomes[..4].iter().all(Result::is_ok), "{outcomes:?}");
    assert_eq!(outcomes[4], Ok(Some("12".to_string())), "the play id");
    assert!(
        outcomes[5]
            .as_ref()
            .is_err_and(|error| error.starts_with("TypeError")),
        "{:?}",
        outcomes[5]
    );
    assert!(outcomes[6].is_ok(), "{:?}", outcomes[6]);
    assert_eq!(
        engine.frames("conference_route"),
        vec![
            json!({"command": "conference_route", "conference_id": "room-5", "from_tag": "bob", "role": {"role": "muted"}})
        ]
    );
    assert_eq!(
        engine.frames("conference_bridge"),
        vec![
            json!({"command": "conference_bridge", "conference_id_a": "room-5", "conference_id_b": "room-6", "direction": "a_to_b"})
        ]
    );
    assert_eq!(
        engine.frames("conference_play"),
        vec![
            json!({"command": "conference_play", "conference_id": "room-5",
                    "source": {"source": "tone", "tone": "425/200,0/200*2"}, "gain_decibels": -6})
        ]
    );
    assert_eq!(
        engine.frames("conference_leave"),
        vec![
            json!({"command": "conference_leave", "conference_id": "room-5", "from_tag": "alice"})
        ]
    );
    assert!(
        engine.frames("delete").is_empty(),
        "{:?}",
        engine.commands()
    );
    assert_eq!(MediaBackend::conference_seat("five-a@example.com"), None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn another_backend_says_it_has_no_mixer() {
    let engine = TestEngine::start(false).await;
    let namespace = namespace(engine.backend().await, ProfileRegistry::new());

    let outcome = with_namespace(namespace, |python, namespace| {
        let call = participant(python, "rtpengine@example.com", "alice");
        let args = PyTuple::new(python, [python_str(python, "room-1"), call]).expect("args");
        call_verb(
            python,
            namespace,
            "conference_join",
            &args,
            &PyDict::new(python),
        )
    })
    .await;

    let refused = outcome.expect_err("refused");
    assert!(
        refused.starts_with("RuntimeError")
            && refused.contains("conference_join is not supported by the rtpengine media backend"),
        "{refused}"
    );
}

#[test]
fn a_join_refused_for_the_participants_codec_is_a_value_error_and_nothing_else_is() {
    Python::initialize();
    Python::attach(|python| {
        let kind = |reason: &str| {
            join_failure(crate::rtpengine::RtpEngineError::EngineError(
                reason.to_string(),
            ))
            .get_type(python)
            .name()
            .map(|name| name.to_string())
            .unwrap_or_default()
        };
        // As siphon-rtp 0.14.0 words them: a codec it cannot decode, one it
        // cannot encode the mix back into, and an offer with no audio codec.
        for refusal in [
            "conference_join: decoder: unsupported: AMR transcoding requires the `amr` build feature",
            "conference_join: codec opus has no encoder, so the room mix cannot be sent to this participant",
            "conference_join: offer has no audio codec",
        ] {
            assert_eq!(kind(refusal), "ValueError", "{refusal}");
        }
        for failure in [
            "conference_join: failed to seat participant",
            "conference_join: SDP parse: missing m= line",
        ] {
            assert_eq!(kind(failure), "RuntimeError", "{failure}");
        }
        let timeout = join_failure(crate::rtpengine::RtpEngineError::Timeout { timeout_ms: 2000 });
        assert!(timeout.is_instance_of::<pyo3::exceptions::PyRuntimeError>(python));
    });
}
