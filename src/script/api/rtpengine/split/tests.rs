//! The split verbs as a script calls them: through the real Python methods,
//! awaited from a coroutine, against an engine that records the raw frames it
//! is sent.

use std::ffi::CString;
use std::sync::Arc;

use pyo3::prelude::*;
use pyo3::types::PyDict;
use serde_json::{json, Value};

use super::super::PyRtpEngine;
use crate::config::{MediaProfileConfig, NgFlagsConfig};
use crate::rtpengine::profile::ProfileRegistry;
use crate::rtpengine::session::MediaSession;
use crate::rtpengine::test_conference_engine::{accept, FakeEngine};
use crate::rtpengine::{MediaBackend, MediaSessionStore};

fn node_info(features: &[&str]) -> Value {
    json!({
        "result": "node_info",
        "node": {
            "node_id": "engine-1", "version": "0.29.0", "media_addresses": [],
            "codecs": [], "features": features, "max_sessions": 0, "draining": false,
        },
    })
}

fn lists_ws_split(request: &Value) -> Value {
    match request["command"].as_str() {
        Some("node_info") => node_info(&["relay", "ws_split"]),
        _ => accept(request),
    }
}

fn lacks_ws_split(request: &Value) -> Value {
    match request["command"].as_str() {
        Some("node_info") => node_info(&["relay"]),
        _ => accept(request),
    }
}

fn refuses_renegotiation(request: &Value) -> Value {
    match request["command"].as_str() {
        Some("attach_ws_split") => json!({
            "result": "error",
            "reason": "attach_ws_split: ws-split-renegotiation: a DTLS re-handshake cannot be followed",
        }),
        _ => lists_ws_split(request),
    }
}

fn unknown_call(request: &Value) -> Value {
    match request["command"].as_str() {
        Some("attach_ws_split") => json!({"result": "error", "reason": "unknown call: no-such"}),
        _ => lists_ws_split(request),
    }
}

fn registry() -> ProfileRegistry {
    let mut custom = std::collections::HashMap::new();
    custom.insert(
        "denoise".to_string(),
        MediaProfileConfig {
            offer: NgFlagsConfig::default(),
            answer: NgFlagsConfig {
                noise_suppression: true,
                ..NgFlagsConfig::default()
            },
        },
    );
    ProfileRegistry::from_config(&custom)
}

fn session(call_id: &str, from_tag: &str) -> MediaSession {
    MediaSession {
        call_id: call_id.to_string(),
        rtpengine_call_id: String::new(),
        from_tag: from_tag.to_string(),
        to_tag: Some("tag-b".to_string()),
        profile: "rtp_passthrough".to_string(),
        ws_uri: None,
        ws_tee: None,
        ws_bridge_attached: false,
        ws_split_attached: false,
        bridge_sides: None,
        created_at: std::time::Instant::now(),
    }
}

/// The namespace on `backend`, with the session store it writes to.
fn namespace(backend: Arc<MediaBackend>) -> (PyRtpEngine, Arc<MediaSessionStore>) {
    let sessions = Arc::new(MediaSessionStore::new());
    sessions.insert(session("call-1@example.com", "tag-a"));
    (bound_to(&backend, &sessions), sessions)
}

/// Another handle on the same engine and sessions, as a script's later call
/// would use.
fn bound_to(backend: &Arc<MediaBackend>, sessions: &Arc<MediaSessionStore>) -> PyRtpEngine {
    PyRtpEngine::new(
        Arc::clone(backend),
        Arc::clone(sessions),
        Arc::new(registry()),
    )
}

/// What awaiting a verb gave: its value, or the exception's class name,
/// message and `token` attribute (`Some(None)` is a `token` that is `None`).
#[derive(Debug)]
enum Outcome {
    Done,
    Raised {
        class: String,
        message: String,
        token: Option<Option<String>>,
    },
}

impl Outcome {
    fn raised(&self) -> (&str, &str, &Option<Option<String>>) {
        match self {
            Outcome::Raised {
                class,
                message,
                token,
            } => (class, message, token),
            Outcome::Done => panic!("expected the verb to raise"),
        }
    }
}

/// `await rtpengine.<verb>(("call-1@example.com", "tag-a"), ws_uri, **kwargs)`
/// from inside a coroutine, the way a script does it, on a thread where a
/// script handler runs. `ws_uri` is left out of a detach.
async fn run(
    namespace: PyRtpEngine,
    verb: &'static str,
    ws_uri: Option<&'static str>,
    kwargs: Vec<(&'static str, Value)>,
) -> Outcome {
    Python::initialize();
    tokio::task::spawn_blocking(move || {
        let _serial = crate::script::async_pool::pool_test_guard();
        Python::attach(|python| {
            let namespace = Bound::new(python, namespace).expect("bound");
            let code = CString::new(format!(
                "async def run(rtpengine, ws_uri, kwargs):\n    \
                 target = ('call-1@example.com', 'tag-a')\n    \
                 if ws_uri is None:\n        \
                 return await rtpengine.{verb}(target)\n    \
                 return await rtpengine.{verb}(target, ws_uri, **kwargs)\n"
            ))
            .expect("source");
            let globals = PyDict::new(python);
            python
                .run(code.as_c_str(), Some(&globals), None)
                .expect("defined");
            let python_kwargs = PyDict::new(python);
            for (name, value) in kwargs {
                match value {
                    Value::String(text) => python_kwargs.set_item(name, text),
                    Value::Number(number) => {
                        python_kwargs.set_item(name, number.as_u64().expect("an unsigned integer"))
                    }
                    other => panic!("unsupported keyword {other}"),
                }
                .expect("kwarg");
            }
            let run = globals.get_item("run").expect("lookup").expect("run");
            let coroutine = run
                .call1((namespace, ws_uri, python_kwargs))
                .expect("coroutine");
            match crate::script::engine::run_coroutine_value(python, &coroutine) {
                Ok(_) => Outcome::Done,
                Err(error) => Outcome::Raised {
                    class: error
                        .get_type(python)
                        .name()
                        .map(|name| name.to_string())
                        .unwrap_or_default(),
                    message: error.value(python).to_string(),
                    token: error
                        .value(python)
                        .getattr("token")
                        .ok()
                        .map(|token| token.extract::<Option<String>>().unwrap_or(None)),
                },
            }
        })
    })
    .await
    .expect("the blocking task")
}

const URI: &str = "wss://bot.example.net/call";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn attach_and_detach_reach_the_engine_and_track_the_leg() {
    let engine = FakeEngine::start(lists_ws_split, Vec::new()).await;
    let backend = engine.backend();
    let (namespace, sessions) = namespace(Arc::clone(&backend));

    let attached = run(
        namespace,
        "attach_ws_split",
        Some(URI),
        vec![
            ("sample_rate", json!(24_000)),
            ("offerer_profile", json!("denoise")),
        ],
    )
    .await;
    assert!(matches!(attached, Outcome::Done), "{attached:?}");

    let frame = &engine.frames("attach_ws_split")[0];
    assert_eq!(frame["call_id"], "call-1@example.com");
    assert_eq!(frame["from_tag"], "tag-a");
    assert_eq!(frame["ws_uri"], "wss://bot.example.net/call");
    assert_eq!(frame["sample_rate"], 24_000);
    assert_eq!(frame["offerer_profile"]["noise_suppression"], true);
    assert!(frame.get("answerer_profile").is_none(), "{frame}");
    assert!(
        sessions
            .get("call-1@example.com")
            .expect("session")
            .ws_split_attached,
        "an accepted attach flags the leg"
    );

    let detached = run(
        bound_to(&backend, &sessions),
        "detach_ws_split",
        None,
        vec![],
    )
    .await;
    assert!(matches!(detached, Outcome::Done), "{detached:?}");
    assert_eq!(engine.frames("detach_ws_split").len(), 1);
    assert!(
        !sessions
            .get("call-1@example.com")
            .expect("session")
            .ws_split_attached,
        "a detach clears the flag"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refusal_reaches_the_script_with_its_token() {
    let engine = FakeEngine::start(refuses_renegotiation, Vec::new()).await;
    let (namespace, sessions) = namespace(engine.backend());

    let outcome = run(namespace, "attach_ws_split", Some(URI), vec![]).await;

    let (class, message, token) = outcome.raised();
    assert_eq!(class, "RuntimeError");
    assert!(
        message.starts_with("rtpengine.attach_ws_split failed: "),
        "{message}"
    );
    assert!(
        message.contains("attach_ws_split: ws-split-renegotiation: "),
        "{message}"
    );
    assert_eq!(
        token,
        &Some(Some("ws-split-renegotiation".to_string())),
        "the token is an attribute of the exception"
    );
    assert!(
        !sessions
            .get("call-1@example.com")
            .expect("session")
            .ws_split_attached,
        "a refused attach flags nothing"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failure_that_is_not_a_token_refusal_has_no_token() {
    let engine = FakeEngine::start(unknown_call, Vec::new()).await;
    let (namespace, _sessions) = namespace(engine.backend());

    let outcome = run(namespace, "attach_ws_split", Some(URI), vec![]).await;

    let (class, _message, token) = outcome.raised();
    assert_eq!(class, "RuntimeError");
    assert_eq!(token, &Some(None), "the attribute exists and is None");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_engine_without_the_feature_is_refused_clearly_and_nothing_is_sent() {
    let engine = FakeEngine::start(lacks_ws_split, Vec::new()).await;
    let (namespace, _sessions) = namespace(engine.backend());

    let outcome = run(namespace, "attach_ws_split", Some(URI), vec![]).await;

    let (class, message, _token) = outcome.raised();
    assert_eq!(class, "RuntimeError");
    assert!(message.contains("ws_split"), "{message}");
    assert!(engine.frames("attach_ws_split").is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bad_rate_or_an_unknown_profile_is_a_value_error_before_anything_is_sent() {
    let engine = FakeEngine::start(lists_ws_split, Vec::new()).await;
    let backend = engine.backend();
    let (_first, sessions) = namespace(Arc::clone(&backend));

    for (name, value, needle) in [
        ("sample_rate", json!(44_100), "44100"),
        (
            "answerer_profile",
            json!("no-such-profile"),
            "no-such-profile",
        ),
    ] {
        let outcome = run(
            bound_to(&backend, &sessions),
            "attach_ws_split",
            Some(URI),
            vec![(name, value)],
        )
        .await;
        let (class, message, _token) = outcome.raised();
        assert_eq!(class, "ValueError", "{name}: {message}");
        assert!(message.contains(needle), "{name}: {message}");
    }
    assert!(engine.commands().is_empty(), "{:?}", engine.commands());
}
