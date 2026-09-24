use super::sbi_callbacks::{pcf_notification_body_to_json, router, status_for_dispatch};
use crate::script::engine::{HandlerEntry, HandlerKind, ScriptState};
use arc_swap::ArcSwap;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::path::PathBuf;
use std::sync::Arc;
use tower::util::ServiceExt;

/// An `EventsNotification` as a PCF posts it to `{evSubsc.notifUri}/notify`
/// (TS 29.514). `failedResourcAllocReports` is the real, misspelled member name.
const EVENTS_NOTIFICATION: &str = r#"{
    "evSubsUri": "http://pcf.example.com:8080/npcf-policyauthorization/v1/app-sessions/sess-abc/events-subscription",
    "evNotifs": [
        {
            "event": "FAILED_RESOURCES_ALLOCATION",
            "flows": [ { "medCompN": 1, "fNums": [1, 2] } ]
        }
    ],
    "failedResourcAllocReports": [
        { "mcResourcStatus": "INACTIVE", "flows": [ { "medCompN": 1 } ] }
    ]
}"#;

/// A `TerminationInfo` as a PCF posts it to `{ascReqData.notifUri}/terminate`.
const TERMINATION_INFO: &str = r#"{
    "termCause": "PDU_SESSION_TERMINATION",
    "resUri": "http://pcf.example.com:8080/npcf-policyauthorization/v1/app-sessions/sess-abc"
}"#;

/// Handlers that record what they were handed: a sync `on_event` and an async
/// `on_terminate`, so both calling conventions go through the route.
const RECORDING_HANDLERS: &std::ffi::CStr = c"
import json
received = []

def on_event(document):
    received.append(('sbi.on_event', json.dumps(document)))

async def on_terminate(document):
    received.append(('sbi.on_terminate', json.dumps(document)))

def raising_on_event(document):
    received.append(('sbi.on_event', json.dumps(document)))
    raise RuntimeError('script bug')
";

struct Recording {
    script_state: Arc<ArcSwap<ScriptState>>,
    received: Py<PyAny>,
}

/// Build a script state holding the recording handlers. `on_event_name`
/// picks which Python function is registered as `@sbi.on_event`.
fn recording(on_event_name: &str) -> Recording {
    Python::initialize();
    Python::attach(|python| {
        let globals = PyDict::new(python);
        python
            .run(RECORDING_HANDLERS, Some(&globals), None)
            .expect("define recording handlers");
        let function = |name: &str| -> Py<PyAny> {
            globals
                .get_item(name)
                .expect("globals lookup")
                .expect("handler defined")
                .unbind()
        };
        let handlers = vec![
            HandlerEntry {
                kind: HandlerKind::SbiOnEvent,
                callable: function(on_event_name),
                is_async: false,
                options: None,
            },
            HandlerEntry {
                kind: HandlerKind::SbiOnTerminate,
                callable: function("on_terminate"),
                is_async: true,
                options: None,
            },
        ];
        let state = ScriptState {
            source_path: PathBuf::from("<sbi-callback-test>"),
            handlers,
        };
        Recording {
            script_state: Arc::new(ArcSwap::from_pointee(state)),
            received: function("received"),
        }
    })
}

impl Recording {
    /// Every (decorator, document) pair the handlers saw, in order.
    fn received(&self) -> Vec<(String, serde_json::Value)> {
        Python::attach(|python| {
            let entries: Vec<(String, String)> = self
                .received
                .bind(python)
                .extract()
                .expect("received is a list of (str, str)");
            entries
                .into_iter()
                .map(|(name, document)| {
                    let value = serde_json::from_str(&document).expect("handler saw JSON");
                    (name, value)
                })
                .collect()
        })
    }
}

async fn post(app: axum::Router, path: &str, body: &str) -> StatusCode {
    app.oneshot(
        Request::post(path)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .expect("request"),
    )
    .await
    .expect("router answers")
    .status()
}

fn json(document: &str) -> serde_json::Value {
    serde_json::from_str(document).expect("fixture is JSON")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn notify_route_runs_on_event_with_the_body_verbatim() {
    let recording = recording("on_event");
    let app = router(Arc::clone(&recording.script_state));

    let status = post(app, "/sbi/events/notify", EVENTS_NOTIFICATION).await;

    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        recording.received(),
        vec![("sbi.on_event".to_string(), json(EVENTS_NOTIFICATION))]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn terminate_route_runs_on_terminate_and_not_on_event() {
    let recording = recording("on_event");
    let app = router(Arc::clone(&recording.script_state));

    let status = post(app, "/sbi/events/terminate", TERMINATION_INFO).await;

    assert_eq!(status, StatusCode::NO_CONTENT);
    // Only the async terminate handler ran, with the document intact.
    assert_eq!(
        recording.received(),
        vec![("sbi.on_terminate".to_string(), json(TERMINATION_INFO))]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bare_events_route_is_gone_and_runs_nothing() {
    // Deprecated in 1.9.0 with the removal release named, removed in 1.10.0.
    // TS 29.514 has the PCF append a suffix to `notifUri`, so the bare path only
    // ever served a PCF that posted the advertised URI verbatim. Asserting the
    // 404 *and* that no handler ran keeps the removal honest: a route that
    // silently dispatched to `@sbi.on_event` anyway would still pass a
    // status-only check if it answered 404 for some other reason.
    let recording = recording("on_event");
    let app = router(Arc::clone(&recording.script_state));

    let status = post(app, "/sbi/events", EVENTS_NOTIFICATION).await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(recording.received().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_sub_path_is_not_found_and_runs_nothing() {
    let recording = recording("on_event");
    let app = router(Arc::clone(&recording.script_state));

    let status = post(app, "/sbi/events/other", EVENTS_NOTIFICATION).await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(recording.received().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_json_body_is_rejected_on_every_route() {
    let recording = recording("on_event");
    let app = router(Arc::clone(&recording.script_state));

    for path in ["/sbi/events/notify", "/sbi/events/terminate"] {
        let status = post(app.clone(), path, "not json at all").await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{path}");
    }
    assert!(recording.received().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handler_exception_is_still_acknowledged() {
    // A retry cannot fix a script bug, so the PCF gets its 204 and the
    // exception goes to the log.
    let recording = recording("raising_on_event");
    let app = router(Arc::clone(&recording.script_state));

    let status = post(app, "/sbi/events/notify", EVENTS_NOTIFICATION).await;

    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(recording.received().len(), 1, "the handler did run");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reloaded_handlers_are_the_ones_that_run() {
    let recording = recording("on_event");
    let app = router(Arc::clone(&recording.script_state));

    // A reload that registers no SBI handlers swaps the state under the
    // running listener; the next callback must see the new state.
    recording.script_state.store(Arc::new(ScriptState {
        source_path: PathBuf::from("<reloaded>"),
        handlers: Vec::new(),
    }));
    let status = post(app, "/sbi/events/terminate", TERMINATION_INFO).await;

    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(recording.received().is_empty());
}

#[test]
fn dispatch_that_ran_is_no_content() {
    let outcome: std::thread::Result<()> = Ok(());
    assert_eq!(status_for_dispatch(&outcome), StatusCode::NO_CONTENT);
}

#[test]
fn executor_refusal_is_service_unavailable() {
    // What `py_executor::try_run` hands back when the queue is full or closed:
    // the handlers never ran, so the PCF must not read it as an ack.
    let outcome: std::thread::Result<()> = Err(Box::new("Python executor queue full — load shed"));
    assert_eq!(
        status_for_dispatch(&outcome),
        StatusCode::SERVICE_UNAVAILABLE
    );
}

/// A real-shaped TS 29.514 `EventsNotification` must reach the script with
/// EVERY field intact. The old typed projection both dropped
/// `evSubsUri`/`succResourcAllocReports` and `422`'d the whole callback because
/// its `flows` model wanted `flowId` instead of TS 29.514's `{medCompN, fNums}`.
#[test]
fn pcf_notification_body_is_passed_through_losslessly() {
    let body = r#"{
        "evSubsUri": "http://pcf01:8080/npcf-policyauthorization/v1/app-sessions/sess-abc/events-subscription",
        "evNotifs": [
            {
                "event": "SUCCESSFUL_RESOURCES_ALLOCATION",
                "flows": [ { "medCompN": 1, "fNums": [1, 2] } ]
            }
        ],
        "succResourcAllocReports": [ { "medComponents": {} } ]
    }"#;
    let out = pcf_notification_body_to_json(body.as_bytes()).expect("well-formed JSON must decode");
    let value: serde_json::Value = serde_json::from_str(&out).unwrap();

    // evSubsUri — the correlation key — survives.
    assert_eq!(
        value["evSubsUri"].as_str(),
        Some(
            "http://pcf01:8080/npcf-policyauthorization/v1/app-sessions/sess-abc/events-subscription"
        )
    );
    // The TS 29.514 flow shape ({medCompN, fNums}) survives — would have 422'd before.
    let flow = &value["evNotifs"][0]["flows"][0];
    assert_eq!(flow["medCompN"].as_u64(), Some(1));
    assert_eq!(flow["fNums"][1].as_u64(), Some(2));
    // Fields outside the old typed model survive.
    assert!(value.get("succResourcAllocReports").is_some());
}

#[test]
fn pcf_notification_body_rejects_non_json() {
    assert!(pcf_notification_body_to_json(b"not json at all").is_none());
}
