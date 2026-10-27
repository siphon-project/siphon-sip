//! A recording's closed file reaches the script's
//! `@rtpengine.on_recording_finished` handlers, keyed on the SIP Call-ID, with
//! everything a script needs to pick the file up.

use std::sync::Arc;

use super::*;
use crate::rtpengine::events::{RecordingFinished, RtpEngineEvent};

const SCRIPT: &str = concat!(
    "import _siphon_registry\n",
    "SEEN = []\n",
    "def closed(call_id, from_tag, recording_id, path, reason, duration_ms):\n",
    "    SEEN.append(f'any {call_id} {from_tag} {recording_id} {path} {reason} {duration_ms}')\n",
    "def other(call_id, from_tag, recording_id, path, reason, duration_ms):\n",
    "    SEEN.append(f'other {call_id}')\n",
    "_siphon_registry.register('rtpengine.on_recording_finished', None, closed, False,\n",
    "    {'call_id': None, 'from_tag': None})\n",
    "_siphon_registry.register('rtpengine.on_recording_finished', None, other, False,\n",
    "    {'call_id': 'another-call@example.com', 'from_tag': None})\n",
);

/// What the script's handlers recorded, once `count` entries are in.
async fn seen(state: &DispatcherState, count: usize) -> Vec<String> {
    for _ in 0..200 {
        let recorded = {
            let engine_state = state.engine.state();
            let handlers = engine_state.recording_finished_handlers("any", "any");
            let handler = handlers
                .first()
                .expect("the script registered on_recording_finished");
            pyo3::Python::attach(|python| {
                handler
                    .callable
                    .bind(python)
                    .getattr("__globals__")
                    .and_then(|globals| globals.get_item("SEEN"))
                    .and_then(|seen| seen.extract::<Vec<String>>())
                    .expect("SEEN is a list of str")
            })
        };
        if recorded.len() >= count {
            return recorded;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("the handlers did not run");
}

#[tokio::test]
async fn a_closed_recording_reaches_the_handlers_for_its_call() {
    let state = Arc::new(super::test_dispatcher::test_dispatcher_with_script(SCRIPT).state);
    let (events, receiver) = tokio::sync::mpsc::channel(8);
    spawn_rtpengine_events(&state, receiver);

    events
        .send(RtpEngineEvent::RecordingFinished(RecordingFinished {
            call_id: "rec-ev@example.com".to_string(),
            from_tag: "tag-a".to_string(),
            recording_id: "rec-1".to_string(),
            path: Some("/var/spool/recordings/rec-1.opus".to_string()),
            reason: "max_duration",
            duration_ms: 61_000,
        }))
        .await
        .expect("the event loop is running");
    events
        .send(RtpEngineEvent::RecordingFinished(RecordingFinished {
            call_id: "rec-ev@example.com".to_string(),
            from_tag: "tag-a".to_string(),
            recording_id: "rec-2".to_string(),
            path: None,
            reason: "error",
            duration_ms: 0,
        }))
        .await
        .expect("the event loop is running");

    assert_eq!(
        seen(&state, 2).await,
        vec![
            "any rec-ev@example.com tag-a rec-1 /var/spool/recordings/rec-1.opus max_duration 61000"
                .to_string(),
            "any rec-ev@example.com tag-a rec-2 None error 0".to_string(),
        ],
        "the filtered handler for another call never ran"
    );
}
