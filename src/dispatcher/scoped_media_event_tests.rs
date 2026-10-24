//! A media event of a leg anchored under a per-call scope reaches the script
//! under the SIP Call-ID, with the scope as a keyword for the handlers that
//! take one, whichever backend reported it.

use std::sync::Arc;

use super::*;
use crate::rtpengine::events::{DtmfEvent, RtpEngineEvent};

const SCRIPT: &str = concat!(
    "import _siphon_registry\n",
    "SEEN = []\n",
    "def scoped(call_id, from_tag, digit, duration_ms, volume, scope=None):\n",
    "    SEEN.append(f'scoped {call_id} {digit} {scope}')\n",
    "def plain(call_id, from_tag, digit, duration_ms, volume):\n",
    "    SEEN.append(f'plain {call_id} {digit}')\n",
    "def timed_out(call_id, from_tag, **extra):\n",
    "    SEEN.append(f'timeout {call_id} {extra.get(\"scope\")}')\n",
    "ANY = {'call_id': None, 'from_tag': None}\n",
    "_siphon_registry.register('rtpengine.on_dtmf', None, scoped, False, ANY)\n",
    "_siphon_registry.register('rtpengine.on_dtmf', None, plain, False, ANY)\n",
    "_siphon_registry.register('rtpengine.on_media_timeout', None, timed_out, False, ANY)\n",
);

fn digit(call_id: &str, digit: &str) -> RtpEngineEvent {
    RtpEngineEvent::Dtmf(DtmfEvent {
        call_id: call_id.to_string(),
        from_tag: "tag-a".to_string(),
        to_tag: None,
        digit: digit.to_string(),
        duration_ms: 80,
        volume: -10,
        source: None,
    })
}

/// What the script's handlers recorded, once `count` entries are in.
async fn seen(state: &DispatcherState, count: usize) -> Vec<String> {
    let kind = crate::script::engine::HandlerKind::RtpEngineOnDtmf {
        call_id: None,
        from_tag: None,
    };
    for _ in 0..200 {
        let recorded = {
            let engine_state = state.engine.state();
            let handlers = engine_state.handlers_for(&kind);
            let handler = handlers.first().expect("the script registered on_dtmf");
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
async fn a_scoped_legs_events_reach_the_script_under_the_call_id_with_the_scope() {
    let state = Arc::new(super::test_dispatcher::test_dispatcher_with_script(SCRIPT).state);
    let (events, receiver) = tokio::sync::mpsc::channel(8);
    spawn_rtpengine_events(&state, receiver);

    // As every backend reports a scoped leg: under its engine call-id.
    events
        .send(digit("scoped-ev@192.0.2.10;orig", "5"))
        .await
        .expect("the event loop is running");
    let first = seen(&state, 2).await;
    // The node's own call: no scope, and the scoped handler sees None.
    events
        .send(digit("scoped-ev@192.0.2.10", "7"))
        .await
        .expect("the event loop is running");
    let both = seen(&state, 4).await;
    events
        .send(RtpEngineEvent::MediaTimeout {
            call_id: "scoped-ev@192.0.2.10;term".to_string(),
            from_tag: "tag-a".to_string(),
            reason: "no_media",
        })
        .await
        .expect("the event loop is running");
    let all = seen(&state, 5).await;

    let mut first = first;
    first.sort();
    assert_eq!(
        first,
        vec![
            "plain scoped-ev@192.0.2.10 5".to_string(),
            "scoped scoped-ev@192.0.2.10 5 orig".to_string(),
        ]
    );
    let mut node = both[2..].to_vec();
    node.sort();
    assert_eq!(
        node,
        vec![
            "plain scoped-ev@192.0.2.10 7".to_string(),
            "scoped scoped-ev@192.0.2.10 7 None".to_string(),
        ]
    );
    assert_eq!(all[4], "timeout scoped-ev@192.0.2.10 term");
}
