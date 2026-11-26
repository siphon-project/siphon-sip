//! The split bridge's lifecycle: the engine's `ws_split_started` /
//! `ws_split_ended` reach the script's handlers under the SIP Call-ID of the
//! offerer's dialog and the control rail with the channel layout, and a leg's
//! flag follows what the engine says about the call being isolated.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use super::*;
use crate::rtpengine::events::{RtpEngineEvent, WsSplitEnded, WsSplitStarted};
use crate::rtpengine::session::MediaSession;
use crate::rtpengine::test_native_engine::NativeTestEngine;
use crate::rtpengine::MediaSessionStore;

const SCRIPT: &str = concat!(
    "import _siphon_registry\n",
    "SEEN = []\n",
    "def started(call_id, from_tag, stream_id, ws_uri, sample_rate):\n",
    "    SEEN.append(f'started {call_id} {from_tag} {stream_id} {ws_uri} {sample_rate}')\n",
    "def ended(call_id, from_tag, stream_id, reason):\n",
    "    SEEN.append(f'ended {call_id} {from_tag} {stream_id} {reason}')\n",
    "def other_call(call_id, from_tag, stream_id, reason):\n",
    "    SEEN.append(f'other {call_id}')\n",
    "_siphon_registry.register('rtpengine.on_ws_split_started', None, started, False,\n",
    "    {'call_id': None, 'from_tag': None})\n",
    "_siphon_registry.register('rtpengine.on_ws_split_ended', None, ended, False,\n",
    "    {'call_id': None, 'from_tag': None})\n",
    "_siphon_registry.register('rtpengine.on_ws_split_ended', None, other_call, False,\n",
    "    {'call_id': 'another-call@example.com', 'from_tag': None})\n",
);

/// A bridged pair on engine call `pair-1`: the caller's dialog (channel 0, the
/// offerer) holds the session, the phone's dialog is the other party.
fn pair_store() -> Arc<MediaSessionStore> {
    let store = Arc::new(MediaSessionStore::new());
    store.insert(MediaSession {
        call_id: "caller@example.com".to_string(),
        rtpengine_call_id: "pair-1".to_string(),
        from_tag: "tag-a".to_string(),
        to_tag: Some("tag-b".to_string()),
        profile: "rtp_passthrough".to_string(),
        ws_uri: None,
        ws_tee: None,
        ws_bridge_attached: false,
        ws_split_attached: false,
        bridge_sides: None,
        created_at: std::time::Instant::now(),
    });
    store.record_parties(
        "caller@example.com",
        "pair-1",
        &[
            ("caller@example.com", Some("tag-a")),
            ("phone@example.com", Some("tag-b")),
        ],
    );
    store
}

fn started() -> WsSplitStarted {
    WsSplitStarted {
        call_id: "pair-1".to_string(),
        from_tag: "tag-a".to_string(),
        stream_id: "split-pair-1".to_string(),
        ws_uri: "wss://bot.example.net/call".to_string(),
        sample_rate: 16_000,
    }
}

fn ended(reason: &str) -> WsSplitEnded {
    WsSplitEnded {
        call_id: "pair-1".to_string(),
        from_tag: "tag-a".to_string(),
        stream_id: "split-pair-1".to_string(),
        reason: reason.to_string(),
    }
}

/// What the script's handlers recorded, once `count` entries are in.
async fn seen(state: &DispatcherState, count: usize) -> Vec<String> {
    for _ in 0..300 {
        let recorded = {
            let engine_state = state.engine.state();
            let handlers = engine_state.ws_split_started_handlers("any", "any");
            let handler = handlers
                .first()
                .expect("the script registered on_ws_split_started");
            Python::attach(|python| {
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

/// Every reason the engine documents, and one it does not know yet, reaches
/// the handler as the engine spells it, under the SIP Call-ID of the offerer's
/// dialog (the pair's engine call-id is not the one a script holds). The leg
/// stays flagged as isolated after every end but `detached` and
/// `call_deleted`.
#[tokio::test(flavor = "multi_thread")]
async fn each_end_reason_reaches_the_handler_under_the_sip_call_id() {
    let store = pair_store();
    let mut dispatcher = super::test_dispatcher::test_dispatcher_with_script(SCRIPT);
    dispatcher.state.rtpengine_sessions = Some(Arc::clone(&store));
    let state = Arc::new(dispatcher.state);
    let (events, receiver) = tokio::sync::mpsc::channel(8);
    spawn_rtpengine_events(&state, receiver);
    let flagged = || {
        store
            .get("caller@example.com")
            .expect("the pair's session")
            .ws_split_attached
    };

    events
        .send(RtpEngineEvent::WsSplitStarted(started()))
        .await
        .expect("the event loop is running");
    let mut expected = vec![
        "started caller@example.com tag-a split-pair-1 wss://bot.example.net/call 16000"
            .to_string(),
    ];
    assert_eq!(seen(&state, 1).await, expected);
    assert!(
        flagged(),
        "a started split flags the leg, whoever attached it"
    );

    for (reason, isolated) in [
        ("detached", false),
        ("ws_closed", true),
        ("ws_stopped", true),
        ("ws_error", true),
        ("call_deleted", false),
        ("renegotiated", true),
        ("restored", true),
    ] {
        events
            .send(RtpEngineEvent::WsSplitEnded(ended(reason)))
            .await
            .expect("the event loop is running");
        expected.push(format!(
            "ended caller@example.com tag-a split-pair-1 {reason}"
        ));
        assert_eq!(
            seen(&state, expected.len()).await,
            expected,
            "the handler filtered to another call never ran"
        );
        assert_eq!(
            flagged(),
            isolated,
            "{reason}: the call is isolated until a detach, except after detached/call_deleted"
        );
    }
}

/// The rail names the party on each channel of the stream, and says whether an
/// end left the call isolated, with the engine's reason verbatim.
#[tokio::test(flavor = "multi_thread")]
async fn the_rail_names_the_party_on_each_channel() {
    let store = pair_store();
    let mut dispatcher = super::test_dispatcher::test_dispatcher_with_script(SCRIPT);
    dispatcher.state.rtpengine_sessions = Some(store);
    crate::control::channel_event_capture::watch("caller@example.com");
    crate::control::channel_event_capture::watch("phone@example.com");

    publish_ws_split_started(&dispatcher.state, &started());
    publish_ws_split_ended(&dispatcher.state, &ended("ws_error"));
    publish_ws_split_ended(&dispatcher.state, &ended("detached"));

    let caller = crate::control::channel_event_capture::take("caller@example.com");
    let phone = crate::control::channel_event_capture::take("phone@example.com");
    assert!(
        phone.is_empty(),
        "the events go to the offerer's channel only: {phone:?}"
    );
    let names: Vec<&str> = caller.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(names, ["WsSplitStarted", "WsSplitEnded", "WsSplitEnded"]);
    assert_eq!(caller[0].1["stream_id"], "split-pair-1");
    assert_eq!(caller[0].1["ws_uri"], "wss://bot.example.net/call");
    assert_eq!(caller[0].1["sample_rate"], 16_000);
    assert_eq!(
        caller[0].1["channels"],
        serde_json::json!([
            {"channel": 0, "party": "offerer", "sip_call_id": "caller@example.com"},
            {"channel": 1, "party": "answerer", "sip_call_id": "phone@example.com"},
        ])
    );
    assert_eq!(caller[1].1["reason"], "ws_error");
    assert_eq!(caller[1].1["isolated"], true);
    assert_eq!(caller[2].1["reason"], "detached");
    assert_eq!(caller[2].1["isolated"], false);
}

/// A script that detaches from inside the end hook, while another thread
/// forces the collector's stop-the-world, still completes: the hook awaits the
/// engine with no interpreter state held across the wait.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_detach_from_inside_the_end_hook_completes_under_a_forced_collection() {
    const HOOK_SCRIPT: &str = concat!(
        "import _siphon_registry\n",
        "import builtins\n",
        "DONE = []\n",
        "SEEN = []\n",
        "async def ended(call_id, from_tag, stream_id, reason):\n",
        "    await builtins._test_rtpengine.detach_ws_split((call_id, from_tag))\n",
        "    DONE.append(reason)\n",
        "def started(call_id, from_tag, stream_id, ws_uri, sample_rate):\n",
        "    SEEN.append(call_id)\n",
        "_siphon_registry.register('rtpengine.on_ws_split_started', None, started, False,\n",
        "    {'call_id': None, 'from_tag': None})\n",
        "_siphon_registry.register('rtpengine.on_ws_split_ended', None, ended, True,\n",
        "    {'call_id': None, 'from_tag': None})\n",
    );
    pyo3::Python::initialize();
    let engine = NativeTestEngine::start_with_ws_split().await;
    engine.admit("hook-call@example.com");
    let backend = engine.backend();
    let sessions = Arc::new(MediaSessionStore::new());
    let mut dispatcher = super::test_dispatcher::test_dispatcher_with_script(HOOK_SCRIPT);
    dispatcher.state.rtpengine_set = Some(Arc::clone(&backend));
    dispatcher.state.rtpengine_sessions = Some(Arc::clone(&sessions));
    Python::attach(|python| {
        let namespace = crate::script::api::rtpengine::PyRtpEngine::new(
            Arc::clone(&backend),
            Arc::clone(&sessions),
            Arc::new(crate::rtpengine::ProfileRegistry::new()),
        );
        python
            .import("builtins")
            .and_then(|builtins| {
                builtins.setattr("_test_rtpengine", Bound::new(python, namespace)?)
            })
            .expect("the namespace is reachable from the script");
    });
    let state = Arc::new(dispatcher.state);
    let (events, receiver) = tokio::sync::mpsc::channel(8);
    spawn_rtpengine_events(&state, receiver);

    backend
        .attach_ws_split(
            "hook-call@example.com",
            "tag-a",
            "wss://bot.example.net/call",
            None,
            None,
            None,
        )
        .await
        .expect("the engine took the split");
    assert_eq!(engine.split_count(), 1);
    engine.end_split(
        "hook-call@example.com",
        siphon_rtp_proto::WsSplitEndReason::WsError,
    );

    // A collection forced from another thread for as long as the hook runs.
    let stop = Arc::new(AtomicBool::new(false));
    let collector = {
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                Python::attach(|python| {
                    let _ = python
                        .import("gc")
                        .and_then(|gc| gc.call_method0("collect"));
                });
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
        })
    };
    for event in engine.take_split_events() {
        events.send(event).await.expect("the event loop is running");
    }
    let finished = tokio::time::timeout(std::time::Duration::from_secs(15), async {
        loop {
            if !engine.commands("detach_ws_split").is_empty() && engine.split_count() == 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await;
    stop.store(true, Ordering::Relaxed);
    let _ = collector.join();

    assert!(
        finished.is_ok(),
        "the detach from inside the hook never reached the engine"
    );
    assert_eq!(engine.commands("detach_ws_split").len(), 1);
    assert_eq!(
        engine.split_count(),
        0,
        "the call has its direct audio back"
    );
}

/// A split on a leg that is bridged again comes off first, or the in-place
/// re-offer ends it `renegotiated` and leaves the new pairing isolated and
/// silent. The leg's flag is read from its session, the plan has the step, the
/// step reaches the engine, and the engine's `detached` clears the flag.
#[tokio::test(flavor = "multi_thread")]
async fn a_split_is_detached_before_a_leg_is_bridged_again() {
    use super::dial_bridge_test_harness::{answered_caller, bridging_dispatcher};
    use crate::b2bua::bridge::{bridge_media_plan, AnchorOffer, MediaStep};

    let engine = NativeTestEngine::start_with_ws_split().await;
    let dispatcher = bridging_dispatcher(&engine);
    let caller = answered_caller(&dispatcher, "split-plan@192.0.2.10");
    let state = Arc::new(dispatcher.state);
    let (events, receiver) = tokio::sync::mpsc::channel(8);
    spawn_rtpengine_events(&state, receiver);
    let backend = engine.backend();
    let session = state
        .rtpengine_sessions
        .as_ref()
        .and_then(|store| store.get(&caller.call_id))
        .expect("the caller's anchored session");

    backend
        .attach_ws_split(
            session.rtpengine_id(),
            &session.from_tag,
            "wss://bot.example.net/call",
            None,
            None,
            None,
        )
        .await
        .expect("the engine took the split");
    for event in engine.take_split_events() {
        events.send(event).await.expect("the event loop is running");
    }
    let flagged = |state: &DispatcherState| {
        bridge_leg_snapshot(state, &caller.call_id, "target")
            .expect("the caller's leg")
            .media
            .expect("anchored")
            .has_ws_split
    };
    let mut waited = 0;
    while !flagged(&state) && waited < 200 {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        waited += 1;
    }
    assert!(flagged(&state), "the leg reads as split from its session");

    let media = bridge_leg_snapshot(&state, &caller.call_id, "target")
        .expect("the caller's leg")
        .media
        .expect("anchored");
    let steps = bridge_media_plan(
        Some(&media),
        None,
        AnchorOffer {
            sdp: b"v=0\r\n",
            pair_profile: None,
            source: None,
            sip_call_id: &caller.call_id,
        },
        "fresh-call",
    );
    let detach = steps
        .iter()
        .find(|step| matches!(step, MediaStep::DetachSplit { .. }))
        .expect("the plan detaches the split");
    bridge_run_media_step(&backend, state.rtpengine_profiles.as_ref(), detach)
        .await
        .expect("the engine detached it");

    assert_eq!(engine.commands("detach_ws_split").len(), 1);
    assert_eq!(engine.split_count(), 0, "the parties have each other back");
    for event in engine.take_split_events() {
        events.send(event).await.expect("the event loop is running");
    }
    let mut waited = 0;
    while flagged(&state) && waited < 200 {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        waited += 1;
    }
    assert!(
        !flagged(&state),
        "the engine's detached end clears the flag"
    );
}

/// One Call-ID can hold an unscoped split and a scoped leg's: an event of the
/// scoped leg (engine call-id `<call-id>;<scope>`) moves the scoped session's
/// flag and never the unscoped one's, whose bridge plan would otherwise skip
/// the detach it needs.
#[tokio::test(flavor = "multi_thread")]
async fn a_scoped_legs_events_move_its_own_flag_not_the_unscoped_ones() {
    let store = Arc::new(MediaSessionStore::new());
    let session = |tag: &str| MediaSession {
        call_id: "shared@example.com".to_string(),
        rtpengine_call_id: String::new(),
        from_tag: tag.to_string(),
        to_tag: None,
        profile: "rtp_passthrough".to_string(),
        ws_uri: None,
        ws_tee: None,
        ws_bridge_attached: false,
        ws_split_attached: false,
        bridge_sides: None,
        created_at: std::time::Instant::now(),
    };
    store.insert(session("tag-a"));
    let scope = crate::rtpengine::CallScope::per_call("out").expect("a scope");
    let scoped = store.scoped(&scope).expect("the scope's store");
    scoped.insert(session("tag-b"));
    let mut dispatcher = super::test_dispatcher::test_dispatcher_with_script(SCRIPT);
    dispatcher.state.rtpengine_sessions = Some(Arc::clone(&store));
    let state = Arc::new(dispatcher.state);
    let (events, receiver) = tokio::sync::mpsc::channel(8);
    spawn_rtpengine_events(&state, receiver);
    let event = |call_id: &str, from_tag: &str| WsSplitStarted {
        call_id: call_id.to_string(),
        from_tag: from_tag.to_string(),
        stream_id: "split-shared".to_string(),
        ws_uri: "wss://bot.example.net/call".to_string(),
        sample_rate: 16_000,
    };
    let end = |call_id: &str, from_tag: &str, reason: &str| WsSplitEnded {
        call_id: call_id.to_string(),
        from_tag: from_tag.to_string(),
        stream_id: "split-shared".to_string(),
        reason: reason.to_string(),
    };
    let flags = || {
        (
            store
                .get("shared@example.com")
                .expect("unscoped")
                .ws_split_attached,
            scoped
                .get("shared@example.com")
                .expect("scoped")
                .ws_split_attached,
        )
    };
    let mut handled = 0;
    for (sent, expected) in [
        (
            RtpEngineEvent::WsSplitStarted(event("shared@example.com", "tag-a")),
            (true, false),
        ),
        (
            RtpEngineEvent::WsSplitStarted(event("shared@example.com;out", "tag-b")),
            (true, true),
        ),
        (
            RtpEngineEvent::WsSplitEnded(end("shared@example.com;out", "tag-b", "detached")),
            (true, false),
        ),
    ] {
        events.send(sent).await.expect("the event loop is running");
        handled += 1;
        for _ in 0..200 {
            if flags() == expected {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(flags(), expected, "after event {handled}");
    }
}
