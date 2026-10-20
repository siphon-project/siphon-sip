//! A registration consumer that falls behind its broadcast keeps delivering,
//! counts the loss, and is re-told the current state.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{broadcast, Notify};

use super::*;
use crate::metrics::event_lag::{lagged, LaggedConsumer};
use crate::registrant::{RegistrantCredentials, RegistrantEntry};
use crate::sip::uri::SipUri;
use crate::transport::Transport;

/// More than the registrar's broadcast holds (1024), so a consumer parked on
/// its first event lags.
const STORM: usize = 1100;

fn save(registrar: &Registrar, user: &str) {
    registrar
        .save(
            &format!("sip:{user}@example.com"),
            SipUri::new("192.0.2.10".to_string()).with_user(user.to_string()),
            3600,
            1.0,
            format!("call-{user}"),
            1,
        )
        .expect("saved");
}

/// Wait until `seen` holds an entry `matches` accepts, or fail.
async fn wait_for<T: Clone>(seen: &Mutex<Vec<T>>, matches: impl Fn(&T) -> bool) {
    for _ in 0..500 {
        if seen
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .iter()
            .any(&matches)
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the delivery never arrived");
}

/// A delivery sink whose first delivery blocks until `gate` is released — the
/// slow `@registrar.on_change` handler of a registration storm.
fn slow_sink<T: Clone + Send + 'static>(
    seen: Arc<Mutex<Vec<T>>>,
    gate: Arc<Notify>,
) -> impl FnMut(T) -> std::pin::Pin<Box<dyn Future<Output = ()> + Send>> {
    let mut first = true;
    move |change: T| {
        let seen = Arc::clone(&seen);
        let gate = Arc::clone(&gate);
        let block = std::mem::replace(&mut first, false);
        Box::pin(async move {
            if block {
                gate.notified().await;
            }
            seen.lock()
                .unwrap_or_else(|error| error.into_inner())
                .push(change);
        })
    }
}

#[tokio::test]
async fn a_registrar_lag_is_counted_snapshotted_and_survived() {
    crate::metrics::init().expect("the metrics build");
    let registrar = Arc::new(Registrar::default());
    let seen = Arc::new(Mutex::new(Vec::<RegistrarChange>::new()));
    let gate = Arc::new(Notify::new());
    let task = tokio::spawn(drain_registrar_events(
        registrar.subscribe_events(),
        Arc::clone(&registrar),
        slow_sink(Arc::clone(&seen), Arc::clone(&gate)),
    ));

    // The first event parks the consumer; the storm behind it overruns the
    // channel.
    save(&registrar, "first");
    tokio::time::sleep(Duration::from_millis(20)).await;
    let lagged_before = lagged(LaggedConsumer::Registrar);
    for index in 0..STORM {
        save(&registrar, &format!("storm{index}"));
    }
    gate.notify_one();

    // Every AoR the registrar holds is re-told as a snapshot.
    wait_for(&seen, |change: &RegistrarChange| {
        change.is_snapshot() && change.aor == format!("sip:storm{}@example.com", STORM - 1)
    })
    .await;
    let snapshot: std::collections::HashSet<String> = seen
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .iter()
        .filter(|change| change.is_snapshot())
        .map(|change| change.aor.clone())
        .collect();
    assert_eq!(
        snapshot.len(),
        STORM + 1,
        "one snapshot delivery per held AoR"
    );
    for aor in registrar.registered_aors() {
        assert!(snapshot.contains(&aor), "{aor} was not re-told");
    }
    assert!(
        lagged(LaggedConsumer::Registrar) > lagged_before,
        "the lost events are counted"
    );

    // The task is still alive: a change after the lag is delivered as one.
    save(&registrar, "after");
    wait_for(&seen, |change: &RegistrarChange| {
        change.aor == "sip:after@example.com" && change.event == "registered"
    })
    .await;
    assert!(!task.is_finished(), "a lag does not end the event task");
    task.abort();
}

#[tokio::test]
async fn a_registrar_snapshot_delivers_after_the_events_still_held() {
    // The events that survived the lag are still delivered after the
    // snapshot, so a removal among them still reaches the consumer.
    let registrar = Arc::new(Registrar::default());
    let seen = Arc::new(Mutex::new(Vec::<RegistrarChange>::new()));
    let gate = Arc::new(Notify::new());
    let task = tokio::spawn(drain_registrar_events(
        registrar.subscribe_events(),
        Arc::clone(&registrar),
        slow_sink(Arc::clone(&seen), Arc::clone(&gate)),
    ));
    save(&registrar, "first");
    tokio::time::sleep(Duration::from_millis(20)).await;
    for index in 0..STORM {
        save(&registrar, &format!("storm{index}"));
    }
    registrar.remove_all("sip:storm0@example.com");
    gate.notify_one();

    wait_for(&seen, |change: &RegistrarChange| {
        change.aor == "sip:storm0@example.com" && change.event == "deregistered"
    })
    .await;
    let seen = seen.lock().unwrap_or_else(|error| error.into_inner());
    assert!(
        !seen
            .iter()
            .any(|change| change.is_snapshot() && change.aor == "sip:storm0@example.com"),
        "an AoR with no binding left is not in the snapshot"
    );
    task.abort();
}

#[tokio::test]
async fn the_registrar_loop_ends_only_when_the_channel_closes() {
    let registrar = Arc::new(Registrar::default());
    let (sender, receiver) = broadcast::channel(4);
    let seen = Arc::new(Mutex::new(Vec::<RegistrarChange>::new()));
    let sink = Arc::clone(&seen);
    let task = tokio::spawn(drain_registrar_events(receiver, registrar, move |change| {
        sink.lock()
            .unwrap_or_else(|error| error.into_inner())
            .push(change);
        std::future::ready(())
    }));
    sender
        .send(RegistrationEvent::Expired {
            aor: "sip:gone@example.com".to_string(),
        })
        .expect("a receiver is listening");
    drop(sender);
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("the loop ends on close")
        .expect("the loop did not panic");
    assert_eq!(
        *seen.lock().unwrap_or_else(|error| error.into_inner()),
        vec![RegistrarChange {
            aor: "sip:gone@example.com".to_string(),
            event: "expired",
        }]
    );
}

fn registrant_manager() -> RegistrantManager {
    RegistrantManager::new(
        3600,
        Duration::from_secs(60),
        Duration::from_secs(300),
        crate::config::IdentityHeaders {
            server: None,
            user_agent: None,
        }
        .shared(),
    )
}

fn registrant_entry(aor: &str) -> RegistrantEntry {
    RegistrantEntry::new(
        aor.to_string(),
        "sip:registrar.example.net".to_string(),
        "192.0.2.20:5060".parse().expect("an address"),
        Transport::Udp,
        RegistrantCredentials::password("trunk".to_string(), "secret".to_string(), None),
        3600,
        None,
    )
}

#[tokio::test]
async fn a_registrant_lag_is_counted_snapshotted_and_survived() {
    crate::metrics::init().expect("the metrics build");
    let registrant = Arc::new(registrant_manager());
    registrant.add(registrant_entry("sip:trunk-a@example.net"));
    registrant.add(registrant_entry("sip:trunk-b@example.net"));
    let seen = Arc::new(Mutex::new(Vec::<RegistrantChange>::new()));
    let gate = Arc::new(Notify::new());
    let task = tokio::spawn(drain_registrant_events(
        registrant.subscribe_events(),
        Arc::clone(&registrant),
        slow_sink(Arc::clone(&seen), Arc::clone(&gate)),
    ));

    registrant.handle_success("sip:trunk-a@example.net", 3600);
    tokio::time::sleep(Duration::from_millis(20)).await;
    let lagged_before = lagged(LaggedConsumer::Registrant);
    // The registrant's channel holds 64.
    for _ in 0..100 {
        registrant.handle_success("sip:trunk-a@example.net", 3600);
    }
    gate.notify_one();

    wait_for(&seen, |change: &RegistrantChange| {
        change.event == SNAPSHOT && change.aor == "sip:trunk-b@example.net"
    })
    .await;
    wait_for(&seen, |change: &RegistrantChange| {
        change.event == SNAPSHOT && change.aor == "sip:trunk-a@example.net"
    })
    .await;
    assert!(lagged(LaggedConsumer::Registrant) > lagged_before);

    registrant.handle_failure("sip:trunk-b@example.net", 503, None);
    wait_for(&seen, |change: &RegistrantChange| {
        change.aor == "sip:trunk-b@example.net"
            && change.event == "failed"
            && change.status_code == Some(503)
    })
    .await;
    assert!(!task.is_finished(), "a lag does not end the event task");
    task.abort();
}

/// What the script's handler recorded: `SEEN` in the module that defines it.
fn script_seen(
    state: &crate::dispatcher::DispatcherState,
    kind: crate::script::engine::HandlerKind,
) -> Vec<String> {
    use pyo3::types::PyAnyMethods;
    let engine_state = state.engine.state();
    let handlers = engine_state.handlers_for(&kind);
    let handler = handlers.first().expect("the script registered the handler");
    pyo3::Python::attach(|python| {
        handler
            .callable
            .bind(python)
            .getattr("__globals__")
            .and_then(|globals| globals.get_item("SEEN"))
            .and_then(|seen| seen.extract::<Vec<String>>())
            .expect("SEEN is a list of str")
    })
}

#[tokio::test]
async fn a_snapshot_reaches_the_script_and_the_control_plane_as_snapshot() {
    use crate::control::app_event_capture;
    let dispatcher = super::super::test_dispatcher::test_dispatcher_with_script(concat!(
        "from siphon import registrar\n",
        "SEEN = []\n",
        "@registrar.on_change\n",
        "def changed(aor, event, contacts):\n",
        "    SEEN.append(f\"{aor} {event} {len(contacts)}\")\n",
    ));
    let state = Arc::new(dispatcher.state);
    let registrar = Arc::clone(crate::script::api::test_registrar());
    let aor = "sip:snapshot-delivery@example.com";
    app_event_capture::watch(aor);
    registrar
        .save(
            aor,
            SipUri::new("192.0.2.30".to_string()).with_user("snapshot-delivery".to_string()),
            3600,
            1.0,
            "call-snapshot".to_string(),
            1,
        )
        .expect("saved");

    super::super::tasks::deliver_registrar_change(
        Arc::clone(&state),
        Arc::clone(&registrar),
        RegistrarChange {
            aor: aor.to_string(),
            event: SNAPSHOT,
        },
    )
    .await;

    let published = app_event_capture::take(aor);
    assert_eq!(published.len(), 1);
    assert_eq!(published[0].0, "RegistrationChanged");
    assert_eq!(published[0].1["event"], "snapshot");
    assert_eq!(published[0].1["contacts"].as_array().map(Vec::len), Some(1));
    assert_eq!(
        script_seen(
            &state,
            crate::script::engine::HandlerKind::RegistrarOnChange
        ),
        vec![format!("{aor} snapshot 1")]
    );
    registrar.remove_all(aor);
}

#[tokio::test]
async fn a_registrant_snapshot_reaches_the_script_with_its_state() {
    let dispatcher = super::super::test_dispatcher::test_dispatcher_with_script(concat!(
        "from siphon import registration\n",
        "SEEN = []\n",
        "@registration.on_change\n",
        "def changed(aor, event, state):\n",
        "    SEEN.append(f\"{aor} {event} {state['state']} {state['failure_count']}\")\n",
    ));
    let state = Arc::new(dispatcher.state);
    let registrant = Arc::new(registrant_manager());
    registrant.add(registrant_entry("sip:trunk-c@example.net"));
    registrant.handle_failure("sip:trunk-c@example.net", 403, None);

    super::super::tasks::deliver_registrant_change(
        Arc::clone(&state),
        Arc::clone(&registrant),
        RegistrantChange {
            aor: "sip:trunk-c@example.net".to_string(),
            event: SNAPSHOT,
            status_code: None,
        },
    )
    .await;

    assert_eq!(
        script_seen(
            &state,
            crate::script::engine::HandlerKind::RegistrantOnChange
        ),
        vec!["sip:trunk-c@example.net snapshot failed 1".to_string()]
    );
}
