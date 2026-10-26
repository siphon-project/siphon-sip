//! The presence store's write-through against a sink the test controls, and
//! the stored form's rebuild.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::persist::{spawn_presence_writer, PresenceWrite, StoredSubscription};
use super::*;
use crate::registrar::backend::coalesce::WriteSink;
use crate::registrar::backend::BackendError;

/// Subscriptions by id, as Redis would hold them; each batch takes `delay`
/// and fails while `down` is set.
#[derive(Clone, Default)]
struct MockSink {
    stored: Arc<Mutex<BTreeMap<String, String>>>,
    down: Arc<AtomicBool>,
    delay: Duration,
}

impl WriteSink<String, PresenceWrite> for MockSink {
    async fn apply_batch(
        &self,
        writes: &[(&String, &PresenceWrite)],
    ) -> Vec<Result<(), BackendError>> {
        tokio::time::sleep(self.delay).await;
        if self.down.load(Ordering::SeqCst) {
            return writes
                .iter()
                .map(|_| Err(BackendError::Connection("connection refused".to_string())))
                .collect();
        }
        let mut stored = self.stored.lock().expect("stored");
        for (id, write) in writes {
            match write {
                PresenceWrite::Save { json, .. } => {
                    stored.insert((*id).clone(), json.clone());
                }
                PresenceWrite::Remove => {
                    stored.remove(*id);
                }
            }
        }
        writes.iter().map(|_| Ok(())).collect()
    }
}

impl MockSink {
    fn stored(&self, id: &str) -> Option<StoredSubscription> {
        self.stored
            .lock()
            .expect("stored")
            .get(id)
            .map(|json| serde_json::from_str(json).expect("stored JSON"))
    }

    fn len(&self) -> usize {
        self.stored.lock().expect("stored").len()
    }
}

fn dialog(id: &str) -> Subscription {
    Subscription::with_dialog(
        id.to_string(),
        "sip:watcher@192.0.2.7:5060".to_string(),
        "sip:001010000000001@ims.example.com".to_string(),
        "reg".to_string(),
        Duration::from_secs(600),
        vec![],
        format!("call-{id}"),
        "ftag".to_string(),
        "notifier".to_string(),
        vec!["<sip:edge.example.com;lr>".to_string()],
        Some("sip:001010000000001@ims.example.com".to_string()),
        Some("sip:001010000000001@ims.example.com".to_string()),
    )
}

/// Wait (in paused time) until `check` holds.
async fn eventually(what: &str, check: impl Fn() -> bool) {
    for _ in 0..600 {
        if check() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("never: {what}");
}

fn store_with(sink: &MockSink) -> (PresenceStore, super::persist::PresenceBackendWriter) {
    let writer = spawn_presence_writer(sink.clone(), 30);
    let store = PresenceStore::new();
    store.set_backend_writer(writer.clone());
    (store, writer)
}

/// Every change to a subscription is written through: its dialog, the CSeq
/// of each NOTIFY, the version of each document, a refresh.
#[tokio::test(start_paused = true)]
async fn every_change_is_written_through() {
    let sink = MockSink::default();
    let (store, _writer) = store_with(&sink);
    store.add_subscription(dialog("sub-1"));
    eventually("the subscription is stored", || {
        sink.stored("sub-1").is_some()
    })
    .await;
    let stored = sink.stored("sub-1").expect("stored");
    assert_eq!(stored.call_id.as_deref(), Some("call-sub-1"));
    assert_eq!(stored.route_set, vec!["<sip:edge.example.com;lr>"]);
    assert_eq!(stored.state, "active");
    assert_eq!((stored.local_cseq, stored.next_version), (0, 0));

    store.prepare_notify("sub-1").expect("a NOTIFY");
    store.prepare_notify("sub-1").expect("a NOTIFY");
    assert_eq!(store.next_version("sub-1"), Some(0));
    assert_eq!(store.next_version("sub-1"), Some(1));
    eventually("the CSeq and version are stored", || {
        sink.stored("sub-1")
            .is_some_and(|stored| (stored.local_cseq, stored.next_version) == (2, 2))
    })
    .await;

    let before = sink.stored("sub-1").expect("stored").expires_at_unix;
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(store.refresh_subscription("sub-1", Duration::from_secs(7200)));
    eventually("the refresh is stored", || {
        sink.stored("sub-1")
            .is_some_and(|stored| stored.expires_at_unix > before + 6000)
    })
    .await;
}

/// Terminating, removing, or a failed NOTIFY's removal takes the stored copy
/// with it; removing what is already gone writes nothing.
#[tokio::test(start_paused = true)]
async fn every_removal_takes_the_stored_copy() {
    let sink = MockSink::default();
    let (store, writer) = store_with(&sink);
    for id in ["sub-term", "sub-rm", "sub-481"] {
        store.add_subscription(dialog(id));
    }
    eventually("all three are stored", || sink.len() == 3).await;

    store.terminate_subscription("sub-term");
    store.remove_subscription("sub-rm");
    let generation = store
        .prepare_notify("sub-481")
        .expect("a NOTIFY")
        .generation;
    assert!(store.remove_subscription_if_current("sub-481", generation));
    eventually("all three are gone", || sink.len() == 0).await;

    store.remove_subscription("sub-rm");
    assert!(!store.remove_subscription_if_current("sub-481", generation));
    eventually("nothing is pending", || writer.pending_writes() == 0).await;
    assert_eq!(sink.len(), 0);
}

/// A burst past any fixed queue, against a slow sink that is down for a
/// while: every subscription lands, nothing is dropped.
#[tokio::test(start_paused = true)]
async fn a_burst_through_an_outage_drops_nothing() {
    const SUBSCRIPTIONS: usize = 6_000;
    let sink = MockSink {
        delay: Duration::from_millis(5),
        ..MockSink::default()
    };
    sink.down.store(true, Ordering::SeqCst);
    let (store, writer) = store_with(&sink);
    for index in 0..SUBSCRIPTIONS {
        let id = format!("sub-{index}");
        store.add_subscription(dialog(&id));
        store.prepare_notify(&id).expect("a NOTIFY");
    }
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(sink.len(), 0, "nothing lands while the sink is down");
    sink.down.store(false, Ordering::SeqCst);
    eventually("every subscription lands", || sink.len() == SUBSCRIPTIONS).await;
    eventually("nothing is pending", || writer.pending_writes() == 0).await;
    assert!((0..SUBSCRIPTIONS).all(|index| sink
        .stored(&format!("sub-{index}"))
        .is_some_and(|stored| stored.local_cseq == 1)));
}

/// Steady state: subscribe, NOTIFY, take a version, terminate, many times.
/// The store, its watchers, the writer's pending writes and the sink all
/// return to empty.
#[tokio::test(start_paused = true)]
async fn subscribe_terminate_cycles_return_to_baseline() {
    let sink = MockSink::default();
    let (store, writer) = store_with(&sink);
    for index in 0..2_000 {
        let id = format!("cycle-{index}");
        store.add_subscription(dialog(&id));
        store.prepare_notify(&id).expect("a NOTIFY");
        store.next_version(&id).expect("a version");
        if index % 2 == 0 {
            store.terminate_subscription(&id);
            store.expire_stale();
        } else {
            store.remove_subscription(&id);
        }
    }
    assert_eq!(store.subscription_count(), 0);
    assert!(store.watchers.is_empty());
    eventually("nothing is pending", || writer.pending_writes() == 0).await;
    assert_eq!(sink.len(), 0);
}

/// A rebuilt subscription continues its dialog: the next NOTIFY carries one
/// CSeq more than the last one stored, the next document the version stored
/// as next, and the expiry is what was left.
#[test]
fn a_stored_subscription_rebuilds_where_it_stopped() {
    let mut subscription = dialog("sub-r");
    subscription.local_cseq = 41;
    subscription.next_version = 7;
    let stored = StoredSubscription::of(&subscription);
    let now = super::persist::unix_now();

    let store = PresenceStore::new();
    store.restore_subscription(stored.clone().into_subscription(now).expect("live"));
    let notify = store.prepare_notify("sub-r").expect("a NOTIFY");
    assert_eq!(notify.cseq, 42);
    assert_eq!(store.next_version("sub-r"), Some(7));
    let restored = store.get_subscription("sub-r").expect("restored");
    assert!(restored.remaining_seconds() <= 600 && restored.remaining_seconds() >= 598);
    assert_eq!(
        store
            .subscriptions_for("sip:001010000000001@ims.example.com")
            .len(),
        1,
        "listed under its resource"
    );

    // Expired by now: dropped, never resurrected.
    assert!(stored.clone().into_subscription(now + 600).is_none());
    // A terminated one is never stored, and never rebuilt if it were.
    let mut terminated = stored;
    terminated.state = "terminated".to_string();
    assert!(terminated.into_subscription(now).is_none());
}

/// Without a backend nothing is written and nothing changes.
#[test]
fn without_a_backend_the_store_stays_in_memory() {
    let store = PresenceStore::new();
    store.add_subscription(dialog("sub-mem"));
    assert_eq!(store.prepare_notify("sub-mem").expect("a NOTIFY").cseq, 1);
    store.remove_subscription("sub-mem");
    assert_eq!(store.subscription_count(), 0);
}

/// The write-through runs on the script path: `presence.subscribe_dialog`,
/// `next_version` and `unsubscribe` enqueue while attached to the
/// interpreter. From several Python threads, against a sink that is down so
/// every write stays queued, while another thread keeps forcing garbage
/// collections: an enqueue never waits, so every call returns. Runs in a
/// child process with a budget, so a regression fails instead of hanging.
#[test]
fn write_through_from_scripts_survives_forced_collections() {
    use crate::script::api::presence::PyPresence;
    use crate::script::stop_the_world_tests::{collect_garbage_until, in_child};
    use pyo3::prelude::*;

    if !in_child(
        concat!(
            module_path!(),
            "::write_through_from_scripts_survives_forced_collections"
        ),
        Duration::from_secs(60),
    ) {
        return;
    }

    pyo3::Python::initialize();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");
    let sink = MockSink::default();
    sink.down.store(true, Ordering::SeqCst);
    let store = Arc::new(PresenceStore::new());
    let writer = {
        let _entered = runtime.enter();
        spawn_presence_writer(sink.clone(), 30)
    };
    store.set_backend_writer(writer.clone());
    let presence = Python::attach(|python| {
        Py::new(python, PyPresence::new(Arc::clone(&store))).expect("namespace")
    });

    let stop = Arc::new(AtomicBool::new(false));
    let collector = collect_garbage_until(Arc::clone(&stop));
    let callers: Vec<_> = (0..4)
        .map(|thread| {
            let presence = Python::attach(|python| presence.clone_ref(python));
            std::thread::spawn(move || {
                Python::attach(|python| {
                    let presence = presence.bind(python);
                    for round in 0..250 {
                        let id: String = presence
                            .call_method1(
                                "subscribe_dialog",
                                (
                                    "sip:watcher@192.0.2.7:5060",
                                    "sip:001010000000001@ims.example.com",
                                    "reg",
                                    600,
                                    format!("gc-{thread}-{round}"),
                                    "ftag",
                                    "notifier",
                                ),
                            )
                            .and_then(|id| id.extract())
                            .expect("a subscription");
                        presence
                            .call_method1("next_version", (id.as_str(),))
                            .expect("a version");
                        if round % 2 == 0 {
                            presence
                                .call_method1("unsubscribe", (id.as_str(),))
                                .expect("unsubscribed");
                        }
                    }
                })
            })
        })
        .collect();
    for caller in callers {
        caller.join().expect("the caller ran");
    }
    stop.store(true, Ordering::SeqCst);
    collector.join().expect("the collector ran");

    assert_eq!(store.subscription_count(), 500);
    // One pending write per subscription id, counted again while the drainer
    // holds a batch of them for its retry: none dropped.
    assert!(
        writer.pending_writes() >= 1000,
        "every write is held, none dropped"
    );
    sink.down.store(false, Ordering::SeqCst);
    runtime.block_on(async {
        for _ in 0..600 {
            if sink.len() == 500 && writer.pending_writes() == 0 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("the held writes never landed");
    });
}
