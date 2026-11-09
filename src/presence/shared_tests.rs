//! Two presence stores over one shared store: a subscription made on one node
//! is seen and notified from another, with one CSeq sequence and one sender per
//! notification.
//!
//! The shared store is in memory behind a handle both nodes hold;
//! `persist_redis_tests` runs the same scenario on Redis when
//! `SIPHON_TEST_REDIS_URL` is set.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::future::BoxFuture;

use super::persist::{spawn_presence_writer, PresenceWrite, StoredSubscription};
use super::shared::{Counter, SharedPresence, SharedSubscriptions};
use super::*;
use crate::registrar::backend::coalesce::WriteSink;
use crate::registrar::backend::BackendError;

const AOR: &str = "sip:001010000000001@ims.example.invalid";

/// What Redis would hold, in memory.
#[derive(Clone, Default, Debug)]
pub(crate) struct MemoryShared {
    subscriptions: Arc<Mutex<BTreeMap<String, String>>>,
    counters: Arc<Mutex<HashMap<(String, &'static str), u32>>>,
    claims: Arc<Mutex<HashSet<(String, String)>>>,
    /// How long a write takes to land, and a read to come back (with what the
    /// store held when it began).
    write_delay: Duration,
    read_delay: Duration,
}

impl MemoryShared {
    fn all(&self) -> Vec<StoredSubscription> {
        self.subscriptions
            .lock()
            .expect("subscriptions")
            .values()
            .filter_map(|json| serde_json::from_str(json).ok())
            .collect()
    }
}

impl WriteSink<String, PresenceWrite> for MemoryShared {
    async fn apply_batch(
        &self,
        writes: &[(&String, &PresenceWrite)],
    ) -> Vec<Result<(), BackendError>> {
        tokio::time::sleep(self.write_delay).await;
        let mut stored = self.subscriptions.lock().expect("subscriptions");
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

impl SharedSubscriptions for MemoryShared {
    fn by_resource<'a>(
        &'a self,
        resource: &'a str,
    ) -> BoxFuture<'a, Result<Vec<StoredSubscription>, BackendError>> {
        Box::pin(async move {
            let held: Vec<StoredSubscription> = self
                .all()
                .into_iter()
                .filter(|sub| sub.resource == resource)
                .collect();
            tokio::time::sleep(self.read_delay).await;
            Ok(held)
        })
    }

    fn by_id<'a>(
        &'a self,
        id: &'a str,
    ) -> BoxFuture<'a, Result<Option<StoredSubscription>, BackendError>> {
        Box::pin(async move { Ok(self.all().into_iter().find(|sub| sub.id == id)) })
    }

    fn by_dialog<'a>(
        &'a self,
        call_id: &'a str,
        from_tag: &'a str,
    ) -> BoxFuture<'a, Result<Option<StoredSubscription>, BackendError>> {
        Box::pin(async move {
            Ok(self.all().into_iter().find(|sub| {
                sub.call_id.as_deref() == Some(call_id) && sub.from_tag.as_deref() == Some(from_tag)
            }))
        })
    }

    fn next_counter<'a>(
        &'a self,
        id: &'a str,
        counter: Counter,
        floor: u32,
        _ttl_secs: u64,
    ) -> BoxFuture<'a, Result<u32, BackendError>> {
        Box::pin(async move {
            let name = match counter {
                Counter::Cseq => "cseq",
                Counter::Version => "ver",
            };
            let mut counters = self.counters.lock().expect("counters");
            let next = counters.entry((id.to_string(), name)).or_insert(0);
            let number = (*next).max(floor);
            *next = number + 1;
            Ok(number)
        })
    }

    fn claim<'a>(
        &'a self,
        id: &'a str,
        marker: &'a str,
    ) -> BoxFuture<'a, Result<bool, BackendError>> {
        Box::pin(async move {
            Ok(self
                .claims
                .lock()
                .expect("claims")
                .insert((id.to_string(), marker.to_string())))
        })
    }
}

fn node(shared: &MemoryShared, freshness_ms: u64) -> Arc<PresenceStore> {
    let store = Arc::new(PresenceStore::new());
    store.set_backend_writer(spawn_presence_writer(shared.clone(), 30));
    store.set_shared(SharedPresence::new(
        Arc::new(shared.clone()),
        Duration::from_millis(freshness_ms),
        30,
    ));
    store
}

fn dialog(id: &str, call_id: &str, expires_secs: u64) -> Subscription {
    Subscription::with_dialog(
        id.to_string(),
        "sip:watcher@192.0.2.7:5060".to_string(),
        AOR.to_string(),
        "reg".to_string(),
        Duration::from_secs(expires_secs),
        vec![],
        call_id.to_string(),
        "ftag".to_string(),
        "notifier".to_string(),
        vec!["<sip:edge.example.invalid;lr>".to_string()],
        Some(AOR.to_string()),
        Some(AOR.to_string()),
    )
}

async fn settled(store: &PresenceStore, id: &str) {
    for _ in 0..200 {
        if !store.write_unsettled(id) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the write-through never reached the store");
}

/// What a notifier does on a change it is told of: send a NOTIFY to each
/// watcher it wins the claim for. Returns `(subscription, cseq)` per NOTIFY.
fn react(store: &PresenceStore, change: &str) -> Vec<(String, u32)> {
    store
        .subscriptions_for(AOR)
        .into_iter()
        .filter(|subscription| store.claim_notification(&subscription.id, change))
        .filter_map(|subscription| {
            store
                .prepare_notify(&subscription.id)
                .map(|prepared| (subscription.id, prepared.cseq))
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_subscription_made_on_one_node_is_found_on_another() {
    let shared = MemoryShared::default();
    let (a, b) = (node(&shared, 1000), node(&shared, 1000));
    assert!(b.subscriptions_for(AOR).is_empty());
    tokio::time::sleep(Duration::from_millis(1100)).await;

    a.add_subscription(dialog("sub-1", "call-1", 600));
    settled(&a, "sub-1").await;

    assert_eq!(b.subscriptions_for(AOR).len(), 1);
    assert!(b.get_subscription("sub-1").is_some());
    assert_eq!(
        b.find_subscription_by_dialog("call-1", "ftag").as_deref(),
        Some("sub-1")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_subscription_ended_on_one_node_disappears_from_another_within_the_window() {
    let shared = MemoryShared::default();
    let (a, b) = (node(&shared, 100), node(&shared, 100));
    a.add_subscription(dialog("sub-1", "call-1", 600));
    settled(&a, "sub-1").await;
    assert_eq!(b.subscriptions_for(AOR).len(), 1);

    a.remove_subscription("sub-1");
    settled(&a, "sub-1").await;
    assert_eq!(
        b.subscriptions_for(AOR).len(),
        1,
        "cached inside the window"
    );
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(b.subscriptions_for(AOR).is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_node_refreshes_and_notifies_a_subscription_another_node_created() {
    let shared = MemoryShared::default();
    let (a, b) = (node(&shared, 1000), node(&shared, 1000));
    a.add_subscription(dialog("sub-1", "call-1", 600));
    settled(&a, "sub-1").await;

    assert!(b.refresh_subscription("sub-1", Duration::from_secs(900)));
    settled(&b, "sub-1").await;
    let prepared = b.prepare_notify("sub-1").expect("a dialog to notify in");
    assert_eq!(prepared.call_id, "call-1");
    assert_eq!(prepared.from_tag, "ftag");
    assert_eq!(prepared.to_tag, "notifier");
    assert_eq!(prepared.route_set, vec!["<sip:edge.example.invalid;lr>"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cseq_and_version_are_one_sequence_across_nodes() {
    let shared = MemoryShared::default();
    let (a, b) = (node(&shared, 1000), node(&shared, 1000));
    a.add_subscription(dialog("sub-1", "call-1", 600));
    settled(&a, "sub-1").await;

    let mut cseqs = Vec::new();
    let mut versions = Vec::new();
    for round in 0..6 {
        let node = if round % 2 == 0 { &a } else { &b };
        cseqs.push(node.prepare_notify("sub-1").expect("dialog").cseq);
        versions.push(node.next_version("sub-1").expect("version"));
    }
    assert_eq!(cseqs, vec![1, 2, 3, 4, 5, 6]);
    assert_eq!(versions, vec![0, 1, 2, 3, 4, 5]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_notification_is_claimed_by_one_node() {
    let shared = MemoryShared::default();
    let (a, b) = (node(&shared, 1000), node(&shared, 1000));
    assert!(a.claim_notification("sub-1", "change-1"));
    assert!(!b.claim_notification("sub-1", "change-1"));
    assert!(b.claim_notification("sub-1", "change-2"));
    assert!(b.claim_notification("sub-2", "change-1"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_change_on_one_node_notifies_a_subscription_made_on_another_exactly_once() {
    let shared = MemoryShared::default();
    let (a, b) = (node(&shared, 50), node(&shared, 50));
    // Watchers subscribe on b; the registration changes are told to both
    // nodes (each reacts), and each NOTIFY must go out once.
    b.add_subscription(dialog("sub-1", "call-1", 600));
    let mut second = dialog("sub-2", "call-2", 600);
    second.subscriber = "sip:other@192.0.2.8:5060".to_string();
    b.add_subscription(second);
    settled(&b, "sub-1").await;
    settled(&b, "sub-2").await;

    let mut sent: Vec<(String, u32)> = Vec::new();
    for change in ["change-1", "change-2", "change-3"] {
        sent.extend(react(&a, change));
        sent.extend(react(&b, change));
        tokio::time::sleep(Duration::from_millis(80)).await;
    }

    for id in ["sub-1", "sub-2"] {
        let cseqs: Vec<u32> = sent
            .iter()
            .filter(|(sub, _)| sub == id)
            .map(|(_, cseq)| *cseq)
            .collect();
        assert_eq!(
            cseqs,
            vec![1, 2, 3],
            "one NOTIFY per change, CSeq rising, for {id}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_sweep_keeps_a_subscription_another_node_refreshed() {
    let shared = MemoryShared::default();
    let (a, b) = (node(&shared, 1000), node(&shared, 1000));
    a.add_subscription(dialog("sub-1", "call-1", 2));
    settled(&a, "sub-1").await;
    assert_eq!(b.subscriptions_for(AOR).len(), 1, "b holds it");

    assert!(a.refresh_subscription("sub-1", Duration::from_secs(600)));
    settled(&a, "sub-1").await;
    tokio::time::sleep(Duration::from_millis(2300)).await;

    b.expire_stale();
    assert!(
        b.get_subscription("sub-1").is_some(),
        "the refreshed subscription survives b's sweep"
    );
    assert!(shared.all().iter().any(|sub| sub.id == "sub-1"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_a_shared_store_a_node_sees_only_its_own_subscriptions() {
    let shared = MemoryShared::default();
    let a = node(&shared, 1000);
    let b = Arc::new(PresenceStore::new());
    b.set_backend_writer(spawn_presence_writer(shared.clone(), 30));
    a.add_subscription(dialog("sub-1", "call-1", 600));
    settled(&a, "sub-1").await;
    assert!(b.subscriptions_for(AOR).is_empty());
    assert!(b.find_subscription_by_dialog("call-1", "ftag").is_none());
    assert!(b.claim_notification("sub-1", "change-1"));
    assert!(
        b.claim_notification("sub-1", "change-1"),
        "no store, no claim"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_node_keeps_its_own_unwritten_subscription_over_the_store() {
    let shared = MemoryShared::default();
    let a = node(&shared, 0);
    a.add_subscription(dialog("sub-1", "call-1", 600));
    // Straight away: the store may not have it yet, the node has.
    assert_eq!(a.subscriptions_for(AOR).len(), 1);
    settled(&a, "sub-1").await;
    assert_eq!(a.subscriptions_for(AOR).len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_read_that_began_before_the_nodes_write_landed_does_not_erase_it() {
    let shared = MemoryShared {
        write_delay: Duration::from_millis(100),
        read_delay: Duration::from_millis(300),
        ..MemoryShared::default()
    };
    let a = node(&shared, 0);
    a.add_subscription(dialog("sub-1", "call-1", 600));
    let reader = {
        let a = Arc::clone(&a);
        tokio::task::spawn_blocking(move || a.subscriptions_for(AOR).len())
    };
    tokio::time::sleep(Duration::from_millis(50)).await;
    settled(&a, "sub-1").await;
    let _ = reader.await;
    assert!(
        a.subscriptions.contains_key("sub-1"),
        "the read erased the subscription"
    );
}
