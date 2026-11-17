//! A subscription ends when its duration runs out (RFC 6665 §4.2.1.4), in the
//! L2 cache as in the local store: its key expires with it, an expired one is
//! never read back, and the sweep takes the key along with the local entry.

use std::sync::Arc;

use super::l2::recording::Recording;
use super::{unix_now, SubscribeDialog, SubscribeStore};

const RESOURCE: &str = "sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org";

/// A notifier-side dialog granted `expires_secs`, `age_secs` ago.
fn dialog(id: &str, expires_secs: u64, age_secs: u64) -> SubscribeDialog {
    SubscribeDialog {
        id: id.to_string(),
        call_id: format!("{id}@example.com"),
        local_tag: "notifier".to_string(),
        remote_tag: "watcher".to_string(),
        local_uri: RESOURCE.to_string(),
        remote_uri: "sip:watcher@example.com".to_string(),
        remote_target: "sip:watcher@192.0.2.20:5060".to_string(),
        received_address: None,
        received_transport: None,
        received_connection_id: None,
        route_set: Vec::new(),
        event: "reg".to_string(),
        expires_secs,
        created_at_unix: unix_now() - age_secs,
        cseq: 3,
        event_version: 0,
        terminated: false,
        is_outbound: false,
        registrant_flow: None,
        body: None,
        local_contact: None,
        generation: 0,
    }
}

fn store() -> (Arc<SubscribeStore>, Arc<Recording>) {
    let (store, cache) = SubscribeStore::new().with_recording_cache();
    (Arc::new(store), cache)
}

/// Let the write-throughs spawned so far run. They do not suspend, so one
/// turn of the single-threaded test runtime each is enough.
async fn settled() {
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
}

/// What another replica, or this node before a restart, left in the cache.
fn seed(cache: &Recording, dialog: &SubscribeDialog, ttl_secs: u64) {
    let json = serde_json::to_string(dialog).expect("the dialog serialises");
    cache.seed(&dialog.id, &json, ttl_secs);
}

/// The second boundary may pass between building the dialog and writing it.
fn assert_ttl(cache: &Recording, id: &str, expected: u64) {
    let ttl = cache.ttl_of(id).expect("the key is stored");
    assert!(
        ttl == expected || ttl + 1 == expected,
        "the key of {id} expires in {ttl} s, expected {expected} s"
    );
}

#[tokio::test]
async fn a_new_dialog_is_stored_for_what_is_left_of_its_duration() {
    let (store, cache) = store();
    store.put(dialog("fresh", 3600, 0));
    store.put(dialog("old", 3600, 3500));
    settled().await;

    assert_ttl(&cache, "fresh", 3600);
    assert_ttl(&cache, "old", 100);
}

/// The write a NOTIFY makes (the CSeq bump) must not buy the key another
/// full period: that is what kept a subscription nobody refreshed alive.
#[tokio::test]
async fn an_update_does_not_renew_the_expiry_of_the_key() {
    let (store, cache) = store();
    store.put(dialog("watched", 3600, 3500));
    settled().await;

    for _ in 0..5 {
        store
            .update("watched", |dialog| {
                dialog.next_cseq();
            })
            .expect("the dialog is there");
    }
    settled().await;

    assert_ttl(&cache, "watched", 100);
    assert_eq!(
        store.get_local("watched").map(|dialog| dialog.cseq),
        Some(8)
    );
}

/// A SUBSCRIBE refresh is what does extend it.
#[tokio::test]
async fn a_refresh_stores_the_key_for_the_new_duration() {
    let (store, cache) = store();
    store.put(dialog("watched", 3600, 3500));
    store.update("watched", |dialog| dialog.refresh(600));
    settled().await;

    assert_ttl(&cache, "watched", 600);
}

/// A dialog with nothing left has no key. The local entry stays for the
/// sweep, which sends the terminating NOTIFY from it.
#[tokio::test]
async fn a_write_of_an_expired_dialog_deletes_its_key() {
    let (store, cache) = store();
    store.put(dialog("lapsed", 3600, 3500));
    settled().await;
    assert_eq!(cache.key_count(), 1);

    store.update("lapsed", |dialog| {
        dialog.created_at_unix -= 200;
        dialog.next_cseq();
    });
    settled().await;
    assert_eq!(cache.key_count(), 0, "an expired dialog is not stored");
    assert_eq!(store.local_count(), 1, "the sweep still has it to notify");

    // Put as expired (a SUBSCRIBE with Expires: 0 accepted for one NOTIFY):
    // nothing is stored, and a key left from before goes.
    seed(&cache, &dialog("fetch", 3600, 0), 3600);
    store.put(dialog("fetch", 0, 0));
    settled().await;
    assert_eq!(cache.ttl_of("fetch"), None);
}

#[tokio::test]
async fn an_expired_dialog_in_the_cache_is_deleted_and_not_read_back() {
    let (store, cache) = store();
    // Left behind with a whole period still on the key.
    seed(&cache, &dialog("leaked", 3600, 30 * 86_400), 3600);
    seed(&cache, &dialog("live", 3600, 60), 3540);

    assert!(store.get("leaked").await.is_none());
    assert_eq!(cache.ttl_of("leaked"), None, "the expired key is deleted");
    assert_eq!(store.local_count(), 0, "and nothing was read into L1");

    assert!(store.get("live").await.is_some());
    assert_eq!(cache.ttl_of("live"), Some(3540));
    assert_eq!(store.local_count(), 1);
}

#[tokio::test]
async fn the_sweep_deletes_the_keys_of_the_dialogs_it_reaps() {
    let (store, cache) = store();
    store.put(dialog("live", 3600, 0));
    settled().await;
    // Expired and terminated dialogs whose keys are still in the cache.
    let expired = dialog("expired", 3600, 4000);
    let mut terminated = dialog("terminated", 3600, 0);
    terminated.terminated = true;
    for stale in [expired, terminated] {
        seed(&cache, &stale, 3600);
        store.dialogs.insert(stale.id.clone(), stale);
    }
    assert_eq!(cache.key_count(), 3);

    let mut reaped: Vec<String> = store
        .take_stale()
        .into_iter()
        .map(|dialog| dialog.id)
        .collect();
    reaped.sort();
    settled().await;

    assert_eq!(reaped, ["expired", "terminated"]);
    assert_eq!(cache.ttl_of("expired"), None);
    assert_eq!(cache.ttl_of("terminated"), None);
    assert_eq!(cache.key_count(), 1, "the live dialog keeps its key");
    assert_eq!(store.local_count(), 1);
}

/// A subscriber that never refreshes: once its duration is over the sweep
/// reaps it (one snapshot, for the terminating NOTIFY), and a state change of
/// the resource after that finds nobody to notify and no key left.
#[tokio::test]
async fn a_subscription_nobody_refreshes_is_gone_after_its_expiry() {
    let (store, cache) = store();
    let subscription = dialog("abandoned", 3600, 0);
    store.put(subscription.clone());
    settled().await;
    assert_eq!(store.for_resource(RESOURCE, "reg").len(), 1);

    // An hour on, with the NOTIFYs of the state changes in between.
    store.update("abandoned", |dialog| {
        dialog.created_at_unix -= 3601;
        dialog.next_cseq();
    });
    let reaped = store.take_stale();
    settled().await;
    assert_eq!(reaped.len(), 1, "one terminating NOTIFY is owed");
    assert_eq!(reaped[0].id, "abandoned");

    // The resource changes state: who is there to notify?
    assert!(store.for_resource(RESOURCE, "reg").is_empty());
    assert!(store.get("abandoned").await.is_none());
    assert!(store.get_local("abandoned").is_none());
    assert_eq!(store.local_count(), 0);
    assert_eq!(cache.key_count(), 0);
    assert!(store.take_stale().is_empty(), "nothing is reaped twice");
}

/// The same from the other side of a restart: only the cache remembers the
/// dialog, and the script that kept its id asks for it on a state change.
#[tokio::test]
async fn a_leaked_key_dies_on_the_first_lookup_after_its_expiry() {
    let (store, cache) = store();
    for index in 0..300 {
        seed(
            &cache,
            &dialog(&format!("leaked-{index}"), 3600, 3600 + index),
            3600,
        );
    }

    let mut notified = 0;
    for index in 0..300 {
        if store.get(&format!("leaked-{index}")).await.is_some() {
            notified += 1;
        }
    }

    assert_eq!(notified, 0, "no expired subscription is notified");
    assert_eq!(cache.key_count(), 0);
    assert_eq!(store.local_count(), 0);
    assert!(store.take_stale().is_empty());
}

/// Dialogs come and go: the local store and the cache both drain back to
/// empty, whether a dialog ended by removal, by expiry or by a failed NOTIFY.
#[tokio::test]
async fn the_store_and_the_cache_drain_to_empty() {
    let (store, cache) = store();
    for round in 0..50 {
        for index in 0..30 {
            store.put(dialog(&format!("{round}-{index}"), 3600, 0));
        }
        settled().await;
        assert_eq!(cache.key_count(), 30);
        for index in 0..30 {
            let id = format!("{round}-{index}");
            match index % 3 {
                0 => store.remove(&id),
                1 => {
                    store.update(&id, |dialog| dialog.created_at_unix -= 3601);
                }
                _ => {
                    let generation = store
                        .get_local(&id)
                        .map(|dialog| dialog.generation)
                        .expect("the dialog is there");
                    assert!(store.notify_ended(&id, generation, Some(481)));
                }
            }
        }
        assert_eq!(store.take_stale().len(), 10);
        settled().await;
        assert_eq!(store.local_count(), 0);
        assert_eq!(cache.key_count(), 0);
    }
}

/// RFC 6665 §4.2.2 on the store: which ends of a NOTIFY remove the
/// subscription, from the local store and the cache.
#[tokio::test]
async fn a_failed_notify_removes_the_dialog_and_its_key() {
    crate::metrics::init().expect("metrics");
    let failures =
        |outcome| crate::metrics::subscribe_notify::failures(outcome).expect("the metrics are up");

    for (outcome, removed) in [
        (Some(200), false),
        (Some(202), false),
        (Some(481), true),
        (Some(408), true),
        (None, true),
        (Some(404), true),
        (Some(489), true),
        (Some(604), true),
        // Not named by §4.2.2: a complaint about the transaction only.
        (Some(401), false),
        (Some(500), false),
        (Some(503), false),
    ] {
        let (store, cache) = store();
        let subscription = dialog("watched", 3600, 10);
        let generation = subscription.generation;
        store.put(subscription);
        settled().await;
        let before = failures(outcome);

        assert_eq!(
            store.notify_ended("watched", generation, outcome),
            removed,
            "{outcome:?}"
        );
        settled().await;

        assert_eq!(store.get_local("watched").is_none(), removed, "{outcome:?}");
        assert_eq!(cache.ttl_of("watched").is_none(), removed, "{outcome:?}");
        assert_eq!(store.get("watched").await.is_none(), removed, "{outcome:?}");
        let failed = !matches!(outcome, Some(200..=299));
        assert_eq!(
            failures(outcome) > before,
            failed,
            "a failed NOTIFY is counted by code, a 2xx is not: {outcome:?}"
        );
    }
}

/// A refresh that landed while the NOTIFY was out proves the subscriber holds
/// the dialog, however soon after the NOTIFY it came (here within the same
/// second, twice); and a subscription this node made as the subscriber is not
/// the notifier's to remove.
#[tokio::test]
async fn a_late_failure_leaves_a_refreshed_or_outbound_dialog_alone() {
    let (store, cache) = store();
    let subscription = dialog("refreshed", 3600, 0);
    let sent_under = subscription.generation;
    store.put(subscription);
    for _ in 0..2 {
        store.update("refreshed", |dialog| dialog.refresh(3600));
        assert!(!store.notify_ended("refreshed", sent_under, Some(481)));
        assert!(store.get_local("refreshed").is_some());
    }
    let refreshed = store
        .get_local("refreshed")
        .expect("the dialog is there")
        .generation;
    assert_eq!(refreshed, sent_under + 2);

    let mut outbound = dialog("outbound", 3600, 10);
    outbound.is_outbound = true;
    let generation = outbound.generation;
    store.put(outbound);
    assert!(!store.notify_ended("outbound", generation, Some(481)));
    assert!(store.get_local("outbound").is_some());

    // An id that is already gone stays a no-op.
    assert!(!store.notify_ended("never-existed", 0, None));
    settled().await;
    assert_eq!(cache.key_count(), 2);
}
