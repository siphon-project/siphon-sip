//! The presence store's Redis persistence against a real Redis: a notifier
//! that restarts keeps its subscriptions.
//!
//! Run only when `SIPHON_TEST_REDIS_URL` names a server; skipped otherwise.

use std::time::Duration;

use super::persist::{restore_presence_subscriptions, spawn_presence_redis_writer};
use super::*;

const AOR: &str = "sip:001010000000001@ims.example.com";

async fn connection() -> Option<redis::aio::MultiplexedConnection> {
    let url = match std::env::var("SIPHON_TEST_REDIS_URL") {
        Ok(url) if !url.is_empty() => url,
        _ => {
            eprintln!("skipped: SIPHON_TEST_REDIS_URL is not set");
            return None;
        }
    };
    Some(
        redis::Client::open(url)
            .expect("redis url")
            .get_multiplexed_async_connection()
            .await
            .expect("connect to the test Redis"),
    )
}

fn client() -> redis::Client {
    redis::Client::open(std::env::var("SIPHON_TEST_REDIS_URL").expect("url")).expect("redis url")
}

fn unique_prefix(test: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!(
        "siphon-test:presence:{test}:{}:{nanos}:",
        std::process::id()
    )
}

fn dialog(id: &str, expires: Duration) -> Subscription {
    Subscription::with_dialog(
        id.to_string(),
        "sip:watcher@192.0.2.7:5060".to_string(),
        AOR.to_string(),
        "reg".to_string(),
        expires,
        vec![],
        format!("call-{id}"),
        "ftag".to_string(),
        "notifier".to_string(),
        vec!["<sip:edge.example.com;lr>".to_string()],
        Some(AOR.to_string()),
        Some(AOR.to_string()),
    )
}

/// A notifier process: a store writing through to Redis under `prefix`,
/// restored from it first.
async fn notifier(prefix: &str) -> (PresenceStore, persist::RestoreCounts) {
    let store = PresenceStore::new();
    let mut connection = client()
        .get_multiplexed_async_connection()
        .await
        .expect("connect");
    let (counts, dropped) = restore_presence_subscriptions(&mut connection, prefix, &store)
        .await
        .expect("restore");
    let writer = spawn_presence_redis_writer(client(), connection, prefix.to_string(), 30);
    for id in dropped {
        writer.remove_at(&id, writer.sequence());
    }
    store.set_backend_writer(writer);
    (store, counts)
}

async fn keys(connection: &mut redis::aio::MultiplexedConnection, prefix: &str) -> Vec<String> {
    let mut keys: Vec<String> = redis::cmd("KEYS")
        .arg(format!("{prefix}*"))
        .query_async(connection)
        .await
        .expect("keys");
    keys.sort();
    keys
}

/// Wait until Redis holds exactly `expected` under `prefix`.
async fn redis_holds(
    connection: &mut redis::aio::MultiplexedConnection,
    prefix: &str,
    expected: &[&str],
) {
    let expected: Vec<String> = expected.iter().map(|id| format!("{prefix}{id}")).collect();
    for _ in 0..100 {
        if keys(connection, prefix).await == expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(keys(connection, prefix).await, expected);
}

/// Subscribe, NOTIFY twice, restart: the restarted notifier lists the
/// subscription under its resource, and its next NOTIFY carries one CSeq
/// more than the last one sent before the restart and the next version.
#[tokio::test]
async fn a_restarted_notifier_continues_each_dialog() {
    let Some(mut connection) = connection().await else {
        return;
    };
    let prefix = unique_prefix("continue");
    {
        let (before, counts) = notifier(&prefix).await;
        assert_eq!(counts.restored, 0);
        before.add_subscription(dialog("sub-1", Duration::from_secs(600)));
        for _ in 0..2 {
            before.prepare_notify("sub-1").expect("a NOTIFY");
            before.next_version("sub-1").expect("a version");
        }
        redis_holds(&mut connection, &prefix, &["sub-1"]).await;
        // The last CSeq and version reach Redis.
        for _ in 0..100 {
            let json: String = redis::cmd("GET")
                .arg(format!("{prefix}sub-1"))
                .query_async(&mut connection)
                .await
                .expect("get");
            let stored: persist::StoredSubscription = serde_json::from_str(&json).expect("json");
            if (stored.local_cseq, stored.next_version) == (2, 2) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    let (after, counts) = notifier(&prefix).await;
    assert_eq!(counts.restored, 1);
    let listed = after.subscriptions_for(AOR);
    assert_eq!(listed.len(), 1, "the watcher is listed after the restart");
    assert_eq!(listed[0].call_id.as_deref(), Some("call-sub-1"));
    let notify = after.prepare_notify("sub-1").expect("a NOTIFY");
    assert_eq!(notify.cseq, 3, "CSeq continues above the last one sent");
    assert_eq!(notify.route_set, vec!["<sip:edge.example.com;lr>"]);
    assert_eq!(notify.from_tag, "ftag");
    assert_eq!(notify.to_tag, "notifier");
    assert_eq!(
        after.next_version("sub-1"),
        Some(2),
        "the version continues"
    );

    // Terminated after the restart: the stored copy goes too.
    after.terminate_subscription("sub-1");
    redis_holds(&mut connection, &prefix, &[]).await;
}

/// A subscription that expired while the notifier was down is dropped at the
/// restore and its key deleted, not resurrected; a live one stays, and its
/// key's TTL is what it has left plus the slack.
#[tokio::test]
async fn an_expired_subscription_is_dropped_at_the_restore() {
    let Some(mut connection) = connection().await else {
        return;
    };
    let prefix = unique_prefix("expiry");
    {
        let (before, _) = notifier(&prefix).await;
        before.add_subscription(dialog("short", Duration::from_secs(1)));
        before.add_subscription(dialog("long", Duration::from_secs(600)));
        redis_holds(&mut connection, &prefix, &["long", "short"]).await;
    }
    let ttl: i64 = redis::cmd("TTL")
        .arg(format!("{prefix}long"))
        .query_async(&mut connection)
        .await
        .expect("ttl");
    assert!((600..=630).contains(&ttl), "TTL {ttl}");

    tokio::time::sleep(Duration::from_millis(2100)).await;
    let (after, counts) = notifier(&prefix).await;
    assert_eq!((counts.restored, counts.dropped), (1, 1));
    assert!(after.get_subscription("short").is_none());
    assert!(after.get_subscription("long").is_some());
    redis_holds(&mut connection, &prefix, &["long"]).await;
    after.remove_subscription("long");
    redis_holds(&mut connection, &prefix, &[]).await;
}

/// A failed NOTIFY's removal after a restart deletes the stored copy.
#[tokio::test]
async fn a_failed_notify_after_a_restart_deletes_the_stored_copy() {
    let Some(mut connection) = connection().await else {
        return;
    };
    let prefix = unique_prefix("failed");
    {
        let (before, _) = notifier(&prefix).await;
        before.add_subscription(dialog("sub-481", Duration::from_secs(600)));
        redis_holds(&mut connection, &prefix, &["sub-481"]).await;
    }
    let (after, _) = notifier(&prefix).await;
    let generation = after
        .prepare_notify("sub-481")
        .expect("a NOTIFY")
        .generation;
    assert!(after.remove_subscription_if_current("sub-481", generation));
    redis_holds(&mut connection, &prefix, &[]).await;
}

/// Restore time with a few thousand subscriptions.
#[tokio::test]
async fn restoring_thousands_of_subscriptions_is_quick() {
    const SUBSCRIPTIONS: usize = 5_000;
    let Some(mut connection) = connection().await else {
        return;
    };
    let prefix = unique_prefix("load");
    {
        let (before, _) = notifier(&prefix).await;
        for index in 0..SUBSCRIPTIONS {
            let id = format!("sub-{index}");
            before.add_subscription(dialog(&id, Duration::from_secs(600)));
            before.prepare_notify(&id).expect("a NOTIFY");
        }
        for _ in 0..500 {
            if keys(&mut connection, &prefix).await.len() == SUBSCRIPTIONS {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
    let started = std::time::Instant::now();
    let (after, counts) = notifier(&prefix).await;
    let elapsed = started.elapsed();
    eprintln!("restored {} subscriptions in {elapsed:?}", counts.restored);
    assert_eq!(counts.restored, SUBSCRIPTIONS);
    assert_eq!(after.subscriptions_for(AOR).len(), SUBSCRIPTIONS);
    assert!(elapsed < Duration::from_secs(5), "restore took {elapsed:?}");
    let _: () = redis::cmd("DEL")
        .arg(keys(&mut connection, &prefix).await)
        .query_async(&mut connection)
        .await
        .expect("cleanup");
}
