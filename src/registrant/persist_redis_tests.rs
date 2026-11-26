//! The binding store against a real Redis.
//!
//! Run only when `SIPHON_TEST_REDIS_URL` names a server; skipped otherwise.

use std::collections::HashSet;
use std::time::Duration;

use super::advertised::ADVERTISED_TTL_SECS;

use super::*;
use crate::redis_target::RedisConnection;

async fn connection() -> Option<RedisConnection> {
    let url = match std::env::var("SIPHON_TEST_REDIS_URL") {
        Ok(url) if !url.is_empty() => url,
        _ => {
            eprintln!("skipped: SIPHON_TEST_REDIS_URL is not set");
            return None;
        }
    };
    Some(
        RedisConnection::connect(url.into())
            .await
            .expect("connect to the test Redis"),
    )
}

fn unique_prefix(test: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!(
        "siphon-test:registrant:{test}:{}:{nanos}:",
        std::process::id()
    )
}

fn record(instance: &str, aor: &str) -> BindingRecord {
    BindingRecord {
        instance: instance.to_string(),
        aor: aor.to_string(),
        registrar_uri: "sip:198.51.100.10:5060".to_string(),
        destination: "198.51.100.10:5060".parse().expect("an address"),
        address_str: None,
        transport: Transport::Udp,
        contact: "sip:siphon@192.0.2.1:5060".to_string(),
        call_id: "reg-0001".to_string(),
        next_cseq: 4,
        local_addr: None,
        interval_secs: 600,
        binding_until_unix: unix_now() + 600,
        origin: EntryOrigin::Yaml,
        attempts: 0,
    }
}

#[tokio::test]
async fn a_saved_binding_is_read_back_with_a_ttl_and_a_removed_one_is_gone() {
    let Some(connection) = connection().await else {
        return;
    };
    let prefix = unique_prefix("roundtrip");
    let store = BindingStore::redis(connection.clone(), "node-a".to_string(), prefix.clone(), 30);
    let stored = record("node-a", "sip:trunk@carrier.example");

    store.save(stored.clone());
    store.flush(Duration::from_secs(5)).await;
    assert_eq!(store.pending_writes(), 0);

    assert_eq!(store.load().await.expect("loaded"), vec![stored]);
    let mut raw = connection.clone();
    let ttl: i64 = redis::cmd("TTL")
        .arg(store.key_of("sip:trunk@carrier.example"))
        .query_async(&mut raw)
        .await
        .expect("TTL");
    assert!((600..=630).contains(&ttl), "ttl {ttl}");

    store.remove("sip:trunk@carrier.example");
    store.flush(Duration::from_secs(5)).await;
    assert!(store.load().await.expect("loaded").is_empty());
}

/// Nothing of a credential is in what Redis holds, and the optional fields a
/// later save drops do not linger from an earlier one.
#[tokio::test]
async fn what_redis_holds_has_only_the_documented_fields_and_a_resave_replaces_it() {
    let Some(connection) = connection().await else {
        return;
    };
    let store = BindingStore::redis(
        connection.clone(),
        "node-a".to_string(),
        unique_prefix("fields"),
        30,
    );
    let mut stored = record("node-a", "sip:trunk@carrier.example");
    stored.address_str = Some("registrar.example.invalid:5060".to_string());
    store.save(stored.clone());
    store.flush(Duration::from_secs(5)).await;
    stored.address_str = None;
    store.save(stored.clone());
    store.flush(Duration::from_secs(5)).await;

    let mut raw = connection.clone();
    let fields: std::collections::HashMap<String, String> = redis::cmd("HGETALL")
        .arg(store.key_of("sip:trunk@carrier.example"))
        .query_async(&mut raw)
        .await
        .expect("HGETALL");
    let mut names: Vec<&str> = fields.keys().map(String::as_str).collect();
    names.sort_unstable();
    let mut expected = FIELDS.to_vec();
    expected.sort_unstable();
    assert_eq!(names, expected);
    assert_eq!(fields.get("address_str").map(String::as_str), Some(""));
    assert_eq!(store.load().await.expect("loaded"), vec![stored]);
}

#[tokio::test]
async fn an_instance_reads_only_its_own_bindings() {
    let Some(connection) = connection().await else {
        return;
    };
    let prefix = unique_prefix("instances");
    let node_a = BindingStore::redis(connection.clone(), "node-a".to_string(), prefix.clone(), 30);
    let node_b = BindingStore::redis(connection.clone(), "node-b".to_string(), prefix.clone(), 30);
    node_a.save(record("node-a", "sip:one@carrier.example"));
    node_b.save(record("node-b", "sip:two@carrier.example"));
    node_a.flush(Duration::from_secs(5)).await;
    node_b.flush(Duration::from_secs(5)).await;

    let seen: Vec<String> = node_a
        .load()
        .await
        .expect("loaded")
        .into_iter()
        .map(|record| record.aor)
        .collect();
    assert_eq!(seen, ["sip:one@carrier.example"]);
}

/// The registrar's index build scans its own prefix: ours is apart from it.
#[tokio::test]
async fn the_default_prefix_is_outside_the_registrars() {
    assert!(!DEFAULT_REGISTRANT_KEY_PREFIX.starts_with("siphon:reg:"));
    assert!(!"siphon:reg:".starts_with(DEFAULT_REGISTRANT_KEY_PREFIX));
}

/// A burst of saves for one AoR is one write: the queue holds the latest per
/// AoR, never a backlog.
#[tokio::test]
async fn a_burst_for_one_aor_leaves_one_pending_write_and_drains_to_zero() {
    let Some(connection) = connection().await else {
        return;
    };
    let store = BindingStore::redis(connection, "node-a".to_string(), unique_prefix("burst"), 30);
    for cseq in 0..500 {
        let mut stored = record("node-a", "sip:trunk@carrier.example");
        stored.next_cseq = cseq;
        store.save(stored);
        assert!(store.pending_writes() <= 1);
    }
    store.flush(Duration::from_secs(5)).await;
    assert_eq!(store.pending_writes(), 0);
    let loaded = store.load().await.expect("loaded");
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].next_cseq, 499);
}

/// Atomic in Redis: the stored record's Call-ID decides, and a save still
/// waiting is not undone by a removal of an older registration.
#[tokio::test]
async fn a_guarded_removal_keeps_a_newer_record_in_redis() {
    let Some(connection) = connection().await else {
        return;
    };
    let store = BindingStore::redis(
        connection,
        "node-a".to_string(),
        unique_prefix("removeif"),
        30,
    );
    let mut first = record("node-a", "sip:trunk@carrier.example");
    first.call_id = "reg-first".to_string();
    let mut second = first.clone();
    second.call_id = "reg-second".to_string();
    store.save(first);
    store.flush(Duration::from_secs(5)).await;
    store.save(second.clone());
    store.flush(Duration::from_secs(5)).await;

    store.remove_if("sip:trunk@carrier.example", "reg-first");
    store.flush(Duration::from_secs(5)).await;
    assert_eq!(store.load().await.expect("loaded"), vec![second.clone()]);

    // Queued behind a save of the newer registration: still not removed.
    store.save(second.clone());
    store.remove_if("sip:trunk@carrier.example", "reg-first");
    store.flush(Duration::from_secs(5)).await;
    assert_eq!(store.load().await.expect("loaded"), vec![second]);

    store.remove_if("sip:trunk@carrier.example", "reg-second");
    store.flush(Duration::from_secs(5)).await;
    assert!(store.load().await.expect("loaded").is_empty());
}

#[tokio::test]
async fn other_instances_records_of_an_aor_are_found_by_scan() {
    let Some(connection) = connection().await else {
        return;
    };
    let prefix = unique_prefix("others");
    let node_a = BindingStore::redis(connection.clone(), "node-a".to_string(), prefix.clone(), 30);
    let node_b = BindingStore::redis(connection, "node-b".to_string(), prefix, 30);
    node_a.save(record("node-a", "sip:trunk@carrier.example"));
    node_b.save(record("node-b", "sip:trunk@carrier.example"));
    node_b.save(record("node-b", "sip:other@carrier.example"));
    node_a.flush(Duration::from_secs(5)).await;
    node_b.flush(Duration::from_secs(5)).await;

    let found = node_a
        .others_holding(&["sip:trunk@carrier.example".to_string()])
        .await
        .expect("read");

    assert_eq!(found.len(), 1);
    assert_eq!(found[0].instance, "node-b");
    assert_eq!(found[0].aor, "sip:trunk@carrier.example");
}

#[tokio::test]
async fn the_attempt_counter_is_guarded_by_call_id_in_redis() {
    let Some(connection) = connection().await else {
        return;
    };
    let store = BindingStore::redis(
        connection,
        "node-a".to_string(),
        unique_prefix("attempts"),
        30,
    );
    let mut first = record("node-a", "sip:trunk@carrier.example");
    first.call_id = "reg-first".to_string();
    let mut second = first.clone();
    second.call_id = "reg-second".to_string();
    store.save(second.clone());
    store.flush(Duration::from_secs(5)).await;

    store.set_attempts_if("sip:trunk@carrier.example", "reg-first", 3);
    store.flush(Duration::from_secs(5)).await;
    assert_eq!(store.load().await.expect("loaded"), vec![second.clone()]);

    store.set_attempts_if("sip:trunk@carrier.example", "reg-second", 3);
    store.flush(Duration::from_secs(5)).await;
    assert_eq!(store.load().await.expect("loaded")[0].attempts, 3);
}

/// Fail closed: a hash of another instance for the AoR that cannot be read
/// counts as held, not as absent.
#[tokio::test]
async fn an_unreadable_record_of_another_instance_is_an_error_not_an_absence() {
    let Some(connection) = connection().await else {
        return;
    };
    let prefix = unique_prefix("unreadable");
    let node_a = BindingStore::redis(connection.clone(), "node-a".to_string(), prefix.clone(), 30);
    let aor = "sip:trunk@carrier.example";
    let mut raw = connection.clone();
    let _: i64 = redis::cmd("HSET")
        .arg(format!("{prefix}node-b:{aor}"))
        .arg("aor")
        .arg(aor)
        .arg("call_id")
        .arg("reg-garbled")
        .query_async(&mut raw)
        .await
        .expect("HSET");

    assert!(node_a.others_holding(&[aor.to_string()]).await.is_err());

    // Our own unreadable record is ours to ignore.
    let _: i64 = redis::cmd("DEL")
        .arg(format!("{prefix}node-b:{aor}"))
        .query_async(&mut raw)
        .await
        .expect("DEL");
    let _: i64 = redis::cmd("HSET")
        .arg(format!("{prefix}node-a:{aor}"))
        .arg("aor")
        .arg(aor)
        .query_async(&mut raw)
        .await
        .expect("HSET");
    assert!(node_a.others_holding(&[aor.to_string()]).await.is_ok());
}

#[tokio::test]
async fn published_addresses_are_read_back_per_node_and_expire() {
    let Some(connection) = connection().await else {
        return;
    };
    let prefix = unique_prefix("advertised");
    let node_a = BindingStore::redis(connection.clone(), "node-a".to_string(), prefix.clone(), 30);
    let node_b = BindingStore::redis(connection.clone(), "node-b".to_string(), prefix.clone(), 30);
    let missing = node_a.advertised_view().await.expect("readable");
    assert_eq!(missing.own, None);

    node_a
        .publish_advertised(&["203.0.113.10".to_string()])
        .await
        .expect("published");
    node_b
        .publish_advertised(&["203.0.113.10".to_string(), "203.0.113.11".to_string()])
        .await
        .expect("published");

    let view = node_a.advertised_view().await.expect("readable");
    assert_eq!(view.own, Some(HashSet::from(["203.0.113.10".to_string()])));
    assert_eq!(
        view.others,
        HashSet::from(["203.0.113.10".to_string(), "203.0.113.11".to_string()])
    );
    // The entry carries a TTL, so a dead node's does not outlive it for long.
    let mut raw = connection.clone();
    let ttl: i64 = redis::cmd("TTL")
        .arg(format!("{prefix}~advertised~node-a"))
        .query_async(&mut raw)
        .await
        .expect("ttl");
    assert!(ttl > 0 && ttl <= ADVERTISED_TTL_SECS as i64, "ttl {ttl}");
    // Its records are not mistaken for an advertised entry, nor the reverse.
    assert!(node_a.load().await.expect("loaded").is_empty());
}
