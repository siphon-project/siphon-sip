//! The iFC store's Redis persistence against a real Redis.
//!
//! Run only when `SIPHON_TEST_REDIS_URL` names a server; skipped otherwise.

use super::*;

const PROFILE: &str = concat!(
    "<ServiceProfile><InitialFilterCriteria><Priority>0</Priority>",
    "<TriggerPoint><ConditionTypeCNF>1</ConditionTypeCNF><SPT>",
    "<ConditionNegated>0</ConditionNegated><Group>0</Group><Method>INVITE</Method>",
    "</SPT></TriggerPoint><ApplicationServer><ServerName>sip:mmtel@example.com</ServerName>",
    "<DefaultHandling>0</DefaultHandling></ApplicationServer></InitialFilterCriteria>",
    "</ServiceProfile>",
);

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

fn unique_prefix(test: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("siphon-test:ifc:{test}:{}:{nanos}:", std::process::id())
}

async fn ttl(connection: &mut redis::aio::MultiplexedConnection, key: &str) -> i64 {
    redis::cmd("TTL")
        .arg(key)
        .query_async(connection)
        .await
        .expect("ttl")
}

/// A stored profile key was a plain SET and outlived its user for good; it
/// now carries the TTL it was given, renewed by every store.
#[tokio::test]
async fn a_stored_profile_carries_its_ttl_and_each_store_renews_it() {
    let Some(mut connection) = connection().await else {
        return;
    };
    let prefix = unique_prefix("ttl");
    let store = IfcStore::new(Vec::new());
    store.set_backend_writer(spawn_ifc_backend_writer_with_ttl(
        connection.clone(),
        prefix.clone(),
        7230,
    ));
    let key = format!("{prefix}sip:alice@example.com");

    store
        .store_profile_xml("sip:alice@example.com", PROFILE)
        .expect("store");
    let mut seen = -2;
    for _ in 0..100 {
        seen = ttl(&mut connection, &key).await;
        if seen > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!((7200..=7230).contains(&seen), "profile ttl {seen}");

    let _: () = redis::cmd("EXPIRE")
        .arg(&key)
        .arg(5)
        .query_async(&mut connection)
        .await
        .expect("shorten");
    store
        .store_profile_xml("sip:alice@example.com", PROFILE)
        .expect("store again");
    for _ in 0..100 {
        seen = ttl(&mut connection, &key).await;
        if seen > 5 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!((7200..=7230).contains(&seen), "renewed ttl {seen}");

    let _: () = redis::cmd("DEL")
        .arg(&key)
        .query_async(&mut connection)
        .await
        .expect("clean up");
}

/// The restore walks the prefix by cursor and finds every profile, across
/// more keys than one SCAN batch returns.
#[tokio::test]
async fn the_restore_finds_every_profile_by_cursor() {
    let Some(mut connection) = connection().await else {
        return;
    };
    let prefix = unique_prefix("restore");
    let mut keys = Vec::new();
    for user in 0..1500 {
        let key = format!("{prefix}sip:user{user}@example.com");
        let _: () = redis::cmd("SET")
            .arg(&key)
            .arg(PROFILE)
            .arg("EX")
            .arg(600)
            .query_async(&mut connection)
            .await
            .expect("set");
        keys.push(key);
    }

    let store = IfcStore::new(Vec::new());
    let restored = restore_ifc_profiles(&mut connection, &prefix, &store)
        .await
        .expect("restore");

    let _: () = redis::cmd("DEL")
        .arg(&keys)
        .query_async(&mut connection)
        .await
        .expect("clean up");
    assert_eq!(restored, (1500, 1500));
    assert!(store.has_profile("sip:user1499@example.com"));
}
