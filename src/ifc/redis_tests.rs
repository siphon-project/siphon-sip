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

/// A client on the test Redis; call only after [`connection`] found one.
fn client() -> redis::Client {
    redis::Client::open(std::env::var("SIPHON_TEST_REDIS_URL").expect("url")).expect("redis url")
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
    store.set_backend_writer(spawn_ifc_backend_writer_with_client_and_ttl(
        client(),
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

/// A registration burst stores more profiles at once than the writer drains
/// before the next arrives. Every one of them must reach Redis: a profile that
/// does not is re-fetched from the HSS after a restart instead of restored,
/// and a removal that does not leaves a profile its user no longer has.
#[tokio::test]
async fn a_burst_of_profile_writes_reaches_redis_in_full() {
    let Some(mut connection) = connection().await else {
        return;
    };
    const USERS: usize = 6_000;
    let prefix = unique_prefix("burst");
    let store = IfcStore::new(Vec::new());
    store.set_backend_writer(spawn_ifc_backend_writer_with_client_and_ttl(
        client(),
        connection.clone(),
        prefix.clone(),
        600,
    ));

    // All of it before the writer task runs once: the test runtime has one
    // thread and this loop never yields.
    for user in 0..USERS {
        store
            .store_profile_xml(&format!("sip:user{user}@example.com"), PROFILE)
            .expect("store");
    }
    for user in 0..USERS / 2 {
        store.remove_profile(&format!("sip:user{user}@example.com"));
    }

    let expected: std::collections::BTreeSet<String> = (USERS / 2..USERS)
        .map(|user| format!("{prefix}sip:user{user}@example.com"))
        .collect();
    let mut stored = std::collections::BTreeSet::new();
    for _ in 0..250 {
        stored = keys_under(&mut connection, &prefix).await;
        if stored == expected {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    if !stored.is_empty() {
        let _: () = redis::cmd("DEL")
            .arg(stored.iter().collect::<Vec<_>>())
            .query_async(&mut connection)
            .await
            .expect("clean up");
    }
    let missing = expected.difference(&stored).count();
    let extra = stored.difference(&expected).count();
    assert!(
        missing == 0 && extra == 0,
        "Redis disagrees with the store: {missing} profiles missing, {extra} removed ones left"
    );
}

/// Every key under `prefix`, by cursor.
async fn keys_under(
    connection: &mut redis::aio::MultiplexedConnection,
    prefix: &str,
) -> std::collections::BTreeSet<String> {
    let mut keys = std::collections::BTreeSet::new();
    let mut cursor: u64 = 0;
    loop {
        let (next, batch): (u64, Vec<String>) = redis::cmd("SCAN")
            .arg(cursor)
            .arg("MATCH")
            .arg(format!("{prefix}*"))
            .arg("COUNT")
            .arg(1000)
            .query_async(connection)
            .await
            .expect("scan");
        keys.extend(batch);
        cursor = next;
        if cursor == 0 {
            return keys;
        }
    }
}

/// Profile writes held while the link to Redis is down reach it through a new
/// connection once it answers again: a connection never recovers by itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn profile_writes_drain_through_a_new_connection_after_the_link_drops() {
    let Some(mut connection) = connection().await else {
        return;
    };
    let url = std::env::var("SIPHON_TEST_REDIS_URL").expect("url");
    let (scheme, rest) = url.split_once("://").expect("scheme");
    let (authority, path) = match rest.find('/') {
        Some(slash) => (&rest[..slash], &rest[slash..]),
        None => (rest, ""),
    };
    let (userinfo, upstream) = match authority.rsplit_once('@') {
        Some((userinfo, host_port)) => (format!("{userinfo}@"), host_port),
        None => (String::new(), authority),
    };
    let cutter =
        crate::registrar::backend::link_cutter::LinkCutter::start(upstream.to_string()).await;
    let relayed = redis::Client::open(format!("{scheme}://{userinfo}{}{path}", cutter.address()))
        .expect("relay url");
    let relayed_connection = relayed
        .get_multiplexed_async_connection()
        .await
        .expect("connect through the relay");
    let prefix = unique_prefix("reconnect");
    let store = IfcStore::new(Vec::new());
    let writer = spawn_ifc_backend_writer_with_client_and_ttl(
        relayed,
        relayed_connection,
        prefix.clone(),
        600,
    );
    store.set_backend_writer(writer.clone());

    store
        .store_profile_xml("sip:before@example.com", PROFILE)
        .expect("store");
    cutter.cut();
    store
        .store_profile_xml("sip:during@example.com", PROFILE)
        .expect("store");
    store.remove_profile("sip:before@example.com");
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    assert!(writer.pending_writes() > 0, "nothing passes a cut link");

    cutter.restore();
    for _ in 0..300 {
        if writer.pending_writes() == 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(writer.pending_writes(), 0, "the held writes never drained");
    let stored = keys_under(&mut connection, &prefix).await;
    let _: () = redis::cmd("DEL")
        .arg(stored.iter().collect::<Vec<_>>())
        .query_async(&mut connection)
        .await
        .expect("clean up");
    assert_eq!(
        stored.into_iter().collect::<Vec<_>>(),
        vec![format!("{prefix}sip:during@example.com")]
    );
}

/// The deprecated connection-only constructor still writes through the
/// coalescing queue (it only cannot reconnect).
#[tokio::test]
#[allow(deprecated)]
async fn the_connection_only_constructor_still_persists() {
    let Some(mut connection) = connection().await else {
        return;
    };
    let prefix = unique_prefix("deprecated");
    let store = IfcStore::new(Vec::new());
    store.set_backend_writer(spawn_ifc_backend_writer_with_ttl(
        connection.clone(),
        prefix.clone(),
        600,
    ));
    store
        .store_profile_xml("sip:alice@example.com", PROFILE)
        .expect("store");
    let key = format!("{prefix}sip:alice@example.com");
    let mut seen = -2;
    for _ in 0..100 {
        seen = ttl(&mut connection, &key).await;
        if seen > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let _: () = redis::cmd("DEL")
        .arg(&key)
        .query_async(&mut connection)
        .await
        .expect("clean up");
    assert!((500..=600).contains(&seen), "profile ttl {seen}");
}
