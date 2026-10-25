//! The backends across a dropped link: writes held while the server is
//! unreachable must reach it once it answers again, through a new connection.
//!
//! Each test puts a [`LinkCutter`] between the backend and the real server
//! named by `SIPHON_TEST_REDIS_URL` / `SIPHON_TEST_POSTGRES_URL` and cuts it:
//! every open connection is reset and new ones refused, which is what a server
//! restart looks like from the client, without restarting the server the other
//! tests share. Skipped when the variable is unset.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use super::link_cutter::LinkCutter;
use super::*;
use crate::registrar::Registrar;
use crate::sip::uri::SipUri;

fn env_url(name: &str) -> Option<String> {
    match std::env::var(name) {
        Ok(url) if !url.is_empty() => Some(url),
        _ => {
            eprintln!("skipped: {name} is not set");
            None
        }
    }
}

/// `scheme://[userinfo@]host:port[/rest]` split around its `host:port`.
fn split_authority(url: &str) -> (String, String, String) {
    let (scheme, rest) = url.split_once("://").expect("a URL with a scheme");
    let (authority, path) = match rest.find('/') {
        Some(slash) => (&rest[..slash], &rest[slash..]),
        None => (rest, ""),
    };
    let (userinfo, host_port) = match authority.rsplit_once('@') {
        Some((userinfo, host_port)) => (format!("{userinfo}@"), host_port),
        None => (String::new(), authority),
    };
    (
        format!("{scheme}://{userinfo}"),
        host_port.to_string(),
        path.to_string(),
    )
}

fn unique(test: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{test}_{}_{nanos}", std::process::id())
}

fn save(registrar: &Registrar, aor: &str) {
    registrar
        .save(
            aor,
            SipUri::new("198.51.100.90".to_string()).with_user("ue".to_string()),
            3600,
            1.0,
            format!("call-{aor}"),
            1,
        )
        .expect("save");
}

/// The AoRs and contact URIs `backend` holds, against the registrar's.
async fn matches_memory<B: RegistrarBackend>(backend: &B, registrar: &Registrar) -> bool {
    let mut memory: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for aor in registrar.registered_aors() {
        let uris = registrar
            .lookup_all(&aor)
            .iter()
            .map(|contact| contact.uri.to_string())
            .collect();
        memory.insert(aor, uris);
    }
    let Ok(aors) = backend.all_aors().await else {
        return false;
    };
    let mut stored: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for aor in aors {
        let Ok(contacts) = backend.load(&aor).await else {
            return false;
        };
        stored.insert(
            aor,
            contacts.into_iter().map(|contact| contact.uri).collect(),
        );
    }
    memory == stored
}

/// Cut the link with writes in flight, write more while it is down, restore
/// it, and require everything to drain through a new connection.
async fn drains_across_a_cut<B: RegistrarBackend + 'static, C: RegistrarBackend>(
    through_cutter: B,
    direct: &C,
    cutter: &LinkCutter,
) {
    let writer = spawn_backend_writer(through_cutter);
    let registrar = Registrar::default();
    registrar.set_backend_writer(writer.clone());

    save(&registrar, "sip:001010000000091@ims.example.com");
    save(&registrar, "sip:001010000000092@ims.example.com");
    wait_for(|| writer.pending_writes() == 0, "the first writes").await;
    assert!(matches_memory(direct, &registrar).await);

    cutter.cut();
    save(&registrar, "sip:001010000000093@ims.example.com");
    registrar.remove_all("sip:001010000000091@ims.example.com");
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        writer.pending_writes() > 0,
        "nothing reaches a server behind a cut link"
    );
    assert!(
        writer.oldest_pending() > Duration::ZERO,
        "the oldest-pending age reports the stall"
    );

    cutter.restore();
    wait_for(
        || writer.pending_writes() == 0,
        "the held writes after the link returned",
    )
    .await;
    assert!(
        matches_memory(direct, &registrar).await,
        "the server holds what memory holds"
    );
    assert_eq!(writer.oldest_pending(), Duration::ZERO);
    // A read through the writer works on the new connection too.
    assert_eq!(writer.count_aors().await.expect("count after the blip"), 2);
}

async fn wait_for(done: impl Fn() -> bool, what: &str) {
    for _ in 0..300 {
        if done() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("timed out waiting for {what}");
}

#[cfg(feature = "redis-backend")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redis_writes_drain_through_a_new_connection_after_the_link_drops() {
    let Some(url) = env_url("SIPHON_TEST_REDIS_URL") else {
        return;
    };
    let (scheme, upstream, path) = split_authority(&url);
    let cutter = LinkCutter::start(upstream).await;
    let prefix = format!("siphon-test:{}:", unique("redis_reconnect"));
    let config = |url: String| RedisBackendConfig {
        url,
        key_prefix: prefix.clone(),
        ..RedisBackendConfig::default()
    };
    let through_cutter =
        RedisBackend::connect(config(format!("{scheme}{}{path}", cutter.address())))
            .await
            .expect("connect through the relay");
    let direct = RedisBackend::connect(config(url.clone()))
        .await
        .expect("connect");

    drains_across_a_cut(through_cutter, &direct, &cutter).await;
}

/// A backend used directly (the boot-time restore, `count_aors`) recovers
/// too: the read that meets the dead connection fails, the next one
/// reconnects.
#[cfg(feature = "redis-backend")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_redis_read_after_the_link_drops_recovers() {
    let Some(url) = env_url("SIPHON_TEST_REDIS_URL") else {
        return;
    };
    let (scheme, upstream, path) = split_authority(&url);
    let cutter = LinkCutter::start(upstream).await;
    let backend = RedisBackend::connect(RedisBackendConfig {
        url: format!("{scheme}{}{path}", cutter.address()),
        key_prefix: format!("siphon-test:{}:", unique("redis_read")),
        ..RedisBackendConfig::default()
    })
    .await
    .expect("connect through the relay");
    assert_eq!(backend.count_aors().await.expect("count"), 0);

    cutter.cut();
    assert!(backend.count_aors().await.is_err());
    cutter.restore();

    let mut recovered = None;
    for _ in 0..50 {
        if let Ok(count) = backend.count_aors().await {
            recovered = Some(count);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(recovered, Some(0), "the read never recovered");
}

#[cfg(feature = "postgres-backend")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn postgres_writes_drain_through_a_new_connection_after_the_link_drops() {
    let Some(url) = env_url("SIPHON_TEST_POSTGRES_URL") else {
        return;
    };
    let (scheme, upstream, path) = split_authority(&url);
    let cutter = LinkCutter::start(upstream).await;
    let table = unique("registrar_test_reconnect");
    let config = |url: String| PostgresBackendConfig {
        url,
        table: table.clone(),
        ..PostgresBackendConfig::default()
    };
    let through_cutter =
        PostgresBackend::connect(config(format!("{scheme}{}{path}", cutter.address())))
            .await
            .expect("connect through the relay");
    let direct = PostgresBackend::connect(config(url.clone()))
        .await
        .expect("connect");

    drains_across_a_cut(through_cutter, &direct, &cutter).await;

    let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .expect("connect");
    tokio::spawn(connection);
    client
        .batch_execute(&format!(
            "DROP TABLE IF EXISTS {table}; DROP TABLE IF EXISTS {table}_aor_state;"
        ))
        .await
        .expect("drop test tables");
}
