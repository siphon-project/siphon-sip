//! The Redis backend as the store several registrar nodes share: the atomic
//! expiry claim, the alias keys, and two nodes over one server.
//!
//! Run only when `SIPHON_TEST_REDIS_URL` names a server; skipped otherwise.

use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::registrar::{InstanceIdentity, Registrar, RegistrarConfig, RegistrationEvent};
use crate::sip::uri::SipUri;

fn test_url() -> Option<String> {
    match std::env::var("SIPHON_TEST_REDIS_URL") {
        Ok(url) if !url.is_empty() => Some(url),
        _ => {
            eprintln!("skipped: SIPHON_TEST_REDIS_URL is not set");
            None
        }
    }
}

fn unique_prefix(test: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("siphon-test:shared:{test}:{}:{nanos}:", std::process::id())
}

async fn connect(url: &str, prefix: &str) -> RedisBackend {
    RedisBackend::connect(RedisBackendConfig {
        target: url.to_string().into(),
        key_prefix: prefix.to_string(),
        ..RedisBackendConfig::default()
    })
    .await
    .expect("connect to the test Redis")
}

#[tokio::test]
async fn an_expiry_is_claimed_by_exactly_one_of_many_concurrent_claimants() {
    let Some(url) = test_url() else { return };
    let prefix = unique_prefix("claim");
    let nodes = futures_util::future::join_all((0..8).map(|_| connect(&url, &prefix))).await;
    let aor = "sip:alice@ims.example.invalid";

    let wins = futures_util::future::join_all(
        nodes
            .iter()
            .map(|node| node.claim_expiry(aor, "generation-1")),
    )
    .await
    .into_iter()
    .filter(|claimed| matches!(claimed, Ok(true)))
    .count();
    assert_eq!(wins, 1);

    assert!(
        nodes[0]
            .claim_expiry(aor, "generation-2")
            .await
            .expect("claim"),
        "a later registration's expiry is a new claim"
    );
    assert!(
        !nodes[1]
            .claim_expiry(aor, "generation-2")
            .await
            .expect("claim"),
        "and is won once too"
    );
}

#[tokio::test]
async fn an_alias_of_the_implicit_set_resolves_to_its_primary() {
    let Some(url) = test_url() else { return };
    let prefix = unique_prefix("alias");
    let writer = connect(&url, &prefix).await;
    let reader = connect(&url, &prefix).await;
    let aor = "sip:alice@ims.example.invalid";

    writer
        .save_aor_state(
            aor,
            &StoredAorState {
                associated_uris: vec!["tel:+15550100".to_string()],
                ..StoredAorState::default()
            },
        )
        .await
        .expect("state");

    assert_eq!(
        reader.load_alias("tel:+15550100").await.expect("alias"),
        Some(aor.to_string())
    );
    assert_eq!(
        reader.load_alias("tel:+15550101").await.expect("alias"),
        None
    );
}

fn node(backend: RedisBackend, name: &str, freshness_ms: u64) -> Arc<Registrar> {
    let backend = Arc::new(backend);
    let registrar = Arc::new(Registrar::new(RegistrarConfig {
        min_expires: 1,
        ..RegistrarConfig::default()
    }));
    registrar.set_instance_identity(InstanceIdentity {
        id: name.to_string(),
        epoch: format!("{name}-epoch"),
    });
    registrar.set_backend_writer(spawn_backend_writer(Arc::clone(&backend)));
    registrar.set_shared_reader(crate::registrar::SharedReader::new(
        backend,
        Duration::from_millis(freshness_ms),
    ));
    registrar
}

/// Two nodes, each with its own connection and memory, over one server.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_nodes_over_one_redis_share_bindings_and_announce_an_expiry_once() {
    let Some(url) = test_url() else { return };
    let prefix = unique_prefix("two-nodes");
    let a = node(connect(&url, &prefix).await, "a", 100);
    let b = node(connect(&url, &prefix).await, "b", 100);
    let (mut a_events, mut b_events) = (a.subscribe_events(), b.subscribe_events());
    let aor = "sip:alice@ims.example.invalid";
    let uri = SipUri::new("198.51.100.10".to_string()).with_user("alice".to_string());

    a.save(aor, uri.clone(), 2, 1.0, "call-1".to_string(), 1)
        .expect("save");
    a.set_associated_uris(aor, vec!["tel:+15550100".to_string()]);
    for _ in 0..100 {
        if b.is_registered("tel:+15550100") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(b.lookup(aor).len(), 1, "written on a, found on b");
    assert_eq!(b.lookup("tel:+15550100").len(), 1, "an alias too");

    tokio::time::sleep(Duration::from_millis(2300)).await;
    a.expire_stale();
    b.expire_stale();
    let announced = |events: &mut tokio::sync::broadcast::Receiver<RegistrationEvent>| {
        let mut count = 0;
        while let Ok(event) = events.try_recv() {
            if matches!(event, RegistrationEvent::Expired { .. }) {
                count += 1;
            }
        }
        count
    };
    assert_eq!(announced(&mut a_events) + announced(&mut b_events), 1);

    a.save(aor, uri, 3600, 1.0, "call-2".to_string(), 1)
        .expect("save");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(b.is_registered(aor));
    a.remove_all(aor);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !b.is_registered(aor),
        "a removal reaches b within the window"
    );
}
