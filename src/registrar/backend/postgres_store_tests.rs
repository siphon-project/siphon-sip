//! Tests of the Postgres backend against a real server.
//!
//! They run only when `SIPHON_TEST_POSTGRES_URL` names one (CI starts a
//! service container for them); without it each says it was skipped and
//! passes. Every test uses tables of its own and drops them at the end.

use std::collections::BTreeSet;
use std::time::Duration;

use super::*;
use crate::registrar::backend::tests::sample_stored_contact;

fn test_url() -> Option<String> {
    match std::env::var("SIPHON_TEST_POSTGRES_URL") {
        Ok(url) if !url.is_empty() => Some(url),
        _ => {
            eprintln!("skipped: SIPHON_TEST_POSTGRES_URL is not set");
            None
        }
    }
}

fn unique_table(test: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("registrar_test_{test}_{}_{nanos}", std::process::id())
}

async fn backend(url: &str, table: &str, max_lifetime: u64) -> PostgresBackend {
    let mut backend = PostgresBackend::connect(PostgresBackendConfig {
        url: url.to_string(),
        table: table.to_string(),
        ..PostgresBackendConfig::default()
    })
    .await
    .expect("connect to the test Postgres")
    .with_max_binding_lifetime(max_lifetime);
    backend.expired_row_grace_secs = 0;
    backend
}

async fn rows(backend: &PostgresBackend, table: &str) -> i64 {
    backend.clients[0]
        .query_one(&format!("SELECT COUNT(*) FROM {table}"), &[])
        .await
        .expect("count rows")
        .get(0)
}

async fn drop_tables(backend: &PostgresBackend, table: &str) {
    backend.clients[0]
        .batch_execute(&format!(
            "DROP TABLE IF EXISTS {table}; DROP TABLE IF EXISTS {table}_aor_state;"
        ))
        .await
        .expect("drop test tables");
}

fn contact(uri: &str, lifetime_secs: u64) -> StoredContact {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    StoredContact {
        uri: uri.to_string(),
        expires_secs: lifetime_secs,
        expires_at: Some(now + lifetime_secs),
        ..sample_stored_contact()
    }
}

fn state() -> StoredAorState {
    StoredAorState {
        service_routes: vec!["<sip:orig@scscf.example.com;lr>".to_string()],
        asserted_identity: Some("sip:alice@example.com".to_string()),
        associated_uris: vec!["sip:alice@example.com".to_string()],
    }
}

/// A save replaces the AoR's bindings. It used to only upsert, so a contact
/// dropped from the set stayed, was restored, and was counted.
#[tokio::test]
async fn a_save_drops_the_contacts_no_longer_in_the_set() {
    let Some(url) = test_url() else { return };
    let table = unique_table("replace");
    let backend = backend(&url, &table, 7200).await;
    let aor = "sip:alice@example.com";

    backend
        .save(
            aor,
            &[
                contact("sip:alice@192.0.2.1:5060", 600),
                contact("sip:alice@192.0.2.2:5060", 600),
            ],
        )
        .await
        .expect("save");
    backend
        .save(aor, &[contact("sip:alice@192.0.2.2:5060", 600)])
        .await
        .expect("remove one contact");

    let uris: BTreeSet<String> = backend
        .load(aor)
        .await
        .expect("load")
        .into_iter()
        .map(|stored| stored.uri)
        .collect();
    drop_tables(&backend, &table).await;
    assert_eq!(
        uris,
        BTreeSet::from(["sip:alice@192.0.2.2:5060".to_string()])
    );
}

/// The count stays exact across register, refresh, de-register, removing a
/// contact, expiry and a second replica on the same tables.
#[tokio::test]
async fn the_count_matches_the_live_aors_across_replicas() {
    let Some(url) = test_url() else { return };
    let table = unique_table("count");
    let first = backend(&url, &table, 7200).await;
    let second = backend(&url, &table, 7200).await;

    for user in 0..20 {
        let replica = if user % 2 == 0 { &first } else { &second };
        let lifetime = if user < 5 { 1 } else { 600 };
        replica
            .save(
                &format!("sip:user{user}@example.com"),
                &[contact(&format!("sip:{user}@192.0.2.1:5060"), lifetime)],
            )
            .await
            .expect("register");
    }
    // Refresh from the other replica, de-register five, empty five.
    for user in 5..10 {
        second
            .save(
                &format!("sip:user{user}@example.com"),
                &[contact(&format!("sip:{user}@192.0.2.1:5060"), 3600)],
            )
            .await
            .expect("refresh");
    }
    for user in 10..15 {
        first
            .remove(&format!("sip:user{user}@example.com"))
            .await
            .expect("deregister");
    }
    for user in 15..20 {
        second
            .save(&format!("sip:user{user}@example.com"), &[])
            .await
            .expect("remove the last contact");
    }
    tokio::time::sleep(Duration::from_millis(2_100)).await;

    let first_count = first.count_aors().await.expect("count");
    let second_count = second.count_aors().await.expect("count");
    drop_tables(&first, &table).await;
    assert_eq!(first_count, 5);
    assert_eq!(second_count, 5);
}

/// The leak gate. Once every binding has expired and the purge has run,
/// nothing is left: no contact row, and no state row its binding outlived.
#[tokio::test]
async fn the_purge_drains_expired_bindings_and_their_state() {
    let Some(url) = test_url() else { return };
    let table = unique_table("purge");
    // A state window of 5 s: wide enough that a loaded machine still runs
    // the first purge inside it.
    let backend = backend(&url, &table, 5).await;

    for user in 0..10 {
        let aor = format!("sip:user{user}@example.com");
        backend
            .save(&aor, &[contact(&format!("sip:{user}@192.0.2.1:5060"), 1)])
            .await
            .expect("register");
        backend.save_aor_state(&aor, &state()).await.expect("state");
    }
    // State written ahead of a binding survives a purge inside its window.
    backend
        .save_aor_state("sip:early@example.com", &state())
        .await
        .expect("state first");
    let last_write = tokio::time::Instant::now();
    let (first_purge, early_kept) = {
        let purged = backend.purge_expired().await.expect("purge");
        (purged, rows(&backend, &format!("{table}_aor_state")).await)
    };

    // Past the window as counted from the last write, however long the
    // writes and the first purge took.
    tokio::time::sleep_until(last_write + Duration::from_millis(6_500)).await;
    let purged = backend.purge_expired().await.expect("purge");
    let contacts_left = rows(&backend, &table).await;
    let state_left = rows(&backend, &format!("{table}_aor_state")).await;
    let count = backend.count_aors().await.expect("count");
    drop_tables(&backend, &table).await;

    assert_eq!(early_kept, 11, "a purge took state still inside its window");
    // The first purge may already take contacts a slow write outlived.
    assert_eq!(first_purge + purged, 21);
    assert_eq!(contacts_left, 0);
    assert_eq!(state_left, 0);
    assert_eq!(count, 0);
}
