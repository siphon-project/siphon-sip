//! Tests of the Redis backend against a real Redis.
//!
//! They need a server and run only when `SIPHON_TEST_REDIS_URL` names one
//! (CI starts a service container for them). Without it each test says it
//! was skipped and passes, so a plain `cargo test` on a laptop stays green.
//!
//! Every test writes under a prefix of its own, so they run in parallel
//! against one server and never see each other's keys.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use super::*;
use crate::registrar::backend::tests::sample_stored_contact;

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
    format!("siphon-test:{test}:{}:{nanos}:", std::process::id())
}

async fn backend(url: &str, prefix: &str, slack: u64, max_lifetime: u64) -> RedisBackend {
    RedisBackend::connect(RedisBackendConfig {
        url: url.to_string(),
        key_prefix: prefix.to_string(),
        ttl_slack_secs: slack,
        ..RedisBackendConfig::default()
    })
    .await
    .expect("connect to the test Redis")
    .with_max_binding_lifetime(max_lifetime)
}

async fn raw_connection(url: &str) -> redis::aio::MultiplexedConnection {
    redis::Client::open(url)
        .expect("redis url")
        .get_multiplexed_async_connection()
        .await
        .expect("connect to the test Redis")
}

/// Every key under `prefix`, by a test-side walk of the keyspace.
async fn keys_under(url: &str, prefix: &str) -> BTreeSet<String> {
    let mut connection = raw_connection(url).await;
    let mut keys = BTreeSet::new();
    let mut cursor: u64 = 0;
    loop {
        let (next, batch): (u64, Vec<String>) = redis::cmd("SCAN")
            .arg(cursor)
            .arg("MATCH")
            .arg(format!("{prefix}*"))
            .arg("COUNT")
            .arg(1000)
            .query_async(&mut connection)
            .await
            .expect("scan");
        keys.extend(batch);
        cursor = next;
        if cursor == 0 {
            return keys;
        }
    }
}

/// The AoRs that really have a binding hash, from the keyspace itself.
async fn real_aors(url: &str, prefix: &str) -> BTreeSet<String> {
    let state = format!("{prefix}state:");
    let index = format!("{prefix}index");
    keys_under(url, prefix)
        .await
        .into_iter()
        .filter(|key| !key.starts_with(&state) && *key != index)
        .map(|key| key[prefix.len()..].to_string())
        .collect()
}

async fn ttl_ms(url: &str, key: &str) -> i64 {
    let mut connection = raw_connection(url).await;
    redis::cmd("PTTL")
        .arg(key)
        .query_async(&mut connection)
        .await
        .expect("pttl")
}

fn contact(uri: &str, lifetime_secs: u64) -> StoredContact {
    let now = epoch_now();
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

/// The state key was a plain SET, so it outlived every binding it described
/// and piled up as the AoRs churned. It now carries the binding's TTL.
#[tokio::test]
async fn the_state_key_carries_the_binding_ttl() {
    let Some(url) = test_url() else { return };
    let prefix = unique_prefix("state-ttl");
    let backend = backend(&url, &prefix, 30, 7200).await;
    let aor = "sip:alice@example.com";

    backend
        .save(aor, &[contact("sip:alice@192.0.2.10:5060", 600)])
        .await
        .expect("save");
    backend.save_aor_state(aor, &state()).await.expect("state");

    let binding = ttl_ms(&url, &format!("{prefix}{aor}")).await;
    let aux = ttl_ms(&url, &format!("{prefix}state:{aor}")).await;
    assert!(
        (600_000..=630_000).contains(&binding),
        "binding ttl {binding}"
    );
    assert!(aux > 0, "the state key has no TTL ({aux})");
    assert!(
        (binding - aux).abs() <= 2_000,
        "state ttl {aux} does not follow the binding's {binding}"
    );
}

/// A refresh moves the state key's TTL with the binding's, whichever was
/// written first.
#[tokio::test]
async fn a_refresh_moves_the_state_ttl_with_the_binding() {
    let Some(url) = test_url() else { return };
    let prefix = unique_prefix("state-refresh");
    let backend = backend(&url, &prefix, 30, 7200).await;
    let aor = "sip:bob@example.com";

    backend
        .save(aor, &[contact("sip:bob@192.0.2.11:5060", 60)])
        .await
        .expect("save");
    backend.save_aor_state(aor, &state()).await.expect("state");
    backend
        .save(aor, &[contact("sip:bob@192.0.2.11:5060", 3600)])
        .await
        .expect("refresh");

    let aux = ttl_ms(&url, &format!("{prefix}state:{aor}")).await;
    assert!(
        (3_600_000..=3_630_000).contains(&aux),
        "state ttl {aux} after a refresh to 3600s"
    );
}

/// State written ahead of any binding (a script may set Service-Route
/// before the save) is bounded by the longest grant, then follows the
/// binding once there is one.
#[tokio::test]
async fn state_ahead_of_the_binding_is_bounded_then_follows_it() {
    let Some(url) = test_url() else { return };
    let prefix = unique_prefix("state-first");
    let backend = backend(&url, &prefix, 30, 7200).await;
    let aor = "sip:carol@example.com";

    backend.save_aor_state(aor, &state()).await.expect("state");
    let aux = ttl_ms(&url, &format!("{prefix}state:{aor}")).await;
    assert!(
        (7_200_000..=7_230_000).contains(&aux),
        "state without a binding got ttl {aux}"
    );

    backend
        .save(aor, &[contact("sip:carol@192.0.2.12:5060", 300)])
        .await
        .expect("save");
    let aux = ttl_ms(&url, &format!("{prefix}state:{aor}")).await;
    assert!(
        (300_000..=330_000).contains(&aux),
        "state ttl {aux} after the binding was saved"
    );
}

/// A save of nothing but expired bindings is a removal, not a hash with no
/// TTL (which nothing would ever delete).
#[tokio::test]
async fn a_save_of_only_expired_bindings_removes_the_aor() {
    let Some(url) = test_url() else { return };
    let prefix = unique_prefix("expired-save");
    let backend = backend(&url, &prefix, 30, 7200).await;
    let aor = "sip:dave@example.com";

    backend
        .save(aor, &[contact("sip:dave@192.0.2.13:5060", 600)])
        .await
        .expect("save");
    let mut stale = contact("sip:dave@192.0.2.13:5060", 0);
    stale.expires_at = Some(epoch_now() - 5);
    backend.save(aor, &[stale]).await.expect("save expired");

    assert!(keys_under(&url, &prefix).await.is_empty());
    assert_eq!(backend.count_aors().await.expect("count"), 0);
}

/// A tiny deterministic generator, so a failing churn run replays exactly.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self, bound: u64) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        (self.0 >> 33) % bound
    }
}

/// What the model says each AoR holds: contact URI to expiry epoch.
type Model = BTreeMap<String, BTreeMap<String, u64>>;

/// One random step against one of the two replicas, mirrored in the model.
///
/// `short_lifetimes` lets the first phase write bindings that expire during
/// the pause between the phases, so expiry is one of the paths exercised.
async fn churn_step(
    random: &mut Lcg,
    replicas: [&RedisBackend; 2],
    model: &mut Model,
    short_lifetimes: bool,
) {
    let backend = replicas[random.next(2) as usize];
    let aor = format!("sip:user{}@example.com", random.next(40));
    let lifetime = if short_lifetimes && random.next(2) == 0 {
        1
    } else {
        600
    };
    let now = epoch_now();
    let live: Vec<(String, u64)> = model
        .get(&aor)
        .map(|contacts| {
            contacts
                .iter()
                .filter(|(_, expiry)| **expiry > now)
                .map(|(uri, expiry)| (uri.clone(), *expiry))
                .collect()
        })
        .unwrap_or_default();

    match random.next(6) {
        // Register a new contact, or refresh one the AoR already has.
        0..=2 => {
            let uri = format!("sip:device{}@192.0.2.1:5060", random.next(3));
            let mut contacts: Vec<StoredContact> = live
                .iter()
                .filter(|(existing, _)| *existing != uri)
                .map(|(existing, expiry)| {
                    let mut kept = contact(existing, expiry - now);
                    kept.expires_at = Some(*expiry);
                    kept
                })
                .collect();
            contacts.push(contact(&uri, lifetime));
            backend.save(&aor, &contacts).await.expect("register");
            let entry = model.entry(aor.clone()).or_default();
            entry.retain(|_, expiry| *expiry > now);
            entry.insert(uri, now + lifetime);
        }
        // De-register the whole AoR.
        3 => {
            backend.remove(&aor).await.expect("deregister");
            backend
                .remove_aor_state(&aor)
                .await
                .expect("deregister state");
            model.remove(&aor);
        }
        // Remove one contact: the registrar writes the AoR back with what
        // is left, an empty list when nothing is.
        4 => {
            if let Some((gone, _)) = live.first() {
                let rest: Vec<StoredContact> = live
                    .iter()
                    .filter(|(uri, _)| uri != gone)
                    .map(|(uri, expiry)| {
                        let mut kept = contact(uri, expiry - now);
                        kept.expires_at = Some(*expiry);
                        kept
                    })
                    .collect();
                backend.save(&aor, &rest).await.expect("remove contact");
                if let Some(entry) = model.get_mut(&aor) {
                    entry.remove(gone);
                    entry.retain(|_, expiry| *expiry > now);
                    if entry.is_empty() {
                        model.remove(&aor);
                    }
                }
            }
        }
        // Attach auxiliary state.
        _ => {
            backend.save_aor_state(&aor, &state()).await.expect("state");
        }
    }
}

fn live_aors(model: &Model) -> BTreeSet<String> {
    let now = epoch_now();
    model
        .iter()
        .filter(|(_, contacts)| contacts.values().any(|expiry| *expiry > now))
        .map(|(aor, _)| aor.clone())
        .collect()
}

/// The count is the index's, so it has to stay equal to the AoRs that really
/// exist through every path that changes them: register, refresh,
/// de-register, removing one contact, expiry, and two replicas writing the
/// same Redis.
#[tokio::test]
async fn the_index_count_matches_the_real_aors_after_churn() {
    let Some(url) = test_url() else { return };
    let prefix = unique_prefix("churn");
    let first = backend(&url, &prefix, 0, 7200).await;
    let second = backend(&url, &prefix, 0, 7200).await;
    let mut random = Lcg(0x5eed_1234);
    let mut model = Model::new();

    for _ in 0..300 {
        churn_step(&mut random, [&first, &second], &mut model, true).await;
    }
    // Let every one-second binding lapse, then churn again over what is left.
    tokio::time::sleep(Duration::from_millis(2_500)).await;
    for _ in 0..300 {
        churn_step(&mut random, [&first, &second], &mut model, false).await;
    }

    let expected = live_aors(&model);
    assert!(!expected.is_empty(), "the churn left nothing to count");
    assert_eq!(
        real_aors(&url, &prefix).await,
        expected,
        "keyspace vs model"
    );
    assert_eq!(first.count_aors().await.expect("count"), expected.len());
    assert_eq!(second.count_aors().await.expect("count"), expected.len());
    let listed: BTreeSet<String> = first
        .all_aors()
        .await
        .expect("all_aors")
        .into_iter()
        .collect();
    assert_eq!(listed, expected, "index vs model");

    // A third replica booting now restores exactly the same set.
    let third = backend(&url, &prefix, 0, 7200).await;
    assert_eq!(third.count_aors().await.expect("count"), expected.len());
}

/// The leak gate. Once every AoR has expired or been de-registered, nothing
/// the backend wrote is left: no binding hash, no state key, no index member.
#[tokio::test]
async fn everything_drains_when_every_aor_expires_or_deregisters() {
    let Some(url) = test_url() else { return };
    let prefix = unique_prefix("drain");
    let first = backend(&url, &prefix, 0, 7200).await;
    let second = backend(&url, &prefix, 0, 7200).await;

    for user in 0..60 {
        let aor = format!("sip:user{user}@example.com");
        let replica = if user % 2 == 0 { &first } else { &second };
        // Long enough that none lapses before the count below.
        let lifetime = if user < 30 { 3 } else { 600 };
        replica
            .save(
                &aor,
                &[
                    contact(&format!("sip:{user}@192.0.2.1:5060"), lifetime),
                    contact(&format!("sip:{user}@192.0.2.2:5060"), lifetime),
                ],
            )
            .await
            .expect("register");
        replica.save_aor_state(&aor, &state()).await.expect("state");
    }
    assert_eq!(first.count_aors().await.expect("count"), 60);

    for user in 30..60 {
        let aor = format!("sip:user{user}@example.com");
        // The other replica tears down what this one wrote.
        let replica = if user % 2 == 0 { &second } else { &first };
        if user < 45 {
            replica.remove(&aor).await.expect("deregister");
        } else {
            // Contact by contact, down to nothing.
            replica
                .save(&aor, &[contact(&format!("sip:{user}@192.0.2.2:5060"), 600)])
                .await
                .expect("remove one contact");
            replica.save(&aor, &[]).await.expect("remove the last");
        }
        replica.remove_aor_state(&aor).await.expect("state");
    }

    tokio::time::sleep(Duration::from_millis(4_000)).await;
    assert_eq!(first.count_aors().await.expect("count"), 0);
    assert_eq!(second.count_aors().await.expect("count"), 0);
    let left = keys_under(&url, &prefix).await;
    assert!(left.is_empty(), "keys left behind: {left:?}");
}

/// The periodic purge keeps the index bounded even when nothing ever asks for
/// the count.
#[tokio::test]
async fn the_purge_drops_expired_index_members() {
    let Some(url) = test_url() else { return };
    let prefix = unique_prefix("purge");
    let backend = backend(&url, &prefix, 0, 7200).await;
    for user in 0..5 {
        backend
            .save(
                &format!("sip:user{user}@example.com"),
                &[contact(&format!("sip:{user}@192.0.2.1:5060"), 1)],
            )
            .await
            .expect("register");
    }
    tokio::time::sleep(Duration::from_millis(2_500)).await;
    assert_eq!(backend.purge_expired().await.expect("purge"), 5);
    assert!(keys_under(&url, &prefix).await.is_empty());
}

/// A keyspace written without an index (an earlier version) gets one at
/// connect, so the restore and the count see every AoR from the first boot.
#[tokio::test]
async fn connect_builds_the_index_for_an_existing_keyspace() {
    let Some(url) = test_url() else { return };
    let prefix = unique_prefix("backfill");
    let mut connection = raw_connection(&url).await;
    for user in 0..7 {
        let key = format!("{prefix}sip:user{user}@example.com");
        let lifetime = if user == 6 { 0 } else { 600 };
        let mut stored = contact(&format!("sip:{user}@192.0.2.1:5060"), lifetime);
        if user == 6 {
            stored.expires_at = Some(epoch_now() - 10);
        }
        let json = serde_json::to_string(&stored).expect("json");
        let _: () = redis::cmd("HSET")
            .arg(&key)
            .arg(&stored.uri)
            .arg(json)
            .query_async(&mut connection)
            .await
            .expect("hset");
        let _: () = redis::cmd("EXPIRE")
            .arg(&key)
            .arg(700)
            .query_async(&mut connection)
            .await
            .expect("expire");
    }
    let _: () = redis::cmd("SET")
        .arg(format!("{prefix}state:sip:user0@example.com"))
        .arg(serde_json::to_string(&state()).expect("json"))
        .query_async(&mut connection)
        .await
        .expect("set state");

    let backend = backend(&url, &prefix, 30, 7200).await;
    // Six live, one whose only binding has already expired.
    assert_eq!(backend.count_aors().await.expect("count"), 6);
    assert_eq!(backend.all_aors().await.expect("all").len(), 6);

    let _: () = redis::cmd("DEL")
        .arg(
            keys_under(&url, &prefix)
                .await
                .into_iter()
                .collect::<Vec<_>>(),
        )
        .query_async(&mut connection)
        .await
        .expect("clean up");
}
