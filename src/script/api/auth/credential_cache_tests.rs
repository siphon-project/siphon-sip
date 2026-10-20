//! The credential cache in front of the HTTP backend, driven against a
//! loopback backend that counts its lookups: realm isolation, the re-read on a
//! cached credential that fails to verify, and the store staying bounded.
//!
//! Every outcome asserted here is the verdict the challenge arm scores
//! `failed_auth_ban` on, so `Valid` after a re-read is what proves a reset
//! password is never counted as a failure.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::Router;

use super::{now_unix_secs, CredentialCheck, PyAuth};
use crate::auth::credential_cache::{CredentialKey, Invalidation};
use crate::config::{AuthBackendType, DatabaseAuthConfig, HttpAuthConfig};

/// An HTTP credential source: `GET /{realm}/{username}` answers the password,
/// or 404 for a user it does not hold.
#[derive(Default)]
struct Backend {
    /// (realm, username) → password.
    passwords: Mutex<HashMap<(String, String), String>>,
    lookups: AtomicUsize,
}

impl Backend {
    fn set(&self, realm: &str, username: &str, password: &str) {
        self.passwords.lock().unwrap().insert(
            (realm.to_string(), username.to_string()),
            password.to_string(),
        );
    }

    fn delete(&self, realm: &str, username: &str) {
        self.passwords
            .lock()
            .unwrap()
            .remove(&(realm.to_string(), username.to_string()));
    }

    fn lookups(&self) -> usize {
        self.lookups.load(Ordering::SeqCst)
    }
}

async fn answer(
    State(backend): State<Arc<Backend>>,
    Path((realm, username)): Path<(String, String)>,
) -> (StatusCode, String) {
    backend.lookups.fetch_add(1, Ordering::SeqCst);
    match backend.passwords.lock().unwrap().get(&(realm, username)) {
        Some(password) => (StatusCode::OK, password.clone()),
        None => (StatusCode::NOT_FOUND, String::new()),
    }
}

async fn start_backend() -> (Arc<Backend>, SocketAddr) {
    let backend = Arc::new(Backend::default());
    let app = Router::new()
        .route("/{realm}/{username}", get(answer))
        .with_state(Arc::clone(&backend));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (backend, address)
}

/// An auth namespace on the HTTP backend for `realm`. The realm is in the URL
/// path the way a per-tenant deployment templates it; siphon only substitutes
/// `{username}`.
fn auth_for(address: SocketAddr, realm: &str, cache_ttl_secs: u64) -> PyAuth {
    let mut auth = PyAuth::empty();
    auth.set_backend_type(AuthBackendType::Http);
    auth.set_http_config(HttpAuthConfig {
        url: format!("http://{address}/{realm}/{{username}}"),
        timeout_ms: 2000,
        connect_timeout_ms: 2000,
        ha1: false,
        cache_ttl_secs,
    })
    .unwrap();
    auth
}

fn md5_hex(input: &str) -> String {
    format!("{:x}", md5::compute(input.as_bytes()))
}

/// An `Authorization` whose response is correct for `password` (RFC 2617
/// §3.2.2, no qop), computed here rather than by the code under test.
fn digest(username: &str, realm: &str, password: &str) -> String {
    let nonce = format!("{:016x}.test", now_unix_secs());
    let digest_uri = "sip:example.com";
    let ha1 = md5_hex(&format!("{username}:{realm}:{password}"));
    let ha2 = md5_hex(&format!("REGISTER:{digest_uri}"));
    let response = md5_hex(&format!("{ha1}:{nonce}:{ha2}"));
    format!(
        "Digest username=\"{username}\", realm=\"{realm}\", nonce=\"{nonce}\", \
         uri=\"{digest_uri}\", response=\"{response}\""
    )
}

fn check(auth: &PyAuth, username: &str, realm: &str, password: &str) -> CredentialCheck {
    auth.validate_credentials(&digest(username, realm, password), realm, "REGISTER")
}

const REALM_A: &str = "tenant-a.example.com";
const REALM_B: &str = "tenant-b.example.com";

/// Two tenants number their extensions the same way. Each realm's entry
/// verifies only its own credential: one shared entry would check one tenant's
/// phone against the other's hash. The backend is unreachable, so nothing but
/// the cache can answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_same_username_in_two_realms_never_shares_a_cache_entry() {
    pyo3::Python::initialize();
    let auth = auth_for(unreachable(), REALM_A, 300);
    auth.store_credential(&CredentialKey::new(REALM_A, "1001", None), "password-a");
    auth.store_credential(&CredentialKey::new(REALM_B, "1001", None), "password-b");
    assert_eq!(
        auth.credential_cache().unwrap().len(),
        2,
        "one entry per realm"
    );

    assert_eq!(
        check(&auth, "1001", REALM_A, "password-a"),
        CredentialCheck::Valid
    );
    assert_eq!(
        check(&auth, "1001", REALM_B, "password-b"),
        CredentialCheck::Valid
    );
    assert_eq!(
        check(&auth, "1001", REALM_A, "password-b"),
        CredentialCheck::Rejected
    );
    assert_eq!(
        check(&auth, "1001", REALM_B, "password-a"),
        CredentialCheck::Rejected
    );
}

/// The database backend keys the same way, because its query binds the realm:
/// an entry cached under one realm is a miss for another, which then goes to
/// the (here unreachable) database instead of being served the wrong hash.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_database_cache_is_keyed_by_realm() {
    pyo3::Python::initialize();
    let mut auth = PyAuth::empty();
    auth.set_backend_type(AuthBackendType::Database);
    auth.set_database_config(DatabaseAuthConfig {
        url: "postgresql://127.0.0.1:9/siphon".to_string(),
        query: "SELECT ha1 FROM subscribers WHERE username = $1 AND realm = $2".to_string(),
        ha1: true,
        cache_ttl_secs: 300,
        timeout_ms: 2000,
    });
    auth.store_credential(
        &CredentialKey::new(REALM_A, "1001", Some("ha1_md5")),
        &md5_hex(&format!("1001:{REALM_A}:password")),
    );
    assert_eq!(
        check(&auth, "1001", REALM_A, "password"),
        CredentialCheck::Valid
    );
    assert_eq!(
        check(&auth, "1001", REALM_B, "password"),
        CredentialCheck::Unavailable,
        "realm B must miss the cache and ask the database, not reuse realm A's hash"
    );
}

/// A loopback port nothing listens on (9, discard): refused at once.
fn unreachable() -> SocketAddr {
    "127.0.0.1:9".parse().unwrap()
}

/// The issue's observed case: a credential changed at the source while the old
/// one is cached. The mismatch against the cached hash re-reads once, the new
/// password verifies, and the entry is replaced so the next check is a hit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_changed_password_is_accepted_after_one_re_read() {
    pyo3::Python::initialize();
    let (backend, address) = start_backend().await;
    let auth = auth_for(address, REALM_A, 300);
    backend.set(REALM_A, "1001", "old-password");

    assert_eq!(
        check(&auth, "1001", REALM_A, "old-password"),
        CredentialCheck::Valid
    );
    assert_eq!(backend.lookups(), 1);

    backend.set(REALM_A, "1001", "new-password");
    assert_eq!(
        check(&auth, "1001", REALM_A, "new-password"),
        CredentialCheck::Valid,
        "a reset password must verify, so it is never scored as a failure"
    );
    assert_eq!(backend.lookups(), 2, "exactly one re-read");

    assert_eq!(
        check(&auth, "1001", REALM_A, "new-password"),
        CredentialCheck::Valid
    );
    assert_eq!(
        backend.lookups(),
        2,
        "the replaced entry serves the next check"
    );
    assert_eq!(
        check(&auth, "1001", REALM_A, "old-password"),
        CredentialCheck::Rejected,
        "the old password no longer verifies"
    );
}

/// A user deleted at the source stops authenticating at once, not at expiry,
/// and its entry leaves the cache.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_deleted_user_is_refused_and_its_entry_dropped() {
    pyo3::Python::initialize();
    let (backend, address) = start_backend().await;
    let auth = auth_for(address, REALM_A, 300);
    let cache = auth.credential_cache().unwrap();
    backend.set(REALM_A, "1001", "password");
    assert_eq!(
        check(&auth, "1001", REALM_A, "password"),
        CredentialCheck::Valid
    );
    assert_eq!(cache.len(), 1);

    backend.delete(REALM_A, "1001");
    // The old password still matches the cached hash, which is the hit the
    // cache serves. Only a mismatch re-reads, so a deleted user is caught
    // the moment it presents anything the cache did not hold; the admin
    // flush covers the rest (see the invalidation test below).
    assert_eq!(
        check(&auth, "1001", REALM_A, "a guess"),
        CredentialCheck::Rejected
    );
    assert_eq!(backend.lookups(), 2);
    assert!(cache.is_empty(), "NotFound on the re-read drops the entry");

    assert_eq!(
        check(&auth, "1001", REALM_A, "password"),
        CredentialCheck::Rejected,
        "with the entry gone the old password reaches the backend, which no longer knows the user"
    );
    assert_eq!(backend.lookups(), 3);
}

/// A credential the cache missed is looked up once: a wrong password on a
/// fresh lookup is not re-read.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fresh_lookup_is_never_read_twice() {
    pyo3::Python::initialize();
    let (backend, address) = start_backend().await;
    let auth = auth_for(address, REALM_A, 300);
    backend.set(REALM_A, "1001", "password");

    assert_eq!(
        check(&auth, "1001", REALM_A, "wrong"),
        CredentialCheck::Rejected
    );
    assert_eq!(backend.lookups(), 1);

    // Caching off: every check is one fresh lookup, never two.
    let uncached = auth_for(address, REALM_A, 0);
    assert_eq!(
        check(&uncached, "1001", REALM_A, "wrong"),
        CredentialCheck::Rejected
    );
    assert_eq!(backend.lookups(), 2);
}

/// The awaitable driver the script APIs use takes the same path.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_awaitable_driver_re_reads_a_stale_credential_too() {
    pyo3::Python::initialize();
    let (backend, address) = start_backend().await;
    let auth = auth_for(address, REALM_A, 300);
    backend.set(REALM_A, "1001", "old-password");
    let run = |password: &'static str| {
        let auth = auth.clone();
        async move {
            auth.validate_http_async(&digest("1001", REALM_A, password), REALM_A, "REGISTER")
                .await
        }
    };

    assert_eq!(run("old-password").await, CredentialCheck::Valid);
    backend.set(REALM_A, "1001", "new-password");
    assert_eq!(run("new-password").await, CredentialCheck::Valid);
    assert_eq!(backend.lookups(), 2);
    backend.delete(REALM_A, "1001");
    assert_eq!(run("a guess").await, CredentialCheck::Rejected);
    assert!(auth.credential_cache().unwrap().is_empty());
}

/// A backend that cannot answer the re-read leaves the cached verdict
/// standing: still a rejection, and the entry is kept.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unreachable_re_read_keeps_the_cached_verdict() {
    pyo3::Python::initialize();
    let auth = auth_for(unreachable(), REALM_A, 300);
    auth.store_credential(&CredentialKey::new(REALM_A, "1001", None), "password");
    assert_eq!(
        check(&auth, "1001", REALM_A, "wrong"),
        CredentialCheck::Rejected
    );
    assert_eq!(
        check(&auth, "1001", REALM_A, "password"),
        CredentialCheck::Valid
    );
    assert_eq!(auth.credential_cache().unwrap().len(), 1);
}

/// What the admin flush does to the live path: after invalidating one user the
/// next check reaches the backend, so even a deleted user's old password stops
/// working without waiting out the TTL.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalidating_a_user_sends_the_next_check_to_the_backend() {
    pyo3::Python::initialize();
    let (backend, address) = start_backend().await;
    let auth = auth_for(address, REALM_A, 300);
    let cache = auth.credential_cache().unwrap();
    backend.set(REALM_A, "1001", "password");
    assert_eq!(
        check(&auth, "1001", REALM_A, "password"),
        CredentialCheck::Valid
    );

    backend.delete(REALM_A, "1001");
    assert_eq!(
        check(&auth, "1001", REALM_A, "password"),
        CredentialCheck::Valid,
        "served from the cache until flushed"
    );
    cache.invalidate(&Invalidation::User {
        realm: REALM_A.to_string(),
        username: "1001".to_string(),
    });
    assert_eq!(
        check(&auth, "1001", REALM_A, "password"),
        CredentialCheck::Rejected
    );
}

/// Leak gate for the cache on the live path: repeated authentication holds one
/// entry per distinct user, and a flush drains it to zero.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repeated_auth_holds_one_entry_per_user_and_drains_on_flush() {
    pyo3::Python::initialize();
    let (backend, address) = start_backend().await;
    let auth = auth_for(address, REALM_A, 300);
    let cache = auth.credential_cache().unwrap();
    let users = 20;
    for user in 0..users {
        backend.set(REALM_A, &format!("{}", 1000 + user), "password");
    }
    for _round in 0..10 {
        for user in 0..users {
            assert_eq!(
                check(&auth, &format!("{}", 1000 + user), REALM_A, "password"),
                CredentialCheck::Valid
            );
        }
    }
    assert_eq!(cache.len(), users);
    assert_eq!(
        backend.lookups(),
        users,
        "every round after the first is a hit"
    );

    cache.invalidate(&Invalidation::All);
    assert_eq!(cache.len(), 0);
}
