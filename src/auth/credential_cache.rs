//! The TTL cache of credential lookups behind `auth.http` and `auth.database`.
//!
//! One cache for both backends: they answer the same question (the stored
//! credential for a user in a realm) and only one is ever the configured
//! backend. It flattens a registration storm, which would otherwise turn into
//! one backend fetch per REGISTER.
//!
//! Entries are keyed by realm, username and (for a database holding one H(A1)
//! column per hash, RFC 8760) the column. The realm is part of the key because
//! the lookup binds it: two tenants numbering their extensions the same way
//! hold two different credentials under one username, and an entry shared
//! between them checks one tenant's phone against the other's hash.
//!
//! A cached entry can go stale when the credential changes at the source. The
//! cache does not rely on the TTL alone for that: the digest path re-reads the
//! backend once when a cached credential fails to verify, and
//! `POST /admin/auth/cache/invalidate` drops entries on demand, so a
//! controller that writes credentials can flush them as it writes.

use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use dashmap::DashMap;

/// What identifies one cached credential.
///
/// A struct rather than a joined string so no username can collide with
/// another realm's: a separator in a joined key is just another character an
/// attacker-controlled username may contain.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct CredentialKey {
    realm: String,
    username: String,
    /// The H(A1) column the credential was read from, when the database holds
    /// one per hash. `None` for a single-credential source.
    column: Option<&'static str>,
}

impl CredentialKey {
    pub(crate) fn new(realm: &str, username: &str, column: Option<&'static str>) -> Self {
        Self {
            realm: realm.to_string(),
            username: username.to_string(),
            column,
        }
    }

    pub(crate) fn username(&self) -> &str {
        &self.username
    }
}

/// One cached lookup, with when it was read so the TTL can be checked on use.
#[derive(Debug, Clone)]
struct CachedCredential {
    /// The stored credential: an H(A1) hex string or a plaintext password.
    value: String,
    fetched_at: Instant,
}

/// Which entries an invalidation drops.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Invalidation {
    /// Every entry.
    All,
    /// Every entry of one realm.
    Realm(String),
    /// One user's entries in one realm (every H(A1) column of it).
    User { realm: String, username: String },
}

/// The credential cache. Cheap to share: callers hold it behind an `Arc`.
#[derive(Debug, Default)]
pub struct CredentialCache {
    entries: DashMap<CredentialKey, CachedCredential>,
}

/// Whether a cache entry of the given age is still within its TTL.
/// Pure so the boundary is unit-testable without touching the clock.
fn is_fresh(age: Duration, ttl: Duration) -> bool {
    age < ttl
}

impl CredentialCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// The cached credential for `key`, if it is still within `ttl_secs`.
    /// An expired entry misses and is left for the next lookup to overwrite.
    pub(crate) fn get(&self, key: &CredentialKey, ttl_secs: u64) -> Option<String> {
        if ttl_secs == 0 {
            return None;
        }
        let entry = self.entries.get(key)?;
        is_fresh(entry.fetched_at.elapsed(), Duration::from_secs(ttl_secs))
            .then(|| entry.value.clone())
    }

    /// Record a lookup the backend answered, replacing any older entry.
    pub(crate) fn store(&self, key: &CredentialKey, value: &str) {
        self.entries.insert(
            key.clone(),
            CachedCredential {
                value: value.to_string(),
                fetched_at: Instant::now(),
            },
        );
    }

    /// Drop one entry: the backend no longer knows the user.
    pub(crate) fn remove(&self, key: &CredentialKey) {
        self.entries.remove(key);
    }

    /// Drop the entries `scope` names. Returns how many went.
    pub fn invalidate(&self, scope: &Invalidation) -> usize {
        let before = self.entries.len();
        match scope {
            Invalidation::All => self.entries.clear(),
            Invalidation::Realm(realm) => self.entries.retain(|key, _| key.realm != *realm),
            Invalidation::User { realm, username } => self
                .entries
                .retain(|key, _| key.realm != *realm || key.username != *username),
        }
        before.saturating_sub(self.entries.len())
    }

    /// How many entries the cache holds, expired ones included.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// The cache this process's `auth` namespace uses, registered at start-up so
/// the admin API can flush it. Unset when caching is off.
static INSTALLED: OnceLock<Arc<CredentialCache>> = OnceLock::new();

/// Register the process's credential cache. Only the first call takes effect;
/// the namespace is built once at start-up.
pub fn install(cache: Arc<CredentialCache>) {
    if INSTALLED.set(cache).is_err() {
        tracing::warn!("credential cache already installed; keeping the first one");
    }
}

/// The registered credential cache, if caching is on.
pub fn installed() -> Option<&'static Arc<CredentialCache>> {
    INSTALLED.get()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(realm: &str, username: &str, column: Option<&'static str>) -> CredentialKey {
        CredentialKey::new(realm, username, column)
    }

    #[test]
    fn freshness_boundary() {
        let ttl = Duration::from_secs(300);
        assert!(is_fresh(Duration::ZERO, ttl));
        assert!(is_fresh(Duration::from_secs(299), ttl));
        assert!(!is_fresh(Duration::from_secs(300), ttl));
        assert!(!is_fresh(Duration::from_secs(301), ttl));
    }

    #[test]
    fn miss_then_store_then_hit() {
        let cache = CredentialCache::new();
        let alice = key("example.com", "alice", None);
        assert!(cache.get(&alice, 300).is_none());
        cache.store(&alice, "deadbeef");
        assert_eq!(cache.get(&alice, 300).as_deref(), Some("deadbeef"));
        assert!(cache.get(&alice, 0).is_none(), "a ttl of 0 always misses");
    }

    /// The bug this key exists for: the same username in two realms is two
    /// credentials, and neither may be served for the other.
    #[test]
    fn the_same_username_in_two_realms_is_two_entries() {
        let cache = CredentialCache::new();
        cache.store(&key("tenant-a.example.com", "1001", None), "hash-a");
        cache.store(&key("tenant-b.example.com", "1001", None), "hash-b");
        assert_eq!(
            cache
                .get(&key("tenant-a.example.com", "1001", None), 300)
                .as_deref(),
            Some("hash-a")
        );
        assert_eq!(
            cache
                .get(&key("tenant-b.example.com", "1001", None), 300)
                .as_deref(),
            Some("hash-b")
        );
        assert_eq!(cache.len(), 2);
    }

    /// A separator inside a username cannot reach another realm's entry.
    #[test]
    fn a_separator_in_a_username_does_not_collide_across_realms() {
        let cache = CredentialCache::new();
        cache.store(&key("a|b", "c", None), "first");
        assert!(cache.get(&key("a", "b|c", None), 300).is_none());
    }

    #[test]
    fn store_replaces_an_older_entry() {
        let cache = CredentialCache::new();
        let alice = key("example.com", "alice", Some("ha1_md5"));
        cache.store(&alice, "old");
        cache.store(&alice, "new");
        assert_eq!(cache.get(&alice, 300).as_deref(), Some("new"));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn remove_drops_one_entry() {
        let cache = CredentialCache::new();
        let alice = key("example.com", "alice", None);
        let bob = key("example.com", "bob", None);
        cache.store(&alice, "a");
        cache.store(&bob, "b");
        cache.remove(&alice);
        assert!(cache.get(&alice, 300).is_none());
        assert_eq!(cache.get(&bob, 300).as_deref(), Some("b"));
    }

    fn populated() -> CredentialCache {
        let cache = CredentialCache::new();
        cache.store(&key("a.example.com", "1001", Some("ha1_md5")), "x");
        cache.store(&key("a.example.com", "1001", Some("ha1_sha256")), "x");
        cache.store(&key("a.example.com", "1002", Some("ha1_md5")), "x");
        cache.store(&key("b.example.com", "1001", Some("ha1_md5")), "x");
        cache
    }

    #[test]
    fn invalidating_a_user_drops_every_column_of_that_user_in_that_realm_only() {
        let cache = populated();
        let removed = cache.invalidate(&Invalidation::User {
            realm: "a.example.com".to_string(),
            username: "1001".to_string(),
        });
        assert_eq!(removed, 2);
        assert!(cache
            .get(&key("a.example.com", "1002", Some("ha1_md5")), 300)
            .is_some());
        assert!(cache
            .get(&key("b.example.com", "1001", Some("ha1_md5")), 300)
            .is_some());
    }

    #[test]
    fn invalidating_a_realm_leaves_the_other_realms() {
        let cache = populated();
        assert_eq!(
            cache.invalidate(&Invalidation::Realm("a.example.com".to_string())),
            3
        );
        assert_eq!(cache.len(), 1);
        assert!(cache
            .get(&key("b.example.com", "1001", Some("ha1_md5")), 300)
            .is_some());
    }

    #[test]
    fn invalidating_all_empties_the_cache() {
        let cache = populated();
        assert_eq!(cache.invalidate(&Invalidation::All), 4);
        assert!(cache.is_empty());
        assert_eq!(cache.invalidate(&Invalidation::All), 0);
    }

    /// Per-module leak gate: the store holds one entry per distinct
    /// (realm, user, column) however often each is refreshed, and drains to
    /// zero on a flush.
    #[test]
    fn the_store_is_bounded_by_distinct_users_and_drains_on_flush() {
        let cache = CredentialCache::new();
        for _round in 0..50 {
            for user in 0..200 {
                cache.store(
                    &key("example.com", &format!("{user}"), Some("ha1_md5")),
                    "hash",
                );
            }
        }
        assert_eq!(cache.len(), 200);
        cache.invalidate(&Invalidation::All);
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn concurrent_store_and_invalidate() {
        let cache = Arc::new(CredentialCache::new());
        let workers: Vec<_> = (0..4)
            .map(|worker| {
                let cache = Arc::clone(&cache);
                std::thread::spawn(move || {
                    for user in 0..100 {
                        cache.store(
                            &key(&format!("realm-{worker}"), &format!("{user}"), None),
                            "hash",
                        );
                        if user % 10 == 0 {
                            cache.invalidate(&Invalidation::Realm(format!("realm-{worker}")));
                        }
                    }
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }
        assert!(cache.len() <= 400);
        cache.invalidate(&Invalidation::All);
        assert!(cache.is_empty());
    }
}
