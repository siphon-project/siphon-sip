//! Named cache manager — local LRU in front of optional Redis backend.
//!
//! Each entry in `siphon.yaml` `cache:` list becomes a named cache that Python
//! scripts access via `await cache.fetch("name", "key")`.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tracing::debug;
#[cfg(feature = "redis-backend")]
use tracing::warn;

use crate::config::NamedCacheConfig;

/// A single cached value with its insertion time.
struct CacheEntry {
    value: String,
    inserted_at: Instant,
}

/// A named cache with local LRU layer and optional Redis backend.
struct NamedCache {
    /// Redis connection URL (connected lazily on first use).
    #[cfg(feature = "redis-backend")]
    url: String,

    /// Redis async connection (established lazily).
    #[cfg(feature = "redis-backend")]
    redis: tokio::sync::OnceCell<redis::aio::MultiplexedConnection>,

    /// Local LRU cache (if `local_ttl_secs` is configured).
    local: Option<Mutex<LocalLru>>,
}

/// Simple LRU-like cache with TTL expiry and max entries.
struct LocalLru {
    entries: HashMap<String, CacheEntry>,
    max_entries: usize,
    ttl: Duration,
}

impl LocalLru {
    fn new(max_entries: usize, ttl: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            max_entries,
            ttl,
        }
    }

    fn get(&self, key: &str) -> Option<&str> {
        let entry = self.entries.get(key)?;
        if entry.inserted_at.elapsed() < self.ttl {
            Some(&entry.value)
        } else {
            None
        }
    }

    fn insert(&mut self, key: String, value: String) {
        // Evict expired entries if at capacity
        if self.entries.len() >= self.max_entries {
            let ttl = self.ttl;
            self.entries.retain(|_, entry| entry.inserted_at.elapsed() < ttl);
        }
        // If still at capacity after eviction, remove oldest entry
        if self.entries.len() >= self.max_entries {
            if let Some(oldest_key) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.inserted_at)
                .map(|(key, _)| key.clone())
            {
                self.entries.remove(&oldest_key);
            }
        }
        self.entries.insert(
            key,
            CacheEntry {
                value,
                inserted_at: Instant::now(),
            },
        );
    }
}

impl NamedCache {
    fn new(config: &NamedCacheConfig) -> Self {
        let local = match (config.local_ttl_secs, config.local_max_entries) {
            (Some(ttl_secs), max_entries) => Some(Mutex::new(LocalLru::new(
                max_entries.unwrap_or(10_000),
                Duration::from_secs(ttl_secs),
            ))),
            _ => None,
        };

        Self {
            #[cfg(feature = "redis-backend")]
            url: config.url.clone(),
            #[cfg(feature = "redis-backend")]
            redis: tokio::sync::OnceCell::new(),
            local,
        }
    }

    /// Fetch a value: check local LRU first, then Redis.
    async fn fetch(&self, key: &str) -> Option<String> {
        // 1. Check local LRU
        if let Some(local) = &self.local {
            if let Ok(lru) = local.lock() {
                if let Some(value) = lru.get(key) {
                    debug!(key = key, "cache hit (local LRU)");
                    return Some(value.to_string());
                }
            }
        }

        // 2. Check Redis (if feature enabled)
        #[cfg(feature = "redis-backend")]
        {
            match self.redis_fetch(key).await {
                Some(value) => {
                    // Insert into local LRU on Redis hit
                    if let Some(local) = &self.local {
                        if let Ok(mut lru) = local.lock() {
                            lru.insert(key.to_string(), value.clone());
                        }
                    }
                    debug!(key = key, "cache hit (Redis)");
                    return Some(value);
                }
                None => {
                    debug!(key = key, "cache miss");
                }
            }
        }

        #[cfg(not(feature = "redis-backend"))]
        {
            debug!(key = key, "cache miss (no Redis backend)");
        }

        None
    }

    /// Store a value: write to local LRU and Redis.
    async fn store(&self, key: &str, value: &str, ttl_secs: Option<u64>) {
        // Write to local LRU
        if let Some(local) = &self.local {
            if let Ok(mut lru) = local.lock() {
                lru.insert(key.to_string(), value.to_string());
            }
        }

        // Write to Redis
        #[cfg(feature = "redis-backend")]
        {
            self.redis_store(key, value, ttl_secs).await;
        }
    }

    async fn delete(&self, key: &str) {
        // Remove from local LRU
        if let Some(local) = &self.local {
            if let Ok(mut lru) = local.lock() {
                lru.entries.remove(key);
            }
        }

        // Remove from Redis
        #[cfg(feature = "redis-backend")]
        {
            self.redis_delete(key).await;
        }
    }

    #[cfg(feature = "redis-backend")]
    async fn redis_delete(&self, key: &str) {
        if let Some(mut connection) = self.get_redis_connection().await {
            if let Err(error) = redis::cmd("DEL")
                .arg(key)
                .query_async::<()>(&mut connection)
                .await
            {
                warn!(key = key, "Redis DEL failed: {error}");
            }
        }
    }

    #[cfg(feature = "redis-backend")]
    async fn get_redis_connection(&self) -> Option<redis::aio::MultiplexedConnection> {
        let connection = self
            .redis
            .get_or_try_init(|| async {
                let client = redis::Client::open(self.url.as_str())?;
                client.get_multiplexed_async_connection().await
            })
            .await;

        match connection {
            Ok(connection) => Some(connection.clone()),
            Err(error) => {
                warn!(url = %self.url, "Redis connection failed: {error}");
                None
            }
        }
    }

    #[cfg(feature = "redis-backend")]
    async fn redis_fetch(&self, key: &str) -> Option<String> {
        let mut connection = self.get_redis_connection().await?;
        match redis::cmd("GET")
            .arg(key)
            .query_async::<Option<String>>(&mut connection)
            .await
        {
            Ok(value) => value,
            Err(error) => {
                warn!(key = key, "Redis GET failed: {error}");
                None
            }
        }
    }

    #[cfg(feature = "redis-backend")]
    async fn redis_store(&self, key: &str, value: &str, ttl_secs: Option<u64>) {
        if let Some(mut connection) = self.get_redis_connection().await {
            let result = if let Some(ttl) = ttl_secs {
                redis::cmd("SETEX")
                    .arg(key)
                    .arg(ttl)
                    .arg(value)
                    .query_async::<()>(&mut connection)
                    .await
            } else {
                redis::cmd("SET")
                    .arg(key)
                    .arg(value)
                    .query_async::<()>(&mut connection)
                    .await
            };
            if let Err(error) = result {
                warn!(key = key, "Redis SET failed: {error}");
            }
        }
    }

    /// Append `item` to the right of a Redis list. Returns the new
    /// length on success, `None` when the Redis backend is unavailable
    /// or the operation failed. Local LRU is never touched — list
    /// values have no concurrent-update semantics there.
    async fn list_push(&self, key: &str, item: &str) -> Option<u64> {
        #[cfg(feature = "redis-backend")]
        {
            let mut connection = self.get_redis_connection().await?;
            match redis::cmd("RPUSH")
                .arg(key)
                .arg(item)
                .query_async::<u64>(&mut connection)
                .await
            {
                Ok(len) => Some(len),
                Err(error) => {
                    warn!(key = key, "Redis RPUSH failed: {error}");
                    None
                }
            }
        }
        #[cfg(not(feature = "redis-backend"))]
        {
            let _ = (key, item);
            debug!(key = key, "list_push: no Redis backend; dropping");
            None
        }
    }

    /// Atomically read and clear a Redis list. Returns the items in
    /// FIFO order (left-to-right), or an empty vec when the key was
    /// absent or the operation failed. Implemented via a MULTI/EXEC
    /// transaction so concurrent producers don't lose items between
    /// the `LRANGE` and the `DEL`.
    async fn list_pop_all(&self, key: &str) -> Vec<String> {
        #[cfg(feature = "redis-backend")]
        {
            let Some(mut connection) = self.get_redis_connection().await else {
                return Vec::new();
            };
            // Pipeline: LRANGE key 0 -1 ; DEL key — atomic via MULTI/EXEC.
            let result: Result<(Vec<String>, ()), _> = redis::pipe()
                .atomic()
                .cmd("LRANGE")
                .arg(key)
                .arg(0)
                .arg(-1)
                .cmd("DEL")
                .arg(key)
                .query_async(&mut connection)
                .await;
            match result {
                Ok((items, _)) => items,
                Err(error) => {
                    warn!(key = key, "Redis list_pop_all failed: {error}");
                    Vec::new()
                }
            }
        }
        #[cfg(not(feature = "redis-backend"))]
        {
            let _ = key;
            debug!(key = key, "list_pop_all: no Redis backend; returning empty");
            Vec::new()
        }
    }

    /// Set a TTL (seconds) on an existing key. Returns `true` if the
    /// timeout was set, `false` when the key did not exist or the
    /// backend rejected the command.
    async fn expire(&self, key: &str, ttl_secs: u64) -> bool {
        #[cfg(feature = "redis-backend")]
        {
            let Some(mut connection) = self.get_redis_connection().await else {
                return false;
            };
            // Redis EXPIRE returns 1 when the timeout was set, 0 when
            // the key did not exist.
            match redis::cmd("EXPIRE")
                .arg(key)
                .arg(ttl_secs)
                .query_async::<i64>(&mut connection)
                .await
            {
                Ok(set) => set == 1,
                Err(error) => {
                    warn!(key = key, "Redis EXPIRE failed: {error}");
                    false
                }
            }
        }
        #[cfg(not(feature = "redis-backend"))]
        {
            let _ = (key, ttl_secs);
            false
        }
    }

    /// Check if `key` exists in this cache. Considers the local LRU
    /// first (cheap, in-process), then Redis. Local-only caches answer
    /// from the LRU alone.
    async fn exists(&self, key: &str) -> bool {
        if let Some(local) = &self.local {
            if let Ok(lru) = local.lock() {
                if lru.get(key).is_some() {
                    return true;
                }
            }
        }
        #[cfg(feature = "redis-backend")]
        {
            let Some(mut connection) = self.get_redis_connection().await else {
                return false;
            };
            match redis::cmd("EXISTS")
                .arg(key)
                .query_async::<i64>(&mut connection)
                .await
            {
                Ok(present) => present > 0,
                Err(error) => {
                    warn!(key = key, "Redis EXISTS failed: {error}");
                    false
                }
            }
        }
        #[cfg(not(feature = "redis-backend"))]
        {
            false
        }
    }
}

/// Manages all named caches configured in `siphon.yaml`.
pub struct CacheManager {
    caches: HashMap<String, NamedCache>,
}

impl CacheManager {
    /// Create a CacheManager from the config's cache list.
    pub fn new(configs: &[NamedCacheConfig]) -> Self {
        let caches = configs
            .iter()
            .map(|config| (config.name.clone(), NamedCache::new(config)))
            .collect();
        Self { caches }
    }

    /// Create an empty CacheManager (no caches configured).
    pub fn empty() -> Self {
        Self {
            caches: HashMap::new(),
        }
    }

    /// Fetch a value from a named cache.
    pub async fn fetch(&self, name: &str, key: &str) -> Option<String> {
        let cache = self.caches.get(name)?;
        cache.fetch(key).await
    }

    /// Store a value in a named cache with optional TTL.
    pub async fn store(&self, name: &str, key: &str, value: &str, ttl_secs: Option<u64>) -> bool {
        if let Some(cache) = self.caches.get(name) {
            cache.store(key, value, ttl_secs).await;
            true
        } else {
            false
        }
    }

    /// Delete a key from a named cache.
    pub async fn delete(&self, name: &str, key: &str) -> bool {
        if let Some(cache) = self.caches.get(name) {
            cache.delete(key).await;
            true
        } else {
            false
        }
    }

    /// Check if a named cache exists.
    pub fn has_cache(&self, name: &str) -> bool {
        self.caches.contains_key(name)
    }

    /// Append `item` to a Redis list under `key`. Returns the list's
    /// new length on success; `None` if the named cache is unknown,
    /// the Redis backend is unavailable, or the command failed.
    pub async fn list_push(&self, name: &str, key: &str, item: &str) -> Option<u64> {
        self.caches.get(name)?.list_push(key, item).await
    }

    /// Atomically drain a Redis list — returns all items in FIFO order
    /// and deletes the key. Empty vec when the cache is unknown, the
    /// key is absent, or Redis is unavailable.
    pub async fn list_pop_all(&self, name: &str, key: &str) -> Vec<String> {
        match self.caches.get(name) {
            Some(cache) => cache.list_pop_all(key).await,
            None => Vec::new(),
        }
    }

    /// Set a TTL (seconds) on an existing key. Returns `true` if the
    /// timeout was set, `false` if the cache is unknown, the key did
    /// not exist, or the backend rejected the command.
    pub async fn expire(&self, name: &str, key: &str, ttl_secs: u64) -> bool {
        match self.caches.get(name) {
            Some(cache) => cache.expire(key, ttl_secs).await,
            None => false,
        }
    }

    /// Check if `key` exists in the named cache (local LRU or Redis).
    pub async fn exists(&self, name: &str, key: &str) -> bool {
        match self.caches.get(name) {
            Some(cache) => cache.exists(key).await,
            None => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config(name: &str, ttl_secs: Option<u64>, max_entries: Option<usize>) -> NamedCacheConfig {
        NamedCacheConfig {
            name: name.to_string(),
            // Use a bogus URL so tests never hit a real Redis instance
            url: "redis://127.0.0.1:1".to_string(),
            local_ttl_secs: ttl_secs,
            local_max_entries: max_entries,
        }
    }

    #[tokio::test]
    async fn local_lru_hit_and_miss() {
        let manager = CacheManager::new(&[make_config("test", Some(60), Some(100))]);
        // Miss on empty
        assert!(manager.fetch("test", "key1").await.is_none());

        // Store and hit
        manager.store("test", "key1", "value1", None).await;
        assert_eq!(manager.fetch("test", "key1").await.unwrap(), "value1");
    }

    #[tokio::test]
    async fn local_lru_ttl_expiry() {
        let configs = [NamedCacheConfig {
            name: "ttl_test".to_string(),
            url: "redis://127.0.0.1:1".to_string(),
            local_ttl_secs: Some(0), // 0-second TTL = expires immediately
            local_max_entries: Some(100),
        }];
        let manager = CacheManager::new(&configs);

        manager.store("ttl_test", "key1", "value1", None).await;
        // With 0s TTL, entry should be expired immediately
        std::thread::sleep(Duration::from_millis(10));
        assert!(manager.fetch("ttl_test", "key1").await.is_none());
    }

    #[tokio::test]
    async fn local_lru_max_entries_eviction() {
        let manager = CacheManager::new(&[make_config("small", Some(60), Some(2))]);

        manager.store("small", "key1", "v1", None).await;
        manager.store("small", "key2", "v2", None).await;
        manager.store("small", "key3", "v3", None).await; // Should evict oldest

        // key3 and key2 should be present, key1 evicted
        assert!(manager.fetch("small", "key3").await.is_some());
        assert_eq!(manager.fetch("small", "key1").await, None);
    }

    #[tokio::test]
    async fn unknown_cache_name_returns_none() {
        let manager = CacheManager::new(&[make_config("test", Some(60), None)]);
        assert!(manager.fetch("nonexistent", "key").await.is_none());
    }

    #[tokio::test]
    async fn empty_manager() {
        let manager = CacheManager::empty();
        assert!(manager.fetch("any", "key").await.is_none());
        assert!(!manager.has_cache("any"));
    }

    #[tokio::test]
    async fn store_returns_false_for_unknown_cache() {
        let manager = CacheManager::empty();
        assert!(!manager.store("nope", "key", "value", None).await);
    }

    #[test]
    fn has_cache() {
        let manager = CacheManager::new(&[make_config("cnam", Some(60), None)]);
        assert!(manager.has_cache("cnam"));
        assert!(!manager.has_cache("other"));
    }

    // -----------------------------------------------------------------
    // List ops + expire + exists
    // -----------------------------------------------------------------
    //
    // The integration tests use a bogus Redis URL on port 1 — the
    // backend is unreachable. These tests therefore exercise the
    // graceful-degradation path, not the happy path. End-to-end
    // happy-path coverage lives in the production deployment with a
    // real Redis instance available; the unit tests verify that the
    // surface stays sane when Redis isn't.

    #[tokio::test]
    async fn exists_finds_value_in_local_lru_without_redis() {
        let manager = CacheManager::new(&[make_config("hot", Some(60), Some(100))]);
        manager.store("hot", "key1", "v1", None).await;
        assert!(manager.exists("hot", "key1").await);
        assert!(!manager.exists("hot", "key_missing").await);
    }

    #[tokio::test]
    async fn exists_returns_false_for_unknown_cache_name() {
        let manager = CacheManager::empty();
        assert!(!manager.exists("nope", "key").await);
    }

    #[tokio::test]
    async fn list_push_returns_none_when_redis_unreachable() {
        let manager = CacheManager::new(&[make_config("queue", None, None)]);
        // Bogus Redis URL — backend is unreachable, op degrades.
        assert!(manager.list_push("queue", "ims_queue_abc", "msg-1").await.is_none());
    }

    #[tokio::test]
    async fn list_push_returns_none_for_unknown_cache_name() {
        let manager = CacheManager::empty();
        assert!(manager.list_push("nope", "key", "item").await.is_none());
    }

    #[tokio::test]
    async fn list_pop_all_returns_empty_when_redis_unreachable() {
        let manager = CacheManager::new(&[make_config("queue", None, None)]);
        let drained = manager.list_pop_all("queue", "ims_queue_abc").await;
        assert!(drained.is_empty());
    }

    #[tokio::test]
    async fn list_pop_all_returns_empty_for_unknown_cache_name() {
        let manager = CacheManager::empty();
        let drained = manager.list_pop_all("nope", "key").await;
        assert!(drained.is_empty());
    }

    #[tokio::test]
    async fn expire_returns_false_when_redis_unreachable() {
        let manager = CacheManager::new(&[make_config("queue", None, None)]);
        assert!(!manager.expire("queue", "key", 60).await);
    }

    #[tokio::test]
    async fn expire_returns_false_for_unknown_cache_name() {
        let manager = CacheManager::empty();
        assert!(!manager.expire("nope", "key", 60).await);
    }
}
