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

#[cfg(feature = "redis-backend")]
mod health;

/// The `op` label values of `siphon_cache_errors_total`.
#[cfg(feature = "redis-backend")]
const OPS: [&str; 9] = [
    "get", "set", "del", "exists", "expire", "rpush", "pop_all", "llen", "scan",
];

/// Escape Redis glob metacharacters (`* ? [ ] \`) so a `SCAN MATCH`
/// prefix is matched literally. Backslash is escaped first (it is the
/// glob escape char) by handling it in the same per-char pass.
#[cfg(feature = "redis-backend")]
fn escape_glob(input: &str) -> String {
    let mut escaped = String::with_capacity(input.len());
    for ch in input.chars() {
        if matches!(ch, '\\' | '*' | '?' | '[' | ']') {
            escaped.push('\\');
        }
        escaped.push(ch);
    }
    escaped
}

/// A single cached value with its insertion time.
struct CacheEntry {
    value: String,
    inserted_at: Instant,
}

/// A named cache with local LRU layer and optional Redis backend.
struct NamedCache {
    /// Redis connection URL (connected lazily on first use).
    #[cfg(feature = "redis-backend")]
    target: crate::redis_target::RedisTarget,

    /// Redis async connection (established lazily).
    #[cfg(feature = "redis-backend")]
    redis: tokio::sync::OnceCell<crate::redis_target::RedisConnection>,

    /// Whether that connection's server is reachable.
    #[cfg(feature = "redis-backend")]
    health: std::sync::Arc<health::BackendHealth>,

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
            self.entries
                .retain(|_, entry| entry.inserted_at.elapsed() < ttl);
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
            target: config.target.clone(),
            #[cfg(feature = "redis-backend")]
            redis: tokio::sync::OnceCell::new(),
            #[cfg(feature = "redis-backend")]
            health: std::sync::Arc::new(health::BackendHealth::new(
                &config.name,
                config.required_for_readiness,
            )),
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
    ///
    /// `ttl_secs` is the Redis expiry; the local LRU bounds itself by size, so
    /// without `redis-backend` there is nothing to apply it to.
    #[cfg_attr(not(feature = "redis-backend"), allow(unused_variables))]
    async fn store(&self, key: &str, value: &str, ttl_secs: Option<u64>) -> bool {
        // Write to local LRU
        if let Some(local) = &self.local {
            if let Ok(mut lru) = local.lock() {
                lru.insert(key.to_string(), value.to_string());
            }
        }

        // Write to Redis
        #[cfg(feature = "redis-backend")]
        {
            return self.redis_store(key, value, ttl_secs).await;
        }
        #[cfg(not(feature = "redis-backend"))]
        true
    }

    async fn delete(&self, key: &str) -> bool {
        // Remove from local LRU
        if let Some(local) = &self.local {
            if let Ok(mut lru) = local.lock() {
                lru.entries.remove(key);
            }
        }

        // Remove from Redis
        #[cfg(feature = "redis-backend")]
        {
            return self.redis_delete(key).await;
        }
        #[cfg(not(feature = "redis-backend"))]
        true
    }

    #[cfg(feature = "redis-backend")]
    async fn redis_delete(&self, key: &str) -> bool {
        let Some(mut connection) = self.connection("del").await else {
            return false;
        };
        let result = redis::cmd("DEL")
            .arg(key)
            .query_async::<()>(&mut connection)
            .await;
        self.settle("del", key, result).is_some()
    }

    /// The connection for one `op`, or `None` (counted as a failed `op`) when
    /// the backend is marked down or cannot be reached. A down backend is not
    /// dialled per command: the caller gets its answer at once, and the
    /// monitor and one trial command per interval do the redialling.
    #[cfg(feature = "redis-backend")]
    async fn connection(&self, op: &'static str) -> Option<crate::redis_target::RedisConnection> {
        if !self.health.admit() {
            crate::metrics::cache::record_error(self.health.cache(), op);
            debug!(cache = %self.health.cache(), op, "cache: Redis backend is down, not tried");
            return None;
        }
        match self.connect().await {
            Ok(connection) => Some(connection),
            Err(error) => {
                crate::metrics::cache::record_error(self.health.cache(), op);
                self.health.mark_down(&error);
                None
            }
        }
    }

    #[cfg(feature = "redis-backend")]
    async fn connect(&self) -> redis::RedisResult<crate::redis_target::RedisConnection> {
        self.redis
            .get_or_try_init(|| async {
                crate::redis_target::RedisConnection::connect(self.target.clone()).await
            })
            .await
            .cloned()
    }

    /// Record how `op` ended: a success marks the backend up, a failure is
    /// counted, and one that says the link or the primary is gone marks the
    /// backend down. Any other failure is logged on its own and leaves the
    /// state alone: the server refusing this command (`WRONGTYPE`, ...), or
    /// one command running past its deadline (a `SCAN` of a large keyspace),
    /// which a server that still answers `PING` is not down for. A server
    /// that answers nothing at all is found by the monitor's probe.
    #[cfg(feature = "redis-backend")]
    fn settle<T>(&self, op: &'static str, key: &str, result: redis::RedisResult<T>) -> Option<T> {
        match result {
            Ok(value) => {
                self.health.mark_up();
                Some(value)
            }
            Err(error) => {
                crate::metrics::cache::record_error(self.health.cache(), op);
                if crate::redis_target::is_link_failure(&error) && !error.is_timeout() {
                    self.health.mark_down(&error);
                } else {
                    warn!(cache = %self.health.cache(), op, key, "Redis command failed: {error}");
                }
                None
            }
        }
    }

    /// [`settle`](Self::settle) for a command that was sent at most once. Its
    /// link failure does not say the backend is down: the connection may have
    /// died idle and been redialled since, which a replayed command would
    /// have shown. A probe on the redialled connection decides instead.
    #[cfg(feature = "redis-backend")]
    async fn settle_unreplayed<T>(
        &self,
        op: &'static str,
        key: &str,
        result: redis::RedisResult<T>,
    ) -> Option<T> {
        match result {
            Err(error) if crate::redis_target::is_link_failure(&error) => {
                crate::metrics::cache::record_error(self.health.cache(), op);
                debug!(cache = %self.health.cache(), op, key, "Redis command not replayed: {error}");
                self.probe().await;
                None
            }
            result => self.settle(op, key, result),
        }
    }

    /// One `PING`, whatever the backend's state: the monitor's probe.
    #[cfg(feature = "redis-backend")]
    async fn probe(&self) {
        match self.connect().await {
            Ok(mut connection) => {
                let result = redis::cmd("PING")
                    .query_async::<String>(&mut connection)
                    .await;
                match result {
                    Ok(_) => self.health.mark_up(),
                    Err(error) => self.health.mark_down(&error),
                }
            }
            Err(error) => self.health.mark_down(&error),
        }
    }

    #[cfg(feature = "redis-backend")]
    async fn redis_fetch(&self, key: &str) -> Option<String> {
        let mut connection = self.connection("get").await?;
        let result = redis::cmd("GET")
            .arg(key)
            .query_async::<Option<String>>(&mut connection)
            .await;
        self.settle("get", key, result).flatten()
    }

    #[cfg(feature = "redis-backend")]
    async fn redis_store(&self, key: &str, value: &str, ttl_secs: Option<u64>) -> bool {
        let Some(mut connection) = self.connection("set").await else {
            return false;
        };
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
        self.settle("set", key, result).is_some()
    }

    /// Append `item` to the right of a Redis list. Returns the new
    /// length on success, `None` when the Redis backend is unavailable
    /// or the operation failed. Local LRU is never touched — list
    /// values have no concurrent-update semantics there.
    async fn list_push(&self, key: &str, item: &str) -> Option<u64> {
        #[cfg(feature = "redis-backend")]
        {
            let connection = self.connection("rpush").await?;
            // Not idempotent: a replay after a lost reply would queue the
            // item twice, so the command is sent at most once.
            let result = redis::cmd("RPUSH")
                .arg(key)
                .arg(item)
                .query_async::<u64>(&mut connection.at_most_once())
                .await;
            self.settle_unreplayed("rpush", key, result).await
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
            let Some(connection) = self.connection("pop_all").await else {
                return Vec::new();
            };
            // Pipeline: LRANGE key 0 -1 ; DEL key — atomic via MULTI/EXEC.
            // Sent at most once: a replay after a lost reply would find the
            // list already deleted and return nothing for the items the first
            // attempt removed.
            let result: Result<(Vec<String>, ()), _> = redis::pipe()
                .atomic()
                .cmd("LRANGE")
                .arg(key)
                .arg(0)
                .arg(-1)
                .cmd("DEL")
                .arg(key)
                .query_async(&mut connection.at_most_once())
                .await;
            self.settle_unreplayed("pop_all", key, result)
                .await
                .map(|(items, _)| items)
                .unwrap_or_default()
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
            let Some(mut connection) = self.connection("expire").await else {
                return false;
            };
            // Redis EXPIRE returns 1 when the timeout was set, 0 when
            // the key did not exist.
            let result = redis::cmd("EXPIRE")
                .arg(key)
                .arg(ttl_secs)
                .query_async::<i64>(&mut connection)
                .await;
            self.settle("expire", key, result) == Some(1)
        }
        #[cfg(not(feature = "redis-backend"))]
        {
            let _ = (key, ttl_secs);
            false
        }
    }

    /// Return the length of the Redis list under `key` (`LLEN`).
    /// `Some(0)` for a missing key — Redis `LLEN` of an absent key is
    /// 0 — and `None` when the Redis backend is unavailable or the
    /// command failed. Local LRU is never consulted; list values live
    /// only in Redis (consistent with `list_push`).
    async fn list_len(&self, key: &str) -> Option<u64> {
        #[cfg(feature = "redis-backend")]
        {
            let mut connection = self.connection("llen").await?;
            let result = redis::cmd("LLEN")
                .arg(key)
                .query_async::<u64>(&mut connection)
                .await;
            self.settle("llen", key, result)
        }
        #[cfg(not(feature = "redis-backend"))]
        {
            let _ = key;
            debug!(key = key, "list_len: no Redis backend; returning None");
            None
        }
    }

    /// Sum `LLEN` over every key matching `{prefix}*`, computed
    /// server-side so the caller gets the total in one await. Cursor
    /// `SCAN MATCH {prefix}* COUNT 512` (deduped into a `HashSet`, since
    /// SCAN may repeat keys under concurrent writes), then a pipelined
    /// `LLEN` over the deduped set. Returns `Some(0)` when nothing
    /// matches, `None` when the Redis backend is unavailable or a Redis
    /// error occurred mid-iteration.
    ///
    /// `SCAN` is O(keyspace of that Redis DB) — intended for a dedicated
    /// queue DB. Glob metacharacters (`* ? [ ] \`) in `prefix` are
    /// escaped so an arbitrary prefix is matched literally.
    async fn list_len_sum(&self, prefix: &str) -> Option<u64> {
        #[cfg(feature = "redis-backend")]
        {
            let mut connection = self.connection("scan").await?;
            let pattern = format!("{}*", escape_glob(prefix));
            let mut keys: std::collections::HashSet<String> = std::collections::HashSet::new();
            let mut cursor: u64 = 0;
            loop {
                let result = redis::cmd("SCAN")
                    .arg(cursor)
                    .arg("MATCH")
                    .arg(&pattern)
                    .arg("COUNT")
                    .arg(512)
                    .query_async(&mut connection)
                    .await;
                let (next_cursor, batch): (u64, Vec<String>) =
                    self.settle("scan", prefix, result)?;
                keys.extend(batch);
                cursor = next_cursor;
                if cursor == 0 {
                    break;
                }
            }
            if keys.is_empty() {
                return Some(0);
            }
            let mut pipe = redis::pipe();
            for key in &keys {
                pipe.cmd("LLEN").arg(key);
            }
            let result = pipe.query_async::<Vec<u64>>(&mut connection).await;
            self.settle("llen", prefix, result)
                .map(|lengths| lengths.iter().sum())
        }
        #[cfg(not(feature = "redis-backend"))]
        {
            let _ = prefix;
            debug!(
                prefix = prefix,
                "list_len_sum: no Redis backend; returning None"
            );
            None
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
            let Some(mut connection) = self.connection("exists").await else {
                return false;
            };
            let result = redis::cmd("EXISTS")
                .arg(key)
                .query_async::<i64>(&mut connection)
                .await;
            self.settle("exists", key, result)
                .is_some_and(|present| present > 0)
        }
        #[cfg(not(feature = "redis-backend"))]
        {
            false
        }
    }
}

/// Manages all named caches configured in `siphon.yaml`.
pub struct CacheManager {
    /// Shared with each cache's monitor task, which holds its own cache only
    /// weakly between probes.
    caches: HashMap<String, std::sync::Arc<NamedCache>>,
}

impl CacheManager {
    /// Create a CacheManager from the config's cache list.
    pub fn new(configs: &[NamedCacheConfig]) -> Self {
        let caches = configs
            .iter()
            .map(|config| {
                (
                    config.name.clone(),
                    std::sync::Arc::new(NamedCache::new(config)),
                )
            })
            .collect();
        Self { caches }
    }

    /// Create an empty CacheManager (no caches configured).
    pub fn empty() -> Self {
        Self {
            caches: HashMap::new(),
        }
    }

    /// Watch the Redis backend of every cache and take part in readiness.
    ///
    /// Starts one monitor task per cache, which probes the backend once a
    /// second until the manager is dropped, and registers the caches with
    /// `participants`: `/admin/ready` then answers 503 while the backend of a
    /// cache marked `required_for_readiness` (off by default) is unreachable
    /// or has not answered yet. A cache not marked is probed and measured the
    /// same and never holds readiness back. Does nothing, and registers
    /// nothing, when no cache is configured. Must be called from inside a
    /// Tokio runtime.
    pub fn watch_backends(&self, participants: &crate::lifecycle::Participants) {
        #[cfg(feature = "redis-backend")]
        {
            if self.caches.is_empty() {
                return;
            }
            let mut backends = Vec::with_capacity(self.caches.len());
            for (name, cache) in &self.caches {
                crate::metrics::cache::declare(name, &OPS);
                backends.push(std::sync::Arc::clone(&cache.health));
                // Each task holds its own cache, and only for the length of a
                // probe: it ends once the manager is gone, however long the
                // probes of the other caches take.
                let cache = std::sync::Arc::downgrade(cache);
                tokio::spawn(async move {
                    loop {
                        let Some(cache) = cache.upgrade() else {
                            return;
                        };
                        cache.probe().await;
                        cache.health.publish();
                        drop(cache);
                        tokio::time::sleep(health::PROBE_INTERVAL).await;
                    }
                });
            }
            backends.sort_by(|left, right| left.cache().cmp(right.cache()));
            participants.register(std::sync::Arc::new(health::CacheReadiness { backends }));
        }
        #[cfg(not(feature = "redis-backend"))]
        {
            // Without a Redis layer a cache is its in-process map: nothing
            // can be unreachable.
            let _ = participants;
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
            cache.store(key, value, ttl_secs).await
        } else {
            false
        }
    }

    /// Delete a key from a named cache.
    pub async fn delete(&self, name: &str, key: &str) -> bool {
        if let Some(cache) = self.caches.get(name) {
            cache.delete(key).await
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

    /// Length of the Redis list under `key` (`LLEN`). `Some(0)` for a
    /// missing key; `None` when the cache is unknown, the Redis backend
    /// is unavailable, or the command failed.
    pub async fn list_len(&self, name: &str, key: &str) -> Option<u64> {
        self.caches.get(name)?.list_len(key).await
    }

    /// Sum of `LLEN` over every key matching `{prefix}*`. `Some(0)` when
    /// nothing matches; `None` when the cache is unknown, the Redis
    /// backend is unavailable, or a Redis error occurred mid-iteration.
    pub async fn list_len_sum(&self, name: &str, prefix: &str) -> Option<u64> {
        self.caches.get(name)?.list_len_sum(prefix).await
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "redis-backend"))]
mod redis_tests;

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config(
        name: &str,
        ttl_secs: Option<u64>,
        max_entries: Option<usize>,
    ) -> NamedCacheConfig {
        NamedCacheConfig {
            name: name.to_string(),
            // Use a bogus URL so tests never hit a real Redis instance
            target: ("redis://127.0.0.1:1".to_string()).into(),
            local_ttl_secs: ttl_secs,
            local_max_entries: max_entries,
            required_for_readiness: false,
        }
    }

    #[cfg(feature = "redis-backend")]
    #[tokio::test]
    async fn failed_writes_are_reported_to_cache_callers() {
        let manager = CacheManager::new(&[make_config("failed", Some(60), Some(100))]);
        assert!(!manager.store("failed", "key", "value", None).await);
        assert!(!manager.delete("failed", "key").await);
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
            target: ("redis://127.0.0.1:1".to_string()).into(),
            local_ttl_secs: Some(0), // 0-second TTL = expires immediately
            local_max_entries: Some(100),
            required_for_readiness: false,
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
        assert!(manager
            .list_push("queue", "ims_queue_abc", "msg-1")
            .await
            .is_none());
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

    #[tokio::test]
    async fn list_len_returns_none_when_redis_unreachable() {
        let manager = CacheManager::new(&[make_config("queue", None, None)]);
        // Bogus Redis URL — backend is unreachable, op degrades.
        assert!(manager.list_len("queue", "ims_queue_abc").await.is_none());
    }

    #[tokio::test]
    async fn list_len_returns_none_for_unknown_cache_name() {
        let manager = CacheManager::empty();
        assert!(manager.list_len("nope", "key").await.is_none());
    }

    #[tokio::test]
    async fn list_len_sum_returns_none_when_redis_unreachable() {
        let manager = CacheManager::new(&[make_config("queue", None, None)]);
        assert!(manager.list_len_sum("queue", "ims_queue_").await.is_none());
    }

    #[tokio::test]
    async fn list_len_sum_returns_none_for_unknown_cache_name() {
        let manager = CacheManager::empty();
        assert!(manager.list_len_sum("nope", "ims_queue_").await.is_none());
    }

    #[test]
    fn a_cache_counts_towards_readiness_only_when_configured_to() {
        let caches: Vec<NamedCacheConfig> = crate::config::yaml::from_str(concat!(
            "- name: cnam\n",
            "  url: redis://192.0.2.10:6379\n",
            "- name: flows\n",
            "  url: redis://192.0.2.10:6379\n",
            "  required_for_readiness: true\n",
        ))
        .expect("cache list");
        assert!(!caches[0].required_for_readiness);
        assert!(caches[1].required_for_readiness);
    }

    /// The readiness wiring end to end, with a Redis that refuses: the
    /// monitor finds it down, the probe names the cache, and a cache
    /// configured out of readiness does not hold the node back.
    #[cfg(feature = "redis-backend")]
    #[tokio::test]
    async fn an_unreachable_backend_holds_readiness_only_for_a_required_cache() {
        let wait = |participants: std::sync::Arc<crate::lifecycle::Participants>,
                    wanted: Option<&'static str>| async move {
            for _ in 0..200 {
                if participants.not_ready_reason().as_deref() == wanted {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            panic!(
                "wanted {wanted:?}, got {:?}",
                participants.not_ready_reason()
            );
        };

        // As configured by default: probed, found down, readiness untouched.
        let optional = make_config("mod_tests_optional", None, None);
        let manager = std::sync::Arc::new(CacheManager::new(&[optional]));
        let participants = std::sync::Arc::new(crate::lifecycle::Participants::default());
        manager.watch_backends(&participants);
        assert_eq!(participants.not_ready_reason(), None, "before the probe");
        for _ in 0..200 {
            if !manager.caches["mod_tests_optional"].health.admit() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(!manager.caches["mod_tests_optional"].health.admit());
        assert!(!crate::metrics::cache::backend_up("mod_tests_optional"));
        assert_eq!(participants.not_ready_reason(), None, "and once it is down");

        let mut required = make_config("mod_tests_required", None, None);
        required.required_for_readiness = true;
        let manager = std::sync::Arc::new(CacheManager::new(&[required]));
        let participants = std::sync::Arc::new(crate::lifecycle::Participants::default());
        manager.watch_backends(&participants);
        wait(
            std::sync::Arc::clone(&participants),
            Some("cache 'mod_tests_required': Redis backend unreachable"),
        )
        .await;
        assert!(!crate::metrics::cache::backend_up("mod_tests_required"));
        // Refused at once and counted, with the server known to be gone.
        assert!(manager.fetch("mod_tests_required", "key").await.is_none());
        assert!(crate::metrics::cache::errors("mod_tests_required", "get") >= 1);
    }

    /// Which command failures take the backend down: the link going, not a
    /// refused command and not one command running past its deadline.
    #[cfg(feature = "redis-backend")]
    #[test]
    fn only_a_lost_link_marks_the_backend_down() {
        let name = "mod_tests_settle";
        let cache = NamedCache::new(&make_config(name, None, None));
        let io = |kind: std::io::ErrorKind| redis::RedisError::from(std::io::Error::from(kind));

        assert_eq!(cache.settle("get", "key", Ok(7)), Some(7));
        let refused = redis::RedisError::from((redis::ErrorKind::InvalidClientConfig, "refused"));
        assert_eq!(cache.settle::<u8>("get", "key", Err(refused)), None);
        assert!(cache.health.admit(), "a refused command is not an outage");
        let slow = io(std::io::ErrorKind::TimedOut);
        assert_eq!(cache.settle::<u8>("get", "key", Err(slow)), None);
        assert!(cache.health.admit(), "a slow command is not an outage");

        let reset = io(std::io::ErrorKind::ConnectionReset);
        assert_eq!(cache.settle::<u8>("get", "key", Err(reset)), None);
        assert!(!cache.health.admit(), "a reset link is");
        assert_eq!(crate::metrics::cache::errors(name, "get"), 3);

        assert_eq!(cache.settle("get", "key", Ok(7)), Some(7));
        assert!(cache.health.admit(), "and an answer ends it");
    }

    #[tokio::test]
    async fn no_configured_cache_registers_nothing_with_readiness() {
        let manager = std::sync::Arc::new(CacheManager::empty());
        let participants = crate::lifecycle::Participants::default();
        manager.watch_backends(&participants);
        assert_eq!(participants.not_ready_reason(), None);
        assert_eq!(participants.registered_count(), 0);
    }

    /// A monitor holds its cache only while it probes, and no other cache at
    /// all: once the manager is dropped every task ends and the caches are
    /// freed, with the monitors already running.
    #[cfg(feature = "redis-backend")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_monitors_end_with_their_manager() {
        let manager = CacheManager::new(&[
            make_config("mod_tests_dropped_a", None, None),
            make_config("mod_tests_dropped_b", None, None),
        ]);
        let participants = crate::lifecycle::Participants::default();
        manager.watch_backends(&participants);
        let caches: Vec<_> = manager
            .caches
            .values()
            .map(std::sync::Arc::downgrade)
            .collect();
        // Both monitors have probed: the backends are known to be down.
        for _ in 0..200 {
            if manager.caches.values().all(|cache| !cache.health.admit()) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(manager.caches.values().all(|cache| !cache.health.admit()));
        drop(manager);
        for _ in 0..200 {
            if caches.iter().all(|cache| cache.strong_count() == 0) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("a monitor task still holds its cache");
    }

    #[cfg(feature = "redis-backend")]
    #[test]
    fn escape_glob_escapes_metacharacters() {
        // Plain prefixes (underscore is not a glob metachar) pass through.
        assert_eq!(escape_glob("ims_queue_"), "ims_queue_");
        // The five glob metacharacters each get a backslash prefix.
        assert_eq!(escape_glob("a*b?c[d]e"), "a\\*b\\?c\\[d\\]e");
        assert_eq!(escape_glob("back\\slash"), "back\\\\slash");
    }
}
