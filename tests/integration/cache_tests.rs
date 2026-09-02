//! Integration tests for the cache module.
//!
//! Tests LRU-only CacheManager (no Redis connection required).

use std::time::Duration;

use siphon::cache::CacheManager;
use siphon::config::NamedCacheConfig;

fn make_config(name: &str, ttl_secs: u64, max_entries: usize) -> NamedCacheConfig {
    NamedCacheConfig {
        name: name.to_string(),
        url: "redis://127.0.0.1:1".to_string(),
        local_ttl_secs: Some(ttl_secs),
        local_max_entries: Some(max_entries),
    }
}

#[tokio::test]
async fn fetch_miss_then_store_then_hit() {
    let manager = CacheManager::new(&[make_config("cnam", 60, 1000)]);

    // Miss
    assert!(manager.fetch("cnam", "msisdn:1234").await.is_none());

    // Store
    assert!(manager.store("cnam", "msisdn:1234", "Alice", None).await);

    // Hit
    assert_eq!(manager.fetch("cnam", "msisdn:1234").await.unwrap(), "Alice");
}

#[tokio::test]
async fn ttl_expiry() {
    let manager = CacheManager::new(&[make_config("short", 0, 1000)]);

    manager.store("short", "key1", "value1", None).await;

    // With 0s TTL, entries expire immediately
    std::thread::sleep(Duration::from_millis(10));
    assert!(manager.fetch("short", "key1").await.is_none());
}

#[tokio::test]
async fn max_entries_eviction() {
    let manager = CacheManager::new(&[make_config("tiny", 60, 3)]);

    manager.store("tiny", "k1", "v1", None).await;
    manager.store("tiny", "k2", "v2", None).await;
    manager.store("tiny", "k3", "v3", None).await;

    // All 3 should be present
    assert!(manager.fetch("tiny", "k1").await.is_some());
    assert!(manager.fetch("tiny", "k2").await.is_some());
    assert!(manager.fetch("tiny", "k3").await.is_some());

    // Adding a 4th should evict the oldest (k1)
    manager.store("tiny", "k4", "v4", None).await;
    assert!(manager.fetch("tiny", "k4").await.is_some());
    // k1 was the oldest insert, so it should be evicted
    assert!(manager.fetch("tiny", "k1").await.is_none());
}

#[tokio::test]
async fn unknown_cache_name() {
    let manager = CacheManager::new(&[make_config("existing", 60, 100)]);
    assert!(manager.fetch("nonexistent", "key").await.is_none());
    assert!(!manager.store("nonexistent", "key", "value", None).await);
}

#[tokio::test]
async fn multiple_named_caches() {
    let manager = CacheManager::new(&[
        make_config("cache_a", 60, 100),
        make_config("cache_b", 60, 100),
    ]);

    manager.store("cache_a", "key", "value_a", None).await;
    manager.store("cache_b", "key", "value_b", None).await;

    // Same key, different caches, different values
    assert_eq!(manager.fetch("cache_a", "key").await.unwrap(), "value_a");
    assert_eq!(manager.fetch("cache_b", "key").await.unwrap(), "value_b");
}

#[tokio::test]
async fn overwrite_existing_key() {
    let manager = CacheManager::new(&[make_config("overwrite", 60, 100)]);

    manager.store("overwrite", "key", "old_value", None).await;
    assert_eq!(
        manager.fetch("overwrite", "key").await.unwrap(),
        "old_value"
    );

    manager.store("overwrite", "key", "new_value", None).await;
    assert_eq!(
        manager.fetch("overwrite", "key").await.unwrap(),
        "new_value"
    );
}

#[tokio::test]
async fn empty_manager_returns_none() {
    let manager = CacheManager::empty();
    assert!(manager.fetch("any", "key").await.is_none());
    assert!(!manager.has_cache("any"));
}
