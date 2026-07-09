//! Python `cache` namespace — async fetch/store/delete for named caches.
//!
//! Replaces the Python stub `_CacheNamespace` with a Rust-backed implementation
//! that delegates to `CacheManager` (local LRU + optional Redis).
//!
//! Keys starting with `siphon:` are reserved for internal use (registrar,
//! iFC store, etc.) and rejected from Python scripts.

use std::sync::Arc;

use pyo3::prelude::*;

use crate::cache::CacheManager;

/// Reject keys with the `siphon:` prefix — reserved for internal subsystems.
fn validate_key(key: &str) -> PyResult<()> {
    if key.starts_with("siphon:") {
        Err(pyo3::exceptions::PyValueError::new_err(
            "keys starting with 'siphon:' are reserved for internal use",
        ))
    } else {
        Ok(())
    }
}

/// Validate a `list_len_sum` prefix: reject the reserved `siphon:`
/// prefix and reject an empty prefix (which would `SCAN` the entire
/// keyspace). Raising `ValueError` matches `validate_key`'s style for
/// programming errors.
fn validate_prefix(prefix: &str) -> PyResult<()> {
    validate_key(prefix)?;
    if prefix.is_empty() {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "prefix must not be empty (would scan the entire keyspace)",
        ));
    }
    Ok(())
}

/// Python-facing cache namespace.
#[pyclass(name = "CacheNamespace")]
pub struct PyCacheNamespace {
    manager: Arc<CacheManager>,
}

impl PyCacheNamespace {
    pub fn new(manager: Arc<CacheManager>) -> Self {
        Self { manager }
    }
}

#[pymethods]
impl PyCacheNamespace {
    /// Fetch a value from a named cache.
    ///
    /// Returns the cached string value, or `None` if not found or cache
    /// doesn't exist. This is an async method on the Python side.
    fn fetch<'py>(&self, py: Python<'py>, name: String, key: String) -> PyResult<Bound<'py, PyAny>> {
        let manager = Arc::clone(&self.manager);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            Ok(manager.fetch(&name, &key).await)
        })
    }

    /// Store a value in a named cache with optional TTL.
    ///
    /// Returns `True` if the named cache exists and the value was stored,
    /// `False` if the cache name is unknown.
    ///
    /// Args:
    ///     name: Cache name (from ``siphon.yaml`` cache list).
    ///     key: Cache key string.
    ///     value: Value to store.
    ///     ttl: Optional TTL in seconds.  When set, the key expires in Redis
    ///         after this duration (uses ``SETEX``).  Without TTL, the key
    ///         persists until the cache's configured TTL evicts it.
    #[pyo3(signature = (name, key, value, ttl=None))]
    fn store<'py>(
        &self,
        py: Python<'py>,
        name: String,
        key: String,
        value: String,
        ttl: Option<u64>,
    ) -> PyResult<Bound<'py, PyAny>> {
        validate_key(&key)?;
        let manager = Arc::clone(&self.manager);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            Ok(manager.store(&name, &key, &value, ttl).await)
        })
    }

    /// Delete a key from a named cache.
    ///
    /// Returns `True` if the named cache exists (key may or may not have existed),
    /// `False` if the cache name is unknown.
    fn delete<'py>(
        &self,
        py: Python<'py>,
        name: String,
        key: String,
    ) -> PyResult<Bound<'py, PyAny>> {
        validate_key(&key)?;
        let manager = Arc::clone(&self.manager);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            Ok(manager.delete(&name, &key).await)
        })
    }

    /// Check if a named cache exists in the configuration.
    fn has_cache(&self, name: &str) -> bool {
        self.manager.has_cache(name)
    }

    /// Push an item onto the right of a Redis list (FIFO when paired
    /// with :meth:`list_pop_all`).
    ///
    /// Args:
    ///     name: Cache name (must reference a Redis-backed entry —
    ///         local-LRU-only caches don't have list semantics).
    ///     key: List key. Reserved keys (``siphon:`` prefix) are rejected.
    ///     item: String value to append.
    ///
    /// Returns the list's new length on success, ``None`` when the
    /// cache is unknown or Redis is unavailable / the command failed.
    fn list_push<'py>(
        &self,
        py: Python<'py>,
        name: String,
        key: String,
        item: String,
    ) -> PyResult<Bound<'py, PyAny>> {
        validate_key(&key)?;
        let manager = Arc::clone(&self.manager);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            Ok(manager.list_push(&name, &key, &item).await)
        })
    }

    /// Atomically read and clear a Redis list. Returns the items in
    /// FIFO order; empty list when the key was absent, the cache is
    /// unknown, or Redis is unavailable.
    ///
    /// Implementation uses a MULTI/EXEC pipeline so concurrent
    /// producers don't lose items between the read and the delete.
    fn list_pop_all<'py>(
        &self,
        py: Python<'py>,
        name: String,
        key: String,
    ) -> PyResult<Bound<'py, PyAny>> {
        validate_key(&key)?;
        let manager = Arc::clone(&self.manager);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            Ok(manager.list_pop_all(&name, &key).await)
        })
    }

    /// Set a TTL (seconds) on an existing key.
    ///
    /// Returns ``True`` when the timeout was set, ``False`` when the
    /// key did not exist, the cache is unknown, or the backend
    /// rejected the command. Useful after :meth:`list_push` to bound
    /// queue lifetime.
    fn expire<'py>(
        &self,
        py: Python<'py>,
        name: String,
        key: String,
        ttl: u64,
    ) -> PyResult<Bound<'py, PyAny>> {
        validate_key(&key)?;
        let manager = Arc::clone(&self.manager);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            Ok(manager.expire(&name, &key, ttl).await)
        })
    }

    /// Return the length of the Redis list under ``key`` (``LLEN``).
    ///
    /// Args:
    ///     name: Cache name (must reference a Redis-backed entry —
    ///         local-LRU-only caches don't have list semantics).
    ///     key: List key. Reserved keys (``siphon:`` prefix) are rejected.
    ///
    /// Returns the list length (``0`` for a missing key — Redis
    /// ``LLEN`` of an absent key is 0), or ``None`` when the cache is
    /// unknown, the cache has no Redis backend, or the command failed.
    fn list_len<'py>(
        &self,
        py: Python<'py>,
        name: String,
        key: String,
    ) -> PyResult<Bound<'py, PyAny>> {
        validate_key(&key)?;
        let manager = Arc::clone(&self.manager);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            Ok(manager.list_len(&name, &key).await)
        })
    }

    /// Sum ``LLEN`` over every key matching ``{prefix}*`` — the live
    /// depth of a set of sharded per-key lists (e.g. summing
    /// ``ims_queue_*``), computed server-side in one await.
    ///
    /// Implemented with a cursor ``SCAN MATCH {prefix}* COUNT 512`` loop
    /// (deduped, since ``SCAN`` may repeat keys under concurrent writes)
    /// then a pipelined ``LLEN`` over the deduped set. Glob
    /// metacharacters in ``prefix`` are escaped so it matches literally.
    /// TTL-expired keys are simply gone from the keyspace, so the sum is
    /// a truthful instantaneous depth.
    ///
    /// Args:
    ///     name: Cache name (must reference a Redis-backed entry).
    ///     prefix: Non-empty key prefix. Reserved (``siphon:``) prefixes
    ///         are rejected; an empty prefix raises ``ValueError`` (it
    ///         would scan the entire keyspace).
    ///
    /// Returns the summed length (``0`` when nothing matches), or
    /// ``None`` when the cache is unknown, the cache has no Redis
    /// backend, or a Redis error occurred mid-iteration.
    ///
    /// Note:
    ///     ``SCAN`` is O(keyspace of that Redis DB) — intended for a
    ///     dedicated queue DB.
    fn list_len_sum<'py>(
        &self,
        py: Python<'py>,
        name: String,
        prefix: String,
    ) -> PyResult<Bound<'py, PyAny>> {
        validate_prefix(&prefix)?;
        let manager = Arc::clone(&self.manager);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            Ok(manager.list_len_sum(&name, &prefix).await)
        })
    }

    /// Check whether ``key`` exists in the named cache.
    ///
    /// Considers the local LRU first (in-process), then Redis. Returns
    /// ``False`` for unknown cache names.
    fn exists<'py>(
        &self,
        py: Python<'py>,
        name: String,
        key: String,
    ) -> PyResult<Bound<'py, PyAny>> {
        validate_key(&key)?;
        let manager = Arc::clone(&self.manager);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            Ok(manager.exists(&name, &key).await)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_prefix_rejects_empty() {
        // Empty prefix would SCAN the whole keyspace — reject it.
        assert!(validate_prefix("").is_err());
    }

    #[test]
    fn validate_prefix_rejects_reserved() {
        assert!(validate_prefix("siphon:internal").is_err());
    }

    #[test]
    fn validate_prefix_accepts_normal() {
        assert!(validate_prefix("ims_queue_").is_ok());
    }
}
