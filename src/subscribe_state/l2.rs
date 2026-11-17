//! The L2 cache a subscribe dialog is written through to: one key per
//! dialog, which lives as long as the subscription has left to run.

use std::sync::Arc;

use crate::cache::CacheManager;

/// Where dialogs are written through to.
#[derive(Clone)]
pub(super) enum L2 {
    /// A named cache from `siphon.yaml`.
    Named {
        manager: Arc<CacheManager>,
        name: String,
    },
    /// A cache a test reads the keys and their expiries off.
    #[cfg(test)]
    Recording(Arc<recording::Recording>),
}

impl L2 {
    /// Store `json` under `key`, to expire in `ttl_secs`.
    pub(super) async fn store(&self, key: &str, json: &str, ttl_secs: u64) {
        match self {
            L2::Named { manager, name } => {
                manager.store(name, key, json, Some(ttl_secs)).await;
            }
            #[cfg(test)]
            L2::Recording(recording) => recording.store(key, json, ttl_secs),
        }
    }

    pub(super) async fn fetch(&self, key: &str) -> Option<String> {
        match self {
            L2::Named { manager, name } => manager.fetch(name, key).await,
            #[cfg(test)]
            L2::Recording(recording) => recording.fetch(key),
        }
    }

    pub(super) async fn delete(&self, key: &str) {
        match self {
            L2::Named { manager, name } => {
                manager.delete(name, key).await;
            }
            #[cfg(test)]
            L2::Recording(recording) => recording.delete(key),
        }
    }
}

#[cfg(test)]
pub(crate) mod recording {
    use std::collections::HashMap;
    use std::sync::{Mutex, PoisonError};

    /// An in-memory stand-in for the shared cache that keeps the expiry each
    /// key was last stored with, which the local LRU of a `CacheManager`
    /// does not.
    #[derive(Default)]
    pub(crate) struct Recording {
        keys: Mutex<HashMap<String, (String, u64)>>,
    }

    impl Recording {
        pub(super) fn store(&self, key: &str, json: &str, ttl_secs: u64) {
            self.lock()
                .insert(key.to_string(), (json.to_string(), ttl_secs));
        }

        pub(super) fn fetch(&self, key: &str) -> Option<String> {
            self.lock().get(key).map(|(json, _)| json.clone())
        }

        pub(super) fn delete(&self, key: &str) {
            self.lock().remove(key);
        }

        /// Put `json` under the key of dialog `id`, as another replica, or
        /// this one before a restart, would have left it.
        pub(crate) fn seed(&self, id: &str, json: &str, ttl_secs: u64) {
            self.store(&super::super::SubscribeStore::cache_key(id), json, ttl_secs);
        }

        /// The expiry the key of dialog `id` was last stored with; `None`
        /// when the cache holds no such key.
        pub(crate) fn ttl_of(&self, id: &str) -> Option<u64> {
            self.lock()
                .get(&super::super::SubscribeStore::cache_key(id))
                .map(|(_, ttl_secs)| *ttl_secs)
        }

        /// How many keys the cache holds.
        pub(crate) fn key_count(&self) -> usize {
            self.lock().len()
        }

        fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, (String, u64)>> {
            self.keys.lock().unwrap_or_else(PoisonError::into_inner)
        }
    }
}
