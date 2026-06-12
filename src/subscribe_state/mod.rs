//! Generic SUBSCRIBE dialog state — the storage + lifecycle layer behind
//! the Python ``proxy.subscribe_state`` namespace.
//!
//! Unlike [`crate::presence`], which is PIDF-specific, this module is
//! event-package-agnostic — any RFC 6665 subscribe dialog can be tracked
//! here (conference-event, reg-event, dialog-info, message-summary, etc.).
//!
//! ## Persistence
//!
//! The store maintains an in-process [`DashMap`] as L1; when configured
//! with a named cache from [`crate::cache::CacheManager`], mutations are
//! write-through to that cache (typically Redis), and a miss on the L1
//! falls back to loading from L2.  This gives MRF-style deployments
//! durable subscribe state across restarts and replicas without needing
//! the script to hand-roll Redis keys.

use std::sync::Arc;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::cache::CacheManager;

/// Seconds since the Unix epoch, capped at `u64::MAX` on clock weirdness.
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// One SUBSCRIBE dialog, serialisable for L2 persistence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscribeDialog {
    /// Opaque handle id (UUID v4).  Scripts pass this to
    /// ``proxy.subscribe_state.get(id)`` to retrieve the handle later.
    pub id: String,
    /// SIP Call-ID from the SUBSCRIBE.
    pub call_id: String,
    /// Our (notifier) tag — was the `To` tag on the SUBSCRIBE; becomes
    /// the `From` tag on NOTIFY.
    pub local_tag: String,
    /// Peer (subscriber) tag — was the `From` tag on the SUBSCRIBE;
    /// becomes the `To` tag on NOTIFY.
    pub remote_tag: String,
    /// Our URI (notifier) — the `To` URI on the SUBSCRIBE, used as
    /// the `From` URI on NOTIFY.
    pub local_uri: String,
    /// Peer URI (subscriber) — the `From` URI on the SUBSCRIBE, used
    /// as the `To` URI on NOTIFY.
    pub remote_uri: String,
    /// Remote target — the Contact URI from the SUBSCRIBE; NOTIFY
    /// Request-URI.
    pub remote_target: String,
    /// Reversed Record-Route from the SUBSCRIBE (empty if none).
    pub route_set: Vec<String>,
    /// Event package name (from the `Event:` header — required per
    /// RFC 6665 §7.2.2).
    pub event: String,
    /// Seconds from creation until this dialog expires.
    pub expires_secs: u64,
    /// Unix epoch seconds when this dialog was created / last refreshed.
    pub created_at_unix: u64,
    /// Monotonic CSeq counter for NOTIFYs sent in this dialog.
    pub cseq: u32,
    /// Monotonic event-package version counter — used in NOTIFY bodies that
    /// require monotonicity (RFC 3680 reginfo `version=`, RFC 4235
    /// dialog-info, RFC 4575 conference).  RFC 6665 §4.4.1 forbids
    /// non-monotonic body versions, so this is persisted alongside the
    /// dialog and survives restart when an L2 cache is configured.
    #[serde(default)]
    pub event_version: u32,
    /// Once true, the dialog is terminated and no further NOTIFYs may
    /// be sent.  Kept in the store briefly so late cross-instance
    /// lookups don't see a revived dialog.
    pub terminated: bool,
    /// `true` when this dialog was created by an outbound SUBSCRIBE we
    /// originated (we are the *subscriber*).  `false` for the original
    /// `create()` flow where we received a SUBSCRIBE and act as the
    /// *notifier*.  Drives termination semantics — outbound subscribers
    /// terminate by sending SUBSCRIBE Expires:0; notifiers terminate by
    /// sending a final NOTIFY with Subscription-State: terminated.
    /// Defaults to `false` so older cached payloads deserialise as the
    /// notifier role.
    #[serde(default)]
    pub is_outbound: bool,
}

impl SubscribeDialog {
    /// Seconds until the dialog expires.  Saturates at 0.
    pub fn remaining_secs(&self) -> u64 {
        let elapsed = unix_now().saturating_sub(self.created_at_unix);
        self.expires_secs.saturating_sub(elapsed)
    }

    /// Increment and return the next NOTIFY CSeq.
    pub fn next_cseq(&mut self) -> u32 {
        self.cseq = self.cseq.saturating_add(1);
        self.cseq
    }

    /// Increment and return the next event-package body version.
    pub fn next_event_version(&mut self) -> u32 {
        self.event_version = self.event_version.saturating_add(1);
        self.event_version
    }

    /// Refresh the created-at anchor (e.g. on SUBSCRIBE refresh).
    pub fn refresh(&mut self, expires_secs: u64) {
        self.expires_secs = expires_secs;
        self.created_at_unix = unix_now();
    }
}

/// Store holding the L1 DashMap and (optionally) an L2 cache handle.
pub struct SubscribeStore {
    dialogs: DashMap<String, SubscribeDialog>,
    /// ``(cache_manager, cache_name)`` when configured.
    cache: Option<(Arc<CacheManager>, String)>,
}

/// Process-wide subscribe-dialog store, installed at startup so background
/// tasks (the dispatcher cleanup tick) can reach it without going through the
/// Python namespace singleton.
static GLOBAL_STORE: OnceLock<Arc<SubscribeStore>> = OnceLock::new();

/// Install the global store. Idempotent (first writer wins).
pub fn set_global_store(store: Arc<SubscribeStore>) {
    let _ = GLOBAL_STORE.set(store);
}

/// Borrow the installed global store, if any.
pub fn global_store() -> Option<Arc<SubscribeStore>> {
    GLOBAL_STORE.get().cloned()
}

impl SubscribeStore {
    pub fn new() -> Self {
        Self {
            dialogs: DashMap::new(),
            cache: None,
        }
    }

    /// Enable L2 write-through persistence via a named cache from
    /// ``siphon.yaml``.
    pub fn with_cache(mut self, cache_manager: Arc<CacheManager>, cache_name: String) -> Self {
        self.cache = Some((cache_manager, cache_name));
        self
    }

    /// Build the cache key for an id.
    fn cache_key(id: &str) -> String {
        format!("subscribe_dialog:{id}")
    }

    /// Write a dialog to L1 and (if configured) L2.
    pub fn put(&self, dialog: SubscribeDialog) {
        if let Some((manager, name)) = &self.cache {
            let manager = Arc::clone(manager);
            let cache_name = name.clone();
            let key = Self::cache_key(&dialog.id);
            let dialog_clone = dialog.clone();
            let ttl = dialog.expires_secs;
            tokio::spawn(async move {
                match serde_json::to_string(&dialog_clone) {
                    Ok(json) => {
                        manager.store(&cache_name, &key, &json, Some(ttl)).await;
                    }
                    Err(error) => {
                        warn!(%error, "subscribe_state: failed to serialize dialog for cache");
                    }
                }
            });
        }
        self.dialogs.insert(dialog.id.clone(), dialog);
    }

    /// Fetch a dialog by id.  Looks in L1 first; on miss, tries L2 and
    /// hydrates L1.  Returns ``None`` if the dialog is unknown or has
    /// been terminated.
    pub async fn get(&self, id: &str) -> Option<SubscribeDialog> {
        if let Some(entry) = self.dialogs.get(id) {
            if entry.terminated {
                return None;
            }
            return Some(entry.clone());
        }

        let (manager, cache_name) = self.cache.as_ref()?;
        let json = manager.fetch(cache_name, &Self::cache_key(id)).await?;
        match serde_json::from_str::<SubscribeDialog>(&json) {
            Ok(dialog) => {
                if dialog.terminated {
                    None
                } else {
                    self.dialogs.insert(dialog.id.clone(), dialog.clone());
                    Some(dialog)
                }
            }
            Err(error) => {
                warn!(%error, id, "subscribe_state: failed to deserialize cached dialog");
                None
            }
        }
    }

    /// Update an existing dialog (e.g. bump CSeq after NOTIFY).
    /// Silently no-ops if the id is unknown.
    pub fn update<F>(&self, id: &str, mutate: F) -> Option<SubscribeDialog>
    where
        F: FnOnce(&mut SubscribeDialog),
    {
        let mut entry = self.dialogs.get_mut(id)?;
        mutate(&mut entry);
        let updated = entry.clone();
        drop(entry);
        // Write-through the updated dialog.
        if let Some((manager, name)) = &self.cache {
            let manager = Arc::clone(manager);
            let cache_name = name.clone();
            let key = Self::cache_key(id);
            let dialog_clone = updated.clone();
            let ttl = updated.expires_secs;
            tokio::spawn(async move {
                if let Ok(json) = serde_json::to_string(&dialog_clone) {
                    manager.store(&cache_name, &key, &json, Some(ttl)).await;
                }
            });
        }
        Some(updated)
    }

    /// Remove a dialog from both L1 and L2.
    pub fn remove(&self, id: &str) {
        self.dialogs.remove(id);
        if let Some((manager, name)) = &self.cache {
            let manager = Arc::clone(manager);
            let cache_name = name.clone();
            let key = Self::cache_key(id);
            tokio::spawn(async move {
                manager.delete(&cache_name, &key).await;
            });
        }
        debug!(id, "subscribe_state: dialog removed");
    }

    /// Number of live dialogs in L1 (does not include cache-only).
    pub fn local_count(&self) -> usize {
        self.dialogs.len()
    }

    /// Reap expired or terminated dialogs from the L1 store, returning the
    /// number removed.  A subscriber that vanishes without an un-SUBSCRIBE
    /// would otherwise pin its `SubscribeDialog` in L1 forever: the L2 cache
    /// expires via its own TTL, but L1 has no such reaper.  Call periodically
    /// (the dispatcher does so on its cleanup tick).
    pub fn sweep_stale(&self) -> usize {
        // Collect ids first, then remove: holding a DashMap iterator (shard
        // read lock) while removing (shard write lock) on the same map can
        // deadlock.
        let stale: Vec<String> = self
            .dialogs
            .iter()
            .filter(|entry| entry.terminated || entry.remaining_secs() == 0)
            .map(|entry| entry.key().clone())
            .collect();
        for id in &stale {
            // L1-only: an expired L2 entry ages out via its own TTL, and a
            // terminated dialog already had its L2 key deleted by `remove`.
            self.dialogs.remove(id);
        }
        stale.len()
    }

    /// Find a dialog by its three identity tags. Used to correlate an
    /// in-dialog NOTIFY (received via `@proxy.on_request("NOTIFY")`)
    /// back to the outbound SUBSCRIBE we sent that established the
    /// dialog. Returns `None` when no live dialog matches — including
    /// when the dialog has been terminated.
    ///
    /// Linear scan over the local DashMap. Subscribe dialog counts in
    /// scripted flows are small (10²–10³) so the cost is negligible;
    /// graduate to an index keyed by `(call_id, local_tag, remote_tag)`
    /// only when there's measured contention.
    pub fn find_by_tags(
        &self,
        call_id: &str,
        local_tag: &str,
        remote_tag: &str,
    ) -> Option<SubscribeDialog> {
        for entry in self.dialogs.iter() {
            let dialog = entry.value();
            if dialog.terminated {
                continue;
            }
            if dialog.call_id == call_id
                && dialog.local_tag == local_tag
                && dialog.remote_tag == remote_tag
            {
                return Some(dialog.clone());
            }
        }
        None
    }
}

impl Default for SubscribeStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_dialog(id: &str) -> SubscribeDialog {
        SubscribeDialog {
            id: id.to_string(),
            call_id: "c1".to_string(),
            local_tag: "ltag".to_string(),
            remote_tag: "rtag".to_string(),
            local_uri: "sip:mrf@ims.example".to_string(),
            remote_uri: "sip:alice@ims.example".to_string(),
            remote_target: "sip:alice@10.0.0.1:5060".to_string(),
            route_set: vec!["<sip:edge.ims.example;lr>".to_string()],
            event: "conference".to_string(),
            expires_secs: 3600,
            created_at_unix: unix_now(),
            cseq: 0,
            event_version: 0,
            terminated: false,
            is_outbound: false,
        }
    }

    #[tokio::test]
    async fn put_and_get_roundtrip_l1() {
        let store = SubscribeStore::new();
        store.put(sample_dialog("abc"));
        let got = store.get("abc").await.expect("dialog present");
        assert_eq!(got.call_id, "c1");
        assert_eq!(store.local_count(), 1);
    }

    #[tokio::test]
    async fn remove_clears_l1() {
        let store = SubscribeStore::new();
        store.put(sample_dialog("abc"));
        store.remove("abc");
        assert!(store.get("abc").await.is_none());
        assert_eq!(store.local_count(), 0);
    }

    #[test]
    fn sweep_reaps_expired_and_terminated_only() {
        let store = SubscribeStore::new();
        store.put(sample_dialog("fresh")); // expires_secs 3600 — survives

        let mut expired = sample_dialog("expired");
        expired.expires_secs = 0; // remaining_secs() == 0
        store.put(expired);

        let mut terminated = sample_dialog("terminated");
        terminated.terminated = true; // reaped even though not expired
        store.put(terminated);

        assert_eq!(store.local_count(), 3);
        let removed = store.sweep_stale();
        assert_eq!(removed, 2, "expired + terminated must be reaped");
        assert_eq!(store.local_count(), 1, "the live dialog must remain");
    }

    #[test]
    fn sweep_keeps_live_dialogs() {
        let store = SubscribeStore::new();
        store.put(sample_dialog("a"));
        store.put(sample_dialog("b"));
        assert_eq!(store.sweep_stale(), 0);
        assert_eq!(store.local_count(), 2);
    }

    #[tokio::test]
    async fn update_increments_cseq() {
        let store = SubscribeStore::new();
        store.put(sample_dialog("abc"));
        let updated = store
            .update("abc", |dialog| {
                dialog.next_cseq();
            })
            .expect("dialog present");
        assert_eq!(updated.cseq, 1);
    }

    #[tokio::test]
    async fn update_increments_event_version_independently_of_cseq() {
        let store = SubscribeStore::new();
        store.put(sample_dialog("abc"));

        let after_first = store
            .update("abc", |dialog| {
                dialog.next_event_version();
            })
            .expect("dialog present");
        assert_eq!(after_first.event_version, 1);
        assert_eq!(after_first.cseq, 0, "event_version must not piggyback on CSeq");

        let after_second = store
            .update("abc", |dialog| {
                dialog.next_event_version();
            })
            .expect("dialog present");
        assert_eq!(after_second.event_version, 2);
    }

    #[test]
    fn event_version_serde_default_for_legacy_payloads() {
        // Older cached dialogs predating event_version are deserialised
        // with the field defaulted to 0 — ensures we don't reject existing
        // L2 cache entries on upgrade.
        let legacy_json = r#"{
            "id":"abc","call_id":"c1","local_tag":"l","remote_tag":"r",
            "local_uri":"sip:s@example","remote_uri":"sip:c@example",
            "remote_target":"sip:c@10.0.0.1","route_set":[],
            "event":"reg","expires_secs":3600,"created_at_unix":1000,
            "cseq":3,"terminated":false
        }"#;
        let dialog: SubscribeDialog =
            serde_json::from_str(legacy_json).expect("legacy json parses");
        assert_eq!(dialog.event_version, 0);
        assert_eq!(dialog.cseq, 3);
    }

    #[tokio::test]
    async fn get_returns_none_for_terminated() {
        let store = SubscribeStore::new();
        let mut dialog = sample_dialog("abc");
        dialog.terminated = true;
        store.put(dialog);
        assert!(store.get("abc").await.is_none());
    }

    #[test]
    fn remaining_secs_saturates_at_zero() {
        let mut dialog = sample_dialog("abc");
        dialog.expires_secs = 10;
        dialog.created_at_unix = 0; // way in the past
        assert_eq!(dialog.remaining_secs(), 0);
    }

    #[test]
    fn serde_roundtrip() {
        let dialog = sample_dialog("abc");
        let json = serde_json::to_string(&dialog).unwrap();
        let parsed: SubscribeDialog = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, dialog.id);
        assert_eq!(parsed.route_set, dialog.route_set);
        assert_eq!(parsed.is_outbound, dialog.is_outbound);
    }

    #[test]
    fn is_outbound_serde_default_for_legacy_payloads() {
        // Pre-existing cached dialogs predating is_outbound deserialise
        // with the field defaulted to false (notifier role) — same
        // discipline as event_version_serde_default_for_legacy_payloads.
        let legacy_json = r#"{
            "id":"abc","call_id":"c1","local_tag":"l","remote_tag":"r",
            "local_uri":"sip:s@example","remote_uri":"sip:c@example",
            "remote_target":"sip:c@10.0.0.1","route_set":[],
            "event":"reg","expires_secs":3600,"created_at_unix":1000,
            "cseq":3,"event_version":2,"terminated":false
        }"#;
        let dialog: SubscribeDialog =
            serde_json::from_str(legacy_json).expect("legacy json parses");
        assert!(!dialog.is_outbound);
    }

    #[test]
    fn find_by_tags_matches_live_dialog() {
        let store = SubscribeStore::new();
        store.put(sample_dialog("abc"));
        let found = store
            .find_by_tags("c1", "ltag", "rtag")
            .expect("dialog should match");
        assert_eq!(found.id, "abc");
    }

    #[test]
    fn find_by_tags_misses_on_any_field_difference() {
        let store = SubscribeStore::new();
        store.put(sample_dialog("abc"));
        assert!(store.find_by_tags("other", "ltag", "rtag").is_none());
        assert!(store.find_by_tags("c1", "other", "rtag").is_none());
        assert!(store.find_by_tags("c1", "ltag", "other").is_none());
    }

    #[test]
    fn find_by_tags_skips_terminated() {
        let store = SubscribeStore::new();
        let mut dialog = sample_dialog("abc");
        dialog.terminated = true;
        store.put(dialog);
        assert!(store.find_by_tags("c1", "ltag", "rtag").is_none());
    }
}
