//! Media sessions a script anchored under a **per-call scope**.
//!
//! The store keys a call's session by its SIP Call-ID, one per call. A proxy
//! that anchors the originating and the terminating leg of one call separately
//! has two sessions under one Call-ID (a proxy does not change it, RFC 3261
//! §16.6), each on an engine call of its own (`rtpengine.offer(..., scope=)`).
//! So each scope a script names gets a store of its own, keyed by Call-ID like
//! this one: everything a session records (the offerer's and answerer's tags,
//! the profile an answer reuses, the WebSocket URI) works per leg exactly as it
//! does per call, and the session never says which scope it is in, since the
//! store it sits in does.
//!
//! The scope stores themselves are kept: there is one per name a script uses
//! (a leg's role), not per call, and dropping an empty one would race a
//! concurrent offer inserting into it. What a call puts in one leaves with the
//! call: a `delete` removes it, and the stale sweep reaches every scope store.

use std::sync::Arc;

use super::{MediaSession, MediaSessionStore};
use crate::rtpengine::CallScope;

/// The most scope names a script may use per process; see
/// [`MediaSessionStore::scoped`].
const MAX_SCOPE_STORES: usize = 256;

impl MediaSessionStore {
    /// The store of the sessions anchored under `scope`, created on first use.
    ///
    /// Refused past [`MAX_SCOPE_STORES`] names: a scope names a leg's role, and
    /// a script that derives one per call would otherwise grow this map with
    /// every call.
    pub fn scoped(&self, scope: &CallScope) -> Result<Arc<MediaSessionStore>, String> {
        if let Some(store) = self.scoped_existing(scope) {
            return Ok(store);
        }
        if self.scopes.len() >= MAX_SCOPE_STORES {
            return Err(format!(
                "scope={scope:?} would be the {}th per-call scope; the maximum is \
                 {MAX_SCOPE_STORES} (a scope names a leg's role, not a call)",
                MAX_SCOPE_STORES + 1
            ));
        }
        let store = self
            .scopes
            .entry(scope.clone())
            .or_insert_with(|| Arc::new(MediaSessionStore::new()));
        Ok(Arc::clone(store.value()))
    }

    /// The store of the sessions anchored under `scope`, if one was ever used.
    pub fn scoped_existing(&self, scope: &CallScope) -> Option<Arc<MediaSessionStore>> {
        self.scopes
            .get(scope)
            .map(|store| Arc::clone(store.value()))
    }

    /// Take every session stored for `call_id` under a per-call scope out of
    /// its scope's store, with the scope it was in: what a teardown that names
    /// no scope has to delete beside the call's own session.
    pub fn take_scoped(&self, call_id: &str) -> Vec<(CallScope, MediaSession)> {
        let stores: Vec<(CallScope, Arc<MediaSessionStore>)> = self
            .scopes
            .iter()
            .map(|entry| (entry.key().clone(), Arc::clone(entry.value())))
            .collect();
        stores
            .into_iter()
            .filter_map(|(scope, store)| store.remove(call_id).map(|session| (scope, session)))
            .collect()
    }

    /// How many sessions are held under per-call scopes, across every scope
    /// (drains to baseline — leak gate).
    pub fn scoped_len(&self) -> usize {
        self.scopes.iter().map(|store| store.len()).sum()
    }

    /// Sweep every scope store as [`MediaSessionStore::sweep_stale`] sweeps
    /// this one.
    pub(super) fn sweep_scoped(&self, max_age: std::time::Duration) {
        for store in self.scopes.iter() {
            store.sweep_stale(max_age);
        }
    }

    /// The engine call-ids of the sessions held under per-call scopes, as
    /// rtpengine knows them (`<call-id>;<scope>`, see
    /// [`crate::rtpengine::backend::engine_call_id`]). siphon-rtp lists only the
    /// node's own scope, so none of these ever meets one of its ids.
    pub(super) fn scoped_engine_call_ids(&self) -> Vec<String> {
        self.scopes
            .iter()
            .flat_map(|entry| {
                let scope = entry.key().clone();
                entry
                    .value()
                    .live_engine_call_ids()
                    .into_iter()
                    .map(move |call_id| {
                        crate::rtpengine::backend::engine_call_id(&call_id, Some(&scope))
                            .into_owned()
                    })
                    .collect::<Vec<_>>()
            })
            .collect()
    }
}
