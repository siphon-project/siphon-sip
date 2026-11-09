//! The registrar over a shared store: read-through for lookups and a single
//! owner for expiry.
//!
//! With several nodes behind one name, each holds its own map of bindings (L1)
//! and writes every change through to the shared store (Redis). Writing is not
//! enough: a node that never wrote an AoR, or wrote it before a peer changed
//! it, would answer from a stale or empty map. So every lookup that names an
//! AoR first brings it up to date from the store when its local copy is older
//! than the freshness window.
//!
//! # Consistency
//!
//! - A binding written, refreshed or removed on one node is seen by every other
//!   node within `read_through_ttl` (default 1 s) of the write reaching the
//!   store, plus one store round trip. The write itself reaches the store
//!   within the write-through queue's delay (milliseconds; longer only while
//!   the store is unreachable).
//! - A node reads its own writes at once: while a local write for an AoR has
//!   not been applied to the store, or changed the AoR while a read was in
//!   flight, the read does not overwrite the local copy.
//! - A lookup that has to read pays one blocking round trip on its own thread
//!   (never on an attached interpreter: the wait releases it),
//!   bounded by [`FETCH_TIMEOUT`]; a store that does not answer degrades the
//!   lookup to the local copy, logged, and is not asked again for one window.
//! - Expiry is owned once. A node whose copy ran out first re-reads the store
//!   (another node may have refreshed it) and only then claims the expiry with
//!   an atomic set-if-absent; the node that wins fires
//!   `RegistrationEvent::Expired`, the others drop their copy silently.
//!
//! Without a shared store nothing here runs: no reader is installed, and every
//! lookup, expiry and write is exactly the local one.

use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::future::BoxFuture;

use super::backend::{BackendError, RegistrarBackend, StoredAorState, StoredContact};
use super::*;

/// The longest one read-through (up to three round trips) may take before the
/// lookup falls back to its local copy.
const FETCH_TIMEOUT: Duration = Duration::from_secs(2);

/// Wait for a read of a shared store on this thread: released from the
/// interpreter if it is attached, and handed off from tokio's scheduler if it
/// is a worker ([`crate::script::blocking`]). `None` on a current-thread
/// runtime, which cannot block: the caller serves its own copy.
pub(crate) fn block_on_shared<T>(
    handle: &tokio::runtime::Handle,
    future: impl std::future::Future<Output = T>,
) -> Option<T> {
    if let Ok(current) = tokio::runtime::Handle::try_current() {
        if !matches!(
            current.runtime_flavor(),
            tokio::runtime::RuntimeFlavor::MultiThread
        ) {
            return None;
        }
    }
    let _entered = handle.enter();
    Some(crate::script::blocking::block_on_released(future))
}

/// What the shared store holds for one AoR.
#[derive(Debug)]
pub(crate) struct SharedAor {
    /// The AoR the bindings are stored under: the name asked for, or the
    /// primary of the implicit set it is an alias of.
    pub(crate) primary: Aor,
    pub(crate) contacts: Vec<StoredContact>,
    pub(crate) state: Option<StoredAorState>,
}

/// Object-safe view of a [`RegistrarBackend`] for the reader.
trait SharedOps: Send + Sync + std::fmt::Debug {
    fn fetch<'a>(&'a self, aor: &'a str) -> BoxFuture<'a, Result<SharedAor, BackendError>>;
    fn claim<'a>(
        &'a self,
        aor: &'a str,
        marker: &'a str,
    ) -> BoxFuture<'a, Result<bool, BackendError>>;
}

#[derive(Debug)]
struct Through<B>(Arc<B>);

impl<B: RegistrarBackend + 'static> SharedOps for Through<B> {
    fn fetch<'a>(&'a self, aor: &'a str) -> BoxFuture<'a, Result<SharedAor, BackendError>> {
        Box::pin(fetch(&*self.0, aor))
    }

    fn claim<'a>(
        &'a self,
        aor: &'a str,
        marker: &'a str,
    ) -> BoxFuture<'a, Result<bool, BackendError>> {
        Box::pin(self.0.claim_expiry(aor, marker))
    }
}

/// Read one AoR from the store: its bindings, or when it has none and is an
/// alias, its primary's; and the auxiliary state of whichever it ended on.
async fn fetch<B: RegistrarBackend>(backend: &B, aor: &str) -> Result<SharedAor, BackendError> {
    let live = |contacts: Vec<StoredContact>| -> Vec<StoredContact> {
        contacts
            .into_iter()
            .filter(|contact| !contact.is_expired())
            .collect()
    };
    let mut contacts = live(backend.load(aor).await?);
    let mut primary = aor.to_string();
    if contacts.is_empty() {
        if let Some(candidate) = backend.load_alias(aor).await? {
            if candidate != aor {
                let state = backend.load_aor_state(&candidate).await?;
                // The alias key is a hint; the primary's own state decides.
                let listed = state.as_ref().is_some_and(|state| {
                    state
                        .associated_uris
                        .iter()
                        .any(|uri| normalize_aor(uri) == aor)
                });
                if listed {
                    return Ok(SharedAor {
                        contacts: live(backend.load(&candidate).await?),
                        primary: candidate,
                        state,
                    });
                }
            }
        }
        contacts = Vec::new();
        primary = aor.to_string();
    }
    let state = backend.load_aor_state(&primary).await?;
    Ok(SharedAor {
        primary,
        contacts,
        state,
    })
}

/// The registrar's handle on the shared store.
#[derive(Debug, Clone)]
pub struct SharedReader {
    ops: Arc<dyn SharedOps>,
    /// The runtime reads run on when the caller is not on one.
    handle: tokio::runtime::Handle,
    /// How long a local copy of an AoR is served without asking the store.
    freshness: Duration,
}

impl SharedReader {
    /// A reader over `backend`, the store the registrar's writer also writes
    /// to. Call from within the runtime. `freshness` is the window a local
    /// copy is served for; it is the bound on how stale another node's change
    /// can look.
    pub fn new<B: RegistrarBackend + 'static>(backend: Arc<B>, freshness: Duration) -> Self {
        Self {
            ops: Arc::new(Through(backend)),
            handle: tokio::runtime::Handle::current(),
            freshness,
        }
    }

    /// Run `future` to completion on this thread, or `None` when the thread
    /// cannot block (a current-thread runtime), so the caller keeps its local
    /// copy. See [`block_on_shared`].
    fn block<T>(&self, future: impl std::future::Future<Output = T>) -> Option<T> {
        block_on_shared(&self.handle, future)
    }

    fn fetch_blocking(&self, aor: &str) -> Option<Result<SharedAor, BackendError>> {
        let read = tokio::time::timeout(FETCH_TIMEOUT, self.ops.fetch(aor));
        self.block(read).map(|outcome| {
            outcome.unwrap_or_else(|_| {
                Err(BackendError::Timeout(format!(
                    "the shared registrar store did not answer within {}s",
                    FETCH_TIMEOUT.as_secs()
                )))
            })
        })
    }

    fn claim_blocking(&self, aor: &str, marker: &str) -> Option<Result<bool, BackendError>> {
        let claim = tokio::time::timeout(FETCH_TIMEOUT, self.ops.claim(aor, marker));
        self.block(claim).map(|outcome| {
            outcome.unwrap_or_else(|_| {
                Err(BackendError::Timeout(format!(
                    "the shared registrar store did not answer within {}s",
                    FETCH_TIMEOUT.as_secs()
                )))
            })
        })
    }
}

/// What a node does about an AoR whose local bindings all ran out.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ExpiryVerdict {
    /// This node owns the expiry: drop the AoR and announce it.
    Announce,
    /// Another node owns it: drop the local copy, say nothing.
    DropQuietly,
    /// The store still holds live bindings (another node refreshed them):
    /// they are installed, keep the AoR.
    Keep,
}

/// A binding as the local map sees it, for noticing a local change.
type Fingerprint = Vec<(String, Instant, u32)>;

fn fingerprint(contacts: &[Contact]) -> Fingerprint {
    contacts
        .iter()
        .map(|contact| (contact.uri.to_string(), contact.registered_at, contact.cseq))
        .collect()
}

/// The identity of one generation of an AoR's bindings, equal on every node
/// that holds them: two nodes that lose the same bindings name the same
/// expiry.
pub(crate) fn expiry_marker(contacts: &[&Contact]) -> String {
    use std::hash::{Hash, Hasher};
    let mut keys: Vec<(String, u32, String)> = contacts
        .iter()
        .map(|contact| {
            (
                contact.call_id.to_string(),
                contact.cseq,
                contact.uri.to_string(),
            )
        })
        .collect();
    keys.sort();
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    keys.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

impl Registrar {
    /// Read AoRs through `reader` from now on. Set once, at boot, after the
    /// restore and with the backend writer.
    pub fn set_shared_reader(&self, reader: SharedReader) {
        let _ = self.shared.set(reader);
    }

    /// [`resolve_alias`](Self::resolve_alias) after bringing `aor` up to date
    /// from the shared store when a reader is installed and the local copy is
    /// older than its freshness window.
    pub(super) fn resolve_fresh(&self, aor: &str) -> Aor {
        if let Some(reader) = self.shared.get() {
            self.refresh_from_shared(reader, &normalize_aor_cow(aor));
        }
        self.resolve_alias(aor)
    }

    fn write_pending(&self, aor: &str) -> bool {
        self.backend_writer
            .get()
            .is_some_and(|writer| writer.has_pending(aor))
    }

    fn refresh_from_shared(&self, reader: &SharedReader, aor: &str) {
        let now = Instant::now();
        if self
            .shared_fetched
            .get(aor)
            .is_some_and(|at| now.duration_since(*at) < reader.freshness)
        {
            return;
        }
        // What the local map holds now, under the names the answer may come
        // back as: a local write that lands while the read is in flight
        // changes it, and then the read must not overwrite it.
        let local_primary = self.resolve_alias(aor);
        let before: Vec<(Aor, Option<Fingerprint>)> = [aor, local_primary.as_str()]
            .iter()
            .map(|name| {
                (
                    name.to_string(),
                    self.bindings.get(*name).map(|e| fingerprint(e.value())),
                )
            })
            .collect();
        // A write of ours still on its way makes the store older than memory:
        // a read taken now would come back with the old answer even if the
        // write lands before it returns, so do not read until it has.
        if before.iter().any(|(name, _)| self.write_pending(name)) {
            return;
        }
        let Some(outcome) = reader.fetch_blocking(aor) else {
            return;
        };
        match outcome {
            Ok(shared) => {
                let seen = before
                    .iter()
                    .find(|(name, _)| *name == shared.primary)
                    .map(|(_, print)| print.clone());
                if self.install_shared(&shared, seen) {
                    self.shared_fetched.insert(aor.to_string(), Instant::now());
                    self.shared_fetched
                        .insert(shared.primary.clone(), Instant::now());
                }
            }
            Err(error) => {
                tracing::error!(
                    aor,
                    %error,
                    "registrar: the shared store could not be read, serving the local copy"
                );
                // Not asked again for a window: a store that is down must not
                // cost every lookup a timeout.
                self.shared_fetched.insert(aor.to_string(), now);
            }
        }
    }

    /// Make the local copy of `shared.primary` what the store says, unless a
    /// local write is in flight or landed since `seen` (`None` inside means the
    /// AoR was absent; outside, that it was not looked at). Returns whether the
    /// store's answer was applied.
    fn install_shared(&self, shared: &SharedAor, seen: Option<Option<Fingerprint>>) -> bool {
        let primary = shared.primary.as_str();
        if self.write_pending(primary) {
            return false;
        }
        let mut dropped_tokens: Vec<String> = Vec::new();
        let mut added_tokens: Vec<String> = Vec::new();
        let mut dropped_connections: Vec<u64> = Vec::new();
        {
            let current = self.bindings.entry(primary.to_string());
            let existing = match &current {
                dashmap::mapref::entry::Entry::Occupied(entry) => entry.get().as_slice(),
                dashmap::mapref::entry::Entry::Vacant(_) => &[][..],
            };
            let unchanged = match &seen {
                Some(print) => print.as_deref().unwrap_or(&[]) == fingerprint(existing).as_slice(),
                None => existing.is_empty(),
            };
            if !unchanged {
                return false;
            }
            let mut merged: Vec<Contact> = shared
                .contacts
                .iter()
                .filter_map(|stored| {
                    // The copy this node wrote is richer than its stored image
                    // (live flow handles), so it stays when nothing changed.
                    existing
                        .iter()
                        .find(|local| {
                            self.is_local_contact(local)
                                && local.uri.to_string() == stored.uri
                                && *local.call_id == *stored.call_id
                                && local.cseq == stored.cseq
                        })
                        .cloned()
                        .or_else(|| stored.to_contact())
                })
                .collect();
            merged.sort_by(|a, b| b.q.partial_cmp(&a.q).unwrap_or(std::cmp::Ordering::Equal));
            for contact in existing {
                if !merged
                    .iter()
                    .any(|kept| kept.uri.to_string() == contact.uri.to_string())
                {
                    if let Some(token) = &contact.flow_token {
                        dropped_tokens.push(token.to_string());
                    }
                    if is_stream_transport(contact.source_transport) {
                        dropped_connections.extend(contact.inbound_connection_id);
                    }
                }
            }
            for contact in &merged {
                if let Some(token) = &contact.flow_token {
                    added_tokens.push(token.to_string());
                }
            }
            self.contact_index.replace(
                primary,
                self.contact_index.keys_of(existing),
                self.contact_index.keys_of(&merged),
            );
            match current {
                dashmap::mapref::entry::Entry::Occupied(mut entry) => {
                    if merged.is_empty() {
                        entry.remove();
                        if let Some(metrics) = crate::metrics::try_metrics() {
                            metrics.registrations_active.dec();
                        }
                    } else {
                        *entry.get_mut() = merged;
                    }
                }
                dashmap::mapref::entry::Entry::Vacant(entry) => {
                    if !merged.is_empty() {
                        entry.insert(merged);
                        if let Some(metrics) = crate::metrics::try_metrics() {
                            metrics.registrations_active.inc();
                        }
                    }
                }
            }
        }
        for token in &dropped_tokens {
            self.tokens.remove(token);
        }
        for token in added_tokens {
            self.tokens.insert(token, primary.to_string());
        }
        for id in dropped_connections {
            self.deindex_connection(id, primary);
        }
        if !self.write_pending(primary) {
            self.prune_aliases_to(primary);
            self.remove_aor_state_entries(primary);
            if let Some(state) = shared.state.clone() {
                self.apply_aor_state(primary, state);
            }
        }
        true
    }

    /// Decide what to do about `aor`, whose local bindings (`markers` names
    /// them) all ran out: see [`ExpiryVerdict`]. Without a shared reader the
    /// node owns every expiry it sees.
    pub(super) fn judge_expiry(&self, aor: &str, marker: &str) -> ExpiryVerdict {
        let Some(reader) = self.shared.get() else {
            return ExpiryVerdict::Announce;
        };
        match reader.fetch_blocking(aor) {
            Some(Ok(shared)) if !shared.contacts.is_empty() => {
                if self.install_shared(&shared, None) {
                    self.shared_fetched.insert(aor.to_string(), Instant::now());
                    return ExpiryVerdict::Keep;
                }
            }
            Some(Err(error)) => {
                tracing::error!(
                    aor,
                    %error,
                    "registrar: could not confirm an expiry against the shared store, announcing it"
                );
                return ExpiryVerdict::Announce;
            }
            _ => {}
        }
        match reader.claim_blocking(aor, marker) {
            Some(Ok(false)) => ExpiryVerdict::DropQuietly,
            Some(Err(error)) => {
                tracing::error!(
                    aor,
                    %error,
                    "registrar: could not claim an expiry in the shared store, announcing it"
                );
                ExpiryVerdict::Announce
            }
            _ => ExpiryVerdict::Announce,
        }
    }

    /// Forget the freshness of AoRs not read for two windows, so scanners
    /// asking for random AoRs do not grow the map.
    pub(super) fn trim_shared_freshness(&self) {
        if let Some(reader) = self.shared.get() {
            let horizon = reader.freshness.saturating_mul(2);
            self.shared_fetched.retain(|_, at| at.elapsed() < horizon);
        }
    }
}

#[cfg(test)]
#[path = "shared_tests.rs"]
mod tests;
