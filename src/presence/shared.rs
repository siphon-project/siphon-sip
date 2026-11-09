//! The presence store over a shared Redis: subscriptions owned across nodes.
//!
//! The S-CSCF's reg-event notifier keeps its watchers here. With several
//! S-CSCF nodes behind one name a SUBSCRIBE lands on one node while the
//! registration it watches changes on another, and a node that dies leaves
//! watchers nobody else knows. So the store reads through to the Redis every
//! write already goes to, the way the registrar does
//! ([`crate::registrar`]'s `shared` module), and numbers NOTIFYs there.
//!
//! # Consistency
//!
//! - The watchers of a resource ([`PresenceStore::subscriptions_for`]), a
//!   dialog ([`PresenceStore::find_subscription_by_dialog`]) and a subscription
//!   a node has not seen ([`PresenceStore::get_subscription`] and every
//!   operation that starts from an id) are read from Redis when the node does
//!   not have them, or has the resource's set older than `freshness`. A
//!   subscription made, refreshed or ended on one node is seen on another
//!   within `freshness` (default 1 s) plus a round trip once its write reached
//!   Redis.
//! - A node's own unwritten changes are never overwritten by a read.
//! - **CSeq and reginfo version are reserved in Redis**, atomically
//!   ([`PresenceStore::prepare_notify`], [`PresenceStore::next_version`]), so
//!   two nodes notifying one dialog never send the same CSeq or the same
//!   version, and each is above everything either sent before (RFC 3261
//!   section 12.2.1.1, RFC 3680 section 5.2). Redis unreachable: the node
//!   counts on its own and says so, since a NOTIFY not sent is worse than one
//!   a subscriber may answer with an error.
//! - **A notification is claimed** with an atomic set-if-absent
//!   ([`PresenceStore::claim_notification`]): of the nodes that react to one
//!   change, the one that wins the claim for a subscription sends its NOTIFY.
//! - The expiry sweep re-reads Redis before it ends a subscription whose local
//!   copy ran out: another node may have refreshed it.
//!
//! Without a shared store (no Redis, or `read_through_ttl_ms: 0`) none of this
//! runs.

use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::future::BoxFuture;

use super::persist::{unix_now, StoredSubscription};
use super::*;
use crate::registrar::backend::BackendError;

/// The longest one read may take before the caller serves its own copy.
const FETCH_TIMEOUT: Duration = Duration::from_secs(2);

/// What of a subscription a local change touches: a refresh (generation), a
/// NOTIFY (CSeq, version) or an end (state).
type Fingerprint = (u64, u32, u32, SubscriptionState);

fn fingerprint(subscription: &Subscription) -> Fingerprint {
    (
        subscription.generation,
        subscription.local_cseq,
        subscription.next_version,
        subscription.state,
    )
}

/// What memory held of some subscriptions when a read of the store began.
///
/// A read is older than any write of ours that was still on its way when it
/// began (it may return the store's answer from before the write even if the
/// write lands before the read returns), and than any local change made while
/// it ran. Neither may be overwritten by it.
#[derive(Default)]
struct Start {
    prints: std::collections::HashMap<String, Fingerprint>,
    unsettled: std::collections::HashSet<String>,
}

/// What a reserved number counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Counter {
    /// The CSeq of the next NOTIFY in the dialog.
    Cseq,
    /// The version of the next event-state document.
    Version,
}

/// The shared store as the presence store reads and numbers through it.
pub(crate) trait SharedSubscriptions: Send + Sync + std::fmt::Debug {
    /// The live subscriptions watching `resource`.
    fn by_resource<'a>(
        &'a self,
        resource: &'a str,
    ) -> BoxFuture<'a, Result<Vec<StoredSubscription>, BackendError>>;
    /// One subscription.
    fn by_id<'a>(
        &'a self,
        id: &'a str,
    ) -> BoxFuture<'a, Result<Option<StoredSubscription>, BackendError>>;
    /// The subscription of dialog `(call_id, from_tag)`.
    fn by_dialog<'a>(
        &'a self,
        call_id: &'a str,
        from_tag: &'a str,
    ) -> BoxFuture<'a, Result<Option<StoredSubscription>, BackendError>>;
    /// The next number of `counter` for `id`, at least `floor`, handed out
    /// once across every node, kept `ttl_secs`.
    fn next_counter<'a>(
        &'a self,
        id: &'a str,
        counter: Counter,
        floor: u32,
        ttl_secs: u64,
    ) -> BoxFuture<'a, Result<u32, BackendError>>;
    /// Claim `(id, marker)`: true for the first caller only.
    fn claim<'a>(
        &'a self,
        id: &'a str,
        marker: &'a str,
    ) -> BoxFuture<'a, Result<bool, BackendError>>;
}

/// The presence store's handle on the shared store.
#[derive(Debug, Clone)]
pub struct SharedPresence {
    ops: Arc<dyn SharedSubscriptions>,
    handle: tokio::runtime::Handle,
    freshness: Duration,
    /// Added to a counter's TTL beyond the subscription's remaining life.
    ttl_slack_secs: u64,
}

impl SharedPresence {
    #[cfg_attr(not(any(feature = "redis-backend", test)), allow(dead_code))]
    pub(crate) fn new(
        ops: Arc<dyn SharedSubscriptions>,
        freshness: Duration,
        ttl_slack_secs: u64,
    ) -> Self {
        Self {
            ops,
            handle: tokio::runtime::Handle::current(),
            freshness,
            ttl_slack_secs,
        }
    }

    /// Subscriptions on the Redis `connection` reaches, under `prefix` (the
    /// presence key prefix their write-through uses).
    #[cfg(feature = "redis-backend")]
    pub fn redis(
        connection: crate::redis_target::RedisConnection,
        prefix: String,
        freshness: Duration,
        ttl_slack_secs: u64,
    ) -> Self {
        Self::new(
            Arc::new(super::shared_redis::RedisSubscriptions::new(
                connection, prefix,
            )),
            freshness,
            ttl_slack_secs,
        )
    }

    /// Run `future` on this thread with a deadline; `None` when the thread
    /// cannot block.
    fn block<T>(
        &self,
        future: impl std::future::Future<Output = T>,
    ) -> Option<Result<T, BackendError>> {
        let bounded = async {
            tokio::time::timeout(FETCH_TIMEOUT, future)
                .await
                .map_err(|_| {
                    BackendError::Timeout(format!(
                        "the shared presence store did not answer within {}s",
                        FETCH_TIMEOUT.as_secs()
                    ))
                })
        };
        crate::registrar::block_on_shared(&self.handle, bounded)
    }
}

impl PresenceStore {
    /// Read subscriptions through `shared` from now on. Set once, at boot,
    /// with the backend writer.
    pub fn set_shared(&self, shared: SharedPresence) {
        let _ = self.shared.set(shared);
    }

    /// Forget the freshness of resources not read for two windows.
    pub(super) fn trim_fetched(&self) {
        if let Some(shared) = self.shared.get() {
            let horizon = shared.freshness.saturating_mul(2);
            self.fetched.retain(|_, at| at.elapsed() < horizon);
        }
    }

    fn fresh(&self, key: &str, shared: &SharedPresence) -> bool {
        self.fetched
            .get(key)
            .is_some_and(|at| at.elapsed() < shared.freshness)
    }

    /// A write of ours for subscription `id` has not reached the store.
    pub(super) fn write_unsettled(&self, id: &str) -> bool {
        self.backend
            .get()
            .is_some_and(|writer| writer.is_unsettled(id))
    }

    /// Memory's subscriptions `ids` as they are now.
    fn start_of<'a>(&self, ids: impl IntoIterator<Item = &'a String>) -> Start {
        let mut start = Start::default();
        for id in ids {
            if self.write_unsettled(id) {
                start.unsettled.insert(id.clone());
            }
            if let Some(subscription) = self.subscriptions.get(id) {
                start.prints.insert(id.clone(), fingerprint(&subscription));
            }
        }
        start
    }

    /// Make memory's copy of `stored` what the store holds, unless a write of
    /// ours is on its way or a local change landed since `start`. Returns
    /// whether it was applied.
    fn install(&self, stored: StoredSubscription, start: &Start) -> bool {
        let id = stored.id.clone();
        if start.unsettled.contains(&id) || self.write_unsettled(&id) {
            return false;
        }
        let Some(mut incoming) = stored.into_subscription(unix_now()) else {
            // Expired or terminated there.
            self.forget_local_if(&id, start);
            return true;
        };
        let resource = incoming.resource.clone();
        match self.subscriptions.entry(id.clone()) {
            dashmap::mapref::entry::Entry::Occupied(mut entry) => {
                let local = entry.get_mut();
                if start.prints.get(&id) != Some(&fingerprint(local)) {
                    return false;
                }
                // Numbers never go back, whatever the stored copy says.
                incoming.local_cseq = incoming.local_cseq.max(local.local_cseq);
                incoming.next_version = incoming.next_version.max(local.next_version);
                // A refresh made elsewhere is a new incarnation, so a late
                // NOTIFY failure of the old one leaves it alone.
                let same = incoming.state == local.state
                    && incoming
                        .remaining_seconds()
                        .abs_diff(local.remaining_seconds())
                        <= 1;
                incoming.generation = if same {
                    local.generation
                } else {
                    next_generation()
                };
                *local = incoming;
            }
            dashmap::mapref::entry::Entry::Vacant(entry) => {
                if start.prints.contains_key(&id) {
                    // Removed here while the read ran: not brought back.
                    return false;
                }
                incoming.generation = next_generation();
                entry.insert(incoming);
                self.watchers.entry(resource).or_default().push(id);
            }
        }
        true
    }

    /// Drop `id` from memory, which the store does not hold, unless a write
    /// of ours is on its way or a local change landed since `start`.
    fn forget_local_if(&self, id: &str, start: &Start) {
        if start.unsettled.contains(id) || self.write_unsettled(id) {
            return;
        }
        let removed = self.subscriptions.remove_if(id, |_, local| {
            start.prints.get(id) == Some(&fingerprint(local))
        });
        if let Some((_, subscription)) = removed {
            self.forget_watcher(id, &subscription.resource);
        }
    }

    /// Bring the watchers of `resource` up to date from the store when memory's
    /// set is older than the freshness window.
    pub(super) fn refresh_resource(&self, resource: &str) {
        let Some(shared) = self.shared.get() else {
            return;
        };
        if self.fresh(resource, shared) {
            return;
        }
        let local: Vec<String> = self
            .watchers
            .get(resource)
            .map(|ids| ids.clone())
            .unwrap_or_default();
        let start = self.start_of(&local);
        let Some(outcome) = shared.block(shared.ops.by_resource(resource)) else {
            return;
        };
        match outcome.and_then(|read| read) {
            Ok(stored) => {
                let seen: std::collections::HashSet<String> =
                    stored.iter().map(|sub| sub.id.clone()).collect();
                for subscription in stored {
                    self.install(subscription, &start);
                }
                for id in local {
                    if !seen.contains(&id) {
                        self.forget_local_if(&id, &start);
                    }
                }
            }
            Err(error) => {
                tracing::error!(
                    resource,
                    %error,
                    "presence: the shared store could not be read, serving the local watchers"
                );
            }
        }
        // On failure too: a store that is down must not cost every call a timeout.
        self.fetched.insert(resource.to_string(), Instant::now());
    }

    /// Load subscription `id` from the store when memory has not got it.
    pub(super) fn ensure_local(&self, id: &str) {
        let Some(shared) = self.shared.get() else {
            return;
        };
        if self.subscriptions.contains_key(id) {
            return;
        }
        match shared.block(shared.ops.by_id(id)) {
            Some(Ok(Ok(Some(stored)))) => {
                self.install(stored, &Start::default());
            }
            Some(Ok(Ok(None))) | None => {}
            Some(Ok(Err(error))) | Some(Err(error)) => {
                tracing::error!(
                    subscription_id = id,
                    %error,
                    "presence: the shared store could not be read for a subscription"
                );
            }
        }
    }

    /// The subscription of dialog `(call_id, from_tag)` in the store, loaded
    /// into memory, for a node that has not got it.
    pub(super) fn find_in_shared_by_dialog(&self, call_id: &str, from_tag: &str) -> Option<String> {
        let shared = self.shared.get()?;
        match shared.block(shared.ops.by_dialog(call_id, from_tag))? {
            Ok(Ok(Some(stored))) => {
                let id = stored.id.clone();
                self.install(stored, &Start::default());
                self.subscriptions
                    .get(&id)
                    .filter(|sub| sub.state != SubscriptionState::Terminated)
                    .map(|_| id)
            }
            Ok(Ok(None)) => None,
            Ok(Err(error)) | Err(error) => {
                tracing::error!(%error, "presence: the shared store could not be read for a dialog");
                None
            }
        }
    }

    /// Reserve the next number of `counter` for `id` in the store: `Some(n)`
    /// when it did, `None` when there is no store or it failed (logged).
    pub(super) fn reserve(&self, id: &str, counter: Counter) -> Option<u32> {
        let shared = self.shared.get()?;
        let (floor, remaining) = {
            let subscription = self.subscriptions.get(id)?;
            let floor = match counter {
                Counter::Cseq => subscription.local_cseq.saturating_add(1),
                Counter::Version => subscription.next_version,
            };
            (floor, subscription.remaining_seconds())
        };
        let ttl = remaining.saturating_add(shared.ttl_slack_secs).max(1);
        match shared.block(shared.ops.next_counter(id, counter, floor, ttl))? {
            Ok(Ok(number)) => Some(number),
            Ok(Err(error)) | Err(error) => {
                tracing::error!(
                    subscription_id = id,
                    ?counter,
                    %error,
                    "presence: could not reserve a number in the shared store, \
                     counting on this node alone"
                );
                None
            }
        }
    }

    /// Claim the notification identified by `marker` for subscription `id`:
    /// `true` for the one node that should send it. Always `true` without a
    /// shared store, or when it cannot be reached (logged): a NOTIFY sent
    /// twice is the lesser harm.
    pub fn claim_notification(&self, id: &str, marker: &str) -> bool {
        let Some(shared) = self.shared.get() else {
            return true;
        };
        match shared.block(shared.ops.claim(id, marker)) {
            Some(Ok(Ok(won))) => won,
            Some(Ok(Err(error))) | Some(Err(error)) => {
                tracing::error!(
                    subscription_id = id,
                    %error,
                    "presence: could not claim a notification in the shared store, sending it"
                );
                true
            }
            None => true,
        }
    }

    /// Whether the expiry sweep should end subscription `id`, whose local copy
    /// ran out: `false` when the store holds a live copy (another node
    /// refreshed it), which is then installed instead.
    pub(super) fn confirm_expired(&self, id: &str) -> bool {
        let Some(shared) = self.shared.get() else {
            return true;
        };
        let start = self.start_of([&id.to_string()]);
        if start.unsettled.contains(id) {
            return true;
        }
        let Some(Ok(Ok(Some(stored)))) = shared.block(shared.ops.by_id(id)) else {
            return true;
        };
        if stored.state == "terminated" || stored.remaining_secs(unix_now()) == 0 {
            return true;
        }
        // Another node refreshed it: keep it, in its refreshed form.
        !(self.install(stored, &start) && self.live(id))
    }

    fn live(&self, id: &str) -> bool {
        self.subscriptions
            .get(id)
            .is_some_and(|sub| !sub.is_expired() && sub.state != SubscriptionState::Terminated)
    }
}
