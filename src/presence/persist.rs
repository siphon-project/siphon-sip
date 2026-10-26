//! The presence store's write-through to the registrar's Redis, and its
//! restore at boot.
//!
//! The store is otherwise memory-only, so a restarted notifier forgot every
//! subscription: state changes and terminating NOTIFYs reached no watcher until
//! each re-SUBSCRIBEd, up to a whole refresh interval later. With the
//! registrar on Redis, every change to a subscription is written through, and
//! the boot restores them before any listener is up.
//!
//! The writes go through the registrar's coalescing queue
//! ([`crate::registrar::backend::coalesce`]): each one is the whole state of
//! one subscription (or its removal), so only the latest per id matters. A
//! newer write replaces an older one still waiting, a burst holds one entry
//! per subscription and drops nothing, and a write Redis refuses is retried
//! with backoff over a link that reconnects. The store takes each write's
//! [`WriteSequence`] while it holds the subscription's entry, so a snapshot
//! that reaches the queue late never overwrites a newer one.
//!
//! Every key carries a TTL of the subscription's remaining lifetime plus the
//! registrar's `ttl_slack_secs`, renewed by each write, so an abandoned
//! subscription leaves Redis by itself.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use super::{Subscription, SubscriptionState};
#[cfg(any(feature = "redis-backend", test))]
use crate::registrar::backend::coalesce::{self, DrainEvent, QueueKind, WriteSink};
use crate::registrar::backend::coalesce::{QueueHandle, QueuedWrite};
#[cfg(feature = "redis-backend")]
use crate::registrar::backend::redis_link::RedisLink;
#[cfg(feature = "redis-backend")]
use crate::registrar::backend::BackendError;
use crate::registrar::backend::WriteSequence;

/// Default key prefix of the subscriptions in Redis, apart from the
/// registrar's own keyspace so neither restore walks the other's keys.
pub const DEFAULT_PRESENCE_KEY_PREFIX: &str = "siphon:presence:";

/// Seconds since the Unix epoch.
pub(crate) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

/// One subscription as Redis holds it: everything needed to send it an
/// in-dialog NOTIFY after a restart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredSubscription {
    pub id: String,
    /// The subscriber's Contact, the dialog's remote target.
    pub subscriber: String,
    pub resource: String,
    pub event: String,
    /// `init`, `active` or `pending`; a terminated one is never stored.
    pub state: String,
    /// When the subscription expires, in Unix seconds.
    pub expires_at_unix: u64,
    #[serde(default)]
    pub dialog_id: Option<String>,
    #[serde(default)]
    pub accept: Vec<String>,
    #[serde(default)]
    pub call_id: Option<String>,
    #[serde(default)]
    pub from_tag: Option<String>,
    #[serde(default)]
    pub to_tag: Option<String>,
    #[serde(default)]
    pub route_set: Vec<String>,
    /// The CSeq of the last NOTIFY sent in the dialog.
    #[serde(default)]
    pub local_cseq: u32,
    #[serde(default)]
    pub local_uri: Option<String>,
    #[serde(default)]
    pub remote_uri: Option<String>,
    /// The version the next event-state document carries.
    #[serde(default)]
    pub next_version: u32,
}

impl StoredSubscription {
    /// The stored form of `subscription` as of now.
    pub fn of(subscription: &Subscription) -> Self {
        let remaining = subscription
            .expires
            .saturating_sub(subscription.created_at.elapsed());
        Self {
            id: subscription.id.clone(),
            subscriber: subscription.subscriber.clone(),
            resource: subscription.resource.clone(),
            event: subscription.event.clone(),
            state: subscription.state.to_string(),
            expires_at_unix: unix_now().saturating_add(remaining.as_secs()),
            dialog_id: subscription.dialog_id.clone(),
            accept: subscription.accept.clone(),
            call_id: subscription.call_id.clone(),
            from_tag: subscription.from_tag.clone(),
            to_tag: subscription.to_tag.clone(),
            route_set: subscription.route_set.clone(),
            local_cseq: subscription.local_cseq,
            local_uri: subscription.local_uri.clone(),
            remote_uri: subscription.remote_uri.clone(),
            next_version: subscription.next_version,
        }
    }

    /// Seconds left at `now_unix`, zero once expired.
    pub fn remaining_secs(&self, now_unix: u64) -> u64 {
        self.expires_at_unix.saturating_sub(now_unix)
    }

    /// The live subscription this rebuilds at `now_unix`, or `None` when it
    /// has expired (or was stored terminated): such an entry is dropped, never
    /// resurrected.
    ///
    /// The dialog continues where it stopped: its next NOTIFY carries one CSeq
    /// more than the last one stored (RFC 3261 §12.2.1.1), and its next
    /// document the version stored as next (RFC 3680 §5.2).
    pub fn into_subscription(self, now_unix: u64) -> Option<Subscription> {
        let remaining = self.remaining_secs(now_unix);
        let state = match self.state.as_str() {
            "init" => SubscriptionState::Init,
            "active" => SubscriptionState::Active,
            "pending" => SubscriptionState::Pending,
            _ => return None,
        };
        if remaining == 0 {
            return None;
        }
        Some(Subscription {
            id: self.id,
            subscriber: self.subscriber,
            resource: self.resource,
            event: self.event,
            state,
            expires: Duration::from_secs(remaining),
            created_at: Instant::now(),
            dialog_id: self.dialog_id,
            accept: self.accept,
            call_id: self.call_id,
            from_tag: self.from_tag,
            to_tag: self.to_tag,
            route_set: self.route_set,
            local_cseq: self.local_cseq,
            local_uri: self.local_uri,
            remote_uri: self.remote_uri,
            generation: 0,
            next_version: self.next_version,
        })
    }
}

/// One write-through: the desired Redis state of one subscription's key.
#[derive(Debug)]
pub enum PresenceWrite {
    /// Store the subscription's JSON for `ttl_secs`.
    Save { json: String, ttl_secs: u64 },
    /// Remove the subscription.
    Remove,
}

impl QueuedWrite for PresenceWrite {
    fn label(&self) -> &'static str {
        match self {
            Self::Save { .. } => "save",
            Self::Remove => "remove",
        }
    }
}

/// Handle for the presence store's write-through. Methods never wait, so
/// they are safe from a thread attached to the interpreter and from a tokio
/// worker.
#[derive(Debug, Clone)]
pub struct PresenceBackendWriter {
    queue: QueueHandle<String, PresenceWrite>,
    /// Added to each key's TTL beyond the subscription's own expiry.
    ttl_slack_secs: u64,
}

impl PresenceBackendWriter {
    /// The order of a write about to be issued: take it while holding the
    /// subscription's entry.
    pub fn sequence(&self) -> WriteSequence {
        self.queue.sequence()
    }

    /// Store `stored`, a snapshot taken at `sequence`. An older write never
    /// replaces a newer one.
    pub fn save_at(&self, stored: &StoredSubscription, sequence: WriteSequence) {
        let json = match serde_json::to_string(stored) {
            Ok(json) => json,
            Err(error) => {
                // A struct of strings and integers: unreachable, and loud.
                tracing::error!(
                    subscription_id = %stored.id,
                    %error,
                    "presence: subscription not written through, it could not be serialized"
                );
                return;
            }
        };
        let ttl_secs = stored
            .remaining_secs(unix_now())
            .saturating_add(self.ttl_slack_secs)
            .max(1);
        self.queue.enqueue(
            stored.id.clone(),
            &stored.id,
            PresenceWrite::Save { json, ttl_secs },
            sequence,
        );
    }

    /// Remove subscription `id`, a removal decided at `sequence`.
    pub fn remove_at(&self, id: &str, sequence: WriteSequence) {
        self.queue
            .enqueue(id.to_string(), id, PresenceWrite::Remove, sequence);
    }

    /// Subscriptions whose latest write has not been applied yet.
    #[cfg(test)]
    pub(crate) fn pending_writes(&self) -> usize {
        self.queue.pending_writes()
    }
}

/// Spawn the task that drains a presence writer into `sink`. It runs until
/// every handle is dropped.
#[cfg(any(feature = "redis-backend", test))]
pub(crate) fn spawn_presence_writer<S: WriteSink<String, PresenceWrite> + 'static>(
    sink: S,
    ttl_slack_secs: u64,
) -> PresenceBackendWriter {
    let (queue, mut drainer) = coalesce::queue(QueueKind::Presence);
    tokio::spawn(async move {
        loop {
            drainer.attempt(&sink).await;
            if let DrainEvent::Closed = drainer.next_event().await {
                break;
            }
        }
        drainer.finish(&sink).await;
    });
    PresenceBackendWriter {
        queue,
        ttl_slack_secs,
    }
}

/// Spawn the presence writer on a Redis client and a connection already open
/// on it, reconnecting when the link drops.
#[cfg(feature = "redis-backend")]
pub fn spawn_presence_redis_writer(
    client: redis::Client,
    connection: redis::aio::MultiplexedConnection,
    key_prefix: String,
    ttl_slack_secs: u64,
) -> PresenceBackendWriter {
    spawn_presence_writer(
        PresenceRedisSink {
            link: RedisLink::with_connection(client, connection),
            key_prefix,
        },
        ttl_slack_secs,
    )
}

/// Applies presence writes to Redis: `SET .. EX` for a subscription, `DEL`
/// for a removal, a batch at a time pipelined on the multiplexed connection.
#[cfg(feature = "redis-backend")]
struct PresenceRedisSink {
    link: RedisLink,
    key_prefix: String,
}

#[cfg(feature = "redis-backend")]
impl WriteSink<String, PresenceWrite> for PresenceRedisSink {
    async fn apply_batch(
        &self,
        writes: &[(&String, &PresenceWrite)],
    ) -> Vec<Result<(), BackendError>> {
        use redis::AsyncCommands;
        futures_util::future::join_all(writes.iter().map(|(id, write)| {
            let key = format!("{}{id}", self.key_prefix);
            async move {
                let mut lease = self.link.lease().await?;
                let connection = &mut lease.connection;
                let result: Result<(), redis::RedisError> = match write {
                    PresenceWrite::Save { json, ttl_secs } => {
                        connection.set_ex(&key, json.as_str(), *ttl_secs).await
                    }
                    PresenceWrite::Remove => connection.del(&key).await,
                };
                result.map_err(|error| self.link.fail(&lease, error))
            }
        }))
        .await
    }
}

/// What a restore found.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RestoreCounts {
    /// Subscriptions put back in the store.
    pub restored: usize,
    /// Entries dropped: expired, terminated or unreadable.
    pub dropped: usize,
}

/// How many keys one `MGET` of the restore reads.
#[cfg(feature = "redis-backend")]
const RESTORE_BATCH: usize = 500;

/// Read every subscription under `key_prefix` back into `store`, dropping
/// the expired ones, and return the ids of the dropped keys still present so
/// the caller can delete them once the writer runs.
///
/// Boot-time only, before any listener is up: a cursor `SCAN`, then `MGET` in
/// batches of [`RESTORE_BATCH`].
#[cfg(feature = "redis-backend")]
pub async fn restore_presence_subscriptions(
    connection: &mut redis::aio::MultiplexedConnection,
    key_prefix: &str,
    store: &super::PresenceStore,
) -> Result<(RestoreCounts, Vec<String>), String> {
    let pattern = format!("{key_prefix}*");
    // A set, because SCAN may return a key more than once.
    let mut keys: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut cursor: u64 = 0;
    loop {
        let (next_cursor, batch): (u64, Vec<String>) = redis::cmd("SCAN")
            .arg(cursor)
            .arg("MATCH")
            .arg(&pattern)
            .arg("COUNT")
            .arg(1000)
            .query_async(connection)
            .await
            .map_err(|error| format!("SCAN failed: {error}"))?;
        keys.extend(batch);
        cursor = next_cursor;
        if cursor == 0 {
            break;
        }
    }

    let keys: Vec<String> = keys.into_iter().collect();
    let now = unix_now();
    let mut counts = RestoreCounts::default();
    let mut dropped_ids = Vec::new();
    for chunk in keys.chunks(RESTORE_BATCH) {
        let values: Vec<Option<String>> = redis::cmd("MGET")
            .arg(chunk)
            .query_async(connection)
            .await
            .map_err(|error| format!("MGET failed: {error}"))?;
        for (key, value) in chunk.iter().zip(values) {
            // Gone between the SCAN and the MGET: its TTL ran out.
            let Some(json) = value else { continue };
            let id = key.strip_prefix(key_prefix).unwrap_or(key).to_string();
            match serde_json::from_str::<StoredSubscription>(&json)
                .map_err(|error| error.to_string())
                .map(|stored| stored.into_subscription(now))
            {
                Ok(Some(subscription)) => {
                    store.restore_subscription(subscription);
                    counts.restored += 1;
                }
                Ok(None) => {
                    counts.dropped += 1;
                    dropped_ids.push(id);
                }
                Err(error) => {
                    tracing::warn!(key, %error, "presence: skipping an unreadable stored subscription");
                    counts.dropped += 1;
                    dropped_ids.push(id);
                }
            }
        }
    }
    Ok((counts, dropped_ids))
}
