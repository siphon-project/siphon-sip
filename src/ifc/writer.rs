//! The iFC store's write-through to Redis, through the same coalescing queue
//! as the registrar's (`registrar::backend::coalesce`).

#[cfg(any(feature = "redis-backend", test))]
use crate::registrar::backend::coalesce::{self, DrainEvent, QueueKind, WriteSink};
use crate::registrar::backend::coalesce::{QueueHandle, QueuedWrite};
#[cfg(feature = "redis-backend")]
use crate::registrar::backend::redis_link::RedisLink;
#[cfg(feature = "redis-backend")]
use crate::registrar::backend::BackendError;
use crate::registrar::backend::WriteSequence;

/// One iFC write-through: the desired Redis state of one AoR's profile key.
#[derive(Debug)]
pub enum IfcWrite {
    /// Store the profile's raw XML.
    Save(String),
    /// Remove the profile.
    Remove,
}

impl QueuedWrite for IfcWrite {
    fn label(&self) -> &'static str {
        match self {
            Self::Save(_) => "save",
            Self::Remove => "remove",
        }
    }
}

/// Handle for the iFC store's write-through to Redis.
///
/// The writes go through the same coalescing queue as the registrar's: the
/// latest write per AoR is kept, a newer one replacing an older one still
/// waiting, so a registration burst or a Redis outage holds one entry per
/// profile and drops nothing (it used to be a FIFO of 4096 that dropped the
/// next write when full). A write Redis refuses is retried with backoff.
/// Methods never wait.
#[derive(Debug, Clone)]
pub struct IfcBackendWriter {
    queue: QueueHandle<String, IfcWrite>,
}

impl IfcBackendWriter {
    /// The order of a profile write about to be issued: take it while holding
    /// the lock that orders the profile (its `raw_xml` entry).
    pub fn sequence(&self) -> WriteSequence {
        self.queue.sequence()
    }

    /// Store the raw XML for an AoR, ordered as of now.
    pub fn save(&self, aor: &str, xml: &str) {
        self.save_at(aor, xml, self.sequence());
    }

    /// Store the raw XML for an AoR, a profile set at `sequence`. An older
    /// write never replaces a newer one.
    pub fn save_at(&self, aor: &str, xml: &str, sequence: WriteSequence) {
        self.queue.enqueue(
            aor.to_string(),
            aor,
            IfcWrite::Save(xml.to_string()),
            sequence,
        );
    }

    /// Remove an AoR's profile, ordered as of now.
    pub fn remove(&self, aor: &str) {
        self.remove_at(aor, self.sequence());
    }

    /// Remove an AoR's profile, a removal decided at `sequence`.
    pub fn remove_at(&self, aor: &str, sequence: WriteSequence) {
        self.queue
            .enqueue(aor.to_string(), aor, IfcWrite::Remove, sequence);
    }

    /// Profiles whose latest write has not been applied yet.
    #[cfg(test)]
    pub(crate) fn pending_writes(&self) -> usize {
        self.queue.pending_writes()
    }
}

/// Spawn the task that drains an iFC writer into `sink`. It runs until every
/// handle is dropped.
#[cfg(any(feature = "redis-backend", test))]
pub(crate) fn spawn_ifc_writer<S: WriteSink<String, IfcWrite> + 'static>(
    sink: S,
) -> IfcBackendWriter {
    let (queue, mut drainer) = coalesce::queue(QueueKind::Ifc);
    tokio::spawn(async move {
        loop {
            drainer.attempt(&sink).await;
            if let DrainEvent::Closed = drainer.next_event().await {
                break;
            }
        }
        drainer.finish(&sink).await;
    });
    IfcBackendWriter { queue }
}

/// TTL [`spawn_ifc_backend_writer_with_client`] gives a profile key: the default
/// `registrar.max_expires` (7200) plus the default `ttl_slack_secs` (30).
pub const DEFAULT_IFC_PROFILE_TTL_SECS: u64 = 7230;

/// Spawn the iFC backend writer task using a Redis connection, writing each
/// profile with [`DEFAULT_IFC_PROFILE_TTL_SECS`].
///
/// The writer cannot reconnect when that connection's link drops: profile
/// writes are then held (never dropped) until the process restarts.
#[cfg(feature = "redis-backend")]
#[deprecated(note = "use spawn_ifc_backend_writer_with_client: it reconnects after the link drops")]
pub fn spawn_ifc_backend_writer(
    connection: redis::aio::MultiplexedConnection,
    key_prefix: String,
) -> IfcBackendWriter {
    spawn_ifc_redis_writer(
        RedisLink::without_reconnect(connection),
        key_prefix,
        DEFAULT_IFC_PROFILE_TTL_SECS,
    )
}

/// Spawn the iFC backend writer task using a Redis connection, writing each
/// profile with a TTL of `ttl_secs` (see
/// [`spawn_ifc_backend_writer_with_client_and_ttl`]).
///
/// The writer cannot reconnect when that connection's link drops: profile
/// writes are then held (never dropped) until the process restarts.
#[cfg(feature = "redis-backend")]
#[deprecated(note = "use spawn_ifc_backend_writer_with_client: it reconnects after the link drops")]
pub fn spawn_ifc_backend_writer_with_ttl(
    connection: redis::aio::MultiplexedConnection,
    key_prefix: String,
    ttl_secs: u64,
) -> IfcBackendWriter {
    spawn_ifc_redis_writer(
        RedisLink::without_reconnect(connection),
        key_prefix,
        ttl_secs,
    )
}

/// Spawn the iFC backend writer task on a Redis client and a connection
/// already open on it, writing each profile with
/// [`DEFAULT_IFC_PROFILE_TTL_SECS`].
#[cfg(feature = "redis-backend")]
pub fn spawn_ifc_backend_writer_with_client(
    client: redis::Client,
    connection: redis::aio::MultiplexedConnection,
    key_prefix: String,
) -> IfcBackendWriter {
    spawn_ifc_backend_writer_with_client_and_ttl(
        client,
        connection,
        key_prefix,
        DEFAULT_IFC_PROFILE_TTL_SECS,
    )
}

/// Spawn the iFC backend writer task on a Redis client and a connection
/// already open on it.
///
/// Every profile is written with a TTL of `ttl_secs`, renewed by each store,
/// so a profile nobody stores again (its user stopped registering) leaves
/// Redis by itself instead of staying for good. Pass the longest registration
/// lifetime plus a grace: a script that stores the profile from the SAR of
/// every REGISTER keeps it alive for as long as the registration.
///
/// The writer starts on `connection` and opens a new one on `client` when that
/// one's link drops (a Redis restart, a network blip): a connection never
/// recovers by itself, and the held writes would otherwise never be applied.
///
/// Returns an [`IfcBackendWriter`] handle. The task runs until every handle
/// is dropped (i.e., until the `IfcStore` is dropped).
#[cfg(feature = "redis-backend")]
pub fn spawn_ifc_backend_writer_with_client_and_ttl(
    client: redis::Client,
    connection: redis::aio::MultiplexedConnection,
    key_prefix: String,
    ttl_secs: u64,
) -> IfcBackendWriter {
    spawn_ifc_redis_writer(
        RedisLink::with_connection(client, connection),
        key_prefix,
        ttl_secs,
    )
}

#[cfg(feature = "redis-backend")]
fn spawn_ifc_redis_writer(link: RedisLink, key_prefix: String, ttl_secs: u64) -> IfcBackendWriter {
    spawn_ifc_writer(IfcRedisSink {
        link,
        key_prefix,
        ttl_secs: ttl_secs.max(1),
    })
}

/// Applies iFC writes to Redis: `SET .. EX` for a profile, `DEL` for a
/// removal, a batch at a time pipelined on the multiplexed connection.
#[cfg(feature = "redis-backend")]
struct IfcRedisSink {
    link: RedisLink,
    key_prefix: String,
    ttl_secs: u64,
}

#[cfg(feature = "redis-backend")]
impl WriteSink<String, IfcWrite> for IfcRedisSink {
    async fn apply_batch(&self, writes: &[(&String, &IfcWrite)]) -> Vec<Result<(), BackendError>> {
        use redis::AsyncCommands;
        futures_util::future::join_all(writes.iter().map(|(aor, write)| {
            let key = format!("{}{aor}", self.key_prefix);
            async move {
                let mut lease = self.link.lease().await?;
                let connection = &mut lease.connection;
                let result: Result<(), redis::RedisError> = match write {
                    IfcWrite::Save(xml) => {
                        connection.set_ex(&key, xml.as_str(), self.ttl_secs).await
                    }
                    IfcWrite::Remove => connection.del(&key).await,
                };
                result.map_err(|error| self.link.fail(&lease, error))
            }
        }))
        .await
    }
}
