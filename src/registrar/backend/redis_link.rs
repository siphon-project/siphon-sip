//! A Redis connection that replaces itself after the link drops.
//!
//! A `MultiplexedConnection` never recovers once its socket is gone: after a
//! Redis restart or a network blip every command on it fails (`broken pipe`)
//! for the life of the process, while a fresh connection works. The writers
//! hold writes they cannot apply and retry them, so without a new connection
//! those writes would wait for ever. A [`RedisLink`] drops a connection that
//! failed that way and opens a new one on the next use.
//!
//! Nothing here retries by itself: the caller's next operation reconnects, so
//! reconnects follow the writer's backoff (or the reader's own pace), and at
//! most one attempt per [`RECONNECT_INTERVAL`] is made however many operations
//! of a batch arrive at once. The connection lock is held for a clone or a
//! swap only, never across an await.

use std::sync::{PoisonError, RwLock};
use std::time::{Duration, Instant};

use redis::aio::MultiplexedConnection;

use super::BackendError;

/// How long a single Redis command may take before it fails.
///
/// The same 500ms the `redis` crate happens to default to, pinned here so
/// it is siphon's choice rather than a dependency's. It is the only reason
/// an individual operation is bounded at all, and a bump that changed or
/// dropped that default would otherwise remove the bound silently, leaving
/// a writer to back up behind commands that never return.
pub(crate) const REDIS_RESPONSE_TIMEOUT: Duration = Duration::from_millis(500);

/// How long opening a new connection may take, so an unreachable server
/// costs one bounded attempt rather than the operating system's connect
/// timeout.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// The least time between two reconnect attempts: the operations of one batch
/// share an attempt instead of each making its own.
const RECONNECT_INTERVAL: Duration = Duration::from_millis(100);

/// A connection lent for one operation, with the generation it came from, so
/// a failure on an old connection never discards a newer one.
pub(crate) struct RedisLease {
    pub(crate) connection: MultiplexedConnection,
    generation: u64,
}

/// A Redis client and its current connection, reopened after the link drops.
pub(crate) struct RedisLink {
    /// What a new connection is opened on; `None` for a link that keeps the
    /// connection it was given (the deprecated iFC constructors).
    client: Option<redis::Client>,
    /// The connection and its generation; `None` once it failed.
    current: RwLock<(u64, Option<MultiplexedConnection>)>,
    /// When the last reconnect attempt failed. Held across the attempt, so
    /// concurrent operations wait for it instead of each opening a socket.
    reconnect: tokio::sync::Mutex<Option<Instant>>,
}

impl std::fmt::Debug for RedisLink {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RedisLink")
            .field("connected", &self.read().1.is_some())
            .finish_non_exhaustive()
    }
}

impl RedisLink {
    /// Open the first connection; fails if Redis cannot be reached now.
    pub(crate) async fn connect(client: redis::Client) -> Result<Self, BackendError> {
        let connection = open(&client).await?;
        Ok(Self::with_connection(client, connection))
    }

    /// A link that starts from a connection already open on `client`.
    pub(crate) fn with_connection(
        client: redis::Client,
        connection: MultiplexedConnection,
    ) -> Self {
        Self {
            client: Some(client),
            current: RwLock::new((0, Some(connection))),
            reconnect: tokio::sync::Mutex::new(None),
        }
    }

    /// A link that never reconnects: it keeps `connection` whatever happens
    /// to it, as before reconnecting existed. Only for callers that hand over
    /// a connection without the client it came from.
    pub(crate) fn without_reconnect(connection: MultiplexedConnection) -> Self {
        Self {
            client: None,
            current: RwLock::new((0, Some(connection))),
            reconnect: tokio::sync::Mutex::new(None),
        }
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, (u64, Option<MultiplexedConnection>)> {
        self.current.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn leased(&self) -> Option<RedisLease> {
        let current = self.read();
        current.1.clone().map(|connection| RedisLease {
            connection,
            generation: current.0,
        })
    }

    /// The connection to run one operation on, reopened first if the last one
    /// failed. Fails without a new attempt when one failed moments ago.
    pub(crate) async fn lease(&self) -> Result<RedisLease, BackendError> {
        if let Some(lease) = self.leased() {
            return Ok(lease);
        }
        let mut last_failure = self.reconnect.lock().await;
        // Another operation may have reconnected while this one waited.
        if let Some(lease) = self.leased() {
            return Ok(lease);
        }
        if let Some(failed_at) = *last_failure {
            if failed_at.elapsed() < RECONNECT_INTERVAL {
                return Err(BackendError::Connection(
                    "Redis is unreachable (reconnect failed moments ago)".to_string(),
                ));
            }
        }
        let Some(client) = &self.client else {
            return Err(BackendError::Connection(
                "Redis connection lost and this link cannot reconnect".to_string(),
            ));
        };
        match open(client).await {
            Ok(connection) => {
                let generation = {
                    let mut current = self.current.write().unwrap_or_else(PoisonError::into_inner);
                    current.0 += 1;
                    current.1 = Some(connection.clone());
                    current.0
                };
                *last_failure = None;
                tracing::info!("reconnected to Redis");
                Ok(RedisLease {
                    connection,
                    generation,
                })
            }
            Err(error) => {
                *last_failure = Some(Instant::now());
                Err(error)
            }
        }
    }

    /// Turn an operation's error into a [`BackendError`], dropping the
    /// connection it ran on when the error says the link is gone, so the next
    /// operation reconnects.
    pub(crate) fn fail(&self, lease: &RedisLease, error: redis::RedisError) -> BackendError {
        let link_gone =
            error.is_connection_dropped() || error.is_io_error() || error.is_unrecoverable_error();
        if link_gone && self.client.is_some() {
            let mut current = self.current.write().unwrap_or_else(PoisonError::into_inner);
            if current.0 == lease.generation && current.1.take().is_some() {
                tracing::warn!(%error, "Redis connection lost; reconnecting on the next operation");
            }
        }
        BackendError::Query(error.to_string())
    }
}

async fn open(client: &redis::Client) -> Result<MultiplexedConnection, BackendError> {
    let config = redis::AsyncConnectionConfig::new()
        .set_connection_timeout(Some(CONNECT_TIMEOUT))
        .set_response_timeout(Some(REDIS_RESPONSE_TIMEOUT));
    client
        .get_multiplexed_async_connection_with_config(&config)
        .await
        .map_err(|error| BackendError::Connection(error.to_string()))
}
