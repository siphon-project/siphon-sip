//! Compatibility facade for persistence sinks over the shared Redis connection.
use super::BackendError;
use crate::redis_target::{RedisConnection, RedisTarget};

pub(crate) struct RedisLease {
    pub(crate) connection: RedisConnection,
}
#[derive(Debug)]
pub(crate) struct RedisLink {
    connection: RedisConnection,
}
impl RedisLink {
    pub(crate) async fn connect_target(target: RedisTarget) -> Result<Self, BackendError> {
        RedisConnection::connect(target)
            .await
            .map(|connection| Self { connection })
            .map_err(|error| BackendError::Connection(error.to_string()))
    }
    pub(crate) fn with_connection(
        client: redis::Client,
        connection: redis::aio::MultiplexedConnection,
    ) -> Self {
        Self {
            connection: RedisConnection::with_client(client, connection),
        }
    }
    pub(crate) fn without_reconnect(connection: redis::aio::MultiplexedConnection) -> Self {
        Self {
            connection: connection.into(),
        }
    }
    pub(crate) fn from_connection(connection: RedisConnection) -> Self {
        Self { connection }
    }
    pub(crate) async fn lease(&self) -> Result<RedisLease, BackendError> {
        Ok(RedisLease {
            connection: self.connection.clone(),
        })
    }
    pub(crate) fn fail(&self, _lease: &RedisLease, error: redis::RedisError) -> BackendError {
        BackendError::Query(error.to_string())
    }
}
