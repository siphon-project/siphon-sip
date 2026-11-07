//! Bounded asynchronous discovery and one retry per operation.
use super::RedisTarget;
use redis::{
    aio::{ConnectionLike, MultiplexedConnection},
    RedisError, RedisResult, Value,
};
use std::{sync::Arc, time::Duration};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const RESPONSE_TIMEOUT: Duration = Duration::from_millis(500);
const BACKOFF: Duration = Duration::from_millis(100);

#[derive(Clone)]
enum Source {
    Target(RedisTarget),
    Client(redis::Client),
    Fixed,
    #[cfg(test)]
    Test {
        next: Arc<tokio::sync::Mutex<Option<MultiplexedConnection>>>,
        attempts: Arc<std::sync::atomic::AtomicUsize>,
    },
}
struct State {
    connection: MultiplexedConnection,
    generation: u64,
    last_attempt: Option<tokio::time::Instant>,
}

/// Clones share the current connection and serialize only reconnect attempts.
/// A failed command is retried once, including pipelines. A dropped response
/// is ambiguous: callers of non-idempotent commands must allow for replay.
#[derive(Clone)]
pub struct RedisConnection {
    source: Arc<Source>,
    state: Arc<tokio::sync::Mutex<State>>,
    db: i64,
}
impl std::fmt::Debug for RedisConnection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RedisConnection")
            .field("db", &self.db)
            .finish_non_exhaustive()
    }
}
impl RedisConnection {
    pub async fn connect(target: RedisTarget) -> RedisResult<Self> {
        let source = Source::Target(target);
        let connection = open(&source).await?;
        Ok(Self::new(source, connection))
    }
    pub(crate) fn with_client(client: redis::Client, connection: MultiplexedConnection) -> Self {
        Self::new(Source::Client(client), connection)
    }
    fn new(source: Source, connection: MultiplexedConnection) -> Self {
        Self {
            db: connection.get_db(),
            source: Arc::new(source),
            state: Arc::new(tokio::sync::Mutex::new(State {
                connection,
                generation: 0,
                last_attempt: None,
            })),
        }
    }
    async fn snapshot(&self) -> (u64, MultiplexedConnection) {
        let state = self.state.lock().await;
        (state.generation, state.connection.clone())
    }
    async fn recover(
        &self,
        generation: u64,
        error: RedisError,
    ) -> RedisResult<MultiplexedConnection> {
        if !recoverable(&error) || matches!(*self.source, Source::Fixed) {
            return Err(error);
        }
        let mut state = self.state.lock().await;
        if state.generation != generation {
            return Ok(state.connection.clone());
        }
        tracing::warn!(%error, target = ?self.target(), "Redis command failed; rediscovering primary before one retry");
        let delay = state
            .last_attempt
            .map(|last| BACKOFF.saturating_sub(last.elapsed()))
            .unwrap_or(BACKOFF);
        tokio::time::sleep(delay).await;
        state.last_attempt = Some(tokio::time::Instant::now());
        let connection = open(&self.source).await?;
        state.connection = connection.clone();
        state.generation += 1;
        Ok(connection)
    }
    fn target(&self) -> Option<&RedisTarget> {
        match self.source.as_ref() {
            Source::Target(target) => Some(target),
            _ => None,
        }
    }
    fn report<T>(&self, result: RedisResult<T>) -> RedisResult<T> {
        if let Err(error) = &result {
            tracing::error!(%error, target = ?self.target(), "Redis retry failed; returning error to caller");
        }
        result
    }
}
impl From<MultiplexedConnection> for RedisConnection {
    fn from(connection: MultiplexedConnection) -> Self {
        Self::new(Source::Fixed, connection)
    }
}
fn recoverable(error: &RedisError) -> bool {
    error.is_io_error()
        || error.is_connection_refusal()
        || error.is_connection_dropped()
        || error.is_unrecoverable_error()
        || matches!(error.code(), Some("READONLY" | "MASTERDOWN"))
        || error.clone().into_server_errors().is_some_and(|errors| {
            errors
                .iter()
                .any(|(_, error)| matches!(error.code(), "READONLY" | "MASTERDOWN"))
        })
}
async fn open(source: &Source) -> RedisResult<MultiplexedConnection> {
    let attempt = async {
        let client = match source {
            #[cfg(test)]
            Source::Test { next, attempts } => {
                attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                return next.lock().await.take().ok_or_else(|| {
                    std::io::Error::from(std::io::ErrorKind::ConnectionRefused).into()
                });
            }
            Source::Client(client) => client.clone(),
            Source::Fixed => {
                return Err(RedisError::from((
                    redis::ErrorKind::InvalidClientConfig,
                    "connection has no discovery target",
                )))
            }
            Source::Target(RedisTarget::Url(url)) => redis::Client::open(url.as_str())?,
            Source::Target(RedisTarget::Sentinel(config)) => {
                use redis::{
                    sentinel::{Sentinel, SentinelNodeConnectionInfo},
                    IntoConnectionInfo, RedisConnectionInfo,
                };
                let addresses = config
                    .addresses
                    .iter()
                    .map(|address| {
                        let info = format!("redis://{address}").into_connection_info()?;
                        let settings = match &config.sentinel_password {
                            Some(password) => RedisConnectionInfo::default().set_password(password),
                            None => RedisConnectionInfo::default(),
                        };
                        Ok(info.set_redis_settings(settings))
                    })
                    .collect::<RedisResult<Vec<_>>>()?;
                let mut settings = RedisConnectionInfo::default().set_db(i64::from(config.db));
                if let Some(password) = &config.password {
                    settings = settings.set_password(password);
                }
                let node =
                    SentinelNodeConnectionInfo::default().set_redis_connection_info(settings);
                let mut last_error = RedisError::from((
                    redis::ErrorKind::MasterNameNotFoundBySentinel,
                    "no Sentinel provided a reachable primary",
                ));
                let mut discovered = None;
                for address in addresses {
                    let mut sentinel = Sentinel::build(vec![address])?;
                    match tokio::time::timeout(
                        RESPONSE_TIMEOUT,
                        sentinel.async_master_for(&config.master, Some(&node)),
                    )
                    .await
                    {
                        Ok(Ok(client)) => {
                            discovered = Some(client);
                            break;
                        }
                        Ok(Err(error)) => last_error = error,
                        Err(_) => {
                            last_error = std::io::Error::new(
                                std::io::ErrorKind::TimedOut,
                                "Sentinel discovery timed out",
                            )
                            .into()
                        }
                    }
                }
                discovered.ok_or(last_error)?
            }
        };
        client
            .get_multiplexed_async_connection_with_config(
                &redis::AsyncConnectionConfig::new()
                    .set_connection_timeout(Some(CONNECT_TIMEOUT))
                    .set_response_timeout(Some(RESPONSE_TIMEOUT)),
            )
            .await
    };
    let result = tokio::time::timeout(CONNECT_TIMEOUT, attempt)
        .await
        .unwrap_or_else(|_| {
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Redis primary discovery/connect timed out",
            )
            .into())
        });
    if let Err(error) = &result {
        let target = match source {
            Source::Target(target) => Some(target),
            _ => None,
        };
        tracing::error!(%error, ?target, "cannot reach Redis primary within connection deadline");
    }
    result
}
// Bound queueing behind another reconnect as well as network I/O.
async fn bounded<T>(
    operation: impl std::future::Future<Output = RedisResult<T>>,
) -> RedisResult<T> {
    tokio::time::timeout(Duration::from_secs(5), operation)
        .await
        .unwrap_or_else(|_| {
            tracing::error!(
                "Redis operation exceeded five-second deadline including reconnect queue"
            );
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Redis operation deadline exceeded",
            )
            .into())
        })
}

impl ConnectionLike for RedisConnection {
    fn req_packed_command<'a>(
        &'a mut self,
        command: &'a redis::Cmd,
    ) -> redis::RedisFuture<'a, Value> {
        Box::pin(bounded(async move {
            let (generation, mut connection) = self.snapshot().await;
            match connection
                .req_packed_command(command)
                .await
                .and_then(Value::extract_error)
            {
                Ok(value) => Ok(value),
                Err(error) => {
                    let mut connection = self.recover(generation, error).await?;
                    self.report(
                        connection
                            .req_packed_command(command)
                            .await
                            .and_then(Value::extract_error),
                    )
                }
            }
        }))
    }
    fn req_packed_commands<'a>(
        &'a mut self,
        pipeline: &'a redis::Pipeline,
        offset: usize,
        count: usize,
    ) -> redis::RedisFuture<'a, Vec<Value>> {
        Box::pin(bounded(async move {
            let (generation, mut connection) = self.snapshot().await;
            match connection
                .req_packed_commands(pipeline, offset, count)
                .await
                .and_then(|values| values.into_iter().map(Value::extract_error).collect())
            {
                Ok(values) => Ok(values),
                Err(error) => {
                    let mut connection = self.recover(generation, error).await?;
                    self.report(
                        connection
                            .req_packed_commands(pipeline, offset, count)
                            .await
                            .and_then(|values| {
                                values.into_iter().map(Value::extract_error).collect()
                            }),
                    )
                }
            }
        }))
    }
    fn get_db(&self) -> i64 {
        self.db
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_connection_and_primary_errors_recover() {
        for code in ["READONLY", "MASTERDOWN"] {
            let error = redis::parse_redis_value(format!("-{code} unavailable\r\n").as_bytes())
                .unwrap()
                .extract_error()
                .unwrap_err();
            assert!(recoverable(&error));
        }
        assert!(recoverable(
            &std::io::Error::from(std::io::ErrorKind::ConnectionReset).into()
        ));
        assert!(!recoverable(&RedisError::from((
            redis::ErrorKind::InvalidClientConfig,
            "bad type"
        ))));
    }
    #[test]
    fn transport_error_kinds_are_recoverable() {
        for kind in [
            std::io::ErrorKind::BrokenPipe,
            std::io::ErrorKind::ConnectionReset,
            std::io::ErrorKind::UnexpectedEof,
            std::io::ErrorKind::ConnectionAborted,
            std::io::ErrorKind::ConnectionRefused,
            std::io::ErrorKind::NotConnected,
            std::io::ErrorKind::TimedOut,
        ] {
            let error = RedisError::from(std::io::Error::from(kind));
            assert!(recoverable(&error), "{kind:?}: {error}");
        }
        assert!(recoverable(&RedisError::from((
            redis::ErrorKind::Io,
            "broken pipe"
        ))));
    }

    #[tokio::test]
    async fn already_dropped_connection_reconnects_once_for_commands_and_pipelines() {
        use redis::AsyncCommands;
        for pipeline in [false, true] {
            let (old, old_driver, old_server) = mock_connection("+OK\r\n").await;
            old_driver.abort();
            assert!(old_driver.await.unwrap_err().is_cancelled());
            let (new, new_driver, new_server) = mock_connection("+OK\r\n").await;
            let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let mut connection = RedisConnection::new(
                Source::Test {
                    next: Arc::new(tokio::sync::Mutex::new(Some(new))),
                    attempts: attempts.clone(),
                },
                old,
            );
            if pipeline {
                redis::pipe()
                    .set("key", "value")
                    .ignore()
                    .query_async::<()>(&mut connection)
                    .await
                    .unwrap();
            } else {
                connection.set::<_, _, ()>("key", "value").await.unwrap();
            }
            assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 1);
            drop(connection);
            for task in [old_server, new_driver, new_server] {
                tokio::time::timeout(Duration::from_secs(1), task)
                    .await
                    .unwrap()
                    .unwrap();
            }
        }
    }

    // Real redis protocol over in-memory Tokio streams: deterministic failure
    // tests require neither ports nor external processes.
    async fn mock_connection(
        reply: &'static str,
    ) -> (
        MultiplexedConnection,
        tokio::task::JoinHandle<()>,
        tokio::task::JoinHandle<()>,
    ) {
        use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
        let (client, server) = tokio::io::duplex(4096);
        let server = tokio::spawn(async move {
            let mut stream = BufReader::new(server);
            loop {
                let mut line = String::new();
                if stream.read_line(&mut line).await.unwrap() == 0 {
                    break;
                }
                let count: usize = line.trim().strip_prefix('*').unwrap().parse().unwrap();
                let mut arguments = Vec::new();
                for _ in 0..count {
                    line.clear();
                    stream.read_line(&mut line).await.unwrap();
                    let length: usize = line.trim().strip_prefix('$').unwrap().parse().unwrap();
                    let mut value = vec![0; length + 2];
                    stream.read_exact(&mut value).await.unwrap();
                    arguments.push(String::from_utf8(value[..length].to_vec()).unwrap());
                }
                let response = if arguments[0] == "SET" {
                    reply
                } else {
                    "+OK\r\n"
                };
                if response.is_empty() || stream.write_all(response.as_bytes()).await.is_err() {
                    break;
                }
            }
        });
        let (connection, driver) = MultiplexedConnection::new_with_config(
            &redis::RedisConnectionInfo::default(),
            client,
            redis::AsyncConnectionConfig::default(),
        )
        .await
        .unwrap();
        (connection, tokio::spawn(driver), server)
    }

    #[tokio::test]
    async fn readonly_retries_once_and_clones_share_recovery_then_release_state() {
        use redis::AsyncCommands;
        let (old, old_driver, old_server) = mock_connection("-READONLY replica\r\n").await;
        let (new, new_driver, new_server) = mock_connection("+OK\r\n").await;
        let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut connection = RedisConnection::new(
            Source::Test {
                next: Arc::new(tokio::sync::Mutex::new(Some(new))),
                attempts: attempts.clone(),
            },
            old,
        );
        let weak = Arc::downgrade(&connection.state);
        let mut other = connection.clone();
        let (first, second) = tokio::join!(
            connection.set::<_, _, ()>("one", "value"),
            other.set::<_, _, ()>("two", "value")
        );
        first.unwrap();
        second.unwrap();
        assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 1);
        drop(connection);
        drop(other);
        assert!(weak.upgrade().is_none());
        for task in [old_driver, old_server, new_driver, new_server] {
            tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .unwrap()
                .unwrap();
        }
    }

    #[tokio::test]
    async fn retry_failure_is_returned_without_a_second_reconnect() {
        use redis::AsyncCommands;
        let (old, old_driver, old_server) = mock_connection("-MASTERDOWN unavailable\r\n").await;
        let (new, new_driver, new_server) = mock_connection("-READONLY replica\r\n").await;
        let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut connection = RedisConnection::new(
            Source::Test {
                next: Arc::new(tokio::sync::Mutex::new(Some(new))),
                attempts: attempts.clone(),
            },
            old,
        );
        assert_eq!(
            connection
                .set::<_, _, ()>("key", "value")
                .await
                .unwrap_err()
                .code(),
            Some("READONLY")
        );
        assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 1);
        drop(connection);
        for task in [old_driver, old_server, new_driver, new_server] {
            tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .unwrap()
                .unwrap();
        }
    }

    #[tokio::test]
    async fn ordinary_server_errors_do_not_reconnect() {
        use redis::AsyncCommands;
        let (old, driver, server) = mock_connection("-WRONGTYPE invalid\r\n").await;
        let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut connection = RedisConnection::new(
            Source::Test {
                next: Arc::new(tokio::sync::Mutex::new(None)),
                attempts: attempts.clone(),
            },
            old,
        );
        assert_eq!(
            connection
                .set::<_, _, ()>("key", "value")
                .await
                .unwrap_err()
                .code(),
            Some("WRONGTYPE")
        );
        assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 0);
        drop(connection);
        for task in [driver, server] {
            tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .unwrap()
                .unwrap();
        }
    }
    #[tokio::test]
    async fn dropped_connection_recovers_and_unreachable_primary_returns_error() {
        use redis::AsyncCommands;
        for reachable in [true, false] {
            let (old, old_driver, old_server) = mock_connection("").await;
            let (new, new_driver, new_server) = mock_connection("+OK\r\n").await;
            let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let next = if reachable {
                Some(new)
            } else {
                drop(new);
                None
            };
            let mut connection = RedisConnection::new(
                Source::Test {
                    next: Arc::new(tokio::sync::Mutex::new(next)),
                    attempts: attempts.clone(),
                },
                old,
            );
            let result = connection.set::<_, _, ()>("key", "value").await;
            assert_eq!(result.is_ok(), reachable);
            assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 1);
            drop(connection);
            for task in [old_driver, old_server, new_driver, new_server] {
                tokio::time::timeout(Duration::from_secs(1), task)
                    .await
                    .unwrap()
                    .unwrap();
            }
        }
    }
}
