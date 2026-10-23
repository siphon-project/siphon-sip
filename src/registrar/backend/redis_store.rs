//! Redis registrar backend.
//!
//! Split out of `backend.rs` so the key layout, the TTLs and the AoR index
//! live in one file next to the commands that maintain them.
//!
//! Keys, all under `key_prefix`:
//!
//! - `{prefix}{aor}`: hash of contact URI to JSON binding. TTL: the longest
//!   contact's remaining lifetime plus `ttl_slack_secs`, set on every save.
//! - `{prefix}state:{aor}`: the AoR's auxiliary state (Service-Route,
//!   P-Asserted-Identity, P-Associated-URI). TTL: the binding hash's, copied
//!   when the state is written and refreshed on every save of the binding.
//!   Written while the AoR has no binding hash, it lives
//!   `max_binding_lifetime_secs + ttl_slack_secs` instead.
//! - `{prefix}index`: sorted set of AoRs scored by the epoch second their
//!   last contact expires. Every save and remove updates it in the same
//!   transaction as the hash, and members whose score has passed are dropped
//!   before it is read, so it needs no expiry events (which Redis drops under
//!   load) and holds across replicas and restarts. `count_aors` and
//!   `all_aors` read it; nothing walks the keyspace at runtime.
//!
//! An AoR can never be named `index` here: a SIP or tel URI always carries a
//! scheme and its colon.

use super::*;
use redis::AsyncCommands;

/// Redis registrar backend.
///
/// Stores contacts as JSON in Redis hashes, with TTL aligned to contact expiry.
/// Supports optional auto-sharding across multiple Redis instances.
#[derive(Debug)]
pub struct RedisBackend {
    config: RedisBackendConfig,
    /// Connections — single element when not sharding, multiple when sharding.
    connections: Vec<redis::aio::MultiplexedConnection>,
    /// The longest binding the registrar grants. Bounds a state key written
    /// while its AoR has no binding hash (a script may set Service-Route
    /// ahead of the save): it lives this long plus `ttl_slack_secs`, and
    /// takes the binding's TTL at the next save.
    max_binding_lifetime_secs: u64,
}

/// How long a single Redis command may take before it fails.
///
/// The same 500ms the `redis` crate happens to default to, pinned here so
/// it is siphon's choice rather than a dependency's. It is the only reason
/// an individual operation is bounded at all, and a bump that changed or
/// dropped that default would otherwise remove the bound silently, leaving
/// the write-through queue to back up behind commands that never return.
const REDIS_RESPONSE_TIMEOUT: Duration = Duration::from_millis(500);

impl RedisBackend {
    /// Connect to Redis (single instance or sharded).
    ///
    /// A shard with no AoR index yet (a keyspace written by a version without
    /// one, or one where every binding has expired) gets it built from the
    /// binding hashes before this returns, so the boot-time restore and the
    /// first count see every AoR. That one walk is a cursor `SCAN`.
    pub async fn connect(config: RedisBackendConfig) -> Result<Self, BackendError> {
        let connections = if config.shard_count > 0 {
            if config.urls.len() != config.shard_count {
                return Err(BackendError::Connection(format!(
                    "shard_count is {} but {} URLs provided",
                    config.shard_count,
                    config.urls.len()
                )));
            }
            let mut connections = Vec::with_capacity(config.shard_count);
            for url in &config.urls {
                let client = redis::Client::open(url.as_str())
                    .map_err(|error| BackendError::Connection(error.to_string()))?;
                let mut connection = client
                    .get_multiplexed_async_connection()
                    .await
                    .map_err(|error| BackendError::Connection(error.to_string()))?;
                connection.set_response_timeout(REDIS_RESPONSE_TIMEOUT);
                connections.push(connection);
            }
            tracing::info!(
                shard_count = config.shard_count,
                "redis registrar backend connected (sharded)"
            );
            connections
        } else {
            let client = redis::Client::open(config.url.as_str())
                .map_err(|error| BackendError::Connection(error.to_string()))?;
            let mut connection = client
                .get_multiplexed_async_connection()
                .await
                .map_err(|error| BackendError::Connection(error.to_string()))?;
            connection.set_response_timeout(REDIS_RESPONSE_TIMEOUT);
            tracing::info!("redis registrar backend connected");
            vec![connection]
        };

        let backend = Self {
            config,
            connections,
            max_binding_lifetime_secs: DEFAULT_MAX_BINDING_LIFETIME_SECS,
        };
        for connection in backend.all_connections() {
            backend.build_index_if_absent(connection).await?;
        }
        Ok(backend)
    }

    /// Set the longest binding the registrar grants (`registrar.max_expires`),
    /// which bounds a state key written ahead of its AoR's binding.
    pub fn with_max_binding_lifetime(mut self, secs: u64) -> Self {
        self.max_binding_lifetime_secs = secs;
        self
    }

    /// The Redis key for an AoR (contact bindings).
    fn key(&self, aor: &str) -> String {
        format!("{}{}", self.config.key_prefix, aor)
    }

    /// The Redis key for an AoR's auxiliary state.
    fn state_key(&self, aor: &str) -> String {
        format!("{}state:{}", self.config.key_prefix, aor)
    }

    /// The sorted set of AoRs by expiry, one per shard.
    fn index_key(&self) -> String {
        format!("{}index", self.config.key_prefix)
    }

    /// Get a cloned connection for the given AoR (shard-aware).
    fn connection_for(&self, aor: &str) -> redis::aio::MultiplexedConnection {
        if self.connections.len() == 1 {
            self.connections[0].clone()
        } else {
            let index = shard_index(aor, self.connections.len());
            self.connections[index].clone()
        }
    }

    /// Get all connections (for operations that span all shards).
    fn all_connections(&self) -> Vec<redis::aio::MultiplexedConnection> {
        self.connections.to_vec()
    }

    /// Build a shard's AoR index from its binding hashes when it has none.
    ///
    /// Runs once per shard at connect. Concurrent replicas booting together
    /// both build it, harmlessly: `ZADD` of the same member and score is
    /// idempotent, and each one's later saves keep it current.
    async fn build_index_if_absent(
        &self,
        mut connection: redis::aio::MultiplexedConnection,
    ) -> Result<(), BackendError> {
        let index_key = self.index_key();
        let present: bool = connection
            .exists(&index_key)
            .await
            .map_err(|error| BackendError::Query(error.to_string()))?;
        if present {
            return Ok(());
        }
        let pattern = format!("{}*", self.config.key_prefix);
        let state_prefix = format!("{}state:", self.config.key_prefix);
        let prefix_len = self.config.key_prefix.len();
        let now = epoch_now();
        let mut indexed = 0usize;
        let mut cursor: u64 = 0;
        loop {
            let (next_cursor, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(&pattern)
                .arg("COUNT")
                .arg(SCAN_COUNT)
                .query_async(&mut connection)
                .await
                .map_err(|error| BackendError::Query(error.to_string()))?;
            for key in keys {
                if key.starts_with(&state_prefix) || key == index_key || key.len() <= prefix_len {
                    continue;
                }
                let aor = &key[prefix_len..];
                // A key under the prefix that is not a binding hash (a
                // deployment sharing the prefix with something else) is not
                // an AoR; skip it rather than fail the boot.
                let entries: Vec<(String, String)> = match connection.hgetall(&key).await {
                    Ok(entries) => entries,
                    Err(_) => continue,
                };
                let expiry = entries
                    .iter()
                    .filter_map(|(_, value)| serde_json::from_str::<StoredContact>(value).ok())
                    .map(|contact| contact_expiry(&contact, now))
                    .max()
                    .unwrap_or(0);
                if expiry > now {
                    let _: () = connection
                        .zadd(&index_key, aor, expiry)
                        .await
                        .map_err(|error| BackendError::Query(error.to_string()))?;
                    indexed += 1;
                }
            }
            cursor = next_cursor;
            if cursor == 0 {
                break;
            }
        }
        if indexed > 0 {
            tracing::info!(
                aors = indexed,
                "built the registrar AoR index from the binding hashes already in Redis"
            );
        }
        Ok(())
    }

    /// Drop the index members whose last binding has expired, then read what
    /// is left with `read` — in one transaction per shard, so a count never
    /// includes an AoR that expired before it was taken.
    async fn read_index<T: redis::FromRedisValue>(
        &self,
        connection: &mut redis::aio::MultiplexedConnection,
        read: redis::Cmd,
    ) -> Result<(usize, T), BackendError> {
        let mut pipe = redis::pipe();
        pipe.atomic()
            .cmd("ZREMRANGEBYSCORE")
            .arg(self.index_key())
            .arg("-inf")
            .arg(epoch_now())
            .add_command(read);
        pipe.query_async(connection)
            .await
            .map_err(|error| BackendError::Query(error.to_string()))
    }
}

/// `SCAN` batch size for the walks that remain (boot-time only).
const SCAN_COUNT: usize = 1000;

/// Write an AoR's state with the TTL its binding hash has now, or with the
/// no-binding lifetime when there is no hash to follow (or it has no TTL).
///
/// One script so the read of the hash's TTL and the write cannot straddle a
/// save of the binding from another replica.
const SAVE_STATE_SCRIPT: &str = r#"
local ttl = redis.call('PTTL', KEYS[1])
if ttl > 0 then
  return redis.call('SET', KEYS[2], ARGV[1], 'PX', ttl)
end
return redis.call('SET', KEYS[2], ARGV[1], 'EX', ARGV[2])
"#;

fn epoch_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// The epoch second a stored contact expires, for one without `expires_at`
/// (written before it existed) counted from `now`.
fn contact_expiry(contact: &StoredContact, now: u64) -> u64 {
    contact
        .expires_at
        .unwrap_or_else(|| now.saturating_add(contact.expires_secs))
}

impl RegistrarBackend for RedisBackend {
    async fn save(&self, aor: &str, contacts: &[StoredContact]) -> Result<(), BackendError> {
        let now = epoch_now();
        let expiry = contacts
            .iter()
            .map(|contact| contact_expiry(contact, now))
            .max()
            .unwrap_or(0);
        // Nothing left that is still live: a save of only expired bindings is
        // a removal. Written as a hash it would have had no TTL to give it.
        if expiry <= now {
            return self.remove(aor).await;
        }

        let key = self.key(aor);
        let ttl_with_slack = (expiry - now).saturating_add(self.config.ttl_slack_secs);
        let mut connection = self.connection_for(aor);

        // Replace the hash, give it and the AoR's state key the binding's
        // TTL, and move the AoR in the index, as one transaction: a reader
        // never sees the hash without its TTL or the index out of step.
        let mut pipe = redis::pipe();
        pipe.atomic().del(&key).ignore();
        let mut hset = redis::cmd("HSET");
        hset.arg(&key);
        for contact in contacts {
            let json = serde_json::to_string(contact)
                .map_err(|error| BackendError::Serialization(error.to_string()))?;
            hset.arg(&contact.uri).arg(json);
        }
        pipe.add_command(hset)
            .ignore()
            .expire(&key, ttl_with_slack as i64)
            .ignore()
            .expire(self.state_key(aor), ttl_with_slack as i64)
            .ignore()
            .zadd(self.index_key(), aor, expiry)
            .ignore();
        pipe.query_async::<()>(&mut connection)
            .await
            .map_err(|error| BackendError::Query(error.to_string()))
    }

    async fn load(&self, aor: &str) -> Result<Vec<StoredContact>, BackendError> {
        let key = self.key(aor);
        let mut connection = self.connection_for(aor);

        let entries: Vec<(String, String)> = connection
            .hgetall(&key)
            .await
            .map_err(|error| BackendError::Query(error.to_string()))?;

        let mut contacts = Vec::with_capacity(entries.len());
        let mut expired_fields: Vec<String> = Vec::new();
        for (field, value) in entries {
            let contact: StoredContact = serde_json::from_str(&value)
                .map_err(|error| BackendError::Serialization(error.to_string()))?;
            // Filter out individually expired contacts (the hash key TTL
            // is set to the *longest* contact, so shorter ones may linger).
            if contact.is_expired() {
                expired_fields.push(field);
            } else {
                contacts.push(contact);
            }
        }

        // Lazily delete expired fields from the hash. The index needs no
        // change: its score is the longest contact's, which is still live
        // while any field is, and is dropped by score once none is.
        if !expired_fields.is_empty() {
            let fields: Vec<&str> = expired_fields.iter().map(|s| s.as_str()).collect();
            let _: () = connection
                .hdel(&key, &fields[..])
                .await
                .map_err(|error| BackendError::Query(error.to_string()))?;
        }

        Ok(contacts)
    }

    async fn remove(&self, aor: &str) -> Result<(), BackendError> {
        let mut connection = self.connection_for(aor);
        let mut pipe = redis::pipe();
        pipe.atomic()
            .del(self.key(aor))
            .ignore()
            .zrem(self.index_key(), aor)
            .ignore();
        pipe.query_async::<()>(&mut connection)
            .await
            .map_err(|error| BackendError::Query(error.to_string()))
    }

    async fn exists(&self, aor: &str) -> Result<bool, BackendError> {
        let key = self.key(aor);
        let mut connection = self.connection_for(aor);
        let result: bool = connection
            .exists(&key)
            .await
            .map_err(|error| BackendError::Query(error.to_string()))?;
        Ok(result)
    }

    async fn all_aors(&self) -> Result<Vec<String>, BackendError> {
        let mut all_aors = Vec::new();
        for mut connection in self.all_connections() {
            let mut range = redis::cmd("ZRANGE");
            range.arg(self.index_key()).arg(0).arg(-1);
            let (_, aors): (usize, Vec<String>) = self.read_index(&mut connection, range).await?;
            all_aors.extend(aors);
        }
        Ok(all_aors)
    }

    async fn count_aors(&self) -> Result<usize, BackendError> {
        let mut total = 0usize;
        for mut connection in self.all_connections() {
            let mut card = redis::cmd("ZCARD");
            card.arg(self.index_key());
            let (_, count): (usize, usize) = self.read_index(&mut connection, card).await?;
            total += count;
        }
        Ok(total)
    }

    async fn purge_expired(&self) -> Result<usize, BackendError> {
        let mut purged = 0usize;
        for mut connection in self.all_connections() {
            let removed: usize = redis::cmd("ZREMRANGEBYSCORE")
                .arg(self.index_key())
                .arg("-inf")
                .arg(epoch_now())
                .query_async(&mut connection)
                .await
                .map_err(|error| BackendError::Query(error.to_string()))?;
            purged += removed;
        }
        Ok(purged)
    }

    async fn save_aor_state(&self, aor: &str, state: &StoredAorState) -> Result<(), BackendError> {
        let key = self.state_key(aor);
        let mut connection = self.connection_for(aor);

        if state.is_empty() {
            let _: () = connection
                .del(&key)
                .await
                .map_err(|error| BackendError::Query(error.to_string()))?;
            return Ok(());
        }

        let json = serde_json::to_string(state)
            .map_err(|error| BackendError::Serialization(error.to_string()))?;
        let without_binding = self
            .max_binding_lifetime_secs
            .saturating_add(self.config.ttl_slack_secs)
            .max(1);
        let _: () = redis::Script::new(SAVE_STATE_SCRIPT)
            .key(self.key(aor))
            .key(&key)
            .arg(json)
            .arg(without_binding)
            .invoke_async(&mut connection)
            .await
            .map_err(|error| BackendError::Query(error.to_string()))?;
        Ok(())
    }

    async fn load_aor_state(&self, aor: &str) -> Result<Option<StoredAorState>, BackendError> {
        let key = self.state_key(aor);
        let mut connection = self.connection_for(aor);
        let value: Option<String> = connection
            .get(&key)
            .await
            .map_err(|error| BackendError::Query(error.to_string()))?;
        match value {
            Some(json) => {
                let state: StoredAorState = serde_json::from_str(&json)
                    .map_err(|error| BackendError::Serialization(error.to_string()))?;
                Ok(Some(state))
            }
            None => Ok(None),
        }
    }

    async fn remove_aor_state(&self, aor: &str) -> Result<(), BackendError> {
        let key = self.state_key(aor);
        let mut connection = self.connection_for(aor);
        let _: () = connection
            .del(&key)
            .await
            .map_err(|error| BackendError::Query(error.to_string()))?;
        Ok(())
    }

    /// Boot-time only (the restore), so a cursor `SCAN` rather than an index.
    async fn all_aor_state_aors(&self) -> Result<Vec<String>, BackendError> {
        let state_prefix = format!("{}state:", self.config.key_prefix);
        let prefix_len = state_prefix.len();
        let pattern = format!("{state_prefix}*");
        let mut aors = Vec::new();

        for mut connection in self.all_connections() {
            let mut cursor: u64 = 0;
            loop {
                let (next_cursor, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                    .arg(cursor)
                    .arg("MATCH")
                    .arg(&pattern)
                    .arg("COUNT")
                    .arg(SCAN_COUNT)
                    .query_async(&mut connection)
                    .await
                    .map_err(|error| BackendError::Query(error.to_string()))?;

                for key in keys {
                    if key.len() > prefix_len {
                        aors.push(key[prefix_len..].to_string());
                    }
                }

                cursor = next_cursor;
                if cursor == 0 {
                    break;
                }
            }
        }

        Ok(aors)
    }
}

#[cfg(test)]
#[path = "redis_store_tests.rs"]
mod tests;
