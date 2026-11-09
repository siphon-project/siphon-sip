//! The Redis side of [`super::shared`]: the indexes and counters that let any
//! node find a subscription, and the atomic operations that number and claim
//! its NOTIFYs.
//!
//! Under `presence_key_prefix` (the subscription itself is `{prefix}{id}`, see
//! [`super::persist`]):
//!
//! - `{prefix}watchers:{resource}`: set of the ids watching a resource. Added
//!   to by every save of a subscription, renewed to the longest TTL of its
//!   members; an id whose subscription key is gone is dropped when read.
//! - `{prefix}dialog:{call_id}:{from_tag}`: the id of the dialog's
//!   subscription, with the subscription's TTL.
//! - `{prefix}seq:cseq:{id}` and `{prefix}seq:ver:{id}`: the next CSeq and the
//!   next reginfo version of a subscription, advanced atomically by a script.
//! - `{prefix}claim:{id}:{marker}`: a notification claim, 10 minutes.

use futures_util::future::BoxFuture;
use redis::AsyncCommands;

use super::persist::StoredSubscription;
use super::shared::{Counter, SharedSubscriptions};
use crate::redis_target::RedisConnection;
use crate::registrar::backend::BackendError;

/// How long a notification claim is kept, seconds.
const CLAIM_TTL_SECS: u64 = 600;

/// The key prefixes of everything that is not a subscription, which a restore
/// of `{prefix}*` must not read as one.
pub(crate) const AUXILIARY_PREFIXES: [&str; 4] = ["watchers:", "dialog:", "seq:", "claim:"];

/// Save one subscription, and index it by resource and by dialog, in one
/// script. KEYS: the subscription, its resource's watchers, its dialog (may be
/// absent). ARGV: the JSON, the TTL in seconds, the id.
pub(crate) const SAVE_SCRIPT: &str = r#"
redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2])
redis.call('SADD', KEYS[2], ARGV[3])
local wanted = tonumber(ARGV[2]) * 1000
if redis.call('PTTL', KEYS[2]) < wanted then
  redis.call('PEXPIRE', KEYS[2], wanted)
end
if KEYS[3] then
  redis.call('SET', KEYS[3], ARGV[3], 'EX', ARGV[2])
end
return 1
"#;

/// Hand out the next number of a counter: at least the caller's floor and at
/// least what was last stored. KEYS: the counter. ARGV: the floor, the TTL.
const NEXT_SCRIPT: &str = r#"
local stored = tonumber(redis.call('GET', KEYS[1]) or '0')
local number = math.max(stored, tonumber(ARGV[1]))
redis.call('SET', KEYS[1], number + 1, 'EX', ARGV[2])
return number
"#;

/// [`SharedSubscriptions`] on the Redis the subscriptions are written to.
#[derive(Debug)]
pub(crate) struct RedisSubscriptions {
    connection: RedisConnection,
    prefix: String,
}

impl RedisSubscriptions {
    pub(crate) fn new(connection: RedisConnection, prefix: String) -> Self {
        Self { connection, prefix }
    }

    fn query(error: redis::RedisError) -> BackendError {
        BackendError::Query(error.to_string())
    }

    fn parse(&self, id: &str, json: &str) -> Option<StoredSubscription> {
        match serde_json::from_str::<StoredSubscription>(json) {
            Ok(stored) => Some(stored),
            Err(error) => {
                tracing::warn!(id, %error, "presence: skipping an unreadable stored subscription");
                None
            }
        }
    }
}

impl SharedSubscriptions for RedisSubscriptions {
    fn by_resource<'a>(
        &'a self,
        resource: &'a str,
    ) -> BoxFuture<'a, Result<Vec<StoredSubscription>, BackendError>> {
        Box::pin(async move {
            let mut connection = self.connection.clone();
            let watchers = format!("{}watchers:{resource}", self.prefix);
            let ids: Vec<String> = connection.smembers(&watchers).await.map_err(Self::query)?;
            if ids.is_empty() {
                return Ok(Vec::new());
            }
            let keys: Vec<String> = ids
                .iter()
                .map(|id| format!("{}{id}", self.prefix))
                .collect();
            let values: Vec<Option<String>> = redis::cmd("MGET")
                .arg(&keys)
                .query_async(&mut connection)
                .await
                .map_err(Self::query)?;
            let mut found = Vec::new();
            let mut gone: Vec<&String> = Vec::new();
            for (id, value) in ids.iter().zip(values) {
                match value {
                    Some(json) => found.extend(self.parse(id, &json)),
                    None => gone.push(id),
                }
            }
            if !gone.is_empty() {
                let _: () = connection
                    .srem(&watchers, gone)
                    .await
                    .map_err(Self::query)?;
            }
            Ok(found)
        })
    }

    fn by_id<'a>(
        &'a self,
        id: &'a str,
    ) -> BoxFuture<'a, Result<Option<StoredSubscription>, BackendError>> {
        Box::pin(async move {
            let mut connection = self.connection.clone();
            let json: Option<String> = connection
                .get(format!("{}{id}", self.prefix))
                .await
                .map_err(Self::query)?;
            Ok(json.and_then(|json| self.parse(id, &json)))
        })
    }

    fn by_dialog<'a>(
        &'a self,
        call_id: &'a str,
        from_tag: &'a str,
    ) -> BoxFuture<'a, Result<Option<StoredSubscription>, BackendError>> {
        Box::pin(async move {
            let mut connection = self.connection.clone();
            let id: Option<String> = connection
                .get(format!("{}dialog:{call_id}:{from_tag}", self.prefix))
                .await
                .map_err(Self::query)?;
            match id {
                Some(id) => self.by_id(&id).await,
                None => Ok(None),
            }
        })
    }

    fn next_counter<'a>(
        &'a self,
        id: &'a str,
        counter: Counter,
        floor: u32,
        ttl_secs: u64,
    ) -> BoxFuture<'a, Result<u32, BackendError>> {
        Box::pin(async move {
            let mut connection = self.connection.clone();
            let name = match counter {
                Counter::Cseq => "cseq",
                Counter::Version => "ver",
            };
            let number: i64 = redis::Script::new(NEXT_SCRIPT)
                .key(format!("{}seq:{name}:{id}", self.prefix))
                .arg(floor)
                .arg(ttl_secs)
                .invoke_async(&mut connection)
                .await
                .map_err(Self::query)?;
            Ok(u32::try_from(number).unwrap_or(u32::MAX))
        })
    }

    fn claim<'a>(
        &'a self,
        id: &'a str,
        marker: &'a str,
    ) -> BoxFuture<'a, Result<bool, BackendError>> {
        Box::pin(async move {
            let mut connection = self.connection.clone();
            let claimed: Option<String> = redis::cmd("SET")
                .arg(format!("{}claim:{id}:{marker}", self.prefix))
                .arg(1)
                .arg("NX")
                .arg("EX")
                .arg(CLAIM_TTL_SECS)
                .query_async(&mut connection)
                .await
                .map_err(Self::query)?;
            Ok(claimed.is_some())
        })
    }
}
