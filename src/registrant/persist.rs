//! What a restarted node needs to clear the bindings the process before it
//! left on a registrar.
//!
//! A node that is killed without a graceful shutdown never sends its
//! de-REGISTERs, and a restart that no longer lists a trunk (its lease moved to
//! another node) has nothing that remembers the binding it held. The registrar
//! then carries two contacts for the trunk until the dead one runs out, up to a
//! whole registration interval.
//!
//! So each binding granted to a digest entry is written to Redis, one hash per
//! binding under a prefix of its own (never under the registrar's, whose index
//! build scans its prefix), with a TTL of the granted expiry plus slack: a
//! record leaves by itself once the registrar would have dropped the binding
//! anyway. After a restart [`super::RegistrantManager::startup_cleanup`] reads
//! this instance's records back and de-registers the ones nothing live owns
//! (RFC 3261 §10.2.2) on the Call-ID and with the next CSeq (§10.2.4).
//!
//! **No secret is stored.** Not the username, not the password, not an HA1: a
//! record holds only what a REGISTER carries on the wire in clear. The credential
//! a challenge to the de-REGISTER needs comes from the source's lookup by AoR
//! (see [`super::source::CredentialLookup`]).
//!
//! Writes never wait: they land in a map keyed by AoR where the latest wins,
//! and one task applies them, retrying what Redis refuses. Safe from a thread
//! attached to the interpreter and from a tokio worker alike.

// Without Redis nothing builds a store (the registrar's Redis backend does):
// the module is then all unreachable by design, and compiles the same.
#![cfg_attr(not(any(feature = "redis-backend", test)), allow(dead_code))]

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::Notify;
#[cfg(feature = "redis-backend")]
use tracing::debug;
use tracing::warn;

use super::EntryOrigin;
use crate::transport::Transport;

/// Default key prefix of the persisted bindings: apart from the registrar's
/// keyspace and the presence store's.
pub const DEFAULT_REGISTRANT_KEY_PREFIX: &str = "siphon:registrant:";

/// How many start-ups may try to clear one record before it is given up on:
/// a record that keeps failing (a registrar that refuses, a lookup that never
/// answers) must not be retried by every restart for ever.
pub const MAX_STARTUP_ATTEMPTS: u32 = 3;

/// How long a failed write waits before it is applied again.
#[cfg(feature = "redis-backend")]
const RETRY_DELAY: Duration = Duration::from_secs(1);

/// Seconds since the Unix epoch.
pub(crate) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

/// The fields of a stored binding, by name. Nothing here is a credential; a
/// test holds the list to that.
#[cfg(test)]
pub(crate) const FIELDS: [&str; 14] = [
    "instance",
    "aor",
    "registrar_uri",
    "destination",
    "address_str",
    "transport",
    "contact",
    "call_id",
    "next_cseq",
    "local_addr",
    "interval_secs",
    "binding_until_unix",
    "origin",
    "attempts",
];

/// One binding a registrar may hold from this instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingRecord {
    /// The instance that registered it (`server.instance_id`).
    pub instance: String,
    pub aor: String,
    pub registrar_uri: String,
    /// Where the REGISTER went.
    pub destination: SocketAddr,
    /// The hostname the destination was resolved from, if any.
    pub address_str: Option<String>,
    pub transport: Transport,
    /// The Contact URI the registrar holds the binding on.
    pub contact: String,
    pub call_id: String,
    /// The CSeq the entry's next REGISTER would have taken.
    pub next_cseq: u32,
    /// The address the entry registers from, when it has one of its own.
    pub local_addr: Option<IpAddr>,
    pub interval_secs: u32,
    /// When the registrar drops the binding unless it is refreshed.
    pub binding_until_unix: u64,
    pub origin: EntryOrigin,
    /// How many start-ups tried to clear it already.
    pub attempts: u32,
}

fn origin_token(origin: EntryOrigin) -> &'static str {
    match origin {
        EntryOrigin::Yaml => "yaml",
        EntryOrigin::Script => "script",
        EntryOrigin::Source => "source",
    }
}

fn origin_from_token(token: &str) -> Option<EntryOrigin> {
    match token {
        "yaml" => Some(EntryOrigin::Yaml),
        "script" => Some(EntryOrigin::Script),
        "source" => Some(EntryOrigin::Source),
        _ => None,
    }
}

impl BindingRecord {
    /// The hash fields this is stored as, named by [`FIELDS`].
    pub(crate) fn to_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("instance", self.instance.clone()),
            ("aor", self.aor.clone()),
            ("registrar_uri", self.registrar_uri.clone()),
            ("destination", self.destination.to_string()),
            ("address_str", self.address_str.clone().unwrap_or_default()),
            ("transport", self.transport.to_string().to_ascii_lowercase()),
            ("contact", self.contact.clone()),
            ("call_id", self.call_id.clone()),
            ("next_cseq", self.next_cseq.to_string()),
            (
                "local_addr",
                self.local_addr
                    .map(|address| address.to_string())
                    .unwrap_or_default(),
            ),
            ("interval_secs", self.interval_secs.to_string()),
            ("binding_until_unix", self.binding_until_unix.to_string()),
            ("origin", origin_token(self.origin).to_string()),
            ("attempts", self.attempts.to_string()),
        ]
    }

    /// Read a stored hash back. `None` for one that is not a binding (a field
    /// missing or unreadable): it is dropped, never guessed at.
    pub(crate) fn from_fields(fields: &HashMap<String, String>) -> Option<Self> {
        let text = |name: &str| fields.get(name).filter(|value| !value.is_empty());
        let required = |name: &str| text(name).cloned();
        Some(Self {
            instance: fields.get("instance").cloned().unwrap_or_default(),
            aor: required("aor")?,
            registrar_uri: required("registrar_uri")?,
            destination: text("destination")?.parse().ok()?,
            address_str: text("address_str").cloned(),
            transport: crate::config::parse_outbound_transport(text("transport")?)?,
            contact: required("contact")?,
            call_id: required("call_id")?,
            next_cseq: text("next_cseq")?.parse().ok()?,
            local_addr: match text("local_addr") {
                Some(address) => Some(address.parse().ok()?),
                None => None,
            },
            interval_secs: text("interval_secs")?.parse().ok()?,
            binding_until_unix: text("binding_until_unix")?.parse().ok()?,
            origin: origin_from_token(text("origin")?)?,
            attempts: text("attempts")
                .and_then(|value| value.parse().ok())
                .unwrap_or(0),
        })
    }

    /// Seconds the registrar may still hold the binding at `now_unix`.
    pub fn remaining_secs(&self, now_unix: u64) -> u64 {
        self.binding_until_unix.saturating_sub(now_unix)
    }
}

/// One write, the latest for its AoR.
#[derive(Debug, Clone)]
enum Write {
    Save(Box<BindingRecord>),
    Remove,
    /// Remove the stored record only if it is the registration `call_id`'s.
    RemoveIf(String),
    /// Set the stored record's attempt counter, only if it is the registration
    /// `call_id`'s.
    SetAttemptsIf(String, u32),
}

/// Set the attempt counter of a record only when it is still the one being
/// cleaned up. Atomic in Redis; the TTL is left as it is.
#[cfg(feature = "redis-backend")]
const SET_ATTEMPTS_IF_SCRIPT: &str = "if redis.call('HGET', KEYS[1], 'call_id') == ARGV[1] then \
     redis.call('HSET', KEYS[1], 'attempts', ARGV[2]) return 1 else return 0 end";

/// Delete a record only when it is still the one being cleaned up: another
/// registration may have replaced it since. Atomic in Redis.
#[cfg(feature = "redis-backend")]
const REMOVE_IF_SCRIPT: &str = "if redis.call('HGET', KEYS[1], 'call_id') == ARGV[1] then \
     return redis.call('DEL', KEYS[1]) else return 0 end";

/// Where the records live.
enum Backend {
    #[cfg(feature = "redis-backend")]
    Redis(crate::redis_target::RedisConnection),
    /// Applied at once, no task: for tests that need no Redis.
    #[cfg(test)]
    Memory(Mutex<HashMap<String, (BindingRecord, u64)>>),
    /// Queues and never applies, and reads as unreadable: for a test of the
    /// queue itself. Nothing builds it outside tests.
    #[cfg_attr(not(test), allow(dead_code))]
    Inert,
}

struct Shared {
    instance_id: String,
    key_prefix: String,
    ttl_slack_secs: u64,
    backend: Backend,
    /// The latest write per AoR not applied yet.
    pending: Mutex<HashMap<String, Write>>,
    /// Writes taken off `pending` and being applied.
    in_flight: AtomicUsize,
    notify: Notify,
    closed: AtomicBool,
}

/// The persisted bindings of one instance.
pub struct BindingStore {
    shared: Arc<Shared>,
}

impl std::fmt::Debug for BindingStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BindingStore")
            .field("instance_id", &self.shared.instance_id)
            .field("key_prefix", &self.shared.key_prefix)
            .finish_non_exhaustive()
    }
}

impl Drop for BindingStore {
    fn drop(&mut self) {
        self.shared.closed.store(true, Ordering::SeqCst);
        self.shared.notify.notify_one();
    }
}

impl Shared {
    fn key(&self, aor: &str) -> String {
        format!("{}{}:{aor}", self.key_prefix, self.instance_id)
    }

    fn ttl_for(&self, record: &BindingRecord) -> u64 {
        record
            .remaining_secs(unix_now())
            .saturating_add(self.ttl_slack_secs)
            .max(1)
    }

    #[cfg(feature = "redis-backend")]
    fn take_pending(&self) -> Vec<(String, Write)> {
        let mut pending = match self.pending.lock() {
            Ok(pending) => pending,
            Err(poisoned) => poisoned.into_inner(),
        };
        // Counted in flight before the lock lets go, so the writes are never
        // in neither place.
        let batch: Vec<(String, Write)> = pending.drain().collect();
        self.in_flight.fetch_add(batch.len(), Ordering::SeqCst);
        batch
    }

    /// Put back what could not be applied, unless a newer write for the AoR
    /// arrived meanwhile.
    #[cfg(feature = "redis-backend")]
    fn requeue(&self, aor: String, write: Write) {
        let mut pending = match self.pending.lock() {
            Ok(pending) => pending,
            Err(poisoned) => poisoned.into_inner(),
        };
        pending.entry(aor).or_insert(write);
    }

    #[cfg(feature = "redis-backend")]
    async fn apply(&self, aor: &str, write: &Write) -> Result<(), String> {
        match &self.backend {
            #[cfg(feature = "redis-backend")]
            Backend::Redis(connection) => {
                let mut connection = connection.clone();
                let key = self.key(aor);
                match write {
                    Write::Remove => redis::cmd("DEL")
                        .arg(&key)
                        .query_async::<i64>(&mut connection)
                        .await
                        .map(|_| ())
                        .map_err(|error| error.to_string()),
                    Write::RemoveIf(call_id) => redis::Script::new(REMOVE_IF_SCRIPT)
                        .key(&key)
                        .arg(call_id)
                        .invoke_async::<i64>(&mut connection)
                        .await
                        .map(|_| ())
                        .map_err(|error| error.to_string()),
                    Write::SetAttemptsIf(call_id, attempts) => {
                        redis::Script::new(SET_ATTEMPTS_IF_SCRIPT)
                            .key(&key)
                            .arg(call_id)
                            .arg(*attempts)
                            .invoke_async::<i64>(&mut connection)
                            .await
                            .map(|_| ())
                            .map_err(|error| error.to_string())
                    }
                    Write::Save(record) => {
                        let mut pipeline = redis::pipe();
                        pipeline.atomic().cmd("DEL").arg(&key).ignore();
                        let mut hset = redis::cmd("HSET");
                        hset.arg(&key);
                        for (name, value) in record.to_fields() {
                            hset.arg(name).arg(value);
                        }
                        pipeline.add_command(hset).ignore();
                        pipeline
                            .cmd("EXPIRE")
                            .arg(&key)
                            .arg(self.ttl_for(record))
                            .ignore();
                        pipeline
                            .query_async::<()>(&mut connection)
                            .await
                            .map_err(|error| error.to_string())
                    }
                }
            }
            #[cfg(test)]
            Backend::Memory(_) => {
                self.apply_memory(aor, write);
                Ok(())
            }
            Backend::Inert => Ok(()),
        }
    }

    #[cfg(test)]
    fn apply_memory(&self, aor: &str, write: &Write) {
        let Backend::Memory(records) = &self.backend else {
            return;
        };
        let mut records = match records.lock() {
            Ok(records) => records,
            Err(poisoned) => poisoned.into_inner(),
        };
        match write {
            Write::Remove => {
                records.remove(&self.key(aor));
            }
            Write::Save(record) => {
                records.insert(self.key(aor), ((**record).clone(), self.ttl_for(record)));
            }
            Write::SetAttemptsIf(call_id, attempts) => {
                if let Some((stored, _)) = records.get_mut(&self.key(aor)) {
                    if stored.call_id == *call_id {
                        stored.attempts = *attempts;
                    }
                }
            }
            Write::RemoveIf(call_id) => {
                let key = self.key(aor);
                if records
                    .get(&key)
                    .is_some_and(|(stored, _)| stored.call_id == *call_id)
                {
                    records.remove(&key);
                }
            }
        }
    }

    /// Apply every pending write once; what fails is queued again.
    #[cfg(feature = "redis-backend")]
    async fn drain_once(&self) -> usize {
        let mut failed = 0;
        let batch = self.take_pending();
        for (aor, write) in batch {
            if let Err(error) = self.apply(&aor, &write).await {
                warn!(%aor, %error, "registrant bindings: write not applied, retrying");
                self.requeue(aor, write);
                failed += 1;
            }
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
        }
        failed
    }
}

impl BindingStore {
    fn with_backend(
        backend: Backend,
        instance_id: String,
        key_prefix: String,
        ttl_slack_secs: u64,
    ) -> Self {
        Self {
            shared: Arc::new(Shared {
                instance_id,
                key_prefix,
                ttl_slack_secs,
                backend,
                pending: Mutex::new(HashMap::new()),
                in_flight: AtomicUsize::new(0),
                notify: Notify::new(),
                closed: AtomicBool::new(false),
            }),
        }
    }

    /// A store on Redis, applying its writes from a task of its own. Must be
    /// called on a tokio runtime.
    #[cfg(feature = "redis-backend")]
    pub fn redis(
        connection: crate::redis_target::RedisConnection,
        instance_id: String,
        key_prefix: String,
        ttl_slack_secs: u64,
    ) -> Arc<Self> {
        let store = Arc::new(Self::with_backend(
            Backend::Redis(connection),
            instance_id,
            key_prefix,
            ttl_slack_secs,
        ));
        let shared = Arc::clone(&store.shared);
        tokio::spawn(async move {
            loop {
                shared.notify.notified().await;
                if shared.closed.load(Ordering::SeqCst) {
                    return;
                }
                while shared.drain_once().await > 0 {
                    if shared.closed.load(Ordering::SeqCst) {
                        return;
                    }
                    tokio::time::sleep(RETRY_DELAY).await;
                }
            }
        });
        store
    }

    /// A store that applies every write at once, in memory.
    #[cfg(test)]
    pub(crate) fn in_memory(instance_id: &str, ttl_slack_secs: u64) -> Arc<Self> {
        Arc::new(Self::with_backend(
            Backend::Memory(Mutex::new(HashMap::new())),
            instance_id.to_string(),
            DEFAULT_REGISTRANT_KEY_PREFIX.to_string(),
            ttl_slack_secs,
        ))
    }

    /// The instance this store holds records of.
    pub fn instance_id(&self) -> &str {
        &self.shared.instance_id
    }

    fn enqueue(&self, aor: &str, write: Write) {
        // No task and no runtime needed: applied where it is written.
        #[cfg(test)]
        if matches!(self.shared.backend, Backend::Memory(_)) {
            self.shared.apply_memory(aor, &write);
            return;
        }
        let mut pending = match self.shared.pending.lock() {
            Ok(pending) => pending,
            Err(poisoned) => poisoned.into_inner(),
        };
        // A guarded write is never made unguarded, and never undoes a save of a
        // newer registration still waiting. Where two cannot both be kept the
        // one that does less wins: the record is then left to expire, as before.
        let write = match (&write, pending.get(aor)) {
            (Write::RemoveIf(call_id), Some(Write::Save(queued))) => {
                if queued.call_id != *call_id {
                    return;
                }
                write
            }
            (Write::SetAttemptsIf(call_id, _), Some(Write::Save(queued))) => {
                if queued.call_id != *call_id {
                    return;
                }
                write
            }
            // An unconditional removal, or a guarded one, stays as it is.
            (Write::SetAttemptsIf(..), Some(Write::Remove | Write::RemoveIf(_))) => return,
            (Write::RemoveIf(_), Some(Write::Remove)) => return,
            _ => write,
        };
        pending.insert(aor.to_string(), write);
        drop(pending);
        self.shared.notify.notify_one();
    }

    /// Set the attempt counter of `aor`'s record if it is still the
    /// registration `call_id`'s.
    pub fn set_attempts_if(&self, aor: &str, call_id: &str, attempts: u32) {
        self.enqueue(aor, Write::SetAttemptsIf(call_id.to_string(), attempts));
    }

    /// What waits for `aor` in the queue.
    #[cfg(test)]
    pub(crate) fn pending_kind(&self, aor: &str) -> Option<&'static str> {
        let pending = self.shared.pending.lock().ok()?;
        pending.get(aor).map(|write| match write {
            Write::Save(_) => "save",
            Write::Remove => "remove",
            Write::RemoveIf(_) => "remove_if",
            Write::SetAttemptsIf(..) => "set_attempts_if",
        })
    }

    /// A store that only queues, for a test of the queue.
    #[cfg(test)]
    pub(crate) fn inert(instance_id: &str) -> Arc<Self> {
        Arc::new(Self::with_backend(
            Backend::Inert,
            instance_id.to_string(),
            DEFAULT_REGISTRANT_KEY_PREFIX.to_string(),
            30,
        ))
    }

    /// Remove the record of `aor` if it is still the registration `call_id`'s.
    pub fn remove_if(&self, aor: &str, call_id: &str) {
        self.enqueue(aor, Write::RemoveIf(call_id.to_string()));
    }

    /// Store `record` (replacing the AoR's earlier one).
    pub fn save(&self, record: BindingRecord) {
        let aor = record.aor.clone();
        self.enqueue(&aor, Write::Save(Box::new(record)));
    }

    /// Remove the record of `aor`.
    pub fn remove(&self, aor: &str) {
        self.enqueue(aor, Write::Remove);
    }

    /// Writes not applied yet.
    pub fn pending_writes(&self) -> usize {
        let queued = match self.shared.pending.lock() {
            Ok(pending) => pending.len(),
            Err(poisoned) => poisoned.into_inner().len(),
        };
        queued + self.shared.in_flight.load(Ordering::SeqCst)
    }

    /// Wait, up to `timeout`, until every write so far is applied. For a
    /// process about to exit.
    pub async fn flush(&self, timeout: Duration) {
        let deadline = tokio::time::Instant::now() + timeout;
        while self.pending_writes() > 0 && tokio::time::Instant::now() < deadline {
            self.shared.notify.notify_one();
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Every record of this instance, expired ones left out.
    pub async fn load(&self) -> Result<Vec<BindingRecord>, String> {
        let now = unix_now();
        let mut records: Vec<BindingRecord> = self
            .load_raw()
            .await?
            .into_iter()
            .filter(|record| record.instance == self.shared.instance_id)
            .collect();
        records.retain(|record| record.remaining_secs(now) > 0);
        records.sort_by(|left, right| left.aor.cmp(&right.aor));
        Ok(records)
    }

    /// The records OTHER instances hold for `aors`: a registrar keys a binding
    /// by its Contact, so another node's record of the same AoR and Contact is
    /// a REGISTER that already replaced ours (RFC 3261 §10.3). Records of this
    /// store's own instance id are left out, so two processes that share an
    /// `instance_id` do not see each other here, and write the same keys: every
    /// node needs a unique `server.instance_id` (see `siphon.yaml`). Scans
    /// `{prefix}*:{aor}` for each (SCAN, never KEYS).
    #[cfg_attr(not(any(feature = "redis-backend", test)), allow(clippy::never_loop))]
    pub async fn others_holding(&self, aors: &[String]) -> Result<Vec<BindingRecord>, String> {
        let mut found: Vec<BindingRecord> = Vec::new();
        for aor in aors {
            let _ = aor;
            match &self.shared.backend {
                #[cfg(feature = "redis-backend")]
                Backend::Redis(connection) => {
                    let pattern = format!(
                        "{}*:{}",
                        glob_escape(&self.shared.key_prefix),
                        glob_escape(aor)
                    );
                    let (records, unreadable) =
                        scan_records(&mut connection.clone(), &pattern).await?;
                    // Another instance's hash that cannot be read may be exactly
                    // the binding that matters: it counts as held.
                    let own = format!("{}{}:", self.shared.key_prefix, self.shared.instance_id);
                    if let Some(key) = unreadable.iter().find(|key| !key.starts_with(&own)) {
                        return Err(format!("another instance's record {key} cannot be read"));
                    }
                    found.extend(records);
                }
                Backend::Inert => return Err("the store cannot be read".to_string()),
                #[cfg(test)]
                Backend::Memory(records) => {
                    let records = match records.lock() {
                        Ok(records) => records,
                        Err(poisoned) => poisoned.into_inner(),
                    };
                    found.extend(records.values().map(|(record, _)| record.clone()));
                }
            }
        }
        found.retain(|record| record.instance != self.shared.instance_id);
        found.retain(|record| aors.contains(&record.aor));
        Ok(found)
    }

    /// Hold a record as another instance wrote it.
    #[cfg(test)]
    pub(crate) fn save_as_instance(&self, record: BindingRecord) {
        if let Backend::Memory(records) = &self.shared.backend {
            let key = format!(
                "{}{}:{}",
                self.shared.key_prefix, record.instance, record.aor
            );
            let ttl = self.shared.ttl_for(&record);
            if let Ok(mut records) = records.lock() {
                records.insert(key, (record, ttl));
            }
        }
    }

    async fn load_raw(&self) -> Result<Vec<BindingRecord>, String> {
        match &self.shared.backend {
            #[cfg(feature = "redis-backend")]
            Backend::Redis(connection) => {
                let pattern = format!(
                    "{}{}:*",
                    glob_escape(&self.shared.key_prefix),
                    glob_escape(&self.shared.instance_id)
                );
                scan_records(&mut connection.clone(), &pattern)
                    .await
                    .map(|(records, _)| records)
            }
            Backend::Inert => Ok(Vec::new()),
            #[cfg(test)]
            Backend::Memory(records) => Ok(match records.lock() {
                Ok(records) => records.values().map(|(record, _)| record.clone()).collect(),
                Err(poisoned) => poisoned
                    .into_inner()
                    .values()
                    .map(|(record, _)| record.clone())
                    .collect(),
            }),
        }
    }

    /// The TTL, in seconds, the in-memory store holds `aor` with.
    #[cfg(test)]
    pub(crate) fn memory_ttl(&self, aor: &str) -> Option<u64> {
        match &self.shared.backend {
            Backend::Memory(records) => records
                .lock()
                .ok()?
                .get(&self.shared.key(aor))
                .map(|(_, ttl)| *ttl),
            #[cfg(feature = "redis-backend")]
            Backend::Redis(_) => None,
            Backend::Inert => None,
        }
    }

    /// The raw key of `aor`, for a test reading Redis directly.
    #[cfg(test)]
    pub(crate) fn key_of(&self, aor: &str) -> String {
        self.shared.key(aor)
    }
}

/// Every readable record under the keys matching `pattern`, found by SCAN.
#[cfg(feature = "redis-backend")]
async fn scan_records(
    connection: &mut crate::redis_target::RedisConnection,
    pattern: &str,
) -> Result<(Vec<BindingRecord>, Vec<String>), String> {
    let mut keys: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut cursor: u64 = 0;
    loop {
        let (next, batch): (u64, Vec<String>) = redis::cmd("SCAN")
            .arg(cursor)
            .arg("MATCH")
            .arg(pattern)
            .arg("COUNT")
            .arg(1000)
            .query_async(connection)
            .await
            .map_err(|error| format!("SCAN failed: {error}"))?;
        keys.extend(batch);
        cursor = next;
        if cursor == 0 {
            break;
        }
    }
    let mut records = Vec::new();
    let mut unreadable = Vec::new();
    for key in keys {
        let fields: HashMap<String, String> = redis::cmd("HGETALL")
            .arg(&key)
            .query_async(connection)
            .await
            .map_err(|error| format!("HGETALL failed: {error}"))?;
        // Gone between the SCAN and now: its TTL ran out.
        if fields.is_empty() {
            continue;
        }
        match BindingRecord::from_fields(&fields) {
            Some(record) => records.push(record),
            None => {
                debug!(%key, "registrant bindings: unreadable record skipped");
                unreadable.push(key);
            }
        }
    }
    Ok((records, unreadable))
}

/// Escape the glob characters of `text` for a `SCAN MATCH`.
#[cfg(feature = "redis-backend")]
fn glob_escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        if matches!(character, '*' | '?' | '[' | ']' | '\\') {
            escaped.push('\\');
        }
        escaped.push(character);
    }
    escaped
}

// ---------------------------------------------------------------------------
// Handing the store to the registrant
// ---------------------------------------------------------------------------

/// The store the Redis backend published, for the registrant to pick up.
///
/// The registrar backend connects before the registrant manager exists, and may
/// connect long after it, so neither can hand the other a reference directly.
static PUBLISHED: OnceLock<Arc<BindingStore>> = OnceLock::new();

/// Publish the store (the registrar's Redis backend, once it is connected).
pub fn publish_store(store: Arc<BindingStore>) {
    if PUBLISHED.set(store).is_err() {
        warn!("registrant bindings: a store was already published");
    }
}

/// The published store, once there is one.
pub fn published_store() -> Option<Arc<BindingStore>> {
    PUBLISHED.get().cloned()
}

#[cfg(test)]
#[path = "persist_tests.rs"]
mod tests;

#[cfg(all(test, feature = "redis-backend"))]
#[path = "persist_redis_tests.rs"]
mod redis_tests;
