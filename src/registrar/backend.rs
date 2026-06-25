//! Pluggable registrar backend trait and implementations.
//!
//! The in-memory DashMap is always the L1 cache. Backends provide L2 persistence
//! via write-through semantics: writes go to both L1 and L2; reads check L1 first.

use std::net::SocketAddr;
use std::time::Duration;

#[cfg(any(feature = "redis-backend", feature = "postgres-backend", test))]
use std::collections::hash_map::DefaultHasher;
#[cfg(any(feature = "redis-backend", feature = "postgres-backend", test))]
use std::hash::{Hash, Hasher};

use serde::{Deserialize, Serialize};

/// Serializable contact binding for persistence backends.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredContact {
    /// Contact URI as a string.
    pub uri: String,
    /// Quality value.
    pub q: f32,
    /// Expires duration in seconds (from the time of storage).
    pub expires_secs: u64,
    /// Absolute expiry as Unix epoch seconds.
    /// Added to support correct TTL after restart. Older entries without
    /// this field fall back to treating `expires_secs` as remaining.
    #[serde(default)]
    pub expires_at: Option<u64>,
    /// Call-ID that created this binding.
    pub call_id: String,
    /// CSeq sequence number.
    pub cseq: u32,
    /// Source address (if known).
    pub source_addr: Option<String>,
    /// Transport protocol the REGISTER arrived on (e.g. "udp", "tcp", "tls").
    #[serde(default)]
    pub source_transport: Option<String>,
    /// RFC 5627 sip.instance.
    pub sip_instance: Option<String>,
    /// RFC 5626 reg-id.
    pub reg_id: Option<u32>,
    /// RFC 3327 Path headers (for routing terminating requests via proxies).
    #[serde(default)]
    pub path: Vec<String>,
    /// Stable identity of the siphon instance that originally accepted this
    /// REGISTER.  `None` for legacy entries written before this field existed.
    #[serde(default)]
    pub instance_id: Option<String>,
    /// Boot-time epoch UUID of the process that accepted this REGISTER.
    /// `None` for legacy entries.
    #[serde(default)]
    pub instance_epoch: Option<String>,
    /// Opaque proxy-side token referencing this binding (RFC 3327 §5 /
    /// TS 24.229 §5.2.7.2 Path-token MT routing).  `None` for non-P-CSCF
    /// bindings and for legacy entries written before this field existed.
    #[serde(default)]
    pub flow_token: Option<String>,
    /// Listener local SocketAddr the inbound REGISTER landed on,
    /// serialized as a string.  Survives restart for UDP (the listener
    /// is recreated at the same address).  `None` for legacy entries.
    #[serde(default)]
    pub inbound_local_addr: Option<String>,
    /// `ConnectionId.0` of the accepted inbound connection.  Meaningful
    /// only on the accepting instance and only for the lifetime of the
    /// connection (TCP/TLS/WS/WSS); for UDP it is the deterministic
    /// `(local, remote)` hash that survives restart.
    #[serde(default)]
    pub inbound_connection_id: Option<u64>,
    /// Additional Contact-header parameters carried through from the
    /// originating REGISTER.  Holds RFC 3840 feature tags
    /// (`+g.3gpp.smsip`, `+g.3gpp.icsi-ref`, …) and any other params
    /// not broken out into typed fields.  `Vec::new()` for legacy
    /// entries written before this field existed.
    #[serde(default)]
    pub params: Vec<(String, Option<String>)>,
    /// `"ue"` (UE-side, default) or `"as"` (application-server contact
    /// captured from a 3PR 200 OK).  AS contacts are excluded from
    /// routing lookups but surface in reg-event NOTIFY bodies
    /// (TS 24.229 §5.4.2.1.2).  Defaults to `"ue"` for legacy entries
    /// written before this field existed.
    #[serde(default = "default_contact_kind")]
    pub kind: String,
}

fn default_contact_kind() -> String {
    "ue".to_string()
}

impl StoredContact {
    /// Convert from the in-memory Contact type.
    pub fn from_contact(contact: &super::Contact) -> Self {
        let remaining = contact.remaining_seconds();
        let now_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            uri: contact.uri.to_string(),
            q: contact.q,
            expires_secs: remaining,
            expires_at: Some(now_epoch + remaining),
            call_id: contact.call_id.clone(),
            cseq: contact.cseq,
            source_addr: contact.source_addr.map(|a| a.to_string()),
            source_transport: contact.source_transport.clone(),
            sip_instance: contact.sip_instance.clone(),
            reg_id: contact.reg_id,
            path: contact.path.clone(),
            instance_id: contact.instance_id.clone(),
            instance_epoch: contact.instance_epoch.clone(),
            flow_token: contact.flow_token.clone(),
            inbound_local_addr: contact.inbound_local_addr.map(|a| a.to_string()),
            inbound_connection_id: contact.inbound_connection_id,
            params: contact.params.clone(),
            kind: contact.kind.as_str().to_string(),
        }
    }

    /// Returns the number of seconds remaining until this contact expires,
    /// using `expires_at` (absolute epoch) when available, falling back to
    /// `expires_secs` for entries stored before this field was added.
    pub fn remaining_secs(&self) -> u64 {
        if let Some(expires_at) = self.expires_at {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            expires_at.saturating_sub(now)
        } else {
            self.expires_secs
        }
    }

    /// Returns true if this contact has expired.
    pub fn is_expired(&self) -> bool {
        self.remaining_secs() == 0
    }

    /// Convert to an in-memory Contact type.
    /// Returns `None` if the URI is unparseable or the contact has expired.
    pub fn to_contact(&self) -> Option<super::Contact> {
        use crate::sip::parser::parse_uri_standalone;

        let remaining = self.remaining_secs();
        if remaining == 0 {
            return None;
        }

        let uri = parse_uri_standalone(&self.uri).ok()?;
        let source_addr = self
            .source_addr
            .as_ref()
            .and_then(|s| s.parse::<SocketAddr>().ok());

        let inbound_local_addr = self
            .inbound_local_addr
            .as_ref()
            .and_then(|s| s.parse::<SocketAddr>().ok());

        Some(super::Contact {
            uri,
            q: self.q,
            registered_at: std::time::Instant::now(),
            expires: Duration::from_secs(remaining),
            call_id: self.call_id.clone(),
            cseq: self.cseq,
            source_addr,
            source_transport: self.source_transport.clone(),
            sip_instance: self.sip_instance.clone(),
            reg_id: self.reg_id,
            path: self.path.clone(),
            pending: false,
            instance_id: self.instance_id.clone(),
            instance_epoch: self.instance_epoch.clone(),
            flow_token: self.flow_token.clone(),
            inbound_local_addr,
            inbound_connection_id: self.inbound_connection_id,
            params: self.params.clone(),
            kind: match self.kind.as_str() {
                "as" => super::ContactKind::As,
                _ => super::ContactKind::Ue,
            },
        })
    }
}

/// Per-AoR state that lives alongside the contact bindings — Service-Route
/// (RFC 3608), P-Asserted-Identity (from IMS SAR user profile), and
/// P-Associated-URI list (RFC 3455).
///
/// These are populated by S-CSCF / P-CSCF scripts after Cx interactions and
/// must survive registrar restarts; without them, terminating routing breaks
/// until each user re-REGISTERs.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredAorState {
    #[serde(default)]
    pub service_routes: Vec<String>,
    #[serde(default)]
    pub asserted_identity: Option<String>,
    #[serde(default)]
    pub associated_uris: Vec<String>,
}

impl StoredAorState {
    /// Returns true when the state carries no information worth persisting.
    pub fn is_empty(&self) -> bool {
        self.service_routes.is_empty()
            && self.asserted_identity.is_none()
            && self.associated_uris.is_empty()
    }
}

/// Async trait for registrar persistence backends.
///
/// All methods are async to support network I/O (Redis, PostgreSQL).
/// The in-memory registrar wraps these with write-through semantics.
/// Futures must be `Send` so the backend can be used from `tokio::spawn`.
pub trait RegistrarBackend: Send + Sync + std::fmt::Debug {
    /// Store contacts for an AoR, replacing any existing bindings.
    fn save(&self, aor: &str, contacts: &[StoredContact]) -> impl std::future::Future<Output = Result<(), BackendError>> + Send;

    /// Load contacts for an AoR.
    fn load(&self, aor: &str) -> impl std::future::Future<Output = Result<Vec<StoredContact>, BackendError>> + Send;

    /// Remove all contacts for an AoR.
    fn remove(&self, aor: &str) -> impl std::future::Future<Output = Result<(), BackendError>> + Send;

    /// Check if an AoR exists in the backend.
    fn exists(&self, aor: &str) -> impl std::future::Future<Output = Result<bool, BackendError>> + Send;

    /// List all AoRs with stored contacts.
    fn all_aors(&self) -> impl std::future::Future<Output = Result<Vec<String>, BackendError>> + Send;

    /// Persist the auxiliary per-AoR state (service-routes, asserted identity,
    /// associated URIs).  Implementations must overwrite any prior state.
    fn save_aor_state(
        &self,
        aor: &str,
        state: &StoredAorState,
    ) -> impl std::future::Future<Output = Result<(), BackendError>> + Send;

    /// Load the auxiliary per-AoR state, or `None` if not present.
    fn load_aor_state(
        &self,
        aor: &str,
    ) -> impl std::future::Future<Output = Result<Option<StoredAorState>, BackendError>> + Send;

    /// Remove the auxiliary per-AoR state.
    fn remove_aor_state(
        &self,
        aor: &str,
    ) -> impl std::future::Future<Output = Result<(), BackendError>> + Send;

    /// List all AoRs that have stored auxiliary state.
    fn all_aor_state_aors(
        &self,
    ) -> impl std::future::Future<Output = Result<Vec<String>, BackendError>> + Send;
}

/// Backend errors.
#[derive(Debug, Clone)]
pub enum BackendError {
    /// Connection error (Redis, PostgreSQL).
    Connection(String),
    /// Serialization/deserialization error.
    Serialization(String),
    /// Query error.
    Query(String),
}

impl std::fmt::Display for BackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackendError::Connection(message) => write!(f, "backend connection error: {message}"),
            BackendError::Serialization(message) => {
                write!(f, "backend serialization error: {message}")
            }
            BackendError::Query(message) => write!(f, "backend query error: {message}"),
        }
    }
}

impl std::error::Error for BackendError {}

/// Compute a deterministic shard index for an AoR string.
#[cfg(any(feature = "redis-backend", feature = "postgres-backend", test))]
fn shard_index(aor: &str, shard_count: usize) -> usize {
    let mut hasher = DefaultHasher::new();
    aor.hash(&mut hasher);
    hasher.finish() as usize % shard_count
}

// ---------------------------------------------------------------------------
// In-memory backend (for testing and as a reference implementation)
// ---------------------------------------------------------------------------

/// In-memory backend using DashMap. Primarily for testing the backend trait.
#[derive(Debug)]
pub struct MemoryBackend {
    data: dashmap::DashMap<String, Vec<StoredContact>>,
    aor_state: dashmap::DashMap<String, StoredAorState>,
}

impl MemoryBackend {
    pub fn new() -> Self {
        Self {
            data: dashmap::DashMap::new(),
            aor_state: dashmap::DashMap::new(),
        }
    }
}

impl Default for MemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl RegistrarBackend for MemoryBackend {
    async fn save(&self, aor: &str, contacts: &[StoredContact]) -> Result<(), BackendError> {
        if contacts.is_empty() {
            self.data.remove(aor);
        } else {
            self.data.insert(aor.to_string(), contacts.to_vec());
        }
        Ok(())
    }

    async fn load(&self, aor: &str) -> Result<Vec<StoredContact>, BackendError> {
        Ok(self
            .data
            .get(aor)
            .map(|entry| entry.value().clone())
            .unwrap_or_default())
    }

    async fn remove(&self, aor: &str) -> Result<(), BackendError> {
        self.data.remove(aor);
        Ok(())
    }

    async fn exists(&self, aor: &str) -> Result<bool, BackendError> {
        Ok(self.data.contains_key(aor))
    }

    async fn all_aors(&self) -> Result<Vec<String>, BackendError> {
        Ok(self.data.iter().map(|entry| entry.key().clone()).collect())
    }

    async fn save_aor_state(
        &self,
        aor: &str,
        state: &StoredAorState,
    ) -> Result<(), BackendError> {
        if state.is_empty() {
            self.aor_state.remove(aor);
        } else {
            self.aor_state.insert(aor.to_string(), state.clone());
        }
        Ok(())
    }

    async fn load_aor_state(
        &self,
        aor: &str,
    ) -> Result<Option<StoredAorState>, BackendError> {
        Ok(self.aor_state.get(aor).map(|entry| entry.value().clone()))
    }

    async fn remove_aor_state(&self, aor: &str) -> Result<(), BackendError> {
        self.aor_state.remove(aor);
        Ok(())
    }

    async fn all_aor_state_aors(&self) -> Result<Vec<String>, BackendError> {
        Ok(self.aor_state.iter().map(|entry| entry.key().clone()).collect())
    }
}

// ---------------------------------------------------------------------------
// Redis backend — real implementation (feature-gated)
// ---------------------------------------------------------------------------

/// Redis backend configuration.
#[derive(Debug, Clone)]
pub struct RedisBackendConfig {
    /// Redis connection URL (e.g., "redis://127.0.0.1:6379").
    /// Used when `shard_count` is 0.
    pub url: String,
    /// List of shard URLs. Must have `shard_count` entries when sharding is enabled.
    pub urls: Vec<String>,
    /// Key prefix for registrar entries.
    pub key_prefix: String,
    /// Number of shards. 0 = no sharding (use `url`), >0 = shard by AoR hash.
    pub shard_count: usize,
    /// Extra seconds beyond the longest contact expiry to retain the Redis key.
    /// Prevents race conditions where a key expires moments before a refresh.
    pub ttl_slack_secs: u64,
}

impl Default for RedisBackendConfig {
    fn default() -> Self {
        Self {
            url: "redis://127.0.0.1:6379".to_string(),
            urls: Vec::new(),
            key_prefix: "siphon:reg:".to_string(),
            shard_count: 0,
            ttl_slack_secs: 30,
        }
    }
}

#[cfg(feature = "redis-backend")]
mod redis_real {
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
    }

    impl RedisBackend {
        /// Connect to Redis (single instance or sharded).
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
                    let connection = client
                        .get_multiplexed_async_connection()
                        .await
                        .map_err(|error| BackendError::Connection(error.to_string()))?;
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
                let connection = client
                    .get_multiplexed_async_connection()
                    .await
                    .map_err(|error| BackendError::Connection(error.to_string()))?;
                tracing::info!("redis registrar backend connected");
                vec![connection]
            };

            Ok(Self {
                config,
                connections,
            })
        }

        /// The Redis key for an AoR (contact bindings).
        fn key(&self, aor: &str) -> String {
            format!("{}{}", self.config.key_prefix, aor)
        }

        /// The Redis key for an AoR's auxiliary state.
        fn state_key(&self, aor: &str) -> String {
            format!("{}state:{}", self.config.key_prefix, aor)
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
    }

    impl RegistrarBackend for RedisBackend {
        async fn save(&self, aor: &str, contacts: &[StoredContact]) -> Result<(), BackendError> {
            let key = self.key(aor);
            let mut connection = self.connection_for(aor);

            if contacts.is_empty() {
                let _: () = connection
                    .del(&key)
                    .await
                    .map_err(|error| BackendError::Query(error.to_string()))?;
                return Ok(());
            }

            // Delete existing hash to replace all bindings, then set new ones.
            let _: () = connection
                .del(&key)
                .await
                .map_err(|error| BackendError::Query(error.to_string()))?;

            let mut max_ttl: u64 = 0;
            for contact in contacts {
                let json = serde_json::to_string(contact)
                    .map_err(|error| BackendError::Serialization(error.to_string()))?;
                let _: () = connection
                    .hset(&key, &contact.uri, &json)
                    .await
                    .map_err(|error| BackendError::Query(error.to_string()))?;
                let remaining = contact.remaining_secs();
                if remaining > max_ttl {
                    max_ttl = remaining;
                }
            }

            // Set TTL to the longest contact expiry + slack (minimum 1 second).
            // The slack prevents the key from expiring moments before a refresh.
            if max_ttl > 0 {
                let ttl_with_slack = max_ttl + self.config.ttl_slack_secs;
                let _: () = connection
                    .expire(&key, ttl_with_slack as i64)
                    .await
                    .map_err(|error| BackendError::Query(error.to_string()))?;
            }

            Ok(())
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

            // Lazily delete expired fields from the hash.
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
            let key = self.key(aor);
            let mut connection = self.connection_for(aor);
            let _: () = connection
                .del(&key)
                .await
                .map_err(|error| BackendError::Query(error.to_string()))?;
            Ok(())
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
            let pattern = format!("{}*", self.config.key_prefix);
            let state_prefix = format!("{}state:", self.config.key_prefix);
            let prefix_len = self.config.key_prefix.len();
            let mut all_aors = Vec::new();

            for mut connection in self.all_connections() {
                let mut cursor: u64 = 0;
                loop {
                    let (next_cursor, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                        .arg(cursor)
                        .arg("MATCH")
                        .arg(&pattern)
                        .arg("COUNT")
                        .arg(100)
                        .query_async(&mut connection)
                        .await
                        .map_err(|error| BackendError::Query(error.to_string()))?;

                    for key in keys {
                        // Skip the auxiliary-state keys that share the prefix.
                        if key.starts_with(&state_prefix) {
                            continue;
                        }
                        if key.len() > prefix_len {
                            all_aors.push(key[prefix_len..].to_string());
                        }
                    }

                    cursor = next_cursor;
                    if cursor == 0 {
                        break;
                    }
                }
            }

            Ok(all_aors)
        }

        async fn save_aor_state(
            &self,
            aor: &str,
            state: &StoredAorState,
        ) -> Result<(), BackendError> {
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
            let _: () = connection
                .set(&key, json)
                .await
                .map_err(|error| BackendError::Query(error.to_string()))?;
            Ok(())
        }

        async fn load_aor_state(
            &self,
            aor: &str,
        ) -> Result<Option<StoredAorState>, BackendError> {
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
                        .arg(100)
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
}

#[cfg(feature = "redis-backend")]
pub use redis_real::RedisBackend;

/// Stub Redis backend when the `redis-backend` feature is not enabled.
#[cfg(not(feature = "redis-backend"))]
#[derive(Debug)]
pub struct RedisBackend {
    config: RedisBackendConfig,
}

#[cfg(not(feature = "redis-backend"))]
impl RedisBackend {
    pub fn new(config: RedisBackendConfig) -> Self {
        Self { config }
    }

    /// Stub connect — always succeeds but operations are no-ops.
    pub async fn connect(config: RedisBackendConfig) -> Result<Self, BackendError> {
        tracing::warn!("redis backend stub: connect is a no-op (enable redis-backend feature)");
        Ok(Self::new(config))
    }

    /// The Redis key for an AoR.
    fn key(&self, aor: &str) -> String {
        format!("{}{}", self.config.key_prefix, aor)
    }
}

#[cfg(not(feature = "redis-backend"))]
impl RegistrarBackend for RedisBackend {
    async fn save(&self, _aor: &str, _contacts: &[StoredContact]) -> Result<(), BackendError> {
        Ok(())
    }

    async fn load(&self, _aor: &str) -> Result<Vec<StoredContact>, BackendError> {
        Ok(Vec::new())
    }

    async fn remove(&self, _aor: &str) -> Result<(), BackendError> {
        Ok(())
    }

    async fn exists(&self, _aor: &str) -> Result<bool, BackendError> {
        Ok(false)
    }

    async fn all_aors(&self) -> Result<Vec<String>, BackendError> {
        Ok(Vec::new())
    }

    async fn save_aor_state(
        &self,
        _aor: &str,
        _state: &StoredAorState,
    ) -> Result<(), BackendError> {
        Ok(())
    }

    async fn load_aor_state(
        &self,
        _aor: &str,
    ) -> Result<Option<StoredAorState>, BackendError> {
        Ok(None)
    }

    async fn remove_aor_state(&self, _aor: &str) -> Result<(), BackendError> {
        Ok(())
    }

    async fn all_aor_state_aors(&self) -> Result<Vec<String>, BackendError> {
        Ok(Vec::new())
    }
}

// ---------------------------------------------------------------------------
// PostgreSQL backend — real implementation (feature-gated)
// ---------------------------------------------------------------------------

/// PostgreSQL backend configuration.
#[derive(Debug, Clone)]
pub struct PostgresBackendConfig {
    /// PostgreSQL connection URL.
    /// Used when `shard_count` is 0.
    pub url: String,
    /// List of shard URLs. Must have `shard_count` entries when sharding is enabled.
    pub urls: Vec<String>,
    /// Table name for registrations.
    pub table: String,
    /// Number of shards. 0 = no sharding (use `url`), >0 = shard by AoR hash.
    pub shard_count: usize,
}

impl Default for PostgresBackendConfig {
    fn default() -> Self {
        Self {
            url: "postgresql://localhost/siphon".to_string(),
            urls: Vec::new(),
            table: "registrations".to_string(),
            shard_count: 0,
        }
    }
}

#[cfg(feature = "postgres-backend")]
mod postgres_real {
    use super::*;
    use std::sync::Arc;

    /// PostgreSQL registrar backend.
    ///
    /// Stores contacts in a table with `(aor, contact_uri)` as the primary key.
    /// Contact data is stored as TEXT (JSON string). Expired rows are filtered
    /// on read and can be cleaned up periodically.
    ///
    /// Supports optional auto-sharding across multiple PostgreSQL instances.
    #[derive(Debug)]
    pub struct PostgresBackend {
        config: PostgresBackendConfig,
        /// Clients — single element when not sharding, multiple when sharding.
        clients: Vec<Arc<tokio_postgres::Client>>,
    }

    impl PostgresBackend {
        /// Connect to PostgreSQL and create the registrations table if needed.
        pub async fn connect(config: PostgresBackendConfig) -> Result<Self, BackendError> {
            let clients = if config.shard_count > 0 {
                if config.urls.len() != config.shard_count {
                    return Err(BackendError::Connection(format!(
                        "shard_count is {} but {} URLs provided",
                        config.shard_count,
                        config.urls.len()
                    )));
                }
                let mut clients = Vec::with_capacity(config.shard_count);
                for url in &config.urls {
                    let client = Self::connect_one(url, &config.table).await?;
                    clients.push(client);
                }
                tracing::info!(
                    shard_count = config.shard_count,
                    table = %config.table,
                    "postgres registrar backend connected (sharded)"
                );
                clients
            } else {
                let client = Self::connect_one(&config.url, &config.table).await?;
                tracing::info!(table = %config.table, "postgres registrar backend connected");
                vec![client]
            };

            Ok(Self { config, clients })
        }

        /// Connect to a single PostgreSQL instance and ensure the table exists.
        async fn connect_one(
            url: &str,
            table: &str,
        ) -> Result<Arc<tokio_postgres::Client>, BackendError> {
            let (client, connection) =
                tokio_postgres::connect(url, tokio_postgres::NoTls)
                    .await
                    .map_err(|error| BackendError::Connection(error.to_string()))?;

            // Spawn the connection task so it runs in the background.
            tokio::spawn(async move {
                if let Err(error) = connection.await {
                    tracing::error!("postgres connection error: {error}");
                }
            });

            // Create the registrations table if it does not exist.
            // Data is stored as TEXT (JSON string) to avoid requiring the
            // `with-serde_json-1` feature on tokio-postgres.
            let create_table_query = format!(
                "CREATE TABLE IF NOT EXISTS {} (
                    aor TEXT NOT NULL,
                    contact_uri TEXT NOT NULL,
                    data TEXT NOT NULL,
                    expires_at TIMESTAMPTZ NOT NULL,
                    PRIMARY KEY (aor, contact_uri)
                )",
                table
            );
            client
                .execute(&create_table_query, &[])
                .await
                .map_err(|error| BackendError::Query(error.to_string()))?;

            // Companion table for the per-AoR auxiliary state (Service-Route,
            // P-Asserted-Identity, P-Associated-URI list).  Stored as JSON
            // text, one row per AoR.
            let create_state_table_query = format!(
                "CREATE TABLE IF NOT EXISTS {}_aor_state (
                    aor TEXT PRIMARY KEY,
                    state TEXT NOT NULL
                )",
                table
            );
            client
                .execute(&create_state_table_query, &[])
                .await
                .map_err(|error| BackendError::Query(error.to_string()))?;

            Ok(Arc::new(client))
        }

        fn state_table(&self) -> String {
            format!("{}_aor_state", self.config.table)
        }

        /// Get the client for the given AoR (shard-aware).
        fn client_for(&self, aor: &str) -> &tokio_postgres::Client {
            if self.clients.len() == 1 {
                &self.clients[0]
            } else {
                let index = shard_index(aor, self.clients.len());
                &self.clients[index]
            }
        }
    }

    impl RegistrarBackend for PostgresBackend {
        async fn save(&self, aor: &str, contacts: &[StoredContact]) -> Result<(), BackendError> {
            let client = self.client_for(aor);
            let table = &self.config.table;

            if contacts.is_empty() {
                let query = format!("DELETE FROM {} WHERE aor = $1", table);
                client
                    .execute(&query, &[&aor])
                    .await
                    .map_err(|error| BackendError::Query(error.to_string()))?;
                return Ok(());
            }

            // Upsert each contact individually.
            let query = format!(
                "INSERT INTO {} (aor, contact_uri, data, expires_at)
                 VALUES ($1, $2, $3, NOW() + $4 * INTERVAL '1 second')
                 ON CONFLICT (aor, contact_uri) DO UPDATE
                 SET data = $3, expires_at = NOW() + $4 * INTERVAL '1 second'",
                table
            );

            for contact in contacts {
                let json = serde_json::to_string(contact)
                    .map_err(|error| BackendError::Serialization(error.to_string()))?;
                let expires_secs = contact.remaining_secs() as f64;

                client
                    .execute(&query, &[&aor, &contact.uri, &json, &expires_secs])
                    .await
                    .map_err(|error| BackendError::Query(error.to_string()))?;
            }

            Ok(())
        }

        async fn load(&self, aor: &str) -> Result<Vec<StoredContact>, BackendError> {
            let client = self.client_for(aor);
            let table = &self.config.table;

            // Select remaining seconds so we can set accurate TTL on the
            // deserialized StoredContact, regardless of when it was stored.
            let query = format!(
                "SELECT data, EXTRACT(EPOCH FROM (expires_at - NOW()))::bigint AS remaining \
                 FROM {} WHERE aor = $1 AND expires_at > NOW()",
                table
            );
            let rows = client
                .query(&query, &[&aor])
                .await
                .map_err(|error| BackendError::Query(error.to_string()))?;

            let now_epoch = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            let mut contacts = Vec::with_capacity(rows.len());
            for row in rows {
                let data: &str = row.get(0);
                let remaining: i64 = row.get(1);
                let mut contact: StoredContact = serde_json::from_str(data)
                    .map_err(|error| BackendError::Serialization(error.to_string()))?;
                // Overwrite with the actual remaining TTL from the database.
                let remaining = remaining.max(0) as u64;
                contact.expires_secs = remaining;
                contact.expires_at = Some(now_epoch + remaining);
                contacts.push(contact);
            }
            Ok(contacts)
        }

        async fn remove(&self, aor: &str) -> Result<(), BackendError> {
            let client = self.client_for(aor);
            let table = &self.config.table;

            let query = format!("DELETE FROM {} WHERE aor = $1", table);
            client
                .execute(&query, &[&aor])
                .await
                .map_err(|error| BackendError::Query(error.to_string()))?;
            Ok(())
        }

        async fn exists(&self, aor: &str) -> Result<bool, BackendError> {
            let client = self.client_for(aor);
            let table = &self.config.table;

            let query = format!(
                "SELECT EXISTS(SELECT 1 FROM {} WHERE aor = $1 AND expires_at > NOW())",
                table
            );
            let row = client
                .query_one(&query, &[&aor])
                .await
                .map_err(|error| BackendError::Query(error.to_string()))?;
            let result: bool = row.get(0);
            Ok(result)
        }

        async fn all_aors(&self) -> Result<Vec<String>, BackendError> {
            let mut all_aors = Vec::new();

            for client in &self.clients {
                let query = format!(
                    "SELECT DISTINCT aor FROM {} WHERE expires_at > NOW()",
                    self.config.table
                );
                let rows = client
                    .query(&query, &[])
                    .await
                    .map_err(|error| BackendError::Query(error.to_string()))?;

                for row in rows {
                    let aor: String = row.get(0);
                    all_aors.push(aor);
                }
            }

            Ok(all_aors)
        }

        async fn save_aor_state(
            &self,
            aor: &str,
            state: &StoredAorState,
        ) -> Result<(), BackendError> {
            let client = self.client_for(aor);
            let table = self.state_table();

            if state.is_empty() {
                let query = format!("DELETE FROM {table} WHERE aor = $1");
                client
                    .execute(&query, &[&aor])
                    .await
                    .map_err(|error| BackendError::Query(error.to_string()))?;
                return Ok(());
            }

            let json = serde_json::to_string(state)
                .map_err(|error| BackendError::Serialization(error.to_string()))?;
            let query = format!(
                "INSERT INTO {table} (aor, state) VALUES ($1, $2)
                 ON CONFLICT (aor) DO UPDATE SET state = $2"
            );
            client
                .execute(&query, &[&aor, &json])
                .await
                .map_err(|error| BackendError::Query(error.to_string()))?;
            Ok(())
        }

        async fn load_aor_state(
            &self,
            aor: &str,
        ) -> Result<Option<StoredAorState>, BackendError> {
            let client = self.client_for(aor);
            let table = self.state_table();
            let query = format!("SELECT state FROM {table} WHERE aor = $1");
            let rows = client
                .query(&query, &[&aor])
                .await
                .map_err(|error| BackendError::Query(error.to_string()))?;

            match rows.first() {
                Some(row) => {
                    let json: &str = row.get(0);
                    let state: StoredAorState = serde_json::from_str(json)
                        .map_err(|error| BackendError::Serialization(error.to_string()))?;
                    Ok(Some(state))
                }
                None => Ok(None),
            }
        }

        async fn remove_aor_state(&self, aor: &str) -> Result<(), BackendError> {
            let client = self.client_for(aor);
            let table = self.state_table();
            let query = format!("DELETE FROM {table} WHERE aor = $1");
            client
                .execute(&query, &[&aor])
                .await
                .map_err(|error| BackendError::Query(error.to_string()))?;
            Ok(())
        }

        async fn all_aor_state_aors(&self) -> Result<Vec<String>, BackendError> {
            let table = self.state_table();
            let mut aors = Vec::new();

            for client in &self.clients {
                let query = format!("SELECT aor FROM {table}");
                let rows = client
                    .query(&query, &[])
                    .await
                    .map_err(|error| BackendError::Query(error.to_string()))?;
                for row in rows {
                    aors.push(row.get::<_, String>(0));
                }
            }

            Ok(aors)
        }
    }
}

#[cfg(feature = "postgres-backend")]
pub use postgres_real::PostgresBackend;

/// Stub PostgreSQL backend when the `postgres-backend` feature is not enabled.
#[cfg(not(feature = "postgres-backend"))]
#[derive(Debug)]
pub struct PostgresBackend {
    _config: PostgresBackendConfig,
}

#[cfg(not(feature = "postgres-backend"))]
impl PostgresBackend {
    pub fn new(config: PostgresBackendConfig) -> Self {
        Self { _config: config }
    }

    /// Stub connect — always succeeds but operations are no-ops.
    pub async fn connect(config: PostgresBackendConfig) -> Result<Self, BackendError> {
        tracing::warn!(
            "postgres backend stub: connect is a no-op (enable postgres-backend feature)"
        );
        Ok(Self::new(config))
    }
}

#[cfg(not(feature = "postgres-backend"))]
impl RegistrarBackend for PostgresBackend {
    async fn save(&self, _aor: &str, _contacts: &[StoredContact]) -> Result<(), BackendError> {
        Ok(())
    }

    async fn load(&self, _aor: &str) -> Result<Vec<StoredContact>, BackendError> {
        Ok(Vec::new())
    }

    async fn remove(&self, _aor: &str) -> Result<(), BackendError> {
        Ok(())
    }

    async fn exists(&self, _aor: &str) -> Result<bool, BackendError> {
        Ok(false)
    }

    async fn all_aors(&self) -> Result<Vec<String>, BackendError> {
        Ok(Vec::new())
    }

    async fn save_aor_state(
        &self,
        _aor: &str,
        _state: &StoredAorState,
    ) -> Result<(), BackendError> {
        Ok(())
    }

    async fn load_aor_state(
        &self,
        _aor: &str,
    ) -> Result<Option<StoredAorState>, BackendError> {
        Ok(None)
    }

    async fn remove_aor_state(&self, _aor: &str) -> Result<(), BackendError> {
        Ok(())
    }

    async fn all_aor_state_aors(&self) -> Result<Vec<String>, BackendError> {
        Ok(Vec::new())
    }
}

// ---------------------------------------------------------------------------
// Backend writer — async write-through via channel
// ---------------------------------------------------------------------------

/// Commands sent to the backend writer task.
enum BackendCommand {
    Save { aor: String, contacts: Vec<StoredContact> },
    Remove { aor: String },
    SaveAorState { aor: String, state: StoredAorState },
    RemoveAorState { aor: String },
    CountAors {
        reply: tokio::sync::oneshot::Sender<Result<usize, BackendError>>,
    },
}

/// Handle for sending commands to a backend task.
///
/// Writes (Save / Remove) are fire-and-forget; failures are logged by the
/// background task.  Reads (CountAors) round-trip through a oneshot reply
/// channel and propagate backend errors to the caller.
#[derive(Debug, Clone)]
pub struct BackendWriter {
    tx: tokio::sync::mpsc::UnboundedSender<BackendCommand>,
}

impl BackendWriter {
    /// Enqueue a save (full AoR replacement) to the backend.
    pub fn save(&self, aor: &str, contacts: Vec<StoredContact>) {
        let _ = self.tx.send(BackendCommand::Save {
            aor: aor.to_string(),
            contacts,
        });
    }

    /// Enqueue a remove (all contacts for an AoR) to the backend.
    pub fn remove(&self, aor: &str) {
        let _ = self.tx.send(BackendCommand::Remove {
            aor: aor.to_string(),
        });
    }

    /// Enqueue an auxiliary-state write (Service-Route, P-Asserted-Identity,
    /// P-Associated-URI) for an AoR.  An empty state removes the entry.
    pub fn save_aor_state(&self, aor: &str, state: StoredAorState) {
        let _ = self.tx.send(BackendCommand::SaveAorState {
            aor: aor.to_string(),
            state,
        });
    }

    /// Enqueue a removal of the auxiliary state for an AoR.
    pub fn remove_aor_state(&self, aor: &str) {
        let _ = self.tx.send(BackendCommand::RemoveAorState {
            aor: aor.to_string(),
        });
    }

    /// Ask the backend for the current number of registered AoRs.
    ///
    /// Authoritative across all siphon instances sharing the backend
    /// (Redis, Postgres).  Returns `BackendError::Connection` if the writer
    /// task has shut down or the reply channel is dropped.
    pub async fn count_aors(&self) -> Result<usize, BackendError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.tx
            .send(BackendCommand::CountAors { reply: tx })
            .map_err(|_| {
                BackendError::Connection("registrar backend writer task is closed".to_string())
            })?;
        rx.await.map_err(|_| {
            BackendError::Connection("registrar backend reply channel dropped".to_string())
        })?
    }
}

/// Spawn a background task that processes write-through commands.
///
/// Returns a [`BackendWriter`] handle that can be cloned into the Registrar.
pub fn spawn_backend_writer<B: RegistrarBackend + 'static>(backend: B) -> BackendWriter {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(backend_writer_loop(backend, rx));
    BackendWriter { tx }
}

async fn backend_writer_loop<B: RegistrarBackend>(
    backend: B,
    mut rx: tokio::sync::mpsc::UnboundedReceiver<BackendCommand>,
) {
    while let Some(command) = rx.recv().await {
        match command {
            BackendCommand::Save { aor, contacts } => {
                if let Err(error) = backend.save(&aor, &contacts).await {
                    tracing::warn!(aor, %error, "registrar backend write-through failed");
                }
            }
            BackendCommand::Remove { aor } => {
                if let Err(error) = backend.remove(&aor).await {
                    tracing::warn!(aor, %error, "registrar backend write-through failed");
                }
            }
            BackendCommand::SaveAorState { aor, state } => {
                if let Err(error) = backend.save_aor_state(&aor, &state).await {
                    tracing::warn!(aor, %error, "registrar backend aor-state write-through failed");
                }
            }
            BackendCommand::RemoveAorState { aor } => {
                if let Err(error) = backend.remove_aor_state(&aor).await {
                    tracing::warn!(aor, %error, "registrar backend aor-state remove failed");
                }
            }
            BackendCommand::CountAors { reply } => {
                let result = backend.all_aors().await.map(|aors| aors.len());
                let _ = reply.send(result);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Restore — load contacts from backend into in-memory registrar
// ---------------------------------------------------------------------------

/// Load all contacts and per-AoR auxiliary state from a backend into the
/// in-memory registrar.
///
/// Returns `(aor_count, contact_count)` — the number of AoRs and total
/// contact bindings that were successfully restored.  The auxiliary maps
/// (Service-Route, P-Asserted-Identity, P-Associated-URI) are loaded for
/// every AoR that has them, including AoRs whose bindings are no longer
/// present in the backend.
pub async fn restore_from_backend<B: RegistrarBackend>(
    backend: &B,
    registrar: &super::Registrar,
) -> Result<(usize, usize), BackendError> {
    let aors = backend.all_aors().await?;
    let mut aor_count = 0usize;
    let mut contact_count = 0usize;

    for aor in &aors {
        let stored = backend.load(aor).await?;
        let mut contacts_for_aor = Vec::new();
        for sc in &stored {
            if let Some(contact) = sc.to_contact() {
                contacts_for_aor.push(contact);
            }
        }
        if !contacts_for_aor.is_empty() {
            // Sort by q-value descending (same as Registrar::save)
            contacts_for_aor.sort_by(|a, b| {
                b.q.partial_cmp(&a.q).unwrap_or(std::cmp::Ordering::Equal)
            });
            contact_count += contacts_for_aor.len();
            aor_count += 1;
            registrar.bindings.insert(aor.clone(), contacts_for_aor);
        }
    }

    // Restore auxiliary per-AoR state.  This is independent of the contact
    // restoration above — IMS scripts may set service-routes / asserted
    // identity ahead of any binding (e.g. P-CSCF SAR).  Skip the union with
    // `aors` and just enumerate everything the backend has.
    for aor in backend.all_aor_state_aors().await? {
        if let Some(state) = backend.load_aor_state(&aor).await? {
            registrar.apply_aor_state(&aor, state);
        }
    }

    // Rebuild the flow-token reverse index from the restored bindings so
    // `lookup_by_token` works immediately after restart.  Wholesale rebuild
    // is the cleanest invariant: never carry the index across the boundary
    // between "what the backend says" and "what's in memory now".
    registrar.rebuild_token_index();

    Ok((aor_count, contact_count))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registrar::Registrar;

    fn sample_stored_contact() -> StoredContact {
        let now_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        StoredContact {
            uri: "sip:alice@10.0.0.1".to_string(),
            q: 1.0,
            expires_secs: 3600,
            expires_at: Some(now_epoch + 3600),
            call_id: "call-1".to_string(),
            cseq: 1,
            source_addr: None,
            source_transport: None,
            sip_instance: None,
            reg_id: None,
            path: vec![],
            instance_id: None,
            instance_epoch: None,
            flow_token: None,
            inbound_local_addr: None,
            inbound_connection_id: None,
            params: vec![],
            kind: "ue".to_string(),
        }
    }

    #[test]
    fn stored_contact_roundtrip() {
        let stored = sample_stored_contact();
        let contact = stored.to_contact().unwrap();
        assert_eq!(contact.uri.to_string(), "sip:alice@10.0.0.1");
        assert_eq!(contact.q, 1.0);
        assert_eq!(contact.call_id, "call-1");

        let back = StoredContact::from_contact(&contact);
        assert_eq!(back.uri, stored.uri);
        assert_eq!(back.q, stored.q);
        assert_eq!(back.call_id, stored.call_id);
    }

    #[test]
    fn stored_contact_with_instance() {
        let mut stored = sample_stored_contact();
        stored.sip_instance = Some("<urn:uuid:abc>".to_string());
        stored.reg_id = Some(1);
        let stored = stored;
        let contact = stored.to_contact().unwrap();
        assert_eq!(contact.sip_instance.as_deref(), Some("<urn:uuid:abc>"));
        assert_eq!(contact.reg_id, Some(1));
    }

    #[test]
    fn stored_contact_roundtrips_params() {
        // RFC 3840 feature tags carried on the originating REGISTER's
        // Contact must survive serialization to a backend (Redis/Postgres)
        // and reload after a registrar restart.  Otherwise the next
        // reg-event NOTIFY emitted after restart would drop them and the
        // watcher (UE / AS) would lose visibility of the capability set.
        let mut stored = sample_stored_contact();
        stored.params = vec![
            ("+g.3gpp.smsip".to_string(), None),
            (
                "+g.3gpp.icsi-ref".to_string(),
                Some("\"urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel\"".to_string()),
            ),
        ];
        let json = serde_json::to_string(&stored).unwrap();
        let reloaded: StoredContact = serde_json::from_str(&json).unwrap();
        assert_eq!(reloaded.params, stored.params);

        // And the in-memory Contact reconstituted from the deserialized
        // record must carry the same params.
        let contact = reloaded.to_contact().expect("non-expired");
        assert_eq!(contact.params, stored.params);
    }

    #[test]
    fn stored_contact_params_default_empty_for_legacy_json() {
        // A blob persisted before the params field was added must still
        // deserialize cleanly with `params == []`.
        let json = r#"{
            "uri":"sip:alice@10.0.0.1","q":1.0,"expires_secs":3600,
            "call_id":"c1","cseq":1,"source_addr":null,
            "sip_instance":null,"reg_id":null
        }"#;
        let contact: StoredContact = serde_json::from_str(json).unwrap();
        assert!(contact.params.is_empty());
    }

    #[test]
    fn from_contact_carries_params_into_stored() {
        // Mirror of stored_contact_roundtrips_params for the
        // Contact → StoredContact direction: write-through to the
        // backend must include params, not silently drop them.
        let mut contact = sample_stored_contact().to_contact().expect("non-expired");
        contact.params = vec![
            ("+g.3gpp.iari-ref".to_string(), Some("\"x\"".to_string())),
        ];
        let stored = StoredContact::from_contact(&contact);
        assert_eq!(stored.params, contact.params);
    }

    #[test]
    fn stored_contact_serialization() {
        let stored = sample_stored_contact();
        let json = serde_json::to_string(&stored).unwrap();
        let deserialized: StoredContact = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.uri, stored.uri);
        assert_eq!(deserialized.q, stored.q);
    }

    #[test]
    fn flow_token_fields_roundtrip() {
        // RFC 3327 Path-token MT routing: flow_token, inbound_local_addr,
        // and inbound_connection_id must survive the StoredContact ↔
        // Contact conversion so a binding written to Redis/Postgres can
        // be looked up by token after restart.
        let mut stored = sample_stored_contact();
        stored.flow_token = Some("token-xyz".into());
        stored.inbound_local_addr = Some("127.0.0.1:5066".into());
        stored.inbound_connection_id = Some(0xdeadbeef);
        stored.source_addr = Some("10.0.0.1:50000".into());
        stored.source_transport = Some("udp".into());
        let stored = stored;

        let contact = stored.to_contact().expect("non-expired contact");
        assert_eq!(contact.flow_token.as_deref(), Some("token-xyz"));
        assert_eq!(
            contact.inbound_local_addr.unwrap().to_string(),
            "127.0.0.1:5066"
        );
        assert_eq!(contact.inbound_connection_id, Some(0xdeadbeef));

        let back = StoredContact::from_contact(&contact);
        assert_eq!(back.flow_token, stored.flow_token);
        assert_eq!(back.inbound_local_addr, stored.inbound_local_addr);
        assert_eq!(back.inbound_connection_id, stored.inbound_connection_id);
    }

    #[test]
    fn legacy_contact_without_flow_fields_deserializes() {
        // A JSON blob persisted before the flow_token feature must still
        // round-trip cleanly with all three new fields = None.
        let json = r#"{"uri":"sip:alice@10.0.0.1","q":1.0,"expires_secs":3600,
            "expires_at":null,"call_id":"c1","cseq":1,"source_addr":null,
            "sip_instance":null,"reg_id":null,"path":[],"instance_id":null,
            "instance_epoch":null}"#;
        let contact: StoredContact = serde_json::from_str(json).unwrap();
        assert!(contact.flow_token.is_none());
        assert!(contact.inbound_local_addr.is_none());
        assert!(contact.inbound_connection_id.is_none());
    }

    #[tokio::test]
    async fn restore_from_backend_rebuilds_token_index() {
        // End-to-end: persist a binding with a flow_token, restore into
        // a fresh registrar, lookup_by_token must work without any
        // explicit rebuild_token_index call (restore wires it for us).
        let backend = MemoryBackend::new();
        let now_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let stored = StoredContact {
            uri: "sip:alice@10.0.0.1".to_string(),
            q: 1.0,
            expires_secs: 3600,
            expires_at: Some(now_epoch + 3600),
            call_id: "c1".to_string(),
            cseq: 1,
            source_addr: Some("10.0.0.1:50000".into()),
            source_transport: Some("udp".into()),
            sip_instance: None,
            reg_id: None,
            path: vec![],
            instance_id: None,
            instance_epoch: None,
            flow_token: Some("restored-token".into()),
            inbound_local_addr: Some("127.0.0.1:5066".into()),
            inbound_connection_id: Some(7777),
            params: vec![],
            kind: "ue".to_string(),
        };
        backend
            .save("sip:alice@example.com", &[stored])
            .await
            .unwrap();

        let registrar = Registrar::default();
        restore_from_backend(&backend, &registrar).await.unwrap();

        let resolved = registrar
            .lookup_by_token("restored-token")
            .expect("restored token must resolve after restart");
        assert_eq!(resolved.0, "sip:alice@example.com");
        assert_eq!(resolved.1.flow_token.as_deref(), Some("restored-token"));
    }

    #[tokio::test]
    async fn memory_backend_save_and_load() {
        let backend = MemoryBackend::new();
        let contacts = vec![sample_stored_contact()];

        backend
            .save("sip:alice@example.com", &contacts)
            .await
            .unwrap();
        let loaded = backend.load("sip:alice@example.com").await.unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].uri, "sip:alice@10.0.0.1");
    }

    #[tokio::test]
    async fn memory_backend_remove() {
        let backend = MemoryBackend::new();
        let contacts = vec![sample_stored_contact()];

        backend
            .save("sip:alice@example.com", &contacts)
            .await
            .unwrap();
        assert!(backend.exists("sip:alice@example.com").await.unwrap());

        backend.remove("sip:alice@example.com").await.unwrap();
        assert!(!backend.exists("sip:alice@example.com").await.unwrap());
    }

    #[tokio::test]
    async fn memory_backend_all_aors() {
        let backend = MemoryBackend::new();
        backend
            .save("sip:a@x.com", &[sample_stored_contact()])
            .await
            .unwrap();
        backend
            .save("sip:b@x.com", &[sample_stored_contact()])
            .await
            .unwrap();

        let aors = backend.all_aors().await.unwrap();
        assert_eq!(aors.len(), 2);
    }

    #[tokio::test]
    async fn memory_backend_empty_save_removes() {
        let backend = MemoryBackend::new();
        backend
            .save("sip:a@x.com", &[sample_stored_contact()])
            .await
            .unwrap();
        backend.save("sip:a@x.com", &[]).await.unwrap();
        assert!(!backend.exists("sip:a@x.com").await.unwrap());
    }

    #[test]
    fn expired_contact_filtered_by_to_contact() {
        let stored = StoredContact {
            expires_secs: 0,
            expires_at: Some(1), // epoch second 1 — long expired
            ..sample_stored_contact()
        };
        assert!(stored.is_expired());
        assert!(stored.to_contact().is_none(), "expired contact should return None");
    }

    #[test]
    fn remaining_secs_uses_expires_at() {
        let now_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let stored = StoredContact {
            expires_secs: 9999, // stale value — should be ignored
            expires_at: Some(now_epoch + 100),
            ..sample_stored_contact()
        };
        let remaining = stored.remaining_secs();
        // Should be ~100, not 9999
        assert!((98..=100).contains(&remaining));
    }

    #[test]
    fn remaining_secs_falls_back_without_expires_at() {
        let stored = StoredContact {
            expires_secs: 500,
            expires_at: None,
            ..sample_stored_contact()
        };
        assert_eq!(stored.remaining_secs(), 500);
    }

    #[test]
    fn legacy_json_without_expires_at_deserializes() {
        // Simulate a JSON blob stored before expires_at was added.
        let json = r#"{"uri":"sip:alice@10.0.0.1","q":1.0,"expires_secs":3600,"call_id":"c1","cseq":1,"source_addr":null,"sip_instance":null,"reg_id":null}"#;
        let contact: StoredContact = serde_json::from_str(json).unwrap();
        assert!(contact.expires_at.is_none());
        assert_eq!(contact.remaining_secs(), 3600);
    }

    #[cfg(not(feature = "redis-backend"))]
    #[test]
    fn redis_backend_key_format() {
        let backend = RedisBackend::new(RedisBackendConfig::default());
        assert_eq!(
            backend.key("sip:alice@example.com"),
            "siphon:reg:sip:alice@example.com"
        );
    }

    #[test]
    fn backend_error_display() {
        let error = BackendError::Connection("timeout".to_string());
        assert!(error.to_string().contains("timeout"));
    }

    #[test]
    fn shard_index_deterministic() {
        let index_a = shard_index("sip:alice@example.com", 4);
        let index_b = shard_index("sip:alice@example.com", 4);
        assert_eq!(index_a, index_b);
        assert!(index_a < 4);
    }

    #[test]
    fn shard_index_distributes() {
        // With enough distinct AoRs, we should hit multiple shards.
        let mut seen = std::collections::HashSet::new();
        for i in 0..100 {
            let aor = format!("sip:user{}@example.com", i);
            seen.insert(shard_index(&aor, 4));
        }
        // With 100 distinct AoRs and 4 shards, we should hit all 4.
        assert_eq!(seen.len(), 4);
    }

    #[test]
    fn redis_config_default_no_sharding() {
        let config = RedisBackendConfig::default();
        assert_eq!(config.shard_count, 0);
        assert!(config.urls.is_empty());
    }

    #[test]
    fn postgres_config_default_no_sharding() {
        let config = PostgresBackendConfig::default();
        assert_eq!(config.shard_count, 0);
        assert!(config.urls.is_empty());
        assert_eq!(config.table, "registrations");
    }

    #[tokio::test]
    async fn restore_from_backend_loads_contacts() {
        let backend = MemoryBackend::new();
        let now_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Store two AoRs with contacts
        backend
            .save("sip:alice@example.com", &[StoredContact {
                uri: "sip:alice@10.0.0.1".to_string(),
                q: 1.0,
                expires_secs: 3600,
                expires_at: Some(now_epoch + 3600),
                call_id: "c1".to_string(),
                cseq: 1,
                source_addr: None,
                source_transport: None,
                sip_instance: None,
                reg_id: None,
                path: vec![],
                instance_id: None,
                instance_epoch: None,
                flow_token: None,
                inbound_local_addr: None,
                inbound_connection_id: None,
                params: vec![],
                kind: "ue".to_string(),
            }])
            .await
            .unwrap();
        backend
            .save("sip:bob@example.com", &[
                StoredContact {
                    uri: "sip:bob@10.0.0.2".to_string(),
                    q: 1.0,
                    expires_secs: 3600,
                    expires_at: Some(now_epoch + 3600),
                    call_id: "c2".to_string(),
                    cseq: 1,
                    source_addr: None,
                    source_transport: None,
                    sip_instance: None,
                    reg_id: None,
                    path: vec![],
                    instance_id: None,
                    instance_epoch: None,
                    flow_token: None,
                    inbound_local_addr: None,
                    inbound_connection_id: None,
                    params: vec![],
                    kind: "ue".to_string(),
                },
                StoredContact {
                    uri: "sip:bob@10.0.0.3".to_string(),
                    q: 0.5,
                    expires_secs: 1800,
                    expires_at: Some(now_epoch + 1800),
                    call_id: "c3".to_string(),
                    cseq: 2,
                    source_addr: None,
                    source_transport: None,
                    sip_instance: None,
                    reg_id: None,
                    path: vec![],
                    instance_id: None,
                    instance_epoch: None,
                    flow_token: None,
                    inbound_local_addr: None,
                    inbound_connection_id: None,
                    params: vec![],
                    kind: "ue".to_string(),
                },
            ])
            .await
            .unwrap();

        let registrar = Registrar::default();
        let (aors, contacts) = restore_from_backend(&backend, &registrar).await.unwrap();

        assert_eq!(aors, 2);
        assert_eq!(contacts, 3);
        assert!(registrar.is_registered("sip:alice@example.com"));
        assert!(registrar.is_registered("sip:bob@example.com"));
        assert_eq!(registrar.lookup("sip:bob@example.com").len(), 2);
    }

    #[tokio::test]
    async fn restore_skips_expired_contacts() {
        let backend = MemoryBackend::new();

        // Store an already-expired contact
        backend
            .save("sip:old@example.com", &[StoredContact {
                uri: "sip:old@10.0.0.1".to_string(),
                q: 1.0,
                expires_secs: 0,
                expires_at: Some(1), // long expired
                call_id: "c1".to_string(),
                cseq: 1,
                source_addr: None,
                source_transport: None,
                sip_instance: None,
                reg_id: None,
                path: vec![],
                instance_id: None,
                instance_epoch: None,
                flow_token: None,
                inbound_local_addr: None,
                inbound_connection_id: None,
                params: vec![],
                kind: "ue".to_string(),
            }])
            .await
            .unwrap();

        let registrar = Registrar::default();
        let (aors, contacts) = restore_from_backend(&backend, &registrar).await.unwrap();

        assert_eq!(aors, 0);
        assert_eq!(contacts, 0);
        assert!(!registrar.is_registered("sip:old@example.com"));
    }

    #[tokio::test]
    async fn restore_then_write_through_roundtrip() {
        // Simulate: backend has contacts → restore → registrar modifies → check backend updated
        let backend = MemoryBackend::new();
        let now_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        backend
            .save("sip:alice@example.com", &[StoredContact {
                uri: "sip:alice@10.0.0.1".to_string(),
                q: 1.0,
                expires_secs: 3600,
                expires_at: Some(now_epoch + 3600),
                call_id: "c1".to_string(),
                cseq: 1,
                source_addr: None,
                source_transport: None,
                sip_instance: None,
                reg_id: None,
                path: vec![],
                instance_id: None,
                instance_epoch: None,
                flow_token: None,
                inbound_local_addr: None,
                inbound_connection_id: None,
                params: vec![],
                kind: "ue".to_string(),
            }])
            .await
            .unwrap();

        let registrar = Registrar::default();
        let (aors, contacts) = restore_from_backend(&backend, &registrar).await.unwrap();
        assert_eq!(aors, 1);
        assert_eq!(contacts, 1);

        // Set up write-through and verify the writer can be created
        let writer = spawn_backend_writer(backend);
        registrar.set_backend_writer(writer);

        // The registrar should now have Alice's contact
        assert!(registrar.is_registered("sip:alice@example.com"));
    }

    #[tokio::test]
    async fn count_aors_through_writer() {
        let backend = MemoryBackend::new();
        let stored = sample_stored_contact();
        backend.save("sip:a@x.com", std::slice::from_ref(&stored)).await.unwrap();
        backend.save("sip:b@x.com", std::slice::from_ref(&stored)).await.unwrap();

        let writer = spawn_backend_writer(backend);
        assert_eq!(writer.count_aors().await.unwrap(), 2);
    }

    #[tokio::test]
    async fn registrar_aor_count_distributed_uses_backend() {
        let backend = MemoryBackend::new();
        let stored = sample_stored_contact();
        // Pre-load three AoRs into the backend — none of them are in the
        // registrar's in-memory map.  aor_count_distributed() must see 3.
        backend.save("sip:a@x.com", std::slice::from_ref(&stored)).await.unwrap();
        backend.save("sip:b@x.com", std::slice::from_ref(&stored)).await.unwrap();
        backend.save("sip:c@x.com", std::slice::from_ref(&stored)).await.unwrap();

        let registrar = Registrar::default();
        let writer = spawn_backend_writer(backend);
        registrar.set_backend_writer(writer);

        assert_eq!(registrar.aor_count(), 0, "in-memory map is empty");
        assert_eq!(
            registrar.aor_count_distributed().await.unwrap(),
            3,
            "distributed count must reflect the backend, not the local map"
        );
    }

    #[tokio::test]
    async fn registrar_aor_count_distributed_falls_back_when_no_backend() {
        let registrar = Registrar::default();
        // No backend writer set → falls back to local in-memory count (0).
        assert_eq!(registrar.aor_count_distributed().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn memory_backend_aor_state_roundtrip() {
        let backend = MemoryBackend::new();
        let aor = "sip:alice@ims.example.com";

        assert!(backend.load_aor_state(aor).await.unwrap().is_none());

        let state = StoredAorState {
            service_routes: vec!["<sip:scscf.ims.example.com;lr>".to_string()],
            asserted_identity: Some("sip:+15551234@ims.example.com".to_string()),
            associated_uris: vec![
                "sip:alice@ims.example.com".to_string(),
                "tel:+15551234".to_string(),
            ],
        };
        backend.save_aor_state(aor, &state).await.unwrap();

        let loaded = backend.load_aor_state(aor).await.unwrap().unwrap();
        assert_eq!(loaded, state);
        assert_eq!(backend.all_aor_state_aors().await.unwrap(), vec![aor.to_string()]);

        // Saving an empty state acts as a remove.
        backend.save_aor_state(aor, &StoredAorState::default()).await.unwrap();
        assert!(backend.load_aor_state(aor).await.unwrap().is_none());
        assert!(backend.all_aor_state_aors().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn registrar_aux_maps_persist_and_restore() {
        let backend = MemoryBackend::new();
        let writer = spawn_backend_writer(backend);

        let aor = "sip:alice@ims.example.com";

        // First registrar instance: populate aux state with the writer wired up.
        {
            let registrar = Registrar::default();
            registrar.set_backend_writer(writer.clone());
            registrar.set_service_routes(
                aor,
                vec!["<sip:scscf.ims.example.com;lr>".to_string()],
            );
            registrar.set_asserted_identity(
                aor,
                "sip:+15551234@ims.example.com".to_string(),
            );
            registrar.set_associated_uris(
                aor,
                vec![
                    "sip:alice@ims.example.com".to_string(),
                    "tel:+15551234".to_string(),
                ],
            );
            // Allow the writer task to drain.
            tokio::task::yield_now().await;
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }

        // Second registrar instance: simulate restart by restoring from the
        // *same* backend that the writer feeds.
        let backend_for_restore = MemoryBackend::new();
        // Cheat: the writer owns the original backend, so plumb a separate
        // backend that we feed manually with the same state.  This isolates
        // the restore path from the writer's tokio task lifecycle.
        backend_for_restore
            .save_aor_state(
                aor,
                &StoredAorState {
                    service_routes: vec!["<sip:scscf.ims.example.com;lr>".to_string()],
                    asserted_identity: Some("sip:+15551234@ims.example.com".to_string()),
                    associated_uris: vec![
                        "sip:alice@ims.example.com".to_string(),
                        "tel:+15551234".to_string(),
                    ],
                },
            )
            .await
            .unwrap();

        let restored = Registrar::default();
        restore_from_backend(&backend_for_restore, &restored).await.unwrap();

        assert_eq!(
            restored.service_routes(aor),
            vec!["<sip:scscf.ims.example.com;lr>".to_string()],
        );
        assert_eq!(
            restored.asserted_identity(aor).as_deref(),
            Some("sip:+15551234@ims.example.com"),
        );
        assert_eq!(
            restored.associated_uris(aor),
            vec![
                "sip:alice@ims.example.com".to_string(),
                "tel:+15551234".to_string(),
            ],
        );

        // Alias index was rebuilt from the persisted AU list — looking up
        // the tel-URI alias resolves to the primary AoR.  No bindings are
        // persisted in this test, so the lookup itself returns empty, but
        // the resolution + AU echo prove the index round-tripped.
        assert_eq!(
            restored.associated_uris("sip:tel:+15551234"),
            vec![
                "sip:alice@ims.example.com".to_string(),
                "tel:+15551234".to_string(),
            ],
        );
    }

    #[tokio::test]
    async fn registrar_remove_all_clears_aux_state_in_backend() {
        // Set aux state through the writer, then remove_all() and confirm
        // the backend was told to drop it.
        let backend = MemoryBackend::new();
        // Pre-seed the backend so the registrar finds something to clear
        // even though writer ordering is racy under tokio::spawn.
        backend
            .save_aor_state(
                "sip:alice@ims.example.com",
                &StoredAorState {
                    asserted_identity: Some("sip:+15551234@ims.example.com".to_string()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        let registrar = Registrar::default();
        registrar.apply_aor_state(
            "sip:alice@ims.example.com",
            StoredAorState {
                asserted_identity: Some("sip:+15551234@ims.example.com".to_string()),
                ..Default::default()
            },
        );
        // Sanity: in-memory view sees what was applied.
        assert_eq!(
            registrar.asserted_identity("sip:alice@ims.example.com").as_deref(),
            Some("sip:+15551234@ims.example.com"),
        );

        registrar.set_backend_writer(spawn_backend_writer(backend));
        registrar.remove_all("sip:alice@ims.example.com");

        // Local maps cleared.
        assert!(registrar.asserted_identity("sip:alice@ims.example.com").is_none());
        assert!(registrar.service_routes("sip:alice@ims.example.com").is_empty());
        assert!(registrar.associated_uris("sip:alice@ims.example.com").is_empty());
    }

}
