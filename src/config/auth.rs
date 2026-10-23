//! `auth:` digest authentication and its credential backends.

use super::DiameterCxConfig;
use serde::Deserialize;

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct AuthConfig {
    #[serde(default = "default_realm")]
    pub realm: String,
    #[serde(default = "default_auth_backend")]
    pub backend: AuthBackendType,
    #[serde(default)]
    pub users: std::collections::HashMap<String, String>,
    /// AKA credentials for IMS authentication (Milenage key derivation).
    /// Key is the IMPI (e.g. "001010000000001@ims.test").
    #[serde(default)]
    pub aka_credentials: std::collections::HashMap<String, AkaCredential>,
    pub http: Option<HttpAuthConfig>,
    /// SQL credential source for `backend: database`.
    pub database: Option<DatabaseAuthConfig>,
    pub diameter: Option<DiameterCxConfig>,
    /// Shared secret for stateless digest-nonce HMAC integrity (RFC 7616 §3.3).
    /// When set, a digest response carrying a nonce the cluster never issued is
    /// rejected. MUST be identical on every instance behind the same SIP domain
    /// (round-robin DNS). When unset, nonces are timestamp-only — still bounding
    /// replay to `nonce_ttl_secs`, and safe across instances with no shared state.
    #[serde(default)]
    pub nonce_secret: Option<String>,
    /// Digest-nonce lifetime in seconds (replay window). Default 3600.
    #[serde(default)]
    pub nonce_ttl_secs: Option<u64>,
    /// Digest algorithms to offer on a 401/407, most preferred first
    /// (RFC 7616 §3.7). One `WWW-Authenticate` / `Proxy-Authenticate` header is
    /// emitted per entry, in this order.
    ///
    /// Defaults to `["MD5", "SHA-256", "SHA-512-256"]`, which is what siphon has
    /// always sent: a single challenge set covering RFC 2617 and RFC 7616
    /// clients. Narrow it for a client population that cannot take a
    /// multi-challenge 401 — some do abandon the registration outright rather
    /// than picking one, whatever the order — at the cost of the algorithms you
    /// drop.
    ///
    /// Validated at config load: an unknown name is refused rather than skipped,
    /// because a silently dropped entry is a challenge set the operator did not
    /// choose. `AKAv1-MD5` is refused too — it is network-selected and reached
    /// through `auth.require_aka_digest()` / `require_ims_digest()`, not this
    /// list.
    #[serde(default = "default_digest_algorithms")]
    pub algorithms: Vec<String>,
}

/// Today's challenge set, unchanged: weakest first, so a legacy MD5-only client
/// finds its entry and a modern one picks the strongest it supports
/// (RFC 7616 §3.7).
fn default_digest_algorithms() -> Vec<String> {
    vec![
        "MD5".to_string(),
        "SHA-256".to_string(),
        "SHA-512-256".to_string(),
    ]
}

/// AKA credential for a single subscriber (3GPP TS 35.206 Milenage).
#[derive(Debug, Deserialize, Clone)]
pub struct AkaCredential {
    /// Subscriber key K (32 hex chars = 16 bytes).
    pub k: String,
    /// Operator variant key OP (32 hex chars = 16 bytes).
    pub op: String,
    /// Authentication Management Field AMF (4 hex chars = 2 bytes).
    #[serde(default = "default_amf")]
    pub amf: String,
    /// SQN of the first challenge `auth.require_aka_digest()` issues for this
    /// subscriber (12 hex chars = 48 bits), default `000000000001`. Later
    /// challenges advance it, and an AUTS from the UE re-bases it (TS 33.102
    /// 6.3.5), so this only matters for the first challenge after a start.
    #[serde(default)]
    pub sqn: Option<String>,
}

impl AkaCredential {
    /// The configured starting SQN as a 48-bit integer, `None` when unset.
    ///
    /// # Errors
    /// When `sqn` is not exactly 12 hex characters.
    pub fn starting_sqn(&self) -> Result<Option<u64>, String> {
        let Some(text) = self.sqn.as_deref() else {
            return Ok(None);
        };
        if text.len() != 12 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(format!(
                "sqn {text:?} is not 12 hex characters (a 48-bit SQN, TS 33.102 C.1)"
            ));
        }
        u64::from_str_radix(text, 16)
            .map(Some)
            .map_err(|error| format!("sqn {text:?}: {error}"))
    }
}

impl AuthConfig {
    /// Refuse an `aka_credentials` entry whose `sqn` is not a 48-bit hex value,
    /// at load rather than at the first challenge.
    ///
    /// # Errors
    /// Names the entry and what is wrong with its `sqn`.
    pub fn validate_aka_credentials(&self) -> Result<(), String> {
        for (identity, credential) in &self.aka_credentials {
            credential
                .starting_sqn()
                .map_err(|error| format!("auth.aka_credentials.{identity}: {error}"))?;
        }
        Ok(())
    }
}

fn default_amf() -> String {
    "8000".to_string()
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            realm: default_realm(),
            backend: default_auth_backend(),
            users: Default::default(),
            aka_credentials: Default::default(),
            http: None,
            database: None,
            diameter: None,
            nonce_secret: None,
            nonce_ttl_secs: None,
            algorithms: default_digest_algorithms(),
        }
    }
}

fn default_realm() -> String {
    "localhost".to_owned()
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AuthBackendType {
    /// Credentials defined inline under `auth.users`.
    Static,
    /// PostgreSQL / generic DB. Not dispatched — rejected at config load.
    Database,
    /// REST lookup — GET `{url}` where `{username}` is substituted.
    /// Response body is either a plaintext password or a pre-hashed HA1.
    Http,
    /// Not a dispatchable backend — rejected at config load. Cx MAR/MAA
    /// authentication is reached from a script via `auth.require_ims_digest()`.
    DiameterCx,
}

fn default_auth_backend() -> AuthBackendType {
    AuthBackendType::Static
}

#[derive(Debug, Deserialize, Clone)]
pub struct HttpAuthConfig {
    /// URL template. `{username}` is replaced at runtime.
    /// Example: `http://127.0.0.1:8000/sip/auth/{username}`
    pub url: String,
    #[serde(default = "default_http_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_http_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    /// If true, the HTTP response body is a pre-hashed HA1 hex string.
    /// If false, it is a plaintext password (SIPhon hashes it internally).
    #[serde(default)]
    pub ha1: bool,
    /// TTL (seconds) for caching a successful credential lookup, keyed by
    /// realm and username. `0` (the default) disables caching — every digest
    /// verification performs a blocking HTTP fetch, so a registration storm
    /// translates 1:1 into blocking calls on the fixed Python executor pool.
    /// Set this (e.g. `300`) so repeated REGISTERs for the same subscriber
    /// reuse the cached HA1/password instead of re-hitting the backend.
    ///
    /// A changed credential does not wait out the TTL: a digest that fails
    /// against a cached credential re-reads the backend once, so a reset
    /// password verifies at once and a user the backend no longer knows is
    /// refused and dropped. Only the final verdict feeds the auto-ban. The one
    /// case the re-read cannot see is a deleted user presenting its *old*
    /// password, which still matches the cached entry; flush it with
    /// `POST /admin/auth/cache/invalidate` when the credential is written.
    #[serde(default)]
    pub cache_ttl_secs: u64,
}

/// SQL credential source for `auth.backend: database`.
///
/// The query is the operator's, not siphon's: schemas differ and a fixed one
/// would mean every deployment maintaining a view. It is passed to PostgreSQL
/// as a prepared statement with `$1` bound to the digest username and, when the
/// query references it, `$2` bound to the realm — so the username never reaches
/// the database as SQL text.
#[derive(Debug, Deserialize, Clone)]
pub struct DatabaseAuthConfig {
    /// libpq connection URI, e.g. `postgresql://siphon@db.internal/siphon`.
    pub url: String,
    /// Statement returning one row, one column: the credential for `$1`
    /// (and `$2`, the realm, when the statement references it).
    #[serde(default = "default_auth_query")]
    pub query: String,
    /// If true, the column is a pre-hashed H(A1) hex string. If false, it is a
    /// plaintext password and siphon hashes it with the algorithm the client
    /// advertised.
    ///
    /// An H(A1) is algorithm-specific by construction (RFC 7616 §3.4.3), so a
    /// stored one only verifies for clients answering with the algorithm it was
    /// computed for.
    #[serde(default)]
    pub ha1: bool,
    /// TTL (seconds) for caching a successful lookup, keyed by realm, username
    /// and H(A1) column. `0` (the default) disables caching, so every digest
    /// verification performs a blocking query and a registration storm
    /// translates 1:1 into queries on the fixed Python executor pool.
    /// Credentials rarely change, so a non-zero TTL is the production setting.
    /// Same staleness contract as `auth.http.cache_ttl_secs`: a failed digest
    /// against a cached credential re-reads once, and
    /// `POST /admin/auth/cache/invalidate` flushes on demand.
    #[serde(default)]
    pub cache_ttl_secs: u64,
    /// Per-query deadline in milliseconds, connection included.
    #[serde(default = "default_auth_query_timeout_ms")]
    pub timeout_ms: u64,
}

fn default_auth_query() -> String {
    "SELECT password FROM subscribers WHERE username = $1 AND realm = $2".to_string()
}

fn default_auth_query_timeout_ms() -> u64 {
    2000
}

fn default_http_timeout_ms() -> u64 {
    2000
}
fn default_http_connect_timeout_ms() -> u64 {
    500
}
