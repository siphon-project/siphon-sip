//! `registrant:` outbound registration (UAC registrant).

use serde::Deserialize;

// ---------------------------------------------------------------------------
// Outbound Registration (UAC Registrant)
// ---------------------------------------------------------------------------

/// Outbound registrant configuration in `siphon.yaml`.
///
/// ```yaml
/// registrant:
///   default_interval: 3600
///   retry_interval: 60
///   max_retry_interval: 300
///   entries:
///     - aor: "sip:alice@carrier.com"
///       registrar: "sip:registrar.carrier.com:5060"
///       user: "alice"
///       password: "secret123"
///       realm: "carrier.com"
///       interval: 1800
///       contact: "sip:alice@1.2.3.4"
///       transport: "udp"
/// ```
#[derive(Debug, Deserialize, Clone)]
pub struct RegistrantYamlConfig {
    /// Where the registering trunks come from. Default: `static`, the
    /// `entries` list below.
    ///
    /// `database` and `http` read them from a source the controller owns and
    /// reconcile against it on an interval, so a trunk added, edited or deleted
    /// there is followed without a restart. Entries added by a script
    /// (`registration.add`) and the `entries` list are never touched by that
    /// reconcile — it owns only what it created.
    #[serde(default = "default_registrant_backend")]
    pub backend: RegistrantBackendType,
    /// SQL source for `backend: database`.
    pub database: Option<RegistrantDatabaseConfig>,
    /// HTTP source for `backend: http`.
    pub http: Option<RegistrantHttpConfig>,
    /// Default registration interval in seconds. Default: 3600.
    #[serde(default = "default_registrant_interval")]
    pub default_interval: u32,
    /// Base retry interval on failure in seconds. Default: 60.
    #[serde(default = "default_registrant_retry")]
    pub retry_interval: u64,
    /// Maximum retry interval (backoff cap) in seconds. Default: 300.
    #[serde(default = "default_registrant_max_retry")]
    pub max_retry_interval: u64,
    /// Static registration entries.
    #[serde(default)]
    pub entries: Vec<RegistrantEntryConfig>,
}

/// Where `registrant:` reads its registering trunks from.
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RegistrantBackendType {
    /// The `entries` list in this file.
    Static,
    /// A PostgreSQL query the controller owns.
    Database,
    /// A JSON endpoint the controller serves.
    Http,
}

/// SQL source for `registrant.backend: database`.
///
/// The query is the operator's, not siphon's: schemas differ and a fixed one
/// would mean every deployment maintaining a view for us. Columns are read by
/// name — `aor`, `registrar` and `username` are required; `password`, `ha1`,
/// `ha1_algorithm`, `realm`, `interval`, `contact`, `transport`, `enabled` and
/// `gateway` are optional. When the statement references `$1`, the instance id
/// (`server.instance_id`) is bound to it, so a deployment can shard its trunks
/// across nodes with `WHERE node = $1`.
#[derive(Debug, Deserialize, Clone)]
pub struct RegistrantDatabaseConfig {
    /// libpq connection URI, e.g. `postgresql://siphon@db.internal/siphon`.
    pub url: String,
    /// Statement returning one row per registering trunk.
    #[serde(default = "default_registrant_query")]
    pub query: String,
    /// How often to re-read the source and reconcile, in seconds. A change is
    /// applied at once by `POST /admin/registrants/refresh`, so this is the
    /// floor rather than the mechanism.
    #[serde(default = "default_registrant_refresh_secs")]
    pub refresh_secs: u64,
    /// Per-query deadline in milliseconds, connection included.
    #[serde(default = "default_registrant_source_timeout_ms")]
    pub timeout_ms: u64,
}

/// JSON source for `registrant.backend: http`.
///
/// The endpoint answers `GET {url}` with the contract in
/// `docs/reference/registrant-api.md` (typed in `siphon_sdk.registrants`).
///
/// This is the form to use when trunk passwords are sealed at rest: the
/// controller unseals in-process and serves the credential over a trusted local
/// channel, so siphon never sees the sealed form and no sealing construction
/// has to enter siphon.
#[derive(Debug, Deserialize, Clone)]
pub struct RegistrantHttpConfig {
    /// URL siphon `GET`s the trunk list from.
    pub url: String,
    /// How often to re-read the source and reconcile, in seconds.
    #[serde(default = "default_registrant_refresh_secs")]
    pub refresh_secs: u64,
    /// Per-request deadline in milliseconds.
    #[serde(default = "default_registrant_source_timeout_ms")]
    pub timeout_ms: u64,
    /// Full `Authorization` header value sent with each request (e.g.
    /// `"Bearer …"`). Supports `${VAR}` expansion.
    pub auth_header: Option<String>,
}

fn default_registrant_backend() -> RegistrantBackendType {
    RegistrantBackendType::Static
}

fn default_registrant_query() -> String {
    "SELECT aor, registrar, username, password, realm, expires AS interval, contact, \
     transport, enabled FROM registrants"
        .to_string()
}

fn default_registrant_refresh_secs() -> u64 {
    30
}

fn default_registrant_source_timeout_ms() -> u64 {
    2000
}

/// A single static registrant entry.
#[derive(Debug, Deserialize, Clone)]
pub struct RegistrantEntryConfig {
    /// Address-of-Record (e.g. "sip:alice@carrier.com"). For IMS AKA this is
    /// the IMPU.
    pub aor: String,
    /// Registrar URI (e.g. "sip:registrar.carrier.com:5060"). For IMS this is
    /// the P-CSCF.
    pub registrar: String,
    /// Authentication username. For IMS AKA this is the IMPI.
    pub user: String,
    /// Authentication password (digest only; unused for AKA).
    #[serde(default)]
    pub password: String,
    /// Optional realm hint — derived from 401 challenge if omitted (the home
    /// domain for IMS).
    pub realm: Option<String>,
    /// Registration interval override in seconds.
    pub interval: Option<u32>,
    /// Contact URI override (auto-generated if omitted).
    pub contact: Option<String>,
    /// Transport: "udp" (default), "tcp", "tls".
    #[serde(default = "default_registrant_transport")]
    pub transport: String,
    /// Authentication mode: "digest" (default) or "aka" for IMS AKAv1-MD5
    /// (RFC 3310 / 3GPP TS 33.203).
    pub auth: Option<String>,
    /// IMS AKA credentials — required when `auth: aka`.
    pub aka: Option<RegistrantAkaConfig>,
    /// IPsec sec-agree (UE side) — only valid with `auth: aka`.
    pub ipsec: Option<RegistrantIpsecConfig>,
    /// IMS Contact feature tags (instance ID + MMTel/video/SMS) so the S-CSCF
    /// registers the implied services.
    pub ims: Option<RegistrantImsConfig>,
}

/// IMS Contact feature tags for a registrant entry (TS 24.229 / GSMA IR.92).
#[derive(Debug, Deserialize, Clone)]
pub struct RegistrantImsConfig {
    /// IMEI for `+sip.instance="<urn:gsma:imei:…>"` (RFC 5626 instance ID).
    pub imei: Option<String>,
    /// Feature tags to advertise: any of "mmtel", "video", "smsip".
    #[serde(default)]
    pub features: Vec<String>,
}

/// IMS AKA credentials for a registrant entry (3GPP TS 33.203).
#[derive(Debug, Deserialize, Clone)]
pub struct RegistrantAkaConfig {
    /// Subscriber key K as 32 hex chars.
    pub k: String,
    /// Operator variant OP as 32 hex chars (supply `op` OR `opc`).
    pub op: Option<String>,
    /// Pre-computed OPc as 32 hex chars (supply `op` OR `opc`).
    pub opc: Option<String>,
    /// Authentication Management Field as 4 hex chars.
    #[serde(default = "default_aka_amf")]
    pub amf: String,
    /// Initial stored sequence number SQN_MS as 12 hex chars.
    #[serde(default = "default_aka_sqn")]
    pub sqn: String,
}

/// IPsec sec-agree parameters for a registrant entry (UE side, TS 33.203).
#[derive(Debug, Deserialize, Clone)]
pub struct RegistrantIpsecConfig {
    /// UE protected client port (must also be a `listen.udp` entry).
    pub ue_port_c: u16,
    /// UE protected server port (must also be a `listen.udp` entry).
    pub ue_port_s: u16,
    /// Offered integrity algorithm: "hmac-sha-1-96" (default), "hmac-md5-96",
    /// or "hmac-sha-256-128".
    #[serde(default = "default_ipsec_alg")]
    pub alg: String,
    /// Offered encryption algorithm: "null" (default) or "aes-cbc".
    #[serde(default = "default_ipsec_ealg")]
    pub ealg: String,
}

fn default_aka_amf() -> String {
    "8000".to_string()
}

fn default_aka_sqn() -> String {
    "000000000000".to_string()
}

fn default_ipsec_alg() -> String {
    "hmac-sha-1-96".to_string()
}

fn default_ipsec_ealg() -> String {
    "null".to_string()
}

fn default_registrant_interval() -> u32 {
    3600
}

fn default_registrant_retry() -> u64 {
    60
}

fn default_registrant_max_retry() -> u64 {
    300
}

fn default_registrant_transport() -> String {
    "udp".to_string()
}
