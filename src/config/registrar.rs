//! `registrar:` store, liveness and persistence backends.

use serde::Deserialize;

// ---------------------------------------------------------------------------
// Registrar
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct RegistrarConfig {
    pub backend: RegistrarBackendType,
    pub default_expires: u32,
    pub max_expires: u32,
    /// Floor on Expires: header value. Requests below this are rejected with 423.
    pub min_expires: Option<u32>,
    /// Maximum contacts per AoR (None = unlimited). Use 1 for single-device deployments.
    pub max_contacts: Option<u32>,
    /// Require the REGISTER's AoR (To-URI user) to match the authenticated
    /// digest user, rejecting attempts to bind a contact under another
    /// subscriber's AoR. Default false (backward-compatible; IMS deployments
    /// where the public identity differs from the private auth identity must
    /// leave this off and authorize via the implicit registration set).
    #[serde(default)]
    pub enforce_auth_aor_match: bool,
    pub redis: Option<RedisBackendConfig>,
    pub postgres: Option<PostgresBackendConfig>,
    /// Registration liveness — network-initiated deregistration when a UE
    /// vanishes without a SIP de-REGISTER (flow failure on TCP/TLS, idle
    /// IPsec SA on UDP).  Default off.
    #[serde(default)]
    pub liveness: RegistrarLivenessConfig,
}

impl Default for RegistrarConfig {
    fn default() -> Self {
        Self {
            backend: RegistrarBackendType::Memory,
            default_expires: 3600,
            max_expires: 7200,
            min_expires: None,
            max_contacts: None,
            enforce_auth_aor_match: false,
            redis: None,
            postgres: None,
            liveness: RegistrarLivenessConfig::default(),
        }
    }
}

/// Registration-liveness configuration (network-initiated deregistration).
///
/// When `enabled`, siphon clears a registration on its own initiative once it
/// detects the UE is gone, instead of waiting for the SIP `Expires` timer
/// (often hours):
///   - **TCP/TLS/WS/WSS**: the binding is removed when its inbound connection
///     closes (peer FIN/RST, read error, idle timeout, or CRLF-keepalive
///     failure) — RFC 5626 §4.2.2 flow failure.
///   - **UDP+IPsec**: an idle binding is detected by polling the kernel XFRM
///     SA inbound use-time; the UE's RFC 6223 keepalive (~every 30 s) keeps
///     the SA warm, so silence beyond `idle_multiplier × keepalive_interval`
///     marks the binding suspect.  A single OPTIONS probe confirms before the
///     binding is deregistered.
#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct RegistrarLivenessConfig {
    /// Master switch.  Default `false` until the feature is proven in the
    /// field; with it off, siphon behaves exactly as before (Expires-only).
    pub enabled: bool,
    /// Negotiated UE keepalive cadence in seconds (RFC 6223 Flow-Timer / NAT
    /// keepalive).  Used as the base unit for the UDP+IPsec idle window.
    pub keepalive_interval_secs: u32,
    /// Grace multiplier: a UDP+IPsec binding is suspect after
    /// `idle_multiplier × keepalive_interval_secs` of SA silence.  Default 3
    /// (~90 s against a 30 s keepalive) survives a brief radio blip or a
    /// single dropped keepalive without false-deregistering a live UE.
    pub idle_multiplier: u32,
    /// Per-attempt timeout (milliseconds) for the one-shot OPTIONS liveness
    /// probe sent to a suspect UDP+IPsec binding before deregistration.
    /// Default 4000 — long enough to cover one ECM-IDLE paging + reconnect
    /// (an OPTIONS to an idle UE *is* a paging trigger, so the answer can't
    /// arrive until the radio is back up); with 2 attempts that is ~8 s of
    /// patience per sweep before a suspect binding counts as one miss.
    pub probe_timeout_ms: u64,
    /// Consecutive sweeps a suspect binding must fail its OPTIONS probe before
    /// it is deregistered.  Default 2 — a UE mid-wakeup (ECM-IDLE → paging →
    /// reconnect) misses one sweep and answers the next, so it survives; a
    /// genuinely gone UE (reboot / airplane mode) misses every sweep and reaps
    /// after the grace.  Biased toward patience: a lingering vanished binding
    /// is benign (it re-registers or ages out on its own `Expires`), whereas a
    /// false deregistration is a dropped registration + a failed MT call.
    /// Reap latency for a truly-gone UE grows by `miss_threshold ×` the 30 s
    /// sweep interval (~60 s), still far inside any registration `Expires`.
    pub miss_threshold: u32,
    /// What to do once a binding is declared dead.
    pub dereg_mode: LivenessDeregMode,
}

impl Default for RegistrarLivenessConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            keepalive_interval_secs: 30,
            idle_multiplier: 3,
            probe_timeout_ms: 4000,
            miss_threshold: 2,
            dereg_mode: LivenessDeregMode::NetworkDereg,
        }
    }
}

/// How siphon clears a binding once liveness detection declares the UE dead.
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LivenessDeregMode {
    /// Authoritative registrar (S-CSCF / single box): drop the binding locally
    /// and emit the `@registrar.on_change` cascade.  P-CSCF cache: additionally
    /// synthesize a de-REGISTER (`Expires: 0`) on the UE's behalf toward the
    /// S-CSCF so the registrar of record also clears the binding.
    NetworkDereg,
    /// Drop local state only (binding + IPsec SA) and emit the local
    /// `on_change` event; never synthesize an upstream de-REGISTER.  Use on a
    /// box that is the registrar of record, where the reg-event NOTIFY already
    /// propagates the teardown.
    LocalOnly,
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum RegistrarBackendType {
    Memory,
    Redis,
    Postgres,
    /// Rejected at config load: the `@registrar.on_save` / `@registrar.on_lookup`
    /// hooks this names were never implemented, and selecting it silently
    /// behaved as `Memory`. Kept as a variant so an existing config fails with
    /// an explanation rather than a deserialization error; removed at 2.0.
    Python,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RedisBackendConfig {
    pub url: String,
    /// Key prefix for all registrar entries (default: "siphon:reg:").
    #[serde(default = "default_redis_key_prefix")]
    pub key_prefix: String,
    /// Extra seconds beyond `expires` to retain keys, to avoid race conditions.
    #[serde(default = "default_ttl_slack")]
    pub ttl_slack_secs: u32,
}

fn default_redis_key_prefix() -> String {
    "siphon:reg:".to_owned()
}

fn default_ttl_slack() -> u32 {
    30
}

#[derive(Debug, Deserialize, Clone)]
pub struct PostgresBackendConfig {
    pub url: String,
    #[serde(default = "default_postgres_table")]
    pub table: String,
}

fn default_postgres_table() -> String {
    "registrar".to_owned()
}
