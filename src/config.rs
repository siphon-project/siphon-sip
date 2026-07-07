//! YAML configuration — `siphon.yaml` deserialization via serde_yaml_ng.

use indexmap::IndexMap;
use regex::Regex;
use serde::{Deserialize, Deserializer, Serialize};
use std::path::Path;
use std::sync::LazyLock;
use crate::error::{Result, SiphonError};

// ---------------------------------------------------------------------------
// Environment variable expansion — `${VAR}` and `${VAR:-default}`
// ---------------------------------------------------------------------------

static ENV_VAR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}").expect("env var regex")
});

/// Expand `${VAR}` and `${VAR:-default}` patterns in a config string.
///
/// - `${VAR}` is replaced with the environment variable's value, or the empty
///   string if unset/empty.
/// - `${VAR:-fallback}` uses `fallback` when the variable is unset or empty.
fn expand_env_vars(input: &str) -> String {
    ENV_VAR_RE
        .replace_all(input, |caps: &regex::Captures| {
            let var_name = &caps[1];
            match std::env::var(var_name) {
                Ok(value) if !value.is_empty() => value,
                _ => caps
                    .get(2)
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default(),
            }
        })
        .into_owned()
}

/// Allocator runtime tuning — how the process *manages* memory, distinct from
/// `metrics` (what it *measures*). The `siphon_glibc_*` gauges are always on
/// regardless of this block; it carries only the optional bounding knobs.
#[derive(Debug, Clone, Deserialize, PartialEq, Default)]
pub struct MemoryConfig {
    /// glibc malloc tuning for the C-side / CPython raw-domain pool.
    #[serde(default)]
    pub glibc: GlibcMemoryConfig,
}

/// glibc `malloc` tuning. Both knobs default off — measure with the gauges
/// first, then bound only if the pool proves to be arena *retention* rather
/// than a true leak.
#[derive(Debug, Clone, Deserialize, PartialEq, Default)]
pub struct GlibcMemoryConfig {
    /// `mallopt(M_ARENA_MAX, n)` — cap the number of glibc arenas (each a
    /// ~64 MB reservation). The primary lever against per-thread-arena
    /// retention under free-threaded concurrency. `None` = leave glibc's
    /// default (8 × CPUs). Applied once at startup, before the thread pools.
    #[serde(default)]
    pub arena_max: Option<usize>,

    /// Period in seconds for a background `malloc_trim(0)` that returns free
    /// arena memory to the OS. `0` = disabled.
    #[serde(default)]
    pub trim_interval_secs: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub listen: ListenConfig,
    pub domain: DomainConfig,
    #[serde(default)]
    pub script: ScriptConfig,
    #[serde(default)]
    pub registrar: RegistrarConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub log: LogConfig,

    // Optional top-level sections — all `None` when not present.
    // Rust holds them as data; wiring into the runtime happens in later phases.

    /// Public IP advertised in Via/Contact/SDP (e.g. EC2 public IP when binding 0.0.0.0).
    pub advertised_address: Option<String>,

    /// TLS certificate and key for the `listen.tls` listeners.
    pub tls: Option<TlsServerConfig>,

    /// Rate limiting, scanner UA blocking, trusted source CIDRs.
    pub security: Option<SecurityConfig>,

    /// NAT traversal: response Contact rewriting + keepalives (OPTIONS + CRLF).
    pub nat: Option<NatConfig>,

    /// SIP call tracing via HEP (Homer/captAgent).
    pub tracing: Option<TracingConfig>,

    /// Prometheus metrics endpoint.
    pub metrics: Option<MetricsConfig>,

    /// HTTP admin API (health/readiness probes + registration inspection).
    /// `None` = disabled.
    pub admin: Option<AdminConfig>,

    /// Server and User-Agent header values injected into responses.
    pub server: Option<ServerIdentityConfig>,

    /// SIP transaction layer timer overrides.
    pub transaction: Option<TransactionConfig>,

    /// Allocator runtime tuning (glibc arena cap + periodic trim). The
    /// `siphon_glibc_*` gauges are always on; this block only adds the optional
    /// bounding knobs. `None` = gauges only, no tuning.
    pub memory: Option<MemoryConfig>,

    /// Dialog state tracking backend.
    pub dialog: Option<DialogConfig>,

    /// Named cache connections available to Python scripts via `cache.fetch(name, key)`.
    pub cache: Option<Vec<NamedCacheConfig>>,

    /// Media proxy (RTPEngine) configuration.
    pub media: Option<MediaConfig>,

    /// Gateway dispatcher (named groups with load balancing + health probing).
    pub gateway: Option<GatewayConfig>,

    /// RFC 4028 session timers for B2BUA mode.
    pub session_timer: Option<SessionTimerConfig>,

    /// B2BUA-wide knobs (header policy, etc.).
    #[serde(default)]
    pub b2bua: B2buaConfig,

    /// Call Detail Records — billing and accounting.
    pub cdr: Option<CdrYamlConfig>,

    /// Outbound registration (UAC registrant) — maintain REGISTER bindings to upstream.
    pub registrant: Option<RegistrantYamlConfig>,

    /// Lawful Intercept — ETSI X1/X2/X3 + SIPREC (RFC 7866).
    pub lawful_intercept: Option<LawfulInterceptConfig>,

    /// Diameter peer connections and application routing table.
    pub diameter: Option<DiameterConfig>,

    /// IPsec SA management for P-CSCF (3GPP TS 33.203).
    pub ipsec: Option<IpsecConfig>,

    /// STIR/SHAKEN caller-ID attestation (RFC 8224/8225/8226, ATIS-1000074).
    /// Drives the `stir` Python namespace (`stir.sign()` / `stir.verify()`).
    pub stir: Option<StirConfig>,

    /// Initial Filter Criteria (3GPP TS 29.228) — S-CSCF iFC evaluation.
    pub isc: Option<IscConfig>,

    /// 5G SBI client configuration (Npcf, Nchf).
    pub sbi: Option<SbiYamlConfig>,

    /// Session Recording Server (SRS) — receive SIPREC INVITEs and record calls.
    pub srs: Option<SrsConfig>,

    /// Generic SUBSCRIBE dialog state (``proxy.subscribe_state``).  When
    /// ``cache`` references a configured named cache, dialogs are
    /// persisted through it so they survive restarts and are visible to
    /// other replicas.
    pub subscribe_state: Option<SubscribeStateConfig>,

    /// Rf offline-charging configuration (3GPP TS 32.299).  Drives
    /// automatic ACR-START / ACR-INTERIM / ACR-STOP on B2BUA and proxy
    /// call lifecycle events, plus ACR-EVENT for REGISTER.  When
    /// ``None`` (default), Rf is fully off — scripts can still call
    /// ``diameter.rf_acr_*`` manually as long as a Diameter peer is
    /// connected.
    pub rf: Option<RfConfig>,

    /// Free-form per-extension configuration. Each entry's value is opaque
    /// to siphon-core and is interpreted by the extension that owns the
    /// name. A scalar string is conventionally treated as a path to a
    /// further configuration file; any other YAML form (mapping, sequence,
    /// number, bool) is passed through verbatim.
    ///
    /// ```yaml
    /// extensions:
    ///   foo: /etc/siphon/foo.yaml          # path form
    ///   bar:                                # inline form
    ///     listen: "0.0.0.0:8080"
    ///     workers: 4
    /// ```
    ///
    /// Extensions read their entry via [`Config::extension_path`] (when
    /// they expect an external file) or [`Config::extension_config`]
    /// (when they consume the value directly).
    #[serde(default)]
    pub extensions: Option<IndexMap<String, serde_yaml_ng::Value>>,
}

/// B2BUA-wide configuration knobs.
///
/// Currently surfaces the default header policy applied to B2BUA calls when
/// the script doesn't pass `header_policy=` on `call.dial()`.  The built-in
/// presets ship with siphon — operators just pin the qualified name (e.g.
/// `"transparent-b2bua@2026"`).  An unset/empty value falls back to
/// `transparent-b2bua@2026`, which reproduces siphon's pre-policy B2BUA
/// behaviour (modulo the intentional `Proxy-Authenticate` strip).
///
/// ```yaml
/// b2bua:
///   default_header_policy: "ims-trust-domain-boundary@2026"
/// ```
#[derive(Debug, Deserialize, Clone, Default)]
pub struct B2buaConfig {
    /// Qualified preset name (`"<name>@<version>"`).  When `None`, falls
    /// back to `"transparent-b2bua@2026"`.
    pub default_header_policy: Option<String>,
}

/// Configuration for ``proxy.subscribe_state`` — generic SUBSCRIBE
/// dialog state with optional Redis-backed write-through.
#[derive(Debug, Deserialize, Clone)]
pub struct SubscribeStateConfig {
    /// Name of a cache defined in the top-level ``cache:`` list that
    /// should be used as L2 write-through storage.  When unset, the
    /// store is in-process only (no cross-replica visibility).
    pub cache: Option<String>,
    /// Default expiry (seconds) when the SUBSCRIBE carries no
    /// ``Expires`` header and the script doesn't override.  Defaults to
    /// 3600.
    #[serde(default = "default_subscribe_state_expires")]
    pub default_expires_secs: u64,
}

fn default_subscribe_state_expires() -> u64 {
    3600
}

// ---------------------------------------------------------------------------
// DSCP / DiffServ — RFC 4594 signaling QoS
// ---------------------------------------------------------------------------

/// Parse a DSCP name (CS0–CS7, AF11–AF43, EF, BE) or a raw integer 0–63.
pub fn parse_dscp(value: &str) -> std::result::Result<u8, String> {
    match value.to_uppercase().as_str() {
        "CS0" | "BE" => Ok(0),
        "CS1" => Ok(8),
        "AF11" => Ok(10),
        "AF12" => Ok(12),
        "AF13" => Ok(14),
        "CS2" => Ok(16),
        "AF21" => Ok(18),
        "AF22" => Ok(20),
        "AF23" => Ok(22),
        "CS3" => Ok(24),
        "AF31" => Ok(26),
        "AF32" => Ok(28),
        "AF33" => Ok(30),
        "CS4" => Ok(32),
        "AF41" => Ok(34),
        "AF42" => Ok(36),
        "AF43" => Ok(38),
        "CS5" => Ok(40),
        "EF" => Ok(46),
        "CS6" => Ok(48),
        "CS7" => Ok(56),
        _ => value
            .parse::<u8>()
            .map_err(|_| format!("invalid DSCP value: {value}"))
            .and_then(|v| {
                if v <= 63 {
                    Ok(v)
                } else {
                    Err(format!("DSCP must be 0-63, got {v}"))
                }
            }),
    }
}

/// Convert a 6-bit DSCP value to the 8-bit TOS byte (RFC 2474 §3).
pub fn dscp_to_tos(dscp: u8) -> u32 {
    (dscp as u32) << 2
}

/// Default DSCP: CS3 (24) — RFC 4594 Signaling class for SIP.
fn default_dscp() -> Option<u8> {
    Some(24)
}

/// Serde deserializer accepting either a DSCP name string or a raw integer.
fn deserialize_dscp<'de, D>(deserializer: D) -> std::result::Result<Option<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de;

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum DscpValue {
        Int(u64),
        Str(String),
    }

    let value: Option<DscpValue> = Option::deserialize(deserializer)?;
    match value {
        None => Ok(None),
        Some(DscpValue::Int(n)) => {
            if n > 63 {
                Err(de::Error::custom(format!("DSCP must be 0-63, got {n}")))
            } else {
                Ok(Some(n as u8))
            }
        }
        Some(DscpValue::Str(s)) => parse_dscp(&s).map(Some).map_err(de::Error::custom),
    }
}

// ---------------------------------------------------------------------------
// Transport listeners
// ---------------------------------------------------------------------------

/// A listen entry: either a plain address string or a struct with an
/// optional advertised address (like OpenSIPS `socket ... as ...`).
///
/// ```yaml
/// listen:
///   tcp:
///     - "10.0.0.1:5060"                          # plain string
///     - address: "10.0.0.1:5061"                  # struct form
///       advertise: "sip.example.com"              #   with advertised host
/// ```
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(untagged)]
pub enum ListenEntry {
    /// Plain address string (e.g. `"10.0.0.1:5060"`).
    Plain(String),
    /// Address with optional advertised host and per-listener DSCP override.
    Extended {
        address: String,
        #[serde(default)]
        advertise: Option<String>,
        /// Per-listener DSCP override (0–63 or name like "CS3", "EF").
        #[serde(default, deserialize_with = "deserialize_dscp")]
        dscp: Option<u8>,
    },
}

impl ListenEntry {
    /// The bind address string.
    pub fn address(&self) -> &str {
        match self {
            ListenEntry::Plain(addr) => addr,
            ListenEntry::Extended { address, .. } => address,
        }
    }

    /// The advertised host (if configured).
    pub fn advertise(&self) -> Option<&str> {
        match self {
            ListenEntry::Plain(_) => None,
            ListenEntry::Extended { advertise, .. } => advertise.as_deref(),
        }
    }

    /// Per-listener DSCP override (if configured).
    pub fn dscp(&self) -> Option<u8> {
        match self {
            ListenEntry::Plain(_) => None,
            ListenEntry::Extended { dscp, .. } => *dscp,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct ListenConfig {
    /// Global DSCP value applied to all listeners (default: CS3 = 24).
    /// Per-listener `dscp` in the extended form overrides this.
    /// Set to `0` or `"BE"` to disable marking.
    #[serde(default = "default_dscp", deserialize_with = "deserialize_dscp")]
    pub dscp: Option<u8>,
    #[serde(default)]
    pub udp: Vec<ListenEntry>,
    #[serde(default)]
    pub tcp: Vec<ListenEntry>,
    #[serde(default)]
    pub tls: Vec<ListenEntry>,
    /// WebSocket (ws://) — browser/WebRTC UEs.
    #[serde(default)]
    pub ws: Vec<ListenEntry>,
    /// Secure WebSocket (wss://) — browser/WebRTC UEs.
    #[serde(default)]
    pub wss: Vec<ListenEntry>,
    /// SCTP (RFC 4168) — used between IMS core nodes.
    #[serde(default)]
    pub sctp: Vec<ListenEntry>,
}

impl Default for ListenConfig {
    fn default() -> Self {
        Self {
            dscp: default_dscp(),
            udp: Vec::new(),
            tcp: Vec::new(),
            tls: Vec::new(),
            ws: Vec::new(),
            wss: Vec::new(),
            sctp: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Network identity
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Clone)]
pub struct DomainConfig {
    pub local: Vec<String>,
}

// ---------------------------------------------------------------------------
// Script engine
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Clone)]
pub struct ScriptConfig {
    #[serde(default = "default_script_path")]
    pub path: String,
    #[serde(default = "default_reload")]
    pub reload: ReloadMode,
    /// Size of the asyncio loop driver pool used to run async script
    /// handlers.  Each driver is a dedicated OS thread running a Python
    /// event loop forever — see `script::async_pool` for why this is
    /// needed (orphaned `asyncio.create_task` survival).  Defaults to
    /// the number of available CPUs (clamped to at least 1).
    #[serde(default)]
    pub async_pool_size: Option<usize>,
    /// Size of the synchronous Python executor pool used to run *sync*
    /// script-handler invocations.  Each worker is a fixed, never-reaped
    /// OS thread with a persistent Python attach — see `script::py_executor`
    /// for why this is needed (the free-threaded-CPython mimalloc heap leak
    /// on the elastic `spawn_blocking` pool).  Defaults to 2× the number of
    /// available CPUs (floored at 8), but **capped by the container memory
    /// budget** so an un-cpu-limited NF on a many-core box doesn't *start* at 32
    /// always-on workers (each carries ~8 MB of persistent free-threaded-CPython
    /// heap).  The hot inbound path runs here, and 2× restores the burst headroom
    /// the elastic pool gave at the throughput ceiling.  Lower it on
    /// memory-constrained, low-traffic NFs.
    #[serde(default)]
    pub sync_pool_size: Option<usize>,
    /// Hard ceiling on synchronous Python executor worker threads. The pool is
    /// elastic — it starts at `sync_pool_size` (the always-on core) and grows
    /// on demand up to this when every worker is busy, then never shrinks. This
    /// restores the burst headroom blocking-I/O handlers need (a handful of
    /// concurrent blocking REGISTERs no longer wedge the engine) without the
    /// free-threaded-CPython heap leak that reaping caused. Each grown worker
    /// costs ~8 MB of persistent free-threaded-CPython heap (measured on 3.14t;
    /// the earlier ~2 MB estimate was ~4× low), so the pool's memory ceiling is
    /// roughly `sync_pool_max × 8 MB`. The default is **memory-aware**: the
    /// MINIMUM of the CPU-derived `max(32, 4 × sync_pool_size)` and a memory
    /// budget (~30 % of the container's cgroup memory limit ÷ per-worker heap),
    /// clamped to at least `sync_pool_size`. On a 512 MB NF that resolves to ~15
    /// (not 32); set this explicitly to override the budget either way.
    #[serde(default)]
    pub sync_pool_max: Option<usize>,
    /// Seconds the synchronous Python executor pool may show *zero forward
    /// progress while fully saturated* before SIPhon aborts the process so a
    /// supervisor (`restart: always`, systemd) restarts it.  Guards against a
    /// handler that blocks every worker indefinitely (a thread-unsafe HTTP
    /// client wedging, a backend that never returns, a lock held forever):
    /// without it the process stays alive but serves no SIP, and a
    /// restart-on-exit policy never fires because the process never exits.
    /// Defaults to 30 (6× the default 5 s HTTP-auth timeout, so transient
    /// backend slowness never trips it); `0` disables the watchdog.  See
    /// `script::py_executor`.
    #[serde(default = "default_handler_stall_abort_secs")]
    pub handler_stall_abort_secs: u64,
    /// Maximum number of handler jobs that may queue for the synchronous
    /// Python executor pool before new inbound work is shed (dropped — the SIP
    /// client retransmits).  Bounds memory under overload so a stuck pool can
    /// no longer grow the queue without limit.  Defaults to 1024; raise it on
    /// high-throughput NFs so normal bursts never shed.  Clamped to at least 1.
    #[serde(default = "default_executor_queue_capacity")]
    pub executor_queue_capacity: usize,
}

fn default_script_path() -> String {
    String::new()
}

fn default_handler_stall_abort_secs() -> u64 {
    30
}

fn default_executor_queue_capacity() -> usize {
    1024
}

impl Default for ScriptConfig {
    fn default() -> Self {
        Self {
            path: default_script_path(),
            reload: default_reload(),
            async_pool_size: None,
            sync_pool_size: None,
            sync_pool_max: None,
            handler_stall_abort_secs: default_handler_stall_abort_secs(),
            executor_queue_capacity: default_executor_queue_capacity(),
        }
    }
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ReloadMode {
    /// inotify watch — reload on file change, no restart required.
    Auto,
    /// Only reload on SIGHUP.
    Sighup,
}

fn default_reload() -> ReloadMode {
    ReloadMode::Auto
}

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
    pub probe_timeout_ms: u64,
    /// What to do once a binding is declared dead.
    pub dereg_mode: LivenessDeregMode,
}

impl Default for RegistrarLivenessConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            keepalive_interval_secs: 30,
            idle_multiplier: 3,
            probe_timeout_ms: 2000,
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
    /// Custom backend via Python hooks: `@registrar.on_save` / `@registrar.on_lookup`.
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
            diameter: None,
            nonce_secret: None,
            nonce_ttl_secs: None,
        }
    }
}

/// Diameter Cx connection to an HSS for IMS authentication (MAR/MAA, SAR/SAA).
#[derive(Debug, Deserialize, Clone)]
pub struct DiameterCxConfig {
    /// HSS hostname or IP address.
    pub host: String,
    /// HSS Diameter port (default: 3868).
    #[serde(default = "default_diameter_port")]
    pub port: u16,
    /// Origin-Host identity for this SIPhon node.
    pub origin_host: String,
    /// Origin-Realm for this SIPhon node.
    pub origin_realm: String,
    /// Destination-Realm (HSS realm).
    pub destination_realm: String,
    /// Destination-Host (optional, for targeted routing).
    pub destination_host: Option<String>,
    /// Transport protocol: "tcp" (default) or "sctp".
    #[serde(default = "default_diameter_transport")]
    pub transport: String,
    /// Watchdog (DWR) interval in seconds.
    #[serde(default = "default_watchdog_interval")]
    pub watchdog_interval: u64,
    /// Reconnect delay in seconds after connection failure.
    #[serde(default = "default_reconnect_delay")]
    pub reconnect_delay: u64,
}

fn default_diameter_port() -> u16 { 3868 }
fn default_diameter_transport() -> String { "tcp".to_string() }
fn default_watchdog_interval() -> u64 { 30 }
fn default_reconnect_delay() -> u64 { 5 }
fn default_diameter_route_algorithm() -> String { "failover".to_string() }

// ---------------------------------------------------------------------------
// Diameter peer + routing table (top-level `diameter:` section)
// ---------------------------------------------------------------------------

/// Top-level Diameter configuration with named peers and application routing.
///
/// SIPhon acts as a Diameter client — it connects outbound to peers (HSS, OCS,
/// PCRF, CDF) and uses the routing table to decide which peer(s) to use for
/// each application interface.
#[derive(Debug, Deserialize, Clone)]
pub struct DiameterConfig {
    /// Origin-Host identity for this SIPhon node (used in all client-mode CER
    /// messages). Optional for pure Diameter server deployments, which carry identity
    /// per-tenant under `tenants.<name>.identity` instead.
    #[serde(default)]
    pub origin_host: String,
    /// Origin-Realm for this SIPhon node.
    #[serde(default)]
    pub origin_realm: String,
    /// Product-Name advertised in CER/CEA. When unset, falls back to the
    /// product name resolved by `SiphonServer::product()` (default "SIPhon").
    #[serde(default)]
    pub product_name: Option<String>,
    /// Default transport for all peers: "tcp" (default) or "sctp".
    #[serde(default = "default_diameter_transport")]
    pub transport: String,
    /// Default DWR/DWA watchdog interval in seconds for all peers.
    #[serde(default = "default_watchdog_interval")]
    pub watchdog_interval: u64,
    /// Default reconnect delay in seconds after connection failure.
    #[serde(default = "default_reconnect_delay")]
    pub reconnect_delay: u64,
    /// Named Diameter peers (HSS, OCS, PCRF, CDF, etc.).
    #[serde(default)]
    pub peers: Vec<DiameterPeerEntry>,
    /// Application → peer routing table.
    #[serde(default)]
    pub routes: Vec<DiameterRouteEntry>,

    // ── Server mode — all opt-in, additive ────────────────────────────
    /// Inbound listener addresses. Presence enables server mode.
    #[serde(default)]
    pub listen: Option<DiameterListenConfig>,
    /// Inbound peers (source-IP ACL + optional Origin-Host validation) for the
    /// single-domain server. Folded into the implicit `"default"` tenant when
    /// `tenants` is omitted. See [`DiameterConfig::effective_tenants`].
    #[serde(default)]
    pub clients: Vec<DiameterClientEntry>,
    /// Backends this server connects out to and relays toward, for the
    /// single-domain server. Folded into the implicit `"default"` tenant.
    #[serde(default)]
    pub servers: Vec<DiameterServerEntry>,
    /// Outbound connections siphon initiates but serves inbound requests on
    /// (e.g. this node dialling an upstream), for the single-domain server.
    /// Folded into the implicit `"default"` tenant.
    #[serde(default)]
    pub connect_to: Vec<DiameterServerEntry>,
    /// Per-tenant identity + peer tables. Optional — the common single-domain
    /// case omits this and uses the flat `clients` / `servers` / `connect_to`
    /// fields above instead.
    #[serde(default)]
    pub tenants: std::collections::HashMap<String, DiameterTenant>,
    /// Generic event sink for Python-emitted signalling events.
    #[serde(default)]
    pub event_sink: Option<EventSinkConfig>,
}

impl DiameterConfig {
    /// Resolve the tenant map the server bootstrap runs against.
    ///
    /// Multi-tenant deployments declare `diameter.tenants.<name>` explicitly.
    /// The common single-domain case omits it and uses the flat
    /// `diameter.{origin_host,origin_realm,clients,servers,connect_to}` fields;
    /// those are folded into one implicit `"default"` tenant here, so the rest
    /// of the server runs through exactly the same path either way. Pure
    /// client-mode NFs (no identity, no peer lists) yield an empty map and
    /// never reach the server bootstrap.
    pub fn effective_tenants(&self) -> std::collections::HashMap<String, DiameterTenant> {
        if !self.tenants.is_empty() {
            return self.tenants.clone();
        }
        // Trigger synthesis on the server-specific fields only. `origin_host`
        // alone is set by pure client-mode NFs too, so it must not by itself
        // conjure a server tenant.
        if self.clients.is_empty() && self.servers.is_empty() && self.connect_to.is_empty() {
            return std::collections::HashMap::new();
        }
        let mut tenants = std::collections::HashMap::new();
        tenants.insert(
            "default".to_string(),
            DiameterTenant {
                identity: DiameterTenantIdentity {
                    origin_host: self.origin_host.clone(),
                    origin_realm: self.origin_realm.clone(),
                },
                clients: self.clients.clone(),
                servers: self.servers.clone(),
                connect_to: self.connect_to.clone(),
            },
        );
        tenants
    }
}

/// Inbound Diameter listener addresses for server mode.
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct DiameterListenConfig {
    /// TCP bind address, e.g. "0.0.0.0:3868".
    #[serde(default)]
    pub tcp: Option<String>,
    /// SCTP bind address, e.g. "0.0.0.0:3868".
    #[serde(default)]
    pub sctp: Option<String>,
}

/// A Diameter server tenant: its advertised identity, inbound clients, and
/// outbound servers. siphon does no routing — where a request goes is decided
/// by the script (`@diameter.on_request` + `forward_to`), so there is no
/// routing table here; the script sources its own (constants, a cache, an
/// external store, …).
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct DiameterTenant {
    pub identity: DiameterTenantIdentity,
    #[serde(default)]
    pub clients: Vec<DiameterClientEntry>,
    #[serde(default)]
    pub servers: Vec<DiameterServerEntry>,
    /// Outbound connections siphon **initiates** but **serves** inbound
    /// requests on — e.g. an HSS dialling a Diameter server, then answering the AIR/ULR
    /// the Diameter server relays back over that same connection. siphon sends the CER
    /// (this tenant's identity) and routes inbound requests to
    /// `@diameter.on_request`, exactly like the listener path. The transport
    /// direction is independent of the request direction (RFC 6733 §2.1).
    #[serde(default)]
    pub connect_to: Vec<DiameterServerEntry>,
}

/// The (origin_host, origin_realm) a tenant advertises in its CEA.
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct DiameterTenantIdentity {
    #[serde(default)]
    pub origin_host: String,
    #[serde(default)]
    pub origin_realm: String,
}

/// An inbound (client) peer the Diameter server accepts connections from.
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct DiameterClientEntry {
    pub name: String,
    /// Source IPs / CIDRs allowed to connect as this peer (ACL gate).
    #[serde(default)]
    pub allowed_ips: Vec<String>,
    /// Optional asserted-Origin-Host validator (exact match).
    #[serde(default)]
    pub expected_origin_host: Option<String>,
}

/// An outbound (server) peer the Diameter server relays to, using the tenant's identity.
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct DiameterServerEntry {
    pub name: String,
    pub host: String,
    #[serde(default = "default_diameter_port")]
    pub port: u16,
    #[serde(default = "default_diameter_transport")]
    pub transport: String,
}

/// Generic batched event sink (Python-emitted signalling events).
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct EventSinkConfig {
    /// "file" | "none" (v1). "clickhouse" / "kafka" are feature-gated stubs.
    #[serde(default = "default_event_sink_backend")]
    pub backend: String,
    #[serde(default)]
    pub file: Option<EventSinkFileConfig>,
}

/// File backend for the event sink (newline-delimited JSON).
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct EventSinkFileConfig {
    pub path: String,
}

fn default_event_sink_backend() -> String {
    "none".to_string()
}

/// A named Diameter peer endpoint.
#[derive(Debug, Deserialize, Clone)]
pub struct DiameterPeerEntry {
    /// Unique name for this peer (referenced in routes).
    pub name: String,
    /// Peer hostname or IP address.
    pub host: String,
    /// Peer Diameter port (default: 3868).
    #[serde(default = "default_diameter_port")]
    pub port: u16,
    /// Destination-Realm for this peer.
    pub destination_realm: String,
    /// Destination-Host (optional, for targeted routing).
    pub destination_host: Option<String>,
    /// Transport override: "tcp" or "sctp" (inherits parent default if absent).
    pub transport: Option<String>,
    /// Watchdog interval override in seconds.
    pub watchdog_interval: Option<u64>,
    /// Reconnect delay override in seconds.
    pub reconnect_delay: Option<u64>,
}

/// Maps a Diameter application to one or more peers.
#[derive(Debug, Deserialize, Clone)]
pub struct DiameterRouteEntry {
    /// Which Diameter application this route serves.
    pub application: DiameterApplication,
    /// Optional realm filter — only match requests for this destination realm.
    pub realm: Option<String>,
    /// Peer names in priority order.
    pub peers: Vec<String>,
    /// Selection algorithm: "failover" (default) or "round_robin".
    #[serde(default = "default_diameter_route_algorithm")]
    pub algorithm: String,
}

/// Supported Diameter application identifiers.
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DiameterApplication {
    Cx,
    Sh,
    Ro,
    Rf,
    Rx,
    /// S6c (TS 29.336) — SMSC ↔ HSS for SMS-over-Diameter.
    S6c,
    /// SGd (TS 29.338) — SMSC ↔ MME/SGSN for SMS-over-NAS delivery.
    Sgd,
    /// S6a (TS 29.272) — MME ↔ HSS for LTE attach/auth.
    S6a,
}

impl DiameterApplication {
    /// Map to (vendor_id, auth_application_id) tuple for CER/CEA.
    pub fn to_app_id(&self) -> (u32, u32) {
        use crate::diameter::dictionary;
        match self {
            Self::Cx => (dictionary::VENDOR_3GPP, dictionary::CX_APP_ID),
            Self::Sh => (dictionary::VENDOR_3GPP, dictionary::SH_APP_ID),
            Self::Rx => (dictionary::VENDOR_3GPP, dictionary::RX_APP_ID),
            Self::Ro => (0, dictionary::RO_APP_ID),
            Self::Rf => (0, dictionary::RF_APP_ID),
            Self::S6c => (dictionary::VENDOR_3GPP, dictionary::S6C_APP_ID),
            Self::Sgd => (dictionary::VENDOR_3GPP, dictionary::SGD_APP_ID),
            Self::S6a => (dictionary::VENDOR_3GPP, dictionary::S6A_APP_ID),
        }
    }
}

impl DiameterConfig {
    /// Look up the ordered peer entries for an application, optionally filtered by realm.
    pub fn peers_for_application(
        &self,
        application: &DiameterApplication,
        realm: Option<&str>,
    ) -> Vec<&DiameterPeerEntry> {
        for route in &self.routes {
            if &route.application != application {
                continue;
            }
            if let Some(ref route_realm) = route.realm {
                if let Some(requested_realm) = realm {
                    if route_realm != requested_realm {
                        continue;
                    }
                }
            }
            return route
                .peers
                .iter()
                .filter_map(|name| self.peers.iter().find(|p| &p.name == name))
                .collect();
        }
        Vec::new()
    }

    /// Build a `PeerConfig` for a specific peer entry.
    ///
    /// Application IDs are collected from all routes that reference this peer,
    /// so a single peer connection can advertise support for multiple interfaces
    /// (e.g., Cx + Sh on the same HSS).
    ///
    /// `product_name` and `product_version` are the values resolved by
    /// `SiphonServer::product()` — they back the Product-Name and
    /// Firmware-Revision AVPs when the YAML `diameter.product_name`
    /// override is unset.
    pub fn to_peer_config(
        &self,
        peer: &DiameterPeerEntry,
        product_name: &str,
        product_version: &str,
    ) -> crate::diameter::peer::PeerConfig {
        let application_ids: Vec<(u32, u32)> = self
            .routes
            .iter()
            .filter(|r| r.peers.contains(&peer.name))
            .map(|r| r.application.to_app_id())
            .collect();

        crate::diameter::peer::PeerConfig {
            host: peer.host.clone(),
            port: peer.port,
            origin_host: self.origin_host.clone(),
            origin_realm: self.origin_realm.clone(),
            destination_host: peer.destination_host.clone(),
            destination_realm: peer.destination_realm.clone(),
            local_ip: std::net::Ipv4Addr::UNSPECIFIED,
            application_ids,
            watchdog_interval: peer.watchdog_interval.unwrap_or(self.watchdog_interval),
            reconnect_delay: peer.reconnect_delay.unwrap_or(self.reconnect_delay),
            product_name: self.product_name.clone()
                .unwrap_or_else(|| product_name.to_string()),
            firmware_revision: crate::diameter::peer::version_to_firmware_revision(
                product_version,
            ),
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
    /// PostgreSQL / generic DB (planned).
    Database,
    /// REST lookup — GET `{url}` where `{username}` is substituted.
    /// Response body is either a plaintext password or a pre-hashed HA1.
    Http,
    /// Diameter Cx MAR → HSS (IMS S-CSCF, planned).
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
    /// TTL (seconds) for caching a successful credential lookup keyed by
    /// username. `0` (the default) disables caching — every digest
    /// verification performs a blocking HTTP fetch, so a registration storm
    /// translates 1:1 into blocking calls on the fixed Python executor pool.
    /// Set this (e.g. `300`) so repeated REGISTERs for the same subscriber
    /// reuse the cached HA1/password instead of re-hitting the backend.
    /// Credentials rarely change, so a non-zero TTL is the recommended
    /// production setting; a change propagates after at most `cache_ttl_secs`.
    #[serde(default)]
    pub cache_ttl_secs: u64,
}

fn default_http_timeout_ms() -> u64 {
    2000
}
fn default_http_connect_timeout_ms() -> u64 {
    500
}

// ---------------------------------------------------------------------------
// TLS server config (certificates — listeners are under `listen.tls`)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Clone)]
pub struct TlsServerConfig {
    pub certificate: String,
    pub private_key: String,
    #[serde(default = "default_tls_method")]
    pub method: String,
    /// If true, client certificates are required and verified against
    /// `client_ca`. Requires `client_ca` to be set, else startup fails.
    #[serde(default)]
    pub verify_client: bool,
    /// PEM bundle of CA certificates that client certificates must chain to,
    /// used only when `verify_client` is true (mutual TLS).
    #[serde(default)]
    pub client_ca: Option<String>,
    /// PEM certificate chain siphon presents as a TLS *client* on OUTBOUND
    /// connections when the upstream peer requests one (mutual TLS — upstream
    /// SIP trunks that require client-certificate auth). Optional; when unset,
    /// siphon presents no client certificate (prior behavior).
    #[serde(default)]
    pub client_certificate: Option<String>,
    /// PEM private key for `client_certificate`. Must be set if and only if
    /// `client_certificate` is set; a one-sided setting is a startup error.
    #[serde(default)]
    pub client_private_key: Option<String>,
}

fn default_tls_method() -> String {
    "TLSv1_3".to_owned()
}

// ---------------------------------------------------------------------------
// Security
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Clone)]
pub struct SecurityConfig {
    pub rate_limit: Option<RateLimitConfig>,
    pub scanner_block: Option<ScannerBlockConfig>,
    /// Source IPs/CIDRs that bypass rate limiting (e.g. internal AS, monitoring).
    #[serde(default)]
    pub trusted_cidrs: Vec<String>,
    /// Block source IP after N consecutive failed authentication attempts.
    pub failed_auth_ban: Option<FailedAuthBanConfig>,
    /// APIBAN community blocklist integration.
    pub apiban: Option<ApiBanConfig>,
    /// Kernel firewall: drop banned sources in the kernel via nf_tables so
    /// abusive traffic never reaches siphon's socket (Linux only, needs
    /// `CAP_NET_ADMIN`). Falls back to the userspace ACL when unavailable.
    pub firewall: Option<FirewallConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct FirewallConfig {
    /// nf_tables table name siphon owns (family `inet`). Default: `siphon`.
    #[serde(default = "default_firewall_table")]
    pub table: String,
    /// Set holding banned IPv4 sources. Default: `banned4`.
    #[serde(default = "default_firewall_set_v4")]
    pub set_v4: String,
    /// Set holding banned IPv6 sources. Default: `banned6`.
    #[serde(default = "default_firewall_set_v6")]
    pub set_v6: String,
    /// Base chain siphon adds the drop rules to. Default: `input`.
    #[serde(default = "default_firewall_chain")]
    pub chain: String,
    /// When true (the default), siphon also owns the chain + drop rules, so no
    /// manual `nft` step is needed — enabling `firewall` is enough. Set false to
    /// have siphon manage only the sets and reference them from your own ruleset.
    #[serde(default = "bool_true")]
    pub manage_rule: bool,
}

fn default_firewall_table() -> String {
    "siphon".to_string()
}
fn default_firewall_chain() -> String {
    "input".to_string()
}
fn default_firewall_set_v4() -> String {
    "banned4".to_string()
}
fn default_firewall_set_v6() -> String {
    "banned6".to_string()
}

#[derive(Debug, Deserialize, Clone)]
pub struct ApiBanConfig {
    /// API key from apiban.org.
    pub api_key: String,
    /// Poll interval in seconds (default: 300).
    #[serde(default = "default_apiban_interval_secs")]
    pub interval_secs: u64,
}

fn default_apiban_interval_secs() -> u64 {
    300
}

#[derive(Debug, Deserialize, Clone)]
pub struct RateLimitConfig {
    pub window_secs: u32,
    pub max_requests: u32,
    #[serde(default = "default_ban_duration_secs")]
    pub ban_duration_secs: u32,
}

fn default_ban_duration_secs() -> u32 {
    3600
}

#[derive(Debug, Deserialize, Clone)]
pub struct ScannerBlockConfig {
    #[serde(default)]
    pub user_agents: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct FailedAuthBanConfig {
    /// Number of failures (auth challenges without a subsequent success, or
    /// non-ACK INVITE server-transaction timeouts) within `window_secs` from a
    /// single source IP before it is banned.
    pub threshold: u32,
    /// Sliding window (seconds) over which failures are counted. A source that
    /// authenticates successfully has its failure count reset, so a legit client
    /// that challenges-then-succeeds never accumulates. Default: 600 (10 min).
    #[serde(default = "default_failed_auth_window_secs")]
    pub window_secs: u32,
    /// How long a ban lasts (seconds) before the source IP is allowed again.
    pub ban_duration_secs: u32,
    /// Weight applied to a single high-confidence abuse signal — present-but-
    /// invalid credentials (wrong password), a forged/stale/replayed digest
    /// nonce, non-SIP garbage on a stream transport, or a scanner User-Agent —
    /// toward `threshold`. A weight > 1 bans these unambiguous signals faster
    /// than a bare scanning probe (which counts as 1) while sharing the same
    /// per-IP window. Clamped to ≥ 1. Default: 3.
    #[serde(default = "default_strong_signal_weight")]
    pub strong_signal_weight: u32,
}

fn default_failed_auth_window_secs() -> u32 {
    600
}

fn default_strong_signal_weight() -> u32 {
    3
}

// ---------------------------------------------------------------------------
// NAT traversal
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Clone)]
pub struct NatConfig {
    /// Rewrite the Contact URI host:port on *responses* with the observed
    /// source address of the entity that sent the response (applied before
    /// `@proxy.on_reply` handlers run).
    ///
    /// Note: there is no `force_rport` / `fix_register` equivalent here.
    /// Responses are always routed symmetrically to the request's source
    /// (RFC 6314), so rport is effectively unconditional, and every
    /// `registrar.save()` already records the observed source for NAT
    /// routing — the REGISTER-side fixups are exposed as the explicit script
    /// methods `request.fix_nated_register()` / `fix_nated_contact()`.
    #[serde(default)]
    pub fix_contact: bool,
    /// Send periodic OPTIONS keep-alives to maintain NAT pinholes.
    pub keepalive: Option<NatKeepaliveConfig>,
    /// RFC 5626 §4.4.1 CRLF keep-alive for persistent connections (TCP/TLS).
    pub crlf_keepalive: Option<CrlfKeepaliveConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct NatKeepaliveConfig {
    #[serde(default = "bool_true")]
    pub enabled: bool,
    /// Interval between OPTIONS pings (seconds).
    #[serde(default = "default_keepalive_interval")]
    pub interval_secs: u32,
    /// Deregister contact after this many consecutive failed pings.
    #[serde(default = "default_keepalive_failure_threshold")]
    pub failure_threshold: u32,
}

fn bool_true() -> bool {
    true
}
fn default_keepalive_interval() -> u32 {
    30
}
fn default_keepalive_failure_threshold() -> u32 {
    10
}

/// RFC 5626 §4.4.1 CRLF keepalive for connection-oriented transports.
#[derive(Debug, Deserialize, Clone)]
pub struct CrlfKeepaliveConfig {
    #[serde(default = "bool_true")]
    pub enabled: bool,
    /// Interval between CRLF pings (seconds).  RFC 5626 recommends 20-30s.
    #[serde(default = "default_crlf_keepalive_interval")]
    pub interval_secs: u32,
    /// Close connection after this many consecutive missed pongs.
    #[serde(default = "default_crlf_keepalive_failure_threshold")]
    pub failure_threshold: u32,
}

fn default_crlf_keepalive_interval() -> u32 {
    30
}

fn default_crlf_keepalive_failure_threshold() -> u32 {
    3
}

// ---------------------------------------------------------------------------
// SIP tracing via HEP (Homer / captAgent)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Clone)]
pub struct TracingConfig {
    pub hep: Option<HepConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct HepConfig {
    /// Endpoint of the captAgent/Homer collector (e.g. "127.0.0.1:9060").
    pub endpoint: String,
    #[serde(default = "default_hep_version")]
    pub version: u8,
    #[serde(default = "default_hep_transport")]
    pub transport: HepTransport,
    /// Label shown in Homer for this agent — use different values per node type.
    pub agent_id: Option<String>,
    /// CA certificate file for TLS transport (PEM format).
    /// When omitted with TLS transport, the system root CAs are used.
    pub ca_cert: Option<String>,
    /// Server name for TLS SNI. Defaults to the hostname from `endpoint`.
    pub tls_server_name: Option<String>,
    /// Minimum interval (in seconds) between repeated error log messages.
    /// Prevents log flooding when the collector is unreachable. Default: 30.
    #[serde(default = "default_hep_error_log_interval")]
    pub error_log_interval: u64,
}

fn default_hep_error_log_interval() -> u64 {
    30
}

fn default_hep_version() -> u8 {
    3
}

fn default_hep_transport() -> HepTransport {
    HepTransport::Udp
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum HepTransport {
    Udp,
    Tcp,
    Tls,
}

// ---------------------------------------------------------------------------
// Prometheus metrics
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Clone)]
pub struct MetricsConfig {
    pub prometheus: Option<PrometheusConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PrometheusConfig {
    /// Address to expose the /metrics endpoint on (e.g. "0.0.0.0:8888").
    pub listen: String,
    #[serde(default = "default_metrics_path")]
    pub path: String,
}

fn default_metrics_path() -> String {
    "/metrics".to_owned()
}

// ---------------------------------------------------------------------------
// HTTP admin API
// ---------------------------------------------------------------------------

/// HTTP admin API listener. Exposes liveness/readiness probes and registration
/// inspection on a dedicated port:
///   `GET /admin/health`              liveness — 200 while the process is alive
///   `GET /admin/ready`               readiness — 200, or 503 while draining
///   `GET /admin/stats`               uptime + active registration count
///   `GET /admin/registrations`       list all AoRs + contacts
///   `GET /admin/registrations/{aor}` one AoR's contacts
///   `DELETE /admin/registrations/{aor}` force-unregister an AoR
///   `GET /admin/bans`                list active auto-bans + remaining TTL
///   `DELETE /admin/bans/{ip}`        lift an auto-ban (also clears the kernel set)
///   `GET /metrics`                   Prometheus scrape (same body as the metrics port)
#[derive(Debug, Deserialize, Clone)]
pub struct AdminConfig {
    /// Address to expose the admin API on (e.g. "0.0.0.0:9091").
    pub listen: String,
}

// ---------------------------------------------------------------------------
// Server identity headers
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Clone)]
pub struct ServerIdentityConfig {
    pub server_header: Option<String>,
    pub user_agent_header: Option<String>,
    /// Graceful drain on SIGTERM/SIGINT: stop accepting new INVITEs and wait
    /// up to this many seconds for in-flight transactions and B2BUA calls to
    /// finish before exiting. Default: 30s. Set to 0 to disable drain (exit
    /// immediately on signal).
    #[serde(default = "default_drain_secs")]
    pub drain_secs: u64,
    /// Stable per-replica identity, stamped onto every accepted REGISTER
    /// binding so scripts can recognise their own bindings after restart.
    /// Recommended: ``"${POD_NAME:-${HOSTNAME}}"`` for K8s StatefulSet
    /// deployments.  When unset, siphon falls back to the ``HOSTNAME``
    /// environment variable, then to ``"siphon"`` as a last resort.
    pub instance_id: Option<String>,
}

fn default_drain_secs() -> u64 {
    30
}

// ---------------------------------------------------------------------------
// Transaction layer timers
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Clone)]
pub struct TransactionConfig {
    /// Non-INVITE transaction timeout (fr_timeout). Default: 5s.
    #[serde(default = "default_tx_timeout")]
    pub timeout_secs: u32,
    /// INVITE transaction timeout (fr_inv_timeout). Default: 30s.
    #[serde(default = "default_tx_invite_timeout")]
    pub invite_timeout_secs: u32,
    /// Auto-emit `100 Trying` on slow non-INVITE server transactions to
    /// suppress UAC retransmits (MESSAGE/SUBSCRIBE/OPTIONS/BYE relays).
    /// Default: true. Timing is governed by RFC 4320 §4.2 — see
    /// `auto_emit_100_trying_delay_ms`.
    #[serde(default = "default_auto_emit_100_trying")]
    pub auto_emit_100_trying: bool,
    /// Delay before the non-INVITE auto-100 fires **over a reliable transport**
    /// (TCP/TLS), where RFC 4320 §4.2 permits a 100 at any time. Default: 200ms.
    /// Over UDP this value is ignored: RFC 4320 §4.2 forbids a 100 to a
    /// non-INVITE before the UAC's Timer E is reset to T2 (≈3.5s with default
    /// timers), so the delay there is derived from T1/T2, not this field. This
    /// is why an in-dialog BYE answered in milliseconds never draws a 100.
    #[serde(default = "default_auto_emit_100_trying_delay_ms")]
    pub auto_emit_100_trying_delay_ms: u64,
}

fn default_tx_timeout() -> u32 {
    5
}
fn default_tx_invite_timeout() -> u32 {
    30
}
fn default_auto_emit_100_trying() -> bool {
    true
}
fn default_auto_emit_100_trying_delay_ms() -> u64 {
    200
}

// ---------------------------------------------------------------------------
// Dialog tracking
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Clone)]
pub struct DialogConfig {
    #[serde(default = "default_dialog_backend")]
    pub backend: DialogBackendType,
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum DialogBackendType {
    Memory,
    Redis,
    Postgres,
}

fn default_dialog_backend() -> DialogBackendType {
    DialogBackendType::Memory
}

// ---------------------------------------------------------------------------
// Named cache connections (accessible from Python scripts via cache.fetch)
// ---------------------------------------------------------------------------

/// A named cache backend available to Python scripts.
///
/// In the script: `from siphon import cache` then `await cache.fetch("myconn", key)`.
///
/// Example siphon.yaml:
/// ```yaml
/// cache:
///   - name: "cnam"
///     url: "redis://172.16.0.252:6379"
///     local_ttl_secs: 60
///     local_max_entries: 10000
/// ```
#[derive(Debug, Deserialize, Clone)]
pub struct NamedCacheConfig {
    /// Identifier used in `cache.fetch(name, key)` calls.
    pub name: String,
    /// Redis URL (currently the only supported backend).
    pub url: String,
    /// If set, a local LRU cache is maintained in front of Redis.
    pub local_ttl_secs: Option<u64>,
    pub local_max_entries: Option<usize>,
}

// ---------------------------------------------------------------------------
// Media (RTPEngine)
// ---------------------------------------------------------------------------

/// Media proxy configuration.
#[derive(Debug, Deserialize, Clone)]
pub struct MediaConfig {
    /// RTPEngine instance(s). A single instance or a list for load-balancing / HA.
    pub rtpengine: RtpEngineSetConfig,
    /// Custom media profiles (name → offer/answer NG flags).
    /// Built-in profiles (srtp_to_rtp, ws_to_rtp, wss_to_rtp, rtp_passthrough)
    /// are always available; custom entries here extend or override them.
    #[serde(default)]
    pub profiles: std::collections::HashMap<String, MediaProfileConfig>,
    /// Name used in SDP `o=` and `s=` lines when sanitizing relayed SDP.
    /// Hides the remote endpoint's identity (e.g. "FreeSWITCH") from the other leg.
    /// Defaults to "SIPhon" if not set.
    pub sdp_name: Option<String>,
    /// Optional inbound event listener for rtpengine async notifications
    /// (DTMF, etc.).  Configure rtpengine with `dtmf-log-ng-tcp-uri=tcp://<this>`
    /// to make it deliver bencode-framed events here.
    pub events: Option<RtpEngineEventsConfig>,
    /// Interval in seconds between rtpengine NG `ping` health probes.
    /// The result is published as `siphon_rtpengine_instances_up` (count of
    /// healthy instances) and `siphon_rtpengine_instance_up{address}` (per
    /// instance 0/1).  Set to `0` to disable probing entirely.
    /// Default: 5.
    #[serde(default = "default_rtpengine_health_check_interval_secs")]
    pub health_check_interval_secs: u64,
}

fn default_rtpengine_health_check_interval_secs() -> u64 {
    5
}

/// Configuration for siphon's inbound listener that accepts rtpengine's
/// async event notifications (DTMF, etc.) over NG-protocol TCP.
#[derive(Debug, Deserialize, Clone)]
pub struct RtpEngineEventsConfig {
    /// Socket address to listen on (e.g. ``"0.0.0.0:22226"``).
    pub listen_addr: String,
}

/// A user-defined RTPEngine media profile with separate offer/answer NG flags.
#[derive(Debug, Deserialize, Clone)]
pub struct MediaProfileConfig {
    pub offer: NgFlagsConfig,
    pub answer: NgFlagsConfig,
}

/// NG protocol flags for one direction (offer or answer).
#[derive(Debug, Deserialize, Clone)]
pub struct NgFlagsConfig {
    /// Transport protocol override (e.g. "RTP/AVP", "RTP/SAVPF").
    pub transport_protocol: Option<String>,
    /// ICE handling: "remove", "force", or "force-relay".
    pub ice: Option<String>,
    /// DTLS mode: "passive", "active", or "off".
    pub dtls: Option<String>,
    /// SDP fields to replace: "origin".
    #[serde(default)]
    pub replace: Vec<String>,
    /// Additional flags: "trust-address", "symmetric", "asymmetric".
    #[serde(default)]
    pub flags: Vec<String>,
    /// Direction pair for NAT traversal: ["external", "internal"].
    #[serde(default)]
    pub direction: Vec<String>,
    /// Enable call recording in RTPEngine.
    #[serde(default)]
    pub record_call: bool,
    /// Directory path for RTPEngine to write recording files.
    pub record_path: Option<String>,
}

/// One or more RTPEngine instances.
///
/// Accepts either a single instance or a list:
/// ```yaml
/// # Single instance:
/// media:
///   rtpengine:
///     address: "127.0.0.1:22222"
///
/// # Multiple instances (round-robin selection):
/// media:
///   rtpengine:
///     instances:
///       - address: "10.0.0.1:22222"
///         weight: 2
///       - address: "10.0.0.2:22222"
///         weight: 1
/// ```
#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum RtpEngineSetConfig {
    /// A single RTPEngine instance (shorthand).
    Single(RtpEngineInstanceConfig),
    /// Multiple instances with optional weights for load-balancing.
    Set { instances: Vec<RtpEngineInstanceConfig> },
}

impl RtpEngineSetConfig {
    /// Return all configured instances as a slice-compatible vec.
    pub fn instances(&self) -> Vec<&RtpEngineInstanceConfig> {
        match self {
            RtpEngineSetConfig::Single(instance) => vec![instance],
            RtpEngineSetConfig::Set { instances } => instances.iter().collect(),
        }
    }
}

/// Configuration for a single RTPEngine instance.
#[derive(Debug, Deserialize, Clone)]
pub struct RtpEngineInstanceConfig {
    /// NG control protocol address (e.g. "127.0.0.1:22222").
    pub address: String,
    /// Timeout in milliseconds for NG protocol responses.
    #[serde(default = "default_rtpengine_timeout_ms")]
    pub timeout_ms: u64,
    /// Weight for load-balancing (higher = more traffic). Default: 1.
    #[serde(default = "default_rtpengine_weight")]
    pub weight: u32,
}

fn default_rtpengine_timeout_ms() -> u64 {
    1000
}

fn default_rtpengine_weight() -> u32 {
    1
}

// ---------------------------------------------------------------------------
// Gateway dispatcher
// ---------------------------------------------------------------------------

/// Gateway dispatcher configuration.
///
/// Example siphon.yaml:
/// ```yaml
/// gateway:
///   groups:
///     - name: "carriers"
///       algorithm: weighted
///       probe:
///         enabled: true
///         interval_secs: 15
///         failure_threshold: 3
///       destinations:
///         - uri: "sip:gw1.carrier.com:5060"
///           address: "10.0.0.1:5060"
///           weight: 3
///           attrs: { region: "us-east" }
///         - uri: "sip:gw2.carrier.com:5060"
///           address: "10.0.0.2:5060"
///           priority: 2
/// ```
#[derive(Debug, Deserialize, Clone)]
pub struct GatewayConfig {
    /// Named destination groups.
    pub groups: Vec<GatewayGroupConfig>,
}

/// A named group of destinations.
#[derive(Debug, Deserialize, Clone)]
pub struct GatewayGroupConfig {
    /// Group name — used in `gateway.select("name")`.
    pub name: String,
    /// Load-balancing algorithm: "round_robin", "weighted" (default), "hash".
    #[serde(default = "default_gateway_algorithm")]
    pub algorithm: String,
    /// Per-group health probe configuration.
    #[serde(default)]
    pub probe: GatewayProbeConfig,
    /// Destinations in this group.
    pub destinations: Vec<GatewayDestConfig>,
}

/// Per-group health probe settings.
#[derive(Debug, Deserialize, Clone)]
pub struct GatewayProbeConfig {
    /// Enable SIP OPTIONS probing. Default: true.
    #[serde(default = "bool_true")]
    pub enabled: bool,
    /// Probe interval in seconds. Default: 30.
    #[serde(default = "default_gateway_probe_interval")]
    pub interval_secs: u32,
    /// Consecutive failures before marking down. Default: 3.
    #[serde(default = "default_gateway_failure_threshold")]
    pub failure_threshold: u32,
    /// User part for the From URI in OPTIONS probes. Default: `"siphon"`.
    pub from_user: Option<String>,
    /// Host part for the From URI in OPTIONS probes. Default: local IP.
    pub from_domain: Option<String>,
}

impl Default for GatewayProbeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: 30,
            failure_threshold: 3,
            from_user: None,
            from_domain: None,
        }
    }
}

/// A single destination in a group.
#[derive(Debug, Deserialize, Clone)]
pub struct GatewayDestConfig {
    /// SIP URI to route to (e.g. "sip:gw1.carrier.com:5060;transport=tls").
    /// Port and transport can be embedded in the URI and will be derived
    /// automatically when `address` / `transport` fields are omitted.
    pub uri: String,
    /// Socket address for sending (e.g. "10.0.0.1:5060").
    /// If omitted, resolved from the URI hostname.
    #[serde(default)]
    pub address: Option<String>,
    /// Transport protocol: "udp", "tcp", "tls".
    /// If omitted, derived from URI `;transport=` param (default: "udp").
    #[serde(default)]
    pub transport: Option<String>,
    /// Weight for weighted round-robin (higher = more traffic). Default: 1.
    #[serde(default = "default_gateway_weight")]
    pub weight: u32,
    /// Priority group (lower = higher priority, for failover tiers). Default: 1.
    #[serde(default = "default_gateway_priority")]
    pub priority: u32,
    /// User-defined attributes (e.g. {"region": "us-east"}).
    #[serde(default)]
    pub attrs: std::collections::HashMap<String, String>,
}

impl GatewayDestConfig {
    /// Return the effective transport string: explicit field, URI `;transport=`
    /// param, or `"udp"` as default.
    pub fn effective_transport(&self) -> String {
        if let Some(ref transport) = self.transport {
            return transport.clone();
        }
        let uri_lower = self.uri.to_lowercase();
        if let Some(pos) = uri_lower.find(";transport=") {
            let after = &uri_lower[pos + 11..];
            let end = after
                .find([';', '>', ' '])
                .unwrap_or(after.len());
            return after[..end].to_string();
        }
        "udp".to_string()
    }
}

fn default_gateway_algorithm() -> String {
    "weighted".to_string()
}
fn default_gateway_probe_interval() -> u32 {
    30
}
fn default_gateway_failure_threshold() -> u32 {
    3
}
fn default_gateway_weight() -> u32 {
    1
}
fn default_gateway_priority() -> u32 {
    1
}

// ---------------------------------------------------------------------------
// Session timers (RFC 4028)
// ---------------------------------------------------------------------------

/// RFC 4028 session timer configuration for B2BUA mode.
///
/// Session timers prevent resource leaks from calls whose BYE was lost.
/// The B2BUA sends periodic re-INVITEs to keep the session alive and tears
/// down calls that fail to refresh within the negotiated interval.
///
/// Example siphon.yaml:
/// ```yaml
/// session_timer:
///   session_expires: 1800
///   min_se: 90
///   refresher: uac
///   enabled: true
/// ```
#[derive(Debug, Deserialize, Clone)]
pub struct SessionTimerConfig {
    /// Default Session-Expires value in seconds. Default: 1800 (30 minutes).
    #[serde(default = "default_session_expires")]
    pub session_expires: u32,
    /// Minimum acceptable Session-Expires (Min-SE header). Default: 90.
    #[serde(default = "default_min_se")]
    pub min_se: u32,
    /// Who sends the refresh re-INVITE: uac (default) or uas.
    #[serde(default = "default_refresher")]
    pub refresher: SessionRefresher,
    /// Enable/disable session timers entirely. Default: true.
    #[serde(default = "bool_true")]
    pub enabled: bool,
}

/// Who is responsible for sending refresh re-INVITEs (RFC 4028).
#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SessionRefresher {
    /// The calling party (UAC) refreshes (default).
    Uac,
    /// The called party (UAS) refreshes.
    Uas,
    /// The B2BUA itself handles refresh re-INVITEs on both legs.
    B2bua,
}

fn default_session_expires() -> u32 {
    1800
}

fn default_min_se() -> u32 {
    90
}

fn default_refresher() -> SessionRefresher {
    SessionRefresher::Uac
}

// ---------------------------------------------------------------------------
// Rf offline charging (3GPP TS 32.299)
// ---------------------------------------------------------------------------

/// Top-level `rf:` configuration.
///
/// ```yaml
/// rf:
///   enabled: true
///   auto_emit_proxy: true        # ACR-START on 2xx-forward, ACR-STOP on in-dialog BYE
///   auto_emit_b2bua: true        # ACR-START on Answered, ACR-STOP on Bye/Terminated
///   auto_emit_register: true     # ACR-EVENT from registrar on_change
///   interim_interval_secs: 300   # 0 = disabled; CDF ACA-START Acct-Interim-Interval overrides
///   node_functionality: scscf    # scscf | pcscf | icscf | mrfc | mgcf | bgcf | as | ibcf
///   service_context_id: "32260@3gpp.org"   # TS 32.260 IMS = 32260, MMTel SC = 32274
///   peer: cdf1                   # optional explicit peer; default = first 'rf' route, else any peer
/// ```
#[derive(Debug, Deserialize, Clone)]
pub struct RfConfig {
    /// Master switch.  Default: false.
    #[serde(default)]
    pub enabled: bool,
    /// Emit ACR-START / ACR-INTERIM / ACR-STOP automatically from the
    /// proxy 2xx-forward and in-dialog-BYE paths.  Default: true.
    #[serde(default = "default_true")]
    pub auto_emit_proxy: bool,
    /// Emit ACR-START / ACR-INTERIM / ACR-STOP automatically from B2BUA
    /// `CallEvent::Answered` / `Bye` / `Terminated`.  Default: true.
    #[serde(default = "default_true")]
    pub auto_emit_b2bua: bool,
    /// Emit ACR-EVENT for every registration state change observed on
    /// the registrar's on-change broadcast channel.  Default: true.
    #[serde(default = "default_true")]
    pub auto_emit_register: bool,
    /// Default ACR-INTERIM cadence in seconds when the CDF does not
    /// return an ``Acct-Interim-Interval`` AVP in ACA-START.  Set to 0
    /// to disable periodic INTERIM.  Default: 0 (disabled).
    #[serde(default)]
    pub interim_interval_secs: u32,
    /// Node-Functionality value baked into auto-emitted records
    /// (TS 32.299 §7.2.111 — `scscf`, `pcscf`, `icscf`, `mrfc`, `mgcf`,
    /// `bgcf`, `as`, `ibcf`, `ecscf`, `atcf`, `mmtel`, `tpf`, `atgw`).
    /// Default: ``"scscf"``.
    #[serde(default = "default_rf_node_functionality")]
    pub node_functionality: String,
    /// Service-Context-Id (TS 32.299 §7.2.91).  Default:
    /// ``"32260@3gpp.org"`` (TS 32.260 IMS).
    #[serde(default = "default_rf_service_context_id")]
    pub service_context_id: String,
    /// Explicit Diameter peer name to send ACRs to.  When unset, the
    /// first peer registered with the manager is used (`any_client`).
    pub peer: Option<String>,
}

impl Default for RfConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            auto_emit_proxy: true,
            auto_emit_b2bua: true,
            auto_emit_register: true,
            interim_interval_secs: 0,
            node_functionality: default_rf_node_functionality(),
            service_context_id: default_rf_service_context_id(),
            peer: None,
        }
    }
}

fn default_true() -> bool { true }
fn default_rf_node_functionality() -> String { "scscf".to_string() }
fn default_rf_service_context_id() -> String { "32260@3gpp.org".to_string() }

// ---------------------------------------------------------------------------
// CDR (Call Detail Records)
// ---------------------------------------------------------------------------

/// CDR configuration in `siphon.yaml`.
///
/// ```yaml
/// cdr:
///   enabled: true
///   include_register: false
///   channel_size: 10000
///   backend: file
///   file:
///     path: "/var/log/siphon/cdr.jsonl"
///     rotate_size_mb: 100
///   # -- or --
///   backend: syslog
///   syslog:
///     target: "10.0.0.5:514"
///   # -- or --
///   backend: http
///   http:
///     url: "https://collector.example.com/v1/cdr"
///     auth_header: "Bearer tok123"
/// ```
#[derive(Debug, Deserialize, Clone)]
pub struct CdrYamlConfig {
    /// Enable CDR generation. Default: false.
    #[serde(default)]
    pub enabled: bool,
    /// Automatically emit a CDR per call on lifecycle events (INVITE answer →
    /// BYE, plus failed/cancelled/timed-out calls) without the script calling
    /// `cdr.write()`. Default: false — existing manual-only deployments are
    /// unchanged; opt in to get call CDRs for free. Manual `cdr.write()` still
    /// works and is additive.
    #[serde(default)]
    pub auto_emit: bool,
    /// Include REGISTER events as CDRs. Only meaningful with `auto_emit: true`
    /// — when set, each registrar state change emits a REGISTER CDR. Default:
    /// false.
    #[serde(default)]
    pub include_register: bool,
    /// Async channel buffer size. Default: 10000.
    #[serde(default = "default_cdr_channel_size")]
    pub channel_size: usize,
    /// Backend type: "file", "syslog", or "http".
    #[serde(default = "default_cdr_backend")]
    pub backend: String,
    /// File backend settings.
    pub file: Option<CdrFileConfig>,
    /// Syslog backend settings.
    pub syslog: Option<CdrSyslogConfig>,
    /// HTTP webhook backend settings.
    pub http: Option<CdrHttpConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CdrFileConfig {
    /// Path to the JSON-lines CDR file.
    #[serde(default = "default_cdr_file_path")]
    pub path: String,
    /// Rotate when file exceeds this size (MB). Default: 100.
    #[serde(default = "default_cdr_rotate_size")]
    pub rotate_size_mb: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CdrSyslogConfig {
    /// UDP syslog target (host:port).
    pub target: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CdrHttpConfig {
    /// HTTP(S) endpoint URL for POST.
    pub url: String,
    /// Optional Authorization header value.
    pub auth_header: Option<String>,
}

impl CdrYamlConfig {
    /// Convert YAML config into runtime `CdrConfig`.
    pub fn to_cdr_config(&self) -> crate::cdr::CdrConfig {
        let backend = match self.backend.as_str() {
            "syslog" => {
                let target = self.syslog.as_ref()
                    .map(|s| s.target.clone())
                    .unwrap_or_else(|| "127.0.0.1:514".to_string());
                crate::cdr::CdrBackendType::Syslog { target }
            }
            "http" => {
                let (url, auth_header) = self.http.as_ref()
                    .map(|h| (h.url.clone(), h.auth_header.clone()))
                    .unwrap_or_else(|| ("http://127.0.0.1:9080/cdr".to_string(), None));
                crate::cdr::CdrBackendType::Http { url, auth_header }
            }
            _ => {
                let (path, rotate_size_mb) = self.file.as_ref()
                    .map(|f| (f.path.clone(), f.rotate_size_mb))
                    .unwrap_or_else(|| (default_cdr_file_path(), default_cdr_rotate_size()));
                crate::cdr::CdrBackendType::File { path, rotate_size_mb }
            }
        };

        crate::cdr::CdrConfig {
            enabled: self.enabled,
            backend,
            auto_emit: self.auto_emit,
            include_register: self.include_register,
            channel_size: self.channel_size,
        }
    }
}

fn default_cdr_channel_size() -> usize {
    10_000
}

fn default_cdr_backend() -> String {
    "file".to_string()
}

fn default_cdr_file_path() -> String {
    "/var/log/siphon/cdr.jsonl".to_string()
}

fn default_cdr_rotate_size() -> u64 {
    100
}

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

// ---------------------------------------------------------------------------
// Lawful Intercept — ETSI X1/X2/X3 + SIPREC
// ---------------------------------------------------------------------------

/// Top-level `lawful_intercept:` configuration.
///
/// ```yaml
/// lawful_intercept:
///   enabled: false
///   audit_log: "/var/log/siphon/li-audit.log"
///   x1:
///     listen: "127.0.0.1:8443"
///     tls:
///       certificate: "/etc/siphon/li/x1.crt"
///       private_key: "/etc/siphon/li/x1.key"
///       verify_client: true
///     auth_token: "warrant-auth-xyz"
///   x2:
///     delivery_address: "10.0.0.50:6543"
///     transport: tcp
///     reconnect_interval_secs: 5
///     channel_size: 10000
///   x3:
///     listen_udp: "127.0.0.1:0"
///     delivery_address: "10.0.0.50:6544"
///     transport: udp
///     encapsulation: etsi
///   siprec:
///     srs_uri: "sip:srs@recorder.example.com"
///     session_copies: 1
/// ```
#[derive(Debug, Deserialize, Clone)]
pub struct LawfulInterceptConfig {
    /// Master switch — disabled by default.
    #[serde(default)]
    pub enabled: bool,
    /// Mandatory audit trail log file. Every X1 operation is recorded here.
    pub audit_log: Option<String>,
    /// X1: ETSI TS 103 221-1 admin interface for intercept provisioning.
    pub x1: Option<LiX1Config>,
    /// X2: ETSI TS 102 232 IRI (signaling event) delivery.
    pub x2: Option<LiX2Config>,
    /// X3: ETSI TS 102 232 CC (media content) delivery via RTPEngine.
    pub x3: Option<LiX3Config>,
    /// SIPREC: RFC 7866 SIP-based media recording.
    pub siprec: Option<LiSiprecConfig>,
}

/// X1 admin interface — separate HTTPS listener with mTLS.
#[derive(Debug, Deserialize, Clone)]
pub struct LiX1Config {
    /// Bind address for X1 HTTPS API (e.g. "127.0.0.1:8443").
    pub listen: String,
    /// TLS settings (mTLS recommended for LEA authentication).
    pub tls: Option<LiTlsConfig>,
    /// Optional bearer token for additional authentication.
    pub auth_token: Option<String>,
}

/// X2 IRI delivery — ASN.1/BER encoded signaling events over TCP/TLS.
#[derive(Debug, Deserialize, Clone)]
pub struct LiX2Config {
    /// Mediation device IRI collector address (host:port).
    pub delivery_address: String,
    /// Transport: "tcp" or "tls". Default: "tcp".
    #[serde(default = "default_li_x2_transport")]
    pub transport: String,
    /// Reconnect interval on connection loss. Default: 5.
    #[serde(default = "default_li_reconnect_interval")]
    pub reconnect_interval_secs: u64,
    /// Async channel buffer size. Default: 10000.
    #[serde(default = "default_li_channel_size")]
    pub channel_size: usize,
    /// TLS settings for X2 delivery (when transport = "tls").
    pub tls: Option<LiTlsConfig>,
}

/// X3 CC delivery — RTPEngine recording mirror + encapsulation to mediation.
#[derive(Debug, Deserialize, Clone)]
pub struct LiX3Config {
    /// Local UDP address to receive mirrored RTP from RTPEngine.
    /// Default: "127.0.0.1:0" (OS-assigned port).
    #[serde(default = "default_li_x3_listen")]
    pub listen_udp: String,
    /// Mediation device CC collector address (host:port).
    pub delivery_address: String,
    /// Transport: "udp" or "tcp". Default: "udp".
    #[serde(default = "default_li_x3_transport")]
    pub transport: String,
    /// Encapsulation format: "etsi" (TS 102 232 CC-PDU) or "raw_ip".
    #[serde(default = "default_li_x3_encapsulation")]
    pub encapsulation: String,
}

/// SIPREC (RFC 7866) — SIP-based media recording.
#[derive(Debug, Deserialize, Clone)]
pub struct LiSiprecConfig {
    /// SIP Recording Server URI (e.g. "sip:srs@recorder.example.com").
    pub srs_uri: String,
    /// Number of parallel recording sessions per call. Default: 1.
    #[serde(default = "default_siprec_session_copies")]
    pub session_copies: u32,
    /// Transport for SRS INVITE: "udp", "tcp", or "tls". Default: "tcp".
    #[serde(default = "default_siprec_transport")]
    pub transport: String,
    /// RTPEngine media profile for subscribe (media fork) commands. Default: "siprec_src".
    #[serde(default = "default_siprec_src_profile")]
    pub rtpengine_profile: String,
}

/// TLS configuration for LI interfaces (X1 admin, X2/X3 delivery).
#[derive(Debug, Deserialize, Clone)]
pub struct LiTlsConfig {
    /// Path to TLS certificate file.
    pub certificate: Option<String>,
    /// Path to TLS private key file.
    pub private_key: Option<String>,
    /// CA certificate for verifying the remote peer.
    pub ca_cert: Option<String>,
    /// Require client certificate (mTLS). Default: false.
    #[serde(default)]
    pub verify_client: bool,
    /// SNI server name for outbound TLS connections.
    pub server_name: Option<String>,
}

fn default_li_x2_transport() -> String { "tcp".to_string() }
fn default_li_reconnect_interval() -> u64 { 5 }
fn default_li_channel_size() -> usize { 10_000 }
fn default_li_x3_listen() -> String { "127.0.0.1:0".to_string() }
fn default_li_x3_transport() -> String { "udp".to_string() }
fn default_li_x3_encapsulation() -> String { "etsi".to_string() }
fn default_siprec_session_copies() -> u32 { 1 }
fn default_siprec_transport() -> String { "tcp".to_string() }
fn default_siprec_src_profile() -> String { "siprec_src".to_string() }

// ---------------------------------------------------------------------------
// SRS — Session Recording Server
// ---------------------------------------------------------------------------

/// Session Recording Server (SIPREC SRS) — RFC 7866.
///
/// When enabled, SIPhon accepts inbound SIPREC INVITEs from external SRCs,
/// parses the recording metadata, captures audio via RTPEngine, and stores
/// recordings + metadata.
///
/// ```yaml
/// srs:
///   enabled: true
///   recording_dir: "/var/lib/siphon/recordings"
///   max_sessions: 1000
///   backend: file
///   file:
///     base_dir: "/var/lib/siphon/recordings"
///   http:
///     url: "https://api.example.com/recordings"
///     auth_header: "Bearer tok123"
///     upload_audio: false
///   rtpengine_profile: "srs_recording"
/// ```
#[derive(Debug, Deserialize, Clone)]
pub struct SrsConfig {
    /// Enable SRS functionality. Default: false.
    #[serde(default)]
    pub enabled: bool,
    /// Directory for recording files (RTPEngine writes here). Default: "/var/lib/siphon/recordings".
    #[serde(default = "default_srs_recording_dir")]
    pub recording_dir: String,
    /// Maximum concurrent recording sessions. Default: 1000.
    #[serde(default = "default_srs_max_sessions")]
    pub max_sessions: usize,
    /// Backend type: "file" or "http". Default: "file".
    #[serde(default = "default_srs_backend")]
    pub backend: String,
    /// File backend settings.
    pub file: Option<SrsFileConfig>,
    /// HTTP webhook backend settings.
    pub http: Option<SrsHttpConfig>,
    /// RTPEngine media profile to use for recording. Default: "srs_recording".
    #[serde(default = "default_srs_rtpengine_profile")]
    pub rtpengine_profile: String,
}

/// SRS file backend — writes JSON metadata alongside audio files.
#[derive(Debug, Deserialize, Clone)]
pub struct SrsFileConfig {
    /// Base directory for metadata JSON files.
    #[serde(default = "default_srs_recording_dir")]
    pub base_dir: String,
}

/// SRS HTTP webhook backend — POSTs recording metadata on session end.
#[derive(Debug, Deserialize, Clone)]
pub struct SrsHttpConfig {
    /// HTTP(S) endpoint URL for POST.
    pub url: String,
    /// Optional Authorization header value.
    pub auth_header: Option<String>,
    /// Upload audio files alongside metadata. Default: false.
    #[serde(default)]
    pub upload_audio: bool,
}

fn default_srs_recording_dir() -> String { "/var/lib/siphon/recordings".to_string() }
fn default_srs_max_sessions() -> usize { 1000 }
fn default_srs_backend() -> String { "file".to_string() }
fn default_srs_rtpengine_profile() -> String { "srs_recording".to_string() }

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct LogConfig {
    pub level: LogLevel,
    pub format: LogFormat,
    /// Optional path to a log file (e.g. `/var/log/siphon.log`).
    /// When set, logs are written to both stderr and the file.
    pub file: Option<String>,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            format: LogFormat::Pretty,
            file: None,
        }
    }
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Pretty,
    Json,
}

// ---------------------------------------------------------------------------
// Config loading
// ---------------------------------------------------------------------------

impl Config {
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let content = std::fs::read_to_string(path.as_ref()).map_err(|e| {
            SiphonError::Config(format!("cannot read siphon.yaml: {e}"))
        })?;
        let expanded = expand_env_vars(&content);
        Self::from_str_raw(&expanded)
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(yaml: &str) -> Result<Self> {
        let expanded = expand_env_vars(yaml);
        Self::from_str_raw(&expanded)
    }

    /// Parse YAML without env-var expansion (used after expansion is already done).
    fn from_str_raw(yaml: &str) -> Result<Self> {
        serde_yaml_ng::from_str(yaml)
            .map_err(|e| SiphonError::Config(format!("invalid siphon.yaml: {e}")))
    }

    /// Returns true if the given host/IP is one of our configured local domains.
    pub fn is_local(&self, host: &str) -> bool {
        self.domain.local.iter().any(|d| d == host)
    }

    /// Path-form accessor for an extension entry.
    ///
    /// Returns `Some(path)` when the entry exists and its value is a YAML
    /// scalar string (the conventional form for "load my config from this
    /// file"). Returns `None` when the entry is absent or its value is an
    /// inline mapping/sequence — extensions that accept inline config
    /// should call [`Config::extension_config`] instead and walk the
    /// `serde_yaml_ng::Value` themselves.
    pub fn extension_path(&self, name: &str) -> Option<&Path> {
        self.extensions
            .as_ref()?
            .get(name)?
            .as_str()
            .map(Path::new)
    }

    /// Raw-value accessor for an extension entry. Returns the entry's
    /// YAML value (any shape) for the extension to interpret. Returns
    /// `None` when the entry is absent.
    pub fn extension_config(&self, name: &str) -> Option<&serde_yaml_ng::Value> {
        self.extensions.as_ref()?.get(name)
    }
}

// ---------------------------------------------------------------------------
// IPsec (3GPP TS 33.203)
// ---------------------------------------------------------------------------

/// IPsec SA management configuration for P-CSCF.
#[derive(Debug, Deserialize, Clone)]
pub struct IpsecConfig {
    /// P-CSCF protected client port.
    #[serde(default = "default_ipsec_port_c")]
    pub pcscf_port_c: u16,
    /// P-CSCF protected server port.
    #[serde(default = "default_ipsec_port_s")]
    pub pcscf_port_s: u16,
    /// XFRM backend.  ``"netlink"`` (default — direct kernel netlink,
    /// fastest) or ``"ip"`` (legacy ``/sbin/ip xfrm`` shell-out, used
    /// as a fallback when running in containers without
    /// CAP_NET_ADMIN-on-netlink or for parity with older deployments).
    #[serde(default = "default_ipsec_backend")]
    pub backend: IpsecBackend,
    /// Optional SPI range for this siphon instance.  When set,
    /// `allocate_spi_pair()` only returns SPIs in `[start, start+count)`,
    /// letting multiple siphon processes coexist on the same kernel
    /// without colliding on SPI values.  When unset (default), siphon
    /// uses the historical wide range starting at 10000.
    #[serde(default)]
    pub spi_range_start: Option<u32>,
    /// Number of SPIs available in the partition (paired with
    /// `spi_range_start`).  Default 8192 — far more than any practical
    /// concurrent registration count.
    #[serde(default = "default_spi_range_count")]
    pub spi_range_count: u32,
    /// Host part siphon writes into the Path URI advertised by
    /// `request.add_pcscf_path(token)` (RFC 3327 §5 / TS 24.229
    /// §5.2.7.2 Path-token MT routing).  Must resolve back to *this*
    /// P-CSCF instance — typically the pod FQDN in a
    /// StatefulSet deployment so MT requests from the S-CSCF route to
    /// the instance that owns the inbound flow.  Optional; when unset,
    /// `add_pcscf_path()` errors at script time so the misconfiguration
    /// is caught loudly rather than producing unroutable Path URIs.
    #[serde(default)]
    pub path_host: Option<String>,
}

/// XFRM backend selection.  Defaults to `Netlink` on Linux (the only
/// platform where IPsec is meaningful).
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum IpsecBackend {
    /// Direct XFRM netlink protocol — fastest, no shell-out.
    Netlink,
    /// Legacy `/sbin/ip xfrm` shell-out — used when netlink is
    /// unavailable (e.g. inside containers without netlink access).
    Ip,
}

fn default_ipsec_port_c() -> u16 {
    5064
}

fn default_ipsec_port_s() -> u16 {
    5066
}

fn default_ipsec_backend() -> IpsecBackend {
    IpsecBackend::Netlink
}

fn default_spi_range_count() -> u32 {
    8192
}

// ---------------------------------------------------------------------------
// STIR/SHAKEN (RFC 8224/8225/8226, ATIS-1000074)
// ---------------------------------------------------------------------------

/// Top-level `stir:` configuration. Either or both of `signing` (the
/// Authentication Service) and `verification` (the Verification Service)
/// may be present; omitting one disables that side.
#[derive(Debug, Deserialize, Clone)]
pub struct StirConfig {
    /// Master on/off switch. Defaults to `true` when the `stir:` block is
    /// present, so adding the block enables it without an extra flag.
    #[serde(default = "default_stir_enabled")]
    pub enabled: bool,
    /// Outbound signing parameters (Authentication Service). When absent,
    /// `stir.sign()` / `stir.sign_div()` raise.
    pub signing: Option<StirSigningConfig>,
    /// Inbound verification parameters (Verification Service). When absent,
    /// `stir.verify()` raises.
    pub verification: Option<StirVerificationConfig>,
}

/// `stir.signing` — Authentication Service parameters.
#[derive(Debug, Deserialize, Clone)]
pub struct StirSigningConfig {
    /// Path to the PEM EC P-256 private key used to sign PASSporTs.
    pub private_key: String,
    /// Public certificate URL embedded as the Identity `info=` parameter and
    /// the PASSporT `x5u` header (RFC 8224 §4).
    pub x5u: String,
    /// Default attestation level (`A`, `B`, or `C`) when the script does not
    /// pass one to `stir.sign()`.
    #[serde(default = "default_stir_attestation")]
    pub default_attestation: String,
    /// Fixed `origid` (UUID) to stamp on every PASSporT. When unset, a fresh
    /// v4 UUID is generated per call.
    #[serde(default)]
    pub origid: Option<String>,
}

/// `stir.verification` — Verification Service parameters.
#[derive(Debug, Deserialize, Clone)]
pub struct StirVerificationConfig {
    /// STI-CA trust-anchor (root) certificate files (PEM).
    #[serde(default)]
    pub trust_anchors: Vec<String>,
    /// Optional directory of PEM trust anchors — every `*.pem`/`*.crt` file
    /// in it is loaded in addition to `trust_anchors`.
    #[serde(default)]
    pub trust_anchor_dir: Option<String>,
    /// PASSporT `iat` freshness window in seconds (ATIS-1000074).
    #[serde(default = "default_stir_freshness_secs")]
    pub freshness_secs: u64,
    /// Log-only rollout mode: x5u/infra failures degrade to
    /// `No-TN-Validation` instead of `TN-Validation-Failed`. Genuine bad
    /// signatures / expired certs / stale PASSporTs always fail.
    #[serde(default)]
    pub permissive: bool,
    /// Default x5u certificate cache TTL in seconds (overridden by a
    /// response `Cache-Control: max-age`).
    #[serde(default = "default_stir_cache_ttl_secs")]
    pub cache_ttl_secs: u64,
    /// Maximum accepted size of an x5u certificate response, in bytes.
    #[serde(default = "default_stir_max_cert_bytes")]
    pub max_cert_bytes: usize,
    /// Require the leaf certificate to carry the RFC 8226 TNAuthList
    /// extension.
    #[serde(default)]
    pub require_tnauthlist: bool,
}

fn default_stir_enabled() -> bool {
    true
}

fn default_stir_attestation() -> String {
    "A".to_string()
}

fn default_stir_freshness_secs() -> u64 {
    60
}

fn default_stir_cache_ttl_secs() -> u64 {
    3600
}

fn default_stir_max_cert_bytes() -> usize {
    65536
}

// ---------------------------------------------------------------------------
// Initial Filter Criteria (3GPP TS 29.228)
// ---------------------------------------------------------------------------

/// Top-level `isc:` configuration for Initial Filter Criteria.
#[derive(Debug, Deserialize, Clone)]
pub struct IscConfig {
    /// Path to the iFC XML file containing ServiceProfile elements.
    pub ifc_xml_path: Option<String>,
    /// Inline iFC XML (alternative to file path).
    pub ifc_xml: Option<String>,
    /// Redis key prefix for iFC profile persistence (default: "siphon:ifc:").
    /// When the registrar backend is Redis, iFC profiles are automatically
    /// persisted and restored alongside registrations.
    #[serde(default = "default_ifc_key_prefix")]
    pub ifc_key_prefix: String,
}

fn default_ifc_key_prefix() -> String {
    "siphon:ifc:".to_owned()
}

// ---------------------------------------------------------------------------
// 5G Service-Based Interface (SBI)
// ---------------------------------------------------------------------------

/// Top-level `sbi:` configuration for 5G Service-Based Interface.
#[derive(Debug, Deserialize, Clone)]
pub struct SbiYamlConfig {
    /// NRF discovery endpoint URL.
    pub nrf_url: Option<String>,
    /// Default timeout for SBI requests in seconds.
    #[serde(default = "default_sbi_timeout")]
    pub timeout_secs: u64,
    /// OAuth2 client ID for NF authorization.
    pub oauth2_client_id: Option<String>,
    /// OAuth2 client secret.
    pub oauth2_client_secret: Option<String>,
    /// Npcf base URL (if not using NRF discovery).
    pub npcf_url: Option<String>,
    /// Nchf base URL (if not using NRF discovery).
    pub nchf_url: Option<String>,
    /// Nbsf_Management (BSF) base URL for `sbi.discover_pcf_binding()`.
    /// May equal the SCP/Npcf URL. When unset, `discover_pcf_binding` raises
    /// a clear "BSF not configured" error rather than silently defaulting.
    pub bsf_url: Option<String>,
    /// Per-discovery timeout for BSF lookups in milliseconds. Falls back to
    /// `timeout_secs` when unset.
    pub bsf_timeout_ms: Option<u64>,
    /// URL scheme ("http" | "https", default "http") used when deriving a PCF
    /// base URL from a `pcfFqdn` returned by the BSF.
    pub pcf_scheme: Option<String>,
    /// SBI communication model: "direct" (default — straight to the NF) or
    /// "indirect" (via the SCP, with `3gpp-Sbi-*` routing headers; TS 29.500
    /// §6.10). When "indirect", `npcf_url`/`bsf_url` point at the SCP.
    pub communication: Option<String>,
    /// Requester NF type advertised in Nbsf delegated discovery
    /// (`3gpp-Sbi-Discovery-requester-nf-type`) when communication is indirect.
    /// Default "AF" (a P-CSCF acts as an AF).
    pub requester_nf_type: Option<String>,
    /// Listen address for incoming PCF event notifications (e.g. "0.0.0.0:8080").
    pub notif_listen: Option<String>,
}

fn default_sbi_timeout() -> u64 {
    5
}

impl SbiYamlConfig {
    pub fn to_sbi_config(&self) -> crate::sbi::SbiConfig {
        crate::sbi::SbiConfig {
            nrf_url: self.nrf_url.clone(),
            timeout_secs: self.timeout_secs,
            oauth2_client_id: self.oauth2_client_id.clone(),
            oauth2_client_secret: self.oauth2_client_secret.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_yaml() -> &'static str {
        r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
registrar:
  backend: memory
auth:
  realm: "example.com"
log:
  level: info
  format: pretty
"#
    }

    #[test]
    fn parses_minimal_config() {
        let config = Config::from_str(minimal_yaml()).unwrap();
        assert_eq!(config.listen.udp[0].address(), "0.0.0.0:5060");
        assert!(config.listen.tcp.is_empty());
        assert_eq!(config.domain.local, vec!["example.com"]);
        assert_eq!(config.script.path, "scripts/proxy_default.py");
        assert_eq!(config.script.reload, ReloadMode::Auto);
        assert_eq!(config.registrar.backend, RegistrarBackendType::Memory);
        assert_eq!(config.registrar.default_expires, 3600);
        assert_eq!(config.registrar.max_expires, 7200);
        assert_eq!(config.auth.realm, "example.com");
        assert_eq!(config.auth.backend, AuthBackendType::Static);
        assert_eq!(config.log.level, LogLevel::Info);
        assert_eq!(config.log.format, LogFormat::Pretty);
        // All optional sections absent
        assert!(config.advertised_address.is_none());
        assert!(config.tls.is_none());
        assert!(config.security.is_none());
        assert!(config.nat.is_none());
        assert!(config.tracing.is_none());
        assert!(config.metrics.is_none());
        assert!(config.server.is_none());
        assert!(config.transaction.is_none());
        assert!(config.dialog.is_none());
        assert!(config.cache.is_none());
        assert!(config.media.is_none());
        assert!(config.gateway.is_none());
        assert!(config.session_timer.is_none());
        assert!(config.registrant.is_none());
        assert!(config.lawful_intercept.is_none());
        assert!(config.diameter.is_none());
    }

    #[test]
    fn parses_full_config() {
        let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
    - "192.168.1.1:5060"
  tcp:
    - "0.0.0.0:5060"
  tls:
    - "0.0.0.0:5061"
domain:
  local:
    - "example.com"
    - "127.0.0.1"
    - "192.168.1.1"
script:
  path: "scripts/custom.py"
  reload: sighup
registrar:
  backend: redis
  default_expires: 1800
  max_expires: 3600
  redis:
    url: "redis://127.0.0.1:6379"
auth:
  realm: "example.com"
  backend: static
  users:
    alice: "secret"
    bob: "hunter2"
log:
  level: debug
  format: json
"#;
        let config = Config::from_str(yaml).unwrap();
        assert_eq!(config.listen.udp.len(), 2);
        assert_eq!(config.listen.tcp[0].address(), "0.0.0.0:5060");
        assert_eq!(config.listen.tls[0].address(), "0.0.0.0:5061");
        assert_eq!(config.domain.local.len(), 3);
        assert_eq!(config.script.reload, ReloadMode::Sighup);
        assert_eq!(config.registrar.backend, RegistrarBackendType::Redis);
        assert_eq!(config.registrar.default_expires, 1800);
        assert_eq!(config.registrar.redis.as_ref().unwrap().url, "redis://127.0.0.1:6379");
        assert_eq!(config.auth.users.get("alice").unwrap(), "secret");
        assert_eq!(config.log.level, LogLevel::Debug);
        assert_eq!(config.log.format, LogFormat::Json);
    }

    #[test]
    fn rejects_invalid_yaml() {
        let result = Config::from_str("this: is: not: valid: yaml:");
        assert!(result.is_err());
    }

    #[test]
    fn is_local_matches_configured_domains() {
        let config = Config::from_str(minimal_yaml()).unwrap();
        assert!(config.is_local("example.com"));
        assert!(!config.is_local("other.com"));
    }

    #[test]
    fn defaults_are_applied_when_fields_omitted() {
        let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
registrar: {}
auth:
  realm: "example.com"
log: {}
"#;
        let config = Config::from_str(yaml).unwrap();
        assert_eq!(config.registrar.backend, RegistrarBackendType::Memory);
        assert_eq!(config.registrar.default_expires, 3600);
        assert_eq!(config.log.level, LogLevel::Info);
        assert_eq!(config.log.format, LogFormat::Pretty);
        assert_eq!(config.script.reload, ReloadMode::Auto);
    }

    #[test]
    fn parses_auth_http_backend() {
        let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
auth:
  realm: "example.com"
  backend: http
  http:
    url: "http://127.0.0.1:8000/sip/auth/{username}"
    timeout_ms: 2000
    connect_timeout_ms: 500
    ha1: true
"#;
        let config = Config::from_str(yaml).unwrap();
        assert_eq!(config.auth.backend, AuthBackendType::Http);
        let http = config.auth.http.unwrap();
        assert!(http.url.contains("{username}"));
        assert_eq!(http.timeout_ms, 2000);
        assert!(http.ha1);
        // HA1 caching is opt-in: absent `cache_ttl_secs` defaults to 0 (disabled),
        // preserving the per-request blocking-fetch behaviour.
        assert_eq!(http.cache_ttl_secs, 0);
    }

    #[test]
    fn parses_auth_http_cache_ttl() {
        let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
auth:
  realm: "example.com"
  backend: http
  http:
    url: "http://127.0.0.1:8000/sip/auth/{username}"
    cache_ttl_secs: 300
"#;
        let config = Config::from_str(yaml).unwrap();
        let http = config.auth.http.unwrap();
        assert_eq!(http.cache_ttl_secs, 300);
    }

    #[test]
    fn script_executor_defaults_and_overrides() {
        // Defaults: watchdog at 30 s, bounded queue at 1024, pool sizes auto.
        let default_script = ScriptConfig::default();
        assert_eq!(default_script.handler_stall_abort_secs, 30);
        assert_eq!(default_script.executor_queue_capacity, 1024);
        assert_eq!(default_script.sync_pool_size, None);
        assert_eq!(default_script.sync_pool_max, None);

        // Defaults survive a YAML that omits the executor knobs.
        let minimal = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
"#;
        let config = Config::from_str(minimal).unwrap();
        assert_eq!(config.script.handler_stall_abort_secs, 30);
        assert_eq!(config.script.executor_queue_capacity, 1024);

        // Explicit overrides parse, including disabling the watchdog (0).
        let overridden = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
  sync_pool_size: 16
  sync_pool_max: 128
  handler_stall_abort_secs: 0
  executor_queue_capacity: 4096
"#;
        let config = Config::from_str(overridden).unwrap();
        assert_eq!(config.script.sync_pool_size, Some(16));
        assert_eq!(config.script.sync_pool_max, Some(128));
        assert_eq!(config.script.handler_stall_abort_secs, 0);
        assert_eq!(config.script.executor_queue_capacity, 4096);
    }

    #[test]
    fn parses_registrar_min_expires_and_max_contacts() {
        let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
registrar:
  backend: memory
  default_expires: 300
  max_expires: 600
  min_expires: 60
  max_contacts: 1
"#;
        let config = Config::from_str(yaml).unwrap();
        assert_eq!(config.registrar.min_expires, Some(60));
        assert_eq!(config.registrar.max_contacts, Some(1));
        assert_eq!(config.registrar.default_expires, 300);
    }

    #[test]
    fn parses_registrant_config() {
        let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
registrant:
  default_interval: 1800
  retry_interval: 30
  max_retry_interval: 120
  entries:
    - aor: "sip:alice@carrier.com"
      registrar: "sip:registrar.carrier.com:5060"
      user: "alice"
      password: "secret123"
      realm: "carrier.com"
      interval: 900
      contact: "sip:alice@1.2.3.4"
      transport: "tcp"
    - aor: "sip:bob@carrier.com"
      registrar: "sip:registrar.carrier.com:5060"
      user: "bob"
      password: "hunter2"
"#;
        let config = Config::from_str(yaml).unwrap();
        let registrant = config.registrant.unwrap();
        assert_eq!(registrant.default_interval, 1800);
        assert_eq!(registrant.retry_interval, 30);
        assert_eq!(registrant.max_retry_interval, 120);
        assert_eq!(registrant.entries.len(), 2);

        let alice = &registrant.entries[0];
        assert_eq!(alice.aor, "sip:alice@carrier.com");
        assert_eq!(alice.registrar, "sip:registrar.carrier.com:5060");
        assert_eq!(alice.user, "alice");
        assert_eq!(alice.password, "secret123");
        assert_eq!(alice.realm.as_deref(), Some("carrier.com"));
        assert_eq!(alice.interval, Some(900));
        assert_eq!(alice.contact.as_deref(), Some("sip:alice@1.2.3.4"));
        assert_eq!(alice.transport, "tcp");

        let bob = &registrant.entries[1];
        assert_eq!(bob.aor, "sip:bob@carrier.com");
        assert_eq!(bob.user, "bob");
        assert_eq!(bob.realm, None);
        assert_eq!(bob.interval, None);
        assert_eq!(bob.contact, None);
        assert_eq!(bob.transport, "udp"); // default

        // Digest entries carry no AKA / IPsec blocks.
        assert!(alice.auth.is_none());
        assert!(alice.aka.is_none());
        assert!(alice.ipsec.is_none());
    }

    #[test]
    fn parses_registrant_aka_ipsec_config() {
        // 3GPP test range (MCC 001 / MNC 01) + TS 35.208 Test Set 1 secrets.
        let yaml = r#"
listen:
  udp:
    - "10.0.0.20:5060"
    - "10.0.0.20:6100"
    - "10.0.0.20:6101"
domain:
  local:
    - "10.0.0.20"
script:
  path: "examples/ims_ue_b2bua.py"
ipsec:
  backend: netlink
registrant:
  entries:
    - aor: "sip:001010000000001@ims.mnc01.mcc001.3gppnetwork.org"
      registrar: "sip:pcscf.ims.mnc01.mcc001.3gppnetwork.org:5060"
      user: "001010000000001@ims.mnc01.mcc001.3gppnetwork.org"
      auth: "aka"
      aka:
        k: "465b5ce8b199b49faa5f0a2ee238a6bc"
        opc: "cd63cb71954a9f4e48a5994e37a02baf"
        amf: "b9b9"
      ipsec:
        ue_port_c: 6100
        ue_port_s: 6101
"#;
        let config = Config::from_str(yaml).unwrap();
        let registrant = config.registrant.unwrap();
        let ue = &registrant.entries[0];
        assert_eq!(ue.auth.as_deref(), Some("aka"));
        // password omitted (unused for AKA) defaults to empty.
        assert_eq!(ue.password, "");

        let aka = ue.aka.as_ref().expect("aka block");
        assert_eq!(aka.k, "465b5ce8b199b49faa5f0a2ee238a6bc");
        assert_eq!(aka.opc.as_deref(), Some("cd63cb71954a9f4e48a5994e37a02baf"));
        assert_eq!(aka.op, None);
        assert_eq!(aka.amf, "b9b9");
        assert_eq!(aka.sqn, "000000000000"); // default

        let ipsec = ue.ipsec.as_ref().expect("ipsec block");
        assert_eq!(ipsec.ue_port_c, 6100);
        assert_eq!(ipsec.ue_port_s, 6101);
        assert_eq!(ipsec.alg, "hmac-sha-1-96"); // default
        assert_eq!(ipsec.ealg, "null"); // default
    }

    /// The shipped IMS UE B2BUA example config must actually parse (env vars
    /// fall back to their `${VAR:-default}` defaults here). Guards against the
    /// example silently rotting.
    #[test]
    fn example_ims_ue_b2bua_yaml_parses() {
        let yaml = include_str!("../examples/ims_ue_b2bua.yaml");
        let config = Config::from_str(yaml).expect("example yaml must parse");
        let registrant = config.registrant.expect("registrant block");
        assert_eq!(registrant.entries.len(), 1);
        let ue = &registrant.entries[0];
        assert_eq!(ue.auth.as_deref(), Some("aka"));
        let aka = ue.aka.as_ref().expect("aka block");
        assert_eq!(aka.k.len(), 32); // 128-bit K as hex
        let ipsec = ue.ipsec.as_ref().expect("ipsec block");
        assert_eq!(ipsec.ue_port_c, 6100);
        assert_eq!(ipsec.ue_port_s, 6101);
        let ims = ue.ims.as_ref().expect("ims block");
        assert!(ims.imei.is_some());
        assert!(ims.features.iter().any(|f| f == "mmtel"));
    }

    #[test]
    fn parses_security_config() {
        let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
security:
  rate_limit:
    window_secs: 10
    max_requests: 30
    ban_duration_secs: 3600
  scanner_block:
    user_agents:
      - "sipvicious"
      - "friendly-scanner"
  trusted_cidrs:
    - "10.0.0.0/8"
  failed_auth_ban:
    threshold: 10
    ban_duration_secs: 300
"#;
        let config = Config::from_str(yaml).unwrap();
        let sec = config.security.unwrap();
        let rl = sec.rate_limit.unwrap();
        assert_eq!(rl.window_secs, 10);
        assert_eq!(rl.max_requests, 30);
        assert_eq!(rl.ban_duration_secs, 3600);
        let sb = sec.scanner_block.unwrap();
        assert_eq!(sb.user_agents.len(), 2);
        assert_eq!(sec.trusted_cidrs, vec!["10.0.0.0/8"]);
        let fab = sec.failed_auth_ban.unwrap();
        assert_eq!(fab.threshold, 10);
        assert_eq!(fab.ban_duration_secs, 300);
        assert_eq!(fab.window_secs, 600); // serde default when omitted
    }

    #[test]
    fn parses_tracing_hep_config() {
        let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
tracing:
  hep:
    endpoint: "127.0.0.1:9060"
    version: 3
    transport: udp
    agent_id: "siphon-registrar"
"#;
        let config = Config::from_str(yaml).unwrap();
        let hep = config.tracing.unwrap().hep.unwrap();
        assert_eq!(hep.endpoint, "127.0.0.1:9060");
        assert_eq!(hep.version, 3);
        assert_eq!(hep.transport, HepTransport::Udp);
        assert_eq!(hep.agent_id.unwrap(), "siphon-registrar");
    }

    #[test]
    fn parses_metrics_config() {
        let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
metrics:
  prometheus:
    listen: "0.0.0.0:8888"
    path: "/metrics"
"#;
        let config = Config::from_str(yaml).unwrap();
        let prom = config.metrics.unwrap().prometheus.unwrap();
        assert_eq!(prom.listen, "0.0.0.0:8888");
        assert_eq!(prom.path, "/metrics");
    }

    #[test]
    fn parses_nat_config() {
        let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
nat:
  fix_contact: true
  keepalive:
    enabled: true
    interval_secs: 30
    failure_threshold: 10
"#;
        let config = Config::from_str(yaml).unwrap();
        let nat = config.nat.unwrap();
        assert!(nat.fix_contact);
        let ka = nat.keepalive.unwrap();
        assert!(ka.enabled);
        assert_eq!(ka.interval_secs, 30);
    }

    #[test]
    fn nat_config_ignores_removed_legacy_keys() {
        // The no-op `force_rport` / `fix_register` keys were removed; a config
        // that still carries them must keep parsing (serde ignores unknown
        // fields) so existing siphon.yaml files don't break on upgrade.
        let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
nat:
  force_rport: true
  fix_contact: true
  fix_register: true
"#;
        let config = Config::from_str(yaml).unwrap();
        let nat = config.nat.unwrap();
        assert!(nat.fix_contact);
    }

    #[test]
    fn parses_cache_config() {
        let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
cache:
  - name: "cnam"
    url: "redis://172.16.0.252:6379"
    local_ttl_secs: 60
    local_max_entries: 10000
"#;
        let config = Config::from_str(yaml).unwrap();
        let caches = config.cache.unwrap();
        assert_eq!(caches.len(), 1);
        assert_eq!(caches[0].name, "cnam");
        assert_eq!(caches[0].local_ttl_secs, Some(60));
        assert_eq!(caches[0].local_max_entries, Some(10000));
    }

    #[test]
    fn parses_transaction_config() {
        let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
transaction:
  timeout_secs: 5
  invite_timeout_secs: 30
"#;
        let config = Config::from_str(yaml).unwrap();
        let tx = config.transaction.unwrap();
        assert_eq!(tx.timeout_secs, 5);
        assert_eq!(tx.invite_timeout_secs, 30);
    }

    #[test]
    fn parses_memory_config() {
        let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
memory:
  glibc:
    arena_max: 2
    trim_interval_secs: 30
"#;
        let config = Config::from_str(yaml).unwrap();
        let memory = config.memory.expect("memory block present");
        assert_eq!(memory.glibc.arena_max, Some(2));
        assert_eq!(memory.glibc.trim_interval_secs, 30);
    }

    #[test]
    fn memory_config_absent_and_partial_defaults() {
        // Absent → None (gauges still always-on; only the knobs are gated).
        let config = Config::from_str(minimal_yaml()).unwrap();
        assert!(config.memory.is_none());

        // Partial → unspecified knobs take their defaults (arena_max None,
        // trim disabled), so a bare `memory:` block is valid.
        let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
memory:
  glibc:
    arena_max: 4
"#;
        let config = Config::from_str(yaml).unwrap();
        let glibc = config.memory.unwrap().glibc;
        assert_eq!(glibc.arena_max, Some(4));
        assert_eq!(glibc.trim_interval_secs, 0);
    }

    #[test]
    fn parses_tls_server_config() {
        let yaml = r#"
listen:
  tls:
    - "0.0.0.0:5061"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
tls:
  certificate: "/etc/siphon/tls/example.com.crt"
  private_key: "/etc/siphon/tls/example.com.key"
  method: "TLSv1_3"
  verify_client: false
"#;
        let config = Config::from_str(yaml).unwrap();
        let tls = config.tls.unwrap();
        assert_eq!(tls.certificate, "/etc/siphon/tls/example.com.crt");
        assert_eq!(tls.method, "TLSv1_3");
        assert!(!tls.verify_client);
        // Outbound client-certificate (mutual TLS) fields default to None.
        assert!(tls.client_certificate.is_none());
        assert!(tls.client_private_key.is_none());
    }

    #[test]
    fn parses_tls_outbound_client_certificate() {
        let yaml = r#"
listen:
  tls:
    - "0.0.0.0:5061"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
tls:
  certificate: "/etc/siphon/tls/example.com.crt"
  private_key: "/etc/siphon/tls/example.com.key"
  client_certificate: "/etc/siphon/tls/client.crt"
  client_private_key: "/etc/siphon/tls/client.key"
"#;
        let config = Config::from_str(yaml).unwrap();
        let tls = config.tls.unwrap();
        assert_eq!(
            tls.client_certificate.as_deref(),
            Some("/etc/siphon/tls/client.crt")
        );
        assert_eq!(
            tls.client_private_key.as_deref(),
            Some("/etc/siphon/tls/client.key")
        );
    }

    #[test]
    fn parses_media_single_rtpengine() {
        let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
media:
  rtpengine:
    address: "127.0.0.1:22222"
    timeout_ms: 500
"#;
        let config = Config::from_str(yaml).unwrap();
        let media = config.media.unwrap();
        let instances = media.rtpengine.instances();
        assert_eq!(instances.len(), 1);
        assert_eq!(instances[0].address, "127.0.0.1:22222");
        assert_eq!(instances[0].timeout_ms, 500);
        assert_eq!(instances[0].weight, 1);
    }

    #[test]
    fn parses_media_multiple_rtpengines() {
        let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
media:
  rtpengine:
    instances:
      - address: "10.0.0.1:22222"
        weight: 2
      - address: "10.0.0.2:22222"
        weight: 1
        timeout_ms: 2000
"#;
        let config = Config::from_str(yaml).unwrap();
        let media = config.media.unwrap();
        let instances = media.rtpengine.instances();
        assert_eq!(instances.len(), 2);
        assert_eq!(instances[0].address, "10.0.0.1:22222");
        assert_eq!(instances[0].weight, 2);
        assert_eq!(instances[0].timeout_ms, 1000); // default
        assert_eq!(instances[1].address, "10.0.0.2:22222");
        assert_eq!(instances[1].weight, 1);
        assert_eq!(instances[1].timeout_ms, 2000);
    }

    #[test]
    fn parses_media_rtpengine_defaults() {
        let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
media:
  rtpengine:
    address: "127.0.0.1:22222"
"#;
        let config = Config::from_str(yaml).unwrap();
        let media = config.media.unwrap();
        let instances = media.rtpengine.instances();
        assert_eq!(instances[0].timeout_ms, 1000); // default
        assert_eq!(instances[0].weight, 1); // default
    }

    #[test]
    fn parses_media_custom_profiles() {
        let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
media:
  rtpengine:
    address: "127.0.0.1:22222"
  profiles:
    srtp_to_srtp:
      offer:
        transport_protocol: "RTP/SAVP"
        ice: "remove"
        replace: ["origin"]
        direction: ["external", "internal"]
      answer:
        transport_protocol: "RTP/SAVP"
        ice: "remove"
        replace: ["origin"]
        direction: ["internal", "external"]
"#;
        let config = Config::from_str(yaml).unwrap();
        let media = config.media.unwrap();
        assert_eq!(media.profiles.len(), 1);
        let profile = media.profiles.get("srtp_to_srtp").unwrap();
        assert_eq!(profile.offer.transport_protocol.as_deref(), Some("RTP/SAVP"));
        assert_eq!(profile.offer.ice.as_deref(), Some("remove"));
        assert!(profile.offer.dtls.is_none());
        assert_eq!(profile.offer.direction, vec!["external", "internal"]);
        assert_eq!(profile.answer.direction, vec!["internal", "external"]);
    }

    #[test]
    fn parses_media_no_profiles_defaults_to_empty() {
        let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
media:
  rtpengine:
    address: "127.0.0.1:22222"
"#;
        let config = Config::from_str(yaml).unwrap();
        let media = config.media.unwrap();
        assert!(media.profiles.is_empty());
    }

    #[test]
    fn parses_gateway_config() {
        let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
gateway:
  groups:
    - name: "carriers"
      algorithm: weighted
      probe:
        enabled: true
        interval_secs: 15
        failure_threshold: 5
      destinations:
        - uri: "sip:gw1.carrier.com:5060"
          address: "10.0.0.1:5060"
          weight: 3
          priority: 1
          attrs:
            region: "us-east"
        - uri: "sip:gw2.carrier.com:5060"
          address: "10.0.0.2:5060"
          transport: "tcp"
          weight: 1
          priority: 2
    - name: "sbc-pool"
      algorithm: hash
      destinations:
        - uri: "sip:sbc1.example.com:5060"
          address: "10.1.0.1:5060"
"#;
        let config = Config::from_str(yaml).unwrap();
        let disp = config.gateway.unwrap();
        assert_eq!(disp.groups.len(), 2);

        let group1 = &disp.groups[0];
        assert_eq!(group1.name, "carriers");
        assert_eq!(group1.algorithm, "weighted");
        assert!(group1.probe.enabled);
        assert_eq!(group1.probe.interval_secs, 15);
        assert_eq!(group1.probe.failure_threshold, 5);
        assert_eq!(group1.destinations.len(), 2);
        assert_eq!(group1.destinations[0].uri, "sip:gw1.carrier.com:5060");
        assert_eq!(group1.destinations[0].weight, 3);
        assert_eq!(group1.destinations[0].transport, None); // omitted
        assert_eq!(group1.destinations[0].effective_transport(), "udp"); // default
        assert_eq!(group1.destinations[0].attrs.get("region").unwrap(), "us-east");
        assert_eq!(group1.destinations[1].transport, Some("tcp".to_string()));
        assert_eq!(group1.destinations[1].priority, 2);

        let group2 = &disp.groups[1];
        assert_eq!(group2.name, "sbc-pool");
        assert_eq!(group2.algorithm, "hash");
        assert_eq!(group2.destinations[0].weight, 1); // default
        assert_eq!(group2.destinations[0].priority, 1); // default
    }

    #[test]
    fn parses_session_timer_config() {
        let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
session_timer:
  session_expires: 1800
  min_se: 90
  refresher: uac
  enabled: true
"#;
        let config = Config::from_str(yaml).unwrap();
        let timer = config.session_timer.unwrap();
        assert_eq!(timer.session_expires, 1800);
        assert_eq!(timer.min_se, 90);
        assert_eq!(timer.refresher, SessionRefresher::Uac);
        assert!(timer.enabled);
    }

    #[test]
    fn parses_session_timer_defaults() {
        let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
session_timer: {}
"#;
        let config = Config::from_str(yaml).unwrap();
        let timer = config.session_timer.unwrap();
        assert_eq!(timer.session_expires, 1800);
        assert_eq!(timer.min_se, 90);
        assert_eq!(timer.refresher, SessionRefresher::Uac);
        assert!(timer.enabled);
    }

    #[test]
    fn session_timer_absent_when_not_configured() {
        let config = Config::from_str(minimal_yaml()).unwrap();
        assert!(config.session_timer.is_none());
    }

    #[test]
    fn parses_session_timer_refresher_variants() {
        for (variant, expected) in [
            ("uac", SessionRefresher::Uac),
            ("uas", SessionRefresher::Uas),
        ] {
            let yaml = format!(r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
session_timer:
  refresher: {variant}
"#);
            let config = Config::from_str(&yaml).unwrap();
            assert_eq!(config.session_timer.unwrap().refresher, expected);
        }
    }

    #[test]
    fn parses_cdr_file_config() {
        let yaml = concat!(
            "listen:\n",
            "  udp:\n",
            "    - \"0.0.0.0:5060\"\n",
            "domain:\n",
            "  local:\n",
            "    - \"example.com\"\n",
            "script:\n",
            "  path: \"scripts/proxy_default.py\"\n",
            "cdr:\n",
            "  enabled: true\n",
            "  include_register: true\n",
            "  channel_size: 5000\n",
            "  backend: file\n",
            "  file:\n",
            "    path: \"/tmp/cdr.jsonl\"\n",
            "    rotate_size_mb: 50\n",
        );
        let config = Config::from_str(yaml).unwrap();
        let cdr = config.cdr.unwrap();
        assert!(cdr.enabled);
        assert!(cdr.include_register);
        assert_eq!(cdr.channel_size, 5000);
        assert_eq!(cdr.backend, "file");

        let runtime = cdr.to_cdr_config();
        assert!(runtime.enabled);
        assert!(runtime.include_register);
        assert_eq!(runtime.channel_size, 5000);
        assert!(matches!(runtime.backend, crate::cdr::CdrBackendType::File { ref path, rotate_size_mb } if path == "/tmp/cdr.jsonl" && rotate_size_mb == 50));
    }

    #[test]
    fn parses_cdr_http_config() {
        let yaml = concat!(
            "listen:\n",
            "  udp:\n",
            "    - \"0.0.0.0:5060\"\n",
            "domain:\n",
            "  local:\n",
            "    - \"example.com\"\n",
            "script:\n",
            "  path: \"scripts/proxy_default.py\"\n",
            "cdr:\n",
            "  enabled: true\n",
            "  backend: http\n",
            "  http:\n",
            "    url: \"https://collector.example.com/v1/cdr\"\n",
            "    auth_header: \"Bearer secret\"\n",
        );
        let config = Config::from_str(yaml).unwrap();
        let cdr = config.cdr.unwrap();
        assert_eq!(cdr.backend, "http");

        let runtime = cdr.to_cdr_config();
        assert!(matches!(runtime.backend, crate::cdr::CdrBackendType::Http { ref url, ref auth_header } if url == "https://collector.example.com/v1/cdr" && auth_header.as_deref() == Some("Bearer secret")));
    }

    #[test]
    fn parses_cdr_syslog_config() {
        let yaml = concat!(
            "listen:\n",
            "  udp:\n",
            "    - \"0.0.0.0:5060\"\n",
            "domain:\n",
            "  local:\n",
            "    - \"example.com\"\n",
            "script:\n",
            "  path: \"scripts/proxy_default.py\"\n",
            "cdr:\n",
            "  enabled: true\n",
            "  backend: syslog\n",
            "  syslog:\n",
            "    target: \"10.0.0.5:514\"\n",
        );
        let config = Config::from_str(yaml).unwrap();
        let runtime = config.cdr.unwrap().to_cdr_config();
        assert!(matches!(runtime.backend, crate::cdr::CdrBackendType::Syslog { ref target } if target == "10.0.0.5:514"));
    }

    #[test]
    fn cdr_absent_when_not_configured() {
        let config = Config::from_str(minimal_yaml()).unwrap();
        assert!(config.cdr.is_none());
    }

    #[test]
    fn parses_lawful_intercept_config() {
        let yaml = concat!(
            "listen:\n",
            "  udp:\n",
            "    - \"0.0.0.0:5060\"\n",
            "domain:\n",
            "  local:\n",
            "    - \"example.com\"\n",
            "script:\n",
            "  path: \"scripts/proxy_default.py\"\n",
            "lawful_intercept:\n",
            "  enabled: true\n",
            "  audit_log: \"/var/log/siphon/li-audit.log\"\n",
            "  x1:\n",
            "    listen: \"127.0.0.1:8443\"\n",
            "    tls:\n",
            "      certificate: \"/etc/siphon/li/x1.crt\"\n",
            "      private_key: \"/etc/siphon/li/x1.key\"\n",
            "      verify_client: true\n",
            "    auth_token: \"warrant-auth-xyz\"\n",
            "  x2:\n",
            "    delivery_address: \"10.0.0.50:6543\"\n",
            "    transport: tls\n",
            "    reconnect_interval_secs: 10\n",
            "    channel_size: 5000\n",
            "    tls:\n",
            "      ca_cert: \"/etc/siphon/li/mediation-ca.pem\"\n",
            "  x3:\n",
            "    listen_udp: \"127.0.0.1:19000\"\n",
            "    delivery_address: \"10.0.0.50:6544\"\n",
            "    transport: udp\n",
            "    encapsulation: etsi\n",
            "  siprec:\n",
            "    srs_uri: \"sip:srs@recorder.example.com\"\n",
            "    session_copies: 2\n",
            "    transport: tls\n",
        );
        let config = Config::from_str(yaml).unwrap();
        let li = config.lawful_intercept.unwrap();
        assert!(li.enabled);
        assert_eq!(li.audit_log.unwrap(), "/var/log/siphon/li-audit.log");

        // X1
        let x1 = li.x1.unwrap();
        assert_eq!(x1.listen, "127.0.0.1:8443");
        assert_eq!(x1.auth_token.unwrap(), "warrant-auth-xyz");
        let x1_tls = x1.tls.unwrap();
        assert!(x1_tls.verify_client);
        assert_eq!(x1_tls.certificate.unwrap(), "/etc/siphon/li/x1.crt");

        // X2
        let x2 = li.x2.unwrap();
        assert_eq!(x2.delivery_address, "10.0.0.50:6543");
        assert_eq!(x2.transport, "tls");
        assert_eq!(x2.reconnect_interval_secs, 10);
        assert_eq!(x2.channel_size, 5000);
        assert_eq!(x2.tls.unwrap().ca_cert.unwrap(), "/etc/siphon/li/mediation-ca.pem");

        // X3
        let x3 = li.x3.unwrap();
        assert_eq!(x3.listen_udp, "127.0.0.1:19000");
        assert_eq!(x3.delivery_address, "10.0.0.50:6544");
        assert_eq!(x3.transport, "udp");
        assert_eq!(x3.encapsulation, "etsi");

        // SIPREC
        let siprec = li.siprec.unwrap();
        assert_eq!(siprec.srs_uri, "sip:srs@recorder.example.com");
        assert_eq!(siprec.session_copies, 2);
        assert_eq!(siprec.transport, "tls");
    }

    #[test]
    fn parses_lawful_intercept_defaults() {
        let yaml = concat!(
            "listen:\n",
            "  udp:\n",
            "    - \"0.0.0.0:5060\"\n",
            "domain:\n",
            "  local:\n",
            "    - \"example.com\"\n",
            "script:\n",
            "  path: \"scripts/proxy_default.py\"\n",
            "lawful_intercept:\n",
            "  enabled: false\n",
            "  x2:\n",
            "    delivery_address: \"10.0.0.50:6543\"\n",
            "  x3:\n",
            "    delivery_address: \"10.0.0.50:6544\"\n",
        );
        let config = Config::from_str(yaml).unwrap();
        let li = config.lawful_intercept.unwrap();
        assert!(!li.enabled);
        assert!(li.x1.is_none());
        assert!(li.siprec.is_none());

        let x2 = li.x2.unwrap();
        assert_eq!(x2.transport, "tcp");
        assert_eq!(x2.reconnect_interval_secs, 5);
        assert_eq!(x2.channel_size, 10_000);

        let x3 = li.x3.unwrap();
        assert_eq!(x3.listen_udp, "127.0.0.1:0");
        assert_eq!(x3.transport, "udp");
        assert_eq!(x3.encapsulation, "etsi");
    }

    #[test]
    fn lawful_intercept_absent_when_not_configured() {
        let config = Config::from_str(minimal_yaml()).unwrap();
        assert!(config.lawful_intercept.is_none());
    }

    #[test]
    fn parses_diameter_config() {
        let yaml = concat!(
            "listen:\n",
            "  udp:\n",
            "    - \"0.0.0.0:5060\"\n",
            "domain:\n",
            "  local:\n",
            "    - \"example.com\"\n",
            "script:\n",
            "  path: \"scripts/proxy_default.py\"\n",
            "diameter:\n",
            "  origin_host: \"siphon.ims.example.com\"\n",
            "  origin_realm: \"ims.example.com\"\n",
            "  product_name: \"SIPhon-Test\"\n",
            "  transport: tcp\n",
            "  watchdog_interval: 20\n",
            "  reconnect_delay: 3\n",
            "  peers:\n",
            "    - name: \"hss1\"\n",
            "      host: \"hss1.example.com\"\n",
            "      port: 3868\n",
            "      destination_realm: \"example.com\"\n",
            "    - name: \"hss2\"\n",
            "      host: \"hss2.example.com\"\n",
            "      port: 3869\n",
            "      destination_realm: \"example.com\"\n",
            "      transport: sctp\n",
            "      watchdog_interval: 60\n",
            "    - name: \"ocs1\"\n",
            "      host: \"ocs.example.com\"\n",
            "      destination_realm: \"charging.example.com\"\n",
            "      destination_host: \"ocs-primary.charging.example.com\"\n",
            "  routes:\n",
            "    - application: cx\n",
            "      realm: \"example.com\"\n",
            "      peers: [\"hss1\", \"hss2\"]\n",
            "      algorithm: failover\n",
            "    - application: sh\n",
            "      peers: [\"hss1\"]\n",
            "    - application: ro\n",
            "      peers: [\"ocs1\"]\n",
            "      algorithm: round_robin\n",
        );
        let config = Config::from_str(yaml).unwrap();
        let diameter = config.diameter.unwrap();

        assert_eq!(diameter.origin_host, "siphon.ims.example.com");
        assert_eq!(diameter.origin_realm, "ims.example.com");
        assert_eq!(diameter.product_name.as_deref(), Some("SIPhon-Test"));
        assert_eq!(diameter.transport, "tcp");
        assert_eq!(diameter.watchdog_interval, 20);
        assert_eq!(diameter.reconnect_delay, 3);

        // Peers
        assert_eq!(diameter.peers.len(), 3);
        assert_eq!(diameter.peers[0].name, "hss1");
        assert_eq!(diameter.peers[0].port, 3868);
        assert_eq!(diameter.peers[0].transport, None);
        assert_eq!(diameter.peers[1].name, "hss2");
        assert_eq!(diameter.peers[1].port, 3869);
        assert_eq!(diameter.peers[1].transport.as_deref(), Some("sctp"));
        assert_eq!(diameter.peers[1].watchdog_interval, Some(60));
        assert_eq!(diameter.peers[2].name, "ocs1");
        assert_eq!(diameter.peers[2].destination_host.as_deref(), Some("ocs-primary.charging.example.com"));
        assert_eq!(diameter.peers[2].port, 3868); // default

        // Routes
        assert_eq!(diameter.routes.len(), 3);
        assert_eq!(diameter.routes[0].application, DiameterApplication::Cx);
        assert_eq!(diameter.routes[0].realm.as_deref(), Some("example.com"));
        assert_eq!(diameter.routes[0].peers, vec!["hss1", "hss2"]);
        assert_eq!(diameter.routes[0].algorithm, "failover");
        assert_eq!(diameter.routes[1].application, DiameterApplication::Sh);
        assert!(diameter.routes[1].realm.is_none());
        assert_eq!(diameter.routes[2].application, DiameterApplication::Ro);
        assert_eq!(diameter.routes[2].algorithm, "round_robin");
    }

    #[test]
    fn diameter_to_peer_config_merges_defaults() {
        let yaml = concat!(
            "listen:\n",
            "  udp:\n",
            "    - \"0.0.0.0:5060\"\n",
            "domain:\n",
            "  local:\n",
            "    - \"example.com\"\n",
            "script:\n",
            "  path: \"scripts/proxy_default.py\"\n",
            "diameter:\n",
            "  origin_host: \"siphon.example.com\"\n",
            "  origin_realm: \"example.com\"\n",
            "  watchdog_interval: 25\n",
            "  reconnect_delay: 7\n",
            "  peers:\n",
            "    - name: \"hss1\"\n",
            "      host: \"hss1.example.com\"\n",
            "      destination_realm: \"example.com\"\n",
            "    - name: \"hss2\"\n",
            "      host: \"hss2.example.com\"\n",
            "      destination_realm: \"example.com\"\n",
            "      watchdog_interval: 60\n",
            "      reconnect_delay: 10\n",
            "  routes:\n",
            "    - application: cx\n",
            "      peers: [\"hss1\", \"hss2\"]\n",
        );
        let config = Config::from_str(yaml).unwrap();
        let diameter = config.diameter.as_ref().unwrap();

        // hss1: inherits parent defaults
        let peer1 = diameter.to_peer_config(&diameter.peers[0], "SIPhon", "1.2.3");
        assert_eq!(peer1.origin_host, "siphon.example.com");
        assert_eq!(peer1.origin_realm, "example.com");
        assert_eq!(peer1.host, "hss1.example.com");
        assert_eq!(peer1.watchdog_interval, 25);
        assert_eq!(peer1.reconnect_delay, 7);
        assert_eq!(peer1.product_name, "SIPhon"); // builder fallback
        assert_eq!(peer1.firmware_revision, 10203); // 1.2.3 → 1*10000+2*100+3

        // hss2: overrides parent defaults
        let peer2 = diameter.to_peer_config(&diameter.peers[1], "SIPhon", "1.2.3");
        assert_eq!(peer2.watchdog_interval, 60);
        assert_eq!(peer2.reconnect_delay, 10);
    }

    #[test]
    fn diameter_to_peer_config_collects_app_ids() {
        let yaml = concat!(
            "listen:\n",
            "  udp:\n",
            "    - \"0.0.0.0:5060\"\n",
            "domain:\n",
            "  local:\n",
            "    - \"example.com\"\n",
            "script:\n",
            "  path: \"scripts/proxy_default.py\"\n",
            "diameter:\n",
            "  origin_host: \"siphon.example.com\"\n",
            "  origin_realm: \"example.com\"\n",
            "  peers:\n",
            "    - name: \"hss1\"\n",
            "      host: \"hss1.example.com\"\n",
            "      destination_realm: \"example.com\"\n",
            "  routes:\n",
            "    - application: cx\n",
            "      peers: [\"hss1\"]\n",
            "    - application: sh\n",
            "      peers: [\"hss1\"]\n",
        );
        let config = Config::from_str(yaml).unwrap();
        let diameter = config.diameter.as_ref().unwrap();
        let peer_config = diameter.to_peer_config(&diameter.peers[0], "SIPhon", "1.2.3");

        // hss1 is in both Cx and Sh routes — should get both app IDs
        assert_eq!(peer_config.application_ids.len(), 2);
        assert_eq!(
            peer_config.application_ids[0],
            DiameterApplication::Cx.to_app_id()
        );
        assert_eq!(
            peer_config.application_ids[1],
            DiameterApplication::Sh.to_app_id()
        );
    }

    #[test]
    fn diameter_peers_for_application() {
        let yaml = concat!(
            "listen:\n",
            "  udp:\n",
            "    - \"0.0.0.0:5060\"\n",
            "domain:\n",
            "  local:\n",
            "    - \"example.com\"\n",
            "script:\n",
            "  path: \"scripts/proxy_default.py\"\n",
            "diameter:\n",
            "  origin_host: \"siphon.example.com\"\n",
            "  origin_realm: \"example.com\"\n",
            "  peers:\n",
            "    - name: \"hss1\"\n",
            "      host: \"hss1.example.com\"\n",
            "      destination_realm: \"example.com\"\n",
            "    - name: \"hss2\"\n",
            "      host: \"hss2.example.com\"\n",
            "      destination_realm: \"example.com\"\n",
            "    - name: \"ocs1\"\n",
            "      host: \"ocs.example.com\"\n",
            "      destination_realm: \"charging.example.com\"\n",
            "  routes:\n",
            "    - application: cx\n",
            "      realm: \"example.com\"\n",
            "      peers: [\"hss1\", \"hss2\"]\n",
            "    - application: ro\n",
            "      peers: [\"ocs1\"]\n",
        );
        let config = Config::from_str(yaml).unwrap();
        let diameter = config.diameter.as_ref().unwrap();

        // Cx with matching realm
        let cx_peers = diameter.peers_for_application(&DiameterApplication::Cx, Some("example.com"));
        assert_eq!(cx_peers.len(), 2);
        assert_eq!(cx_peers[0].name, "hss1");
        assert_eq!(cx_peers[1].name, "hss2");

        // Cx with non-matching realm
        let cx_wrong = diameter.peers_for_application(&DiameterApplication::Cx, Some("other.com"));
        assert!(cx_wrong.is_empty());

        // Cx with no realm filter — still matches (route realm is optional filter)
        let cx_any = diameter.peers_for_application(&DiameterApplication::Cx, None);
        assert_eq!(cx_any.len(), 2);

        // Ro — no realm on route
        let ro_peers = diameter.peers_for_application(&DiameterApplication::Ro, None);
        assert_eq!(ro_peers.len(), 1);
        assert_eq!(ro_peers[0].name, "ocs1");

        // Rx — not configured
        let rx_peers = diameter.peers_for_application(&DiameterApplication::Rx, None);
        assert!(rx_peers.is_empty());
    }

    #[test]
    fn diameter_absent_when_not_configured() {
        let config = Config::from_str(minimal_yaml()).unwrap();
        assert!(config.diameter.is_none());
    }

    #[test]
    fn absent_isc_and_sbi() {
        let config = Config::from_str(minimal_yaml()).unwrap();
        assert!(config.isc.is_none());
        assert!(config.sbi.is_none());
    }

    // -----------------------------------------------------------------------
    // Environment variable expansion
    // -----------------------------------------------------------------------

    #[test]
    fn expand_env_var_set() {
        std::env::set_var("SIPHON_TEST_HOST", "10.0.0.1");
        let result = expand_env_vars("host: ${SIPHON_TEST_HOST}");
        assert_eq!(result, "host: 10.0.0.1");
        std::env::remove_var("SIPHON_TEST_HOST");
    }

    #[test]
    fn expand_env_var_unset_no_default() {
        std::env::remove_var("SIPHON_TEST_MISSING");
        let result = expand_env_vars("host: ${SIPHON_TEST_MISSING}");
        assert_eq!(result, "host: ");
    }

    #[test]
    fn expand_env_var_unset_with_default() {
        std::env::remove_var("SIPHON_TEST_MISSING2");
        let result = expand_env_vars("host: ${SIPHON_TEST_MISSING2:-localhost}");
        assert_eq!(result, "host: localhost");
    }

    #[test]
    fn expand_env_var_empty_uses_default() {
        std::env::set_var("SIPHON_TEST_EMPTY", "");
        let result = expand_env_vars("host: ${SIPHON_TEST_EMPTY:-fallback}");
        assert_eq!(result, "host: fallback");
        std::env::remove_var("SIPHON_TEST_EMPTY");
    }

    #[test]
    fn expand_env_var_set_ignores_default() {
        std::env::set_var("SIPHON_TEST_PRIO", "actual");
        let result = expand_env_vars("val: ${SIPHON_TEST_PRIO:-ignored}");
        assert_eq!(result, "val: actual");
        std::env::remove_var("SIPHON_TEST_PRIO");
    }

    #[test]
    fn expand_env_var_multiple() {
        std::env::set_var("SIPHON_TEST_A", "alpha");
        std::env::set_var("SIPHON_TEST_B", "beta");
        let result = expand_env_vars("${SIPHON_TEST_A}:${SIPHON_TEST_B}");
        assert_eq!(result, "alpha:beta");
        std::env::remove_var("SIPHON_TEST_A");
        std::env::remove_var("SIPHON_TEST_B");
    }

    #[test]
    fn expand_env_var_no_placeholders() {
        let input = "listen:\n  udp: \"0.0.0.0:5060\"";
        assert_eq!(expand_env_vars(input), input);
    }

    #[test]
    fn expand_env_var_in_config_parse() {
        std::env::set_var("SIPHON_TEST_DOMAIN", "test.example.com");
        let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "${SIPHON_TEST_DOMAIN}"
script:
  path: "scripts/proxy_default.py"
registrar:
  enabled: false
"#;
        let config = Config::from_str(yaml).unwrap();
        assert_eq!(config.domain.local[0], "test.example.com");
        std::env::remove_var("SIPHON_TEST_DOMAIN");
    }

    // --- DSCP / DiffServ tests ---

    #[test]
    fn parse_dscp_named_values() {
        assert_eq!(parse_dscp("CS0").unwrap(), 0);
        assert_eq!(parse_dscp("BE").unwrap(), 0);
        assert_eq!(parse_dscp("CS1").unwrap(), 8);
        assert_eq!(parse_dscp("AF11").unwrap(), 10);
        assert_eq!(parse_dscp("AF12").unwrap(), 12);
        assert_eq!(parse_dscp("AF13").unwrap(), 14);
        assert_eq!(parse_dscp("CS2").unwrap(), 16);
        assert_eq!(parse_dscp("AF21").unwrap(), 18);
        assert_eq!(parse_dscp("AF22").unwrap(), 20);
        assert_eq!(parse_dscp("AF23").unwrap(), 22);
        assert_eq!(parse_dscp("CS3").unwrap(), 24);
        assert_eq!(parse_dscp("AF31").unwrap(), 26);
        assert_eq!(parse_dscp("AF32").unwrap(), 28);
        assert_eq!(parse_dscp("AF33").unwrap(), 30);
        assert_eq!(parse_dscp("CS4").unwrap(), 32);
        assert_eq!(parse_dscp("AF41").unwrap(), 34);
        assert_eq!(parse_dscp("AF42").unwrap(), 36);
        assert_eq!(parse_dscp("AF43").unwrap(), 38);
        assert_eq!(parse_dscp("CS5").unwrap(), 40);
        assert_eq!(parse_dscp("EF").unwrap(), 46);
        assert_eq!(parse_dscp("CS6").unwrap(), 48);
        assert_eq!(parse_dscp("CS7").unwrap(), 56);
    }

    #[test]
    fn parse_dscp_case_insensitive() {
        assert_eq!(parse_dscp("cs3").unwrap(), 24);
        assert_eq!(parse_dscp("ef").unwrap(), 46);
        assert_eq!(parse_dscp("af41").unwrap(), 34);
        assert_eq!(parse_dscp("Cs3").unwrap(), 24);
    }

    #[test]
    fn parse_dscp_raw_integers() {
        assert_eq!(parse_dscp("0").unwrap(), 0);
        assert_eq!(parse_dscp("24").unwrap(), 24);
        assert_eq!(parse_dscp("46").unwrap(), 46);
        assert_eq!(parse_dscp("63").unwrap(), 63);
    }

    #[test]
    fn parse_dscp_rejects_out_of_range() {
        assert!(parse_dscp("64").is_err());
        assert!(parse_dscp("255").is_err());
    }

    #[test]
    fn parse_dscp_rejects_invalid() {
        assert!(parse_dscp("INVALID").is_err());
        assert!(parse_dscp("CS8").is_err());
        assert!(parse_dscp("").is_err());
    }

    #[test]
    fn dscp_to_tos_conversion() {
        assert_eq!(dscp_to_tos(0), 0);      // BE
        assert_eq!(dscp_to_tos(24), 96);     // CS3 → signaling
        assert_eq!(dscp_to_tos(46), 184);    // EF  → voice media
        assert_eq!(dscp_to_tos(34), 136);    // AF41 → video
        assert_eq!(dscp_to_tos(63), 252);    // max DSCP
    }

    #[test]
    fn listen_config_defaults_to_cs3() {
        let config = Config::from_str(minimal_yaml()).unwrap();
        assert_eq!(config.listen.dscp, Some(24), "default DSCP should be CS3 (24)");
    }

    #[test]
    fn listen_config_dscp_from_yaml_string() {
        let yaml = r#"
listen:
  dscp: EF
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
"#;
        let config = Config::from_str(yaml).unwrap();
        assert_eq!(config.listen.dscp, Some(46));
    }

    #[test]
    fn diameter_server_config_parses() {
        let yaml = r#"
listen:
  udp:
    - "127.0.0.1:5099"
domain:
  local:
    - "epc.mnc001.mcc001.3gppnetwork.org"
script:
  path: "examples/diameter_server.py"
diameter:
  listen:
    tcp: "0.0.0.0:3868"
    sctp: "0.0.0.0:3868"
  event_sink:
    backend: file
    file:
      path: "/tmp/diameter.jsonl"
  tenants:
    default:
      identity:
        origin_host: "diam.epc.mnc001.mcc001.3gppnetwork.org"
        origin_realm: "epc.mnc001.mcc001.3gppnetwork.org"
      clients:
        - name: mme
          allowed_ips: ["172.16.0.0/24"]
          expected_origin_host: "mme.epc.example.org"
      servers:
        - { name: hss, host: "172.16.0.61", port: 3868, transport: tcp }
"#;
        let config = Config::from_str(yaml).expect("Diameter server config should parse");
        let diameter = config.diameter.expect("diameter section");
        let listen = diameter.listen.expect("listen");
        assert_eq!(listen.tcp.as_deref(), Some("0.0.0.0:3868"));
        assert_eq!(listen.sctp.as_deref(), Some("0.0.0.0:3868"));
        // Flat client-only fields default cleanly when omitted.
        assert!(diameter.origin_host.is_empty());

        let tenant = diameter.tenants.get("default").expect("default tenant");
        assert_eq!(tenant.identity.origin_host, "diam.epc.mnc001.mcc001.3gppnetwork.org");
        assert_eq!(tenant.clients[0].name, "mme");
        assert_eq!(tenant.clients[0].allowed_ips, vec!["172.16.0.0/24"]);
        assert_eq!(tenant.servers[0].name, "hss");
        assert_eq!(tenant.servers[0].port, 3868);

        let event_sink = diameter.event_sink.expect("event_sink");
        assert_eq!(event_sink.backend, "file");
    }

    #[test]
    fn hss_connect_to_server_config_parses() {
        // An HSS that dials a Diameter server: no listener, a tenant with connect_to.
        let yaml = r#"
listen:
  udp:
    - "127.0.0.1:5099"
domain:
  local:
    - "epc.mnc001.mcc001.3gppnetwork.org"
script:
  path: "examples/hss_s6a.py"
diameter:
  tenants:
    default:
      identity:
        origin_host: "hss.epc.example.org"
        origin_realm: "epc.example.org"
      connect_to:
        - { name: upstream, host: "172.16.0.10", port: 3868, transport: sctp }
"#;
        let config = Config::from_str(yaml).expect("HSS connect_to config should parse");
        let diameter = config.diameter.expect("diameter section");
        assert!(diameter.listen.is_none(), "HSS dials out, no listener");
        let tenant = diameter.tenants.get("default").unwrap();
        assert_eq!(tenant.connect_to.len(), 1);
        assert_eq!(tenant.connect_to[0].name, "upstream");
        assert_eq!(tenant.connect_to[0].transport, "sctp");
    }

    #[test]
    fn example_diameter_server_yaml_loads() {
        // The shipped example must always parse (acceptance artifact).
        let config = Config::from_file("examples/diameter_server.yaml")
            .expect("examples/diameter_server.yaml must parse");
        let diameter = config.diameter.expect("diameter section");
        assert!(diameter.listen.is_some());
        // Flat single-domain shape: no `tenants:` block — the server runs
        // against the implicit "default" tenant synthesized from the flat
        // fields by effective_tenants().
        assert!(diameter.tenants.is_empty());
        assert!(!diameter.origin_host.is_empty());
        assert_eq!(diameter.clients[0].name, "client-a");
        assert_eq!(diameter.servers[0].name, "backend");

        let effective = diameter.effective_tenants();
        let default = effective.get("default").expect("synthesized default tenant");
        assert_eq!(default.identity.origin_host, diameter.origin_host);
        assert_eq!(default.identity.origin_realm, diameter.origin_realm);
        assert_eq!(default.clients[0].name, "client-a");
        assert_eq!(default.servers[0].name, "backend");
    }

    #[test]
    fn effective_tenants_prefers_explicit_over_flat() {
        // When `tenants:` is declared, the flat fields are ignored.
        let yaml = r#"
listen:
  udp: ["127.0.0.1:5099"]
domain:
  local: ["example.org"]
script:
  path: "examples/diameter_server.py"
diameter:
  origin_host: "flat.example.org"
  servers:
    - { name: flatbackend, host: "10.0.0.1" }
  tenants:
    alpha:
      identity: { origin_host: "alpha.example.org", origin_realm: "example.org" }
"#;
        let diameter = Config::from_str(yaml).unwrap().diameter.unwrap();
        let effective = diameter.effective_tenants();
        assert!(effective.contains_key("alpha"));
        assert!(!effective.contains_key("default"));
    }

    #[test]
    fn effective_tenants_empty_for_client_only() {
        // Pure client-mode NFs set origin_host (for their CER) but no server
        // fields (clients/servers/connect_to) — they synthesize no tenant.
        let yaml = r#"
listen:
  udp: ["127.0.0.1:5099"]
domain:
  local: ["example.org"]
script:
  path: "examples/diameter_server.py"
diameter:
  origin_host: "client.example.org"
  origin_realm: "example.org"
"#;
        let diameter = Config::from_str(yaml).unwrap().diameter.unwrap();
        assert!(diameter.effective_tenants().is_empty());
    }

    #[test]
    fn listen_config_dscp_from_yaml_integer() {
        let yaml = r#"
listen:
  dscp: 24
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
"#;
        let config = Config::from_str(yaml).unwrap();
        assert_eq!(config.listen.dscp, Some(24));
    }

    #[test]
    fn listen_entry_per_listener_dscp_override() {
        let yaml = r#"
listen:
  dscp: CS3
  udp:
    - address: "0.0.0.0:5060"
      dscp: EF
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
"#;
        let config = Config::from_str(yaml).unwrap();
        assert_eq!(config.listen.dscp, Some(24));
        assert_eq!(config.listen.udp[0].dscp(), Some(46));
    }

    #[test]
    fn listen_entry_plain_has_no_dscp() {
        let entry = ListenEntry::Plain("0.0.0.0:5060".to_string());
        assert_eq!(entry.dscp(), None);
    }

    // --- GatewayDestConfig::effective_transport tests ---

    fn gateway_dest(uri: &str, transport: Option<&str>) -> GatewayDestConfig {
        GatewayDestConfig {
            uri: uri.to_string(),
            address: None,
            transport: transport.map(|s| s.to_string()),
            weight: 1,
            priority: 1,
            attrs: Default::default(),
        }
    }

    #[test]
    fn effective_transport_explicit_field_wins() {
        let dest = gateway_dest("sip:gw.example.com;transport=tls", Some("tcp"));
        assert_eq!(dest.effective_transport(), "tcp");
    }

    #[test]
    fn effective_transport_from_uri_tls() {
        let dest = gateway_dest("sip:gw.example.com:5061;transport=tls", None);
        assert_eq!(dest.effective_transport(), "tls");
    }

    #[test]
    fn effective_transport_from_uri_tcp() {
        let dest = gateway_dest("sip:gw.example.com;transport=tcp", None);
        assert_eq!(dest.effective_transport(), "tcp");
    }

    #[test]
    fn effective_transport_case_insensitive() {
        let dest = gateway_dest("sip:gw.example.com;Transport=TLS", None);
        assert_eq!(dest.effective_transport(), "tls");
    }

    #[test]
    fn effective_transport_param_not_last() {
        let dest = gateway_dest("sip:gw.example.com;transport=tcp;lr", None);
        assert_eq!(dest.effective_transport(), "tcp");
    }

    #[test]
    fn effective_transport_defaults_to_udp() {
        let dest = gateway_dest("sip:gw.example.com:5060", None);
        assert_eq!(dest.effective_transport(), "udp");
    }

    // -----------------------------------------------------------------------
    // extensions: section
    // -----------------------------------------------------------------------

    fn extensions_yaml(extensions_block: &str) -> String {
        format!(
            r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
registrar:
  backend: memory
auth:
  realm: "example.com"
log:
  level: info
  format: pretty
{extensions_block}
"#
        )
    }

    #[test]
    fn extensions_absent_when_unset() {
        let config = Config::from_str(minimal_yaml()).unwrap();
        assert!(config.extensions.is_none());
        assert!(config.extension_path("anything").is_none());
        assert!(config.extension_config("anything").is_none());
    }

    #[test]
    fn extensions_path_form() {
        let yaml = extensions_yaml(
            r#"extensions:
  foo: /etc/siphon/foo.yaml
"#,
        );
        let config = Config::from_str(&yaml).unwrap();
        let path = config
            .extension_path("foo")
            .expect("foo extension should resolve to a path");
        assert_eq!(path, Path::new("/etc/siphon/foo.yaml"));
    }

    #[test]
    fn extensions_inline_form() {
        let yaml = extensions_yaml(
            r#"extensions:
  bar:
    listen: "0.0.0.0:8080"
    workers: 4
"#,
        );
        let config = Config::from_str(&yaml).unwrap();
        // The path accessor returns None for non-string entries.
        assert!(config.extension_path("bar").is_none());

        let value = config
            .extension_config("bar")
            .expect("bar extension should resolve to a value");
        let mapping = value.as_mapping().expect("bar should be a mapping");
        let listen = mapping
            .get(serde_yaml_ng::Value::String("listen".to_owned()))
            .and_then(|v| v.as_str())
            .expect("listen key");
        assert_eq!(listen, "0.0.0.0:8080");
        let workers = mapping
            .get(serde_yaml_ng::Value::String("workers".to_owned()))
            .and_then(|v| v.as_u64())
            .expect("workers key");
        assert_eq!(workers, 4);
    }

    #[test]
    fn extensions_mixed_forms_coexist() {
        let yaml = extensions_yaml(
            r#"extensions:
  foo: /etc/siphon/foo.yaml
  bar:
    key: value
  baz: 42
"#,
        );
        let config = Config::from_str(&yaml).unwrap();
        assert_eq!(
            config.extension_path("foo"),
            Some(Path::new("/etc/siphon/foo.yaml")),
        );
        assert!(config.extension_path("bar").is_none());
        assert!(config.extension_config("bar").is_some());
        // Numeric scalar — neither a path nor an inline mapping.
        assert!(config.extension_path("baz").is_none());
        assert_eq!(
            config
                .extension_config("baz")
                .and_then(|v| v.as_u64()),
            Some(42),
        );
    }

    #[test]
    fn extensions_unknown_name_returns_none() {
        let yaml = extensions_yaml(
            r#"extensions:
  foo: /etc/siphon/foo.yaml
"#,
        );
        let config = Config::from_str(&yaml).unwrap();
        assert!(config.extension_path("missing").is_none());
        assert!(config.extension_config("missing").is_none());
    }

    #[test]
    fn extensions_preserve_yaml_order() {
        let yaml = extensions_yaml(
            r#"extensions:
  zeta: /a
  alpha: /b
  middle: /c
"#,
        );
        let config = Config::from_str(&yaml).unwrap();
        let extensions = config.extensions.expect("extensions present");
        let names: Vec<&str> = extensions.keys().map(String::as_str).collect();
        assert_eq!(names, vec!["zeta", "alpha", "middle"]);
    }
}
