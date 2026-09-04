//! YAML configuration — `siphon.yaml` deserialization via serde_yaml_ng.

use crate::error::{Result, SiphonError};
use crate::rtpengine::profile::{validate_ws_sample_rate, WsTeeDirection, WsVadEngine};
use indexmap::IndexMap;
use regex::Regex;
use serde::{Deserialize, Deserializer, Serialize};
use std::path::Path;
use std::sync::LazyLock;

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

    /// External remote-control plane (ARI/ESL-class). `None` = disabled.
    pub control: Option<ControlConfig>,

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

    /// Home numbering plan (country code + trunk/international prefixes) that
    /// drives E.164 number normalization for identity headers.
    #[serde(default)]
    pub numbering: crate::numbers::policy::NumberingConfig,

    /// Named number-format policies (`"<name>@<version>" -> policy`) applied by
    /// `request.rewrite_identities()` / `call.dial(number_policy=…)`.
    #[serde(default)]
    pub number_policies:
        std::collections::HashMap<String, crate::numbers::policy::NumberPolicyConfig>,

    /// Operator-defined B2BUA header policies (`"<name>@<version>" -> policy`),
    /// selectable anywhere a built-in preset is: `b2bua.default_header_policy`
    /// and `call.dial(header_policy=…)` / `call.fork(header_policy=…)`.
    ///
    /// Each entry either extends a built-in preset or declares both directions
    /// in full; see
    /// [`HeaderPolicyConfig`](crate::b2bua::header_policy::HeaderPolicyConfig).
    /// Resolved and validated at load by
    /// [`Self::validate_header_policies`], so a policy that could never work
    /// stops the node at boot rather than at the first call across the
    /// boundary it was meant to guard.
    #[serde(default)]
    pub header_policies:
        std::collections::HashMap<String, crate::b2bua::header_policy::HeaderPolicyConfig>,

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

    /// Least-Cost Routing (LCR) external HTTP API. Drives the `lcr` Python
    /// namespace (`await lcr.route(call)`) — B2BUA-only. The API owns the
    /// cost-order decision; siphon caches it and executes the ordered route
    /// set against the `gateway` health/failover machinery.
    pub lcr: Option<LcrConfig>,

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

    /// Ro online charging (Diameter Credit-Control, RFC 8506 / TS 32.299).
    /// When present and `enabled`, siphon reserves credit at call setup,
    /// re-authorizes on a configurable cadence (SCUR, voice) and does one-shot
    /// event charging for SMS/RCS (IEC). Absent/`enabled: false` = no online
    /// charging; scripts can still call ``diameter.ro_ccr_*`` manually.
    pub ro: Option<RoConfig>,

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
/// the script doesn't pass `header_policy=` on `call.dial()`.  Names either a
/// built-in preset (e.g. `"transparent-b2bua@2026"`) or an operator-defined
/// one from the top-level `header_policies:` map — one namespace, and a name
/// that resolves to neither refuses to start.  An unset/empty value falls back
/// to `transparent-b2bua@2026`, which reproduces siphon's pre-policy B2BUA
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

    /// Default number-format policy applied to every B2BUA call when the
    /// script doesn't pass `number_policy=` on `call.dial()`/`call.fork()`.
    /// Names an entry in the top-level `number_policies:` map.  When `None`,
    /// no number normalization is applied unless a call opts in explicitly.
    pub default_number_policy: Option<String>,

    /// Default REFER transfer mode applied when an `@b2bua.on_refer` handler
    /// calls `accept_refer()` without an explicit `mode=`.
    ///
    /// - `"terminate"` (default) — siphon terminates the transfer: answer 202
    ///   locally, re-resolve the Refer-To through the dial plan as a new leg,
    ///   re-bridge the media, and BYE the referred-away leg. Correct for
    ///   trunk-facing SBCs (the far end need not support REFER) and keeps media
    ///   anchored.
    /// - `"transparent"` — siphon re-emits the REFER on the far leg's own dialog
    ///   and relays the far end's 202 + `message/sipfrag` NOTIFYs back. Correct
    ///   for UA-to-UA (PBX / softphone) topologies.
    ///
    /// Unset → `"terminate"`.
    pub default_refer_mode: Option<String>,

    /// Whether an inbound `INVITE` carrying a `Replaces` (RFC 3891) may take
    /// over the dialog it names — the transferee half of attended transfer,
    /// and the shape of a directed call pickup.
    ///
    /// **Off unless enabled.** Possession of a dialog's identifiers is not
    /// proof of authorisation to end that dialog: RFC 3891 §5 calls out
    /// exactly this, the transferor hands the triple to the transferee by
    /// design, and anyone who can observe unprotected signalling reads it off
    /// the wire. Turning this on grants every party that reaches this node —
    /// subject to whatever admission `@b2bua.on_invite` applies — the ability
    /// to disconnect one party from a live call and take their place. That is
    /// a capability an operator opts into, not one an upgrade switches on.
    ///
    /// With it off, a `Replaces` naming a dialog this node hosts is declined
    /// `603` (RFC 3891 §3's answer for a dialog the UA is unwilling to
    /// replace) rather than being ignored — the INVITE never becomes an
    /// unrelated second call.
    ///
    /// **Enable it only where INVITEs are authenticated or the source is
    /// trusted.** `auth.require_proxy_digest()` in `@b2bua.on_invite` is what
    /// makes this safe on an untrusted edge; the takeover runs only after that
    /// handler admits the request, so a challenge or a `call.reject()` stops
    /// it.
    ///
    /// ```yaml
    /// b2bua:
    ///   accept_replaces: true
    /// ```
    pub accept_replaces: Option<bool>,
}

impl B2buaConfig {
    /// The header-policy name to apply when a call doesn't pass one.
    ///
    /// Unset, empty, or whitespace all mean "not configured" and resolve to
    /// [`DEFAULT_PRESET_NAME`](crate::b2bua::header_policy::DEFAULT_PRESET_NAME);
    /// anything else is taken verbatim and must exist in the registry (the
    /// load-time check in [`Config::validate_header_policies`] proves it does).
    pub fn resolved_default_header_policy(&self) -> &str {
        match self.default_header_policy.as_deref().map(str::trim) {
            Some(name) if !name.is_empty() => name,
            _ => crate::b2bua::header_policy::DEFAULT_PRESET_NAME,
        }
    }

    /// Whether an inbound `Replaces` may take a dialog over. Defaults to
    /// `false` — see [`accept_replaces`](Self::accept_replaces).
    pub fn replaces_takeover_enabled(&self) -> bool {
        self.accept_replaces.unwrap_or(false)
    }

    /// Resolve the configured default REFER mode. `None`, empty, or an
    /// unrecognized value fall back to the safe trunk-facing default
    /// (`Terminate`); only an explicit `"transparent"` selects transparent
    /// forwarding.
    pub fn resolved_default_refer_mode(&self) -> crate::script::api::call::ReferMode {
        match self.default_refer_mode.as_deref().map(str::trim) {
            Some("transparent") => crate::script::api::call::ReferMode::Transparent,
            _ => crate::script::api::call::ReferMode::Terminate,
        }
    }
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
/// Default UDP receive-buffer floor: 1 MiB per listener socket.
///
/// Roughly 5x the usual kernel default, which is enough to ride out a
/// scheduler stall at the throughput siphon targets, while staying small
/// enough that `worker_count` sockets do not meaningfully dent a
/// memory-capped container's cgroup budget.
///
/// It is a floor rather than a fixed size precisely because it is a default:
/// a host tuned above it has an operator's decision behind that number, and a
/// shipped constant must not quietly override one.
fn default_udp_recv_buffer_bytes() -> usize {
    1024 * 1024
}

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
    /// Path MTU in bytes for the outbound UDP request path (RFC 3261 §18.1.1).
    /// When set, an outbound SIP *request* built for UDP whose serialised length
    /// exceeds `mtu - 200` is sent over TCP instead (if a TCP path to the
    /// destination is reachable), else it falls back to UDP with a warning.
    /// Default `None` (off) — existing UDP-at-any-size deployments are unchanged.
    /// `1280` (the IPv6 minimum MTU) is a safe dual-stack lower bound for IMS
    /// core legs. Responses follow the transport of the request they answer;
    /// the inbound side is unaffected.
    #[serde(default)]
    pub mtu: Option<u16>,
    /// Minimum receive-buffer size in bytes (`SO_RCVBUF`) for every UDP
    /// listener socket. Default 1 MiB.
    ///
    /// A **floor, not a target**: a host whose `net.core.rmem_default` already
    /// exceeds this keeps its larger buffer. Applying it unconditionally would
    /// shrink the queue on a tuned host, and silently, because an untouched
    /// socket reports `rmem_default` raw while an explicit request comes back
    /// doubled — so 1 MiB against a 4 MiB default lands at 2 MiB with nothing
    /// clamped and no warning to show for it.
    ///
    /// The kernel default (`net.core.rmem_default`, typically ~212 KB) is a
    /// few hundred milliseconds of headroom at IMS registration rates, so a
    /// scheduler stall on a busy box overflows the socket queue and the kernel
    /// drops datagrams silently — which a UAC sees as a retransmit, not an
    /// error, and which shows up as a sharp cliff rather than gradual
    /// degradation. `SO_REUSEPORT` gives one socket per worker, so the real
    /// cost is this value times the worker count.
    ///
    /// Socket buffers are charged to the process's cgroup, so raise this
    /// deliberately on a memory-capped deployment. `net.core.rmem_max` caps
    /// what the kernel will actually grant; siphon reads the value back and
    /// warns when it was clamped. `0` leaves the kernel default in place.
    #[serde(default = "default_udp_recv_buffer_bytes")]
    pub udp_recv_buffer_bytes: usize,
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
            mtu: None,
            udp_recv_buffer_bytes: default_udp_recv_buffer_bytes(),
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
    /// Extra directories added to the Python `sys.path` so a script can
    /// `import` shared helper modules that live outside its own directory.
    /// The script's *own* directory (the parent of `path`) is always added
    /// automatically; this list is only for helpers shared across scripts/NFs
    /// (e.g. a common `/etc/siphon/lib`).  Modules imported from any of these
    /// directories (and from the script's own directory) hot-reload on change
    /// just like the main script.  Defaults to empty.
    #[serde(default)]
    pub include_paths: Vec<String>,
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
            include_paths: Vec::new(),
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

fn default_diameter_port() -> u16 {
    3868
}
fn default_diameter_transport() -> String {
    "tcp".to_string()
}
fn default_watchdog_interval() -> u64 {
    30
}
fn default_reconnect_delay() -> u64 {
    5
}
fn default_diameter_route_algorithm() -> String {
    "failover".to_string()
}

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
            product_name: self
                .product_name
                .clone()
                .unwrap_or_else(|| product_name.to_string()),
            firmware_revision: crate::diameter::peer::version_to_firmware_revision(product_version),
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
    /// Additional certificate pairs selected by the TLS SNI extension
    /// (RFC 6066) on `listen.tls` and `listen.wss`. Empty (the default) serves
    /// `certificate`/`private_key` to every client, exactly as before.
    #[serde(default)]
    pub certificates: Vec<SniCertificate>,
    /// Minimum TLS protocol version siphon negotiates — on the `listen.tls` /
    /// `listen.wss` listeners this block serves, and on outbound SIP TLS
    /// connections from the connection pool.
    ///
    /// This is a **floor**, not an exact version: `TLSv1_2` (the default)
    /// negotiates TLS 1.2 or 1.3, `TLSv1_3` negotiates 1.3 only. TLS 1.0/1.1
    /// are rejected at config load — RFC 8996 deprecates them and the rustls
    /// stack siphon is built on does not implement them.
    #[serde(default)]
    pub method: TlsMethod,
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

/// One additional certificate/key pair, selected by the server name the client
/// sends in the TLS SNI extension (RFC 6066).
///
/// Serving several domains from a single TLS/WSS listener otherwise needs one
/// SAN certificate covering all of them, which couples every domain to a single
/// renewal — one failed ACME validation blocks the cert for all of them, and
/// every peer sees the full list. Each entry here is an independent pair.
///
/// The top-level `certificate`/`private_key` remains the default: it is served
/// to a client that sends no SNI (including any IP-literal peer, which RFC 6066
/// forbids from sending one) or whose server name matches no entry. Selection
/// never aborts a handshake.
#[derive(Debug, Deserialize, Clone)]
pub struct SniCertificate {
    /// Server names this pair serves, matched case-insensitively.
    ///
    /// A leading-label wildcard (`*.example.com`) matches exactly one label per
    /// RFC 6125 §6.4.3 — `ue.example.com` matches, `example.com` and
    /// `a.b.example.com` do not. A name may appear only once across all
    /// entries; a duplicate is a startup error rather than a silent
    /// last-one-wins.
    pub server_names: Vec<String>,
    /// PEM certificate chain served for `server_names`.
    pub certificate: String,
    /// PEM private key matching `certificate`.
    pub private_key: String,
}

/// Minimum TLS protocol version, from `tls.method`.
///
/// Named `method` after the OpenSSL/Kamailio spelling operators already have in
/// their configs, but the semantics are a floor: `TLSv1_2` serves TLS 1.2 *and*
/// 1.3, `TLSv1_3` serves 1.3 only. Only these two exist — RFC 8996 deprecates
/// TLS 1.0/1.1 and rustls does not implement them, so a config asking for one
/// fails at load rather than silently getting something newer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TlsMethod {
    /// TLS 1.2 and above. The default, and what siphon has always served.
    #[default]
    Tls12,
    /// TLS 1.3 only — TLS 1.2 handshakes are refused.
    Tls13,
}

impl TlsMethod {
    /// The spelling used in `siphon.yaml`.
    pub fn as_str(self) -> &'static str {
        match self {
            TlsMethod::Tls12 => "TLSv1_2",
            TlsMethod::Tls13 => "TLSv1_3",
        }
    }
}

impl std::fmt::Display for TlsMethod {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::str::FromStr for TlsMethod {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        // Accept every spelling an operator plausibly carries over from
        // OpenSSL/Kamailio/OpenSIPS: `TLSv1_2`, `TLSv1.2`, `TLSv1.2+`, `1.2`.
        // The `+` suffix (Kamailio's "this version or higher") is redundant
        // here because the value is already a floor, so it is accepted and
        // ignored rather than rejected.
        let normalized = value
            .trim()
            .trim_end_matches('+')
            .trim()
            .to_ascii_lowercase()
            .replace('_', ".");
        let version = normalized
            .strip_prefix("tlsv")
            .or_else(|| normalized.strip_prefix("tls"))
            .unwrap_or(normalized.as_str());

        match version {
            "1.2" => Ok(TlsMethod::Tls12),
            "1.3" => Ok(TlsMethod::Tls13),
            "1" | "1.0" | "1.1" | "sslv2" | "sslv3" | "sslv23" | "ssl" => Err(format!(
                "tls.method '{value}': TLS 1.0/1.1 and SSL are deprecated (RFC 8996) and \
                 are not implemented — use TLSv1_2 (minimum 1.2, negotiates 1.2 or \
                 1.3) or TLSv1_3 (1.3 only)"
            )),
            _ => Err(format!(
                "tls.method '{value}' is not a TLS version siphon supports — use TLSv1_2 \
                 (minimum 1.2, negotiates 1.2 or 1.3) or TLSv1_3 (1.3 only)"
            )),
        }
    }
}

impl<'de> Deserialize<'de> for TlsMethod {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        raw.parse().map_err(serde::de::Error::custom)
    }
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
    /// Largest single SIP message accepted on a stream transport (TCP/TLS/WS/
    /// WSS), in bytes. A peer that declares a larger `Content-Length` is
    /// answered 513 and disconnected rather than buffered, so one connection
    /// cannot drive unbounded memory growth. Defaults to
    /// [`crate::security::DEFAULT_MAX_MESSAGE_BYTES`] (256 KB).
    pub max_message_bytes: Option<usize>,
}

/// Smallest accepted `security.max_message_bytes`. A REGISTER or INVITE with a
/// digest challenge, a Route set and a modest SDP body sits comfortably under
/// 4 KB; anything below this is an operator typo, not a policy.
pub const MIN_MAX_MESSAGE_BYTES: usize = 4 * 1024;

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
    /// How long a fetched entry stays blocked, in seconds (default: 604800, 7
    /// days — the feed's own release policy). Applied as a per-element timeout
    /// in the kernel set, so the kernel expires it without siphon acting.
    ///
    /// `0` disables expiry and restores the pre-TTL behaviour, where an entry
    /// stayed blocked for the life of the process.
    #[serde(default = "default_apiban_ban_ttl_secs")]
    pub ban_ttl_secs: u64,
}

fn default_apiban_interval_secs() -> u64 {
    300
}

/// 7 days, matching the interval after which APIBAN itself releases an address.
fn default_apiban_ban_ttl_secs() -> u64 {
    604_800
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
    /// Optional CORS policy so a browser dashboard served from another origin
    /// can `fetch()` this endpoint. Unset = no CORS headers (default).
    #[serde(default)]
    pub cors: Option<CorsConfig>,
}

fn default_metrics_path() -> String {
    "/metrics".to_owned()
}

// ---------------------------------------------------------------------------
// CORS (browser-facing HTTP endpoints)
// ---------------------------------------------------------------------------

/// Cross-Origin Resource Sharing policy for a browser-facing HTTP endpoint
/// (the Prometheus `/metrics` listener and/or the admin API).
///
/// A browser blocks a cross-origin `fetch()` of these endpoints unless the
/// server echoes an `Access-Control-Allow-Origin` header. Set this to let a
/// monitoring dashboard served from a different origin (e.g. a local dev
/// server on `http://localhost:5173`) read the endpoint. Leaving it unset
/// emits no CORS headers at all — same-origin callers and Prometheus scrapers
/// are unaffected either way, so this is opt-in and backwards compatible.
#[derive(Debug, Deserialize, Clone)]
pub struct CorsConfig {
    /// Origins allowed to read this endpoint from a browser, echoed into
    /// `Access-Control-Allow-Origin`. Each entry is a full origin including
    /// scheme and port (`http://localhost:5173`, `https://dash.example.com`).
    /// A single `"*"` entry allows any origin — convenient for local
    /// development, but prefer an explicit list in production, especially for
    /// the admin API (which can force-unregister AoRs and lift bans). An empty
    /// list disables CORS.
    #[serde(default)]
    pub allowed_origins: Vec<String>,
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
    /// Optional CORS policy so a browser dashboard served from another origin
    /// can `fetch()` the admin API (and the `/metrics` it also serves). Unset =
    /// no CORS headers (default). Prefer an explicit origin list here — the
    /// admin API can force-unregister AoRs and lift auto-bans.
    #[serde(default)]
    pub cors: Option<CorsConfig>,
    /// Optional bearer-token auth for the admin API. The admin API can
    /// force-unregister AoRs and lift auto-bans, so when the embedded UI is
    /// exposed a token should protect at least the mutating routes. Unset =
    /// no auth (network-placement trust only, unchanged from before).
    #[serde(default)]
    pub auth: Option<AdminAuthConfig>,
    /// Optional embedded web dashboard served from this listener. Requires a
    /// binary built with the `ui` cargo feature; on a binary without it,
    /// `enabled: true` warns and no UI is served.
    #[serde(default)]
    pub ui: Option<AdminUiConfig>,
}

/// Bearer-token auth for the admin API (RFC 6750). When `token` is set, the
/// `DELETE` routes (force-unregister, lift-ban) require
/// `Authorization: Bearer <token>`; set `protect_reads` to require it on the
/// `GET` routes and `/metrics` too. Same-origin dashboard callers send the
/// token themselves; Prometheus scrapers of a `protect_reads` endpoint must be
/// configured with the bearer token.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct AdminAuthConfig {
    /// Shared bearer token. Empty/unset disables auth. Supports `${VAR}`
    /// expansion, so keep the literal out of the YAML: `token: "${ADMIN_TOKEN}"`.
    #[serde(default)]
    pub token: Option<String>,
    /// Also require the token on the read routes (`GET`, `/metrics`,
    /// `/admin/metrics.json`), not only the mutating `DELETE` routes. Default
    /// false — reads stay open (back-compat), writes are gated as soon as a
    /// token is set.
    #[serde(default)]
    pub protect_reads: bool,
}

/// Embedded web-dashboard settings for the admin listener.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct AdminUiConfig {
    /// Serve the embedded dashboard at the admin listener root (`/`). Default
    /// false. Requires a binary built with `--features ui`; otherwise a loud
    /// warning is logged and no UI is served.
    #[serde(default)]
    pub enabled: bool,
}

// ---------------------------------------------------------------------------
// External remote-control plane (ARI/ESL-class)
// ---------------------------------------------------------------------------

/// External remote-control plane listener + per-app registry.
///
/// An out-of-process application drives B2BUA calls that a Python
/// `@b2bua.on_invite` handler explicitly hands over with `call.handover("app")`
/// (the ARI *Stasis* model). Two connection modes, same wire protocol:
/// a persistent inbound WebSocket per app (`listen`), and outbound
/// per-call-connect where siphon dials the app's `connect_url` at handover.
///
/// A management plane — treat it like the admin API. Off by default; enable it
/// deliberately and set per-app bearer tokens.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct ControlConfig {
    /// Address for the inbound persistent-WebSocket listener
    /// (e.g. "127.0.0.1:9092"). `None` = only outbound per-call-connect apps
    /// are usable.
    #[serde(default)]
    pub listen: Option<String>,
    /// Registered control applications. An app not listed here can neither
    /// connect (unknown token) nor receive a handover (unknown app name).
    #[serde(default)]
    pub apps: Vec<ControlAppConfig>,
    /// Global resource caps + backpressure policy.
    #[serde(default)]
    pub limits: ControlLimits,
}

/// A single registered control application.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct ControlAppConfig {
    /// The application name. `call.handover("<name>")` routes to this app, and
    /// the connection's `hello.args.app` must equal it.
    pub name: String,
    /// The bearer token this app presents (`Authorization: Bearer <token>` on
    /// the inbound upgrade, or the token siphon presents when dialing
    /// `connect_url`). Supports `${VAR}` expansion — keep the literal out of the
    /// YAML.
    #[serde(default)]
    pub token: String,
    /// When true, siphon dials `connect_url` per handed-over call and the
    /// accepting socket owns that call (the FreeSWITCH-outbound model — the
    /// documented default for multi-pod controllers). When false (default), the
    /// app connects in over `listen` and owns per round-robin assignment.
    #[serde(default)]
    pub per_call_connect: bool,
    /// The controller's WebSocket URL for `per_call_connect` mode
    /// (e.g. "ws://controller.internal:8443/siphon").
    #[serde(default)]
    pub connect_url: Option<String>,
    /// What to do if the owning connection is lost mid-call (owner disconnects):
    /// "hangup" (default), "continue", or "fallback".
    #[serde(default)]
    pub on_lost: Option<String>,
}

/// Global control-plane resource caps + backpressure policy.
#[derive(Debug, Deserialize, Clone)]
pub struct ControlLimits {
    /// Bounded per-connection outbound event-queue depth. On overflow the
    /// `slow_consumer` policy applies (events only — replies are never dropped).
    #[serde(default = "ControlLimits::default_event_queue_depth")]
    pub event_queue_depth: usize,
    /// Overflow policy for a slow/stuck consumer: "drop_oldest" (default) or
    /// "disconnect".
    #[serde(default = "ControlLimits::default_slow_consumer")]
    pub slow_consumer: String,
    /// Grace window (seconds) after an owner disconnects during which a
    /// reconnecting controller of the same app may `resync` and re-claim its
    /// calls before `on_lost` fires. Default 10.
    #[serde(default = "ControlLimits::default_reattach_grace_secs")]
    pub reattach_grace_secs: u64,
    /// Default handoff deadline (milliseconds) applied when `call.handover()`
    /// does not pass an explicit `deadline_ms`. If no controller accepts and
    /// acts within it, the call degrades (503 / fallback). Default 3000.
    #[serde(default = "ControlLimits::default_handoff_deadline_ms")]
    pub handoff_deadline_ms: u64,
}

impl Default for ControlLimits {
    fn default() -> Self {
        Self {
            event_queue_depth: Self::default_event_queue_depth(),
            slow_consumer: Self::default_slow_consumer(),
            reattach_grace_secs: Self::default_reattach_grace_secs(),
            handoff_deadline_ms: Self::default_handoff_deadline_ms(),
        }
    }
}

impl ControlLimits {
    fn default_event_queue_depth() -> usize {
        1024
    }
    fn default_slow_consumer() -> String {
        "drop_oldest".to_string()
    }
    fn default_reattach_grace_secs() -> u64 {
        10
    }
    fn default_handoff_deadline_ms() -> u64 {
        3000
    }
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
///     url: "redis://192.0.2.131:6379"
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

/// Which media-control backend siphon drives.
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum MediaBackendKind {
    /// rtpengine NG protocol (bencode over UDP) — the default.
    #[default]
    Rtpengine,
    /// Native `siphon-rtp` control protocol (JSON over TCP).
    SiphonRtp,
    /// Classic `rtpproxy` control protocol (text over UDP).
    Rtpproxy,
}

impl MediaBackendKind {
    /// The engine's name as it appears in `media.backend`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rtpengine => "rtpengine",
            Self::SiphonRtp => "siphon-rtp",
            Self::Rtpproxy => "rtpproxy",
        }
    }

    /// Which of `flags`' set fields this backend has no way to express.
    ///
    /// The WebSocket bridge, the WebSocket tee and the DSP knobs are native
    /// `siphon-rtp` extensions; `received_from` and `rtcp_mux` are also real
    /// rtpengine NG keys but have no `rtpproxy` equivalent.
    ///
    /// A field the engine cannot honour is not a degraded call, it is a dead
    /// one — a `ws_uri` the engine never sees means the leg is answered and
    /// bridged nowhere, and the caller hears silence for its whole duration.
    /// So this drives a hard config error rather than the boot warning that
    /// covers `address_family` on `rtpproxy` (which merely loses IPv4/IPv6
    /// interworking on an otherwise working call).
    pub fn unsupported_profile_fields(self, flags: &NgFlagsConfig) -> Vec<&'static str> {
        let mut unsupported = Vec::new();

        if !matches!(self, Self::SiphonRtp) {
            if flags.ws_uri.is_some() {
                unsupported.push("ws_uri");
            }
            if flags.ws_vad {
                unsupported.push("ws_vad");
            }
            if flags.ws_barge_in {
                unsupported.push("ws_barge_in");
            }
            if flags.ws_vad_threshold.is_some() {
                unsupported.push("ws_vad_threshold");
            }
            if flags.ws_vad_hangover_ms.is_some() {
                unsupported.push("ws_vad_hangover_ms");
            }
            if flags.ws_sample_rate.is_some() {
                unsupported.push("ws_sample_rate");
            }
            if flags.ws_vad_engine.is_some() {
                unsupported.push("ws_vad_engine");
            }
            if flags.ws_vad_min_speech_ms.is_some() {
                unsupported.push("ws_vad_min_speech_ms");
            }
            if flags.beep_detection {
                unsupported.push("beep_detection");
            }
            if flags.beep_cadence_guard_ms.is_some() {
                unsupported.push("beep_cadence_guard_ms");
            }
            if flags.noise_suppression {
                unsupported.push("noise_suppression");
            }
            if flags.echo_cancellation {
                unsupported.push("echo_cancellation");
            }
            if flags.ws_tee.is_some() {
                unsupported.push("ws_tee");
            }
            if flags.ws_tee_direction.is_some() {
                unsupported.push("ws_tee_direction");
            }
            if flags.ws_tee_channels.is_some() {
                unsupported.push("ws_tee_channels");
            }
            if flags.ws_tee_sample_rate.is_some() {
                unsupported.push("ws_tee_sample_rate");
            }
            if flags.text_events {
                unsupported.push("text_events");
            }
        }

        if matches!(self, Self::Rtpproxy) {
            if flags.received_from {
                unsupported.push("received_from");
            }
            if !flags.rtcp_mux.is_empty() {
                unsupported.push("rtcp_mux");
            }
        }

        // Codec manipulation works on both real engines. rtpengine takes it as
        // its NG `codec` dict; the native engine implements the same model but
        // reads it off the flag list, so siphon flattens the block for it
        // (`CodecFlags::to_native_flags`). Only the two ops with no native
        // equivalent are refused there — the alternative is a config that reads
        // as "restricted to PCMA/PCMU" while every offered codec crosses
        // untouched, which is the failure this feature replaces.
        if matches!(self, Self::SiphonRtp) {
            for op in flags.codec.native_unsupported_ops() {
                unsupported.push(op);
            }
        }
        // rtpproxy is a plain relay with no transcoder and no codec control.
        if matches!(self, Self::Rtpproxy) && !flags.codec.is_empty() {
            unsupported.push("codec");
        }

        unsupported
    }
}

/// Media proxy configuration.
#[derive(Debug, Deserialize, Clone)]
pub struct MediaConfig {
    /// Which media engine to drive. Defaults to `rtpengine` for backward
    /// compatibility; set to `siphon-rtp` to use the native JSON-over-TCP
    /// engine via the `siphon_rtp:` block below.
    #[serde(default)]
    pub backend: MediaBackendKind,
    /// RTPEngine instance(s). A single instance or a list for load-balancing / HA.
    /// Required when `backend: rtpengine` (the default); ignored for `siphon-rtp`.
    #[serde(default)]
    pub rtpengine: Option<RtpEngineSetConfig>,
    /// Native `siphon-rtp` engine connection. Required when `backend: siphon-rtp`.
    #[serde(default)]
    pub siphon_rtp: Option<SiphonRtpConfig>,
    /// Classic `rtpproxy` relay connection. Required when `backend: rtpproxy`.
    #[serde(default)]
    pub rtpproxy: Option<RtpProxyConfig>,
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

/// Connection to the native `siphon-rtp` media engine (JSON-over-TCP control).
///
/// Accepts a single engine (`address`) or several (`instances`) for HA /
/// load-balancing, mirroring `media.rtpengine`. Per-call-id affinity keeps all
/// of a call's commands on one connection (siphon-rtp keys call ownership to the
/// control connection). `control_secret` is shared across all instances.
///
/// Events (DTMF, media-timeout) arrive on the control connection itself, so the
/// rtpengine-specific `media.events` listener is not used with this backend.
#[derive(Debug, Deserialize, Clone)]
pub struct SiphonRtpConfig {
    /// Single control endpoint, e.g. ``"127.0.0.1:8080"``
    /// (`siphon-rtp --control <addr>`). Shorthand for one instance; ignored when
    /// `instances` is non-empty.
    #[serde(default)]
    pub address: Option<String>,
    /// Multiple control endpoints for HA / weighted load-balancing. Takes
    /// precedence over `address` when present.
    #[serde(default)]
    pub instances: Vec<SiphonRtpInstanceConfig>,
    /// Optional shared secret. When set, siphon authenticates each control
    /// connection before issuing commands (matches `siphon-rtp`'s
    /// `SIPHON_RTP_CONTROL_SECRET`). Supports `${VAR}` env expansion.
    #[serde(default)]
    pub control_secret: Option<String>,
    /// Default per-command response timeout in milliseconds (per-instance
    /// `timeout_ms` overrides it). Default: 2000.
    #[serde(default = "default_siphon_rtp_timeout_ms")]
    pub timeout_ms: u64,
    /// Fallback cap in milliseconds for a blocking `rtpengine.play_media()` — how
    /// long to wait for the prompt-finished event before giving up. A prompt can
    /// be far longer than a control request, so this is separate from
    /// `timeout_ms`. Default: 300000 (5 min).
    #[serde(default = "default_siphon_rtp_play_timeout_ms")]
    pub play_timeout_ms: u64,
}

impl SiphonRtpConfig {
    /// Normalized `(address, timeout_ms, weight)` tuples — from `instances` when
    /// present, else the single `address`. Empty when neither is configured.
    pub fn instances(&self) -> Vec<(String, u64, u32)> {
        if !self.instances.is_empty() {
            self.instances
                .iter()
                .map(|instance| {
                    (
                        instance.address.clone(),
                        instance.timeout_ms.unwrap_or(self.timeout_ms),
                        instance.weight,
                    )
                })
                .collect()
        } else if let Some(address) = &self.address {
            vec![(address.clone(), self.timeout_ms, 1)]
        } else {
            Vec::new()
        }
    }
}

/// One `siphon-rtp` control endpoint in a multi-instance set.
#[derive(Debug, Deserialize, Clone)]
pub struct SiphonRtpInstanceConfig {
    /// Control endpoint, e.g. ``"10.0.0.1:8080"``.
    pub address: String,
    /// Response timeout in ms; falls back to the parent `timeout_ms` when unset.
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    /// Weight for load-balancing (higher = more traffic). Default: 1.
    #[serde(default = "default_rtpengine_weight")]
    pub weight: u32,
}

/// Connection to a classic `rtpproxy` media relay (text-over-UDP control).
///
/// Accepts a single relay (`address`) or several (`instances`) for HA /
/// load-balancing, mirroring `media.rtpengine`. Per-call-id affinity keeps all
/// of a call's commands on one relay (the allocated ports live on one instance).
///
/// rtpproxy only allocates relay ports and returns them; siphon rewrites the SDP
/// itself. The rtpengine-only verbs (announcements, DTMF injection, gating,
/// SIPREC/MPTY) are not available on this backend. The rtpengine `media.events`
/// listener is also unused — rtpproxy pushes no async events.
#[derive(Debug, Deserialize, Clone)]
pub struct RtpProxyConfig {
    /// Single control endpoint, e.g. ``"127.0.0.1:22222"``
    /// (`rtpproxy -s udp:<addr>`). Shorthand for one instance; ignored when
    /// `instances` is non-empty.
    #[serde(default)]
    pub address: Option<String>,
    /// Multiple control endpoints for HA / weighted load-balancing. Takes
    /// precedence over `address` when present.
    #[serde(default)]
    pub instances: Vec<RtpProxyInstanceConfig>,
    /// Default per-command response budget in milliseconds, split across
    /// retransmits (per-instance `timeout_ms` overrides it). Default: 1000.
    #[serde(default = "default_rtpproxy_timeout_ms")]
    pub timeout_ms: u64,
    /// Retransmits after the first send before giving up. rtpproxy de-duplicates
    /// by cookie, so retransmitting the same command is safe and is the standard
    /// way to ride out UDP loss. Default: 2 (i.e. up to 3 sends).
    #[serde(default = "default_rtpproxy_retries")]
    pub retries: u32,
}

impl RtpProxyConfig {
    /// Normalized `(address, timeout_ms, weight)` tuples — from `instances` when
    /// present, else the single `address`. Empty when neither is configured.
    pub fn instances(&self) -> Vec<(String, u64, u32)> {
        if !self.instances.is_empty() {
            self.instances
                .iter()
                .map(|instance| {
                    (
                        instance.address.clone(),
                        instance.timeout_ms.unwrap_or(self.timeout_ms),
                        instance.weight,
                    )
                })
                .collect()
        } else if let Some(address) = &self.address {
            vec![(address.clone(), self.timeout_ms, 1)]
        } else {
            Vec::new()
        }
    }
}

/// One `rtpproxy` control endpoint in a multi-instance set.
#[derive(Debug, Deserialize, Clone)]
pub struct RtpProxyInstanceConfig {
    /// Control endpoint, e.g. ``"10.0.0.1:22222"``.
    pub address: String,
    /// Response timeout in ms; falls back to the parent `timeout_ms` when unset.
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    /// Weight for load-balancing (higher = more traffic). Default: 1.
    #[serde(default = "default_rtpengine_weight")]
    pub weight: u32,
}

fn default_rtpproxy_timeout_ms() -> u64 {
    1000
}

fn default_rtpproxy_retries() -> u32 {
    2
}

fn default_siphon_rtp_timeout_ms() -> u64 {
    2000
}

fn default_siphon_rtp_play_timeout_ms() -> u64 {
    300_000
}

/// Serde deserializer for a media profile's `address_family`, canonicalising to
/// the `IP4`/`IP6` spelling every media engine expects (it is the SDP `addrtype`
/// token — rtpengine's `"address family"` NG key, siphon-rtp's `address_family`
/// JSON field).
///
/// Case-insensitive, and `ipv4`/`ipv6` are accepted as aliases.  Any other value
/// is a config error: the engines ignore an unknown family silently, so a typo
/// would otherwise land as a relay quietly allocated in the wrong family.
fn deserialize_address_family<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de;

    let value: Option<String> = Option::deserialize(deserializer)?;
    let Some(value) = value else {
        return Ok(None);
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "ip4" | "ipv4" => Ok(Some("IP4".to_string())),
        "ip6" | "ipv6" => Ok(Some("IP6".to_string())),
        other => Err(de::Error::custom(format!(
            "media profile address_family must be \"IP4\" or \"IP6\" (aliases \
             \"ipv4\"/\"ipv6\"), got {other:?}"
        ))),
    }
}

/// Serde deserializer for a media profile's `rtcp_mux` directive list.
///
/// The engines accept a fixed vocabulary (RFC 5761 mux handling); an unknown
/// token is silently ignored, which would land as a call quietly negotiating the
/// opposite mux decision from the one the operator wrote.  Same reasoning as
/// [`deserialize_address_family`].
fn deserialize_rtcp_mux<'de, D>(deserializer: D) -> std::result::Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de;

    const VALID: [&str; 6] = ["offer", "require", "demux", "accept", "reject", "remove"];

    let values: Vec<String> = Vec::deserialize(deserializer)?;
    values
        .into_iter()
        .map(|value| {
            let normalised = value.trim().to_ascii_lowercase();
            if VALID.contains(&normalised.as_str()) {
                Ok(normalised)
            } else {
                Err(de::Error::custom(format!(
                    "media profile rtcp_mux entries must be one of {}, got {value:?}",
                    VALID.join(", ")
                )))
            }
        })
        .collect()
}

/// Validate a WebSocket URI field, naming `field` in the error.
///
/// The engine dials these as a WebSocket client, so anything that is not
/// `ws://` / `wss://` can never connect.  Caught here rather than as a
/// connect failure per call.  `field` is threaded through so an operator with
/// a bad `ws_tee` is not told about `ws_uri`, a field they never set.
fn validate_ws_uri_field<E>(
    value: Option<String>,
    field: &str,
) -> std::result::Result<Option<String>, E>
where
    E: serde::de::Error,
{
    let Some(value) = value else {
        return Ok(None);
    };
    let trimmed = value.trim();
    let scheme = trimmed.split("://").next().unwrap_or_default();
    match scheme.to_ascii_lowercase().as_str() {
        "ws" | "wss" if trimmed.contains("://") => Ok(Some(trimmed.to_string())),
        _ => Err(E::custom(format!(
            "media profile {field} must be a ws:// or wss:// URI, got {value:?}"
        ))),
    }
}

/// Serde deserializer for a media profile's `ws_uri`.
fn deserialize_ws_uri<'de, D>(deserializer: D) -> std::result::Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    validate_ws_uri_field(Option::deserialize(deserializer)?, "ws_uri")
}

/// Serde deserializer for a media profile's `ws_tee`.
fn deserialize_ws_tee<'de, D>(deserializer: D) -> std::result::Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    validate_ws_uri_field(Option::deserialize(deserializer)?, "ws_tee")
}

/// Validate `ws_tee_direction` against the three values the engine accepts.
///
/// A direction the engine would reject is a config error rather than a value
/// relayed onto the wire, matching how `address_family` is validated at load.
fn deserialize_ws_tee_direction<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<WsTeeDirection>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de;

    let value: Option<String> = Option::deserialize(deserializer)?;
    let Some(value) = value else {
        return Ok(None);
    };
    WsTeeDirection::parse(&value).map(Some).ok_or_else(|| {
        de::Error::custom(format!(
            "media profile ws_tee_direction must be one of {}, got {value:?}",
            WsTeeDirection::VALUES.join(" / ")
        ))
    })
}

/// Accept `energy` / `neural` case-insensitively for `ws_vad_engine`.
///
/// A detector the engine would reject is a config error rather than a value
/// relayed onto the wire, matching `ws_tee_direction` above.  It is deliberately
/// *not* forgiving: falling back to a detector the operator was explicitly
/// avoiding is the silent downgrade the media engine already refuses.
fn deserialize_ws_vad_engine<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<WsVadEngine>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de;

    let value: Option<String> = Option::deserialize(deserializer)?;
    let Some(value) = value else {
        return Ok(None);
    };
    WsVadEngine::parse(&value).map(Some).ok_or_else(|| {
        de::Error::custom(format!(
            "media profile ws_vad_engine must be one of {}, got {value:?}",
            WsVadEngine::VALUES.join(" / ")
        ))
    })
}

/// Validate `ws_sample_rate` at config load.
///
/// The media engine *fails* an offer/answer carrying an out-of-range rate rather
/// than clamping it, so a profile with a bad value produces calls that answer
/// and never get media.  Rejecting at load means the operator learns at boot.
fn deserialize_ws_sample_rate<'de, D>(deserializer: D) -> std::result::Result<Option<u32>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_checked_sample_rate(deserializer, "ws_sample_rate")
}

/// Validate `ws_tee_sample_rate` at config load — same rule, same reason.
fn deserialize_ws_tee_sample_rate<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<u32>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_checked_sample_rate(deserializer, "ws_tee_sample_rate")
}

/// Shared body for the two L16 wire-rate fields, so the rule lives in one place.
fn deserialize_checked_sample_rate<'de, D>(
    deserializer: D,
    field: &str,
) -> std::result::Result<Option<u32>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de;

    let value: Option<u32> = Option::deserialize(deserializer)?;
    let Some(rate) = value else {
        return Ok(None);
    };
    validate_ws_sample_rate(rate)
        .map_err(|reason| de::Error::custom(format!("media profile {field} {reason}")))?;
    Ok(Some(rate))
}

/// A user-defined RTPEngine media profile with separate offer/answer NG flags.
#[derive(Debug, Deserialize, Clone)]
pub struct MediaProfileConfig {
    pub offer: NgFlagsConfig,
    pub answer: NgFlagsConfig,
}

/// rtpengine `codec` dictionary — which codecs cross, in what order, and what
/// gets transcoded. Modelled on the rtpengine NG `codec` sub-dict, which the
/// native engine implements too.
///
/// Every field is a list of RTP payload names (`PCMA`, `opus`, `AMR-WB`), and
/// an empty one is omitted from the wire entirely.
///
/// Works on both real engines from one block: rtpengine takes it as its NG
/// `codec` dictionary, and the native `siphon-rtp` engine implements the same
/// model but reads it off its flag list, so siphon flattens the block to
/// `codec-<op>-<NAME>` for it.
///
/// `ignore` and `set` have no native equivalent and are refused on that backend;
/// `rtpproxy` is a plain relay with no transcoder and refuses the block outright.
/// Refused at config load, never silently dropped — a codec policy that reads as
/// applied but is not is the failure this exists to remove.
///
/// **Honoured on `offer:`.** Both engines apply codec manipulation to the offer
/// and ignore most of it on an answer, so put it under the `offer:` half.
///
/// ```yaml
/// offer:
///   codec:
///     strip: ["SILK", "G722"]
///     offer: ["PCMA", "PCMU", "telephone-event"]
/// ```
#[derive(Debug, Deserialize, Clone, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CodecFlagsConfig {
    /// Remove these from the outgoing SDP. Accepts the wildcards `all` / `full`.
    #[serde(default)]
    pub strip: Vec<String>,
    /// The only codecs to offer, in this order (rtpengine `offer`) — like
    /// `except` but also fixes preference order.
    #[serde(default)]
    pub offer: Vec<String>,
    /// Add these to the offer even when the offerer did not list them, engaging
    /// the transcoder.
    #[serde(default)]
    pub transcode: Vec<String>,
    /// Hide these from the far side but keep accepting them from the offerer,
    /// transcoding on its behalf.
    #[serde(default)]
    pub mask: Vec<String>,
    /// Like `mask`, but engages the transcoder even with no other codec option set.
    #[serde(default)]
    pub consume: Vec<String>,
    /// Like `mask`/`consume` but leaves the codec in the offered list.
    #[serde(default)]
    pub accept: Vec<String>,
    /// Allow only these through, blocking every other offered codec.
    #[serde(default)]
    pub except: Vec<String>,
    /// Treat these as though the offer never contained them.
    #[serde(default)]
    pub ignore: Vec<String>,
    /// Options for implicitly accepted transcoding codecs — bitrate, clock rate,
    /// channels (e.g. `opus/48000/2/16000`).
    #[serde(default)]
    pub set: Vec<String>,
}

impl CodecFlagsConfig {
    /// The ops the native `siphon-rtp` engine has no equivalent for. It
    /// implements the rest of the rtpengine codec model, so only these are
    /// refused on that backend.
    pub fn native_unsupported_ops(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if !self.ignore.is_empty() {
            out.push("codec.ignore");
        }
        if !self.set.is_empty() {
            out.push("codec.set");
        }
        out
    }

    /// True when nothing is set, so nothing is emitted on the wire.
    pub fn is_empty(&self) -> bool {
        self.strip.is_empty()
            && self.offer.is_empty()
            && self.transcode.is_empty()
            && self.mask.is_empty()
            && self.consume.is_empty()
            && self.accept.is_empty()
            && self.except.is_empty()
            && self.ignore.is_empty()
            && self.set.is_empty()
    }
}

/// NG protocol flags for one direction (offer or answer).
#[derive(Debug, Deserialize, Clone, Default)]
pub struct NgFlagsConfig {
    /// Transport protocol override (e.g. "RTP/AVP", "RTP/SAVPF").
    pub transport_protocol: Option<String>,
    /// Codec manipulation — see [`CodecFlagsConfig`]. Honoured by rtpengine and
    /// the native `siphon-rtp` engine; refused on `rtpproxy`.
    #[serde(default)]
    pub codec: CodecFlagsConfig,
    /// ICE handling: "remove", "force", or "force-relay".
    pub ice: Option<String>,
    /// DTLS mode: "passive", "active", or "off".
    pub dtls: Option<String>,
    /// SDP fields to replace: "origin".
    #[serde(default)]
    pub replace: Vec<String>,
    /// Address family the engine should allocate its relay endpoints in for this
    /// side of the call: `"IP4"` or `"IP6"`.  Unset (the default) leaves the
    /// engine following the offered SDP's own family — a single-family relay.
    ///
    /// Setting it is how an IPv4↔IPv6 interworking leg is expressed: a v6 VoLTE
    /// access side bridged to a v4 core sets `address_family: "IP4"` on the
    /// profile used toward the core.  Accepted case-insensitively, and `ipv4`/
    /// `ipv6` are taken as aliases; anything else is a hard config error rather
    /// than a value the media engine would silently ignore.
    #[serde(default, deserialize_with = "deserialize_address_family")]
    pub address_family: Option<String>,
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
    /// Single-channel noise suppression on this leg's decoded ingress audio.
    /// `siphon-rtp` backend only.
    #[serde(default)]
    pub noise_suppression: bool,
    /// Acoustic/line echo cancellation on this leg's send path, referenced
    /// against the audio played toward that party.  `siphon-rtp` backend only.
    #[serde(default)]
    pub echo_cancellation: bool,
    /// Bridge this leg's audio to an external WebSocket media server: the engine
    /// dials this URI and relays the leg's RTP to it as L16.  `siphon-rtp`
    /// backend only.
    ///
    /// Supports `{call_id}`, `{from_tag}`, `{from_user}` and `{to_user}`
    /// placeholders, expanded per call.  A script can override the whole URI for
    /// one call with `rtpengine.offer(..., ws_uri=...)`.
    #[serde(default, deserialize_with = "deserialize_ws_uri")]
    pub ws_uri: Option<String>,
    /// Run a local energy-VAD on the WebSocket uplink and emit
    /// `speech_started`/`speech_stopped` on the caller's speech edges.  Inert
    /// without `ws_uri`.  `siphon-rtp` backend only.
    #[serde(default)]
    pub ws_vad: bool,
    /// Flush queued downlink playout locally when the caller starts speaking,
    /// without a server round-trip.  Implies `ws_vad`; inert without `ws_uri`.
    /// `siphon-rtp` backend only.
    #[serde(default)]
    pub ws_barge_in: bool,
    /// Mean-square energy threshold for the WebSocket uplink VAD.  Unset uses
    /// the engine default; higher is less sensitive.
    #[serde(default)]
    pub ws_vad_threshold: Option<i64>,
    /// Trailing hangover for the WebSocket uplink VAD in milliseconds — how long
    /// speech is held after energy drops before the turn endpoint fires.  Unset
    /// uses the engine default.  Only meaningful with the `energy` detector;
    /// `neural` holds speech with its own probability hysteresis.
    #[serde(default)]
    pub ws_vad_hangover_ms: Option<u32>,
    /// L16 wire sample rate in Hz for the `ws_uri` takeover bridge, independent
    /// of the leg's codec rate and applied in both directions (uplink resampled
    /// into it, downlink resampled back before re-encoding).  So an 8 kHz G.711
    /// call can speak 16 kHz to the server, and a server rendering 24 kHz audio
    /// plays at the right speed and pitch.
    ///
    /// Also the domain the noise suppressor and echo canceller run in, and those
    /// engage only at 8 or 16 kHz.  Must be a multiple of 1000 within
    /// 8000–48000 — the engine *fails* the offer rather than clamping, so a bad
    /// value is rejected here at boot.  Inert without `ws_uri`.  `siphon-rtp`
    /// backend only.
    #[serde(default, deserialize_with = "deserialize_ws_sample_rate")]
    pub ws_sample_rate: Option<u32>,
    /// Which detector the WebSocket uplink VAD runs: `energy` (default, cheap,
    /// but any loud sound reads as speech) or `neural` (answers "is this
    /// speech", so it does not turn-start on noise).  Inert without `ws_vad` /
    /// `ws_barge_in`.  `siphon-rtp` backend only.
    #[serde(default, deserialize_with = "deserialize_ws_vad_engine")]
    pub ws_vad_engine: Option<WsVadEngine>,
    /// **Leading** minimum-speech run in milliseconds: how long the uplink must
    /// read as speech *continuously* before the speech-start edge (and barge-in)
    /// fires.  Distinct from the trailing `ws_vad_hangover_ms`.
    ///
    /// Unset means no leading requirement — the edge fires on the first speech
    /// frame, which is what lets a cough or one burst of echo interrupt a
    /// prompt.  Rounded up to whole ptime frames and added directly to
    /// turn-start latency, so 60–120 ms is the useful range.  `siphon-rtp` only.
    #[serde(default)]
    pub ws_vad_min_speech_ms: Option<u32>,
    /// Watch this leg's decoded ingress audio for the short tone an answering
    /// machine plays before recording (the "voicemail beep") and deliver it to
    /// `@rtpengine.on_beep` — the media half of answering-machine detection.
    ///
    /// Set per leg, so arming it on the profile used toward the callee is what
    /// watches the party that might be a machine.  Needs decoded audio, so it
    /// promotes a same-codec plaintext call onto the userspace pipeline, and it
    /// is inert unless the codec's native rate is 8 or 16 kHz.  Fires once per
    /// leg per call — no mid-call re-arm.  `siphon-rtp` backend only.
    #[serde(default)]
    pub beep_detection: bool,
    /// How long in milliseconds the beep detector waits after a candidate tone
    /// to confirm no repeat follows — what keeps a cadenced ringback / busy tone
    /// from reading as a record tone.  **Also the detection latency**: the event
    /// arrives this long after the beep.  Unset uses the engine default
    /// (4500 ms).  Inert without `beep_detection`.  `siphon-rtp` backend only.
    #[serde(default)]
    pub beep_cadence_guard_ms: Option<u32>,
    /// Attach a **WebSocket tee** to this call: the engine dials this URI and
    /// streams a copy of the call's decoded audio to it as L16.  `siphon-rtp`
    /// backend only.
    ///
    /// Distinct from `ws_uri`, and the distinction matters: `ws_uri` is a
    /// *takeover* (the WS server becomes leg A's far side, the A↔B relay is not
    /// wired), a tee is *send-only and additive* (the call relays normally and
    /// the tee streams a copy, leaving SIPREC and recording untouched).
    ///
    /// Supports the same `{call_id}`, `{from_tag}`, `{from_user}` and
    /// `{to_user}` placeholders as `ws_uri`, expanded per call.  A script can
    /// attach or detach a tee on a live call with
    /// `rtpengine.attach_ws_tee(...)` / `rtpengine.detach_ws_tee(...)`.
    #[serde(default, deserialize_with = "deserialize_ws_tee")]
    pub ws_tee: Option<String>,
    /// Which leg(s) `ws_tee` streams: `both` (default), `caller` or `callee`.
    /// Inert without `ws_tee`.
    #[serde(default, deserialize_with = "deserialize_ws_tee_direction")]
    pub ws_tee_direction: Option<WsTeeDirection>,
    /// Wire channel count for `ws_tee`: `2` interleaves caller/callee as stereo,
    /// `1` mixes them to mono.  Only meaningful with `ws_tee_direction: both` —
    /// a single-leg tee is always mono.  Unset uses the engine default (2 for
    /// both legs, 1 for one).  Inert without `ws_tee`.
    #[serde(default)]
    pub ws_tee_channels: Option<u8>,
    /// L16 wire sample rate in Hz for `ws_tee`, independent of the legs' codec
    /// rates — the engine resamples the teed copy into it.  Send-only, unlike
    /// `ws_sample_rate`: it changes only what the tee consumer receives, never
    /// what the call itself hears.
    ///
    /// Must be a multiple of 1000 within 8000–48000 — the engine *fails* the
    /// offer rather than clamping, so a bad value is rejected here at boot.
    /// Inert without `ws_tee`.  `siphon-rtp` backend only.
    #[serde(default, deserialize_with = "deserialize_ws_tee_sample_rate")]
    pub ws_tee_sample_rate: Option<u32>,
    /// Carry the real post-NAT source IP the proxy saw the request arrive from
    /// (rtpengine's `received from`), gating the leg's media ingress to it.
    ///
    /// A tighter source gate than a NATed UA's unusable private `c=` address.
    /// Opt-in, and off by default: a profile that leaves it unset emits exactly
    /// the command it did before this knob existed.  Not honoured by `rtpproxy`.
    #[serde(default)]
    pub received_from: bool,
    /// `rtcp-mux` directives (`offer`, `require`, `demux`, `accept`, `reject`,
    /// `remove`), overriding the mux decision derived from the offered SDP
    /// (RFC 5761).  Empty mirrors the offer.  Not honoured by `rtpproxy`.
    #[serde(default, deserialize_with = "deserialize_rtcp_mux")]
    pub rtcp_mux: Vec<String>,
    /// Observe RFC 4103 real-time text on this call, delivering each recovered
    /// T.140 increment to `@rtpengine.on_text` and per-leg reception counters in
    /// the media CDR.  Promotes only the `m=text` stream, never audio, and is
    /// inert on a call that negotiated no text.  `siphon-rtp` only.
    #[serde(default)]
    pub text_events: bool,
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
    Set {
        instances: Vec<RtpEngineInstanceConfig>,
    },
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
    /// Source IP CIDR ranges whose senders count as members of this group for
    /// `request.from_gateway` / `call.from_gateway`, in addition to the
    /// destinations' resolved addresses.
    ///
    /// Use this for a peer that sources SIP from a whole published subnet rather
    /// than only the IPs its signalling FQDNs resolve to — a carrier trunk or
    /// cloud voice service whose inbound signalling can arrive from any address
    /// in a documented range, not just what its SIP FQDNs currently resolve to.
    /// Listing the ranges here makes membership stable regardless of DNS. Each
    /// entry is a CIDR or a bare IP, IPv4 or IPv6: `"203.0.113.0/24"`,
    /// `"2001:db8::/32"`, or a bare address (`"203.0.113.7"` → `/32`,
    /// `"2001:db8::1"` → `/128`).
    #[serde(default)]
    pub source_networks: Vec<String>,
    /// SIP response codes from a carrier in this group that trigger LCR failover
    /// to the next carrier, overriding the global `lcr.reroute_causes` for routes
    /// dialed through this group. For a carrier that doesn't play nice with the
    /// standard codes (e.g. sends `404`/`403` for "no circuits"). Empty = use the
    /// global set. A per-route `reroute_causes` from the API wins over this.
    #[serde(default)]
    pub reroute_causes: Vec<u16>,
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
            let end = after.find([';', '>', ' ']).unwrap_or(after.len());
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
///   service_context_id: "32260@3gpp.org"   # TS 32.260 IMS = 32260, SMS = 32274, MMTel = 32275
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

fn default_true() -> bool {
    true
}
fn default_rf_node_functionality() -> String {
    "scscf".to_string()
}
fn default_rf_service_context_id() -> String {
    "32260@3gpp.org".to_string()
}

/// Ro online charging (Diameter Credit-Control) configuration.
///
/// **B2BUA-only.** Ro enforcement (reserve → re-authorize → *disconnect the
/// call* when credit runs out) requires siphon to own and be able to tear down
/// the session, which is a B2BUA capability. This matches 3GPP: online charging
/// is triggered by the **AS / MMTel-AS** (TS 32.275), never by the P-CSCF (a
/// P-CSCF is an *offline*/Rf node). There is no proxy-mode Ro auto-emit — run
/// the charging siphon as a B2BUA (e.g. an MMTel-AS on ISC). The raw
/// `diameter.ro_ccr_*` scripting API is available in any mode for manual use,
/// but auto-emit + mid-call teardown only fire on B2BUA calls.
///
/// Reserve-before-connect is **script-driven**: a `@b2bua.on_invite` handler
/// calls `await call.ro_authorize(...)` BEFORE `call.dial(...)`. On a grant it
/// dials the B-leg; on a denial it rejects with `credit_denied_status` and no
/// B-leg is ever created (prepaid: no call unless the OCS allows it). siphon
/// then runs the re-auth loop and disconnects mid-call on exhaustion, and sends
/// CCR-TERMINATION on BYE — all autonomously. There is no config auto-emit
/// because the correct prepaid gate has to sit before the script's dial
/// decision (some calls aren't charged at all).
///
/// ```yaml
/// ro:
///   enabled: true
///   reauth_interval_secs: 30      # customer cadence; the OCS-granted quota overrides
///   requested_seconds: 30         # Requested-Service-Unit CC-Time (0 = empty RSU, OCS decides)
///   node_functionality: as        # as (MMTel-AS, standard) | scscf | ...
///   service_context_id: "32260@3gpp.org"       # voice (SCUR); 32275 for MMTel-AS
///   sms_service_context_id: "32274@3gpp.org"   # SMS/RCS (IEC)
///   charge: orig                  # orig | term | both
///   charge_message: true          # one-shot IEC on SIP MESSAGE (SMS/RCS)
///   on_ocs_failure: terminate     # terminate (fail-closed) | continue (fail-open)
///   credit_denied_status: 402     # SIP status when the OCS denies at setup
///   rating_group: 100             # optional; presence selects the MSCC (multi-service) shape
///   peer: ocs1                    # optional explicit OCS peer
/// ```
#[derive(Debug, Deserialize, Clone)]
pub struct RoConfig {
    /// Master switch. Default: false.
    #[serde(default)]
    pub enabled: bool,
    /// Fallback re-authorization cadence (seconds) when the OCS grants no
    /// CC-Time / Validity-Time. The OCS-granted quota is authoritative and
    /// overrides this. Default: 30.
    #[serde(default = "default_ro_interval")]
    pub reauth_interval_secs: u32,
    /// Requested-Service-Unit CC-Time (seconds) asked for on CCR-INITIAL/UPDATE.
    /// 0 = emit an empty RSU and let the OCS decide the quota. Default: 30.
    #[serde(default = "default_ro_interval")]
    pub requested_seconds: u32,
    /// Node-Functionality for the IMS-Information (TS 32.299 §7.2.111). The
    /// textbook Ro trigger is the AS/S-CSCF; `pcscf` reflects edge enforcement.
    /// Default: ``"pcscf"``.
    #[serde(default = "default_ro_node_functionality")]
    pub node_functionality: String,
    /// Service-Context-Id for voice SCUR (TS 32.260). Default ``"32260@3gpp.org"``.
    #[serde(default = "default_rf_service_context_id")]
    pub service_context_id: String,
    /// Service-Context-Id for SMS/RCS IEC (TS 32.274). Default ``"32274@3gpp.org"``.
    #[serde(default = "default_ro_sms_service_context_id")]
    pub sms_service_context_id: String,
    /// Which party to charge: ``"orig"`` | ``"term"`` | ``"both"``. Default ``"orig"``.
    #[serde(default = "default_ro_charge")]
    pub charge: String,
    /// When the chargeable clock starts: ``"answer"`` | ``"invite"``.
    /// Default ``"answer"``.
    ///
    /// ``answer`` counts reported usage from the 200 OK, which is what
    /// TS 32.260 means by chargeable duration. ``invite`` counts from the
    /// CCR-INITIAL — i.e. from the reservation, before any carrier was dialled
    /// — so ring time is billed. That was the only behaviour before this
    /// setting existed; it is kept for anyone who depended on it.
    ///
    /// Only the clock moves. The reservation still happens at INVITE, because
    /// reserve-before-connect is the entire point of the prepaid gate.
    #[serde(default = "default_ro_charge_from")]
    pub charge_from: String,
    /// One-shot IEC charging on SIP MESSAGE (SMS/RCS). Default: true.
    #[serde(default = "default_true")]
    pub charge_message: bool,
    /// Behavior when the OCS is unreachable / times out (Credit-Control-Failure-
    /// Handling): ``"terminate"`` (fail-closed) | ``"continue"`` (fail-open).
    /// Default ``"terminate"``.
    #[serde(default = "default_ro_ocs_failure")]
    pub on_ocs_failure: String,
    /// SIP status returned when the OCS denies credit at setup. Default: 402.
    #[serde(default = "default_ro_denied_status")]
    pub credit_denied_status: u16,
    /// Optional Rating-Group. When set (or `service_identifier`), the CCR uses
    /// the multi-service MSCC shape; otherwise single-service command-level.
    pub rating_group: Option<u32>,
    /// Optional Service-Identifier.
    pub service_identifier: Option<u32>,
    /// Explicit OCS peer name. When unset, the first registered peer is used.
    pub peer: Option<String>,
}

impl Default for RoConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            reauth_interval_secs: default_ro_interval(),
            requested_seconds: default_ro_interval(),
            node_functionality: default_ro_node_functionality(),
            service_context_id: default_rf_service_context_id(),
            sms_service_context_id: default_ro_sms_service_context_id(),
            charge: default_ro_charge(),
            charge_from: default_ro_charge_from(),
            charge_message: true,
            on_ocs_failure: default_ro_ocs_failure(),
            credit_denied_status: default_ro_denied_status(),
            rating_group: None,
            service_identifier: None,
            peer: None,
        }
    }
}

fn default_ro_interval() -> u32 {
    30
}
fn default_ro_node_functionality() -> String {
    "pcscf".to_string()
}
fn default_ro_sms_service_context_id() -> String {
    "32274@3gpp.org".to_string()
}
/// Chargeable duration runs from the answer (TS 32.260 §5): a call that rings
/// and is never answered has no chargeable duration at all.
fn default_ro_charge_from() -> String {
    "answer".to_string()
}

fn default_ro_charge() -> String {
    "orig".to_string()
}
fn default_ro_ocs_failure() -> String {
    "terminate".to_string()
}
fn default_ro_denied_status() -> u16 {
    402
}

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
    /// Rename the file out of the way once it reaches this size, in MB, so
    /// the next record starts a fresh one. Rotated files are named
    /// `<path>.<UTC timestamp>` and are never deleted — retention belongs to
    /// logrotate or whatever ships them. `0` disables rotation entirely.
    /// Default: 100.
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
                let target = self
                    .syslog
                    .as_ref()
                    .map(|s| s.target.clone())
                    .unwrap_or_else(|| "127.0.0.1:514".to_string());
                crate::cdr::CdrBackendType::Syslog { target }
            }
            "http" => {
                let (url, auth_header) = self
                    .http
                    .as_ref()
                    .map(|h| (h.url.clone(), h.auth_header.clone()))
                    .unwrap_or_else(|| ("http://127.0.0.1:9080/cdr".to_string(), None));
                crate::cdr::CdrBackendType::Http { url, auth_header }
            }
            _ => {
                let (path, rotate_size_mb) = self
                    .file
                    .as_ref()
                    .map(|f| (f.path.clone(), f.rotate_size_mb))
                    .unwrap_or_else(|| (default_cdr_file_path(), default_cdr_rotate_size()));
                crate::cdr::CdrBackendType::File {
                    path,
                    rotate_size_mb,
                }
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
///     enabled: true
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
    /// Bind address for the X1 HTTPS listener (e.g. "0.0.0.0:8443").
    pub listen: String,
    /// Path the single X1 endpoint is served on.
    ///
    /// TS 103 221-1 mandates one endpoint but does not name it. `/X1/NE` is
    /// the convention (it is the default target of the sipgate X1/X2/X3
    /// simulator, among others); confirm it with the mediation partner, since
    /// a wrong path stops the very first message reaching the server.
    #[serde(default = "default_x1_path")]
    pub path: String,
    /// TLS for the listener. Mutual TLS is the authentication on X1, so
    /// `client_ca` is required — see [`LiX1TlsConfig`].
    pub tls: LiX1TlsConfig,
    /// This network element's identifier, as it appears in `neIdentifier`.
    pub ne_identifier: String,
    /// The ADMF identifier this element expects in `admfIdentifier`.
    ///
    /// When set, a message naming a different ADMF is refused with
    /// `UnexpectedAdmfIdentifier` (1040). When unset, any well-formed
    /// identifier is accepted and only the certificate binding applies.
    pub admf_identifier: Option<String>,
    /// The schema version declared in every message's `version` element.
    ///
    /// Defaults to the version this build implements. Override only when a
    /// mediation partner pins an older one; the message set is identical
    /// across the published v1.x range, so only the declared string differs.
    #[serde(default = "default_x1_version")]
    pub version: String,
    /// Bind the `admfIdentifier` to the presented client certificate.
    ///
    /// When true (the default), a message whose `admfIdentifier` does not
    /// match the certificate's subject Common Name is refused with
    /// `AdmfIdentifierDoesNotMatchCertificateDetails` (1030). Turn it off only
    /// when the ADMF's certificate legitimately carries an unrelated CN.
    #[serde(default = "default_true")]
    pub bind_admf_identifier_to_certificate: bool,
    /// The network-element-to-ADMF direction. Absent means siphon serves X1
    /// but never initiates toward the ADMF.
    pub admf: Option<LiX1AdmfConfig>,
}

fn default_x1_path() -> String {
    "/X1/NE".to_string()
}

fn default_x1_version() -> String {
    crate::li::x1::types::DEFAULT_VERSION.to_string()
}

/// TLS for the X1 listener.
///
/// All three fields are mandatory. X1 carries warrant provisioning, and mutual
/// TLS is the only authentication the specification defines for it, so a
/// listener without a client CA would accept anyone. A missing field is a
/// startup error, not a silent downgrade — the same fail-closed rule the SIP
/// TLS listener applies to `verify_client` without `client_ca`.
#[derive(Debug, Deserialize, Clone)]
pub struct LiX1TlsConfig {
    /// PEM certificate chain this element presents.
    pub certificate: String,
    /// PEM private key for `certificate`.
    pub private_key: String,
    /// PEM CA bundle that ADMF client certificates must chain to.
    pub client_ca: String,
}

/// The network-element-to-ADMF direction (TS 103 221-1 clause 6.5).
///
/// Without this block siphon answers X1 but never speaks first: no issue
/// reports, no keepalives, and no reconciliation of provisioned state after a
/// restart.
#[derive(Debug, Deserialize, Clone)]
pub struct LiX1AdmfConfig {
    /// Absolute URL of the ADMF's X1 endpoint.
    pub endpoint: String,
    /// PEM client certificate this element presents to the ADMF.
    pub client_certificate: String,
    /// PEM private key for `client_certificate`.
    pub client_private_key: String,
    /// PEM CA bundle used to verify the ADMF's server certificate.
    ///
    /// Absent falls back to the platform/webpki roots, which is right for a
    /// publicly-issued certificate and wrong for the private CA most ADMF
    /// deployments use — set it.
    pub server_ca: Option<String>,
    /// Keepalive interval in seconds. Zero disables keepalives.
    #[serde(default = "default_x1_keepalive_secs")]
    pub keepalive_secs: u64,
    /// Per-request timeout in seconds.
    #[serde(default = "default_x1_request_timeout_secs")]
    pub request_timeout_secs: u64,
    /// Reconcile provisioned state with the ADMF at startup.
    ///
    /// Issues `GetAllDetails` outbound so the two sides agree after a restart.
    /// Without it, a bounce silently diverges the ADMF's view from the
    /// element's.
    #[serde(default = "default_true")]
    pub reconcile_on_start: bool,
}

fn default_x1_keepalive_secs() -> u64 {
    30
}

fn default_x1_request_timeout_secs() -> u64 {
    10
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

/// X3 content delivery.
///
/// Presence is the switch, and there is deliberately nothing else to set.
///
/// The TS 103 221-2 content framing lives in the media engine, because that is
/// where the RTP is, and the engine delivers straight to the destinations the
/// ADMF provisioned over X1. So this process has no collector address to dial,
/// no transport to choose and no encapsulation to pick — every one of those was
/// a setting for a path that no longer exists, and a setting that changes
/// nothing is worse than no setting at all.
#[derive(Debug, Deserialize, Clone)]
pub struct LiX3Config {
    /// Whether this node delivers content.
    ///
    /// Required, so that writing the block is a statement rather than an empty
    /// gesture. `true` requires `media.backend: siphon-rtp` and is refused at
    /// load on anything else; `false` is the same as omitting the block, and is
    /// there so content can be turned off without deleting configuration.
    pub enabled: bool,
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

fn default_li_x2_transport() -> String {
    "tcp".to_string()
}
fn default_li_reconnect_interval() -> u64 {
    5
}
fn default_li_channel_size() -> usize {
    10_000
}
fn default_siprec_session_copies() -> u32 {
    1
}
fn default_siprec_transport() -> String {
    "tcp".to_string()
}
fn default_siprec_src_profile() -> String {
    "siprec_src".to_string()
}

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

fn default_srs_recording_dir() -> String {
    "/var/lib/siphon/recordings".to_string()
}
fn default_srs_max_sessions() -> usize {
    1000
}
fn default_srs_backend() -> String {
    "file".to_string()
}
fn default_srs_rtpengine_profile() -> String {
    "srs_recording".to_string()
}

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct LogConfig {
    pub level: LogLevel,
    pub format: LogFormat,
    /// Optional path to a log file (e.g. `/var/log/siphon/siphon.log`).
    /// When set, logs are written to both stderr and the file. A missing
    /// parent directory is created; the packaged logrotate config rotates
    /// anything named `*.log` under `/var/log/siphon`.
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
        let path = path.as_ref();
        let content = std::fs::read_to_string(path)
            .map_err(|e| SiphonError::Config(format!("cannot read siphon.yaml: {e}")))?;
        let expanded = expand_env_vars(&content);
        let mut config = Self::from_str_raw(&expanded)?;
        config.anchor_script_paths(path);
        Ok(config)
    }

    /// Re-anchor a relative `script.path` / `script.include_paths` on the
    /// directory holding the config file.
    ///
    /// Both are resolved against the process working directory
    /// (`ScriptEngine::new` does `PathBuf::from(&config.path)`), which is fine
    /// when siphon is started from its config directory and wrong under any
    /// supervisor. systemd hands a unit `/` as its working directory, so the
    /// packaged `script.path: "scripts/proxy_default.py"` resolves to
    /// `/scripts/proxy_default.py`, the script load fails, and the service
    /// restart-loops — while the identical config starts by hand from
    /// `/etc/siphon`. Same trap for a container `WORKDIR` and for an embedding
    /// binary that chdirs.
    ///
    /// A relative entry therefore now prefers the config-relative location, the
    /// way nginx and Kamailio resolve a relative include. The rewrite only
    /// happens when the candidate actually exists, so a config that relies on
    /// the working directory keeps resolving exactly as before — this can make
    /// a previously-failing config start, never the reverse.
    ///
    /// Only applies to `from_file`: `from_str` has no file to anchor on.
    fn anchor_script_paths(&mut self, config_path: &Path) {
        let Some(config_dir) = config_path.parent() else {
            return;
        };
        // A bare `siphon.yaml` yields an empty parent, which would turn every
        // relative path into itself — nothing to anchor on.
        if config_dir.as_os_str().is_empty() {
            return;
        }

        let anchor = |value: &mut String| {
            if Path::new(&*value).is_absolute() {
                return;
            }
            let candidate = config_dir.join(&*value);
            if candidate.exists() {
                *value = candidate.to_string_lossy().into_owned();
            }
        };

        anchor(&mut self.script.path);
        for include_path in &mut self.script.include_paths {
            anchor(include_path);
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(yaml: &str) -> Result<Self> {
        let expanded = expand_env_vars(yaml);
        Self::from_str_raw(&expanded)
    }

    /// Parse YAML without env-var expansion (used after expansion is already done).
    fn from_str_raw(yaml: &str) -> Result<Self> {
        let config: Self = serde_yaml_ng::from_str(yaml)
            .map_err(|e| SiphonError::Config(format!("invalid siphon.yaml: {e}")))?;
        config.validate_media_profiles()?;
        config.validate_header_policies()?;
        config.validate_lawful_intercept()?;
        config.validate_max_message_bytes()?;
        Ok(config)
    }

    /// Reject a message-size ceiling too small to carry a SIP message.
    ///
    /// The ceiling bounds what one stream connection can make siphon buffer,
    /// so it is load-bearing for availability. A value below
    /// [`MIN_MAX_MESSAGE_BYTES`] would refuse ordinary INVITEs — an operator
    /// typo that turns into a total outage — so it is refused at load rather
    /// than answering 513 to every call.
    fn validate_max_message_bytes(&self) -> Result<()> {
        let Some(limit) = self.security.as_ref().and_then(|sec| sec.max_message_bytes) else {
            return Ok(());
        };
        if limit < MIN_MAX_MESSAGE_BYTES {
            return Err(SiphonError::Config(format!(
                "security.max_message_bytes is {limit}, below the {MIN_MAX_MESSAGE_BYTES} byte \
                 floor — a SIP INVITE with authentication and SDP does not fit, so every call \
                 would be answered 513 Message Too Large. Raise it or remove the field to take \
                 the default."
            )));
        }
        Ok(())
    }

    /// Reject an X3 content-delivery configuration the media backend cannot honour.
    ///
    /// X1 and X2 are backend-independent — provisioning is HTTPS and IRI is
    /// SIP signalling, so both behave identically on `rtpengine`, `rtpproxy`
    /// and `siphon-rtp`. X3 carries the content of communication, and the
    /// TS 103 221-2 framing lives in the media engine, so only the native
    /// `siphon-rtp` backend can emit it.
    ///
    /// | `deliveryType` | rtpengine | rtpproxy | siphon-rtp |
    /// |---|---|---|---|
    /// | `X2Only`  | yes | yes | yes |
    /// | `X3Only`  | no  | no  | yes |
    /// | `X2andX3` | no  | no  | yes |
    ///
    /// Refused at load rather than at the first warrant, following
    /// [`Self::validate_media_profiles`]: name the offending field, the
    /// backend that cannot honour it, and the remedy. The same rule is applied
    /// again at `ActivateTask`, because a task can be provisioned long after
    /// boot.
    fn validate_lawful_intercept(&self) -> Result<()> {
        let Some(lawful_intercept) = &self.lawful_intercept else {
            return Ok(());
        };
        if !lawful_intercept.enabled {
            return Ok(());
        }
        // `enabled: false` is the same as no block at all, so a node that has
        // turned content off is not held to the backend requirement.
        if !lawful_intercept.x3.as_ref().is_some_and(|x3| x3.enabled) {
            return Ok(());
        }

        let backend = self
            .media
            .as_ref()
            .map(|media| media.backend)
            .unwrap_or_default();
        if backend == MediaBackendKind::SiphonRtp {
            return Ok(());
        }

        Err(SiphonError::Config(format!(
            "lawful_intercept.x3 is configured, but media.backend is {:?}, which cannot \
             deliver X3 content of communication — ETSI TS 103 221-2 content framing is \
             implemented in the siphon-rtp media engine only. Set media.backend to \
             \"siphon-rtp\", or remove lawful_intercept.x3 and provision X2Only warrants \
             (X1 provisioning and X2 IRI delivery work on every backend).",
            backend.as_str(),
        )))
    }

    /// Reject a media profile asking for something `media.backend` cannot do.
    ///
    /// Runs on every load path (`from_file` and `from_str` both route through
    /// `from_str_raw`), so a misconfigured box fails to start instead of coming
    /// up healthy and answering calls into a media path that was never wired.
    ///
    /// Only covers operator-declared `media.profiles` — a built-in profile is
    /// registered regardless of backend, so a script naming one the backend
    /// cannot honour is caught at the call instead (see the `rtpengine` script
    /// API's profile resolution).
    fn validate_media_profiles(&self) -> Result<()> {
        let Some(media) = &self.media else {
            return Ok(());
        };

        // Sorted so the error text is deterministic across runs (HashMap order).
        let mut names: Vec<&String> = media.profiles.keys().collect();
        names.sort_unstable();

        for name in names {
            let Some(profile) = media.profiles.get(name) else {
                continue;
            };
            for (direction, flags) in [("offer", &profile.offer), ("answer", &profile.answer)] {
                let unsupported = media.backend.unsupported_profile_fields(flags);
                if !unsupported.is_empty() {
                    return Err(SiphonError::Config(format!(
                        "media profile {name:?} sets {} on its {direction} flags, which the \
                         {} backend cannot honour — remove {} or set media.backend to a \
                         backend that supports {}",
                        unsupported.join(", "),
                        media.backend.as_str(),
                        if unsupported.len() == 1 {
                            "the field"
                        } else {
                            "those fields"
                        },
                        if unsupported.len() == 1 { "it" } else { "them" },
                    )));
                }
            }
        }

        Ok(())
    }

    /// Reject a `header_policies:` entry that cannot compile, and a
    /// `b2bua.default_header_policy` that names no known policy.
    ///
    /// Runs on every load path, so a policy with a typo in an op token, a rule
    /// aimed at a framework-managed header, or a name nothing defines stops the
    /// node at boot. The default in particular used to warn and silently fall
    /// back to `transparent-b2bua@2026` — which is the *most* permissive
    /// posture, so a typo in the name of a trust-boundary control opened the
    /// boundary instead of closing it, on a node that came up reporting healthy.
    fn validate_header_policies(&self) -> Result<()> {
        let registry = crate::b2bua::header_policy::build_registry(&self.header_policies)
            .map_err(|error| SiphonError::Config(error.to_string()))?;

        let name = self.b2bua.resolved_default_header_policy();
        if !registry.contains_key(name) {
            let mut known: Vec<&str> = registry.keys().map(String::as_str).collect();
            known.sort_unstable();
            return Err(SiphonError::Config(format!(
                "b2bua.default_header_policy {name:?} names no known header policy — define it \
                 under header_policies:, or pick one of: {}",
                known.join(", ")
            )));
        }

        Ok(())
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
        self.extensions.as_ref()?.get(name)?.as_str().map(Path::new)
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
// Least-Cost Routing (LCR)
// ---------------------------------------------------------------------------

/// Top-level `lcr:` configuration — the external Least-Cost-Routing API.
///
/// ```yaml
/// lcr:
///   api_url: "${LCR_API_URL:-https://lcr.internal/route}"
///   timeout_ms: 2000
///   cache: "lcr"                     # optional: a name from the cache: list
///   cache_ttl_secs: 300              # default TTL when the API omits one
///   auth_header: "Bearer ${LCR_TOKEN}"
///   fallback_gateway_group: "emergency-pstn"   # used when the API is down
/// ```
#[derive(Debug, Deserialize, Clone)]
pub struct LcrConfig {
    /// URL siphon `POST`s each LCR query to (JSON contract v1). Required.
    pub api_url: String,
    /// Per-query timeout in milliseconds.
    #[serde(default = "default_lcr_timeout_ms")]
    pub timeout_ms: u64,
    /// Name of a `cache:` entry to cache decisions in (L1 LRU + optional Redis
    /// so a decision cached on one node is reused fleet-wide). When unset,
    /// decisions are not cached.
    pub cache: Option<String>,
    /// Default cache TTL (seconds) used only when a decision omits
    /// `cache_ttl_secs`. A decision's own `cache_ttl_secs` always wins;
    /// `0` disables caching for that decision.
    #[serde(default = "default_lcr_cache_ttl_secs")]
    pub cache_ttl_secs: u64,
    /// Full `Authorization` header value sent with each query (e.g.
    /// `"Bearer …"`). Supports `${VAR}` expansion.
    pub auth_header: Option<String>,
    /// Configured `gateway:` group to fall back to when the API is unreachable
    /// or times out — degrades routing instead of failing the call. When unset,
    /// an API failure surfaces to the script as "unavailable" (no decision).
    pub fallback_gateway_group: Option<String>,
    /// SIP response codes that trigger failover to the next carrier (the generic
    /// level). When unset, the built-in default `[408, 500, 502, 503, 504]` is
    /// used. A per-gateway `reroute_causes` or a per-route one (from the API)
    /// overrides this for that carrier.
    pub reroute_causes: Option<Vec<u16>>,
}

fn default_lcr_timeout_ms() -> u64 {
    2000
}

fn default_lcr_cache_ttl_secs() -> u64 {
    300
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Codec manipulation is an rtpengine NG capability. The native engine's
    /// `ProfileFlags` has no codec fields and rtpproxy is a plain relay, so a
    /// profile asking for it there is refused at load rather than reading as
    /// "restricted to PCMA/PCMU" while every offered codec crosses untouched.
    #[test]
    fn codec_flags_are_rtpengine_only() {
        let flags = NgFlagsConfig {
            codec: CodecFlagsConfig {
                offer: vec!["PCMA".to_string(), "PCMU".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };

        assert!(
            MediaBackendKind::Rtpengine
                .unsupported_profile_fields(&flags)
                .is_empty(),
            "rtpengine speaks the codec dict"
        );
        // The native engine implements the same codec model, reading it off the
        // flag list — so an `offer` list is honoured there, not refused.
        assert!(
            MediaBackendKind::SiphonRtp
                .unsupported_profile_fields(&flags)
                .is_empty(),
            "siphon-rtp implements codec manipulation and must accept it"
        );
        // rtpproxy is a plain relay: no transcoder, no codec control.
        assert!(
            MediaBackendKind::Rtpproxy
                .unsupported_profile_fields(&flags)
                .contains(&"codec"),
            "rtpproxy cannot express codec manipulation and must refuse it"
        );

        // The two ops with no native equivalent ARE refused on siphon-rtp,
        // rather than silently dropped when the block is flattened to flags.
        let unmappable = NgFlagsConfig {
            codec: CodecFlagsConfig {
                ignore: vec!["G729".to_string()],
                set: vec!["opus/48000/2".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let native = MediaBackendKind::SiphonRtp.unsupported_profile_fields(&unmappable);
        assert!(native.contains(&"codec.ignore"), "got {native:?}");
        assert!(native.contains(&"codec.set"), "got {native:?}");
        assert!(
            MediaBackendKind::Rtpengine
                .unsupported_profile_fields(&unmappable)
                .is_empty(),
            "rtpengine takes every op"
        );

        // An unset codec block is inert on every backend.
        let bare = NgFlagsConfig::default();
        for backend in [
            MediaBackendKind::Rtpengine,
            MediaBackendKind::SiphonRtp,
            MediaBackendKind::Rtpproxy,
        ] {
            assert!(!backend.unsupported_profile_fields(&bare).contains(&"codec"));
        }
    }

    /// The codec block is a DICT of named lists. The shape that shipped in the
    /// Teams example (`codec: ["offer", "PCMA,PCMU"]`) is not it, and now fails
    /// the config load instead of being silently dropped — which is how it went
    /// unnoticed while implying siphon was restricting codecs.
    #[test]
    fn codec_block_parses_as_a_dict_and_rejects_the_old_list_form() {
        let good: NgFlagsConfig = serde_yaml_ng::from_str(
            r#"
transport_protocol: "RTP/AVP"
codec:
  strip: ["SILK", "G722"]
  offer: ["PCMA", "PCMU", "telephone-event"]
"#,
        )
        .expect("the dict form must parse");
        assert_eq!(good.codec.strip, vec!["SILK", "G722"]);
        assert_eq!(good.codec.offer, vec!["PCMA", "PCMU", "telephone-event"]);
        assert!(good.codec.transcode.is_empty());

        assert!(
            serde_yaml_ng::from_str::<NgFlagsConfig>("codec: [\"offer\", \"PCMA,PCMU\"]").is_err(),
            "the old list form must be rejected, not ignored"
        );
        assert!(
            serde_yaml_ng::from_str::<NgFlagsConfig>("codec:\n  bogus: [\"PCMA\"]").is_err(),
            "an unknown codec key must be rejected, not ignored"
        );
    }

    /// The `Replaces` takeover is a capability, not a default: an upgrade must
    /// never hand every party that can reach this node the ability to
    /// disconnect someone from a live call and take their place (RFC 3891 §5).
    #[test]
    fn replaces_takeover_is_off_unless_enabled() {
        assert!(
            !B2buaConfig::default().replaces_takeover_enabled(),
            "an operator opts into call takeover; it is never inherited"
        );
        assert!(!B2buaConfig {
            accept_replaces: Some(false),
            ..Default::default()
        }
        .replaces_takeover_enabled());
        assert!(B2buaConfig {
            accept_replaces: Some(true),
            ..Default::default()
        }
        .replaces_takeover_enabled());
    }

    #[test]
    fn replaces_takeover_parses_from_yaml() {
        let config: B2buaConfig =
            serde_yaml_ng::from_str("accept_replaces: true").expect("b2bua block must parse");
        assert!(config.replaces_takeover_enabled());
        // An omitted key leaves the capability off.
        let empty: B2buaConfig =
            serde_yaml_ng::from_str("default_refer_mode: terminate").expect("must parse");
        assert!(!empty.replaces_takeover_enabled());
    }

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
    fn parses_sni_certificates() {
        let yaml = format!(
            "{}{}",
            minimal_yaml(),
            r#"
tls:
  certificate: "/etc/siphon/tls/default.crt"
  private_key: "/etc/siphon/tls/default.key"
  certificates:
    - server_names: ["sip.tenant-a.example", "sip.tenant-a.net"]
      certificate: "/etc/siphon/tls/tenant-a.crt"
      private_key: "/etc/siphon/tls/tenant-a.key"
    - server_names: ["*.tenant-b.example"]
      certificate: "/etc/siphon/tls/tenant-b.crt"
      private_key: "/etc/siphon/tls/tenant-b.key"
"#
        );
        let config = Config::from_str(&yaml).unwrap();
        let tls = config.tls.expect("tls block");
        assert_eq!(tls.certificate, "/etc/siphon/tls/default.crt");
        assert_eq!(tls.certificates.len(), 2);
        assert_eq!(
            tls.certificates[0].server_names,
            vec!["sip.tenant-a.example", "sip.tenant-a.net"]
        );
        assert_eq!(
            tls.certificates[0].certificate,
            "/etc/siphon/tls/tenant-a.crt"
        );
        assert_eq!(tls.certificates[1].server_names, vec!["*.tenant-b.example"]);
    }

    #[test]
    fn tls_certificates_defaults_to_empty() {
        // A pre-SNI config must keep parsing, with the single-cert behaviour.
        let yaml = format!(
            "{}{}",
            minimal_yaml(),
            r#"
tls:
  certificate: "/etc/siphon/tls/default.crt"
  private_key: "/etc/siphon/tls/default.key"
"#
        );
        let config = Config::from_str(&yaml).unwrap();
        assert!(config.tls.expect("tls block").certificates.is_empty());
    }

    #[test]
    fn parses_minimal_config() {
        let config = Config::from_str(minimal_yaml()).unwrap();
        assert_eq!(config.listen.udp[0].address(), "0.0.0.0:5060");
        assert!(config.listen.tcp.is_empty());
        assert_eq!(config.domain.local, vec!["example.com"]);
        assert_eq!(config.script.path, "scripts/proxy_default.py");
        assert_eq!(config.script.reload, ReloadMode::Auto);
        assert!(config.script.include_paths.is_empty());
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

    // --- script path anchoring (Config::from_file) ---

    /// Build a config dir holding `siphon.yaml` plus a `scripts/main.py`, and
    /// return `(tempdir, config_path)`.
    fn config_dir_with_script(script_body: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("scripts")).unwrap();
        std::fs::write(dir.path().join("scripts/main.py"), script_body).unwrap();
        let config_path = dir.path().join("siphon.yaml");
        std::fs::write(
            &config_path,
            r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/main.py"
  include_paths:
    - "lib"
    - "/etc/siphon/shared"
auth:
  realm: "example.com"
"#,
        )
        .unwrap();
        (dir, config_path)
    }

    /// The systemd case: the working directory is not the config directory, so
    /// a relative `script.path` must still resolve.
    #[test]
    fn relative_script_path_anchors_on_config_dir() {
        let (dir, config_path) = config_dir_with_script("# script\n");

        let config = Config::from_file(&config_path).unwrap();

        assert_eq!(
            config.script.path,
            dir.path().join("scripts/main.py").to_string_lossy()
        );
        assert!(std::path::Path::new(&config.script.path).exists());
    }

    #[test]
    fn relative_include_paths_anchor_on_config_dir() {
        let (dir, config_path) = config_dir_with_script("# script\n");
        std::fs::create_dir(dir.path().join("lib")).unwrap();

        let config = Config::from_file(&config_path).unwrap();

        assert_eq!(
            config.script.include_paths,
            vec![
                dir.path().join("lib").to_string_lossy().into_owned(),
                // Absolute entries are never touched.
                "/etc/siphon/shared".to_string(),
            ]
        );
    }

    /// Anchoring must not change a config that already worked: when there is no
    /// config-relative candidate, the value is left alone so the process
    /// working directory still resolves it (and the same "script not found"
    /// error still names what the operator wrote).
    #[test]
    fn missing_config_relative_candidate_leaves_path_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("siphon.yaml");
        std::fs::write(
            &config_path,
            r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/absent.py"
  include_paths:
    - "absent-lib"
auth:
  realm: "example.com"
"#,
        )
        .unwrap();

        let config = Config::from_file(&config_path).unwrap();

        assert_eq!(config.script.path, "scripts/absent.py");
        assert_eq!(config.script.include_paths, vec!["absent-lib".to_string()]);
    }

    /// An absolute `script.path` is never rewritten, even when a same-named
    /// file sits beside the config.
    #[test]
    fn absolute_script_path_is_not_anchored() {
        let dir = tempfile::tempdir().unwrap();
        let elsewhere = dir.path().join("elsewhere.py");
        std::fs::write(&elsewhere, "# script\n").unwrap();
        let config_path = dir.path().join("siphon.yaml");
        std::fs::write(
            &config_path,
            format!(
                r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "{}"
auth:
  realm: "example.com"
"#,
                elsewhere.display()
            ),
        )
        .unwrap();

        let config = Config::from_file(&config_path).unwrap();

        assert_eq!(config.script.path, elsewhere.to_string_lossy());
    }

    /// `from_str` has no file to anchor on and must stay byte-for-byte what the
    /// caller wrote (embedding / `--config-string` path).
    #[test]
    fn from_str_does_not_anchor_script_path() {
        let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/main.py"
auth:
  realm: "example.com"
"#;
        let config = Config::from_str(yaml).unwrap();
        assert_eq!(config.script.path, "scripts/main.py");
    }

    /// A bare filename config (`siphon --config siphon.yaml`) has an empty
    /// parent — anchoring is a no-op rather than a self-join.
    #[test]
    fn bare_config_filename_anchors_nothing() {
        let mut config = Config::from_str(minimal_yaml()).unwrap();
        config.script.path = "scripts/main.py".to_string();

        config.anchor_script_paths(std::path::Path::new("siphon.yaml"));

        assert_eq!(config.script.path, "scripts/main.py");
    }

    #[test]
    fn parses_script_include_paths() {
        let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/main.py"
  include_paths:
    - "/etc/siphon/lib"
    - "shared"
auth:
  realm: "example.com"
"#;
        let config = Config::from_str(yaml).unwrap();
        assert_eq!(
            config.script.include_paths,
            vec!["/etc/siphon/lib".to_string(), "shared".to_string()]
        );
    }

    #[test]
    fn parses_metrics_and_admin_cors() {
        let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/main.py"
auth:
  realm: "example.com"
metrics:
  prometheus:
    listen: "0.0.0.0:8888"
    cors:
      allowed_origins:
        - "http://localhost:5173"
        - "https://dash.example.com"
admin:
  listen: "0.0.0.0:9091"
  cors:
    allowed_origins:
      - "*"
"#;
        let config = Config::from_str(yaml).unwrap();

        let prom_cors = config
            .metrics
            .as_ref()
            .and_then(|metrics| metrics.prometheus.as_ref())
            .and_then(|prom| prom.cors.as_ref())
            .expect("metrics.prometheus.cors must parse");
        assert_eq!(
            prom_cors.allowed_origins,
            vec![
                "http://localhost:5173".to_string(),
                "https://dash.example.com".to_string()
            ]
        );

        let admin_cors = config
            .admin
            .as_ref()
            .and_then(|admin| admin.cors.as_ref())
            .expect("admin.cors must parse");
        assert_eq!(admin_cors.allowed_origins, vec!["*".to_string()]);
    }

    #[test]
    fn metrics_without_cors_leaves_it_none() {
        let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/main.py"
auth:
  realm: "example.com"
metrics:
  prometheus:
    listen: "0.0.0.0:8888"
admin:
  listen: "0.0.0.0:9091"
"#;
        let config = Config::from_str(yaml).unwrap();
        assert!(config
            .metrics
            .as_ref()
            .and_then(|metrics| metrics.prometheus.as_ref())
            .and_then(|prom| prom.cors.as_ref())
            .is_none());
        assert!(config
            .admin
            .as_ref()
            .and_then(|admin| admin.cors.as_ref())
            .is_none());
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
        assert_eq!(
            config.registrar.redis.as_ref().unwrap().url,
            "redis://127.0.0.1:6379"
        );
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

    /// The shipped WhatsApp Business Calling gateway example must parse, and its
    /// WhatsApp-specific invariants must hold: no mutual-TLS client cert (Meta is
    /// server-auth only), no session timer (a re-INVITE would fail the WhatsApp
    /// leg), the whatsapp + internal gateway groups (WhatsApp probe disabled —
    /// Meta does not answer OPTIONS), and the DTLS-SRTP media profiles. Guards
    /// against the example silently rotting.
    #[test]
    fn example_whatsapp_calling_yaml_parses() {
        let yaml = include_str!("../examples/whatsapp_calling.yaml");
        let config = Config::from_str(yaml).expect("example yaml must parse");

        // Server-auth TLS only — no outbound client certificate toward Meta.
        let tls = config.tls.expect("tls block");
        assert!(tls.client_certificate.is_none());
        assert!(tls.client_private_key.is_none());

        // SIPhon must never originate a re-INVITE toward the WhatsApp leg.
        assert!(config.session_timer.is_none());

        let gateway = config.gateway.expect("gateway block");
        let whatsapp = gateway
            .groups
            .iter()
            .find(|g| g.name == "whatsapp")
            .expect("whatsapp gateway group");
        assert!(!whatsapp.probe.enabled);
        // Meta's source ranges drive call.from_gateway("whatsapp") direction
        // detection — the group must carry source_networks.
        assert!(!whatsapp.source_networks.is_empty());
        assert!(gateway.groups.iter().any(|g| g.name == "internal"));

        // DTLS-SRTP profiles for the Meta leg (the SDES default reuses built-ins).
        let media = config.media.expect("media block");
        let dtls_in = media
            .profiles
            .get("whatsapp_dtls_in")
            .expect("whatsapp_dtls_in profile");
        assert_eq!(
            dtls_in.answer.transport_protocol.as_deref(),
            Some("RTP/SAVPF")
        );
        assert_eq!(dtls_in.answer.dtls.as_deref(), Some("passive"));
        let dtls_out = media
            .profiles
            .get("whatsapp_dtls_out")
            .expect("whatsapp_dtls_out profile");
        assert_eq!(dtls_out.offer.dtls.as_deref(), Some("passive"));
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
    url: "redis://192.0.2.131:6379"
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
        assert_eq!(tls.method, TlsMethod::Tls13);
        assert!(!tls.verify_client);
        // Outbound client-certificate (mutual TLS) fields default to None.
        assert!(tls.client_certificate.is_none());
        assert!(tls.client_private_key.is_none());
    }

    #[test]
    fn tls_method_defaults_to_tls12_floor() {
        // Unset `method` must keep serving what siphon has always served
        // (TLS 1.2 + 1.3). A 1.3 default here would silently drop every TLS 1.2
        // peer on upgrade.
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
"#;
        let config = Config::from_str(yaml).unwrap();
        let tls = config.tls.unwrap();
        assert_eq!(tls.method, TlsMethod::Tls12);
    }

    #[test]
    fn tls_method_accepts_openssl_and_kamailio_spellings() {
        for spelling in [
            "TLSv1_2",
            "TLSv1.2",
            "tlsv1_2",
            " TLSv1_2 ",
            "TLSv1.2+",
            "1.2",
        ] {
            assert_eq!(
                spelling.parse::<TlsMethod>(),
                Ok(TlsMethod::Tls12),
                "{spelling} should parse as the TLS 1.2 floor"
            );
        }
        for spelling in ["TLSv1_3", "TLSv1.3", "tlsv1_3", "TLSv1.3+", "1.3"] {
            assert_eq!(
                spelling.parse::<TlsMethod>(),
                Ok(TlsMethod::Tls13),
                "{spelling} should parse as the TLS 1.3 floor"
            );
        }
    }

    #[test]
    fn tls_method_rejects_deprecated_versions() {
        for spelling in ["TLSv1", "TLSv1_0", "TLSv1_1", "SSLv3", "SSLv23"] {
            let error = spelling
                .parse::<TlsMethod>()
                .expect_err("deprecated TLS/SSL versions must be rejected");
            assert!(
                error.contains("RFC 8996"),
                "error should name the deprecation: {error}"
            );
        }
    }

    #[test]
    fn tls_method_rejects_unknown_value_at_config_load() {
        // Fail closed and loud: an unrecognised value used to be accepted and
        // ignored, so a typo read as a hardened config while nothing enforced it.
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
  method: "TLSv1_4"
"#;
        let error = Config::from_str(yaml).expect_err("unknown tls.method must fail config load");
        let error = error.to_string();
        assert!(
            error.contains("TLSv1_2") && error.contains("TLSv1_3"),
            "error should list the accepted values: {error}"
        );
    }

    #[test]
    fn tls_method_display_round_trips() {
        for method in [TlsMethod::Tls12, TlsMethod::Tls13] {
            assert_eq!(method.to_string().parse::<TlsMethod>(), Ok(method));
        }
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
        let rtpengine = media.rtpengine.expect("rtpengine block configured");
        let instances = rtpengine.instances();
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
        let rtpengine = media.rtpengine.expect("rtpengine block configured");
        let instances = rtpengine.instances();
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
        let rtpengine = media.rtpengine.expect("rtpengine block configured");
        let instances = rtpengine.instances();
        assert_eq!(instances[0].timeout_ms, 1000); // default
        assert_eq!(instances[0].weight, 1); // default
    }

    #[test]
    fn media_backend_defaults_to_rtpengine() {
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
        assert_eq!(media.backend, MediaBackendKind::Rtpengine);
        assert!(media.rtpengine.is_some());
        assert!(media.siphon_rtp.is_none());
    }

    #[test]
    fn parses_media_backend_siphon_rtp() {
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
  backend: siphon-rtp
  siphon_rtp:
    address: "127.0.0.1:8080"
    control_secret: "s3cret"
"#;
        let config = Config::from_str(yaml).unwrap();
        let media = config.media.unwrap();
        assert_eq!(media.backend, MediaBackendKind::SiphonRtp);
        assert!(media.rtpengine.is_none());
        let siphon_rtp = media.siphon_rtp.expect("siphon_rtp block configured");
        assert_eq!(siphon_rtp.address.as_deref(), Some("127.0.0.1:8080"));
        assert_eq!(siphon_rtp.control_secret.as_deref(), Some("s3cret"));
        assert_eq!(siphon_rtp.timeout_ms, 2000); // default
                                                 // Single `address` normalizes to one (address, timeout, weight) tuple.
        let instances = siphon_rtp.instances();
        assert_eq!(instances.len(), 1);
        assert_eq!(instances[0], ("127.0.0.1:8080".to_string(), 2000, 1));
    }

    #[test]
    fn parses_media_siphon_rtp_multiple_instances() {
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
  backend: siphon-rtp
  siphon_rtp:
    control_secret: "shared"
    timeout_ms: 1500
    instances:
      - address: "10.0.0.1:8080"
        weight: 2
      - address: "10.0.0.2:8080"
        weight: 1
        timeout_ms: 3000
"#;
        let config = Config::from_str(yaml).unwrap();
        let media = config.media.unwrap();
        assert_eq!(media.backend, MediaBackendKind::SiphonRtp);
        let siphon_rtp = media.siphon_rtp.expect("siphon_rtp block configured");
        assert_eq!(siphon_rtp.control_secret.as_deref(), Some("shared"));
        let instances = siphon_rtp.instances();
        assert_eq!(instances.len(), 2);
        // First inherits the parent timeout; second overrides it.
        assert_eq!(instances[0], ("10.0.0.1:8080".to_string(), 1500, 2));
        assert_eq!(instances[1], ("10.0.0.2:8080".to_string(), 3000, 1));
    }

    #[test]
    fn parses_media_backend_rtpproxy() {
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
  backend: rtpproxy
  rtpproxy:
    address: "127.0.0.1:22222"
"#;
        let config = Config::from_str(yaml).unwrap();
        let media = config.media.unwrap();
        assert_eq!(media.backend, MediaBackendKind::Rtpproxy);
        assert!(media.rtpengine.is_none());
        assert!(media.siphon_rtp.is_none());
        let rtpproxy = media.rtpproxy.expect("rtpproxy block configured");
        assert_eq!(rtpproxy.address.as_deref(), Some("127.0.0.1:22222"));
        assert_eq!(rtpproxy.timeout_ms, 1000); // default
        assert_eq!(rtpproxy.retries, 2); // default
        let instances = rtpproxy.instances();
        assert_eq!(instances.len(), 1);
        assert_eq!(instances[0], ("127.0.0.1:22222".to_string(), 1000, 1));
    }

    #[test]
    fn parses_media_rtpproxy_multiple_instances() {
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
  backend: rtpproxy
  rtpproxy:
    timeout_ms: 1500
    retries: 3
    instances:
      - address: "10.0.0.1:22222"
        weight: 2
      - address: "10.0.0.2:22222"
        weight: 1
        timeout_ms: 3000
"#;
        let config = Config::from_str(yaml).unwrap();
        let media = config.media.unwrap();
        assert_eq!(media.backend, MediaBackendKind::Rtpproxy);
        let rtpproxy = media.rtpproxy.expect("rtpproxy block configured");
        assert_eq!(rtpproxy.retries, 3);
        let instances = rtpproxy.instances();
        assert_eq!(instances.len(), 2);
        // First inherits the parent timeout; second overrides it.
        assert_eq!(instances[0], ("10.0.0.1:22222".to_string(), 1500, 2));
        assert_eq!(instances[1], ("10.0.0.2:22222".to_string(), 3000, 1));
    }

    /// Minimum config the loader accepts, plus whatever the test is about.
    fn config_with(extra: &str) -> Result<Config> {
        Config::from_str(&format!(
            concat!(
                "listen:\n",
                "  udp:\n",
                "    - \"0.0.0.0:5060\"\n",
                "domain:\n",
                "  local:\n",
                "    - \"example.com\"\n",
                "script:\n",
                "  path: \"scripts/proxy_default.py\"\n",
                "{}"
            ),
            extra
        ))
    }

    #[test]
    fn parses_header_policies_in_both_forms() {
        let config = config_with(concat!(
            "header_policies:\n",
            "  \"trunk-edge-plus@1\":\n",
            "    extends: \"sip-trunk-edge@2026\"\n",
            "    request:\n",
            "      copy: [\"X-Account-Ref\"]\n",
            "      strip: [\"Alert-Info\"]\n",
            "      translate:\n",
            "        Diversion: diversion-to-history-info\n",
            "      rewrite:\n",
            "        P-Asserted-Identity: host-to-advertised\n",
            "    response:\n",
            "      strip: [\"Server\"]\n",
            "  \"locked-down@1\":\n",
            "    request:\n",
            "      default: strip\n",
            "      copy: [\"Allow\", \"Supported\"]\n",
            "    response:\n",
            "      default: copy\n",
            "      strip: [\"P-*\"]\n",
            "b2bua:\n",
            "  default_header_policy: \"trunk-edge-plus@1\"\n",
        ))
        .expect("both policy forms should load");

        assert_eq!(config.header_policies.len(), 2);
        let extended = config
            .header_policies
            .get("trunk-edge-plus@1")
            .expect("policy present");
        assert_eq!(extended.extends.as_deref(), Some("sip-trunk-edge@2026"));
        let request = extended.request.as_ref().expect("request block present");
        assert_eq!(request.copy, vec!["X-Account-Ref".to_string()]);
        assert_eq!(
            request
                .rewrite
                .get("P-Asserted-Identity")
                .map(String::as_str),
            Some("host-to-advertised")
        );

        let standalone = config
            .header_policies
            .get("locked-down@1")
            .expect("policy present");
        assert!(standalone.extends.is_none());
        assert_eq!(
            standalone
                .request
                .as_ref()
                .and_then(|direction| direction.default),
            Some(crate::b2bua::header_policy::DefaultVerb::Strip)
        );

        assert_eq!(
            config.b2bua.resolved_default_header_policy(),
            "trunk-edge-plus@1"
        );
    }

    #[test]
    fn header_policies_default_to_empty() {
        let config = config_with("").expect("config without header_policies should load");
        assert!(config.header_policies.is_empty());
        assert_eq!(
            config.b2bua.resolved_default_header_policy(),
            crate::b2bua::header_policy::DEFAULT_PRESET_NAME
        );
    }

    #[test]
    fn rejects_a_header_policy_that_cannot_compile() {
        // The load-time gate: an op token nobody implements would otherwise
        // surface as a header silently not being rewritten, mid-call.
        let error = config_with(concat!(
            "header_policies:\n",
            "  \"broken@1\":\n",
            "    extends: \"transparent-b2bua@2026\"\n",
            "    request:\n",
            "      rewrite:\n",
            "        P-Asserted-Identity: make-it-nice\n",
        ))
        .expect_err("an unknown rewrite op must refuse to load");
        let message = error.to_string();
        assert!(message.contains("broken@1"), "{message}");
        assert!(message.contains("make-it-nice"), "{message}");
    }

    #[test]
    fn rejects_an_undefined_default_header_policy() {
        // Used to warn and fall back to transparent-b2bua@2026 — the most
        // permissive posture — so a typo opened the boundary it was meant to
        // close, on a node that came up healthy.
        let error = config_with(concat!(
            "b2bua:\n",
            "  default_header_policy: \"trunk-edge-pluss@1\"\n",
        ))
        .expect_err("an undefined default must refuse to load");
        let message = error.to_string();
        assert!(message.contains("trunk-edge-pluss@1"), "{message}");
        assert!(
            message.contains("sip-trunk-edge@2026"),
            "the error should list what is available: {message}"
        );
    }

    #[test]
    fn accepts_a_default_naming_an_operator_defined_policy() {
        let config = config_with(concat!(
            "header_policies:\n",
            "  \"our-trunk@1\":\n",
            "    extends: \"sip-trunk-edge@2026\"\n",
            "b2bua:\n",
            "  default_header_policy: \"our-trunk@1\"\n",
        ))
        .expect("a default naming a custom policy should load");
        assert_eq!(config.b2bua.resolved_default_header_policy(), "our-trunk@1");
    }

    #[test]
    fn accepts_a_default_naming_a_builtin_preset() {
        let config = config_with(concat!(
            "b2bua:\n",
            "  default_header_policy: \"ims-trust-domain-boundary@2026\"\n",
        ))
        .expect("a built-in name should still load");
        assert_eq!(
            config.b2bua.resolved_default_header_policy(),
            "ims-trust-domain-boundary@2026"
        );
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
        assert_eq!(
            profile.offer.transport_protocol.as_deref(),
            Some("RTP/SAVP")
        );
        assert_eq!(profile.offer.ice.as_deref(), Some("remove"));
        assert!(profile.offer.dtls.is_none());
        assert_eq!(profile.offer.direction, vec!["external", "internal"]);
        assert_eq!(profile.answer.direction, vec!["internal", "external"]);
        // Unset unless the profile asks for a family.
        assert!(profile.offer.address_family.is_none());
        assert!(profile.answer.address_family.is_none());
    }

    /// A v6 VoLTE access side bridged to a v4 core: the profile used toward the
    /// core pins `IP4`.  Accepted case-insensitively with `ipv4`/`ipv6` aliases,
    /// always canonicalised to the SDP `addrtype` spelling the engines want.
    #[test]
    fn parses_media_profile_address_family() {
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
    v6_access_to_v4_core:
      offer:
        replace: ["origin"]
        address_family: "IP4"
      answer:
        replace: ["origin"]
        address_family: "ipv6"
"#;
        let config = Config::from_str(yaml).unwrap();
        let media = config.media.unwrap();
        let profile = media.profiles.get("v6_access_to_v4_core").unwrap();
        assert_eq!(profile.offer.address_family.as_deref(), Some("IP4"));
        assert_eq!(profile.answer.address_family.as_deref(), Some("IP6"));
    }

    /// The engines drop an unknown family silently, so a typo has to fail the
    /// config load — otherwise it lands as a relay in the wrong family.
    #[test]
    fn rejects_media_profile_bad_address_family() {
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
    broken:
      offer:
        address_family: "IP5"
      answer: {}
"#;
        let error = Config::from_str(yaml).expect_err("IP5 must be rejected");
        let message = error.to_string();
        assert!(
            message.contains("address_family"),
            "error should name the field: {message}"
        );
    }

    // -----------------------------------------------------------------------
    // Media profiles: WebSocket bridge / DSP / received_from / rtcp_mux
    // -----------------------------------------------------------------------

    /// Base config for the WS-profile cases, parameterised on backend + profile
    /// body so each test states only what it is about.
    fn ws_profile_yaml(backend_block: &str, profile_body: &str) -> String {
        format!(
            "listen:\n  udp:\n    - \"0.0.0.0:5060\"\ndomain:\n  local:\n    \
             - \"example.com\"\nscript:\n  path: \"scripts/proxy_default.py\"\n\
             media:\n{backend_block}  profiles:\n    voice_ai_custom:\n{profile_body}"
        )
    }

    const SIPHON_RTP_BACKEND: &str =
        "  backend: siphon-rtp\n  siphon_rtp:\n    address: \"127.0.0.1:9000\"\n";
    const RTPENGINE_BACKEND: &str = "  rtpengine:\n    address: \"127.0.0.1:22222\"\n";
    const RTPPROXY_BACKEND: &str =
        "  backend: rtpproxy\n  rtpproxy:\n    address: \"127.0.0.1:22222\"\n";

    #[test]
    fn parses_media_profile_websocket_and_dsp_fields() {
        let yaml = ws_profile_yaml(
            SIPHON_RTP_BACKEND,
            "      offer:\n        replace: [\"origin\"]\n        \
             ws_uri: \"wss://ai.example.com/stream/{call_id}\"\n        \
             ws_vad: true\n        ws_barge_in: true\n        \
             ws_vad_threshold: 2000000\n        ws_vad_hangover_ms: 300\n        \
             noise_suppression: true\n        echo_cancellation: true\n        \
             received_from: true\n        rtcp_mux: [\"require\"]\n      answer: {}\n",
        );
        let config = Config::from_str(&yaml).unwrap();
        let media = config.media.unwrap();
        let offer = &media.profiles.get("voice_ai_custom").unwrap().offer;
        assert_eq!(
            offer.ws_uri.as_deref(),
            Some("wss://ai.example.com/stream/{call_id}")
        );
        assert!(offer.ws_vad);
        assert!(offer.ws_barge_in);
        assert_eq!(offer.ws_vad_threshold, Some(2_000_000));
        assert_eq!(offer.ws_vad_hangover_ms, Some(300));
        assert!(offer.noise_suppression);
        assert!(offer.echo_cancellation);
        assert!(offer.received_from);
        assert_eq!(offer.rtcp_mux, vec!["require"]);
    }

    /// Defaults must stay off, so an existing profile emits exactly the command
    /// it did before these knobs existed.
    #[test]
    fn media_profile_websocket_fields_default_off() {
        let yaml = ws_profile_yaml(
            RTPENGINE_BACKEND,
            "      offer:\n        replace: [\"origin\"]\n      answer: {}\n",
        );
        let config = Config::from_str(&yaml).unwrap();
        let media = config.media.unwrap();
        let offer = &media.profiles.get("voice_ai_custom").unwrap().offer;
        assert!(offer.ws_uri.is_none());
        assert!(!offer.ws_vad);
        assert!(!offer.ws_barge_in);
        assert!(offer.ws_vad_threshold.is_none());
        assert!(offer.ws_vad_hangover_ms.is_none());
        assert!(!offer.noise_suppression);
        assert!(!offer.echo_cancellation);
        assert!(!offer.received_from);
        assert!(offer.rtcp_mux.is_empty());
    }

    #[test]
    fn rejects_media_profile_non_websocket_ws_uri_scheme() {
        let yaml = ws_profile_yaml(
            SIPHON_RTP_BACKEND,
            "      offer:\n        ws_uri: \"https://ai.example.com/stream\"\n      answer: {}\n",
        );
        let error = Config::from_str(&yaml).expect_err("https:// must be rejected");
        assert!(
            error.to_string().contains("ws_uri"),
            "error should name the field: {error}"
        );
    }

    #[test]
    fn rejects_media_profile_bad_rtcp_mux_token() {
        let yaml = ws_profile_yaml(
            SIPHON_RTP_BACKEND,
            "      offer:\n        rtcp_mux: [\"mux-please\"]\n      answer: {}\n",
        );
        let error = Config::from_str(&yaml).expect_err("unknown token must be rejected");
        assert!(
            error.to_string().contains("rtcp_mux"),
            "error should name the field: {error}"
        );
    }

    #[test]
    fn accepts_media_profile_rtcp_mux_case_insensitively() {
        let yaml = ws_profile_yaml(
            SIPHON_RTP_BACKEND,
            "      offer:\n        rtcp_mux: [\"OFFER\", \" Require \"]\n      answer: {}\n",
        );
        let config = Config::from_str(&yaml).unwrap();
        let media = config.media.unwrap();
        assert_eq!(
            media
                .profiles
                .get("voice_ai_custom")
                .unwrap()
                .offer
                .rtcp_mux,
            vec!["offer", "require"]
        );
    }

    /// A `ws_uri` the engine never receives means the leg is answered and bridged
    /// nowhere — silence for the call's whole duration.  So it fails the load
    /// rather than warning, unlike `address_family` on rtpproxy (which only
    /// loses IPv4/IPv6 interworking on an otherwise working call).
    #[test]
    fn rejects_websocket_profile_on_rtpengine_backend() {
        let yaml = ws_profile_yaml(
            RTPENGINE_BACKEND,
            "      offer:\n        ws_uri: \"wss://ai.example.com/stream\"\n      answer: {}\n",
        );
        let error = Config::from_str(&yaml).expect_err("ws_uri on rtpengine must be rejected");
        let message = error.to_string();
        assert!(
            message.contains("ws_uri") && message.contains("rtpengine"),
            "error should name the field and the backend: {message}"
        );
        assert!(
            message.contains("voice_ai_custom"),
            "error should name the profile: {message}"
        );
    }

    #[test]
    fn parses_media_profile_websocket_tee_fields() {
        let yaml = ws_profile_yaml(
            SIPHON_RTP_BACKEND,
            "      offer:\n        ws_tee: \"wss://asr.example.com/{call_id}\"\n        \
             ws_tee_direction: \"callee\"\n        ws_tee_channels: 1\n      answer: {}\n",
        );
        let config = Config::from_str(&yaml).unwrap();
        let media = config.media.unwrap();
        let offer = &media.profiles.get("voice_ai_custom").unwrap().offer;
        assert_eq!(
            offer.ws_tee.as_deref(),
            Some("wss://asr.example.com/{call_id}")
        );
        assert_eq!(offer.ws_tee_direction, Some(WsTeeDirection::Callee));
        assert_eq!(offer.ws_tee_channels, Some(1));
    }

    /// A profile that does not ask for a tee must stay byte-identical on the
    /// wire to what it emitted before these knobs existed.
    #[test]
    fn media_profile_websocket_tee_fields_default_off() {
        let yaml = ws_profile_yaml(
            RTPENGINE_BACKEND,
            "      offer:\n        replace: [\"origin\"]\n      answer: {}\n",
        );
        let config = Config::from_str(&yaml).unwrap();
        let media = config.media.unwrap();
        let offer = &media.profiles.get("voice_ai_custom").unwrap().offer;
        assert!(offer.ws_tee.is_none());
        assert!(offer.ws_tee_direction.is_none());
        assert!(offer.ws_tee_channels.is_none());
    }

    #[test]
    fn accepts_media_profile_ws_tee_direction_case_insensitively() {
        let yaml = ws_profile_yaml(
            SIPHON_RTP_BACKEND,
            "      offer:\n        ws_tee: \"wss://asr.example.com/s\"\n        \
             ws_tee_direction: \" Caller \"\n      answer: {}\n",
        );
        let config = Config::from_str(&yaml).unwrap();
        let media = config.media.unwrap();
        assert_eq!(
            media
                .profiles
                .get("voice_ai_custom")
                .unwrap()
                .offer
                .ws_tee_direction,
            Some(WsTeeDirection::Caller)
        );
    }

    /// The six fields added with the 0.3.0 media contract must parse on the
    /// native backend and land on the profile.
    #[test]
    fn parses_media_profile_beep_and_vad_engine_fields() {
        let yaml = ws_profile_yaml(
            SIPHON_RTP_BACKEND,
            "      offer:\n        ws_uri: \"wss://ai.example.com/s\"\n        \
             ws_vad: true\n        ws_sample_rate: 16000\n        \
             ws_vad_engine: \"neural\"\n        ws_vad_min_speech_ms: 80\n        \
             beep_detection: true\n        beep_cadence_guard_ms: 3000\n        \
             ws_tee: \"wss://asr.example.com/t\"\n        \
             ws_tee_sample_rate: 48000\n      answer: {}\n",
        );
        let config = Config::from_str(&yaml).unwrap();
        let media = config.media.expect("media block");
        let offer = &media.profiles.get("voice_ai_custom").unwrap().offer;

        assert_eq!(offer.ws_sample_rate, Some(16_000));
        assert_eq!(offer.ws_vad_engine, Some(WsVadEngine::Neural));
        assert_eq!(offer.ws_vad_min_speech_ms, Some(80));
        assert!(offer.beep_detection);
        assert_eq!(offer.beep_cadence_guard_ms, Some(3_000));
        assert_eq!(offer.ws_tee_sample_rate, Some(48_000));
    }

    /// `ws_vad_engine` is a closed selector: an unknown detector must be a hard
    /// config error, never a quiet fall back to the detector the operator was
    /// explicitly avoiding.
    #[test]
    fn rejects_media_profile_bad_ws_vad_engine() {
        let yaml = ws_profile_yaml(
            SIPHON_RTP_BACKEND,
            "      offer:\n        ws_vad_engine: \"telepathy\"\n      answer: {}\n",
        );
        let error = Config::from_str(&yaml).expect_err("unknown detector must be rejected");
        assert!(
            error.to_string().contains("ws_vad_engine"),
            "error should name the field: {error}"
        );
    }

    /// The engine *fails* an offer carrying an out-of-range wire rate rather
    /// than clamping it, so a bad value must be caught at boot — otherwise the
    /// box comes up healthy and every call answers with no media.
    #[test]
    fn rejects_media_profile_bad_ws_sample_rates() {
        for (field, value) in [
            ("ws_sample_rate", "44100"), // not a whole kHz
            ("ws_sample_rate", "4000"),  // below the floor
            ("ws_sample_rate", "96000"), // above the ceiling
            ("ws_tee_sample_rate", "12345"),
            ("ws_tee_sample_rate", "0"),
        ] {
            let yaml = ws_profile_yaml(
                SIPHON_RTP_BACKEND,
                &format!("      offer:\n        {field}: {value}\n      answer: {{}}\n"),
            );
            let error = Config::from_str(&yaml).expect_err("{field}={value} must be rejected");
            assert!(
                error.to_string().contains(field),
                "error should name {field}: {error}"
            );
        }
    }

    /// The boundary values must be accepted — a validator that is merely strict
    /// is as wrong as one that is merely lax.
    #[test]
    fn accepts_media_profile_boundary_ws_sample_rates() {
        for value in ["8000", "48000", "16000"] {
            let yaml = ws_profile_yaml(
                SIPHON_RTP_BACKEND,
                &format!("      offer:\n        ws_sample_rate: {value}\n      answer: {{}}\n"),
            );
            Config::from_str(&yaml).unwrap_or_else(|error| panic!("{value} Hz rejected: {error}"));
        }
    }

    /// All six are native `siphon-rtp` extensions.  On any other backend the
    /// engine never sees them, so the call answers into a media path that was
    /// never wired — a hard config error, not a warning.
    #[test]
    fn rejects_new_media_fields_on_non_native_backends() {
        for field_line in [
            "ws_sample_rate: 16000",
            "ws_vad_engine: \"neural\"",
            "ws_vad_min_speech_ms: 80",
            "beep_detection: true",
            "beep_cadence_guard_ms: 3000",
            "ws_tee_sample_rate: 16000",
        ] {
            let field = field_line.split(':').next().expect("field name");
            for backend in [RTPENGINE_BACKEND, RTPPROXY_BACKEND] {
                let yaml = ws_profile_yaml(
                    backend,
                    &format!("      offer:\n        {field_line}\n      answer: {{}}\n"),
                );
                let error = Config::from_str(&yaml)
                    .err()
                    .unwrap_or_else(|| {
                        panic!("{field} must be rejected on backend block {backend:?}")
                    })
                    .to_string();
                assert!(
                    error.contains(field),
                    "error should name {field} on {backend:?}: {error}"
                );
            }

            // ...and must be accepted on the native backend, so the gate is
            // proven to be backend-specific rather than a blanket refusal.
            let yaml = ws_profile_yaml(
                SIPHON_RTP_BACKEND,
                &format!("      offer:\n        {field_line}\n      answer: {{}}\n"),
            );
            Config::from_str(&yaml)
                .unwrap_or_else(|error| panic!("{field} rejected on siphon-rtp: {error}"));
        }
    }

    #[test]
    fn rejects_media_profile_bad_ws_tee_direction() {
        let yaml = ws_profile_yaml(
            SIPHON_RTP_BACKEND,
            "      offer:\n        ws_tee: \"wss://asr.example.com/s\"\n        \
             ws_tee_direction: \"send\"\n      answer: {}\n",
        );
        let error = Config::from_str(&yaml).expect_err("unknown direction must be rejected");
        assert!(
            error.to_string().contains("ws_tee_direction"),
            "error should name the field: {error}"
        );
    }

    #[test]
    fn rejects_media_profile_non_websocket_ws_tee_scheme() {
        let yaml = ws_profile_yaml(
            SIPHON_RTP_BACKEND,
            "      offer:\n        ws_tee: \"https://asr.example.com/s\"\n      answer: {}\n",
        );
        let error = Config::from_str(&yaml).expect_err("https:// must be rejected");
        assert!(
            error.to_string().contains("ws_tee"),
            "error should name the field: {error}"
        );
    }

    /// Same reasoning as `ws_uri`: a tee the engine never receives streams
    /// nothing, so the consumer sits silent on a call that looks healthy.
    #[test]
    fn rejects_websocket_tee_profile_on_rtpengine_backend() {
        let yaml = ws_profile_yaml(
            RTPENGINE_BACKEND,
            "      offer:\n        ws_tee: \"wss://asr.example.com/s\"\n      answer: {}\n",
        );
        let error = Config::from_str(&yaml).expect_err("ws_tee on rtpengine must be rejected");
        let message = error.to_string();
        assert!(
            message.contains("ws_tee") && message.contains("rtpengine"),
            "error should name the field and the backend: {message}"
        );
        assert!(
            message.contains("voice_ai_custom"),
            "error should name the profile: {message}"
        );
    }

    #[test]
    fn rejects_websocket_tee_profile_on_rtpproxy_backend() {
        let yaml = ws_profile_yaml(
            RTPPROXY_BACKEND,
            "      offer:\n        ws_tee: \"wss://asr.example.com/s\"\n      answer: {}\n",
        );
        let error = Config::from_str(&yaml).expect_err("ws_tee on rtpproxy must be rejected");
        let message = error.to_string();
        assert!(
            message.contains("ws_tee") && message.contains("rtpproxy"),
            "error should name the field and the backend: {message}"
        );
    }

    #[test]
    fn rejects_dsp_profile_on_rtpproxy_backend() {
        let yaml = ws_profile_yaml(
            RTPPROXY_BACKEND,
            "      offer:\n        noise_suppression: true\n      answer: {}\n",
        );
        let error = Config::from_str(&yaml).expect_err("noise_suppression must be rejected");
        assert!(
            error.to_string().contains("noise_suppression"),
            "error should name the field: {error}"
        );
    }

    /// The answer direction is checked too — a profile is only half-validated if
    /// only its offer flags are.
    #[test]
    fn rejects_websocket_profile_set_on_answer_direction_only() {
        let yaml = ws_profile_yaml(
            RTPENGINE_BACKEND,
            "      offer: {}\n      answer:\n        ws_barge_in: true\n",
        );
        let error = Config::from_str(&yaml).expect_err("answer-side ws_barge_in must be rejected");
        let message = error.to_string();
        assert!(
            message.contains("ws_barge_in") && message.contains("answer"),
            "error should name the field and direction: {message}"
        );
    }

    /// `received_from` and `rtcp_mux` are real rtpengine NG keys, so only
    /// rtpproxy rejects them.
    #[test]
    fn accepts_received_from_and_rtcp_mux_on_rtpengine_backend() {
        let yaml = ws_profile_yaml(
            RTPENGINE_BACKEND,
            "      offer:\n        received_from: true\n        \
             rtcp_mux: [\"require\"]\n      answer: {}\n",
        );
        let config = Config::from_str(&yaml).expect("rtpengine honours both");
        let media = config.media.unwrap();
        assert!(
            media
                .profiles
                .get("voice_ai_custom")
                .unwrap()
                .offer
                .received_from
        );
    }

    #[test]
    fn rejects_received_from_on_rtpproxy_backend() {
        let yaml = ws_profile_yaml(
            RTPPROXY_BACKEND,
            "      offer:\n        received_from: true\n      answer: {}\n",
        );
        let error = Config::from_str(&yaml).expect_err("rtpproxy cannot gate on received_from");
        assert!(
            error.to_string().contains("received_from"),
            "error should name the field: {error}"
        );
    }

    #[test]
    fn accepts_websocket_profile_on_siphon_rtp_backend() {
        let yaml = ws_profile_yaml(
            SIPHON_RTP_BACKEND,
            "      offer:\n        ws_uri: \"wss://ai.example.com/stream\"\n        \
             noise_suppression: true\n      answer: {}\n",
        );
        Config::from_str(&yaml).expect("siphon-rtp honours the WS bridge");
    }

    /// The check must not fire on a config with no `media` block at all.
    #[test]
    fn media_profile_validation_skips_config_without_media() {
        let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
"#;
        let config = Config::from_str(yaml).unwrap();
        assert!(config.media.is_none());
    }

    #[test]
    fn unsupported_profile_fields_is_empty_for_plain_profile() {
        let plain = NgFlagsConfig {
            replace: vec!["origin".into()],
            ..NgFlagsConfig::default()
        };
        for backend in [
            MediaBackendKind::Rtpengine,
            MediaBackendKind::SiphonRtp,
            MediaBackendKind::Rtpproxy,
        ] {
            assert!(
                backend.unsupported_profile_fields(&plain).is_empty(),
                "{} rejected a plain profile",
                backend.as_str()
            );
        }
    }

    /// `text_events` drives the engine's RFC 4103 text processor, which only
    /// siphon-rtp has.  It must be a hard config error on the other two rather
    /// than a silent no-op: a script waiting on `@rtpengine.on_text` for events
    /// that can never arrive looks identical to a caller who typed nothing.
    #[test]
    fn unsupported_profile_fields_rejects_text_events_off_siphon_rtp() {
        let flags = NgFlagsConfig {
            text_events: true,
            ..NgFlagsConfig::default()
        };
        for backend in [MediaBackendKind::Rtpengine, MediaBackendKind::Rtpproxy] {
            assert!(
                backend
                    .unsupported_profile_fields(&flags)
                    .contains(&"text_events"),
                "{} accepted text_events it cannot honour",
                backend.as_str()
            );
        }
        assert!(
            MediaBackendKind::SiphonRtp
                .unsupported_profile_fields(&flags)
                .is_empty(),
            "siphon-rtp rejected text_events it supports"
        );
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
        assert_eq!(
            group1.destinations[0].attrs.get("region").unwrap(),
            "us-east"
        );
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
            let yaml = format!(
                r#"
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
"#
            );
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
        assert!(
            matches!(runtime.backend, crate::cdr::CdrBackendType::File { ref path, rotate_size_mb } if path == "/tmp/cdr.jsonl" && rotate_size_mb == 50)
        );
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
        assert!(
            matches!(runtime.backend, crate::cdr::CdrBackendType::Http { ref url, ref auth_header } if url == "https://collector.example.com/v1/cdr" && auth_header.as_deref() == Some("Bearer secret"))
        );
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
        assert!(
            matches!(runtime.backend, crate::cdr::CdrBackendType::Syslog { ref target } if target == "10.0.0.5:514")
        );
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
            "    ne_identifier: \"siphon-ne-1\"\n",
            "    admf_identifier: \"admf-id\"\n",
            "    tls:\n",
            "      certificate: \"/etc/siphon/li/x1.crt\"\n",
            "      private_key: \"/etc/siphon/li/x1.key\"\n",
            "      client_ca: \"/etc/siphon/li/admf-ca.pem\"\n",
            "    admf:\n",
            "      endpoint: \"https://admf.example/X1/ADMF\"\n",
            "      client_certificate: \"/etc/siphon/li/ne.pem\"\n",
            "      client_private_key: \"/etc/siphon/li/ne.key\"\n",
            "      keepalive_secs: 45\n",
            "  x2:\n",
            "    delivery_address: \"10.0.0.50:6543\"\n",
            "    transport: tls\n",
            "    reconnect_interval_secs: 10\n",
            "    channel_size: 5000\n",
            "    tls:\n",
            "      ca_cert: \"/etc/siphon/li/mediation-ca.pem\"\n",
            "  x3:\n",
            "    enabled: true\n",
            "  siprec:\n",
            "    srs_uri: \"sip:srs@recorder.example.com\"\n",
            "    session_copies: 2\n",
            "    transport: tls\n",
            // X3 content delivery is only possible on the native media
            // engine, and the config-load gate enforces that.
            "media:\n",
            "  backend: siphon-rtp\n",
        );
        let config = Config::from_str(yaml).unwrap();
        let li = config.lawful_intercept.unwrap();
        assert!(li.enabled);
        assert_eq!(li.audit_log.unwrap(), "/var/log/siphon/li-audit.log");

        // X1
        let x1 = li.x1.unwrap();
        assert_eq!(x1.listen, "127.0.0.1:8443");
        assert_eq!(x1.ne_identifier, "siphon-ne-1");
        assert_eq!(x1.admf_identifier.as_deref(), Some("admf-id"));
        // The endpoint path and declared schema version default rather than
        // being spelled out in every deployment.
        assert_eq!(x1.path, "/X1/NE");
        assert_eq!(x1.version, crate::li::x1::types::DEFAULT_VERSION);
        assert!(x1.bind_admf_identifier_to_certificate);
        assert_eq!(x1.tls.certificate, "/etc/siphon/li/x1.crt");
        assert_eq!(x1.tls.private_key, "/etc/siphon/li/x1.key");
        assert_eq!(x1.tls.client_ca, "/etc/siphon/li/admf-ca.pem");

        // The network-element-to-ADMF direction.
        let admf = x1.admf.unwrap();
        assert_eq!(admf.endpoint, "https://admf.example/X1/ADMF");
        assert_eq!(admf.client_certificate, "/etc/siphon/li/ne.pem");
        assert_eq!(admf.keepalive_secs, 45);
        assert!(admf.reconcile_on_start);

        // X2
        let x2 = li.x2.unwrap();
        assert_eq!(x2.delivery_address, "10.0.0.50:6543");
        assert_eq!(x2.transport, "tls");
        assert_eq!(x2.reconnect_interval_secs, 10);
        assert_eq!(x2.channel_size, 5000);
        assert_eq!(
            x2.tls.unwrap().ca_cert.unwrap(),
            "/etc/siphon/li/mediation-ca.pem"
        );

        // X3 is a switch and nothing more: the media engine frames the content
        // and delivers it to the destinations provisioned over X1.
        assert!(li.x3.unwrap().enabled);

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
            "    enabled: true\n",
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

        // An empty block is enough to switch content delivery on.
        assert!(li.x3.unwrap().enabled);
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
        assert_eq!(
            diameter.peers[2].destination_host.as_deref(),
            Some("ocs-primary.charging.example.com")
        );
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
        let cx_peers =
            diameter.peers_for_application(&DiameterApplication::Cx, Some("example.com"));
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
    fn udp_recv_buffer_defaults_and_overrides() {
        // Absent → the 1 MiB default.
        let config = Config::from_str(minimal_yaml()).unwrap();
        assert_eq!(config.listen.udp_recv_buffer_bytes, 1024 * 1024);

        // Explicit value wins.
        let yaml = r#"
listen:
  udp_recv_buffer_bytes: 4194304
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
"#;
        let config = Config::from_str(yaml).unwrap();
        assert_eq!(config.listen.udp_recv_buffer_bytes, 4 * 1024 * 1024);

        // 0 is the documented "leave the kernel default alone" escape hatch.
        let yaml = r#"
listen:
  udp_recv_buffer_bytes: 0
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
"#;
        let config = Config::from_str(yaml).unwrap();
        assert_eq!(config.listen.udp_recv_buffer_bytes, 0);
    }

    #[test]
    fn dscp_to_tos_conversion() {
        assert_eq!(dscp_to_tos(0), 0); // BE
        assert_eq!(dscp_to_tos(24), 96); // CS3 → signaling
        assert_eq!(dscp_to_tos(46), 184); // EF  → voice media
        assert_eq!(dscp_to_tos(34), 136); // AF41 → video
        assert_eq!(dscp_to_tos(63), 252); // max DSCP
    }

    #[test]
    fn listen_config_defaults_to_cs3() {
        let config = Config::from_str(minimal_yaml()).unwrap();
        assert_eq!(
            config.listen.dscp,
            Some(24),
            "default DSCP should be CS3 (24)"
        );
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
    fn listen_config_mtu_from_yaml() {
        let yaml = r#"
listen:
  mtu: 1280
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
"#;
        let config = Config::from_str(yaml).unwrap();
        assert_eq!(config.listen.mtu, Some(1280));
    }

    #[test]
    fn listen_config_mtu_defaults_off() {
        let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
"#;
        let config = Config::from_str(yaml).unwrap();
        assert_eq!(
            config.listen.mtu, None,
            "mtu must default to off (no behaviour change on a bump)"
        );
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
          allowed_ips: ["192.0.2.0/24"]
          expected_origin_host: "mme.epc.example.org"
      servers:
        - { name: hss, host: "192.0.2.164", port: 3868, transport: tcp }
"#;
        let config = Config::from_str(yaml).expect("Diameter server config should parse");
        let diameter = config.diameter.expect("diameter section");
        let listen = diameter.listen.expect("listen");
        assert_eq!(listen.tcp.as_deref(), Some("0.0.0.0:3868"));
        assert_eq!(listen.sctp.as_deref(), Some("0.0.0.0:3868"));
        // Flat client-only fields default cleanly when omitted.
        assert!(diameter.origin_host.is_empty());

        let tenant = diameter.tenants.get("default").expect("default tenant");
        assert_eq!(
            tenant.identity.origin_host,
            "diam.epc.mnc001.mcc001.3gppnetwork.org"
        );
        assert_eq!(tenant.clients[0].name, "mme");
        assert_eq!(tenant.clients[0].allowed_ips, vec!["192.0.2.0/24"]);
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
        - { name: upstream, host: "192.0.2.137", port: 3868, transport: sctp }
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
        let default = effective
            .get("default")
            .expect("synthesized default tenant");
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
            config.extension_config("baz").and_then(|v| v.as_u64()),
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
