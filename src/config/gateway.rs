//! `gateway:` dispatcher groups and `lcr:` least-cost routing.

use super::bool_true;
use serde::Deserialize;

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
    /// Where the groups come from. Default: `static`, the `groups` list below.
    ///
    /// `database` and `http` read them from a source the controller owns and
    /// reconcile against it on an interval, so a gateway added, edited or
    /// deleted there is followed without a restart. Groups declared in `groups`
    /// and ones a script created with `gateway.add_group()` are never touched
    /// by that reconcile — it owns only what it created.
    #[serde(default = "default_gateway_backend")]
    pub backend: GatewayBackendType,
    /// SQL source for `backend: database`.
    pub database: Option<GatewayDatabaseConfig>,
    /// HTTP source for `backend: http`.
    pub http: Option<GatewayHttpConfig>,
    /// Named destination groups. May be empty when a source supplies them.
    #[serde(default)]
    pub groups: Vec<GatewayGroupConfig>,
}

/// Where `gateway:` reads its destination groups from.
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum GatewayBackendType {
    /// The `groups` list in this file.
    Static,
    /// A PostgreSQL query the controller owns.
    Database,
    /// A JSON endpoint the controller serves.
    Http,
}

/// SQL source for `gateway.backend: database`.
///
/// The query is the operator's. Columns are read by name: `group` (or
/// `group_name`) and `uri` are required; `address`, `transport`, `weight`,
/// `priority`, `username`, `password`, `ha1`, `ha1_algorithm`,
/// `source_networks`, `enabled`, `registers` and `require_registration` are
/// optional. When the statement references `$1`, the instance id
/// (`server.instance_id`) is bound to it, so a deployment can shard its
/// gateways across nodes.
#[derive(Debug, Deserialize, Clone)]
pub struct GatewayDatabaseConfig {
    /// libpq connection URI.
    pub url: String,
    /// Statement returning one row per destination.
    #[serde(default = "default_gateway_query")]
    pub query: String,
    /// How often to re-read the source and reconcile, in seconds. `POST
    /// /admin/gateways/refresh` applies a change at once, so this is the floor
    /// rather than the mechanism.
    #[serde(default = "default_gateway_refresh_secs")]
    pub refresh_secs: u64,
    /// Per-query deadline in milliseconds, connection included.
    #[serde(default = "default_gateway_source_timeout_ms")]
    pub timeout_ms: u64,
}

/// JSON source for `gateway.backend: http`.
///
/// The endpoint answers `GET {url}` with the contract in
/// `docs/reference/gateway-api.md` (typed in `siphon_sdk.gateways`). Use this
/// form when gateway credentials are sealed at rest: the controller unseals
/// in-process and serves them over a trusted local channel.
#[derive(Debug, Deserialize, Clone)]
pub struct GatewayHttpConfig {
    /// URL siphon `GET`s the gateway list from.
    pub url: String,
    /// How often to re-read the source and reconcile, in seconds.
    #[serde(default = "default_gateway_refresh_secs")]
    pub refresh_secs: u64,
    /// Per-request deadline in milliseconds.
    #[serde(default = "default_gateway_source_timeout_ms")]
    pub timeout_ms: u64,
    /// Full `Authorization` header value sent with each request.
    pub auth_header: Option<String>,
}

fn default_gateway_backend() -> GatewayBackendType {
    GatewayBackendType::Static
}

fn default_gateway_query() -> String {
    "SELECT \"group\", uri, address, transport, weight, priority, username, password, \
     enabled FROM gateways"
        .to_string()
}

fn default_gateway_refresh_secs() -> u64 {
    30
}

fn default_gateway_source_timeout_ms() -> u64 {
    2000
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
    /// Digest credentials this destination challenges with, used to answer a
    /// 401/407 on any B-leg sent to it.
    #[serde(default)]
    pub auth: Option<GatewayAuthConfig>,
    /// AoR of an outbound registration this destination belongs to, linking one
    /// trunk's registration and its egress. When set and this destination has
    /// no `auth` of its own, it answers challenges with that registration's
    /// credentials, so one trunk's secret is defined once.
    #[serde(default)]
    pub registers: Option<String>,
    /// Keep this destination out of `gateway.select()` while the registration
    /// named by `registers` is not registered.
    ///
    /// Off by default: a gateway that authenticates per call does not need its
    /// registration to be up, and silently withholding a destination is worse
    /// than trying it. Turn it on for a trunk that only accepts calls from a
    /// registered peer, where dialling it unregistered just earns a 403.
    #[serde(default)]
    pub require_registration: bool,
}

/// Digest credentials for one gateway destination.
///
/// Supply `password` or `ha1`, not both. An `ha1` is
/// `H(username:realm:password)` for the realm the gateway challenges with, so
/// a credential store need not hold a reversible secret — but it is still
/// password-equivalent *for that realm*, and it is bound to one hash
/// (RFC 7616 §3.4.3), so a gateway that challenges with SHA-256 cannot be
/// answered from an MD5 one.
#[derive(Debug, Deserialize, Clone)]
pub struct GatewayAuthConfig {
    /// Digest username.
    pub username: String,
    /// Plaintext password. Supports `${VAR}` expansion, so it need not sit in
    /// the file.
    #[serde(default)]
    pub password: Option<String>,
    /// Pre-computed `H(username:realm:password)` as a hex string.
    #[serde(default)]
    pub ha1: Option<String>,
    /// Which hash `ha1` was computed with: `md5` (default), `sha-256`, or
    /// `sha-512-256`.
    #[serde(default = "default_gateway_ha1_algorithm")]
    pub ha1_algorithm: String,
}

fn default_gateway_ha1_algorithm() -> String {
    "md5".to_string()
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
