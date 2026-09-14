//! `security:` limits, firewall and bans, and `nat:` traversal.

use super::bool_true;
use serde::Deserialize;

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
    /// Ceilings on concurrent inbound stream connections and handshakes.
    ///
    /// Unlike the guards above this one is **always on** — every field has a
    /// default, so omitting the block (or the whole `security:` section) still
    /// bounds what one source can make siphon spend. See
    /// [`ConnectionLimitsConfig`].
    #[serde(default)]
    pub connection_limits: ConnectionLimitsConfig,
}

/// `security.connection_limits` — see [`crate::security::ConnectionLimits`] for
/// what each ceiling bounds and why the two are sized so differently.
///
/// Every field defaults; `0` disables that ceiling.
#[derive(Debug, Deserialize, Clone)]
pub struct ConnectionLimitsConfig {
    /// Concurrent in-flight handshakes (TLS/WS) plus first-line sniffs from one
    /// source. Default 32.
    #[serde(default = "default_max_handshakes_per_source")]
    pub max_handshakes_per_source: u32,
    /// Concurrent in-flight handshakes across all sources. Default 1024.
    #[serde(default = "default_max_handshakes")]
    pub max_handshakes: u32,
    /// Established stream connections from one source. Default 256.
    ///
    /// **Raise this (or set 0) where one upstream address legitimately fronts
    /// hundreds of registrations** — a carrier CGNAT pool, a large enterprise
    /// NAT, an aggregator. The default is a runaway detector, not a policy, and
    /// `siphon_connections_refused_total{reason="connections_per_source"}` is
    /// what tells you it is binding on real traffic.
    #[serde(default = "default_max_connections_per_source")]
    pub max_connections_per_source: u32,
    /// Established stream connections across all sources. Default 16384.
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
}

impl Default for ConnectionLimitsConfig {
    fn default() -> Self {
        Self {
            max_handshakes_per_source: default_max_handshakes_per_source(),
            max_handshakes: default_max_handshakes(),
            max_connections_per_source: default_max_connections_per_source(),
            max_connections: default_max_connections(),
        }
    }
}

impl From<&ConnectionLimitsConfig> for crate::security::ConnectionLimits {
    fn from(config: &ConnectionLimitsConfig) -> Self {
        Self {
            max_handshakes_per_source: config.max_handshakes_per_source,
            max_handshakes: config.max_handshakes,
            max_connections_per_source: config.max_connections_per_source,
            max_connections: config.max_connections,
        }
    }
}

fn default_max_handshakes_per_source() -> u32 {
    crate::security::DEFAULT_MAX_HANDSHAKES_PER_SOURCE
}
fn default_max_handshakes() -> u32 {
    crate::security::DEFAULT_MAX_HANDSHAKES
}
fn default_max_connections_per_source() -> u32 {
    crate::security::DEFAULT_MAX_CONNECTIONS_PER_SOURCE
}
fn default_max_connections() -> u32 {
    crate::security::DEFAULT_MAX_CONNECTIONS
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
    ///
    /// The expiry **slides**: an abuse signal from an already-banned source
    /// pushes it out to a full `ban_duration_secs` from that signal, so a
    /// scanner that keeps hammering through its ban does not walk out on
    /// schedule. `max_ban_duration_secs` caps the total.
    pub ban_duration_secs: u32,
    /// Ceiling (seconds) on how far continued abuse may push a single ban's
    /// expiry, measured from the instant that ban was raised. Defaults to
    /// 24 × `ban_duration_secs`; clamped up to at least `ban_duration_secs`.
    ///
    /// This is the safety valve on the sliding expiry. Uncapped, one source in a
    /// retry loop is banned forever — a handset with a stale password re-tries
    /// on a timer, and behind CGNAT the address it holds is shared with every
    /// other subscriber on that NAT, none of whom did anything. The cap bounds
    /// how long a wrong verdict can last while still pinning a real scanner far
    /// longer than a fixed TTL would.
    #[serde(default)]
    pub max_ban_duration_secs: Option<u32>,
    /// Weight applied to a single high-confidence abuse signal — present-but-
    /// invalid credentials (wrong password), a forged/stale/replayed digest
    /// nonce, non-SIP garbage on a stream transport, or a scanner User-Agent —
    /// toward `threshold`. A weight > 1 bans these unambiguous signals faster
    /// than a bare scanning probe (which counts as 1) while sharing the same
    /// per-IP window. Clamped to ≥ 1. Default: 3.
    #[serde(default = "default_strong_signal_weight")]
    pub strong_signal_weight: u32,
    /// Weight applied to a challenge issued because the request carried no
    /// credentials at all, toward `threshold`.
    ///
    /// **Default 0 — not counted.** RFC 3261 §22.2 makes the credential-less
    /// request the opening leg of challenge-response, so every client sends one
    /// before it has a nonce and counting it bans clients for behaving
    /// correctly. Behind CGNAT the blast radius is every subscriber sharing the
    /// address. The abuse this was reaching for is caught with far fewer false
    /// positives by `scanner_block`, `rate_limit`, `apiban`, and the
    /// non-SIP/handshake signals. Set to 1 to restore the pre-1.7 behaviour.
    /// Clamped to `threshold`.
    #[serde(default)]
    pub missing_credentials_weight: u32,
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
