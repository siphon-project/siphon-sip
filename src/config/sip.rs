//! SIP server-core sections: `subscribe_state:`, `server:` identity, `transaction:`
//! timers, `dialog:` tracking and the named `cache:` connections.

use serde::Deserialize;

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
    /// After the drain deadline, end the calls still up rather than exiting on
    /// top of them, and wait up to this many seconds for that to complete.
    /// Default: 5. Set to 0 to restore the pre-1.9.2 behaviour exactly (exit at
    /// the deadline, tearing nothing down).
    ///
    /// A call lasts minutes and `drain_secs` is seconds, so every restart taken
    /// with traffic up reaches the deadline: without this, each surviving call
    /// is cut with no BYE on either leg, no Ro `CCR-TERMINATION`, no Rf stop, no
    /// media release and no CDR, leaving the far side holding a channel until
    /// someone hangs it up.
    ///
    /// The wait is what makes it real: the charging stops and the media delete
    /// are spawned and awaited nowhere, so exiting straight after issuing the
    /// teardowns would kill them mid-flight.
    ///
    /// **Your container runtime's stop timeout must exceed
    /// `drain_secs + teardown_secs`**, or its `SIGKILL` lands first and none of
    /// this happens. Docker's default is 10 s; Kubernetes'
    /// `terminationGracePeriodSeconds` is 30 s.
    #[serde(default = "default_teardown_secs")]
    pub teardown_secs: u64,
    /// Stable per-replica identity, stamped onto every accepted REGISTER
    /// binding so scripts can recognise their own bindings after restart.
    /// Recommended: ``"${POD_NAME:-${HOSTNAME}}"`` for K8s StatefulSet
    /// deployments.  When unset, siphon falls back to the ``HOSTNAME``
    /// environment variable, then to ``"siphon"`` as a last resort.
    pub instance_id: Option<String>,
    /// Answer an OPTIONS that **no** script handler claims with `200 OK` plus
    /// `Contact` and `Allow` (RFC 3261 §11.2). Default: true.
    ///
    /// Every registrar qualifies its bindings — Asterisk's `qualify_frequency`
    /// and its equivalents probe the registered contact on a timer for the life
    /// of the registration — so a siphon that registers to a provider answers
    /// one of these forever, and making each deployment hand-write the same
    /// handler meant nobody did.
    ///
    /// This only governs the case where no `@proxy.on_request` handler matches:
    /// a script that registers one (including a catch-all `@proxy.on_request`)
    /// owns OPTIONS entirely and is unaffected either way.
    ///
    /// Set to false and an unclaimed OPTIONS is dropped silently rather than
    /// answered — no response at all, the same policy the scripting API uses for
    /// scanner traffic, so siphon does not confirm its own existence to a probe
    /// nobody asked it to answer. Turning it off without registering a handler
    /// means OPTIONS goes unanswered; that is the point of turning it off.
    #[serde(default = "default_auto_options")]
    pub auto_options: bool,
}

fn default_drain_secs() -> u64 {
    30
}

fn default_teardown_secs() -> u64 {
    5
}

fn default_auto_options() -> bool {
    true
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
