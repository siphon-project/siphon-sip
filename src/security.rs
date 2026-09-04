//! Auto-ban store — per-source-IP failure tracking with TTL bans.
//!
//! Feeds the transport ACL ([`crate::transport::acl::TransportAcl::is_allowed`])
//! so a banned source is dropped at accept/recv, before any SIP parsing. Several
//! failure signals increment the same per-IP counter, at different weights:
//!   * rejected credentials — a wrong password, a denied username, or a
//!     forged/stale/replayed nonce ([`crate::script::api`] auth path): weight
//!     `strong_signal_weight` over a transport whose handshake validates the
//!     source, weight 1 over UDP where it does not;
//!   * non-SIP bytes on a stream transport, and a scanner `User-Agent`: weight
//!     `strong_signal_weight`;
//!   * a failed or timed-out TLS/WS handshake: weight 1;
//!   * a non-ACK INVITE **server**-transaction timeout (dispatcher) — the peer
//!     sent an INVITE, got a final response, and never ACKed it: weight 1;
//!   * a challenge issued because the request carried *no* credentials: weight
//!     `missing_credentials_weight`, **0 by default**. That leg is required by
//!     RFC 3261 §22.2, so counting it bans clients for behaving correctly.
//!
//! What is deliberately **not** a signal: a credential source that could not
//! answer. An HTTP auth backend that times out is an outage of ours, not
//! evidence about the peer, and counting it turned one backend blip into
//! hour-long bans on real subscribers.
//!
//! A successful authentication resets the counter, so a legitimate client that
//! challenges-then-succeeds never accumulates. Sources matching `trusted_cidrs`
//! are never counted and never banned (own infrastructure: BGCF, trunks,
//! monitoring).
//!
//! The whole feature is opt-in: it is only constructed when
//! `security.failed_auth_ban` is configured.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use ipnet::IpNet;

/// Process-wide auto-ban store. `None` until installed at startup (only when
/// `security.failed_auth_ban` is configured), so the whole feature is opt-in and
/// every hot-path check is a cheap `OnceLock` read. Mirrors
/// [`crate::metrics::try_metrics`].
static AUTO_BAN: OnceLock<Arc<AutoBanStore>> = OnceLock::new();

/// Install the process-wide auto-ban store (idempotent — a second call is a
/// no-op). Called once at server startup before any traffic is accepted.
pub fn set_auto_ban(store: Arc<AutoBanStore>) {
    let _ = AUTO_BAN.set(store);
}

/// The process-wide auto-ban store, or `None` when `security.failed_auth_ban`
/// is not configured. Read on the accept/recv path (ACL), the auth path, and the
/// transaction-timeout path.
pub fn auto_ban() -> Option<&'static Arc<AutoBanStore>> {
    AUTO_BAN.get()
}

/// Process-wide request-level security filter (PIKE-style per-source rate
/// limiting + scanner User-Agent blocking). `None` until installed at startup,
/// and only installed when `security.rate_limit` or `security.scanner_block` is
/// configured — so the dispatcher hot-path check is a cheap `OnceLock` read that
/// no-ops until the feature is turned on. Mirrors [`AUTO_BAN`].
static SECURITY_FILTER: OnceLock<Arc<SecurityFilter>> = OnceLock::new();

/// Install the process-wide request security filter (idempotent — a second call
/// is a no-op). Called once at server startup before any traffic is accepted.
pub fn set_security_filter(filter: Arc<SecurityFilter>) {
    let _ = SECURITY_FILTER.set(filter);
}

/// The process-wide request security filter, or `None` when neither
/// `security.rate_limit` nor `security.scanner_block` is configured. Read on the
/// dispatcher's inbound-request path before transaction/dialog processing.
pub fn security_filter() -> Option<&'static Arc<SecurityFilter>> {
    SECURITY_FILTER.get()
}

/// Default ceiling on a single SIP message over a stream transport, in bytes.
///
/// Comfortably above anything legitimate — a VoLTE INVITE with a full P-header
/// set is a few KB, and even SIPREC metadata (RFC 7865) runs to tens of KB —
/// while bounding what one connection can make siphon buffer. Raise it with
/// `security.max_message_bytes` if a deployment genuinely carries larger
/// bodies.
pub const DEFAULT_MAX_MESSAGE_BYTES: usize = 256 * 1024;

/// Process-wide stream message-size ceiling. Unset until startup installs the
/// configured value, so every read-path check is a cheap `OnceLock` read that
/// falls back to [`DEFAULT_MAX_MESSAGE_BYTES`]. Mirrors [`AUTO_BAN`].
static MAX_MESSAGE_BYTES: OnceLock<usize> = OnceLock::new();

/// Install the process-wide message-size ceiling (idempotent — a second call is
/// a no-op). Called once at server startup before any traffic is accepted.
pub fn set_max_message_bytes(limit: usize) {
    let _ = MAX_MESSAGE_BYTES.set(limit);
}

/// The configured stream message-size ceiling, or [`DEFAULT_MAX_MESSAGE_BYTES`]
/// when none was installed. Read on every stream framing attempt.
pub fn max_message_bytes() -> usize {
    MAX_MESSAGE_BYTES
        .get()
        .copied()
        .unwrap_or(DEFAULT_MAX_MESSAGE_BYTES)
}

/// Record one failed/timed-out transport handshake (TLS / WSS TLS / WS upgrade)
/// from `source` as an auto-ban signal, and bump the handshake-failure metric.
///
/// Called from the TLS/WSS/WS accept paths when a handshake never completes.
/// Because all three run over TCP, `source` is validated by the TCP three-way
/// handshake (no UDP-style spoofing), making a failed handshake one of the
/// highest-confidence ban signals available — a legitimate SIP client never
/// fails the handshake this way (it sends sig-algs, a usable cipher suite, a
/// well-formed `Sec-WebSocket-Protocol`). The metric is always counted (so
/// scanner volume is visible even before bans are turned on); the ban itself is
/// a no-op until `security.failed_auth_ban` is configured, and `trusted_cidrs`
/// are exempt inside the store. `transport` only labels the ban-transition log.
pub fn record_handshake_failure(source: IpAddr, transport: &str) {
    if let Some(metrics) = crate::metrics::try_metrics() {
        metrics.handshake_failures_total.inc();
    }
    if let Some(ban) = auto_ban() {
        if ban.record_failure(source) {
            tracing::warn!(
                source = %source,
                transport,
                "auto-ban: source banned (repeated handshake failures)"
            );
        }
    }
}

/// Record one non-SIP / unparseable message from `source` on a stream transport
/// (`transport` = "TCP" / "TLS") as a high-confidence auto-ban signal, and bump
/// the malformed-message metric.
///
/// Called from the TCP/TLS read loop only when the accumulated bytes are a
/// *definite* non-SIP attempt — never for an incomplete-but-plausible SIP frame
/// still arriving, never for an empty connection (an AWS NLB / load-balancer TCP
/// health check opens and closes without data), and never for a CRLF keepalive
/// (RFC 5626 §4.4.1), all of which are drained/filtered before this is reached.
/// Because the bytes arrived over a completed TCP handshake the source IP is
/// validated (no UDP-style spoofing), so this is weighted as a strong signal.
pub fn record_malformed_message(source: IpAddr, transport: &str) {
    if let Some(metrics) = crate::metrics::try_metrics() {
        metrics.malformed_messages_total.inc();
    }
    if let Some(ban) = auto_ban() {
        if ban.record_strong_failure(source) {
            tracing::warn!(
                source = %source,
                transport,
                "auto-ban: source banned (non-SIP bytes on stream)"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Inbound connection limits
// ---------------------------------------------------------------------------

/// Default ceiling on concurrent in-flight handshakes from one source.
///
/// A legitimate client opens one connection and completes its handshake; even a
/// large NAT re-registering after a network flap arrives as a stream of them,
/// not as a wall of simultaneous half-open ones. Observed abuse ran ~50 at once
/// from a single address, each pinning a task for the full handshake timeout.
pub const DEFAULT_MAX_HANDSHAKES_PER_SOURCE: u32 = 32;

/// Default ceiling on concurrent in-flight handshakes across all sources.
///
/// What bounds the CPU a *distributed* flood can spend: a TLS handshake is real
/// asymmetric crypto, and the per-source cap alone does not bound how many
/// sources there are.
pub const DEFAULT_MAX_HANDSHAKES: u32 = 1024;

/// Default ceiling on established stream connections from one source.
///
/// A runaway detector, not a policy — see the type-level note on
/// [`ConnectionLimits`] about carrier NAT.
pub const DEFAULT_MAX_CONNECTIONS_PER_SOURCE: u32 = 256;

/// Default ceiling on established stream connections across all sources.
pub const DEFAULT_MAX_CONNECTIONS: u32 = 16_384;

/// Ceilings on concurrent inbound stream connections, per source and overall.
///
/// Two different resources, because they are abused differently. An *in-flight
/// handshake* is CPU and a task; it is held for at most the handshake timeout,
/// and no legitimate peer has many at once, so that cap can be tight. An
/// *established connection* is a socket, a read buffer and a slot in the
/// connection map, held until the peer leaves or the 300 s idle timeout reaps
/// it, and a busy NAT legitimately holds many — so that cap has to be loose.
///
/// **The established per-source cap and carrier NAT.** A CGNAT address can front
/// far more registered UEs than the default allows, and every one of them is a
/// paying subscriber. The default is sized to catch a runaway, not to express a
/// policy: raise `max_connections_per_source` (or set it to 0) wherever one
/// upstream address legitimately carries hundreds of registrations.
/// `siphon_connections_refused_total{reason="connections_per_source"}` is how
/// that shows up before the support tickets do.
///
/// Every field is a maximum; `0` disables that particular ceiling.
#[derive(Debug, Clone, Copy)]
pub struct ConnectionLimits {
    /// Concurrent handshakes (TLS/WS) plus first-line sniffs from one source.
    pub max_handshakes_per_source: u32,
    /// Concurrent handshakes across all sources.
    pub max_handshakes: u32,
    /// Established stream connections from one source.
    pub max_connections_per_source: u32,
    /// Established stream connections across all sources.
    pub max_connections: u32,
}

impl Default for ConnectionLimits {
    fn default() -> Self {
        Self {
            max_handshakes_per_source: DEFAULT_MAX_HANDSHAKES_PER_SOURCE,
            max_handshakes: DEFAULT_MAX_HANDSHAKES,
            max_connections_per_source: DEFAULT_MAX_CONNECTIONS_PER_SOURCE,
            max_connections: DEFAULT_MAX_CONNECTIONS,
        }
    }
}

/// Which ceiling refused a connection. Names the `reason` metric label so an
/// operator can tell "one source is misbehaving" from "the box is full".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusedReason {
    HandshakesPerSource,
    Handshakes,
    ConnectionsPerSource,
    Connections,
}

impl RefusedReason {
    /// Metric label / log value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HandshakesPerSource => "handshakes_per_source",
            Self::Handshakes => "handshakes",
            Self::ConnectionsPerSource => "connections_per_source",
            Self::Connections => "connections",
        }
    }
}

impl std::fmt::Display for RefusedReason {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Process-wide inbound connection limiter. Installed unconditionally at
/// startup (unlike the opt-in guards above) because the ceilings it enforces
/// have to hold even for a deployment with no `security:` block at all.
static CONNECTION_LIMITER: OnceLock<Arc<ConnectionLimiter>> = OnceLock::new();

/// Install the process-wide connection limiter (idempotent — a second call is a
/// no-op). Called once at server startup before any listener binds.
pub fn set_connection_limiter(limiter: Arc<ConnectionLimiter>) {
    let _ = CONNECTION_LIMITER.set(limiter);
}

/// The process-wide connection limiter, if one has been installed.
pub fn connection_limiter() -> Option<&'static Arc<ConnectionLimiter>> {
    CONNECTION_LIMITER.get()
}

/// Take a slot for a newly accepted stream connection from `source`.
///
/// Call from an accept loop right after the ACL check and before spawning the
/// connection task, then move the returned permit into that task: the
/// established slot is held for as long as the permit lives, so every exit path
/// — clean close, error, panic — frees it. Release the handshake half with
/// [`AcceptPermit::handshake_done`] once the connection is confirmed to speak
/// SIP.
///
/// Returns an unmetered permit when no limiter is installed, so a caller never
/// has to branch on whether the feature is on.
pub fn try_accept_connection(source: IpAddr) -> Result<AcceptPermit, RefusedReason> {
    match connection_limiter() {
        Some(limiter) => limiter.try_accept(source),
        None => Ok(AcceptPermit::unmetered(source)),
    }
}

/// Per-source and global counters behind [`try_accept_connection`].
pub struct ConnectionLimiter {
    limits: ConnectionLimits,
    /// Sources exempt from every ceiling (trunks, monitoring, own infra).
    trusted: Vec<IpNet>,
    /// IP → in-flight handshakes. Only populated when the per-source handshake
    /// ceiling is enabled, so an unlimited policy allocates nothing per source.
    handshakes: DashMap<IpAddr, u32>,
    /// IP → established connections. Same conditional-population rule.
    connections: DashMap<IpAddr, u32>,
    handshakes_total: AtomicU32,
    connections_total: AtomicU32,
}

impl ConnectionLimiter {
    /// Build a limiter from the configured ceilings and `trusted_cidrs`.
    /// Invalid CIDRs are ignored (logged by the caller), matching
    /// [`AutoBanStore::new`].
    pub fn new(limits: ConnectionLimits, trusted_cidrs: &[String]) -> Self {
        Self {
            limits,
            trusted: trusted_cidrs
                .iter()
                .filter_map(|cidr| cidr.parse::<IpNet>().ok())
                .collect(),
            handshakes: DashMap::new(),
            connections: DashMap::new(),
            handshakes_total: AtomicU32::new(0),
            connections_total: AtomicU32::new(0),
        }
    }

    fn is_trusted(&self, source: IpAddr) -> bool {
        self.trusted.iter().any(|net| net.contains(&source))
    }

    /// Take one established-connection slot and one handshake slot, or say
    /// which ceiling refused.
    ///
    /// The connection slot is taken first: it is the longer-lived resource, so
    /// refusing on it avoids doing handshake bookkeeping for a connection that
    /// could never be served anyway.
    pub fn try_accept(self: &Arc<Self>, source: IpAddr) -> Result<AcceptPermit, RefusedReason> {
        if self.is_trusted(source) {
            return Ok(AcceptPermit::unmetered(source));
        }

        if !take_global(&self.connections_total, self.limits.max_connections) {
            return Err(RefusedReason::Connections);
        }
        if !take_per_source(
            &self.connections,
            source,
            self.limits.max_connections_per_source,
        ) {
            release_global(&self.connections_total);
            return Err(RefusedReason::ConnectionsPerSource);
        }
        if !take_global(&self.handshakes_total, self.limits.max_handshakes) {
            release_per_source(&self.connections, source);
            release_global(&self.connections_total);
            return Err(RefusedReason::Handshakes);
        }
        if !take_per_source(
            &self.handshakes,
            source,
            self.limits.max_handshakes_per_source,
        ) {
            release_global(&self.handshakes_total);
            release_per_source(&self.connections, source);
            release_global(&self.connections_total);
            return Err(RefusedReason::HandshakesPerSource);
        }

        self.publish_gauges();
        Ok(AcceptPermit {
            limiter: Some(Arc::clone(self)),
            source,
            handshake_held: true,
            connection_held: true,
        })
    }

    fn release_handshake(&self, source: IpAddr) {
        release_per_source(&self.handshakes, source);
        release_global(&self.handshakes_total);
        self.publish_gauges();
    }

    fn release_connection(&self, source: IpAddr) {
        release_per_source(&self.connections, source);
        release_global(&self.connections_total);
        self.publish_gauges();
    }

    fn publish_gauges(&self) {
        if let Some(metrics) = crate::metrics::try_metrics() {
            metrics
                .handshakes_in_flight
                .set(i64::from(self.handshakes_total.load(Ordering::Relaxed)));
            metrics
                .stream_connections_active
                .set(i64::from(self.connections_total.load(Ordering::Relaxed)));
        }
    }

    /// Number of sources currently holding at least one slot, as
    /// `(handshakes, connections)`. Both must return to zero once every permit
    /// is dropped — these maps are keyed by a live entity, so a row that
    /// outlives its connection is a per-source leak.
    #[cfg(test)]
    fn tracked_sources(&self) -> (usize, usize) {
        (self.handshakes.len(), self.connections.len())
    }
}

/// Take one per-source slot, or report the ceiling was reached.
///
/// A zero ceiling means unlimited, and deliberately does not touch the map: an
/// operator who turned the cap off should not pay a row per source for it.
fn take_per_source(map: &DashMap<IpAddr, u32>, source: IpAddr, limit: u32) -> bool {
    if limit == 0 {
        return true;
    }
    let mut entry = map.entry(source).or_insert(0);
    if *entry >= limit {
        return false;
    }
    *entry += 1;
    true
}

/// Give back one per-source slot, removing the row when it reaches zero.
///
/// The row must go, not merely decrement: leaving zeroes behind would grow the
/// map by one entry per source ever seen, which is exactly the shape of leak
/// this kind of table is prone to.
fn release_per_source(map: &DashMap<IpAddr, u32>, source: IpAddr) {
    // Never hold a shard guard across another operation on the same map — take
    // the decision inside this scope and act on it after the guard is dropped.
    let now_empty = {
        match map.get_mut(&source) {
            Some(mut entry) => {
                *entry = entry.saturating_sub(1);
                *entry == 0
            }
            // Unmetered (the ceiling is off) or already released.
            None => false,
        }
    };
    if now_empty {
        map.remove_if(&source, |_, count| *count == 0);
    }
}

/// Take one global slot. A zero ceiling still counts — the total is what the
/// active-connections gauge reports.
fn take_global(counter: &AtomicU32, limit: u32) -> bool {
    if limit == 0 {
        counter.fetch_add(1, Ordering::Relaxed);
        return true;
    }
    counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            (current < limit).then_some(current + 1)
        })
        .is_ok()
}

fn release_global(counter: &AtomicU32) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_sub(1))
    });
}

/// A held pair of connection slots. Dropping it gives back whatever is still
/// held, so no accept path can leak a slot by returning early.
pub struct AcceptPermit {
    /// `None` for a trusted source, or when no limiter is installed — nothing
    /// was taken, so nothing is given back.
    limiter: Option<Arc<ConnectionLimiter>>,
    source: IpAddr,
    handshake_held: bool,
    connection_held: bool,
}

// Hand-written so the permit can be `unwrap_err`'d in tests and logged, without
// dragging the whole limiter (two `DashMap`s) into a `Debug` impl.
impl std::fmt::Debug for AcceptPermit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AcceptPermit")
            .field("source", &self.source)
            .field("metered", &self.limiter.is_some())
            .field("handshake_held", &self.handshake_held)
            .field("connection_held", &self.connection_held)
            .finish()
    }
}

impl AcceptPermit {
    /// A permit that counts against nothing.
    fn unmetered(source: IpAddr) -> Self {
        Self {
            limiter: None,
            source,
            handshake_held: false,
            connection_held: false,
        }
    }

    /// Give back the handshake slot, keeping the established-connection slot.
    ///
    /// Call as soon as the connection is known to speak SIP — after the TLS
    /// handshake and the first-line sniff. Holding it for the connection's whole
    /// life would make the tight handshake ceiling behave like a second, much
    /// stricter connection ceiling. Idempotent.
    pub fn handshake_done(&mut self) {
        if !self.handshake_held {
            return;
        }
        self.handshake_held = false;
        if let Some(limiter) = &self.limiter {
            limiter.release_handshake(self.source);
        }
    }
}

impl Drop for AcceptPermit {
    fn drop(&mut self) {
        let Some(limiter) = &self.limiter else {
            return;
        };
        if self.handshake_held {
            limiter.release_handshake(self.source);
        }
        if self.connection_held {
            limiter.release_connection(self.source);
        }
    }
}

/// Count one connection refused by [`try_accept_connection`], labelled by the
/// ceiling that refused it.
///
/// Deliberately not an auto-ban signal. Hitting a concurrency ceiling is a
/// capacity fact, not proof of intent — a NAT whose UEs all re-register after a
/// network flap arrives exactly like a flood — and the ceiling has already done
/// the protective work by refusing the connection.
pub fn record_connection_refused(reason: RefusedReason) {
    if let Some(metrics) = crate::metrics::try_metrics() {
        metrics
            .connections_refused_total
            .with_label_values(&[reason.as_str()])
            .inc();
    }
}

/// Fixed-window failure counter for one source IP.
#[derive(Debug, Clone, Copy)]
struct FailureWindow {
    count: u32,
    window_start: Instant,
}

/// Per-source-IP auto-ban store. Cheap, lock-free reads (DashMap), `Send + Sync`,
/// shared as an `Arc` between the transport ACL, the auth path, and the dispatcher.
pub struct AutoBanStore {
    /// IP → current failure window.
    failures: DashMap<IpAddr, FailureWindow>,
    /// IP → ban expiry instant.
    bans: DashMap<IpAddr, Instant>,
    /// Sources that are never counted and never banned.
    trusted: Vec<IpNet>,
    threshold: u32,
    window: Duration,
    ban_duration: Duration,
    /// Failure weight applied by [`Self::record_strong_failure`] — how many
    /// counts a single high-confidence abuse signal (present-but-invalid
    /// credentials, forged/stale/replayed nonce, non-SIP garbage on a stream,
    /// scanner User-Agent) contributes toward `threshold`. A weight > 1 bans
    /// these unambiguous signals faster than a bare scanning probe (weight 1)
    /// while reusing the single per-IP window. Always ≥ 1.
    strong_weight: u32,
    /// Failure weight applied by [`Self::record_missing_credentials`] — a
    /// challenge issued because the request carried no credentials at all.
    ///
    /// **Zero by default, and that is deliberate.** RFC 3261 §22.2 makes the
    /// credential-less request the opening leg of challenge-response: every
    /// client sends one before it has a nonce, so counting it bans clients for
    /// behaving correctly. It fired in production — a subscriber address
    /// accrued five in one window and lost an hour — and behind CGNAT the blast
    /// radius is every subscriber sharing the address, none of whom did
    /// anything. The signal it was reaching for (a scanner that only ever
    /// probes) is covered better by `scanner_block`, `rate_limit`, apiban and
    /// the non-SIP/handshake signals, all of which a real client never trips.
    /// Set it to 1 to restore the old behaviour.
    missing_credentials_weight: u32,
    /// Optional kernel-firewall handle. When wired, every new ban is also
    /// pushed to the nf_tables set so the source is dropped pre-userspace.
    firewall: OnceLock<crate::firewall::KernelFirewall>,
}

impl AutoBanStore {
    /// Build a store from the `failed_auth_ban` policy and `trusted_cidrs`.
    /// Invalid CIDRs in `trusted_cidrs` are ignored (logged by the caller).
    pub fn new(
        threshold: u32,
        window_secs: u32,
        ban_duration_secs: u32,
        trusted_cidrs: &[String],
        strong_weight: u32,
        missing_credentials_weight: u32,
    ) -> Self {
        let trusted = trusted_cidrs
            .iter()
            .filter_map(|cidr| cidr.parse::<IpNet>().ok())
            .collect();
        let threshold = threshold.max(1);
        Self {
            failures: DashMap::new(),
            bans: DashMap::new(),
            trusted,
            // Guard against a zero policy disabling the feature by accident.
            threshold,
            window: Duration::from_secs(u64::from(window_secs.max(1))),
            ban_duration: Duration::from_secs(u64::from(ban_duration_secs.max(1))),
            strong_weight: strong_weight.max(1),
            // Zero is a meaningful value here (do not count it at all) and is
            // the default, so unlike the others this one is not clamped up.
            // Clamped down to the threshold only to keep it on the same scale
            // it is measured against; at exactly the threshold one
            // credential-less request bans, which is a policy an operator can
            // legitimately ask for.
            missing_credentials_weight: missing_credentials_weight.min(threshold),
            firewall: OnceLock::new(),
        }
    }

    /// Attach a kernel-firewall handle so new bans are also programmed into the
    /// nf_tables set. Called once at startup; a second call is a no-op.
    pub fn set_firewall(&self, firewall: crate::firewall::KernelFirewall) {
        let _ = self.firewall.set(firewall);
    }

    fn is_trusted(&self, source: IpAddr) -> bool {
        self.trusted.iter().any(|net| net.contains(&source))
    }

    /// Record one low-confidence failure for `source` (weight 1) — a signal that
    /// could occasionally fire for a benign peer: a non-ACK INVITE
    /// server-transaction timeout, a failed transport handshake, or a rejected
    /// credential over UDP (where the source is spoofable). Returns `true` if
    /// this call newly banned the IP (so the caller can log/metric the
    /// transition once).
    pub fn record_failure(&self, source: IpAddr) -> bool {
        self.record_failure_weighted_at(source, 1, Instant::now())
    }

    /// Record a challenge issued because the request carried no credentials,
    /// weighted by `missing_credentials_weight` (0 by default — see the field).
    ///
    /// At weight 0 this is a total no-op: it does not create a `failures` entry,
    /// so a scanner sweeping a /16 cannot grow the map one row per source IP
    /// through a signal that is not being acted on anyway. Returns `true` if
    /// this call newly banned the IP.
    pub fn record_missing_credentials(&self, source: IpAddr) -> bool {
        self.record_failure_weighted_at(source, self.missing_credentials_weight, Instant::now())
    }

    /// Record one high-confidence abuse signal for `source`, weighted by
    /// `strong_weight` so it bans faster than a bare probe: present-but-invalid
    /// credentials (wrong password), a forged/stale/replayed digest nonce,
    /// non-SIP garbage on a stream transport, or a scanner User-Agent. A
    /// legitimate client never produces these (a stale-nonce retry is reset by
    /// the subsequent [`Self::record_success`]). Returns `true` if this call
    /// newly banned the IP.
    pub fn record_strong_failure(&self, source: IpAddr) -> bool {
        self.record_failure_weighted_at(source, self.strong_weight, Instant::now())
    }

    fn record_failure_weighted_at(&self, source: IpAddr, weight: u32, now: Instant) -> bool {
        // A zero-weight signal is not counted at all — and specifically does not
        // touch `failures`, so a policy that declines to act on a signal also
        // declines to allocate a per-source row for it.
        if weight == 0 {
            return false;
        }
        if self.is_trusted(source) {
            return false;
        }
        if self.is_banned_at(source, now) {
            // Already banned — nothing to escalate.
            return false;
        }

        let newly_banned = {
            let mut entry = self.failures.entry(source).or_insert(FailureWindow {
                count: 0,
                window_start: now,
            });
            // Roll the window if it has elapsed.
            if now.duration_since(entry.window_start) > self.window {
                entry.count = 0;
                entry.window_start = now;
            }
            entry.count = entry.count.saturating_add(weight);
            entry.count >= self.threshold
            // `entry` (shard write guard) dropped here, before we touch `bans`
            // or `failures` again — never hold a DashMap guard across another
            // op on the same map.
        };

        if newly_banned {
            self.failures.remove(&source);
            self.bans.insert(source, now + self.ban_duration);
            // Mirror the ban into the kernel firewall (nf_tables) if wired, so
            // the source is dropped before it reaches siphon's socket. The
            // kernel element carries the same TTL as the in-memory ban, so both
            // expire in lockstep. Non-blocking (drops silently if the actor
            // queue is full — the userspace ACL still enforces the ban).
            if let Some(firewall) = self.firewall.get() {
                firewall.ban(source, self.ban_duration);
            }
        }
        newly_banned
    }

    /// Test-only weight-1 shim preserving the pre-weighting call shape.
    #[cfg(test)]
    fn record_failure_at(&self, source: IpAddr, now: Instant) -> bool {
        self.record_failure_weighted_at(source, 1, now)
    }

    /// A successful authentication from `source` clears its failure count.
    pub fn record_success(&self, source: IpAddr) {
        self.failures.remove(&source);
    }

    /// Whether `source` is currently banned. Trusted sources are never banned.
    /// Expired bans are lazily removed.
    pub fn is_banned(&self, source: IpAddr) -> bool {
        self.is_banned_at(source, Instant::now())
    }

    fn is_banned_at(&self, source: IpAddr, now: Instant) -> bool {
        if self.is_trusted(source) {
            return false;
        }
        // Copy the expiry out so we never hold the shard read guard across the
        // `remove()` below (would deadlock on the same shard).
        let expiry = self.bans.get(&source).map(|entry| *entry.value());
        match expiry {
            Some(exp) if exp > now => true,
            Some(_) => {
                self.bans.remove(&source);
                false
            }
            None => false,
        }
    }

    /// Number of currently-tracked bans (may include not-yet-pruned expired
    /// entries; published as a metric and pruned periodically).
    pub fn active_bans(&self) -> usize {
        self.bans.len()
    }

    /// Currently-banned sources with their remaining ban time in seconds
    /// (expired-but-not-yet-pruned entries are skipped). For the admin API's
    /// `GET /admin/bans`.
    pub fn banned_sources(&self) -> Vec<(IpAddr, u64)> {
        let now = Instant::now();
        self.bans
            .iter()
            .filter_map(|entry| {
                let remaining = entry.value().saturating_duration_since(now);
                if remaining.is_zero() {
                    None
                } else {
                    Some((*entry.key(), remaining.as_secs()))
                }
            })
            .collect()
    }

    /// Lift the ban on `source` early — an operator clearing a false positive
    /// (via the admin API). Removes the userspace ban and the failure window,
    /// and, when the kernel firewall is wired, removes the source from the
    /// nf_tables set too so the in-kernel drop is lifted in lockstep. Returns
    /// `true` if a ban was actually present.
    pub fn unban(&self, source: IpAddr) -> bool {
        let was_banned = self.bans.remove(&source).is_some();
        // Always clear any failure window so the source starts clean.
        self.failures.remove(&source);
        if was_banned {
            if let Some(firewall) = self.firewall.get() {
                firewall.unban(source);
            }
        }
        was_banned
    }

    /// Drop expired bans and stale failure windows. Call periodically to keep
    /// memory bounded under scanner churn.
    pub fn prune(&self) {
        self.prune_at(Instant::now());
    }

    fn prune_at(&self, now: Instant) {
        self.bans.retain(|_, expiry| *expiry > now);
        self.failures
            .retain(|_, window| now.duration_since(window.window_start) <= self.window);
    }
}

/// Verdict for one inbound request, returned by [`SecurityFilter::evaluate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityVerdict {
    /// Source is permitted — proceed to transaction/dialog/script processing.
    Allow,
    /// Source's `User-Agent` matched a `security.scanner_block` signature —
    /// drop silently (no response) so the server is not fingerprinted.
    Scanner,
    /// Source exceeded `security.rate_limit.max_requests` within the window (or
    /// is inside the resulting ban) — drop silently.
    RateLimited,
}

/// Fixed-window per-source-IP rate limiter with TTL bans. Replaces the Kamailio
/// PIKE module: once a source sends more than `max_requests` within `window`, it
/// is banned for `ban_duration` and every further request is dropped until the
/// ban expires.
struct RateLimitState {
    /// IP → current request-count window.
    windows: DashMap<IpAddr, FailureWindow>,
    /// IP → ban expiry instant.
    bans: DashMap<IpAddr, Instant>,
    max_requests: u32,
    window: Duration,
    ban_duration: Duration,
}

impl RateLimitState {
    /// Count one request from `source`. Returns `true` when the request is
    /// within the limit, `false` when the source is over the limit (and now
    /// banned) or already inside an active ban.
    fn check_at(&self, source: IpAddr, now: Instant) -> bool {
        // Active ban? (Copy the expiry out before any mutation so we never hold
        // a DashMap shard guard across a second op on the same map.)
        let ban_expiry = self.bans.get(&source).map(|entry| *entry.value());
        match ban_expiry {
            Some(expiry) if expiry > now => return false,
            Some(_) => {
                self.bans.remove(&source);
            }
            None => {}
        }

        let over_limit = {
            let mut entry = self.windows.entry(source).or_insert(FailureWindow {
                count: 0,
                window_start: now,
            });
            if now.duration_since(entry.window_start) > self.window {
                entry.count = 0;
                entry.window_start = now;
            }
            entry.count += 1;
            entry.count > self.max_requests
            // shard write guard dropped here, before touching `bans`/`windows`.
        };

        if over_limit {
            self.windows.remove(&source);
            self.bans.insert(source, now + self.ban_duration);
            return false;
        }
        true
    }

    fn active_bans(&self) -> usize {
        self.bans.len()
    }

    fn prune_at(&self, now: Instant) {
        self.bans.retain(|_, expiry| *expiry > now);
        self.windows
            .retain(|_, window| now.duration_since(window.window_start) <= self.window);
    }
}

/// Request-level security filter: per-source rate limiting (`rate_limit`) plus
/// scanner User-Agent blocking (`scanner_block`), both bypassed for
/// `trusted_cidrs`. Consulted by the dispatcher before any request processing.
///
/// The whole feature is opt-in: [`SecurityFilter::from_config`] returns `None`
/// unless at least one of `rate_limit` / `scanner_block` is configured.
pub struct SecurityFilter {
    /// Per-source rate limiter — `None` when `rate_limit` is not configured.
    rate_limit: Option<RateLimitState>,
    /// Lower-cased `User-Agent` substrings to block. Empty = scanner blocking off.
    scanner_user_agents: Vec<String>,
    /// Sources exempt from both rate limiting and scanner blocking (own
    /// infrastructure: AS, trunks, monitoring).
    trusted: Vec<IpNet>,
}

impl SecurityFilter {
    /// Build a filter from the `security` config block. Returns `None` when
    /// neither `rate_limit` nor `scanner_block` is set (feature is opt-in, so
    /// the dispatcher check is a no-op). Invalid `trusted_cidrs` are ignored.
    pub fn from_config(config: &crate::config::SecurityConfig) -> Option<Arc<Self>> {
        let rate_limit = config.rate_limit.as_ref().map(|policy| RateLimitState {
            windows: DashMap::new(),
            bans: DashMap::new(),
            // Guard against a zero policy permitting nothing / dividing by zero.
            max_requests: policy.max_requests.max(1),
            window: Duration::from_secs(u64::from(policy.window_secs.max(1))),
            ban_duration: Duration::from_secs(u64::from(policy.ban_duration_secs.max(1))),
        });

        let scanner_user_agents: Vec<String> = config
            .scanner_block
            .as_ref()
            .map(|block| {
                block
                    .user_agents
                    .iter()
                    .map(|agent| agent.to_lowercase())
                    .collect()
            })
            .unwrap_or_default();

        if rate_limit.is_none() && scanner_user_agents.is_empty() {
            return None;
        }

        let trusted = config
            .trusted_cidrs
            .iter()
            .filter_map(|cidr| cidr.parse::<IpNet>().ok())
            .collect();

        Some(Arc::new(Self {
            rate_limit,
            scanner_user_agents,
            trusted,
        }))
    }

    fn is_trusted(&self, source: IpAddr) -> bool {
        self.trusted.iter().any(|net| net.contains(&source))
    }

    /// Whether `user_agent` matches a configured scanner signature
    /// (case-insensitive substring — sipvicious advertises `friendly-scanner`).
    fn is_scanner(&self, user_agent: Option<&str>) -> bool {
        if self.scanner_user_agents.is_empty() {
            return false;
        }
        match user_agent {
            Some(agent) => {
                let agent = agent.to_lowercase();
                self.scanner_user_agents
                    .iter()
                    .any(|needle| agent.contains(needle))
            }
            None => false,
        }
    }

    /// Evaluate one inbound request from `source` carrying `user_agent`. Trusted
    /// sources always pass. Scanner blocking is checked before the rate limit so
    /// a flood of scanner traffic doesn't burn a rate-limit ban slot it doesn't
    /// need.
    pub fn evaluate(&self, source: IpAddr, user_agent: Option<&str>) -> SecurityVerdict {
        self.evaluate_at(source, user_agent, Instant::now())
    }

    fn evaluate_at(
        &self,
        source: IpAddr,
        user_agent: Option<&str>,
        now: Instant,
    ) -> SecurityVerdict {
        if self.is_trusted(source) {
            return SecurityVerdict::Allow;
        }
        if self.is_scanner(user_agent) {
            return SecurityVerdict::Scanner;
        }
        if let Some(ref rate) = self.rate_limit {
            if !rate.check_at(source, now) {
                return SecurityVerdict::RateLimited;
            }
        }
        SecurityVerdict::Allow
    }

    /// Drop expired rate-limit bans and stale windows. Call periodically to keep
    /// memory bounded under scanner churn. No-op when rate limiting is off.
    pub fn prune(&self) {
        if let Some(ref rate) = self.rate_limit {
            rate.prune_at(Instant::now());
        }
    }

    /// Number of currently-tracked rate-limit bans (0 when rate limiting is off).
    pub fn rate_limit_bans(&self) -> usize {
        self.rate_limit
            .as_ref()
            .map_or(0, RateLimitState::active_bans)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    #[test]
    fn bans_after_threshold_failures() {
        let store = AutoBanStore::new(3, 600, 3600, &[], 1, 0);
        let source = ip("203.0.113.7");
        assert!(!store.record_failure(source)); // 1
        assert!(!store.record_failure(source)); // 2
        assert!(!store.is_banned(source));
        assert!(store.record_failure(source)); // 3 -> ban, returns true
        assert!(store.is_banned(source));
        assert_eq!(store.active_bans(), 1);
    }

    #[test]
    fn success_resets_the_counter() {
        let store = AutoBanStore::new(3, 600, 3600, &[], 1, 0);
        let source = ip("203.0.113.8");
        store.record_failure(source);
        store.record_failure(source);
        store.record_success(source); // legit auth — wipe the count
        store.record_failure(source);
        store.record_failure(source);
        assert!(!store.is_banned(source)); // only 2 since reset
        assert!(store.record_failure(source)); // now 3 -> ban
    }

    #[test]
    fn trusted_cidr_never_banned() {
        let store = AutoBanStore::new(2, 600, 3600, &["10.0.0.0/8".to_string()], 1, 0);
        let source = ip("10.1.2.3");
        for _ in 0..10 {
            assert!(!store.record_failure(source));
        }
        assert!(!store.is_banned(source));
        assert_eq!(store.active_bans(), 0);
    }

    #[test]
    fn window_rolls_so_slow_failures_do_not_ban() {
        let store = AutoBanStore::new(3, 600, 3600, &[], 1, 0);
        let source = ip("203.0.113.9");
        let t0 = Instant::now();
        assert!(!store.record_failure_at(source, t0));
        assert!(!store.record_failure_at(source, t0 + Duration::from_secs(10)));
        // Past the window — counter rolls, so this is "1" again, not "3".
        assert!(!store.record_failure_at(source, t0 + Duration::from_secs(700)));
        assert!(!store.is_banned_at(source, t0 + Duration::from_secs(700)));
    }

    #[test]
    fn ban_expires_after_ttl() {
        let store = AutoBanStore::new(1, 600, 60, &[], 1, 0);
        let source = ip("203.0.113.10");
        let t0 = Instant::now();
        assert!(store.record_failure_at(source, t0)); // threshold 1 -> immediate ban
        assert!(store.is_banned_at(source, t0 + Duration::from_secs(30)));
        assert!(!store.is_banned_at(source, t0 + Duration::from_secs(61))); // expired
    }

    #[test]
    fn prune_drops_expired_entries() {
        let store = AutoBanStore::new(1, 600, 60, &[], 1, 0);
        let source = ip("203.0.113.11");
        let t0 = Instant::now();
        store.record_failure_at(source, t0);
        assert_eq!(store.active_bans(), 1);
        store.prune_at(t0 + Duration::from_secs(61));
        assert_eq!(store.active_bans(), 0);
    }

    #[test]
    fn already_banned_failure_is_noop() {
        let store = AutoBanStore::new(1, 600, 3600, &[], 1, 0);
        let source = ip("203.0.113.12");
        assert!(store.record_failure(source)); // ban
        assert!(!store.record_failure(source)); // already banned -> not "newly banned"
        assert!(store.is_banned(source));
    }

    #[test]
    fn unban_lifts_an_active_ban() {
        let store = AutoBanStore::new(1, 600, 3600, &[], 1, 0);
        let source = ip("203.0.113.40");
        assert!(store.record_failure(source)); // threshold 1 -> banned
        assert!(store.is_banned(source));
        assert!(store.unban(source)); // present -> true
        assert!(!store.is_banned(source)); // lifted
        assert_eq!(store.active_bans(), 0);
    }

    #[test]
    fn unban_of_an_unbanned_source_is_false() {
        let store = AutoBanStore::new(3, 600, 3600, &[], 1, 0);
        let source = ip("203.0.113.41");
        // Never banned -> nothing to lift.
        assert!(!store.unban(source));
        // A failure count without a ban is still cleared, and reports false.
        store.record_failure(source);
        assert!(!store.unban(source));
    }

    #[test]
    fn banned_sources_lists_active_bans_with_remaining() {
        let store = AutoBanStore::new(1, 600, 3600, &[], 1, 0);
        let one = ip("203.0.113.42");
        let two = ip("2001:db8::42");
        store.record_failure(one);
        store.record_failure(two);
        let mut listed = store.banned_sources();
        listed.sort_by_key(|(address, _)| address.to_string());
        assert_eq!(listed.len(), 2);
        // Both carry a positive remaining TTL (≤ the 3600 s ban duration).
        assert!(listed
            .iter()
            .all(|(_, remaining)| *remaining > 0 && *remaining <= 3600));
        assert!(listed.iter().any(|(address, _)| *address == one));
        assert!(listed.iter().any(|(address, _)| *address == two));
    }

    #[test]
    fn strong_failures_ban_faster_than_plain_probes() {
        // threshold 6, strong weight 3: two high-confidence signals (3+3=6) ban,
        // while a plain probe (weight 1) needs the full six hits.
        let store = AutoBanStore::new(6, 600, 3600, &[], 3, 0);

        let abuser = ip("203.0.113.30");
        assert!(!store.record_strong_failure(abuser)); // 3 < 6
        assert!(store.record_strong_failure(abuser)); // 6 -> ban
        assert!(store.is_banned(abuser));

        let prober = ip("203.0.113.31");
        for _ in 0..5 {
            assert!(!store.record_failure(prober)); // 1..=5 < 6
        }
        assert!(store.record_failure(prober)); // 6 -> ban
        assert!(store.is_banned(prober));
    }

    #[test]
    fn strong_weight_is_clamped_to_at_least_one() {
        // A misconfigured weight of 0 must not make strong signals free.
        let store = AutoBanStore::new(2, 600, 3600, &[], 0, 0);
        let source = ip("203.0.113.32");
        assert!(!store.record_strong_failure(source)); // 1
        assert!(store.record_strong_failure(source)); // 2 -> ban
    }

    /// The regression this default exists for. A client that keeps sending
    /// credential-less requests — a handset in a retry loop, a UA that never
    /// caches a nonce — is doing what RFC 3261 §22.2 tells it to, and it used to
    /// earn an hour-long ban on the fifth one. Behind CGNAT that address is
    /// shared, so the ban lands on every subscriber behind it.
    #[test]
    fn missing_credentials_do_not_ban_at_the_default_weight() {
        let store = AutoBanStore::new(5, 600, 3600, &[], 3, 0);
        let subscriber = ip("203.0.113.40");

        for _ in 0..50 {
            assert!(!store.record_missing_credentials(subscriber));
        }
        assert!(!store.is_banned(subscriber));

        // …and it leaves no per-source row behind, so a scanner sweeping a range
        // cannot grow the map through a signal nothing acts on.
        assert_eq!(store.failures.len(), 0);

        // A credential the backend actually rejected still bans, from the same
        // source, on the same store: switching the default off did not disarm
        // the signal that matters.
        assert!(!store.record_strong_failure(subscriber)); // 3 < 5
        assert!(store.record_strong_failure(subscriber)); // 6 -> ban
    }

    #[test]
    fn missing_credentials_weight_is_configurable_back_on() {
        // weight 1 restores the pre-1.7 behaviour: five in the window, ban.
        let store = AutoBanStore::new(5, 600, 3600, &[], 3, 1);
        let prober = ip("203.0.113.41");
        for _ in 0..4 {
            assert!(!store.record_missing_credentials(prober));
        }
        assert!(store.record_missing_credentials(prober));
        assert!(store.is_banned(prober));
    }

    #[test]
    fn missing_credentials_weight_is_clamped_to_the_threshold() {
        // An over-large value stays on the scale it is measured against rather
        // than saturating the counter in ways the window logic cannot reason
        // about. At exactly the threshold, one request bans — a policy an
        // operator can legitimately ask for.
        let store = AutoBanStore::new(3, 600, 3600, &[], 3, 99);
        let source = ip("203.0.113.42");
        assert!(store.record_missing_credentials(source));
        assert!(store.is_banned(source));
    }

    #[test]
    fn trusted_sources_are_exempt_from_missing_credential_counting() {
        let store = AutoBanStore::new(1, 600, 3600, &["203.0.113.0/24".to_string()], 3, 1);
        let trusted = ip("203.0.113.43");
        assert!(!store.record_missing_credentials(trusted));
        assert!(!store.is_banned(trusted));
    }

    // --- transport auto-ban signals (handshake failure, non-SIP bytes) -----
    //
    // This test owns the process-global AUTO_BAN OnceLock: no other test (and no
    // code outside server.rs startup) installs a store, so the install here is
    // deterministic within the lib test binary. It uses TEST-NET-2 addresses
    // (RFC 5737, 198.51.100.0/24) that no other test touches, so the lingering
    // global store cannot perturb the ACL/auth tests that share the binary.
    #[test]
    fn transport_abuse_signals_feed_the_auto_ban_store_and_acl() {
        // Before any store is installed, the helper must be a cheap no-op and
        // never panic — the whole feature is off until failed_auth_ban is set.
        let never = ip("198.51.100.78");
        crate::security::record_handshake_failure(never, "TLS");

        // Install a low-threshold store (3 weighted failures / 600 s window /
        // 1 h ban), with a strong signal weighted at the full threshold so the
        // two confidence levels are told apart below.
        //
        // Loopback is trusted, and that matters beyond this test: the store
        // installed here stays live for the rest of the binary, and the
        // transport tests drive real 127.0.0.1 sockets through paths that
        // report abuse signals (a non-SIP probe, a failed handshake). Without
        // this, one such test bans loopback and every socket test that runs
        // after it is refused at accept.
        let loopback = ["127.0.0.0/8".to_string(), "::1/128".to_string()];
        let store = Arc::new(AutoBanStore::new(3, 600, 3600, &loopback, 3, 0));
        set_auto_ban(Arc::clone(&store));

        // Handshake failures accumulate per-IP across transports and ban at the
        // threshold — exactly like the auth / INVITE-timeout signals.
        let scanner = ip("198.51.100.77");
        crate::security::record_handshake_failure(scanner, "TLS");
        crate::security::record_handshake_failure(scanner, "TLS");
        assert!(!store.is_banned(scanner)); // 2 < threshold
        crate::security::record_handshake_failure(scanner, "WSS"); // 3rd -> ban
        assert!(store.is_banned(scanner));

        // The pre-install no-op IP never accrued a count.
        assert!(!store.is_banned(never));

        // Non-SIP bytes on a stream transport are a *strong* signal: the source
        // completed a TCP handshake (so it is not spoofed) and then sent
        // something that cannot be SIP. One probe is enough at this weight,
        // where a handshake failure needed three.
        let prober = ip("198.51.100.79");
        crate::security::record_malformed_message(prober, "TLS");
        assert!(store.is_banned(prober));

        // End-to-end: the banned scanner is now dropped at transport accept by
        // the ACL (which consults the same global store), while an IP that never
        // failed a handshake still passes.
        let acl = crate::transport::acl::TransportAcl::new(vec![], vec![]);
        assert!(!acl.is_allowed(scanner));
        assert!(acl.is_allowed(never));
    }

    // --- SecurityFilter (rate_limit + scanner_block) -----------------------

    use crate::config::{RateLimitConfig, ScannerBlockConfig, SecurityConfig};

    fn security_config(
        rate_limit: Option<RateLimitConfig>,
        user_agents: Vec<&str>,
        trusted_cidrs: Vec<&str>,
    ) -> SecurityConfig {
        SecurityConfig {
            max_message_bytes: None,
            rate_limit,
            scanner_block: if user_agents.is_empty() {
                None
            } else {
                Some(ScannerBlockConfig {
                    user_agents: user_agents.into_iter().map(String::from).collect(),
                })
            },
            trusted_cidrs: trusted_cidrs.into_iter().map(String::from).collect(),
            failed_auth_ban: None,
            apiban: None,
            firewall: None,
            connection_limits: Default::default(),
        }
    }

    #[test]
    fn filter_opt_in_none_when_unconfigured() {
        // No rate_limit, no scanner_block -> feature stays off.
        let config = security_config(None, vec![], vec!["10.0.0.0/8"]);
        assert!(SecurityFilter::from_config(&config).is_none());
    }

    #[test]
    fn scanner_block_matches_case_insensitive_substring() {
        let config = security_config(None, vec!["sipvicious", "friendly-scanner"], vec![]);
        let filter = SecurityFilter::from_config(&config).unwrap();
        let source = ip("203.0.113.20");

        // Exact, mixed-case, and substring-within-larger-UA all match.
        assert_eq!(
            filter.evaluate(source, Some("friendly-scanner")),
            SecurityVerdict::Scanner
        );
        assert_eq!(
            filter.evaluate(source, Some("SIPVICIOUS")),
            SecurityVerdict::Scanner
        );
        assert_eq!(
            filter.evaluate(source, Some("Mozilla sipvicious/0.3.0")),
            SecurityVerdict::Scanner
        );
        // A legit UA and a missing UA both pass.
        assert_eq!(
            filter.evaluate(source, Some("Acme-SIP/1.0")),
            SecurityVerdict::Allow
        );
        assert_eq!(filter.evaluate(source, None), SecurityVerdict::Allow);
    }

    #[test]
    fn rate_limit_bans_after_max_requests() {
        let config = security_config(
            Some(RateLimitConfig {
                window_secs: 10,
                max_requests: 3,
                ban_duration_secs: 3600,
            }),
            vec![],
            vec![],
        );
        let filter = SecurityFilter::from_config(&config).unwrap();
        let source = ip("203.0.113.21");
        let t0 = Instant::now();

        // First 3 within the window pass.
        for _ in 0..3 {
            assert_eq!(filter.evaluate_at(source, None, t0), SecurityVerdict::Allow);
        }
        // 4th trips the limit -> banned.
        assert_eq!(
            filter.evaluate_at(source, None, t0),
            SecurityVerdict::RateLimited
        );
        assert_eq!(filter.rate_limit_bans(), 1);
        // Still banned a moment later (well inside ban_duration).
        assert_eq!(
            filter.evaluate_at(source, None, t0 + Duration::from_secs(5)),
            SecurityVerdict::RateLimited
        );
    }

    #[test]
    fn rate_limit_window_rolls() {
        let config = security_config(
            Some(RateLimitConfig {
                window_secs: 10,
                max_requests: 3,
                ban_duration_secs: 3600,
            }),
            vec![],
            vec![],
        );
        let filter = SecurityFilter::from_config(&config).unwrap();
        let source = ip("203.0.113.22");
        let t0 = Instant::now();

        for _ in 0..3 {
            assert_eq!(filter.evaluate_at(source, None, t0), SecurityVerdict::Allow);
        }
        // Past the window — counter rolls, so this is request #1 again, not #4.
        assert_eq!(
            filter.evaluate_at(source, None, t0 + Duration::from_secs(11)),
            SecurityVerdict::Allow
        );
        assert_eq!(filter.rate_limit_bans(), 0);
    }

    #[test]
    fn rate_limit_ban_expires() {
        let config = security_config(
            Some(RateLimitConfig {
                window_secs: 10,
                max_requests: 1,
                ban_duration_secs: 60,
            }),
            vec![],
            vec![],
        );
        let filter = SecurityFilter::from_config(&config).unwrap();
        let source = ip("203.0.113.23");
        let t0 = Instant::now();

        assert_eq!(filter.evaluate_at(source, None, t0), SecurityVerdict::Allow);
        assert_eq!(
            filter.evaluate_at(source, None, t0),
            SecurityVerdict::RateLimited
        );
        // After the ban TTL the source is allowed again.
        assert_eq!(
            filter.evaluate_at(source, None, t0 + Duration::from_secs(61)),
            SecurityVerdict::Allow
        );
    }

    #[test]
    fn trusted_cidr_bypasses_both_checks() {
        let config = security_config(
            Some(RateLimitConfig {
                window_secs: 10,
                max_requests: 1,
                ban_duration_secs: 3600,
            }),
            vec!["sipvicious"],
            vec!["10.0.0.0/8"],
        );
        let filter = SecurityFilter::from_config(&config).unwrap();
        let trusted = ip("10.1.2.3");
        let t0 = Instant::now();

        // Scanner UA from a trusted source is still allowed.
        assert_eq!(
            filter.evaluate_at(trusted, Some("sipvicious"), t0),
            SecurityVerdict::Allow
        );
        // And it never accrues a rate-limit ban no matter how many it sends.
        for _ in 0..50 {
            assert_eq!(
                filter.evaluate_at(trusted, None, t0),
                SecurityVerdict::Allow
            );
        }
        assert_eq!(filter.rate_limit_bans(), 0);
    }

    #[test]
    fn prune_drops_expired_rate_limit_bans() {
        let config = security_config(
            Some(RateLimitConfig {
                window_secs: 10,
                max_requests: 1,
                ban_duration_secs: 60,
            }),
            vec![],
            vec![],
        );
        let filter = SecurityFilter::from_config(&config).unwrap();
        let source = ip("203.0.113.24");
        let now = Instant::now();
        filter.evaluate_at(source, None, now);
        filter.evaluate_at(source, None, now); // ban
        assert_eq!(filter.rate_limit_bans(), 1);
        if let Some(ref rate) = filter.rate_limit {
            rate.prune_at(now + Duration::from_secs(61));
        }
        assert_eq!(filter.rate_limit_bans(), 0);
    }

    // --- connection limits (ConnectionLimiter) -----------------------------

    fn limits(
        max_handshakes_per_source: u32,
        max_handshakes: u32,
        max_connections_per_source: u32,
        max_connections: u32,
    ) -> ConnectionLimits {
        ConnectionLimits {
            max_handshakes_per_source,
            max_handshakes,
            max_connections_per_source,
            max_connections,
        }
    }

    /// The abuse this exists for: one source opening far more simultaneous
    /// connections than it could ever be doing legitimately, each one pinning a
    /// task for the whole handshake timeout. The auto-ban cannot help — it needs
    /// completed failures first, and these never complete.
    #[test]
    fn a_source_cannot_hold_more_handshakes_than_its_ceiling() {
        let limiter = Arc::new(ConnectionLimiter::new(limits(3, 0, 0, 0), &[]));
        let flood = ip("203.0.113.50");

        let held: Vec<_> = (0..3)
            .map(|_| limiter.try_accept(flood).expect("under the ceiling"))
            .collect();
        assert_eq!(
            limiter.try_accept(flood).unwrap_err(),
            RefusedReason::HandshakesPerSource
        );

        // A different source is unaffected — the ceiling is per source, so one
        // abuser cannot deny service to everyone else.
        let bystander = limiter.try_accept(ip("203.0.113.51"));
        assert!(bystander.is_ok());

        drop(held);
        assert!(limiter.try_accept(flood).is_ok(), "slots come back");
    }

    #[test]
    fn established_connections_have_their_own_per_source_ceiling() {
        let limiter = Arc::new(ConnectionLimiter::new(limits(0, 0, 2, 0), &[]));
        let source = ip("203.0.113.52");

        let mut first = limiter.try_accept(source).unwrap();
        let mut second = limiter.try_accept(source).unwrap();
        // Finishing the handshakes must NOT free the connection slots, or the
        // established ceiling would only ever bound connections mid-handshake.
        first.handshake_done();
        second.handshake_done();

        assert_eq!(
            limiter.try_accept(source).unwrap_err(),
            RefusedReason::ConnectionsPerSource
        );
        drop(first);
        assert!(limiter.try_accept(source).is_ok());
    }

    /// The per-source ceilings say nothing about how many sources there are, so
    /// a distributed flood needs the global ones.
    #[test]
    fn global_ceilings_bound_a_distributed_flood() {
        let limiter = Arc::new(ConnectionLimiter::new(limits(0, 2, 0, 0), &[]));
        let _one = limiter.try_accept(ip("203.0.113.60")).unwrap();
        let _two = limiter.try_accept(ip("203.0.113.61")).unwrap();
        assert_eq!(
            limiter.try_accept(ip("203.0.113.62")).unwrap_err(),
            RefusedReason::Handshakes
        );

        let limiter = Arc::new(ConnectionLimiter::new(limits(0, 0, 0, 1), &[]));
        let _held = limiter.try_accept(ip("203.0.113.63")).unwrap();
        assert_eq!(
            limiter.try_accept(ip("203.0.113.64")).unwrap_err(),
            RefusedReason::Connections
        );
    }

    /// `handshake_done` releases the tight ceiling and keeps the loose one.
    /// Without that split, a 32-handshake ceiling would silently behave as a
    /// 32-connection ceiling and cut off any busy NAT.
    #[test]
    fn handshake_done_releases_only_the_handshake_half() {
        let limiter = Arc::new(ConnectionLimiter::new(limits(1, 0, 4, 0), &[]));
        let source = ip("203.0.113.70");

        let mut first = limiter.try_accept(source).unwrap();
        assert_eq!(
            limiter.try_accept(source).unwrap_err(),
            RefusedReason::HandshakesPerSource
        );

        first.handshake_done();
        let _second = limiter
            .try_accept(source)
            .expect("the handshake slot was returned");

        // Idempotent: a second call must not double-release into an underflow
        // that hands out free slots forever.
        first.handshake_done();
        first.handshake_done();
        assert_eq!(
            limiter.try_accept(source).unwrap_err(),
            RefusedReason::HandshakesPerSource,
            "the second connection still holds the only handshake slot"
        );
    }

    /// Trunks and monitoring must never be refused: an outage caused by our own
    /// ceiling on a carrier interconnect is worse than anything it prevents.
    #[test]
    fn trusted_sources_are_never_refused() {
        let limiter = Arc::new(ConnectionLimiter::new(
            limits(1, 1, 1, 1),
            &["198.51.100.0/24".to_string()],
        ));
        let trunk = ip("198.51.100.7");
        let held: Vec<_> = (0..64)
            .map(|_| limiter.try_accept(trunk).expect("trusted is exempt"))
            .collect();
        assert_eq!(held.len(), 64);
        // And an exempt source consumes none of the global budget that protects
        // everyone else.
        assert!(limiter.try_accept(ip("203.0.113.80")).is_ok());
    }

    /// A disabled ceiling must cost nothing — in particular it must not keep a
    /// row per source that has ever connected.
    #[test]
    fn zero_means_unlimited_and_tracks_no_per_source_state() {
        let limiter = Arc::new(ConnectionLimiter::new(limits(0, 0, 0, 0), &[]));
        let held: Vec<_> = (0..1000)
            .map(|index| {
                limiter
                    .try_accept(ip(&format!("203.0.113.{}", index % 250)))
                    .expect("unlimited")
            })
            .collect();
        assert_eq!(limiter.tracked_sources(), (0, 0));
        drop(held);
    }

    /// Steady-state allocation check for the two per-source maps: they are
    /// keyed by a live entity, so a row that outlives its connection is a leak
    /// that grows with every source ever seen. Drives complete accept/release
    /// cycles and asserts both maps return to their starting size.
    #[test]
    fn per_source_maps_drain_to_baseline_after_complete_cycles() {
        let limiter = Arc::new(ConnectionLimiter::new(limits(8, 0, 8, 0), &[]));
        assert_eq!(limiter.tracked_sources(), (0, 0));

        for round in 0..200u32 {
            // A fresh source each round is the shape that leaks: a scanner
            // sweeping a range, or ordinary churn across a subscriber base.
            let source = ip(&format!("198.51.100.{}", round % 250));
            let mut permit = limiter.try_accept(source).unwrap();
            permit.handshake_done();
            drop(permit);
        }

        assert_eq!(
            limiter.tracked_sources(),
            (0, 0),
            "every source that finished must leave no row behind"
        );
    }

    #[test]
    fn concurrent_accepts_never_exceed_the_ceiling() {
        use std::sync::atomic::AtomicUsize;
        use std::thread;

        const CEILING: u32 = 16;
        let limiter = Arc::new(ConnectionLimiter::new(limits(0, 0, CEILING, 0), &[]));
        let source = ip("203.0.113.90");
        let granted = Arc::new(AtomicUsize::new(0));

        // Every thread takes a slot and holds it, so the ceiling has to be
        // enforced across threads, not merely within one.
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let limiter = Arc::clone(&limiter);
                let granted = Arc::clone(&granted);
                thread::spawn(move || {
                    let mut held = Vec::new();
                    for _ in 0..32 {
                        if let Ok(permit) = limiter.try_accept(source) {
                            granted.fetch_add(1, Ordering::Relaxed);
                            held.push(permit);
                        }
                    }
                    held
                })
            })
            .collect();

        let held: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert_eq!(
            granted.load(Ordering::Relaxed),
            CEILING as usize,
            "the ceiling must hold under contention, with no lost or double counts"
        );

        drop(held);
        assert_eq!(limiter.tracked_sources(), (0, 0));
        assert!(limiter.try_accept(source).is_ok());
    }

    #[test]
    fn refused_reason_labels_are_stable() {
        // These are metric label values; renaming one silently breaks a
        // dashboard or an alert rule.
        assert_eq!(
            RefusedReason::HandshakesPerSource.as_str(),
            "handshakes_per_source"
        );
        assert_eq!(RefusedReason::Handshakes.as_str(), "handshakes");
        assert_eq!(
            RefusedReason::ConnectionsPerSource.as_str(),
            "connections_per_source"
        );
        assert_eq!(RefusedReason::Connections.as_str(), "connections");
    }

    #[test]
    fn default_ceilings_are_the_documented_ones() {
        let defaults = ConnectionLimits::default();
        assert_eq!(defaults.max_handshakes_per_source, 32);
        assert_eq!(defaults.max_handshakes, 1024);
        assert_eq!(defaults.max_connections_per_source, 256);
        assert_eq!(defaults.max_connections, 16_384);
    }
}
