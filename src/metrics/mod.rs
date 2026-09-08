//! Prometheus metrics for SIPhon.
//!
//! Exposes counters, histograms, and gauges for SIP traffic, transactions,
//! registrations, dialogs, and transport connections. Metrics are collected
//! inline (at the call site) and scraped via the HTTP admin API `/metrics`.

pub mod custom;
pub mod glibc;

use std::sync::{Arc, OnceLock};

use prometheus::{
    Encoder, Gauge, GaugeVec, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge,
    IntGaugeVec, Opts, Registry, TextEncoder,
};
use tracing::error;

use self::custom::CustomMetrics;

/// Global metrics registry — initialized once at startup.
static METRICS: OnceLock<SiphonMetrics> = OnceLock::new();

/// Custom metrics registered by Python scripts.
static CUSTOM_METRICS: OnceLock<Arc<CustomMetrics>> = OnceLock::new();

/// When metrics were initialised, i.e. process start for uptime purposes.
///
/// Kept here rather than threaded through the dispatcher because both the 30 s
/// sweep and the admin snapshot publish uptime, and a second source of truth is
/// how the gauge ended up reading zero forever in the first place.
static STARTED_AT: OnceLock<std::time::Instant> = OnceLock::new();

/// Access the global metrics instance. Returns `None` if not initialized.
pub fn metrics() -> Option<&'static SiphonMetrics> {
    METRICS.get()
}

/// Try to access the global metrics (returns None before init).
/// Alias for `metrics()`.
pub fn try_metrics() -> Option<&'static SiphonMetrics> {
    METRICS.get()
}

/// Initialize the global metrics. Call once at startup.
/// Returns an error if metric creation fails (should never happen with
/// valid hardcoded metric names — indicates a bug if it does).
pub fn init() -> Result<(), prometheus::Error> {
    if METRICS.get().is_some() {
        return Ok(());
    }
    let _ = STARTED_AT.set(std::time::Instant::now());
    let metrics = SiphonMetrics::new()?;
    let custom = Arc::new(CustomMetrics::new(&metrics.registry));
    let _ = CUSTOM_METRICS.set(custom);
    let _ = METRICS.set(metrics);
    Ok(())
}

/// Access the custom metrics store (for script-defined metrics).
/// Returns `None` before `init()` is called.
pub fn custom_metrics() -> Option<&'static Arc<CustomMetrics>> {
    CUSTOM_METRICS.get()
}

/// Which way a SIP message crossed the wire, as the `direction` label on
/// [`SiphonMetrics::record_request`] / [`SiphonMetrics::record_response`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// Received from a peer.
    In,
    /// Sent to a peer.
    Out,
}

impl Direction {
    pub fn as_str(self) -> &'static str {
        match self {
            Direction::In => "in",
            Direction::Out => "out",
        }
    }

    const fn index(self) -> usize {
        match self {
            Direction::In => 0,
            Direction::Out => 1,
        }
    }
}

/// Label values for the `method` dimension of `siphon_requests_total`, in the
/// order [`method_index`] maps to.
///
/// `Method::Extension(_)` collapses into the single `OTHER` bucket rather than
/// passing the token through. The method is read straight off the request line,
/// so a peer that sends `FOO1 sip:… SIP/2.0`, `FOO2 …`, … would otherwise mint
/// an unbounded number of Prometheus series through the scrape endpoint — a
/// cardinality DoS on the monitoring stack rather than on siphon itself.
pub const METHOD_LABELS: [&str; 15] = [
    "INVITE",
    "ACK",
    "BYE",
    "CANCEL",
    "OPTIONS",
    "REGISTER",
    "INFO",
    "UPDATE",
    "PRACK",
    "SUBSCRIBE",
    "NOTIFY",
    "REFER",
    "MESSAGE",
    "PUBLISH",
    "OTHER",
];

/// Label values for the `class` dimension of `siphon_responses_total`.
pub const CLASS_LABELS: [&str; 6] = ["1xx", "2xx", "3xx", "4xx", "5xx", "6xx"];

/// Index into [`METHOD_LABELS`] for a parsed method.
fn method_index(method: &crate::sip::message::Method) -> usize {
    use crate::sip::message::Method;
    match method {
        Method::Invite => 0,
        Method::Ack => 1,
        Method::Bye => 2,
        Method::Cancel => 3,
        Method::Options => 4,
        Method::Register => 5,
        Method::Info => 6,
        Method::Update => 7,
        Method::Prack => 8,
        Method::Subscribe => 9,
        Method::Notify => 10,
        Method::Refer => 11,
        Method::Message => 12,
        Method::Publish => 13,
        Method::Extension(_) => 14,
    }
}

/// Index into [`CLASS_LABELS`] for a status code. Anything outside 100–699 is
/// clamped into the nearest real class rather than dropped, so a malformed
/// status line still lands somewhere countable.
fn class_index(status_code: u16) -> usize {
    ((status_code / 100).clamp(1, 6) - 1) as usize
}

/// What an already-serialized SIP frame turned out to be.
enum Frame {
    /// Index into [`METHOD_LABELS`].
    Request(usize),
    Response(u16),
}

/// Classify a serialized SIP frame from its start line alone.
///
/// The outbound counting point sits below serialization (it is the only place
/// *everything* siphon emits passes through — relayed requests, UAC keepalives
/// and outbound REGISTERs never touch the typed reply helpers), so the kind has
/// to be recovered from the bytes. This reads the start line only: no parse, no
/// allocation, no copy.
///
/// Returns `None` for anything that is not a SIP start line, which is how
/// double-CRLF keepalives stay out of the counters.
fn classify_frame(data: &[u8]) -> Option<Frame> {
    // Response: "SIP/2.0 <code> <reason>". Only siphon's own serializer feeds
    // this path, so the version token is always canonical.
    if let Some(rest) = data.strip_prefix(b"SIP/2.0 ") {
        let digits = rest.get(..3)?;
        if !digits.iter().all(u8::is_ascii_digit) {
            return None;
        }
        let code = u16::from(digits[0] - b'0') * 100
            + u16::from(digits[1] - b'0') * 10
            + u16::from(digits[2] - b'0');
        return Some(Frame::Response(code));
    }

    // Request: "<METHOD> <request-uri> SIP/2.0". Method names are case-sensitive
    // (RFC 3261 §7.1) and we emit them canonically, so an exact byte match is
    // correct. Anything unrecognised (including a genuinely empty token) lands
    // in OTHER rather than minting a series.
    let end = data.iter().position(|&byte| byte == b' ')?;
    let token = data.get(..end)?;
    if token.is_empty() {
        return None;
    }
    let index = METHOD_LABELS
        .iter()
        .position(|label| label.as_bytes() == token)
        .unwrap_or(METHOD_LABELS.len() - 1);
    Some(Frame::Request(index))
}

/// All SIPhon metrics in one struct for easy access.
pub struct SiphonMetrics {
    pub registry: Registry,

    // --- Request counters ---
    pub requests_total: IntCounterVec,
    pub responses_total: IntCounterVec,

    /// Pre-resolved children of `requests_total`, indexed by
    /// `method_index(m) * 2 + direction.index()`.
    ///
    /// These exist because this is the only per-SIP-message counter in the
    /// process. `IntCounterVec::with_label_values` takes an `RwLock` read and
    /// hashes the label slice on every call; at 30k cps that is 60k lock+hash
    /// per second on the hot path for a value that can be an array index. Every
    /// child is materialised at startup, so each series is also present (as a
    /// zero) from the first scrape — `rate()` works immediately instead of
    /// returning "no data" until the first message of that kind arrives.
    requests_by_method: [IntCounter; METHOD_LABELS.len() * 2],

    /// Pre-resolved children of `responses_total`, indexed by
    /// `class_index(code) * 2 + direction.index()`. Same rationale as
    /// [`Self::requests_by_method`].
    responses_by_class: [IntCounter; CLASS_LABELS.len() * 2],

    // --- Transaction gauges ---
    pub transactions_active: IntGauge,

    /// In-flight UAC requests (NAT keepalive / health probe) awaiting a
    /// response.  Climbs without bound if pending entries are not swept —
    /// watch this to confirm the sweep is keeping the `UacSender` map drained.
    pub uac_pending_requests: IntGauge,

    /// Live proxy dialog-key entries (one per INVITE awaiting/within its 2xx
    /// ACK window).  Returns to ~0 when call setup is idle; a monotonic climb
    /// means completed-call dialog keys are leaking (`by_dialog_key`).
    pub proxy_dialog_sessions: IntGauge,

    /// Live `cdr.auto_emit` per-call tracking entries (INVITE → answer → BYE).
    /// Returns to ~0 when calls are idle; a monotonic climb under a steady,
    /// completed-call workload means a call teardown hook isn't draining the
    /// `cdr_sessions` store. Zero when `cdr.auto_emit` is off.
    pub cdr_sessions: IntGauge,

    /// Live Rf offline-charging accounting sessions (ACR-START without a
    /// matching ACR-STOP). Returns to ~0 when calls are idle; a monotonic climb
    /// under a steady, completed-call workload means an ACR-STOP hook (or the
    /// interim-timer max-lifetime backstop) isn't draining the session table.
    /// Zero when `rf.enabled` is off.
    pub rf_sessions: IntGauge,

    /// Live Ro online-charging sessions (CCR-INITIAL without a matching
    /// CCR-TERMINATION). A monotonic climb under a steady, completed-call
    /// workload means a call teardown hook isn't draining the credit sessions.
    /// Zero when `ro.enabled` is off.
    pub ro_sessions: IntGauge,

    /// Sessions with a remembered lawful-intercept matching decision.
    ///
    /// The dispatcher decides once per session rather than per message, and
    /// keys that on the Call-ID — which the peer chooses. This is what makes
    /// the bound observable: it must track live dialogs and fall back, never
    /// climb monotonically. Pinned at the cap means the map is being cleared
    /// repeatedly, which is the signature of a Call-ID flood.
    pub li_remembered_sessions: IntGauge,

    /// Live SUBSCRIBE dialogs in the L1 `subscribe_state` store.  A monotonic
    /// climb under a steady subscribe/expire workload means expired dialogs
    /// are leaking (L1 has no TTL; the sweep reaps them).
    pub subscribe_dialogs: IntGauge,

    /// Live P-CSCF IPsec SA pairs in the `IpsecManager` (one per registered
    /// UE binding; each backs 4 XFRM states + 4 policies).  A monotonic climb
    /// under a steady REGISTER/expire workload means abandoned-UE SAs are
    /// leaking — the sweep reaps them on their own hard-lifetime + grace.
    pub ipsec_sa_pairs: IntGauge,

    // --- Registration gauges ---
    pub registrations_active: IntGauge,

    // --- Dialog gauges ---
    /// Active SIP dialogs, defined as `proxy_dialog_sessions + b2bua_calls_active`.
    ///
    /// A single number here conflates two unrelated things — a proxy retains a
    /// dialog-key entry per answered call it routed, while a B2BUA owns a
    /// `CallActor` per bridged call — so prefer the two component gauges when
    /// you care which side the load is on. This stays as the rolled-up total.
    pub dialogs_active: IntGauge,

    /// Active B2BUA calls (`CallActorStore::count()`) — the B2BUA half of
    /// `dialogs_active`.
    pub b2bua_calls_active: IntGauge,

    // --- Connection gauges ---
    /// Live inbound connections per stream transport (`TCP`/`TLS`/`WS`/`WSS`/`SCTP`).
    ///
    /// UDP is deliberately absent rather than reported as zero: it is
    /// connectionless, so there is no connection to count, and a zero here would
    /// read as "no UDP traffic" instead of "not a meaningful question".
    pub connections_active: GaugeVec,

    // --- Uptime ---
    pub uptime_seconds: Gauge,

    // --- Memory (jemalloc stats — the precise leak signal) ---
    /// Live bytes allocated by the application (`jemalloc stats.allocated`).
    /// Steady growth under constant load is a real leak — unlike RSS, this
    /// excludes allocator retention/fragmentation.  Alert on this.
    pub memory_allocated_bytes: IntGauge,
    /// Physical pages backing the allocator (`stats.resident`) — RSS-like.
    pub memory_resident_bytes: IntGauge,
    /// Bytes in active pages (`stats.active`).
    pub memory_active_bytes: IntGauge,
    /// Virtual memory retained by the allocator, not returned to the OS
    /// (`stats.retained`).  Explains RSS sitting above `allocated`.
    pub memory_retained_bytes: IntGauge,
    /// Total mapped bytes (`stats.mapped`).
    pub memory_mapped_bytes: IntGauge,
    /// Allocator bookkeeping — arena headers, extent structures, bin metadata
    /// (`stats.metadata`).  Scales with arena count, which jemalloc defaults to
    /// `4 x ncpus`, so on a many-core box this is the part of RSS that is
    /// neither live data nor retained pages and is the one to read before
    /// reaching for `narenas`.
    pub memory_metadata_bytes: IntGauge,
    /// Currently-allocated CPython memory blocks (`sys.getallocatedblocks()`).
    /// Python objects use CPython's own allocator (mimalloc on free-threaded
    /// builds), NOT jemalloc — so this is the leak signal for the *Python* side
    /// (script globals, leaked `Py<>` references) that `memory_allocated_bytes`
    /// cannot see. Steady growth at a flat, completed-call workload is a leak.
    pub python_allocated_blocks: IntGauge,

    // --- Script execution ---
    /// Python handler invocations that raised. Incremented by
    /// `dispatcher::record_script_error` alongside the `error!` log, so the
    /// counter and the logs cannot disagree.
    ///
    /// There is deliberately no matching `script_executions_total`: handler
    /// volume is already covered by `pyexec_jobs_completed_total`, and a
    /// per-handler labelled counter would put a label-map lookup on the
    /// request path to say the same thing.
    pub script_errors_total: IntCounter,

    // --- Synchronous Python executor pool (handler dispatch) ---
    /// Live worker-thread count of the synchronous Python executor pool. The
    /// pool is elastic: this grows from the core size toward `pyexec_pool_max`
    /// under load and never shrinks. Saturation = `pyexec_inflight == pyexec_pool_size`.
    pub pyexec_pool_size: IntGauge,
    /// Configured hard ceiling on executor worker threads. When `pyexec_pool_size`
    /// reaches this and stays saturated, the pool can no longer absorb more
    /// blocking handlers — the watchdog's abort condition.
    pub pyexec_pool_max: IntGauge,
    /// Handler jobs currently executing on a pool worker. Pinned at
    /// `pyexec_pool_size` means the pool is fully saturated — every worker is
    /// busy and new work is queueing. Sampled by the pool watchdog.
    pub pyexec_inflight: IntGauge,
    /// Handler jobs waiting in the pool's bounded queue. A sustained climb means
    /// handlers are not draining fast enough (blocking I/O, a wedged backend).
    /// Sampled by the pool watchdog.
    pub pyexec_queue_depth: IntGauge,
    /// Handler jobs completed by the pool. With `pyexec_inflight` pinned at the
    /// pool size, a flat `completed` rate is the precise signal that the pool
    /// has wedged (zero forward progress) — what the watchdog aborts on.
    pub pyexec_jobs_completed_total: IntCounter,
    /// Handler jobs shed because the pool's bounded queue was full (load-shed
    /// under overload). Non-zero means inbound work was dropped; the SIP client
    /// retransmits. Alert on a sustained rate.
    pub pyexec_jobs_shed_total: IntCounter,

    // --- Auth (HTTP backend) ---
    /// HTTP-auth credential lookups served from the in-process HA1 cache
    /// instead of a blocking backend fetch (`auth.http.cache_ttl_secs`). A high
    /// hit ratio is what keeps a registration storm from translating 1:1 into
    /// blocking HTTP on the executor pool.
    pub auth_ha1_cache_hits_total: IntCounter,

    // --- Security / abuse (failed_auth_ban scanner protection) ---
    /// Source IPs currently auto-banned. Pruned periodically; trusted_cidrs are
    /// never counted. Alert on a sustained rise to spot a scanning campaign.
    pub banned_ips: IntGauge,
    /// Total challenges issued because the request carried no credentials — the
    /// RFC 3261 §22.2 opening leg of challenge-response. Counted for visibility
    /// whether or not `failed_auth_ban.missing_credentials_weight` acts on it
    /// (it is 0 by default), so a scanning campaign is still measurable.
    pub auth_failures_total: IntCounter,
    /// Total TLS/WSS/WS handshakes that failed or timed out before completing,
    /// each recorded toward the auto-ban. These are TCP-validated source IPs
    /// (no spoofing), so a sustained rise is an unambiguous scanning campaign.
    pub handshake_failures_total: IntCounter,
    /// Total digest attempts carrying present-but-invalid credentials (wrong
    /// password), a username the backend denied, or a forged/stale/replayed
    /// nonce, each recorded toward the auto-ban as a high-confidence signal.
    /// Distinct from `auth_failures_total` (credential-less first legs) and from
    /// `auth_backend_errors_total` (the backend never answered).
    pub credential_failures_total: IntCounter,
    /// Total credential checks that could not be decided because the credential
    /// source did not answer — HTTP auth backend timeout / connection failure,
    /// or no usable backend configured. Never counted toward the auto-ban: an
    /// outage of our own backend is not evidence about the peer, and treating it
    /// as one banned real subscribers two REGISTER retries into an outage.
    ///
    /// **Alert on this.** A non-zero rate means authentication is failing open
    /// into 401s for everyone, and it is otherwise invisible — it used to be
    /// indistinguishable from a password brute-force.
    pub auth_backend_errors_total: IntCounter,
    /// Total non-SIP / unparseable messages received on a stream transport
    /// (TCP/TLS) and dropped, each recorded toward the auto-ban. Excludes
    /// incomplete-but-plausible frames, empty connections, and CRLF keepalives.
    pub malformed_messages_total: IntCounter,
    /// Inbound stream connections refused by `security.connection_limits`,
    /// labelled by which ceiling refused them (`handshakes_per_source`,
    /// `handshakes`, `connections_per_source`, `connections`).
    ///
    /// A rising `connections_per_source` is the one to read carefully: it can
    /// equally mean one source is misbehaving or that a carrier NAT legitimately
    /// fronts more registrations than the ceiling allows. `handshakes` rising is
    /// unambiguous — the box is at its concurrent-handshake ceiling.
    pub connections_refused_total: IntCounterVec,
    /// Inbound stream connections currently established across all sources.
    pub stream_connections_active: IntGauge,
    /// Inbound handshakes (TLS/WS) plus first-line sniffs currently in flight.
    /// Sits near zero on a healthy edge; a sustained non-zero value is a flood.
    pub handshakes_in_flight: IntGauge,
    /// Total inbound requests whose topmost Via carried no `branch` parameter,
    /// so no server transaction could be keyed for them (RFC 3261 §8.1.1.7
    /// makes it mandatory). siphon has no RFC 2543 legacy matching, so these
    /// are processed statelessly: their retransmissions are not absorbed and
    /// each one runs the script again. A non-zero rate means a legacy or
    /// broken peer is on the network.
    pub requests_without_branch_total: IntCounter,
    /// Total inbound UDP datagrams that exactly filled the receive buffer, so
    /// the kernel may have discarded a tail siphon will never see. RFC 3261
    /// §18.1.1 requires a UAC to switch to a congestion-controlled transport
    /// well before this size, so a non-zero value means a peer is sending
    /// oversized UDP — the messages are still processed, and a truncated one is
    /// then refused by the parser's Content-Length check rather than acted on.
    pub udp_datagrams_at_buffer_limit_total: IntCounter,
    /// Total inbound requests dropped because the source's User-Agent matched a
    /// `security.scanner_block` signature (sipvicious, friendly-scanner, …).
    pub scanner_blocked_total: IntCounter,
    /// Total inbound requests dropped because the source exceeded
    /// `security.rate_limit.max_requests` within the window (PIKE-style flood
    /// protection). trusted_cidrs are never counted.
    pub rate_limited_total: IntCounter,
    /// Total kernel-firewall (nf_tables) commands dropped before reaching the
    /// netlink actor because its queue was full — only plausible under a ban
    /// storm. The userspace ACL still enforces the dropped ban; a sustained
    /// rate means kernel enforcement is lagging the ban rate.
    pub firewall_commands_dropped_total: IntCounter,
    /// Total kernel-firewall (nf_tables) netlink commands that failed. Any
    /// non-zero rate means bans are NOT being enforced in the kernel (ruleset
    /// deleted out from under siphon, capability lost, nf_tables broken) —
    /// alert on it; the userspace ACL is the only enforcement left.
    pub firewall_command_failures_total: IntCounter,

    // --- Diameter ---
    pub diameter_peers_connected: IntGauge,
    pub diameter_requests_total: IntCounterVec,
    pub diameter_request_errors_total: IntCounterVec,
    pub diameter_request_duration_seconds: HistogramVec,
    pub diameter_watchdog_failures_total: IntCounter,

    // --- RTPEngine health ---
    pub rtpengine_instances_up: IntGauge,
    pub rtpengine_instances_total: IntGauge,
    pub rtpengine_instance_up: IntGaugeVec,

    // --- SBI (5G N5/Npcf) ---
    /// Active N5/Npcf app-sessions this NF created and has not yet deleted. A
    /// steady climb under flat call rate is a session leak (a missed
    /// delete_session — e.g. the early-media Rx/N5 session stranded at the PCF).
    pub sbi_npcf_app_sessions_active: IntGauge,

    // --- glibc allocator (C-side / CPython raw domain) ---
    // The pool jemalloc and CPython's mimalloc cannot see. Sourced from
    // `malloc_info(3)` (all arenas), not `mallinfo2` (main arena only).
    /// Total OS memory held by glibc malloc across all arenas (non-mmap). The
    /// resident "dark pool"; where free-threaded-CPython per-thread 64 MB
    /// arenas show up. The C-side analogue of `siphon_memory_resident_bytes`.
    pub glibc_system_bytes: IntGauge,
    /// Live (allocated, not freed) C-side bytes = system − free. A steady climb
    /// here under flat load is a genuine raw-domain leak — the alert signal.
    pub glibc_in_use_bytes: IntGauge,
    /// Free/retained bytes inside the arenas. High free + high system + flat
    /// in_use = arena retention (tune arena_max / malloc_trim), not a leak.
    pub glibc_free_bytes: IntGauge,
    /// Bytes served by mmap (large allocations), separate from the arenas.
    pub glibc_mmap_bytes: IntGauge,
    /// Number of arenas (heaps). Each is a ~64 MB reservation; a rising count
    /// is per-thread-arena proliferation under free-threaded concurrency.
    pub glibc_arena_count: IntGauge,

    // --- External remote-control plane ---
    /// Live control-plane connections per app (drains to 0 on disconnect).
    pub control_connections: IntGaugeVec,
    /// Live controlled calls (handed over, not yet ended) per app — a
    /// drain-to-zero gauge, the control-plane analogue of proxy_dialog_sessions.
    pub control_controlled_calls: IntGaugeVec,
    /// Commands applied, by app + verb.
    pub control_commands_total: IntCounterVec,
    /// Events dropped by slow-consumer backpressure, by app.
    pub control_events_dropped_total: IntCounterVec,
    /// Control-plane auth failures (bad/missing token on the upgrade).
    pub control_auth_failures_total: IntCounter,
    /// Handoff deadlines that fired (no controller accepted + acted in time),
    /// by app.
    pub control_handoff_timeouts_total: IntCounterVec,
}

impl SiphonMetrics {
    fn new() -> Result<Self, prometheus::Error> {
        let registry = Registry::new();

        // Both counters count *wire events*, not transactions: a retransmitted
        // INVITE increments once per datagram, because retransmit detection
        // happens well downstream of the dispatch point these are taken at.
        // That is the right meaning for a receive/send counter, but it does
        // mean `requests_total` is not a call or transaction count.
        let requests_total = IntCounterVec::new(
            Opts::new(
                "siphon_requests_total",
                "SIP requests crossing the wire, including retransmissions (unknown methods bucket into OTHER)",
            ),
            &["method", "direction"],
        )?;

        let responses_total = IntCounterVec::new(
            Opts::new(
                "siphon_responses_total",
                "SIP responses crossing the wire, including retransmissions",
            ),
            &["class", "direction"],
        )?;

        // Materialise every child up front so the hot path is an array index
        // (see the field docs). Label-major, direction-minor — must match
        // `method_index(m) * 2 + direction.index()`.
        let mut request_children = Vec::with_capacity(METHOD_LABELS.len() * 2);
        for method in METHOD_LABELS {
            for direction in [Direction::In, Direction::Out] {
                request_children.push(
                    requests_total.get_metric_with_label_values(&[method, direction.as_str()])?,
                );
            }
        }
        let requests_by_method: [IntCounter; METHOD_LABELS.len() * 2] = request_children
            .try_into()
            .map_err(|_| prometheus::Error::Msg("requests_total child count mismatch".into()))?;

        let mut response_children = Vec::with_capacity(CLASS_LABELS.len() * 2);
        for class in CLASS_LABELS {
            for direction in [Direction::In, Direction::Out] {
                response_children.push(
                    responses_total.get_metric_with_label_values(&[class, direction.as_str()])?,
                );
            }
        }
        let responses_by_class: [IntCounter; CLASS_LABELS.len() * 2] = response_children
            .try_into()
            .map_err(|_| prometheus::Error::Msg("responses_total child count mismatch".into()))?;

        let transactions_active = IntGauge::new(
            "siphon_transactions_active",
            "Number of active SIP transactions",
        )?;

        let uac_pending_requests = IntGauge::new(
            "siphon_uac_pending_requests",
            "In-flight UAC requests (NAT keepalive / health probe) awaiting a response",
        )?;

        let proxy_dialog_sessions = IntGauge::new(
            "siphon_proxy_dialog_sessions",
            "Live proxy dialog-key entries (INVITEs within their 2xx ACK window)",
        )?;

        let cdr_sessions = IntGauge::new(
            "siphon_cdr_sessions",
            "Live cdr.auto_emit per-call tracking entries (INVITE to BYE)",
        )?;

        let rf_sessions = IntGauge::new(
            "siphon_rf_sessions",
            "Live Rf accounting sessions (ACR-START without a matching ACR-STOP)",
        )?;

        let ro_sessions = IntGauge::new(
            "siphon_ro_sessions",
            "Live Ro online-charging sessions (CCR-INITIAL without CCR-TERMINATION)",
        )?;

        let li_remembered_sessions = IntGauge::new(
            "siphon_li_remembered_sessions",
            "Sessions with a remembered lawful-intercept matching decision",
        )?;

        let subscribe_dialogs = IntGauge::new(
            "siphon_subscribe_dialogs",
            "Live SUBSCRIBE dialogs in the L1 subscribe_state store",
        )?;

        let ipsec_sa_pairs = IntGauge::new(
            "siphon_ipsec_sa_pairs",
            "Live P-CSCF IPsec SA pairs in the IpsecManager (4 XFRM states + 4 policies each)",
        )?;

        let registrations_active = IntGauge::new(
            "siphon_registrations_active",
            "Number of active registrations (AoR bindings)",
        )?;

        let dialogs_active = IntGauge::new(
            "siphon_dialogs_active",
            "Active SIP dialogs (proxy dialog sessions + active B2BUA calls)",
        )?;

        let b2bua_calls_active = IntGauge::new(
            "siphon_b2bua_calls_active",
            "Number of active B2BUA calls (bridged call actors)",
        )?;

        let connections_active = GaugeVec::new(
            Opts::new(
                "siphon_connections_active",
                "Live inbound connections per stream transport (UDP is connectionless and not reported)",
            ),
            &["transport"],
        )?;

        let uptime_seconds =
            Gauge::new("siphon_uptime_seconds", "Time since SIPhon process started")?;

        let memory_allocated_bytes = IntGauge::new(
            "siphon_memory_allocated_bytes",
            "Live bytes allocated by the application (jemalloc stats.allocated) — the leak signal",
        )?;
        let memory_resident_bytes = IntGauge::new(
            "siphon_memory_resident_bytes",
            "Physical pages backing the allocator (jemalloc stats.resident)",
        )?;
        let memory_active_bytes = IntGauge::new(
            "siphon_memory_active_bytes",
            "Bytes in active pages (jemalloc stats.active)",
        )?;
        let memory_retained_bytes = IntGauge::new(
            "siphon_memory_retained_bytes",
            "Virtual memory retained by the allocator, not returned to the OS (jemalloc stats.retained)",
        )?;
        let memory_mapped_bytes = IntGauge::new(
            "siphon_memory_mapped_bytes",
            "Total mapped bytes (jemalloc stats.mapped)",
        )?;
        let memory_metadata_bytes = IntGauge::new(
            "siphon_memory_metadata_bytes",
            "Allocator bookkeeping: arena headers, extents, bin metadata (jemalloc stats.metadata)",
        )?;
        let python_allocated_blocks = IntGauge::new(
            "siphon_python_allocated_blocks",
            "Currently-allocated CPython memory blocks (sys.getallocatedblocks) — the Python-side leak signal",
        )?;

        let script_errors_total = IntCounter::new(
            "siphon_script_errors_total",
            "Total Python script execution errors",
        )?;

        let pyexec_pool_size = IntGauge::new(
            "siphon_pyexec_pool_size",
            "Live worker threads in the synchronous Python executor pool (elastic; grows to pool_max)",
        )?;
        let pyexec_pool_max = IntGauge::new(
            "siphon_pyexec_pool_max",
            "Configured hard ceiling on synchronous Python executor worker threads",
        )?;
        let pyexec_inflight = IntGauge::new(
            "siphon_pyexec_inflight",
            "Handler jobs currently executing on a Python executor pool worker",
        )?;
        let pyexec_queue_depth = IntGauge::new(
            "siphon_pyexec_queue_depth",
            "Handler jobs waiting in the Python executor pool's bounded queue",
        )?;
        let pyexec_jobs_completed_total = IntCounter::new(
            "siphon_pyexec_jobs_completed_total",
            "Total handler jobs completed by the Python executor pool",
        )?;
        let pyexec_jobs_shed_total = IntCounter::new(
            "siphon_pyexec_jobs_shed_total",
            "Total handler jobs shed because the Python executor pool queue was full",
        )?;

        let auth_ha1_cache_hits_total = IntCounter::new(
            "siphon_auth_ha1_cache_hits_total",
            "Total HTTP-auth credential lookups served from the in-process HA1 cache",
        )?;

        let banned_ips = IntGauge::new(
            "siphon_banned_ips",
            "Source IPs currently auto-banned by failed_auth_ban scanner protection",
        )?;

        let auth_failures_total = IntCounter::new(
            "siphon_auth_failures_total",
            "Total challenges issued because the request carried no credentials (the RFC 3261 opening leg of challenge-response); counted for visibility whether or not failed_auth_ban.missing_credentials_weight acts on it",
        )?;

        let handshake_failures_total = IntCounter::new(
            "siphon_handshake_failures_total",
            "Total TLS/WSS/WS handshakes that failed or timed out before completing, each recorded toward the auto-ban (TCP-validated source IPs)",
        )?;

        let credential_failures_total = IntCounter::new(
            "siphon_credential_failures_total",
            "Total digest attempts with present-but-invalid credentials, a denied username, or a forged/stale/replayed nonce, each recorded toward the auto-ban as a high-confidence signal",
        )?;

        let auth_backend_errors_total = IntCounter::new(
            "siphon_auth_backend_errors_total",
            "Total credential checks the credential source could not answer (HTTP auth backend timeout/connection failure, or no usable backend configured); never counted toward the auto-ban",
        )?;

        let malformed_messages_total = IntCounter::new(
            "siphon_malformed_messages_total",
            "Total non-SIP / unparseable messages received on a stream transport (TCP/TLS) and dropped, each recorded toward the auto-ban",
        )?;

        let connections_refused_total = IntCounterVec::new(
            Opts::new(
                "siphon_connections_refused_total",
                "Inbound stream connections refused by security.connection_limits, by which ceiling refused them",
            ),
            &["reason"],
        )?;

        let stream_connections_active = IntGauge::new(
            "siphon_stream_connections_active",
            "Inbound stream connections currently established across all sources",
        )?;

        let handshakes_in_flight = IntGauge::new(
            "siphon_handshakes_in_flight",
            "Inbound handshakes (TLS/WS) and first-line sniffs currently in flight",
        )?;

        let requests_without_branch_total = IntCounter::new(
            "siphon_requests_without_branch_total",
            "Total inbound requests with no branch parameter in the topmost Via, processed statelessly because no server transaction can be keyed for them (no RFC 2543 legacy matching)",
        )?;

        let udp_datagrams_at_buffer_limit_total = IntCounter::new(
            "siphon_udp_datagrams_at_buffer_limit_total",
            "Total inbound UDP datagrams that exactly filled the receive buffer and may have been truncated by the kernel",
        )?;

        let scanner_blocked_total = IntCounter::new(
            "siphon_scanner_blocked_total",
            "Total inbound requests dropped because the source User-Agent matched a security.scanner_block signature",
        )?;

        let rate_limited_total = IntCounter::new(
            "siphon_rate_limited_total",
            "Total inbound requests dropped because the source exceeded security.rate_limit.max_requests within the window",
        )?;

        let firewall_commands_dropped_total = IntCounter::new(
            "siphon_firewall_commands_dropped_total",
            "Total kernel-firewall (nf_tables) commands dropped because the netlink actor queue was full",
        )?;

        let firewall_command_failures_total = IntCounter::new(
            "siphon_firewall_command_failures_total",
            "Total kernel-firewall (nf_tables) netlink commands that failed — bans not enforced in the kernel",
        )?;

        let diameter_peers_connected = IntGauge::new(
            "siphon_diameter_peers_connected",
            "Number of currently connected Diameter peers",
        )?;

        let diameter_requests_total = IntCounterVec::new(
            Opts::new(
                "siphon_diameter_requests_total",
                "Total Diameter requests sent",
            ),
            &["command"],
        )?;

        let diameter_request_errors_total = IntCounterVec::new(
            Opts::new(
                "siphon_diameter_request_errors_total",
                "Total Diameter request errors",
            ),
            &["error"],
        )?;

        let diameter_request_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "siphon_diameter_request_duration_seconds",
                "Diameter request round-trip duration in seconds",
            )
            .buckets(vec![
                0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0, 10.0,
            ]),
            &["command"],
        )?;

        let diameter_watchdog_failures_total = IntCounter::new(
            "siphon_diameter_watchdog_failures_total",
            "Total Diameter watchdog (DWR/DWA) failures indicating dead peers",
        )?;

        let rtpengine_instances_up = IntGauge::new(
            "siphon_rtpengine_instances_up",
            "Number of RTPEngine instances responding to ping",
        )?;

        let rtpengine_instances_total = IntGauge::new(
            "siphon_rtpengine_instances_total",
            "Total number of configured RTPEngine instances",
        )?;

        let rtpengine_instance_up = IntGaugeVec::new(
            Opts::new(
                "siphon_rtpengine_instance_up",
                "Per-instance RTPEngine health (1=responding to ping, 0=not responding)",
            ),
            &["address"],
        )?;

        let sbi_npcf_app_sessions_active = IntGauge::new(
            "siphon_sbi_npcf_app_sessions_active",
            "Active N5/Npcf app-sessions created by this NF and not yet deleted",
        )?;

        let glibc_system_bytes = IntGauge::new(
            "siphon_glibc_system_bytes",
            "Total OS memory held by glibc malloc across all arenas (C-side / CPython raw domain; invisible to jemalloc)",
        )?;
        let glibc_in_use_bytes = IntGauge::new(
            "siphon_glibc_in_use_bytes",
            "Live (allocated, not freed) glibc bytes across all arenas — the C-side leak signal",
        )?;
        let glibc_free_bytes = IntGauge::new(
            "siphon_glibc_free_bytes",
            "Free/retained bytes within glibc arenas (high while in_use is flat = arena retention, not a leak)",
        )?;
        let glibc_mmap_bytes = IntGauge::new(
            "siphon_glibc_mmap_bytes",
            "Bytes served by glibc via mmap (large allocations), separate from the arenas",
        )?;
        let glibc_arena_count = IntGauge::new(
            "siphon_glibc_arena_count",
            "Number of glibc malloc arenas (each a ~64 MB reservation; rises with per-thread contention)",
        )?;

        let control_connections = IntGaugeVec::new(
            Opts::new(
                "siphon_control_connections",
                "Live control-plane connections per app",
            ),
            &["app"],
        )?;
        let control_controlled_calls = IntGaugeVec::new(
            Opts::new(
                "siphon_control_controlled_calls",
                "Live controlled calls per app (handed over, not yet ended)",
            ),
            &["app"],
        )?;
        let control_commands_total = IntCounterVec::new(
            Opts::new(
                "siphon_control_commands_total",
                "Control-plane commands applied",
            ),
            &["app", "verb"],
        )?;
        let control_events_dropped_total = IntCounterVec::new(
            Opts::new(
                "siphon_control_events_dropped_total",
                "Control-plane events dropped by slow-consumer backpressure",
            ),
            &["app"],
        )?;
        let control_auth_failures_total = IntCounter::new(
            "siphon_control_auth_failures_total",
            "Control-plane auth failures (bad/missing token on the upgrade)",
        )?;
        let control_handoff_timeouts_total = IntCounterVec::new(
            Opts::new(
                "siphon_control_handoff_timeouts_total",
                "Control-plane handoff deadlines that fired (no controller acted in time)",
            ),
            &["app"],
        )?;

        // Register all metrics
        registry.register(Box::new(control_connections.clone()))?;
        registry.register(Box::new(control_controlled_calls.clone()))?;
        registry.register(Box::new(control_commands_total.clone()))?;
        registry.register(Box::new(control_events_dropped_total.clone()))?;
        registry.register(Box::new(control_auth_failures_total.clone()))?;
        registry.register(Box::new(control_handoff_timeouts_total.clone()))?;
        registry.register(Box::new(requests_total.clone()))?;
        registry.register(Box::new(responses_total.clone()))?;
        registry.register(Box::new(transactions_active.clone()))?;
        registry.register(Box::new(uac_pending_requests.clone()))?;
        registry.register(Box::new(proxy_dialog_sessions.clone()))?;
        registry.register(Box::new(cdr_sessions.clone()))?;
        registry.register(Box::new(rf_sessions.clone()))?;
        registry.register(Box::new(ro_sessions.clone()))?;
        registry.register(Box::new(li_remembered_sessions.clone()))?;
        registry.register(Box::new(subscribe_dialogs.clone()))?;
        registry.register(Box::new(ipsec_sa_pairs.clone()))?;
        registry.register(Box::new(registrations_active.clone()))?;
        registry.register(Box::new(dialogs_active.clone()))?;
        registry.register(Box::new(b2bua_calls_active.clone()))?;
        registry.register(Box::new(connections_active.clone()))?;
        registry.register(Box::new(uptime_seconds.clone()))?;
        registry.register(Box::new(memory_allocated_bytes.clone()))?;
        registry.register(Box::new(memory_resident_bytes.clone()))?;
        registry.register(Box::new(memory_active_bytes.clone()))?;
        registry.register(Box::new(memory_retained_bytes.clone()))?;
        registry.register(Box::new(memory_mapped_bytes.clone()))?;
        registry.register(Box::new(memory_metadata_bytes.clone()))?;
        registry.register(Box::new(python_allocated_blocks.clone()))?;
        registry.register(Box::new(script_errors_total.clone()))?;
        registry.register(Box::new(pyexec_pool_size.clone()))?;
        registry.register(Box::new(pyexec_pool_max.clone()))?;
        registry.register(Box::new(pyexec_inflight.clone()))?;
        registry.register(Box::new(pyexec_queue_depth.clone()))?;
        registry.register(Box::new(pyexec_jobs_completed_total.clone()))?;
        registry.register(Box::new(pyexec_jobs_shed_total.clone()))?;
        registry.register(Box::new(auth_ha1_cache_hits_total.clone()))?;
        registry.register(Box::new(banned_ips.clone()))?;
        registry.register(Box::new(auth_failures_total.clone()))?;
        registry.register(Box::new(handshake_failures_total.clone()))?;
        registry.register(Box::new(credential_failures_total.clone()))?;
        registry.register(Box::new(auth_backend_errors_total.clone()))?;
        registry.register(Box::new(malformed_messages_total.clone()))?;
        registry.register(Box::new(connections_refused_total.clone()))?;
        registry.register(Box::new(stream_connections_active.clone()))?;
        registry.register(Box::new(handshakes_in_flight.clone()))?;
        registry.register(Box::new(requests_without_branch_total.clone()))?;
        registry.register(Box::new(udp_datagrams_at_buffer_limit_total.clone()))?;
        registry.register(Box::new(scanner_blocked_total.clone()))?;
        registry.register(Box::new(rate_limited_total.clone()))?;
        registry.register(Box::new(firewall_commands_dropped_total.clone()))?;
        registry.register(Box::new(firewall_command_failures_total.clone()))?;
        registry.register(Box::new(diameter_peers_connected.clone()))?;
        registry.register(Box::new(diameter_requests_total.clone()))?;
        registry.register(Box::new(diameter_request_errors_total.clone()))?;
        registry.register(Box::new(diameter_request_duration_seconds.clone()))?;
        registry.register(Box::new(diameter_watchdog_failures_total.clone()))?;
        registry.register(Box::new(rtpengine_instances_up.clone()))?;
        registry.register(Box::new(rtpengine_instances_total.clone()))?;
        registry.register(Box::new(rtpengine_instance_up.clone()))?;
        registry.register(Box::new(sbi_npcf_app_sessions_active.clone()))?;
        registry.register(Box::new(glibc_system_bytes.clone()))?;
        registry.register(Box::new(glibc_in_use_bytes.clone()))?;
        registry.register(Box::new(glibc_free_bytes.clone()))?;
        registry.register(Box::new(glibc_mmap_bytes.clone()))?;
        registry.register(Box::new(glibc_arena_count.clone()))?;

        Ok(Self {
            registry,
            requests_total,
            responses_total,
            requests_by_method,
            responses_by_class,
            transactions_active,
            uac_pending_requests,
            proxy_dialog_sessions,
            cdr_sessions,
            rf_sessions,
            ro_sessions,
            li_remembered_sessions,
            subscribe_dialogs,
            ipsec_sa_pairs,
            registrations_active,
            dialogs_active,
            b2bua_calls_active,
            connections_active,
            uptime_seconds,
            memory_allocated_bytes,
            memory_resident_bytes,
            memory_active_bytes,
            memory_retained_bytes,
            memory_mapped_bytes,
            memory_metadata_bytes,
            python_allocated_blocks,
            script_errors_total,
            pyexec_pool_size,
            pyexec_pool_max,
            pyexec_inflight,
            pyexec_queue_depth,
            pyexec_jobs_completed_total,
            pyexec_jobs_shed_total,
            auth_ha1_cache_hits_total,
            banned_ips,
            auth_failures_total,
            handshake_failures_total,
            credential_failures_total,
            auth_backend_errors_total,
            malformed_messages_total,
            connections_refused_total,
            stream_connections_active,
            handshakes_in_flight,
            requests_without_branch_total,
            udp_datagrams_at_buffer_limit_total,
            scanner_blocked_total,
            rate_limited_total,
            firewall_commands_dropped_total,
            firewall_command_failures_total,
            diameter_peers_connected,
            diameter_requests_total,
            diameter_request_errors_total,
            diameter_request_duration_seconds,
            diameter_watchdog_failures_total,
            rtpengine_instances_up,
            rtpengine_instances_total,
            rtpengine_instance_up,
            sbi_npcf_app_sessions_active,
            glibc_system_bytes,
            glibc_in_use_bytes,
            glibc_free_bytes,
            glibc_mmap_bytes,
            glibc_arena_count,
            control_connections,
            control_controlled_calls,
            control_commands_total,
            control_events_dropped_total,
            control_auth_failures_total,
            control_handoff_timeouts_total,
        })
    }

    /// Count one SIP request crossing the wire.
    ///
    /// Hot path — one array index plus one relaxed atomic add, no label-map
    /// lookup. Counts wire events, so a retransmission counts each time.
    #[inline]
    pub fn record_request(&self, method: &crate::sip::message::Method, direction: Direction) {
        // Indices come from `method_index` / `Direction::index`, both of which
        // are total over their input types, so this cannot be out of range.
        // `get` rather than `[]` keeps a future label-set edit from panicking
        // on the datapath.
        if let Some(counter) = self
            .requests_by_method
            .get(method_index(method) * 2 + direction.index())
        {
            counter.inc();
        }
    }

    /// Count one SIP response crossing the wire. See [`Self::record_request`].
    #[inline]
    pub fn record_response(&self, status_code: u16, direction: Direction) {
        if let Some(counter) = self
            .responses_by_class
            .get(class_index(status_code) * 2 + direction.index())
        {
            counter.inc();
        }
    }

    /// Count one already-serialized SIP frame, classifying it from its start
    /// line. Used on the outbound path, which sits below serialization.
    ///
    /// Non-SIP frames (the double-CRLF keepalive) are ignored.
    #[inline]
    pub fn record_frame(&self, data: &[u8], direction: Direction) {
        match classify_frame(data) {
            Some(Frame::Request(index)) => {
                if let Some(counter) = self.requests_by_method.get(index * 2 + direction.index()) {
                    counter.inc();
                }
            }
            Some(Frame::Response(code)) => self.record_response(code, direction),
            None => {}
        }
    }
}

/// Encode all metrics as Prometheus text format.
/// Returns an empty string if metrics are not initialized or encoding fails.
pub fn encode_metrics() -> String {
    let Some(metrics) = metrics() else {
        return String::new();
    };
    let encoder = TextEncoder::new();
    let metric_families = metrics.registry.gather();
    let mut buffer = Vec::new();
    if let Err(error) = encoder.encode(&metric_families, &mut buffer) {
        error!("Failed to encode metrics: {error}");
        return String::new();
    }
    String::from_utf8(buffer).unwrap_or_default()
}

/// Sum every series of a labelled counter vector across all label
/// combinations. Used to expose a single scalar total (e.g. all SIP requests
/// regardless of method) in the JSON metrics snapshot the web dashboard polls,
/// where the browser diffs the total over time to derive a rate.
pub fn sum_int_counter_vec(vector: &IntCounterVec) -> u64 {
    use prometheus::core::Collector;
    vector
        .collect()
        .iter()
        .flat_map(|family| family.get_metric())
        .map(|metric| metric.get_counter().value() as u64)
        .sum()
}

/// Collapse a labelled gauge vector into a `label-value -> summed gauge` map,
/// keyed on one label name (e.g. `"transport"` for `siphon_connections_active`).
/// Series missing the label are grouped under the empty string.
pub fn gauge_vec_by_label(
    vector: &GaugeVec,
    label: &str,
) -> std::collections::BTreeMap<String, f64> {
    use prometheus::core::Collector;
    let mut out = std::collections::BTreeMap::new();
    for family in vector.collect() {
        for metric in family.get_metric() {
            let key = metric
                .get_label()
                .iter()
                .find(|pair| pair.name() == label)
                .map(|pair| pair.value().to_owned())
                .unwrap_or_default();
            *out.entry(key).or_insert(0.0) += metric.get_gauge().value();
        }
    }
    out
}

/// Refresh `siphon_uptime_seconds`. Called from the dispatcher sweep (so a
/// Prometheus-only deployment sees it) and from the admin snapshot (so a
/// dashboard poll between sweeps is not 30 s stale).
pub fn update_uptime() {
    if let (Some(metrics), Some(started)) = (try_metrics(), STARTED_AT.get()) {
        metrics.uptime_seconds.set(started.elapsed().as_secs_f64());
    }
}

/// [`gauge_vec_by_label`] for an `IntGaugeVec` — e.g. per-instance media health
/// (`siphon_rtpengine_instance_up` keyed on `"address"`) or per-app control
/// connections.
pub fn int_gauge_vec_by_label(
    vector: &IntGaugeVec,
    label: &str,
) -> std::collections::BTreeMap<String, i64> {
    use prometheus::core::Collector;
    let mut out = std::collections::BTreeMap::new();
    for family in vector.collect() {
        for metric in family.get_metric() {
            let key = metric
                .get_label()
                .iter()
                .find(|pair| pair.name() == label)
                .map(|pair| pair.value().to_owned())
                .unwrap_or_default();
            *out.entry(key).or_insert(0) += metric.get_gauge().value() as i64;
        }
    }
    out
}

/// [`gauge_vec_by_label`] for an `IntCounterVec` — the per-label breakdown that
/// [`sum_int_counter_vec`] collapses away. The dashboard needs both: the total
/// to derive an overall rate, and the breakdown to say *which* method, command
/// or refusal reason is moving.
pub fn int_counter_vec_by_label(
    vector: &IntCounterVec,
    label: &str,
) -> std::collections::BTreeMap<String, u64> {
    use prometheus::core::Collector;
    let mut out = std::collections::BTreeMap::new();
    for family in vector.collect() {
        for metric in family.get_metric() {
            let key = metric
                .get_label()
                .iter()
                .find(|pair| pair.name() == label)
                .map(|pair| pair.value().to_owned())
                .unwrap_or_default();
            *out.entry(key).or_insert(0) += metric.get_counter().value() as u64;
        }
    }
    out
}

/// Per-label totals for one value of a second label — e.g. `requests_total`
/// broken down by `method`, restricted to `direction="in"`.
///
/// Kept separate from [`int_counter_vec_by_label`] rather than generalised into
/// a filter argument, because these two label sets are the only ones the
/// dashboard slices this way.
pub fn int_counter_vec_by_label_where(
    vector: &IntCounterVec,
    label: &str,
    filter_label: &str,
    filter_value: &str,
) -> std::collections::BTreeMap<String, u64> {
    use prometheus::core::Collector;
    let mut out = std::collections::BTreeMap::new();
    for family in vector.collect() {
        for metric in family.get_metric() {
            let labels = metric.get_label();
            let matches = labels
                .iter()
                .any(|pair| pair.name() == filter_label && pair.value() == filter_value);
            if !matches {
                continue;
            }
            let key = labels
                .iter()
                .find(|pair| pair.name() == label)
                .map(|pair| pair.value().to_owned())
                .unwrap_or_default();
            *out.entry(key).or_insert(0) += metric.get_counter().value() as u64;
        }
    }
    out
}

/// Refresh the jemalloc memory-stat gauges from the allocator's internal
/// counters.  Call periodically (the dispatcher does so on its cleanup tick).
/// No-op when metrics aren't initialised or jemalloc isn't the allocator.
///
/// `memory_allocated_bytes` is the one to alert on: it is actual live bytes,
/// so steady growth under constant load is a real leak — independent of RSS,
/// which also moves with allocator retention and fragmentation.
#[cfg(not(target_env = "msvc"))]
pub fn update_memory_stats() {
    let Some(metrics) = metrics() else {
        return;
    };
    // jemalloc snapshots stats at epoch advance; without this the reads are
    // stale (often zero) on the first call.
    if tikv_jemalloc_ctl::epoch::advance().is_err() {
        return;
    }
    if let Ok(value) = tikv_jemalloc_ctl::stats::allocated::read() {
        metrics.memory_allocated_bytes.set(value as i64);
    }
    if let Ok(value) = tikv_jemalloc_ctl::stats::resident::read() {
        metrics.memory_resident_bytes.set(value as i64);
    }
    if let Ok(value) = tikv_jemalloc_ctl::stats::active::read() {
        metrics.memory_active_bytes.set(value as i64);
    }
    if let Ok(value) = tikv_jemalloc_ctl::stats::retained::read() {
        metrics.memory_retained_bytes.set(value as i64);
    }
    if let Ok(value) = tikv_jemalloc_ctl::stats::mapped::read() {
        metrics.memory_mapped_bytes.set(value as i64);
    }
    if let Ok(value) = tikv_jemalloc_ctl::stats::metadata::read() {
        metrics.memory_metadata_bytes.set(value as i64);
    }
}

/// No-op on MSVC, where jemalloc (and thus its stats) is not the allocator.
#[cfg(target_env = "msvc")]
pub fn update_memory_stats() {}

/// Probe whether jemalloc is the live global allocator.
///
/// Allocates ~1 MiB and checks jemalloc's `allocated` stat moved: if jemalloc is
/// *not* the global allocator the probe routes through the system allocator and
/// jemalloc's internal counter doesn't budge. Read-only — never changes the
/// allocator's runtime configuration.
///
/// Note: under `cargo test` this returns `false`, because the lib/integration
/// test binaries set no `#[global_allocator]` and so run on the system allocator
/// (the same reason the jemalloc gauges read ~0 in tests). It returns `true`
/// only in a binary that emitted `siphon::install_allocator!()` (or its own
/// jemalloc `#[global_allocator]`), e.g. the `siphon` binary.
#[cfg(not(target_env = "msvc"))]
pub fn jemalloc_is_active() -> bool {
    use tikv_jemalloc_ctl::{epoch, stats};

    const PROBE_BYTES: usize = 1 << 20; // 1 MiB
    const MIN_DELTA: usize = 1 << 19; // 512 KiB — half the probe, tolerant of rounding/noise

    // If the epoch can't be advanced we can't read jemalloc stats at all, which
    // itself means jemalloc isn't the operative allocator.
    if epoch::advance().is_err() {
        return false;
    }
    let before = stats::allocated::read().unwrap_or(0);
    // `with_capacity` allocates the backing buffer immediately; `black_box`
    // stops the optimiser from eliding an otherwise-unused allocation.
    let probe = std::hint::black_box(Vec::<u8>::with_capacity(PROBE_BYTES));
    let _ = epoch::advance();
    let after = stats::allocated::read().unwrap_or(0);
    drop(probe);

    after.saturating_sub(before) >= MIN_DELTA
}

/// On MSVC jemalloc is never a dependency, so it is never the allocator.
#[cfg(target_env = "msvc")]
pub fn jemalloc_is_active() -> bool {
    false
}

/// Verify jemalloc is the live global allocator and warn loudly at boot if not.
///
/// A binary that forgot `siphon::install_allocator!()` runs siphon's Rust
/// working set on the **system** allocator — RSS bloat (per-thread glibc
/// arenas) and meaningless `siphon_memory_*` gauges, which then read jemalloc's
/// idle internal footprint instead of the real working set. Catch it in the log
/// at startup rather than in a memory post-mortem. Safe to call unconditionally:
/// the probe is read-only.
#[cfg(not(target_env = "msvc"))]
pub fn verify_global_allocator() {
    if jemalloc_is_active() {
        tracing::debug!(target: "siphon", "jemalloc confirmed as the global allocator");
    } else {
        tracing::warn!(
            target: "siphon",
            "jemalloc is NOT the active global allocator — running on the system \
             allocator. Add `siphon::install_allocator!();` to this binary's main.rs. \
             Expect RSS bloat and meaningless siphon_memory_* gauges."
        );
    }
}

/// No-op on MSVC, where jemalloc isn't a dependency and the system allocator is
/// expected — a warning there would be misleading.
#[cfg(target_env = "msvc")]
pub fn verify_global_allocator() {}

/// Refresh the Python-side allocation gauge from `sys.getallocatedblocks()`.
///
/// Python objects live in CPython's own allocator (mimalloc on free-threaded
/// builds), which jemalloc — and therefore [`update_memory_stats`] — cannot
/// see. This is the leak signal for the Python side: a script accumulating
/// objects, or a leaked `Py<>` reference. Cheap; called on the cleanup tick.
pub fn update_python_stats() {
    let Some(metrics) = metrics() else {
        return;
    };
    use pyo3::prelude::*;
    let result = pyo3::Python::attach(|python| -> PyResult<i64> {
        python
            .import("sys")?
            .call_method0("getallocatedblocks")?
            .extract()
    });
    if let Ok(blocks) = result {
        metrics.python_allocated_blocks.set(blocks);
    }
}

/// Refresh the glibc allocator gauges from `malloc_info`. Call periodically (the
/// dispatcher does so on its cleanup tick). This is the C-side / CPython
/// raw-domain pool that neither [`update_memory_stats`] (jemalloc) nor
/// [`update_python_stats`] (CPython's mimalloc) can see — because Rust runs on
/// jemalloc, glibc's arenas hold *only* the C side, so these gauges isolate it.
/// No-op off glibc.
///
/// `glibc_in_use_bytes` is the one to alert on (the C-side leak signal). A high
/// `glibc_system_bytes` with high `glibc_free_bytes` and flat `in_use` is arena
/// retention — address it with `memory.glibc.arena_max` / `trim_interval_secs`.
pub fn update_glibc_stats() {
    let Some(metrics) = metrics() else {
        return;
    };
    let Some(stats) = glibc::read_stats() else {
        return;
    };
    metrics.glibc_system_bytes.set(stats.system_bytes as i64);
    metrics.glibc_in_use_bytes.set(stats.in_use_bytes as i64);
    metrics.glibc_free_bytes.set(stats.free_bytes as i64);
    metrics.glibc_mmap_bytes.set(stats.mmap_bytes as i64);
    metrics.glibc_arena_count.set(stats.arena_count as i64);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// The probe must not panic, and — because the `cargo test` binaries set no
    /// `#[global_allocator]` and so run on the system allocator (the documented
    /// reason the jemalloc gauges read ~0 in tests) — it must report jemalloc as
    /// inactive here. `verify_global_allocator()` would WARN in this same case,
    /// which is exactly its job for a binary that forgot `install_allocator!()`.
    #[test]
    fn jemalloc_inactive_under_cargo_test() {
        assert!(
            !jemalloc_is_active(),
            "cargo-test binaries run on the system allocator, so jemalloc must \
             probe as inactive; if this flips, a #[global_allocator] leaked into \
             the test build"
        );
        // Smoke: the boot guard path must not panic either.
        verify_global_allocator();
    }

    /// Read one `requests_total` child directly off the vector, so the test
    /// asserts against the *registered* series rather than the pre-resolved
    /// array it is meant to be checking.
    fn request_count(method: &str, direction: &str) -> u64 {
        metrics()
            .unwrap()
            .requests_total
            .with_label_values(&[method, direction])
            .get()
    }

    #[test]
    fn record_request_increments_the_matching_series() {
        use crate::sip::message::Method;
        init().unwrap();
        let metrics = metrics().unwrap();

        // The global registry is shared across tests in this binary, so assert
        // on deltas rather than absolute values.
        let invite_in_before = request_count("INVITE", "in");
        let invite_out_before = request_count("INVITE", "out");
        let register_in_before = request_count("REGISTER", "in");

        metrics.record_request(&Method::Invite, Direction::In);
        metrics.record_request(&Method::Invite, Direction::In);
        metrics.record_request(&Method::Register, Direction::In);
        metrics.record_request(&Method::Invite, Direction::Out);

        assert_eq!(request_count("INVITE", "in") - invite_in_before, 2);
        assert_eq!(request_count("REGISTER", "in") - register_in_before, 1);
        assert_eq!(
            request_count("INVITE", "out") - invite_out_before,
            1,
            "direction must select a distinct series"
        );
    }

    #[test]
    fn unknown_methods_bucket_into_other() {
        use crate::sip::message::Method;
        init().unwrap();
        let metrics = metrics().unwrap();

        let before = request_count("OTHER", "in");
        metrics.record_request(&Method::Extension("FOO1".into()), Direction::In);
        metrics.record_request(&Method::Extension("FOO2".into()), Direction::In);

        assert_eq!(
            request_count("OTHER", "in") - before,
            2,
            "extension methods must share one series — the method token is \
             attacker-controlled, so a series per token is a cardinality DoS"
        );
        assert!(
            !encode_metrics().contains("FOO1"),
            "an extension method token must never reach a label value"
        );
    }

    #[test]
    fn record_response_buckets_by_class() {
        init().unwrap();
        let metrics = metrics().unwrap();

        let read = |class: &str| {
            metrics
                .responses_total
                .with_label_values(&[class, "out"])
                .get()
        };
        let (before_2xx, before_4xx) = (read("2xx"), read("4xx"));

        metrics.record_response(200, Direction::Out);
        metrics.record_response(202, Direction::Out);
        metrics.record_response(404, Direction::Out);

        assert_eq!(read("2xx") - before_2xx, 2);
        assert_eq!(read("4xx") - before_4xx, 1);
    }

    #[test]
    fn classify_frame_reads_the_start_line() {
        let request = |data: &[u8]| match classify_frame(data) {
            Some(Frame::Request(index)) => METHOD_LABELS[index],
            other => panic!(
                "expected a request, got {}",
                match other {
                    Some(Frame::Response(code)) => format!("response {code}"),
                    _ => "nothing".to_string(),
                }
            ),
        };

        assert_eq!(
            request(b"INVITE sip:bob@biloxi.com SIP/2.0\r\nVia: x\r\n\r\n"),
            "INVITE"
        );
        assert_eq!(request(b"ACK sip:bob@biloxi.com SIP/2.0\r\n\r\n"), "ACK");
        assert_eq!(
            request(b"REGISTER sip:biloxi.com SIP/2.0\r\n\r\n"),
            "REGISTER"
        );
        // A method siphon does not know is a label-cardinality hazard, so it
        // must collapse rather than pass through.
        assert_eq!(request(b"FROBNICATE sip:x@y SIP/2.0\r\n\r\n"), "OTHER");

        match classify_frame(b"SIP/2.0 200 OK\r\nVia: x\r\n\r\n") {
            Some(Frame::Response(code)) => assert_eq!(code, 200),
            _ => panic!("expected a 200 response"),
        }
        match classify_frame(b"SIP/2.0 486 Busy Here\r\n\r\n") {
            Some(Frame::Response(code)) => assert_eq!(code, 486),
            _ => panic!("expected a 486 response"),
        }
    }

    #[test]
    fn classify_frame_ignores_non_sip_frames() {
        // The CRLF keepalive (RFC 5626 §4.4.1) shares the outbound path and
        // must not inflate the request counter.
        assert!(classify_frame(b"\r\n\r\n").is_none());
        assert!(classify_frame(b"").is_none());
        assert!(classify_frame(b" ").is_none());
        // A truncated or non-numeric status line is not a countable response.
        assert!(classify_frame(b"SIP/2.0 2").is_none());
        assert!(classify_frame(b"SIP/2.0 OK Fine\r\n").is_none());
    }

    #[test]
    fn record_frame_counts_the_outbound_direction() {
        init().unwrap();
        let metrics = metrics().unwrap();

        let before_in = request_count("BYE", "in");
        let before_out = request_count("BYE", "out");
        metrics.record_frame(b"BYE sip:bob@biloxi.com SIP/2.0\r\n\r\n", Direction::Out);

        assert_eq!(request_count("BYE", "out") - before_out, 1);
        assert_eq!(
            request_count("BYE", "in"),
            before_in,
            "an outbound frame must not touch the inbound series"
        );
    }

    /// Field names declared on `SiphonMetrics`, read back out of this file.
    ///
    /// Rust has no reflection over struct fields, and the alternative — a
    /// hand-maintained list — would rot in exactly the way the tests below
    /// exist to prevent.
    fn declared_metric_fields() -> Vec<String> {
        let source = include_str!("mod.rs");
        let start = source
            .find("pub struct SiphonMetrics {")
            .expect("SiphonMetrics struct not found — did it get renamed?");
        let body = &source[start..];
        let end = body.find("\n}").expect("unterminated SiphonMetrics struct");

        body[..end]
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                // `pub name: Type,` and the two private pre-resolved arrays.
                let declaration = line.strip_prefix("pub ").unwrap_or(line);
                let (name, rest) = declaration.split_once(':')?;
                // Skip doc comments, attributes and anything that isn't a plain
                // field declaration.
                if !rest.trim_end().ends_with(',')
                    || name.is_empty()
                    || !name
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
                {
                    return None;
                }
                Some(name.to_string())
            })
            .collect()
    }

    /// Metrics whose only writer is `src/metrics/` itself — the allocator and
    /// interpreter gauges refreshed by `update_*_stats`. Everything else must be
    /// written by the subsystem it measures.
    const WRITTEN_BY_THE_METRICS_MODULE: &[&str] = &[
        "registry",
        // Written through the pre-resolved child arrays by `record_request` /
        // `record_response` / `record_frame`, never by field name, so the
        // name-appearance heuristic cannot see them.
        // `recorders_are_called_from_the_datapath` covers these instead.
        "requests_total",
        "responses_total",
        "requests_by_method",
        "responses_by_class",
        // Published by `update_uptime`, called from the dispatcher sweep.
        "uptime_seconds",
        "memory_allocated_bytes",
        "memory_resident_bytes",
        "memory_active_bytes",
        "memory_retained_bytes",
        "memory_mapped_bytes",
        "memory_metadata_bytes",
        "python_allocated_blocks",
        "glibc_system_bytes",
        "glibc_in_use_bytes",
        "glibc_free_bytes",
        "glibc_mmap_bytes",
        "glibc_arena_count",
    ];

    fn crate_source_files() -> Vec<std::path::PathBuf> {
        fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    walk(&path, out);
                } else if path.extension().is_some_and(|ext| ext == "rs") {
                    out.push(path);
                }
            }
        }
        let mut files = Vec::new();
        walk(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
            &mut files,
        );
        files
    }

    #[test]
    fn every_declared_metric_has_a_production_write_site() {
        // The check that would have caught siphon_requests_total,
        // siphon_responses_total, siphon_connections_active,
        // siphon_dialogs_active, siphon_transactions_active,
        // siphon_uptime_seconds and siphon_script_errors_total all shipping
        // registered-but-never-incremented — every one of them exported a flat
        // zero (or no series at all) for the life of the process, so every
        // dashboard and alert built on them was silently dead.
        //
        // "Write site" is approximated by the field name appearing in a file
        // outside src/metrics/ and src/admin/ — admin only ever *reads* for the
        // JSON snapshot, so a mention there does not prove anything is
        // publishing the metric.
        let fields = declared_metric_fields();
        assert!(
            fields.len() > 40,
            "parsed only {} fields — the struct-scraping heuristic has broken, \
             which would make this test silently vacuous",
            fields.len()
        );

        let sources: Vec<(std::path::PathBuf, String)> = crate_source_files()
            .into_iter()
            .filter(|path| {
                let text = path.to_string_lossy().replace('\\', "/");
                !text.contains("/src/metrics/") && !text.contains("/src/admin/")
            })
            .filter_map(|path| std::fs::read_to_string(&path).ok().map(|body| (path, body)))
            .collect();
        assert!(!sources.is_empty(), "no source files found to scan");

        let mut unwired = Vec::new();
        for field in &fields {
            if WRITTEN_BY_THE_METRICS_MODULE.contains(&field.as_str()) {
                continue;
            }
            let needle = format!(".{field}");
            if !sources.iter().any(|(_, body)| body.contains(&needle)) {
                unwired.push(field.clone());
            }
        }

        assert!(
            unwired.is_empty(),
            "these metrics are registered but never written outside src/metrics/ \
             — they will export a flat zero forever, so either wire them up or \
             delete them: {unwired:?}"
        );
    }

    #[test]
    fn recorders_are_called_from_the_datapath() {
        // `requests_total` / `responses_total` are allow-listed above because
        // they are written through pre-resolved children rather than by field
        // name. That allow-list would happily hide them going dead again, so
        // pin the actual call sites instead: one inbound classification point
        // and one outbound, each outside src/metrics/.
        let sources: Vec<String> = crate_source_files()
            .into_iter()
            .filter(|path| {
                !path
                    .to_string_lossy()
                    .replace('\\', "/")
                    .contains("/src/metrics/")
            })
            .filter_map(|path| std::fs::read_to_string(path).ok())
            .collect();

        for recorder in ["record_request(", "record_response(", "record_frame("] {
            assert!(
                sources.iter().any(|body| body.contains(recorder)),
                "{recorder} has no call site outside src/metrics/ — \
                 siphon_requests_total / siphon_responses_total are dead again"
            );
        }
    }

    #[test]
    fn every_declared_metric_is_surfaced_in_the_admin_snapshot() {
        // `/admin/metrics.json` is hand-written, so it drifts behind the
        // registry — which is how the control plane, per-instance media health,
        // Diameter per-command counters and the handshake-failure counter all
        // ended up collected but unreachable from the dashboard.
        let admin = include_str!("../admin/mod.rs");
        let allowed: &[&str] = &[
            "registry",
            "requests_by_method",
            "responses_by_class",
            // Exported for Prometheus scrape only — the JSON has no consumer for
            // a bare latency histogram, and the dashboard reads the per-command
            // request/error counters beside it instead.
            "diameter_request_duration_seconds",
            "control_handoff_timeouts_total",
            "memory_metadata_bytes",
            "glibc_free_bytes",
            "glibc_mmap_bytes",
            "auth_ha1_cache_hits_total",
            "registrations_active",
            "uptime_seconds",
        ];

        let missing: Vec<String> = declared_metric_fields()
            .into_iter()
            .filter(|field| !allowed.contains(&field.as_str()))
            .filter(|field| !admin.contains(&format!(".{field}")))
            .collect();

        assert!(
            missing.is_empty(),
            "these metrics exist but never reach /admin/metrics.json, so the \
             dashboard cannot show them — add them to the snapshot or to the \
             allow-list with a reason: {missing:?}"
        );
    }

    #[test]
    fn class_index_clamps_out_of_range_status_codes() {
        // A malformed status line should still land in a real bucket rather
        // than panic or silently vanish.
        assert_eq!(class_index(100), 0);
        assert_eq!(class_index(699), 5);
        assert_eq!(class_index(0), 0);
        assert_eq!(class_index(999), 5);
    }

    #[test]
    fn every_method_and_class_series_exists_before_any_traffic() {
        init().unwrap();
        let output = encode_metrics();
        // Pre-resolving every child means `rate()` works from the first scrape
        // instead of returning "no data" until that method is first seen.
        for method in METHOD_LABELS {
            assert!(
                output.contains(&format!(r#"method="{method}""#)),
                "missing requests_total series for {method}"
            );
        }
        for class in CLASS_LABELS {
            assert!(
                output.contains(&format!(r#"class="{class}""#)),
                "missing responses_total series for {class}"
            );
        }
    }

    #[test]
    fn method_index_is_unique_and_in_range() {
        use crate::sip::message::Method;
        let methods = [
            Method::Invite,
            Method::Ack,
            Method::Bye,
            Method::Cancel,
            Method::Options,
            Method::Register,
            Method::Info,
            Method::Update,
            Method::Prack,
            Method::Subscribe,
            Method::Notify,
            Method::Refer,
            Method::Message,
            Method::Publish,
            Method::Extension("X".into()),
        ];
        let mut seen = std::collections::HashSet::new();
        for method in &methods {
            let index = method_index(method);
            assert!(index < METHOD_LABELS.len(), "{method:?} out of range");
            assert!(seen.insert(index), "duplicate index for {method:?}");
            // The label must describe the method it is filed under.
            if !matches!(method, Method::Extension(_)) {
                assert_eq!(METHOD_LABELS[index], method.as_str());
            }
        }
        assert_eq!(seen.len(), METHOD_LABELS.len(), "a label has no method");
    }

    #[test]
    fn metrics_encode_produces_text() {
        init().unwrap();
        let output = encode_metrics();
        // Gauges always appear (even at zero), counters appear after first observation
        assert!(
            output.contains("siphon_transactions_active"),
            "output: {}",
            &output[..output.len().min(500)]
        );
        assert!(output.contains("siphon_registrations_active"));
    }

    /// Every jemalloc statistic siphon reads has to reach `/metrics`, or the
    /// operator is asked to reason about resident memory from a subset of the
    /// allocator's own numbers. `metadata` is the one that was missing:
    /// `resident - allocated - retained` is otherwise unattributed, and it is
    /// the arena-count term.
    #[test]
    fn every_jemalloc_stat_is_exported() {
        init().unwrap();
        let output = encode_metrics();
        for gauge in [
            "siphon_memory_allocated_bytes",
            "siphon_memory_resident_bytes",
            "siphon_memory_active_bytes",
            "siphon_memory_retained_bytes",
            "siphon_memory_mapped_bytes",
            "siphon_memory_metadata_bytes",
        ] {
            assert!(output.contains(gauge), "{gauge} missing from /metrics");
        }
    }

    #[test]
    fn gauge_operations() {
        init().unwrap();
        let metrics = metrics().unwrap();

        metrics.transactions_active.set(5);
        assert_eq!(metrics.transactions_active.get(), 5);

        metrics.transactions_active.inc();
        assert_eq!(metrics.transactions_active.get(), 6);

        metrics.transactions_active.dec();
        assert_eq!(metrics.transactions_active.get(), 5);
    }

    #[test]
    fn connection_gauge_by_transport() {
        init().unwrap();
        let metrics = metrics().unwrap();

        metrics
            .connections_active
            .with_label_values(&["TCP"])
            .set(10.0);
        metrics
            .connections_active
            .with_label_values(&["UDP"])
            .set(0.0);
        metrics
            .connections_active
            .with_label_values(&["TLS"])
            .set(3.0);

        assert_eq!(
            metrics.connections_active.with_label_values(&["TCP"]).get(),
            10.0
        );
    }

    #[test]
    fn sum_int_counter_vec_totals_all_series() {
        // Built on a local, isolated vector so the shared global registry can't
        // perturb the total.
        let vector = IntCounterVec::new(Opts::new("test_reqs_total", "test"), &["method"]).unwrap();
        vector.with_label_values(&["INVITE"]).inc_by(3);
        vector.with_label_values(&["REGISTER"]).inc_by(5);
        assert_eq!(sum_int_counter_vec(&vector), 8);
    }

    #[test]
    fn gauge_vec_by_label_groups_by_key() {
        let vector = GaugeVec::new(Opts::new("test_conns_active", "test"), &["transport"]).unwrap();
        vector.with_label_values(&["udp"]).set(6.0);
        vector.with_label_values(&["tcp"]).set(2.0);
        let map = gauge_vec_by_label(&vector, "transport");
        assert_eq!(map.get("udp"), Some(&6.0));
        assert_eq!(map.get("tcp"), Some(&2.0));
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn diameter_peers_connected_gauge() {
        // Gauge inc/dec/get mechanics on a fresh, isolated instance. The
        // process-global gauge is shared across parallel tests — the diameter
        // peer leak tests open real loopback connections that inc it — so
        // asserting absolute values on the global here would race. A fresh
        // instance is the correct unit under test for the mechanics.
        let metrics = SiphonMetrics::new().unwrap();
        assert_eq!(metrics.diameter_peers_connected.get(), 0);
        metrics.diameter_peers_connected.inc();
        metrics.diameter_peers_connected.inc();
        assert_eq!(metrics.diameter_peers_connected.get(), 2);
        metrics.diameter_peers_connected.dec();
        assert_eq!(metrics.diameter_peers_connected.get(), 1);

        // Registration + text encoding go through the global registry.
        init().unwrap();
        assert!(encode_metrics().contains("siphon_diameter_peers_connected"));
    }

    #[test]
    fn diameter_request_counters() {
        init().unwrap();
        let metrics = metrics().unwrap();

        metrics
            .diameter_requests_total
            .with_label_values(&["UAR"])
            .inc();
        metrics
            .diameter_requests_total
            .with_label_values(&["UAR"])
            .inc();
        metrics
            .diameter_requests_total
            .with_label_values(&["SAR"])
            .inc();

        assert_eq!(
            metrics
                .diameter_requests_total
                .with_label_values(&["UAR"])
                .get(),
            2
        );
        assert_eq!(
            metrics
                .diameter_requests_total
                .with_label_values(&["SAR"])
                .get(),
            1
        );
    }

    #[test]
    fn diameter_error_and_watchdog_counters() {
        init().unwrap();
        let metrics = metrics().unwrap();

        // These are process-global counters; other tests (e.g. peer
        // request-timeout paths) bump the same series under the parallel test
        // runner, so assert deltas from a baseline rather than absolute values.
        let base_timeout = metrics
            .diameter_request_errors_total
            .with_label_values(&["timeout"])
            .get();
        let base_watchdog = metrics.diameter_watchdog_failures_total.get();

        metrics
            .diameter_request_errors_total
            .with_label_values(&["timeout"])
            .inc();
        metrics
            .diameter_request_errors_total
            .with_label_values(&["channel_dropped"])
            .inc();
        metrics.diameter_watchdog_failures_total.inc();

        assert_eq!(
            metrics
                .diameter_request_errors_total
                .with_label_values(&["timeout"])
                .get(),
            base_timeout + 1
        );
        assert_eq!(
            metrics.diameter_watchdog_failures_total.get(),
            base_watchdog + 1
        );

        let output = encode_metrics();
        assert!(output.contains("siphon_diameter_request_errors_total"));
        assert!(output.contains("siphon_diameter_watchdog_failures_total"));
    }

    #[test]
    fn diameter_request_duration_histogram() {
        init().unwrap();
        let metrics = metrics().unwrap();

        metrics
            .diameter_request_duration_seconds
            .with_label_values(&["MAR"])
            .observe(0.015);

        let output = encode_metrics();
        assert!(output.contains("siphon_diameter_request_duration_seconds"));
    }
}
