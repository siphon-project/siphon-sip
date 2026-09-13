//! The state every handler in the dispatcher is passed, the drain flag the
//! shutdown path reads, and the bounded wrapper the background event loops
//! call script handlers through.

use super::*;

/// A pending timer entry in the timer wheel.
#[derive(Debug, Clone)]
pub struct TimerEntry {
    /// Transaction this timer belongs to.
    pub key: TransactionKey,
    /// Which timer.
    pub name: TimerName,
    /// When this timer fires.
    pub fires_at: std::time::Instant,
    /// Destination for retransmits (client transactions).
    pub destination: Option<SocketAddr>,
    /// Transport for retransmits.
    pub transport: Option<Transport>,
    /// Connection ID for sending.
    pub connection_id: Option<ConnectionId>,
    /// Local socket the original request arrived on — required by
    /// 3GPP TS 33.203 §7.4 so retransmitted server-transaction-cached
    /// responses egress on the same SA's local endpoint as the
    /// original.  None for client transactions or when the source
    /// doesn't matter (TCP/TLS connection-affine sends).
    pub source_local_addr: Option<SocketAddr>,
}

/// Shared state for the dispatcher, passed to each spawned task.
pub struct DispatcherState {
    pub engine: Arc<ScriptEngine>,
    pub outbound: Arc<OutboundRouter>,
    pub local_domains: LocalDomains,
    /// Host/port pairs that identify *this* proxy for Route recognition
    /// (RFC 3261 §16.4 "indicates this proxy") — every listener, advertised
    /// host, and stamping fallback, i.e. exactly what we put into Record-Route.
    /// Distinct from `local_domains`, which answers the different question of
    /// which SIP domains we *serve* (`ruri.is_local`, Rf/Ro charging role).
    pub self_identity: Arc<core::SelfIdentity>,
    pub local_addr: SocketAddr,
    /// Per-transport advertised host (hostname or IP) for Record-Route/Via.
    /// Configured via `listen: { tls: [{ address: ..., advertise: "..." }] }`.
    /// Falls back to the global `advertised_address` config when not set per-transport.
    pub advertised_addrs: std::collections::HashMap<Transport, String>,
    /// Per-transport listen address for HEP capture (so TLS responses report
    /// port 5061, not the UDP/TCP port 5060).
    pub listen_addrs: std::collections::HashMap<Transport, SocketAddr>,
    /// Every configured listener (transport + bound addr + advertised host).
    /// Backs `send_socket=` egress resolution — a script may only pin a source
    /// socket siphon is actually listening on, and the advertised host for the
    /// outgoing Via comes from the matched listener.
    pub listener_registry: crate::transport::ListenerRegistry,
    /// Path MTU (bytes) for the outbound UDP request path (RFC 3261 §18.1.1).
    /// `Some(mtu)` biases an over-`(mtu - 200)` UDP request to TCP; `None` = off.
    pub mtu: Option<u16>,
    /// Server header value injected into locally-generated responses.
    pub server_header: Option<String>,
    /// Answer an OPTIONS no script handler claims with 200 (`server.auto_options`).
    /// False drops it silently instead — see the config field for why.
    pub auto_options: bool,
    /// User-Agent header value for outbound requests (UAC, registrant).
    #[allow(dead_code)]
    pub user_agent_header: Option<String>,
    /// Transaction timeout for pending branch TTL.
    pub transaction_timeout: std::time::Duration,
    /// B2BUA call actor store (active when script has @b2bua handlers).
    pub call_actors: Arc<CallActorStore>,
    /// Transaction state machine manager.
    pub transaction_manager: Arc<TransactionManager>,
    /// Timer wheel — keyed by a unique timer ID string.
    /// Boxed: `hashbrown` sizes its bucket array for peak concurrency and never
    /// shrinks it, so an inline 176-byte `TimerEntry` meant a 200-byte bucket
    /// retained for the life of the process at the busiest moment the box ever
    /// saw. There is roughly one entry per live transaction timer, so the count
    /// tracks `rate x Timer J` the same way the transaction map did. Boxed the
    /// bucket is 32 bytes.
    pub timer_wheel: Arc<DashMap<String, Box<TimerEntry>>>,
    /// RFC 3261 §17.1 retransmission schedules for siphon-originated B2BUA
    /// requests. The proxy datapath gets Timer A / Timer E from the client
    /// transactions it registers; the B2BUA registers none (it owns its legs
    /// and routes responses by branch), so without this every B-leg INVITE,
    /// BYE and CANCEL left the socket exactly once and a single lost datagram
    /// stalled the call until the answer-timeout sweep.
    pub b2bua_retransmits: Arc<crate::b2bua::retransmit::B2buaRetransmits>,
    /// Proxy session store — links server transactions to client transactions.
    pub session_store: Arc<ProxySessionStore>,
    /// DNS resolver for SIP target resolution (RFC 3263).
    pub dns_resolver: Arc<SipResolver>,
    /// HEP capture sender (None when tracing is not configured).
    pub hep_sender: Option<Arc<HepSender>>,
    /// UAC sender for outbound requests (keepalive, health probes).
    pub uac_sender: Arc<UacSender>,
    /// Media-control backend — rtpengine NG or native siphon-rtp (None when
    /// `media` is not configured).
    pub rtpengine_set: Option<Arc<crate::rtpengine::MediaBackend>>,
    /// RTPEngine media session store (None when media is not configured).
    pub rtpengine_sessions: Option<Arc<crate::rtpengine::session::MediaSessionStore>>,
    /// RTPEngine media profile registry (None when media is not configured).
    pub rtpengine_profiles: Option<Arc<crate::rtpengine::ProfileRegistry>>,
    /// RFC 4028 session timer configuration (None when not configured).
    /// Hand every out-of-dialog INVITE to a control application, with no
    /// script (`control.inbound`). `Some` turns B2BUA mode on by itself, the
    /// way a registered `@b2bua.*` handler does.
    pub control_inbound: Option<crate::config::ControlInboundConfig>,
    pub session_timer_config: Option<crate::config::SessionTimerConfig>,
    /// B2BUA header policy library — keyed by qualified name (e.g.
    /// `"transparent-b2bua@2026"`).  Built once at startup by
    /// [`crate::b2bua::header_policy::build_registry`]: the built-in presets
    /// plus every operator-defined policy from `header_policies:`, in one
    /// namespace, so a script naming either resolves the same way.
    pub header_policy_registry:
        Arc<std::collections::HashMap<String, Arc<crate::b2bua::header_policy::Preset>>>,
    /// Default header policy applied when the script doesn't pass
    /// `header_policy=` on `call.dial()`.  Resolved from
    /// `config.b2bua.default_header_policy`, falling back to
    /// `"transparent-b2bua@2026"` if unset.
    pub default_header_policy: Arc<crate::b2bua::header_policy::Preset>,
    /// Default REFER transfer mode applied when an `@b2bua.on_refer` handler
    /// calls `accept_refer()` without an explicit `mode=`.  Resolved from
    /// `config.b2bua.default_refer_mode` (defaults to `Terminate`).
    pub default_refer_mode: crate::script::api::call::ReferMode,
    /// Whether an inbound `INVITE` with `Replaces` (RFC 3891) may take over the
    /// dialog it names. Resolved from `config.b2bua.accept_replaces`; **off**
    /// unless the operator turned it on, because possession of a dialog's
    /// identifiers is not authority to end that dialog (RFC 3891 §5).
    pub accept_replaces: bool,
    /// Whether every outbound B-leg INVITE is reported at `info` as it is
    /// handed to the transport. Resolved from `config.b2bua.log_dial`; **off**
    /// unless the operator turned it on — one line per call on the hottest
    /// path siphon has.
    pub log_dial: bool,
    /// Ceiling on how long an answered B2BUA call may run, for calls that do
    /// not set their own (`call.dial(max_duration=…)`). Resolved from
    /// `config.b2bua.max_call_duration_secs`; `None` = uncapped, which is the
    /// default and was the only behaviour before this existed.
    pub default_max_call_duration_secs: Option<u32>,
    /// Outbound registration manager (None when registrant is not configured).
    pub registrant_manager: Option<Arc<crate::registrant::RegistrantManager>>,
    /// SIPREC recording manager (SRC role — sends recordings to external SRS).
    pub recording_manager: Arc<crate::siprec::RecordingManager>,
    /// SRS URI from lawful_intercept.siprec config (used when li.record() is called).
    pub li_siprec_srs_uri: Option<String>,
    /// RTPEngine profile name for SIPREC SRC subscribe commands.
    pub li_siprec_rtpengine_profile: Option<String>,
    /// SRS — Session Recording Server manager (receives SIPREC INVITEs from external SRCs).
    pub srs_manager: Option<Arc<crate::srs::SrsManager>>,
    /// IPsec SA manager (None when ipsec is not configured).
    pub ipsec_manager: Option<Arc<crate::ipsec::IpsecManager>>,
    /// IPsec config (P-CSCF ports).
    pub ipsec_config: Option<crate::config::IpsecConfig>,
    /// Registrar liveness knobs (network-initiated deregistration).  Cloned
    /// from `config.registrar.liveness`; `enabled == false` (the default)
    /// makes the whole UDP+IPsec idle sweep a no-op.
    pub registrar_liveness: crate::config::RegistrarLivenessConfig,
    /// SIP-layer last-seen per registered IPsec UE (source IP → UNIX secs).
    /// Refreshed on any inbound message arriving on a P-CSCF protected port
    /// (REGISTER, SUBSCRIBE, in-dialog, and the OPTIONS 200 answer) and folded
    /// into the SA-idle sweep's idle test — a more reliable liveness signal
    /// than the kernel XFRM `use_time`, which on some kernels does not advance
    /// on an inbound-answered SA and so makes every binding look perpetually
    /// idle.  Bounded to live SAs: the sweep GCs entries whose IP has no SA,
    /// and `liveness_dereg_contact` prunes on reap.  Empty (and never written)
    /// unless `registrar_liveness.enabled`.
    pub liveness_last_seen: Arc<DashMap<std::net::IpAddr, u64>>,
    /// Consecutive-failed-sweep counter per AoR for the SA-idle probe
    /// hysteresis (AoR → miss count).  A suspect binding must miss its OPTIONS
    /// probe on `registrar_liveness.miss_threshold` consecutive sweeps before
    /// it is deregistered, so a UE racing an ECM-IDLE → paging window (misses
    /// one sweep, answers the next) is not false-reaped.  Cleared on any
    /// answer / recent activity; GCed with the registration set.
    pub liveness_misses: Arc<DashMap<String, u64>>,
    /// Outbound TCP/TLS connection pool for relay to new destinations.
    pub connection_pool: Arc<ConnectionPool>,
    /// Unified stream-connection registry: peer SocketAddr → (Transport,
    /// ConnectionId).  Populated by the TLS/WS/WSS listeners (inbound) and the
    /// connection pool (outbound TLS); used by `send_to_target` to reuse an
    /// existing connection when relaying to a registered endpoint (like
    /// OpenSIPS), and — for WebSocket — the only way to reach the UE at all
    /// (RFC 7118 §5 / RFC 5626 §5.3).
    pub stream_connections: StreamConnections,
    /// Automatically rewrite Contact URI in responses with the observed source
    /// address (from `nat.fix_contact` config).
    pub nat_fix_contact: bool,
    /// Name used in SDP `o=` and `s=` lines (from media.sdp_name config).
    pub sdp_name: String,
    /// Per-call event receivers from B-leg actors.
    /// Keyed by internal call ID; the receiver gets [`CallEvent`]s from all
    /// B-leg actors belonging to that call.
    pub call_event_receivers: Arc<DashMap<String, tokio::sync::mpsc::Receiver<CallEvent>>>,
    /// RFC 3262 — outstanding reliable provisional responses awaiting PRACK.
    /// Keyed by (Call-ID, RSeq); the entry carries a Notify the retransmit
    /// task watches for cancellation, plus the original CSeq number for RAck
    /// validation. Removed when PRACK arrives or the retransmit deadline hits.
    pub reliable_provisionals: Arc<DashMap<(String, u32), Arc<ReliableProvisional>>>,
    /// Outstanding B2BUA A-leg 2xx responses awaiting the caller's ACK.
    /// Keyed by internal call ID. RFC 3261 §13.3.1.4: the UAS *core* (not the
    /// transaction) retransmits a 2xx until ACK or 64×T1. The B2BUA intercepts
    /// the A-leg INVITE before an IST exists (see `handle_b2bua_invite`), and
    /// the IST steps aside on 2xx anyway ("TU owns retransmissions"), so nothing
    /// else recovers a lost A-leg 200 — without this the caller rings until it
    /// CANCELs. The entry's `Notify` is fired by the late-ACK handler when the
    /// caller's ACK arrives; the retransmit task otherwise gives up at 64×T1.
    pub uas_2xx_retransmits: Arc<DashMap<String, Arc<tokio::sync::Notify>>>,
    /// INVITE server transactions whose CANCEL has already been accepted,
    /// keyed by the INVITE's transaction key.
    ///
    /// RFC 3261 §9.2: a CANCEL is a request with its own server transaction, so
    /// a retransmitted CANCEL must be absorbed and answered from that
    /// transaction. siphon intercepts CANCEL *before* transaction creation (see
    /// `handle_cancel`), so no such transaction exists and nothing absorbs the
    /// retransmission — the proxy path removed the session on the first CANCEL,
    /// and the second fell through to `481 Call/Transaction Does Not Exist`
    /// even though the CANCEL had been accepted and the INVITE already 487'd.
    /// Over UDP that is the ordinary case, not an edge: Timer E retransmits the
    /// CANCEL at 500 ms whenever the 200 is lost.
    ///
    /// Entries live for 64×T1 (Timer J, 32 s) — the window a CANCEL's own NIST
    /// would have held its cached response — and are then dropped.
    /// The B2BUA path needs no entry: it already answers 200 to a CANCEL for a
    /// call that is no longer Calling/Ringing.
    pub cancelled_invites: Arc<DashMap<TransactionKey, ()>>,
    /// Shared drain state — the server flips `drain.is_draining` on
    /// SIGTERM/SIGINT. While set, new INVITEs are rejected with 503 Service
    /// Unavailable; in-dialog requests (ACK, BYE, PRACK, re-INVITE) and
    /// responses still flow so active calls can drain.
    pub is_draining: Arc<DrainState>,
    /// Rf offline-charging service (3GPP TS 32.299) — `None` when
    /// `rf:` is unset/disabled or no Diameter peers are configured.
    pub rf_charger: Option<Arc<crate::diameter::rf_service::RfChargingService>>,
    /// Per-record Rf state for proxy + B2BUA auto-emit.
    ///
    /// Keys (TS 32.260 §5.5 ICID + role suffix, with SIP-dialog
    /// fallback — see `crate::diameter::rf_service`):
    /// - `icid:<ICID>:orig` / `icid:<ICID>:term` — primary, deduplicates
    ///   iFC re-dispatch hits that share the same ICID.
    /// - `dialog:<Call-ID>\0<tag>:orig` / `dialog:<...>:term` — fallback
    ///   when ICID is absent, plus a co-stored alias of the ICID record
    ///   so STOP / CDR lookups still resolve when the in-dialog request
    ///   arrives without an ICID.
    /// - `b2bua:<internal-call-id>` — B2BUA path (no role suffix; no
    ///   dual-ACR support there yet).
    ///
    /// Values are wrapped in `Arc` so co-storing under multiple keys
    /// (ICID alias + dialog fallback) is just a refcount bump.  Empty
    /// when `rf_charger` is `None` so the auto-emit hot path branches
    /// out cheaply.
    pub rf_sessions: Arc<DashMap<String, Arc<ProxyRfState>>>,
    /// Primary `rf_sessions` keys with an ACR-START **in flight**, so the
    /// dedupe gate holds across the CDF round-trip.
    ///
    /// `rf_sessions` only gains an entry once ACR-START has been answered, but
    /// the two legs of an intra-node call are answered within milliseconds of
    /// each other — the S-CSCF's speculative dual-ACR terminating record
    /// (spawned off the originating leg's 2xx) and the terminating leg's own
    /// record both passed a `contains_key` check before either insert landed,
    /// so the node opened two TERMINATING records on one ICID.  Only one of
    /// them is reachable from the BYE, so the other never gets an ACR-STOP and
    /// emits an ACR-INTERIM every `interim_interval_secs` until the 24h
    /// max-lifetime backstop fires.
    ///
    /// Reserving the key synchronously — before the spawn — closes that
    /// window.  Entries are removed as soon as ACR-START resolves either way;
    /// the orphan sweep reaps any whose task died mid-flight.
    pub rf_pending_starts: Arc<DashMap<String, std::time::Instant>>,
    /// Ro online-charging service (RFC 8506 / TS 32.299) — `None` when `ro:`
    /// is unset/disabled or no Diameter peers are configured.
    pub ro_charger: Option<Arc<crate::diameter::ro_service::RoChargingService>>,
    /// Live per-call Ro credit sessions, keyed [`RO_B2BUA_KEY_PREFIX`] +
    /// internal call UUID, so the BYE handler can send CCR-TERMINATION. Empty
    /// when `ro_charger` is `None`; the mid-call teardown is driven Rust-side by
    /// the session's own re-auth timer, not from here.
    ///
    /// `call.ro_authorize()` reserves *before* the B-leg is connected, so unlike
    /// Rf — whose ACR-START only fires on a successful answer — this store has
    /// to survive everything that can end a call before it is answered, and
    /// every one of those paths owes it a release. [`check_orphaned_ro_sessions`]
    /// is the backstop that catches one that does not.
    pub ro_sessions: Arc<DashMap<String, crate::diameter::ro_service::CcCreditSession>>,
    /// Per-call CDR tracking for `cdr.auto_emit` (INVITE → answer → BYE).
    ///
    /// Keyed by the SIP dialog (`<Call-ID>\0<tag>`) for proxy calls and by the
    /// internal call UUID for B2BUA calls. Populated at INVITE, stamped with the
    /// answer time on 2xx, and drained (a CDR is written) when the call ends —
    /// BYE / failure / cancel / answer-timeout. Empty and cheaply skipped when
    /// `cdr.auto_emit` is off; the orphan sweep reaps any entry whose teardown
    /// never reached the dispatcher.
    pub cdr_sessions: Arc<DashMap<String, crate::cdr::CdrSession>>,
    /// Inbound REFERs on *controlled* B2BUA calls held un-answered while the
    /// owning control app decides (`accept_refer` / `reject_refer`). Populated by
    /// [`handle_b2bua_refer`] only when the call is controlled; drained on accept
    /// / reject / the decision-deadline sweep. Empty and cheaply skipped when no
    /// control plane is configured (no call is ever controlled).
    pub pending_inbound_refer: Arc<PendingInboundReferStore>,
    /// `BYE`s owed to a transfer referrer, held until the terminating `NOTIFY`
    /// sharing their dialog has been answered — see [`DeferredReferrerByeStore`].
    /// Empty except while a siphon-terminated transfer is completing.
    pub deferred_referrer_bye: Arc<DeferredReferrerByeStore>,
    /// Lawful interception. `None` when `lawful_intercept.enabled` is false.
    ///
    /// The dispatcher consults this on every message, so interception does not
    /// depend on the operator's script calling anything — see
    /// [`intercept_message`].
    pub li_manager: Option<crate::li::LiManager>,
}

/// Bundle held in `DispatcherState::rf_sessions` so ACR-STOP can reuse
/// the IMS data captured at ACR-START (calling/called party, ICID, IOI,
/// User-Session-Id, etc.) and just update the cause_code from the BYE.
///
/// Multiple map entries may point at the same `Arc<ProxyRfState>` —
/// every record is co-stored under both the ICID-keyed primary and a
/// SIP-dialog fallback so lookups via either path resolve identically.
pub struct ProxyRfState {
    pub session: crate::diameter::rf_service::RfChargingSession,
    pub ims_data: crate::diameter::ro::ImsChargingData,
    pub user_name: Option<String>,
    /// Every storage key under which this record is filed.  Used by
    /// the STOP path so a single found-by-X lookup can clean up all
    /// the aliases without scanning the map.
    pub storage_keys: Vec<String>,
    /// When this record was created.  Used by the orphan backstop sweep
    /// (`sweep_stale_entries`) to reap Rf sessions whose ACR-STOP never
    /// fired (call torn down without a BYE reaching the dispatcher).
    /// Normal calls are reaped on BYE; this only catches orphans.
    pub created_at: std::time::Instant,
}

impl ProxyRfState {
    /// Public accessor used by CDR auto-stamp callers.
    pub(crate) fn rf_session(&self) -> &crate::diameter::rf_service::RfChargingSession {
        &self.session
    }
}

/// State for one outstanding reliable provisional response (RFC 3262 §3).
pub struct ReliableProvisional {
    /// Notified by the dispatcher when a matching PRACK arrives, or when the
    /// retransmit task itself decides to give up. The retransmit loop selects
    /// on this; once notified it stops sending and exits.
    pub cancel: tokio::sync::Notify,
    /// CSeq number of the INVITE the response belongs to. Used to validate
    /// the RAck — a PRACK whose RAck cseq doesn't match this is not for us.
    pub cseq_num: u32,
}

/// Log a Python handler failure and count it in `siphon_script_errors_total`.
///
/// Every handler-invocation site routes its error through here so the counter
/// cannot drift from the log. It previously did not exist and the counter was
/// declared but never incremented — which is what happens when thirty-odd call
/// sites each have to remember to bump it. `context` names the handler, e.g.
/// `"B2BUA on_invite"`.
pub fn record_script_error(context: &str, error: &dyn std::fmt::Display) {
    error!("{context} handler error: {error}");
    if let Some(metrics) = crate::metrics::try_metrics() {
        metrics.script_errors_total.inc();
    }
}

/// Publish the live-store gauges: active transactions, active B2BUA calls, and
/// the `dialogs_active` roll-up.
///
/// Shared by the 30 s dispatcher sweep (which drives the Prometheus scrape) and
/// by `/admin/metrics.json` (which needs them fresh per poll), so the two can't
/// drift apart. All three inputs must be O(1) `len()` reads — this runs on every
/// dashboard poll, so nothing here may iterate a store.
pub fn publish_store_gauges(
    metrics: &crate::metrics::SiphonMetrics,
    transactions: usize,
    b2bua_calls: usize,
    proxy_dialog_sessions: usize,
) {
    metrics.transactions_active.set(transactions as i64);
    metrics.b2bua_calls_active.set(b2bua_calls as i64);
    // `dialogs_active` is the documented sum of the proxy and B2BUA halves;
    // the two components are also exported separately because which side is
    // carrying the load is the actually useful question.
    metrics
        .dialogs_active
        .set((proxy_dialog_sessions + b2bua_calls) as i64);
}

/// Shared drain state — server flips `is_draining` on signal; dispatcher fills
/// in `transaction_manager` and `call_actors` at startup so the server can poll
/// counts during the drain wait.
pub struct DrainState {
    pub is_draining: std::sync::atomic::AtomicBool,
    pub transaction_manager: std::sync::OnceLock<Arc<TransactionManager>>,
    pub call_actors: std::sync::OnceLock<Arc<CallActorStore>>,
}

impl DrainState {
    pub fn new() -> Self {
        Self {
            is_draining: std::sync::atomic::AtomicBool::new(false),
            transaction_manager: std::sync::OnceLock::new(),
            call_actors: std::sync::OnceLock::new(),
        }
    }

    /// Active transaction count, or 0 before the dispatcher registers its
    /// manager.
    ///
    /// Unlike [`active_counts`](Self::active_counts) this is an O(1) `len()`,
    /// so it is safe on the `/admin/metrics.json` poll path — the call half of
    /// `active_counts` sorts and de-duplicates the leg registry, which is fine
    /// once per drain iteration but not once every two seconds.
    pub fn transaction_count(&self) -> usize {
        self.transaction_manager
            .get()
            .map(|manager| manager.count())
            .unwrap_or(0)
    }

    /// Number of (transactions, b2bua_calls) currently active. Returns
    /// `(0, 0)` until the dispatcher has registered its managers.
    pub fn active_counts(&self) -> (usize, usize) {
        let txs = self
            .transaction_manager
            .get()
            .map(|tm| tm.count())
            .unwrap_or(0);
        let calls = self
            .call_actors
            .get()
            .map(|ca| ca.registry.call_count())
            .unwrap_or(0);
        (txs, calls)
    }
}

impl Default for DrainState {
    fn default() -> Self {
        Self::new()
    }
}

impl DispatcherState {
    /// Return the host (IP or hostname) to use in Via headers for the given transport.
    ///
    /// Prefers the per-transport advertised address (public IP) when configured,
    /// falling back to the local bind address.  The result is already formatted
    /// for SIP (IPv6 addresses are bracketed).
    pub fn via_host(&self, transport: &Transport) -> String {
        self.advertised_addrs
            .get(transport)
            .map(|h| format_sip_host(h))
            .unwrap_or_else(|| format_sip_host(&self.local_addr.ip().to_string()))
    }

    /// Return the port to use in Via/Contact headers for the given transport.
    pub fn via_port(&self, transport: &Transport) -> u16 {
        self.listen_addrs
            .get(transport)
            .map(|a| a.port())
            .unwrap_or(self.local_addr.port())
    }

    /// Family-matched host to advertise to the A-leg (Contact / Via /
    /// Record-Route), selected from the socket the request arrived on.
    ///
    /// Host-side analogue of [`a_leg_advertised_port`].  `via_host` keys only on
    /// transport and so collapses to the first configured listener's family — on
    /// a dual-stack P-CSCF a UE that registered over IPv6 would get the IPv4
    /// advertised host stamped on its responses.  Passing the arrival socket
    /// (`inbound.local_addr` / `leg.transport.local_addr`) selects the
    /// family-correct identity.  `None` (arrival socket unknown — e.g. a
    /// core-facing outbound leg) reproduces the legacy per-transport `via_host`.
    pub fn a_leg_advertised_host(
        &self,
        a_leg_local_addr: Option<SocketAddr>,
        transport: &Transport,
    ) -> String {
        resolve_advertised_host(
            &self.listener_registry,
            &self.advertised_addrs,
            self.local_addr.ip(),
            a_leg_local_addr,
            transport,
        )
    }

    /// Resolve siphon's own endpoint to report in a HEP capture for `transport`.
    ///
    /// When siphon binds to the wildcard address (`0.0.0.0` / `[::]`, the usual
    /// production `listen` config), the raw bind/recv address is unspecified and
    /// renders as `0.0.0.0` in Homer — hiding which node/interface the leg
    /// belongs to and breaking IP-based correlation. Substitute the advertised
    /// address (the same resolution Via/Contact use, per transport) so the
    /// capture carries siphon's real address. The candidate's port is preserved,
    /// and a non-unspecified candidate passes through unchanged.
    pub fn hep_local_addr(&self, candidate: SocketAddr, transport: Transport) -> SocketAddr {
        // `advertised_addrs` is the merged map — the global `advertised_address`
        // is already folded into every listener transport at startup — so the
        // trailing `None` never drops the global fallback.
        crate::uac::resolve_via_addr(candidate, &transport, &self.advertised_addrs, None)
    }

    /// Resolve a script `send_socket=` spec against the configured listeners.
    ///
    /// Returns `Some(SendSocket)` only when the spec is well-formed AND names a
    /// socket siphon is actually listening on.  A malformed spec can't reach
    /// here (the script API rejects it with `ValueError`); a well-formed spec
    /// that doesn't match any listener warns and returns `None`, so the caller
    /// falls back to default routing rather than dropping the request —
    /// silently dropping would violate the "always answer" invariant, and an
    /// operator typo shouldn't blackhole calls.
    pub fn resolve_send_socket(&self, spec: Option<&str>) -> Option<crate::transport::SendSocket> {
        let spec = spec?;
        match crate::transport::parse_send_socket(spec) {
            Ok((transport, addr)) => {
                let resolved = self.listener_registry.resolve(transport, addr);
                if resolved.is_none() {
                    warn!(
                        send_socket = %spec,
                        "send_socket names no configured listener — falling back to default routing"
                    );
                }
                resolved
            }
            Err(error) => {
                // Should be unreachable (validated at the API), but never panic.
                warn!(send_socket = %spec, "ignoring malformed send_socket: {error}");
                None
            }
        }
    }

    /// Resolve the header policy for a B2BUA call.  Returns the per-call
    /// policy when the script attached one via `call.dial(header_policy=…)`,
    /// otherwise the configured default.
    pub fn resolve_header_policy(
        &self,
        call_id: &str,
    ) -> crate::b2bua::header_policy::ResolvedPolicy {
        if let Some(call) = self.call_actors.get_call(call_id) {
            if let Some(ref p) = call.resolved_header_policy {
                return (**p).clone();
            }
        }
        crate::b2bua::header_policy::ResolvedPolicy::from_preset(self.default_header_policy.clone())
    }

    /// Check whether a resolved destination points back to one of our own
    /// listen addresses (loop detection).  Checks the primary `local_addr` and
    /// **every** configured listener via `listener_registry` — on a multi-homed
    /// / dual-stack host `listen_addrs` keeps only the first listener per
    /// transport, so a destination on the second-family (or second-port)
    /// listener would otherwise slip through.
    pub fn is_own_address(&self, destination: &std::net::SocketAddr) -> bool {
        let ip = destination.ip();
        let port = destination.port();

        // Check primary listen address (the resolved via_addr, which may not be
        // an exact registry entry when bound to a wildcard).
        if port == self.local_addr.port() && (ip == self.local_addr.ip() || ip.is_loopback()) {
            return true;
        }

        // Check every configured listener (both families, all transports).
        self.listener_registry.matches_local(destination)
    }
}

/// Bound on one event-handler invocation from a background drain loop.
///
/// Generous — a media or registrar handler may legitimately do a Diameter round
/// trip — but well under the script executor's own stall window, so the drain
/// loop always gives up before the watchdog would.
#[cfg(not(test))]
pub const EVENT_HANDLER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// Shortened under test only. The regression asserts *relative* to this value
/// ("it waited out its own window"), never against an absolute number, so the
/// shorter value tests the same property without costing the suite ten seconds
/// per run. A stuck handler blocks a real thread, so paused time cannot be used
/// here — the runtime never goes idle enough to auto-advance.
#[cfg(test)]
pub const EVENT_HANDLER_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(200);

/// Invoke a script handler from a background event loop without letting one
/// stuck handler stop the loop.
///
/// These loops `recv` from a bounded channel and previously `.await`ed the
/// handler inline, so a handler that never returned stopped the whole drain.
/// For media events that is not a lost DTMF digit: the channel fills, the media
/// engine's control **read** task parks trying to enqueue the next event, no
/// response is routed back to its pending request any more, and every in-flight
/// and future media command fails on its own timeout — media control dead
/// process-wide, connection still established.
///
/// The handler is still awaited rather than spawned, so events keep their
/// order (DTMF digits arriving out of order would break any IVR reading them);
/// only the wait is bounded. The result was already discarded, so abandoning it
/// costs nothing — the job itself runs on, and the executor's own watchdog is
/// what covers a handler that never finishes.
pub async fn run_event_handler<F>(kind: &'static str, handler: F)
where
    F: FnOnce() + Send + 'static,
{
    if tokio::time::timeout(
        EVENT_HANDLER_TIMEOUT,
        crate::script::py_executor::try_run(handler),
    )
    .await
    .is_err()
    {
        warn!(
            handler = kind,
            timeout = ?EVENT_HANDLER_TIMEOUT,
            "script event handler did not return within the window — continuing to \
             drain events rather than letting one handler stop the loop (the \
             handler itself is still running; the executor watchdog covers it)"
        );
    }
}
