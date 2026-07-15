//! Core request dispatcher — glue between transport and script engine.
//!
//! Receives raw SIP bytes from the transport layer, parses them, invokes
//! Python script handlers, and sends responses back through the transport.
//! Implements stateless proxy relay with Via-based response routing.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};

use bytes::Bytes;
use dashmap::DashMap;
use pyo3::prelude::*;
use tracing::{debug, error, info, warn};

use crate::b2bua::actor::{CallActorStore, CallEvent, CallState, Leg, LegActor, TransportInfo as LegTransport};
use crate::dns::SipResolver;
use crate::config::Config;
use crate::proxy::core;
use crate::proxy::session::{ClientBranch, ProxySession, ProxySessionStore};
use crate::registrar::{Registrar, RegistrarConfig};
use crate::script::api::auth::PyAuth;
use crate::script::api::call::{CallAction, PyByeInitiator, PyCall};
use crate::script::api::log::PyLogNamespace;
use crate::script::api::registrar::PyRegistrar;
use crate::script::api::reply::PyReply;
use crate::script::api::request::{LocalDomains, PyRequest, RequestAction};
use crate::script::engine::{HandlerKind, ScriptEngine, run_coroutine};
use crate::sip::builder::SipMessageBuilder;
use crate::sip::headers::via::Via;
use crate::sip::message::{Method, RequestLine, SipMessage, StartLine, StatusLine, Version};
use crate::sip::headers::SipHeaders;
use crate::sip::uri::SipUri;
use crate::sip::parser::{parse_sip_message_bytes, parse_uri_standalone};
use crate::sip::uri::format_sip_host;
use crate::transaction::key::TransactionKey;
use crate::transaction::state::{
    Action, TimerName,
    IstEvent, NistEvent, IctEvent, NictEvent,
};
use crate::transaction::{TransactionManager, ServerEvent, ClientEvent};
use crate::transaction::timer::TimerConfig;
use crate::hep::HepSender;
use crate::transport::{ConnectionId, InboundMessage, OutboundMessage, OutboundRouter, StreamConnections, Transport};
use crate::transport::pool::ConnectionPool;
use crate::uac::UacSender;

/// RTPEngine wiring produced by [`init_rtpengine`]: the media-control backend
/// (rtpengine NG or native siphon-rtp), the media session store, and the
/// profile registry. Each component is present only when `media` is configured
/// (otherwise all three are `None`).
type RtpEngineComponents = (
    Option<Arc<crate::rtpengine::MediaBackend>>,
    Option<Arc<crate::rtpengine::session::MediaSessionStore>>,
    Option<Arc<crate::rtpengine::ProfileRegistry>>,
);

/// A pending timer entry in the timer wheel.
#[derive(Debug, Clone)]
struct TimerEntry {
    /// Transaction this timer belongs to.
    key: TransactionKey,
    /// Which timer.
    name: TimerName,
    /// When this timer fires.
    fires_at: std::time::Instant,
    /// Destination for retransmits (client transactions).
    destination: Option<SocketAddr>,
    /// Transport for retransmits.
    transport: Option<Transport>,
    /// Connection ID for sending.
    connection_id: Option<ConnectionId>,
    /// Local socket the original request arrived on — required by
    /// 3GPP TS 33.203 §7.4 so retransmitted server-transaction-cached
    /// responses egress on the same SA's local endpoint as the
    /// original.  None for client transactions or when the source
    /// doesn't matter (TCP/TLS connection-affine sends).
    source_local_addr: Option<SocketAddr>,
}

/// Shared state for the dispatcher, passed to each spawned task.
struct DispatcherState {
    engine: Arc<ScriptEngine>,
    outbound: Arc<OutboundRouter>,
    local_domains: LocalDomains,
    local_addr: SocketAddr,
    /// Per-transport advertised host (hostname or IP) for Record-Route/Via.
    /// Configured via `listen: { tls: [{ address: ..., advertise: "..." }] }`.
    /// Falls back to the global `advertised_address` config when not set per-transport.
    advertised_addrs: std::collections::HashMap<Transport, String>,
    /// Per-transport listen address for HEP capture (so TLS responses report
    /// port 5061, not the UDP/TCP port 5060).
    listen_addrs: std::collections::HashMap<Transport, SocketAddr>,
    /// Every configured listener (transport + bound addr + advertised host).
    /// Backs `send_socket=` egress resolution — a script may only pin a source
    /// socket siphon is actually listening on, and the advertised host for the
    /// outgoing Via comes from the matched listener.
    listener_registry: crate::transport::ListenerRegistry,
    /// Server header value injected into locally-generated responses.
    server_header: Option<String>,
    /// User-Agent header value for outbound requests (UAC, registrant).
    #[allow(dead_code)]
    user_agent_header: Option<String>,
    /// Transaction timeout for pending branch TTL.
    transaction_timeout: std::time::Duration,
    /// B2BUA call actor store (active when script has @b2bua handlers).
    call_actors: Arc<CallActorStore>,
    /// Transaction state machine manager.
    transaction_manager: Arc<TransactionManager>,
    /// Timer wheel — keyed by a unique timer ID string.
    timer_wheel: Arc<DashMap<String, TimerEntry>>,
    /// Proxy session store — links server transactions to client transactions.
    session_store: Arc<ProxySessionStore>,
    /// DNS resolver for SIP target resolution (RFC 3263).
    dns_resolver: Arc<SipResolver>,
    /// HEP capture sender (None when tracing is not configured).
    hep_sender: Option<Arc<HepSender>>,
    /// UAC sender for outbound requests (keepalive, health probes).
    uac_sender: Arc<UacSender>,
    /// Media-control backend — rtpengine NG or native siphon-rtp (None when
    /// `media` is not configured).
    rtpengine_set: Option<Arc<crate::rtpengine::MediaBackend>>,
    /// RTPEngine media session store (None when media is not configured).
    rtpengine_sessions: Option<Arc<crate::rtpengine::session::MediaSessionStore>>,
    /// RTPEngine media profile registry (None when media is not configured).
    rtpengine_profiles: Option<Arc<crate::rtpengine::ProfileRegistry>>,
    /// RFC 4028 session timer configuration (None when not configured).
    session_timer_config: Option<crate::config::SessionTimerConfig>,
    /// B2BUA header policy preset library — keyed by qualified name
    /// (e.g. `"transparent-b2bua@2026"`).  Built once at startup from
    /// [`crate::b2bua::header_policy::builtin_presets`].
    header_policy_registry: Arc<std::collections::HashMap<String, Arc<crate::b2bua::header_policy::Preset>>>,
    /// Default header policy applied when the script doesn't pass
    /// `header_policy=` on `call.dial()`.  Resolved from
    /// `config.b2bua.default_header_policy`, falling back to
    /// `"transparent-b2bua@2026"` if unset.
    default_header_policy: Arc<crate::b2bua::header_policy::Preset>,
    /// Outbound registration manager (None when registrant is not configured).
    registrant_manager: Option<Arc<crate::registrant::RegistrantManager>>,
    /// SIPREC recording manager (SRC role — sends recordings to external SRS).
    recording_manager: Arc<crate::siprec::RecordingManager>,
    /// SRS URI from lawful_intercept.siprec config (used when li.record() is called).
    li_siprec_srs_uri: Option<String>,
    /// RTPEngine profile name for SIPREC SRC subscribe commands.
    li_siprec_rtpengine_profile: Option<String>,
    /// SRS — Session Recording Server manager (receives SIPREC INVITEs from external SRCs).
    srs_manager: Option<Arc<crate::srs::SrsManager>>,
    /// IPsec SA manager (None when ipsec is not configured).
    ipsec_manager: Option<Arc<crate::ipsec::IpsecManager>>,
    /// IPsec config (P-CSCF ports).
    ipsec_config: Option<crate::config::IpsecConfig>,
    /// Registrar liveness knobs (network-initiated deregistration).  Cloned
    /// from `config.registrar.liveness`; `enabled == false` (the default)
    /// makes the whole UDP+IPsec idle sweep a no-op.
    registrar_liveness: crate::config::RegistrarLivenessConfig,
    /// SIP-layer last-seen per registered IPsec UE (source IP → UNIX secs).
    /// Refreshed on any inbound message arriving on a P-CSCF protected port
    /// (REGISTER, SUBSCRIBE, in-dialog, and the OPTIONS 200 answer) and folded
    /// into the SA-idle sweep's idle test — a more reliable liveness signal
    /// than the kernel XFRM `use_time`, which on some kernels does not advance
    /// on an inbound-answered SA and so makes every binding look perpetually
    /// idle.  Bounded to live SAs: the sweep GCs entries whose IP has no SA,
    /// and `liveness_dereg_contact` prunes on reap.  Empty (and never written)
    /// unless `registrar_liveness.enabled`.
    liveness_last_seen: Arc<DashMap<std::net::IpAddr, u64>>,
    /// Consecutive-failed-sweep counter per AoR for the SA-idle probe
    /// hysteresis (AoR → miss count).  A suspect binding must miss its OPTIONS
    /// probe on `registrar_liveness.miss_threshold` consecutive sweeps before
    /// it is deregistered, so a UE racing an ECM-IDLE → paging window (misses
    /// one sweep, answers the next) is not false-reaped.  Cleared on any
    /// answer / recent activity; GCed with the registration set.
    liveness_misses: Arc<DashMap<String, u64>>,
    /// Outbound TCP/TLS connection pool for relay to new destinations.
    connection_pool: Arc<ConnectionPool>,
    /// Unified stream-connection registry: peer SocketAddr → (Transport,
    /// ConnectionId).  Populated by the TLS/WS/WSS listeners (inbound) and the
    /// connection pool (outbound TLS); used by `send_to_target` to reuse an
    /// existing connection when relaying to a registered endpoint (like
    /// OpenSIPS), and — for WebSocket — the only way to reach the UE at all
    /// (RFC 7118 §5 / RFC 5626 §5.3).
    stream_connections: StreamConnections,
    /// Automatically rewrite Contact URI in responses with the observed source
    /// address (from `nat.fix_contact` config).
    nat_fix_contact: bool,
    /// Name used in SDP `o=` and `s=` lines (from media.sdp_name config).
    sdp_name: String,
    /// Per-call event receivers from B-leg actors.
    /// Keyed by internal call ID; the receiver gets [`CallEvent`]s from all
    /// B-leg actors belonging to that call.
    call_event_receivers: Arc<DashMap<String, tokio::sync::mpsc::Receiver<CallEvent>>>,
    /// RFC 3262 — outstanding reliable provisional responses awaiting PRACK.
    /// Keyed by (Call-ID, RSeq); the entry carries a Notify the retransmit
    /// task watches for cancellation, plus the original CSeq number for RAck
    /// validation. Removed when PRACK arrives or the retransmit deadline hits.
    reliable_provisionals: Arc<DashMap<(String, u32), Arc<ReliableProvisional>>>,
    /// Outstanding B2BUA A-leg 2xx responses awaiting the caller's ACK.
    /// Keyed by internal call ID. RFC 3261 §13.3.1.4: the UAS *core* (not the
    /// transaction) retransmits a 2xx until ACK or 64×T1. The B2BUA intercepts
    /// the A-leg INVITE before an IST exists (see `handle_b2bua_invite`), and
    /// the IST steps aside on 2xx anyway ("TU owns retransmissions"), so nothing
    /// else recovers a lost A-leg 200 — without this the caller rings until it
    /// CANCELs. The entry's `Notify` is fired by the late-ACK handler when the
    /// caller's ACK arrives; the retransmit task otherwise gives up at 64×T1.
    uas_2xx_retransmits: Arc<DashMap<String, Arc<tokio::sync::Notify>>>,
    /// Shared drain state — the server flips `drain.is_draining` on
    /// SIGTERM/SIGINT. While set, new INVITEs are rejected with 503 Service
    /// Unavailable; in-dialog requests (ACK, BYE, PRACK, re-INVITE) and
    /// responses still flow so active calls can drain.
    pub is_draining: Arc<DrainState>,
    /// Rf offline-charging service (3GPP TS 32.299) — `None` when
    /// `rf:` is unset/disabled or no Diameter peers are configured.
    rf_charger: Option<Arc<crate::diameter::rf_service::RfChargingService>>,
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
    rf_sessions: Arc<DashMap<String, Arc<ProxyRfState>>>,
    /// Per-call CDR tracking for `cdr.auto_emit` (INVITE → answer → BYE).
    ///
    /// Keyed by the SIP dialog (`<Call-ID>\0<tag>`) for proxy calls and by the
    /// internal call UUID for B2BUA calls. Populated at INVITE, stamped with the
    /// answer time on 2xx, and drained (a CDR is written) when the call ends —
    /// BYE / failure / cancel / answer-timeout. Empty and cheaply skipped when
    /// `cdr.auto_emit` is off; the orphan sweep reaps any entry whose teardown
    /// never reached the dispatcher.
    cdr_sessions: Arc<DashMap<String, crate::cdr::CdrSession>>,
}

/// Bundle held in `DispatcherState::rf_sessions` so ACR-STOP can reuse
/// the IMS data captured at ACR-START (calling/called party, ICID, IOI,
/// User-Session-Id, etc.) and just update the cause_code from the BYE.
///
/// Multiple map entries may point at the same `Arc<ProxyRfState>` —
/// every record is co-stored under both the ICID-keyed primary and a
/// SIP-dialog fallback so lookups via either path resolve identically.
pub(crate) struct ProxyRfState {
    session: crate::diameter::rf_service::RfChargingSession,
    ims_data: crate::diameter::ro::ImsChargingData,
    user_name: Option<String>,
    /// Every storage key under which this record is filed.  Used by
    /// the STOP path so a single found-by-X lookup can clean up all
    /// the aliases without scanning the map.
    storage_keys: Vec<String>,
    /// When this record was created.  Used by the orphan backstop sweep
    /// (`sweep_stale_entries`) to reap Rf sessions whose ACR-STOP never
    /// fired (call torn down without a BYE reaching the dispatcher).
    /// Normal calls are reaped on BYE; this only catches orphans.
    created_at: std::time::Instant,
}

impl ProxyRfState {
    /// Public accessor used by CDR auto-stamp callers.
    pub(crate) fn rf_session(&self) -> &crate::diameter::rf_service::RfChargingSession {
        &self.session
    }
}

/// Format the B2BUA Rf-session key from the internal call UUID.
fn rf_b2bua_key(internal_call_id: &str) -> String {
    format!("b2bua:{internal_call_id}")
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

/// Shared drain state — server flips `is_draining` on signal; dispatcher fills
/// in `transaction_manager` and `call_actors` at startup so the server can poll
/// counts during the drain wait.
pub struct DrainState {
    pub is_draining: std::sync::atomic::AtomicBool,
    transaction_manager: std::sync::OnceLock<Arc<TransactionManager>>,
    call_actors: std::sync::OnceLock<Arc<CallActorStore>>,
}

impl DrainState {
    pub fn new() -> Self {
        Self {
            is_draining: std::sync::atomic::AtomicBool::new(false),
            transaction_manager: std::sync::OnceLock::new(),
            call_actors: std::sync::OnceLock::new(),
        }
    }

    /// Number of (transactions, b2bua_calls) currently active. Returns
    /// `(0, 0)` until the dispatcher has registered its managers.
    pub fn active_counts(&self) -> (usize, usize) {
        let txs = self.transaction_manager.get().map(|tm| tm.count()).unwrap_or(0);
        let calls = self.call_actors.get().map(|ca| ca.registry.call_count()).unwrap_or(0);
        (txs, calls)
    }
}

impl Default for DrainState {
    fn default() -> Self { Self::new() }
}

impl DispatcherState {
    /// Return the host (IP or hostname) to use in Via headers for the given transport.
    ///
    /// Prefers the per-transport advertised address (public IP) when configured,
    /// falling back to the local bind address.  The result is already formatted
    /// for SIP (IPv6 addresses are bracketed).
    fn via_host(&self, transport: &Transport) -> String {
        self.advertised_addrs
            .get(transport)
            .map(|h| format_sip_host(h))
            .unwrap_or_else(|| format_sip_host(&self.local_addr.ip().to_string()))
    }

    /// Return the port to use in Via/Contact headers for the given transport.
    fn via_port(&self, transport: &Transport) -> u16 {
        self.listen_addrs
            .get(transport)
            .map(|a| a.port())
            .unwrap_or(self.local_addr.port())
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
    fn hep_local_addr(&self, candidate: SocketAddr, transport: Transport) -> SocketAddr {
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
    fn resolve_send_socket(
        &self,
        spec: Option<&str>,
    ) -> Option<crate::transport::SendSocket> {
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
    fn resolve_header_policy(
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
    /// listen addresses (loop detection).  Checks the primary `local_addr`
    /// AND every per-transport listen address in `listen_addrs`.
    fn is_own_address(&self, destination: &std::net::SocketAddr) -> bool {
        let ip = destination.ip();
        let port = destination.port();
        let ip_matches = |listen_ip: std::net::IpAddr| {
            ip == listen_ip || ip.is_loopback()
        };

        // Check primary listen address
        if port == self.local_addr.port() && ip_matches(self.local_addr.ip()) {
            return true;
        }

        // Check all per-transport listen addresses (e.g. TLS on :5061)
        for addr in self.listen_addrs.values() {
            if port == addr.port() && ip_matches(addr.ip()) {
                return true;
            }
        }

        false
    }
}

/// Run the core dispatcher loop.
///
/// Reads inbound messages from transport, parses, invokes Python handlers,
/// and sends responses back via the outbound channel.
// Wide by necessity: the dispatcher loop is wired to every transport channel,
// store, and engine handle at startup, exceeding the configured threshold.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    inbound_rx: flume::Receiver<InboundMessage>,
    outbound: Arc<OutboundRouter>,
    engine: Arc<ScriptEngine>,
    config: Arc<Config>,
    local_addr: SocketAddr,
    listen_addrs: std::collections::HashMap<Transport, SocketAddr>,
    advertised_addrs: std::collections::HashMap<Transport, String>,
    listener_registry: crate::transport::ListenerRegistry,
    hep_sender: Option<Arc<HepSender>>,
    uac_sender: Arc<UacSender>,
    connection_pool: Arc<ConnectionPool>,
    pre_rtpengine: RtpEngineComponents,
    registrant_manager: Option<Arc<crate::registrant::RegistrantManager>>,
    ipsec_manager: Option<Arc<crate::ipsec::IpsecManager>>,
    ipsec_config: Option<crate::config::IpsecConfig>,
    stream_connections: StreamConnections,
    registrar_event_rx: Option<tokio::sync::broadcast::Receiver<crate::registrar::RegistrationEvent>>,
    diameter_incoming_rx: tokio::sync::mpsc::Receiver<(
        crate::diameter::peer::IncomingRequest,
        std::sync::Arc<crate::diameter::peer::DiameterPeer>,
    )>,
    rtpengine_events_rx: tokio::sync::mpsc::Receiver<crate::rtpengine::events::RtpEngineEvent>,
    rf_charger: Option<Arc<crate::diameter::rf_service::RfChargingService>>,
    drain: Arc<DrainState>,
    product_name: &'static str,
    product_version: &'static str,
) {
    // Resolve the local address for Via insertion.
    // If bound to 0.0.0.0 / [::], use advertised_address from config, or loopback.
    let via_addr = if local_addr.ip().is_unspecified() {
        let fallback = if local_addr.is_ipv6() { "::1" } else { "127.0.0.1" };
        let host = config
            .advertised_address
            .as_deref()
            .unwrap_or(fallback);
        if config.advertised_address.is_none() {
            warn!(
                bind = %local_addr,
                "binding to unspecified address with no `advertised_address` configured — \
                 Via/Contact will use {fallback}; remote peers will not be able to reach this instance"
            );
        }
        let ip: std::net::IpAddr = host
            .parse()
            .unwrap_or_else(|_| {
                if local_addr.is_ipv6() {
                    std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
                } else {
                    std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
                }
            });
        SocketAddr::new(ip, local_addr.port())
    } else {
        local_addr
    };

    let default_server = format!("{product_name}/{product_version}");
    let server_header = Some(
        config
            .server
            .as_ref()
            .and_then(|s| s.server_header.clone())
            .unwrap_or_else(|| default_server.clone()),
    );
    let user_agent_header = Some(
        config
            .server
            .as_ref()
            .and_then(|s| s.user_agent_header.clone())
            .unwrap_or(default_server),
    );

    let tx_config = config.transaction.as_ref();
    let transaction_timeout = std::time::Duration::from_secs(
        tx_config.map(|t| t.invite_timeout_secs as u64).unwrap_or(30) + 2,
    );
    let _non_invite_timeout = std::time::Duration::from_secs(
        tx_config.map(|t| t.timeout_secs as u64).unwrap_or(5),
    );

    let timer_config = {
        let mut config = TimerConfig::default();
        if let Some(tx) = tx_config {
            config.auto_100_trying = tx.auto_emit_100_trying;
            config.auto_100_delay = std::time::Duration::from_millis(tx.auto_emit_100_trying_delay_ms);
        }
        config
    };
    let transaction_manager = Arc::new(TransactionManager::new(timer_config));

    let dns_resolver = Arc::new(match SipResolver::from_system() {
        Ok(resolver) => resolver,
        Err(error) => {
            error!("failed to initialize DNS resolver: {error}");
            return;
        }
    });

    let (rtpengine_set, rtpengine_sessions, rtpengine_profiles) = pre_rtpengine;

    // Merge per-transport advertised addresses with global advertised_address fallback.
    // Per-transport takes precedence; global fills in any transport that lacks one.
    let mut merged_advertised = advertised_addrs;
    if let Some(ref global_adv) = config.advertised_address {
        for &transport in listen_addrs.keys() {
            merged_advertised.entry(transport).or_insert_with(|| global_adv.clone());
        }
    }

    // B2BUA header policy library — built-in presets only in v1.
    let header_policy_registry = Arc::new(crate::b2bua::header_policy::builtin_presets());
    let default_policy_name = config
        .b2bua
        .default_header_policy
        .as_deref()
        .unwrap_or("transparent-b2bua@2026");
    let default_header_policy = header_policy_registry
        .get(default_policy_name)
        .cloned()
        .unwrap_or_else(|| {
            warn!(
                requested = %default_policy_name,
                "b2bua.default_header_policy unknown — falling back to transparent-b2bua@2026"
            );
            header_policy_registry
                .get("transparent-b2bua@2026")
                .cloned()
                .expect("builtin transparent-b2bua@2026 must exist")
        });

    // Publish the call store for read-only observability (admin `/admin/calls`)
    // before it's moved into the dispatcher state.
    let call_actors = Arc::new(CallActorStore::new());
    crate::b2bua::actor::set_global_call_store(Arc::clone(&call_actors));

    let state = Arc::new(DispatcherState {
        engine,
        outbound,
        local_domains: Arc::new(config.domain.local.clone()),
        local_addr: via_addr,
        advertised_addrs: merged_advertised,
        listen_addrs,
        listener_registry,
        server_header,
        user_agent_header,
        transaction_timeout,
        call_actors,
        transaction_manager,
        timer_wheel: Arc::new(DashMap::new()),
        session_store: Arc::new(ProxySessionStore::new()),
        dns_resolver,
        hep_sender,
        uac_sender,
        rtpengine_set,
        rtpengine_sessions,
        rtpengine_profiles,
        session_timer_config: config.session_timer.clone(),
        header_policy_registry,
        default_header_policy,
        registrant_manager,
        recording_manager: Arc::new(crate::siprec::RecordingManager::new(product_name, product_version)),
        li_siprec_srs_uri: config.lawful_intercept.as_ref()
            .and_then(|li| li.siprec.as_ref())
            .map(|siprec| siprec.srs_uri.clone()),
        li_siprec_rtpengine_profile: config.lawful_intercept.as_ref()
            .and_then(|li| li.siprec.as_ref())
            .map(|siprec| siprec.rtpengine_profile.clone()),
        srs_manager: config.srs.as_ref()
            .filter(|srs_config| srs_config.enabled)
            .map(|srs_config| Arc::new(crate::srs::SrsManager::new(srs_config.clone()))),
        ipsec_manager,
        ipsec_config,
        registrar_liveness: config.registrar.liveness.clone(),
        liveness_last_seen: Arc::new(DashMap::new()),
        liveness_misses: Arc::new(DashMap::new()),
        connection_pool,
        stream_connections,
        nat_fix_contact: config.nat.as_ref().map(|n| n.fix_contact).unwrap_or(false),
        sdp_name: config.media.as_ref()
            .and_then(|m| m.sdp_name.clone())
            .unwrap_or_else(|| product_name.to_string()),
        call_event_receivers: Arc::new(DashMap::new()),
        reliable_provisionals: Arc::new(DashMap::new()),
        uas_2xx_retransmits: Arc::new(DashMap::new()),
        is_draining: drain.clone(),
        rf_charger,
        rf_sessions: Arc::new(DashMap::new()),
        cdr_sessions: Arc::new(DashMap::new()),
    });

    // Hand the freshly-constructed manager handles to the drain coordinator
    // so the server's drain loop can poll active counts on shutdown.
    let _ = drain.transaction_manager.set(Arc::clone(&state.transaction_manager));
    let _ = drain.call_actors.set(Arc::clone(&state.call_actors));

    // Publish a handle to the running dispatcher + its tokio runtime so the
    // imperative `b2bua.terminate` script API can tear a call down by SIP
    // Call-ID from any thread (event callbacks, timers). First writer wins.
    let _ = B2BUA_CONTROL.set(B2buaControlHandle {
        state: Arc::clone(&state),
        runtime: tokio::runtime::Handle::current(),
    });

    // Install the rf_sessions lookup so the CDR Python API can
    // auto-stamp `rf_session_id` / `rf_result_code` on every CDR
    // emitted while an Rf session is active for the SIP dialog.
    {
        let rf_sessions = Arc::clone(&state.rf_sessions);
        crate::diameter::rf_service::install_rf_lookup(Arc::new(move |dialog_key: &str| {
            rf_sessions.get(dialog_key).map(|entry| {
                let session = entry.value().rf_session();
                (session.session_id().to_string(), session.last_result_code())
            })
        }));
    }

    // Install the script → auto-emit charging-param channel so
    // `request.set_charging_param("outgoing-trunk-group-id", ...)` from
    // a Python handler bridges to the proxy/B2BUA ACR-START builders
    // without needing to thread state through every API surface.
    {
        let params_store: Arc<DashMap<String, Vec<(String, String)>>> =
            Arc::new(DashMap::new());
        let writer_store = Arc::clone(&params_store);
        let reader_store = Arc::clone(&params_store);
        crate::diameter::rf_service::install_rf_param_channel(
            Arc::new(move |dialog_key: &str, name: String, value: String| {
                writer_store
                    .entry(dialog_key.to_string())
                    .or_default()
                    .push((name, value));
            }),
            Arc::new(move |dialog_key: &str| {
                // Drain semantics: removing on read keeps the map
                // bounded even when an INVITE never reaches the
                // auto-emit path (rejected, dropped, etc.).
                reader_store
                    .remove(dialog_key)
                    .map(|(_, v)| v)
                    .unwrap_or_default()
            }),
        );
    }

    // Spawn background task: fire transaction timers + sweep stale entries
    {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            // Timer check interval: 100ms for responsive retransmissions
            let mut timer_interval = tokio::time::interval(std::time::Duration::from_millis(100));
            // Stale entry cleanup: every 30s
            let mut cleanup_interval = tokio::time::interval(std::time::Duration::from_secs(30));

            loop {
                tokio::select! {
                    _ = timer_interval.tick() => {
                        fire_expired_timers(&state);
                    }
                    _ = cleanup_interval.tick() => {
                        sweep_stale_entries(&state).await;
                    }
                }
            }
        });
    }

    // Spawn background task: RFC 4028 session timer refresh
    if state.session_timer_config.as_ref().is_some_and(|c| c.enabled) {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
            loop {
                interval.tick().await;
                // Run in spawn_blocking since it accesses DashMap and may build SIP messages
                let state = Arc::clone(&state);
                tokio::task::spawn_blocking(move || {
                    session_timer_sweep(&state);
                }).await.ok();
            }
        });
    }

    // Spawn background task: registrar change event → on_change handlers
    if let Some(registrar) = crate::script::api::registrar_arc() {
        let mut event_receiver = registrar_event_rx
            .unwrap_or_else(|| registrar.subscribe_events());
        let state_for_events = Arc::clone(&state);
        let registrar = Arc::clone(registrar);
        tokio::spawn(async move {
            while let Ok(event) = event_receiver.recv().await {
                let (aor, event_type) = match &event {
                    crate::registrar::RegistrationEvent::Registered { aor } => {
                        (aor.clone(), "registered")
                    }
                    crate::registrar::RegistrationEvent::Refreshed { aor } => {
                        (aor.clone(), "refreshed")
                    }
                    crate::registrar::RegistrationEvent::Deregistered { aor } => {
                        (aor.clone(), "deregistered")
                    }
                    crate::registrar::RegistrationEvent::Expired { aor } => {
                        (aor.clone(), "expired")
                    }
                };

                // CDR: emit a REGISTER record for this state change when
                // cdr.auto_emit + cdr.include_register are on — independent of
                // whether a @registrar.on_change handler is registered.
                if crate::cdr::auto_emit_enabled() && crate::cdr::include_register_enabled() {
                    cdr_emit_register(&aor, event_type);
                }

                // Quick check if any handlers exist (avoids spawn_blocking overhead)
                {
                    let engine_state = state_for_events.engine.state();
                    if engine_state
                        .handlers_for(&HandlerKind::RegistrarOnChange)
                        .is_empty()
                    {
                        continue;
                    }
                }

                // Build contacts list for the callback
                let contacts: Vec<super::script::api::registrar::PyContact> = registrar
                    .lookup(&aor)
                    .iter()
                    .map(super::script::api::registrar::PyContact::from_rust_contact)
                    .collect();

                let event_type_str = event_type.to_string();
                let state_ref = Arc::clone(&state_for_events);

                // Invoke Python handlers in a blocking context
                let _ = crate::script::py_executor::try_run(move || {
                    let engine_state = state_ref.engine.state();
                    let handlers =
                        engine_state.handlers_for(&HandlerKind::RegistrarOnChange);

                    pyo3::Python::attach(|python| {
                        let py_items: Vec<_> = contacts.into_iter().filter_map(|contact| {
                            match pyo3::Py::new(python, contact) {
                                Ok(py) => Some(py.into_bound(python)),
                                Err(error) => {
                                    error!("PyContact creation failed: {error}");
                                    None
                                }
                            }
                        }).collect();
                        let Ok(py_contacts) = pyo3::types::PyList::new(python, py_items) else {
                            error!("PyList creation failed for registrar on_change contacts");
                            return;
                        };

                        for handler in handlers {
                            let callable = handler.callable.bind(python);
                            let result = callable.call1((
                                aor.as_str(),
                                event_type_str.as_str(),
                                &py_contacts,
                            ));
                            match result {
                                Ok(ret) => {
                                    if handler.is_async {
                                        if let Err(error) = run_coroutine(python, &ret) {
                                            tracing::error!(
                                                %error,
                                                "async registrar.on_change handler error"
                                            );
                                        }
                                    }
                                }
                                Err(error) => {
                                    tracing::error!(
                                        %error,
                                        "registrar.on_change handler failed"
                                    );
                                }
                            }
                        }
                    });
                })
                .await;
            }
        });
    }

    // Spawn background task: registrant change event → on_change handlers
    if let Some(ref registrant) = state.registrant_manager {
        let mut event_receiver = registrant.subscribe_events();
        let state_for_events = Arc::clone(&state);
        let registrant = Arc::clone(registrant);
        tokio::spawn(async move {
            while let Ok(event) = event_receiver.recv().await {
                let (aor, event_type, failed_status_code) = match &event {
                    crate::registrant::RegistrantEvent::Registered { aor } => {
                        (aor.clone(), "registered", None)
                    }
                    crate::registrant::RegistrantEvent::Refreshed { aor } => {
                        (aor.clone(), "refreshed", None)
                    }
                    crate::registrant::RegistrantEvent::Failed { aor, status_code } => {
                        (aor.clone(), "failed", Some(*status_code))
                    }
                    crate::registrant::RegistrantEvent::Deregistered { aor } => {
                        (aor.clone(), "deregistered", None)
                    }
                };

                // Quick check if any handlers exist (avoids spawn_blocking overhead)
                {
                    let engine_state = state_for_events.engine.state();
                    if engine_state
                        .handlers_for(&HandlerKind::RegistrantOnChange)
                        .is_empty()
                    {
                        continue;
                    }
                }

                // Build state dict for the callback
                let (expires_in, failure_count, registrar_uri) = registrant
                    .entry_info(&aor)
                    .unwrap_or((0, 0, String::new()));

                let event_type_str = event_type.to_string();
                let state_ref = Arc::clone(&state_for_events);

                // Invoke Python handlers in a blocking context
                let _ = crate::script::py_executor::try_run(move || {
                    let engine_state = state_ref.engine.state();
                    let handlers =
                        engine_state.handlers_for(&HandlerKind::RegistrantOnChange);

                    pyo3::Python::attach(|python| {
                        let py_state = pyo3::types::PyDict::new(python);
                        let status_code_ok = match failed_status_code {
                            Some(code) => py_state.set_item("status_code", code).is_ok(),
                            None => true,
                        };
                        if py_state.set_item("expires_in", expires_in).is_err()
                            || py_state.set_item("failure_count", failure_count).is_err()
                            || py_state.set_item("registrar", &registrar_uri).is_err()
                            || !status_code_ok
                        {
                            error!("PyDict creation failed for registration on_change state");
                            return;
                        }

                        for handler in handlers {
                            let callable = handler.callable.bind(python);
                            let result = callable.call1((
                                aor.as_str(),
                                event_type_str.as_str(),
                                &py_state,
                            ));
                            match result {
                                Ok(ret) => {
                                    if handler.is_async {
                                        if let Err(error) = run_coroutine(python, &ret) {
                                            tracing::error!(
                                                %error,
                                                "async registration.on_change handler error"
                                            );
                                        }
                                    }
                                }
                                Err(error) => {
                                    tracing::error!(
                                        %error,
                                        "registration.on_change handler failed"
                                    );
                                }
                            }
                        }
                    });
                })
                .await;
            }
        });
    }

    // Spawn background task: incoming Diameter requests (RTR from HSS, etc.)
    {
        let mut diameter_rx = diameter_incoming_rx;
        let state_for_diameter = Arc::clone(&state);
        tokio::spawn(async move {
            let diameter_inflight = std::sync::Arc::new(tokio::sync::Semaphore::new(512));
            while let Some((incoming, peer)) = diameter_rx.recv().await {
                // Unified inbound dispatch (RFC 6733): every inbound request —
                // any application, any command — is handed to
                // @diameter.on_request. siphon transports; the script reads
                // AVPs and returns the answer (or 3002 when unhandled). Adding
                // a new server-side application needs zero Rust here.
                let engine = std::sync::Arc::clone(&state_for_diameter.engine);
                let config = peer.config();
                let peer_info = crate::script::api::diameter_server::PyInboundPeer {
                    name: config.host.clone(),
                    tenant: "default".to_string(),
                    addr: format!("{}:{}", config.host, config.port),
                    transport: "tcp".to_string(),
                };
                let origin_host = config.origin_host.clone();
                let origin_realm = config.origin_realm.clone();
                let inflight = std::sync::Arc::clone(&diameter_inflight);
                let inbound_peer = std::sync::Arc::clone(&peer);
                tokio::spawn(async move {
                    let _permit = match inflight.acquire_owned().await {
                        Ok(permit) => permit,
                        Err(_) => return,
                    };
                    crate::script::diameter_dispatch::dispatch_request(
                        engine,
                        inbound_peer,
                        incoming,
                        peer_info,
                        origin_host,
                        origin_realm,
                    )
                    .await;
                });
            }
        });
    }

    // Spawn background task: rtpengine async events (DTMF, etc.)
    {
        let mut events_rx = rtpengine_events_rx;
        let state_for_events = Arc::clone(&state);
        tokio::spawn(async move {
            while let Some(event) = events_rx.recv().await {
                match event {
                    crate::rtpengine::events::RtpEngineEvent::Dtmf(dtmf) => {
                        let engine_state = state_for_events.engine.state();
                        let handlers = engine_state.dtmf_handlers(&dtmf.call_id, &dtmf.from_tag);
                        if handlers.is_empty() {
                            continue;
                        }
                        let state_ref = Arc::clone(&state_for_events);
                        let dtmf_clone = dtmf.clone();
                        let _ = crate::script::py_executor::try_run(move || {
                            let engine_state = state_ref.engine.state();
                            let handlers = engine_state
                                .dtmf_handlers(&dtmf_clone.call_id, &dtmf_clone.from_tag);
                            pyo3::Python::attach(|python| {
                                for handler in handlers {
                                    let callable = handler.callable.bind(python);
                                    let result = callable.call1((
                                        dtmf_clone.call_id.as_str(),
                                        dtmf_clone.from_tag.as_str(),
                                        dtmf_clone.digit.as_str(),
                                        dtmf_clone.duration_ms,
                                        dtmf_clone.volume,
                                    ));
                                    match result {
                                        Ok(ret) => {
                                            if handler.is_async {
                                                if let Err(error) = run_coroutine(python, &ret) {
                                                    tracing::error!(
                                                        %error,
                                                        "async rtpengine.on_dtmf handler error"
                                                    );
                                                }
                                            }
                                        }
                                        Err(error) => {
                                            tracing::error!(
                                                %error,
                                                "rtpengine.on_dtmf handler failed"
                                            );
                                        }
                                    }
                                }
                            });
                        })
                        .await;
                    }
                    crate::rtpengine::events::RtpEngineEvent::MediaTimeout {
                        call_id,
                        from_tag,
                    } => {
                        // The media engine owns the call and reaped it on timeout
                        // (the reaper removes the call *before* emitting this
                        // event), so drop our own per-call media bookkeeping now.
                        // The teardown that any @rtpengine.on_media_timeout handler
                        // drives (e.g. b2bua.terminate) then finds no record and
                        // issues no safety-net delete against a call the engine
                        // already dropped — no wasted round-trip, no "unknown call".
                        clear_media_session_on_timeout(
                            state_for_events.rtpengine_sessions.as_ref(),
                            &call_id,
                        );
                        // The media engine tore down a dead-path call. Log it for
                        // visibility regardless of whether a script handles it,
                        // then invoke any @rtpengine.on_media_timeout handlers so
                        // the script can release the per-call state no BYE will
                        // now clear (Rx/N5 QoS, charging, dialog).
                        tracing::warn!(
                            %call_id,
                            %from_tag,
                            "media engine reported media timeout (engine tore down call)"
                        );
                        let engine_state = state_for_events.engine.state();
                        let handlers =
                            engine_state.media_timeout_handlers(&call_id, &from_tag);
                        if handlers.is_empty() {
                            continue;
                        }
                        let state_ref = Arc::clone(&state_for_events);
                        let call_id_clone = call_id.clone();
                        let from_tag_clone = from_tag.clone();
                        let _ = crate::script::py_executor::try_run(move || {
                            let engine_state = state_ref.engine.state();
                            let handlers = engine_state
                                .media_timeout_handlers(&call_id_clone, &from_tag_clone);
                            pyo3::Python::attach(|python| {
                                for handler in handlers {
                                    let callable = handler.callable.bind(python);
                                    let result = callable.call1((
                                        call_id_clone.as_str(),
                                        from_tag_clone.as_str(),
                                    ));
                                    match result {
                                        Ok(ret) => {
                                            if handler.is_async {
                                                if let Err(error) = run_coroutine(python, &ret) {
                                                    tracing::error!(
                                                        %error,
                                                        "async rtpengine.on_media_timeout handler error"
                                                    );
                                                }
                                            }
                                        }
                                        Err(error) => {
                                            tracing::error!(
                                                %error,
                                                "rtpengine.on_media_timeout handler failed"
                                            );
                                        }
                                    }
                                }
                            });
                        })
                        .await;
                    }
                    crate::rtpengine::events::RtpEngineEvent::CallSummary(summary) => {
                        // The media engine reports the end-of-call byte/packet
                        // counters and (when a userspace actor measured them) the
                        // RFC 3550 loss/jitter + ITU-T G.107 MOS shape. Write a
                        // media CDR keyed on the SIP Call-ID so a collector joins
                        // it to the SIP-side CDR — the structured twin of the
                        // engine's `siphon_rtp::cdr` log, no log scraping. Gated
                        // on auto-emit, same as the proxy/b2bua lifecycle CDRs.
                        tracing::debug!(
                            call_id = %summary.call_id,
                            reason = %summary.reason,
                            legs = summary.legs.len(),
                            "media engine reported end-of-call summary"
                        );
                        if crate::cdr::auto_emit_enabled() {
                            crate::cdr::write(media_summary_to_cdr(&summary));
                        }
                    }
                    crate::rtpengine::events::RtpEngineEvent::Unknown { event, call_id, .. } => {
                        tracing::debug!(
                            %event,
                            ?call_id,
                            "unhandled rtpengine event"
                        );
                    }
                }
            }
        });
    }

    info!("dispatcher started");

    while let Ok(inbound) = inbound_rx.recv_async().await {
        let state = Arc::clone(&state);

        // Both requests and responses may invoke Python handlers
        // (on_request and on_reply), so dispatch on the fixed Python executor
        // pool rather than tokio's elastic blocking pool — the latter reaps
        // idle threads mid-process and orphans their pinned free-threaded
        // CPython mimalloc heap (~2 MB each).  See `script::py_executor`.
        crate::script::py_executor::spawn(move || {
            handle_inbound(inbound, &state);
        });
    }

    info!("dispatcher shutting down (inbound channel closed)");
}

/// Drop siphon-sip's own media-session bookkeeping for a call the media engine
/// already reaped (media-timeout). The engine owns the call and tore it down
/// before emitting the `MediaTimeout` event, so a later safety-net `delete`
/// would just return "unknown call". Every safety-net delete site is gated on
/// `if let Some(session) = rtpengine_sessions.remove(&…)`, so removing the
/// record here makes those sites no-ops — no delete is issued.
///
/// Returns true if a record was actually present (i.e. we cleared something).
fn clear_media_session_on_timeout(
    rtpengine_sessions: Option<&Arc<crate::rtpengine::session::MediaSessionStore>>,
    call_id: &str,
) -> bool {
    match rtpengine_sessions {
        Some(store) if store.remove(call_id).is_some() => {
            debug!(
                %call_id,
                "media timeout: dropped media-session bookkeeping (engine already reaped call)"
            );
            true
        }
        _ => false,
    }
}

/// Fire all expired timers in the timer wheel.
fn fire_expired_timers(state: &DispatcherState) {
    let now = std::time::Instant::now();
    let mut fired: Vec<TimerEntry> = Vec::new();

    state.timer_wheel.retain(|_id, entry| {
        if now >= entry.fires_at {
            fired.push(entry.clone());
            false // remove from wheel
        } else {
            true
        }
    });

    for entry in fired {
        // Non-ACK INVITE auto-ban signal. Timer H is the INVITE *server*
        // transaction timeout (RFC 3261 §17.2.1 — a non-2xx final was sent and no
        // ACK arrived within 64*T1). That is exactly the toll-fraud-scanner
        // pattern: the peer sent an INVITE, got the 401/403, and walked away
        // without ACKing. `entry.destination` is the UAC (the source), so this can
        // only ever count against the originator — never a downstream relay/trunk
        // (whose failures would surface as ICT Timer B, deliberately not counted).
        if matches!(entry.name, TimerName::H) {
            if let (Some(ban), Some(dest)) =
                (crate::security::auto_ban(), entry.destination)
            {
                if ban.record_failure(dest.ip()) {
                    warn!(source = %dest.ip(), "auto-ban: source banned (non-ACK INVITE timeout)");
                }
                if let Some(metrics) = crate::metrics::try_metrics() {
                    metrics.auth_failures_total.inc();
                }
            }
        }

        let event = match entry.name {
            // Server transaction timers
            TimerName::J => Some(ServerEvent::Nist(NistEvent::TimerJ)),
            TimerName::G => Some(ServerEvent::Ist(IstEvent::TimerG)),
            TimerName::H => Some(ServerEvent::Ist(IstEvent::TimerH)),
            TimerName::I => Some(ServerEvent::Ist(IstEvent::TimerI)),
            TimerName::Trying100 => Some(ServerEvent::Nist(NistEvent::Trying100Fired)),
            _ => None,
        };

        if let Some(server_event) = event {
            match state.transaction_manager.process_server_event(&entry.key, server_event) {
                Ok(actions) => {
                    process_timer_actions(
                        &actions,
                        &entry.key,
                        entry.destination,
                        entry.transport,
                        entry.connection_id,
                        entry.source_local_addr,
                        state,
                    );
                }
                Err(error) => {
                    debug!(key = %entry.key, timer = ?entry.name, "timer fire for gone transaction: {error}");
                }
            }
            continue;
        }

        let client_event = match entry.name {
            TimerName::A => Some(ClientEvent::Ict(IctEvent::TimerA)),
            TimerName::B => Some(ClientEvent::Ict(IctEvent::TimerB)),
            TimerName::D => Some(ClientEvent::Ict(IctEvent::TimerD)),
            TimerName::E => Some(ClientEvent::Nict(NictEvent::TimerE)),
            TimerName::F => Some(ClientEvent::Nict(NictEvent::TimerF)),
            TimerName::K => Some(ClientEvent::Nict(NictEvent::TimerK)),
            _ => None,
        };

        if let Some(client_event) = client_event {
            match state.transaction_manager.process_client_event(&entry.key, client_event) {
                Ok(actions) => {
                    process_timer_actions(
                        &actions,
                        &entry.key,
                        entry.destination,
                        entry.transport,
                        entry.connection_id,
                        entry.source_local_addr,
                        state,
                    );
                }
                Err(error) => {
                    debug!(key = %entry.key, timer = ?entry.name, "timer fire for gone transaction: {error}");
                }
            }
        }
    }
}

/// Process actions from a timer-driven state machine event.
///
/// `source_local_addr` is the local socket the original request
/// arrived on — required by 3GPP TS 33.203 §7.4 for IPsec sec-agree
/// (responses cached by server transactions and re-emitted as
/// `Action::SendMessage` must egress on the same socket the request
/// arrived on).  For client transactions or paths where the source
/// doesn't matter, callers pass `None`.
fn process_timer_actions(
    actions: &[Action],
    key: &TransactionKey,
    destination: Option<SocketAddr>,
    transport: Option<Transport>,
    connection_id: Option<ConnectionId>,
    source_local_addr: Option<SocketAddr>,
    state: &DispatcherState,
) {
    for action in actions {
        match action {
            Action::SendMessage(message) => {
                if let (Some(dest), Some(trans)) = (destination, transport) {
                    let conn_id = connection_id.unwrap_or_default();
                    send_message_from(message.clone(), trans, dest, conn_id, source_local_addr, state);
                }
            }
            Action::StartTimer(name, duration) => {
                let timer_id = format!("{}:{:?}", key, name);
                state.timer_wheel.insert(timer_id, TimerEntry {
                    key: key.clone(),
                    name: *name,
                    fires_at: std::time::Instant::now() + *duration,
                    destination,
                    transport,
                    connection_id,
                    source_local_addr,
                });
            }
            Action::CancelTimer(name) => {
                let timer_id = format!("{}:{:?}", key, name);
                state.timer_wheel.remove(&timer_id);
            }
            Action::Timeout => {
                warn!(key = %key, "transaction timeout");
                // Session cleanup happens via sweep_stale_entries
            }
            Action::ProtocolError(message) => {
                warn!(key = %key, "transaction protocol error: {message}");
            }
            Action::Terminated | Action::PassToTu(_) => {
                // PassToTu from timer context is unusual (shouldn't happen)
                // Terminated: transaction already auto-removed by manager
            }
        }
    }
}

/// Backstop TTL for call-lifetime stores (rtpengine sessions, B2BUA call
/// actors, proxy Rf charging sessions, SIPREC recordings).
///
/// Normal calls reap their entries on BYE / teardown within seconds-to-minutes;
/// this only catches truly-orphaned entries whose teardown path never fired.
/// A call still alive after 24 h is abnormal/nonexistent, so ageing strictly
/// by creation time at this TTL never drops an active call.
const ORPHAN_CALL_TTL: std::time::Duration = std::time::Duration::from_secs(24 * 3600);

/// Sweep stale proxy sessions.
async fn sweep_stale_entries(state: &DispatcherState) {
    let now = std::time::Instant::now();
    let ttl = state.transaction_timeout;
    let expired_sessions = state.session_store.sweep_stale(ttl) as u64;

    // Expire UAC pending requests whose response never arrived. Callers
    // (NAT keepalive, gateway health probe, proxy.send_request) apply a short
    // receiver timeout and drop the receiver, but that does not remove the
    // pending entry — only a matching response or this sweep does. Without it
    // the map grows by one stranded oneshot::Sender per unanswered probe.
    let expired_uac = state.uac_sender.sweep_stale(ttl) as u64;
    let uac_pending = state.uac_sender.pending_count();
    let dialog_sessions = state.session_store.dialog_key_count();
    // Reap expired/abandoned SUBSCRIBE dialogs from the L1 store (L2 expires
    // via its own TTL; L1 has no reaper, so a subscriber that vanishes without
    // an un-SUBSCRIBE would otherwise pin its dialog forever).
    let (expired_subs, subscribe_dialogs) = match crate::subscribe_state::global_store() {
        Some(store) => (store.sweep_stale() as u64, store.local_count()),
        None => (0, 0),
    };

    // ── Orphan backstop sweeps (call-lifetime stores) ──────────────────────
    // These are reaped promptly on BYE for normal calls; the backstop only
    // catches entries whose teardown path never fired. Age strictly by
    // creation with a long TTL so active calls are never disturbed.

    // RTPEngine media sessions — ages by MediaSession::created_at, returns ().
    if let Some(store) = &state.rtpengine_sessions {
        store.sweep_stale(ORPHAN_CALL_TTL);
    }

    // B2BUA answer-timeout: fail calls still un-answered past their
    // fork/dial `timeout=` deadline with a 408 (CANCEL pending legs, fire
    // @b2bua.on_failure, respond to the A-leg). Without this a non-responding
    // B-leg would only be caught by the 24h orphan backstop below.
    for timed_out in state.call_actors.take_timed_out_calls(now) {
        fail_b2bua_call_on_timeout(&timed_out, state);
    }

    // B2BUA call actors — ages by CallActor::created_at (set once at creation,
    // never refreshed), returns the number reaped.
    let expired_calls = state.call_actors.sweep_stale(ORPHAN_CALL_TTL) as u64;

    // Proxy Rf charging sessions — one Arc may be filed under several keys
    // (storage_keys aliases), so retain on the value's age to drop every alias
    // of an orphan in one pass.
    let rf_before = state.rf_sessions.len();
    state
        .rf_sessions
        .retain(|_, st| now.duration_since(st.created_at) < ORPHAN_CALL_TTL);
    let expired_rf = rf_before.saturating_sub(state.rf_sessions.len()) as u64;

    // Auto-emit CDR sessions — orphan backstop. Normal calls drain on their
    // teardown hook (BYE / failure / cancel / timeout); this only reaps entries
    // whose teardown never reached the dispatcher (e.g. a UA that vanished after
    // answer). Dropped silently rather than emitting a misleading long-duration
    // record — every cleanly-ended call is already accounted by a direct hook.
    let cdr_before = state.cdr_sessions.len();
    state
        .cdr_sessions
        .retain(|_, session| now.duration_since(session.created_at()) < ORPHAN_CALL_TTL);
    let expired_cdr = cdr_before.saturating_sub(state.cdr_sessions.len()) as u64;

    // SIPREC recording sessions — ages by RecordingSession::created_at, and
    // clears the call_sessions / branch_to_session aliases too.
    let expired_recordings = state.recording_manager.sweep_stale(ORPHAN_CALL_TTL) as u64;

    // Expire stale presence documents/subscriptions from the L1 store (no TTL
    // reaper of its own; only removes already-expired entries, so it's safe).
    if let Some(presence) = crate::presence::global_store() {
        presence.expire_stale();
    }

    // Reap expired registrar bindings + emit RegistrationEvent::Expired. Only
    // removes entries whose own `expires` already elapsed, so an actively-
    // refreshing binding (future expires) is never disturbed. In production
    // nothing else calls this, so without it expired AoRs would pin memory
    // until the next REGISTER for the same AoR.
    let expired_registrations = match crate::script::api::registrar_arc() {
        Some(reg) => reg.expire_stale() as u64,
        None => 0,
    };

    // Sweep abandoned P-CSCF IPsec SA pairs whose own hard lifetime + grace
    // has elapsed (tears down the 4 XFRM states + 4 policies + the in-memory
    // entry). An ACTIVE registration re-REGISTERs and reinstalls a fresh SA
    // (new expires_at) before this deadline, so only truly-abandoned UEs are
    // reaped. None when no P-CSCF/ipsec role is configured.
    let (expired_ipsec_sas, ipsec_sa_pairs) = match crate::ipsec::global_manager() {
        Some(manager) => {
            let reaped = manager.sweep_expired_reaped().await;
            // Registrar-liveness Part B.4: an abandoned UE's SA pair just
            // aged out of the kernel — its SIP registration should go with it
            // rather than linger to its own Expires.  Only when liveness is on.
            if state.registrar_liveness.enabled && !reaped.is_empty() {
                liveness_dereg_reaped_sas(state, &reaped).await;
            }
            (reaped.len() as u64, manager.active_count())
        }
        None => (0, 0),
    };

    // Registrar-liveness Part B: UDP+IPsec idle detection (kernel SA use-time
    // poll → one OPTIONS probe → deregister on no answer).  No-op unless
    // enabled and a P-CSCF IPsec role is configured.
    if state.registrar_liveness.enabled {
        sweep_registrar_liveness(state).await;
    }

    if let Some(metrics) = crate::metrics::try_metrics() {
        metrics.uac_pending_requests.set(uac_pending as i64);
        metrics.proxy_dialog_sessions.set(dialog_sessions as i64);
        metrics.cdr_sessions.set(state.cdr_sessions.len() as i64);
        metrics.subscribe_dialogs.set(subscribe_dialogs as i64);
        metrics.ipsec_sa_pairs.set(ipsec_sa_pairs as i64);
    }
    // Refresh allocator memory gauges (jemalloc live/resident/retained bytes)
    // so operators can alert on `siphon_memory_allocated_bytes` growth — the
    // precise, RSS-noise-free leak signal.  Also refresh the Python-side block
    // count (jemalloc can't see CPython's allocator) for Python leak detection.
    crate::metrics::update_memory_stats();
    crate::metrics::update_python_stats();
    // Refresh the glibc allocator gauges — the C-side / CPython raw-domain pool
    // that jemalloc and CPython's mimalloc can't see (no-op off glibc).
    crate::metrics::update_glibc_stats();

    if expired_sessions > 0
        || expired_uac > 0
        || expired_subs > 0
        || expired_calls > 0
        || expired_rf > 0
        || expired_recordings > 0
        || expired_registrations > 0
        || expired_ipsec_sas > 0
        || expired_cdr > 0
    {
        info!(
            expired_sessions,
            expired_uac,
            expired_subs,
            expired_calls,
            expired_rf,
            expired_cdr,
            expired_recordings,
            expired_registrations,
            expired_ipsec_sas,
            uac_pending,
            sessions = state.session_store.session_count(),
            transactions = state.transaction_manager.count(),
            "stale entry cleanup"
        );
    }
}

// ===========================================================================
// Registrar liveness — UDP+IPsec idle detection + network-initiated dereg.
// (TCP/TLS flow-failure dereg is handled at the transport layer via the
// connection-close channel → Registrar::unregister_flow.)
// ===========================================================================

/// Everything a detached liveness-dereg task needs, cloned out of
/// `DispatcherState` so the task is `'static`.
#[derive(Clone)]
struct LivenessDeregCtx {
    registrar: Arc<Registrar>,
    ipsec_manager: Option<Arc<crate::ipsec::IpsecManager>>,
    uac_sender: Arc<UacSender>,
    dns_resolver: Arc<SipResolver>,
    dereg_mode: crate::config::LivenessDeregMode,
    /// Shared SIP-layer last-seen map (source IP → UNIX secs) — see
    /// [`DispatcherState::liveness_last_seen`].  The idle sweep reads it, the
    /// probe stamps it on an answer, and the dereg funnel prunes it on reap.
    last_seen: Arc<DashMap<std::net::IpAddr, u64>>,
    /// Shared consecutive-miss counter (AoR → misses) for probe hysteresis —
    /// see [`DispatcherState::liveness_misses`].
    misses: Arc<DashMap<String, u64>>,
    /// Consecutive failed sweeps before a suspect binding is reaped
    /// (`registrar_liveness.miss_threshold`).
    miss_threshold: u32,
}

impl LivenessDeregCtx {
    fn from_state(state: &DispatcherState, registrar: Arc<Registrar>) -> Self {
        Self {
            registrar,
            ipsec_manager: state.ipsec_manager.clone(),
            uac_sender: Arc::clone(&state.uac_sender),
            dns_resolver: Arc::clone(&state.dns_resolver),
            dereg_mode: state.registrar_liveness.dereg_mode,
            last_seen: Arc::clone(&state.liveness_last_seen),
            misses: Arc::clone(&state.liveness_misses),
            miss_threshold: state.registrar_liveness.miss_threshold,
        }
    }

    /// Build the funnel context from process globals, for the flow-failure
    /// close-drain task (`server.rs`) which has no `DispatcherState`.  Returns
    /// `None` if the registrar / UAC / resolver globals aren't installed yet.
    ///
    /// The flow-failure path only synthesizes the upstream de-REGISTER and
    /// never touches the idle-sweep bookkeeping, so `last_seen` / `misses` are
    /// fresh empty maps and `miss_threshold` is the config default.
    fn from_globals(dereg_mode: crate::config::LivenessDeregMode) -> Option<Self> {
        Some(Self {
            registrar: crate::script::api::registrar_arc()?.clone(),
            ipsec_manager: crate::ipsec::global_manager(),
            uac_sender: crate::script::api::proxy_utils::uac_sender()?.clone(),
            dns_resolver: crate::script::api::proxy_utils::send_resolver()?.clone(),
            dereg_mode,
            last_seen: Arc::new(DashMap::new()),
            misses: Arc::new(DashMap::new()),
            miss_threshold: crate::config::RegistrarLivenessConfig::default().miss_threshold,
        })
    }
}

/// Current UNIX time in whole seconds, or `None` if the clock is before the
/// epoch (never, in practice).  Shared by the liveness last-seen stamp sites.
fn now_unix() -> Option<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|elapsed| elapsed.as_secs())
}

/// Most recent liveness evidence for a binding: the kernel XFRM inbound
/// `use_time` folded with siphon's own SIP-layer last-seen.  The kernel
/// counter can fail to advance on an inbound-answered SA (making a live UE
/// look perpetually idle), so the SIP signal — refreshed on every message
/// arriving on a protected port — is the corrective input.
fn liveness_last_active(kernel_last_active: u64, sip_last_seen: u64) -> u64 {
    kernel_last_active.max(sip_last_seen)
}

/// Whether a binding counts as recently active (inside the idle window) and so
/// must not be probed this sweep.
fn liveness_recently_active(now: u64, last_active: u64, idle_window: u64) -> bool {
    now.saturating_sub(last_active) <= idle_window
}

/// Hysteresis decision after a suspect binding fails its in-sweep OPTIONS probe
/// loop.  Given the prior consecutive-miss count and the configured threshold,
/// returns `(new_count, reap)`: within grace it bumps the counter and keeps the
/// binding (`reap == false`); once the threshold is reached it resets the
/// counter and signals a reap (`reap == true`).  A `threshold` of 0 is treated
/// as 1 (reap on the first miss) so the feature can never be silently disabled
/// by a zero.
fn liveness_miss_outcome(before: u64, threshold: u32) -> (u64, bool) {
    let misses = before.saturating_add(1);
    if misses < threshold.max(1) as u64 {
        (misses, false)
    } else {
        (0, true)
    }
}

/// Record that a UE is alive (answered a probe, or an inbound arrived): stamp
/// its SIP last-seen and clear any accumulated miss strike so the next sweep
/// skips it for a full idle window and a later transient miss starts from zero.
fn liveness_note_alive(
    last_seen: &DashMap<std::net::IpAddr, u64>,
    misses: &DashMap<String, u64>,
    ue_ip: std::net::IpAddr,
    aor: &str,
    now: u64,
) {
    last_seen.insert(ue_ip, now);
    misses.remove(aor);
}

/// Reconcile the liveness bookkeeping with the current registration set: keep
/// last-seen only for IPs that still have a live SA, and miss counters only for
/// AoRs still present as IPsec bindings.  This is what drains both maps to
/// baseline as UEs deregister (project per-module leak rule).
fn liveness_gc(
    last_seen: &DashMap<std::net::IpAddr, u64>,
    misses: &DashMap<String, u64>,
    live_ips: &std::collections::HashSet<std::net::IpAddr>,
    live_aors: &std::collections::HashSet<String>,
) {
    last_seen.retain(|ip, _| live_ips.contains(ip));
    misses.retain(|aor, _| live_aors.contains(aor));
}

/// Run the network-dereg cascade for bindings removed by the **flow-failure**
/// close path (`server.rs` drain task).  Under `network_dereg`, a P-CSCF cache
/// binding (one carrying a `flow_token`) additionally synthesizes an
/// `Expires: 0` REGISTER toward the S-CSCF via its stored Service-Route, so
/// the registrar of record clears it too — matching the SA-idle path.  No-op
/// under `local_only`, or when none of the removed bindings is a P-CSCF cache
/// binding.  The local removal + `on_change` cascade already happened in
/// `unregister_flow_collect`; this adds only the upstream de-REGISTER.
pub(crate) async fn liveness_flow_failure_network_dereg(
    removed: Vec<(crate::registrar::Aor, crate::registrar::Contact)>,
    dereg_mode: crate::config::LivenessDeregMode,
) {
    if dereg_mode != crate::config::LivenessDeregMode::NetworkDereg
        || !removed.iter().any(|(_, contact)| contact.flow_token.is_some())
    {
        return;
    }
    let context = match LivenessDeregCtx::from_globals(dereg_mode) {
        Some(context) => context,
        None => return,
    };
    for (aor, contact) in removed {
        if contact.flow_token.is_some() {
            send_liveness_network_dereg(&context, &aor, &contact.uri.to_string()).await;
        }
    }
}

/// The set of contact URIs to **retain** (detach, not deregister) when a stream
/// flow closes: those whose UE source IP still has a live IPsec SA.  A closed
/// IPsec flow is a recoverable RFC 5626 §4.2.2 flow failure owned by the
/// SA-idle sweep, not a death signal — the UE stays reachable via paging and
/// its XFRM SA stays warm across ECM-IDLE.  A non-IPsec stream close has no SA
/// to consult and remains an authoritative death signal (keep set excludes it).
fn flow_close_keep_set(
    bindings: &[(crate::registrar::Aor, crate::registrar::Contact)],
    sa_ips: &std::collections::HashSet<std::net::IpAddr>,
) -> std::collections::HashSet<String> {
    bindings
        .iter()
        .filter(|(_, contact)| {
            contact
                .source_addr
                .map(|addr| sa_ips.contains(&addr.ip()))
                .unwrap_or(false)
        })
        .map(|(_, contact)| contact.uri.to_string())
        .collect()
}

/// Handle a stream connection close under registrar liveness (RFC 5626
/// §4.2.2).  Runs from the `server.rs` close-drain task (which has no
/// `DispatcherState`), so it reads process globals.
///
/// IPsec bindings on the dead flow are **retained** (detached) and left to the
/// SA-idle sweep ([`sweep_registrar_liveness`]), which ages them on the
/// authoritative XFRM SA use-time plus an OPTIONS probe.  This stops a VoLTE UE
/// from being network-deregistered on every benign ECM-IDLE transition: its
/// SIP-over-TCP flow FINs at the radio inactivity timer, but the IMS
/// registration must survive so an MT INVITE can page it.  Non-IPsec stream
/// closes (plain TCP, WSS WebRTC) keep today's immediate flow-failure
/// deregistration and cascade.
pub(crate) async fn liveness_on_flow_close(
    connection_id: u64,
    dereg_mode: crate::config::LivenessDeregMode,
) {
    let registrar = match crate::script::api::registrar_arc() {
        Some(registrar) => Arc::clone(registrar),
        None => return,
    };

    // Same discriminator the SA-idle sweep uses: a UE IP with a live SA.
    let sa_ips: std::collections::HashSet<std::net::IpAddr> = match crate::ipsec::global_manager() {
        Some(manager) => manager
            .liveness_snapshot()
            .into_iter()
            .map(|row| row.ue_addr)
            .collect(),
        None => std::collections::HashSet::new(),
    };

    let keep = flow_close_keep_set(&registrar.bindings_for_connection(connection_id), &sa_ips);
    let retained = keep.len();
    let removed = registrar.close_flow(connection_id, &keep);

    if retained > 0 {
        tracing::info!(
            connection_id,
            retained,
            "registrar liveness: stream flow closed — IPsec binding(s) retained, \
             deferring to SA-idle sweep (RFC 5626 flow recovery)"
        );
    }
    if !removed.is_empty() {
        tracing::info!(
            connection_id,
            removed = removed.len(),
            "registrar liveness: flow-failure deregistration (non-IPsec stream connection closed)"
        );
        liveness_flow_failure_network_dereg(removed, dereg_mode).await;
    }
}

/// Part B.4 — an abandoned UE's SA pair was just reaped from the kernel;
/// remove the matching registrar binding(s) so the registration doesn't
/// linger to its own `Expires`.  Runs synchronously in the sweep because the
/// reaped set is small and the dereg is local + (optionally) one upstream
/// REGISTER.
async fn liveness_dereg_reaped_sas(state: &DispatcherState, reaped: &[(std::net::IpAddr, u16)]) {
    let registrar = match crate::script::api::registrar_arc() {
        Some(registrar) => Arc::clone(registrar),
        None => return,
    };
    let context = LivenessDeregCtx::from_state(state, registrar);
    let reaped_ips: std::collections::HashSet<std::net::IpAddr> =
        reaped.iter().map(|(ip, _)| *ip).collect();
    let port_for: std::collections::HashMap<std::net::IpAddr, u16> =
        reaped.iter().map(|(ip, port)| (*ip, *port)).collect();

    for (aor, contact) in context.registrar.all_contacts() {
        let ue_ip = match contact.source_addr {
            Some(addr) => addr.ip(),
            None => continue,
        };
        if !reaped_ips.contains(&ue_ip) {
            continue;
        }
        let ue_port_c = port_for.get(&ue_ip).copied();
        liveness_dereg_contact(
            &context,
            &aor,
            &contact,
            ue_port_c,
            "ipsec SA torn down (abandoned-SA sweep)",
        )
        .await;
    }
}

/// Part B — UDP+IPsec idle-liveness sweep.  Polls the kernel SA use-times,
/// flags bindings whose SA has been silent beyond
/// `idle_multiplier × keepalive_interval`, and spawns a one-shot OPTIONS
/// probe that deregisters on no answer.  A live UE's response is itself
/// inbound protected traffic, so it refreshes the SA use-time and clears the
/// suspect state on the next sweep.
async fn sweep_registrar_liveness(state: &DispatcherState) {
    let manager = match &state.ipsec_manager {
        Some(manager) => manager,
        None => return, // no P-CSCF IPsec role → no UDP+IPsec bindings to age
    };
    let registrar = match crate::script::api::registrar_arc() {
        Some(registrar) => Arc::clone(registrar),
        None => return,
    };

    let use_times = manager.dump_sa_use_times().await;
    let snapshot = manager.liveness_snapshot();
    // One registration per UE IP in an IPsec P-CSCF — index the SA rows by IP.
    let mut sa_by_ip: std::collections::HashMap<std::net::IpAddr, crate::ipsec::SaLivenessRow> =
        std::collections::HashMap::with_capacity(snapshot.len());
    for row in snapshot {
        sa_by_ip.insert(row.ue_addr, row);
    }
    let context = LivenessDeregCtx::from_state(state, registrar);
    let live_ips: std::collections::HashSet<std::net::IpAddr> =
        sa_by_ip.keys().copied().collect();

    // No live SAs, or the kernel use-time dump is unavailable on this platform
    // → nothing to age this sweep.  Still reconcile the liveness bookkeeping so
    // last-seen / miss entries for UEs whose SA has gone drain to baseline
    // instead of accumulating (project per-module leak rule).  No bindings are
    // eligible, so `live_aors` is empty and every miss counter is cleared.
    if live_ips.is_empty() || use_times.is_empty() {
        liveness_gc(
            &context.last_seen,
            &context.misses,
            &live_ips,
            &std::collections::HashSet::new(),
        );
        return;
    }

    let now = match now_unix() {
        Some(now) => now,
        None => return,
    };
    let liveness = &state.registrar_liveness;
    let idle_window =
        liveness.keepalive_interval_secs as u64 * liveness.idle_multiplier.max(1) as u64;
    let probe_timeout = std::time::Duration::from_millis(liveness.probe_timeout_ms);
    // AoRs of live IPsec bindings seen this sweep — the post-sweep GC keeps miss
    // counters only for these and drops counters for bindings that have vanished.
    let mut live_aors: std::collections::HashSet<String> =
        std::collections::HashSet::with_capacity(sa_by_ip.len());
    let mut total = 0usize;
    let mut ipsec_protected = 0usize;
    let mut suspects = 0usize;

    for (aor, contact) in context.registrar.all_contacts() {
        total += 1;
        let ue_addr = match contact.source_addr {
            Some(addr) => addr,
            None => continue,
        };
        // Any IPsec-protected binding is eligible — UDP *or* TCP/TLS/WS.  The
        // XFRM SA use-time is the authoritative liveness signal regardless of
        // SIP transport: a Gm registration over TCP whose UE silently dies
        // (radio loss, no FIN/RST) is invisible to flow-failure dereg until
        // the CRLF-keepalive timeout (minutes), but its SA goes stale at the
        // same rate as a UDP UE's.  Matching on the SA (by UE IP) also
        // naturally excludes non-IPsec bindings, which have no use-time signal
        // and rely on flow-failure (Part A) alone.
        let row = match sa_by_ip.get(&ue_addr.ip()) {
            Some(row) => row,
            None => continue, // not an IPsec-protected UE
        };
        ipsec_protected += 1;
        live_aors.insert(aor.clone());

        // Most recent inbound activity across the two inbound SAs (the SAs the
        // UE's keepalive / MO requests land on).
        let kernel_last_active = use_times
            .get(&row.spi_ps)
            .copied()
            .unwrap_or(0)
            .max(use_times.get(&row.spi_pc).copied().unwrap_or(0));
        if kernel_last_active == 0 {
            // Neither inbound SA is currently in the kernel dump — likely a
            // dump/snapshot race or an SA mid-teardown.  Genuine teardown is
            // handled by the abandoned-SA sweep (Part B.4); skip here to avoid
            // false deregistration.
            continue;
        }
        // Fold in siphon's own SIP-layer last-seen: on some kernels the XFRM
        // inbound use-time does not advance on an inbound-answered SA, so a live
        // UE that answers its keepalive / OPTIONS every 30 s still looks idle to
        // the kernel counter alone.  The SIP signal (refreshed on every message
        // arriving on a protected port) corrects that, collapsing the probe
        // cadence for a responsive UE from every sweep to at most once per idle
        // window.
        let sip_last_seen = context
            .last_seen
            .get(&ue_addr.ip())
            .map(|entry| *entry)
            .unwrap_or(0);
        let last_active = liveness_last_active(kernel_last_active, sip_last_seen);
        if liveness_recently_active(now, last_active, idle_window) {
            // Recently active → clear any stale miss strike so a UE that
            // answered normally never carries a partial strike into a later
            // idle window.
            context.misses.remove(&aor);
            continue;
        }

        // Suspect.  Probe over the binding's *actual* transport — for a stream
        // binding the OPTIONS rides the captured inbound connection, so a dead
        // half-open socket simply yields no answer within probe_timeout.
        // Detach so a slow UE can't stall the sweep.
        suspects += 1;
        let binding_transport = transport_from_name(contact.source_transport.as_deref());
        debug!(
            aor = %aor,
            ue = %ue_addr,
            transport = %binding_transport,
            idle_secs = now.saturating_sub(last_active),
            idle_window,
            "registrar liveness: binding idle past window — probing with OPTIONS"
        );
        let (source_local_addr, transport) =
            crate::script::api::ipsec::outbound_for(ue_addr, binding_transport).unwrap_or((
                contact.inbound_local_addr.unwrap_or(ue_addr),
                binding_transport,
            ));
        // Stream: ride the captured inbound connection (a dead half-open socket
        // times out → dereg).  UDP routes by source_local_addr, so the sentinel
        // id is correct there.
        let connection_id = if matches!(transport, Transport::Udp) {
            ConnectionId::default()
        } else {
            contact
                .inbound_connection_id
                .map(ConnectionId)
                .unwrap_or_default()
        };
        let context = context.clone();
        let aor = aor.clone();
        let contact = contact.clone();
        let ue_port_c = row.ue_port_c;
        tokio::spawn(async move {
            liveness_probe_then_dereg(
                context,
                aor,
                contact,
                ue_port_c,
                source_local_addr,
                transport,
                connection_id,
                probe_timeout,
            )
            .await;
        });
    }

    // Reconcile the liveness bookkeeping with the current registration set so
    // last-seen / miss entries drain to baseline as UEs deregister (project
    // per-module leak rule): keep last-seen only for IPs that still have a live
    // SA, and miss counters only for AoRs still present as IPsec bindings.  A
    // UE that de-REGISTERs normally has its SA torn down, so its IP leaves
    // `live_ips` and its entries are dropped on the next sweep.
    liveness_gc(&context.last_seen, &context.misses, &live_ips, &live_aors);

    // Census so an operator can see why a dead UE is (or isn't) being reaped.
    debug!(
        contacts = total,
        ipsec_protected,
        idle_suspect = suspects,
        idle_window_secs = idle_window,
        tracked_last_seen = context.last_seen.len(),
        tracked_misses = context.misses.len(),
        "registrar liveness: idle sweep census"
    );
}

/// Map a stored `source_transport` string to a `Transport` (defaults to UDP).
fn transport_from_name(name: Option<&str>) -> Transport {
    match name.map(|n| n.to_ascii_lowercase()).as_deref() {
        Some("tcp") => Transport::Tcp,
        Some("tls") => Transport::Tls,
        Some("ws") => Transport::WebSocket,
        Some("wss") => Transport::WebSocketSecure,
        _ => Transport::Udp,
    }
}

/// Send one OPTIONS over the captured flow (with a single retry); if the UE
/// answers, stamp its SIP-layer last-seen and clear any miss strike so the next
/// sweep skips it for a full idle window.  On no answer, apply consecutive-miss
/// hysteresis: keep the binding for `miss_threshold` failed sweeps (a UE racing
/// an ECM-IDLE → paging → reconnect window misses one sweep and answers the
/// next) and only run the dereg funnel once the grace is exhausted.
async fn liveness_probe_then_dereg(
    context: LivenessDeregCtx,
    aor: String,
    contact: crate::registrar::Contact,
    ue_port_c: u16,
    source_local_addr: SocketAddr,
    transport: Transport,
    connection_id: ConnectionId,
    probe_timeout: std::time::Duration,
) {
    let destination = match contact.source_addr {
        Some(addr) => addr,
        None => return,
    };
    let request_uri = contact.uri.clone();

    for attempt in 0..2 {
        let receiver = context.uac_sender.send_options_over_flow(
            destination,
            source_local_addr,
            transport,
            connection_id,
            request_uri.clone(),
        );
        if let Ok(Ok(crate::uac::UacResult::Response(_))) =
            tokio::time::timeout(probe_timeout, receiver).await
        {
            // The UE is alive — stamp its SIP last-seen (in case the general
            // inbound stamp raced or the answer arrived over UDP) and reset the
            // hysteresis counter so a later transient miss starts from zero.
            if let Some(now) = now_unix() {
                liveness_note_alive(&context.last_seen, &context.misses, destination.ip(), &aor, now);
            }
            debug!(aor = %aor, attempt, "registrar liveness: UE answered OPTIONS probe — keeping binding");
            return;
        }
    }

    // No answer this sweep.  Bump the consecutive-miss counter; only reap once
    // it reaches `miss_threshold`, so a single missed probe (paging in flight)
    // never false-deregisters a live UE.
    let before = context.misses.get(&aor).map(|entry| *entry).unwrap_or(0);
    let (misses, reap) = liveness_miss_outcome(before, context.miss_threshold);
    if !reap {
        context.misses.insert(aor.clone(), misses);
        info!(
            aor = %aor,
            misses,
            threshold = context.miss_threshold,
            "registrar liveness: probe unanswered — within grace, re-probing next sweep"
        );
        return;
    }
    context.misses.remove(&aor);
    liveness_dereg_contact(
        &context,
        &aor,
        &contact,
        Some(ue_port_c),
        "ipsec idle (no OPTIONS answer, grace exhausted)",
    )
    .await;
}

/// The shared dereg funnel for both the idle-probe path and the SA-teardown
/// path.  Removes the local binding (which emits `Deregistered` →
/// `@registrar.on_change` → the terminated reg-event NOTIFY), tears down the
/// UE's IPsec SA, and — for a P-CSCF cache binding under `network_dereg` —
/// synthesizes a de-REGISTER (`Expires: 0`) toward the S-CSCF so the
/// registrar of record clears the binding too.
async fn liveness_dereg_contact(
    context: &LivenessDeregCtx,
    aor: &str,
    contact: &crate::registrar::Contact,
    ue_port_c: Option<u16>,
    reason: &str,
) {
    let contact_uri = contact.uri.to_string();
    let network_dereg = context.dereg_mode == crate::config::LivenessDeregMode::NetworkDereg
        && contact.flow_token.is_some();
    info!(
        aor = %aor,
        contact = %contact_uri,
        reason,
        network_dereg,
        "registrar liveness: deregistering binding"
    );

    // 1. P-CSCF network de-REGISTER (before dropping local state, while the
    //    Service-Route is still available).  Only for a proxy-cached binding
    //    (one carrying a flow_token) under network-dereg mode.
    if network_dereg {
        send_liveness_network_dereg(context, aor, &contact_uri).await;
    }

    // 2. Drop the local binding — emits Deregistered → on_change cascade.
    context.registrar.remove_contact(aor, &contact_uri);

    // 3. Tear down the UE's IPsec SA so the kernel state goes with the binding.
    if let (Some(manager), Some(ue_addr), Some(ue_port_c)) =
        (&context.ipsec_manager, contact.source_addr, ue_port_c)
    {
        if let Err(error) = manager.delete_sa_pair(&ue_addr.ip(), ue_port_c).await {
            debug!(aor = %aor, %error, "registrar liveness: IPsec SA teardown failed (may already be gone)");
        }
    }

    // 4. Prune the liveness bookkeeping for the gone binding so it drains with
    //    the registration (the sweep GC would also catch it once the SA leaves
    //    the kernel snapshot, but pruning here keeps both maps tight).
    context.misses.remove(aor);
    if let Some(ue_addr) = contact.source_addr {
        context.last_seen.remove(&ue_addr.ip());
    }
}

/// Synthesize and fire-and-forget a de-REGISTER (`Expires: 0`) toward the
/// S-CSCF via the binding's stored Service-Route, on the UE's behalf.
async fn send_liveness_network_dereg(context: &LivenessDeregCtx, aor: &str, contact_uri: &str) {
    let routes = context.registrar.service_routes(aor);
    let top_route = match routes.first() {
        Some(route) => route.clone(),
        None => {
            debug!(aor = %aor, "registrar liveness: no Service-Route — skipping network de-REGISTER");
            return;
        }
    };

    // Resolve the top Service-Route to a next hop.
    let route_uri = match parse_route_uri(&top_route) {
        Some(uri) => uri,
        None => {
            warn!(aor = %aor, route = %top_route, "registrar liveness: unparseable Service-Route");
            return;
        }
    };
    let scheme = if route_uri.scheme == "sips" { "sips" } else { "sip" };
    let targets = context
        .dns_resolver
        .resolve(&route_uri.host, route_uri.port, scheme, Some("udp"))
        .await;
    let destination = match targets.first() {
        Some(target) => target.address,
        None => {
            warn!(aor = %aor, host = %route_uri.host, "registrar liveness: Service-Route did not resolve");
            return;
        }
    };

    let register = match build_dereg_register(aor, contact_uri, &routes, destination) {
        Ok(message) => message,
        Err(error) => {
            warn!(aor = %aor, %error, "registrar liveness: failed to build de-REGISTER");
            return;
        }
    };
    info!(aor = %aor, %destination, "registrar liveness: sending network de-REGISTER (Expires: 0) to S-CSCF");
    context
        .uac_sender
        .send_request(register, destination, Transport::Udp);
}

/// Parse a Route/Service-Route header value (`<sip:host:port;lr>`) into a
/// `SipUri`.
fn parse_route_uri(route: &str) -> Option<SipUri> {
    let trimmed = route.trim();
    let inner = trimmed
        .strip_prefix('<')
        .and_then(|rest| rest.split('>').next())
        .unwrap_or(trimmed);
    parse_uri_standalone(inner).ok()
}

/// Build a de-REGISTER (REGISTER with `Expires: 0`) on the UE's behalf,
/// routed to the S-CSCF via the stored Service-Route(s).
///
/// - R-URI is the registrar domain (the AoR's host).
/// - To/From are the AoR; Contact is the UE's binding with `;expires=0`.
/// - `Route` carries the Service-Route set so the request reaches the same
///   S-CSCF that granted the registration.
fn build_dereg_register(
    aor: &str,
    contact_uri: &str,
    routes: &[String],
    destination: SocketAddr,
) -> Result<SipMessage, String> {
    let aor_uri = parse_uri_standalone(aor).ok();
    let domain = aor_uri
        .as_ref()
        .map(|uri| uri.host.clone())
        .unwrap_or_else(|| destination.ip().to_string());
    // The S-CSCF skips the IMS-AKA re-challenge on a re-/de-REGISTER only when
    // it arrives integrity-protected (TS 24.229 §5.4.1.2.2): a real UE de-REG
    // rides the IPsec SA and the P-CSCF stamps `integrity-protected="ip-assoc-yes"`
    // (§5.2.6.3).  This synthesized de-REGISTER asserts that same protection on
    // the (now-torn-down) SA's behalf — the P-CSCF *was* the entity holding the
    // SA — so it must carry the marker; without it the S-CSCF challenges
    // (401/403) and the de-registration never completes (no SAR
    // User-Deregistration, no AS 3rd-party de-REGISTER, no terminated NOTIFY).
    // The S-CSCF keys the skip on the marker substring + `is_registered(pub_id)`
    // (pub_id from To/From, not the Authorization username), so the digest
    // fields are placeholders.
    let username = aor_uri
        .as_ref()
        .and_then(|uri| uri.user.clone())
        .map(|user| format!("{user}@{domain}"))
        .unwrap_or_else(|| domain.clone());
    let authorization = format!(
        "Digest username=\"{username}\", realm=\"{domain}\", nonce=\"\", \
         uri=\"sip:{domain}\", response=\"\", integrity-protected=\"ip-assoc-yes\""
    );
    let request_uri = SipUri::new(domain);

    let branch = format!("z9hG4bK-liveness-{}", uuid::Uuid::new_v4());
    let via = format!(
        "SIP/2.0/UDP {}:{};branch={}",
        destination.ip(),
        destination.port(),
        branch
    );
    let from_tag = uuid::Uuid::new_v4();
    let call_id = format!("liveness-dereg-{}", uuid::Uuid::new_v4());

    let mut builder = SipMessageBuilder::new()
        .request(Method::Register, request_uri)
        .via(via)
        .from(format!("<{aor}>;tag=liveness-{from_tag}"))
        .to(format!("<{aor}>"))
        .call_id(call_id)
        .cseq("1 REGISTER".to_string())
        .max_forwards(70)
        .header("Authorization", authorization)
        .header("Contact", format!("<{contact_uri}>;expires=0"))
        .header("Expires", "0".to_string());

    for route in routes {
        builder = builder.header("Route", route.clone());
    }

    builder.content_length(0).build()
}

/// Handle a single inbound SIP message (request or response).
fn handle_inbound(inbound: InboundMessage, state: &Arc<DispatcherState>) {
    // Defensive drop of all-whitespace UDP datagrams (RFC 3261 §7.5 — peers
    // may send stray CRLF as a NAT keepalive ping).  Stream transports
    // (TCP/TLS/WSS/pool) handle RFC 5626 §4.4.1 ping/pong in their own
    // read tasks before forwarding to the dispatcher, so this branch only
    // fires for UDP and shields the parser from logging a warn.
    //
    // Fast-path gate: real SIP messages start with an uppercase ASCII
    // letter, so the all-bytes scan only runs when the first byte already
    // looks like whitespace.
    if matches!(inbound.data.first(), Some(b'\r' | b'\n' | b' ')) {
        let all_whitespace = inbound.data.iter()
            .all(|b| matches!(b, b'\r' | b'\n' | b' '));
        if all_whitespace {
            return;
        }
    }

    // Parse SIP message — supports binary bodies (e.g. SMS TPDU)
    let message = match parse_sip_message_bytes(&inbound.data) {
        Ok(message) => message,
        Err(error) => {
            warn!(remote = %inbound.remote_addr, "SIP parse error: {error}");
            return;
        }
    };

    // HEP capture — inbound (received from network)
    if let Some(ref hep) = state.hep_sender {
        hep.capture_inbound(
            inbound.remote_addr,
            state.hep_local_addr(inbound.local_addr, inbound.transport),
            inbound.transport,
            &inbound.data,
        );
    }

    // Registrar-liveness SIP-layer last-seen (Part B, fix A).  Any message
    // arriving on a P-CSCF protected port is inbound traffic from a UE with a
    // live IPsec SA — a direct liveness signal siphon observes even when the
    // kernel XFRM `use_time` counter fails to advance.  The SA-idle sweep folds
    // this into its idle test, so a UE that just answered anything (its
    // keepalive, an MO request, or the OPTIONS probe's 200) is not re-probed
    // for a full idle window.  Gated on `enabled` first so it is a single bool
    // read when liveness is off (the default); `is_protected_local_port` bounds
    // the keyspace to active IPsec UEs.
    if state.registrar_liveness.enabled
        && crate::script::api::ipsec::is_protected_local_port(inbound.local_addr.port())
    {
        if let Some(now) = now_unix() {
            state
                .liveness_last_seen
                .insert(inbound.remote_addr.ip(), now);
        }
    }

    match &message.start_line {
        StartLine::Request(request_line) => {
            let method = request_line.method.as_str().to_string();
            handle_request(inbound, message, method, state);
        }
        StartLine::Response(status_line) => {
            let status_code = status_line.status_code;
            handle_response(inbound, message, status_code, state);
        }
    }
}

/// Handle an inbound SIP request — run through Python handlers.
fn handle_request(
    inbound: InboundMessage,
    message: SipMessage,
    method: String,
    state: &Arc<DispatcherState>,
) {
    // --- Request security filter (scanner_block + rate_limit) ---
    // Runs before any transaction/dialog/script processing. trusted_cidrs are
    // exempt (handled inside the filter). A blocked request is dropped silently
    // (no response) so we never fingerprint the server to scanners — the same
    // silent-drop policy the Python blocking API uses. Opt-in: a cheap OnceLock
    // read that no-ops until security.rate_limit / security.scanner_block is set.
    if let Some(filter) = crate::security::security_filter() {
        let source = inbound.remote_addr.ip();
        let user_agent = message.headers.get("User-Agent").map(String::as_str);
        match filter.evaluate(source, user_agent) {
            crate::security::SecurityVerdict::Allow => {}
            crate::security::SecurityVerdict::Scanner => {
                debug!(source = %source, %method, "security: dropping request (scanner User-Agent)");
                if let Some(metrics) = crate::metrics::try_metrics() {
                    metrics.scanner_blocked_total.inc();
                }
                // Escalate to an IP ban so the scanner's *other* probes (across
                // methods and transports) are dropped at the ACL too — but only
                // over a connection-oriented transport, where the TCP/TLS/WS/SCTP
                // handshake validates the source address. A scanner User-Agent in
                // a lone UDP datagram has a spoofable source, so banning on it
                // would let an attacker get a victim's IP banned (reflected ban).
                if inbound.transport != crate::transport::Transport::Udp {
                    if let Some(ban) = crate::security::auto_ban() {
                        if ban.record_strong_failure(source) {
                            warn!(source = %source, "auto-ban: source banned (scanner User-Agent)");
                        }
                    }
                }
                return;
            }
            crate::security::SecurityVerdict::RateLimited => {
                debug!(source = %source, %method, "security: dropping request (rate limit exceeded)");
                if let Some(metrics) = crate::metrics::try_metrics() {
                    metrics.rate_limited_total.inc();
                }
                return;
            }
        }
    }

    // --- Extract the UAC's Via branch and sent-by ---
    let uac_via = message
        .headers
        .get("Via")
        .and_then(|raw| Via::parse_multi(raw).ok())
        .and_then(|vias| vias.into_iter().next());
    let uac_branch = uac_via.as_ref().and_then(|v| v.branch.clone());
    let uac_sent_by = uac_via.as_ref()
        .map(|v| TransactionKey::format_sent_by(&v.host, v.port))
        .unwrap_or_default();

    // --- CANCEL handling ---
    // CANCEL has the same branch as the INVITE it cancels, so we must
    // intercept it BEFORE retransmission detection (which keys on branch).
    if method == "CANCEL" {
        handle_cancel(inbound, message, uac_branch.as_deref(), &uac_sent_by, state);
        return;
    }

    // --- ACK handling (RFC 3261 §17.2.1) ---
    // ACK for non-2xx is hop-by-hop: the transaction layer absorbs it.
    // ACK for 2xx is end-to-end: no IST exists (it terminated on 2xx),
    // so handle_ack returns None and we fall through to the script.
    if method == "ACK" {
        match state.transaction_manager.handle_ack(&message) {
            Ok(Some((key, actions))) => {
                debug!(
                    key = %key,
                    "ACK absorbed by INVITE server transaction"
                );
                process_timer_actions(
                    &actions,
                    &key,
                    Some(inbound.remote_addr),
                    Some(inbound.transport),
                    Some(inbound.connection_id),
                    Some(inbound.local_addr),
                    state,
                );
                return;
            }
            Ok(None) => {
                // No IST found — ACK for 2xx (end-to-end) or stale.
                // Route via ProxySession using Call-ID + From-tag dialog key.
                // Using both fields avoids ambiguity when a B2BUA (e.g. FreeSWITCH)
                // reuses the same Call-ID for both call legs through this proxy.
                let call_id = message.headers.get("Call-ID");
                let from_tag = message
                    .typed_from()
                    .ok()
                    .flatten()
                    .and_then(|na| na.tag);
                if let (Some(cid), Some(ftag)) = (call_id, from_tag.as_deref()) {
                    if let Some(session_arc) = state.session_store.get_by_dialog_key(cid, ftag) {
                        handle_ack_via_session(inbound, message, session_arc, state);
                        return;
                    }

                    // B2BUA late ACK: absorb A-leg's ACK, then send deferred
                    // ACK to the winning B-leg. This completes both legs of the
                    // INVITE transaction simultaneously (RFC 3261 §14.1).
                    if let Some(internal_id) = state.call_actors.find_by_sip_call_id(cid) {
                        // The caller's ACK stops A-leg 2xx retransmission
                        // (RFC 3261 §13.3.1.4). Fire the Notify so the retransmit
                        // task exits; no-op if none is armed (non-2xx ACK).
                        if let Some((_, notify)) = state.uas_2xx_retransmits.remove(&internal_id) {
                            notify.notify_one();
                        }
                        // Take the pending ACK and mark both legs as ACKed
                        let pending_ack = if let Some(mut call) = state.call_actors.get_call_mut(&internal_id) {
                            call.a_leg.initial_acked = true;
                            if let Some(b_leg) = call.winner.and_then(|i| call.b_legs.get_mut(i)) {
                                b_leg.initial_acked = true;
                            }
                            call.pending_b_leg_ack.take()
                        } else {
                            None
                        };

                        // Send the pre-built ACK to B-leg
                        if let Some((ack, b_transport, b_dest)) = pending_ack {
                            send_b2bua_to_bleg(ack, b_transport, b_dest, state);
                            debug!(
                                call_id = %internal_id,
                                "B2BUA: sent deferred ACK to B-leg (A-leg ACKed)"
                            );
                        } else {
                            debug!(
                                call_id = %internal_id,
                                "B2BUA: absorbed A-leg ACK (no pending B-leg ACK)"
                            );
                        }
                        return;
                    }
                }
                debug!("ACK matched no IST/session/dialog — dropping (RFC 3261: never respond to or route an ACK)");
            }
            Err(error) => {
                debug!("failed to match ACK to transaction: {error} — dropping ACK");
            }
        }
        // An ACK that matched no server transaction, dialog session, or B2BUA
        // call is a stray/orphan — e.g. the caller's ACK for a B2BUA-forwarded
        // non-2xx (407/486/…) whose call was already torn down, or an ACK that
        // arrives after teardown. RFC 3261 §17: a stateful element MUST NOT
        // respond to an ACK, and an ACK is never a routable standalone request.
        // Drop it silently — never fall through to request routing, which would
        // otherwise fabricate a 502 back to the ACK when its R-URI does not
        // resolve (a response to an ACK — itself a protocol violation).
        return;
    }

    // --- Server transaction retransmission detection ---
    // Check if a server transaction already exists for this request.
    // If so, the state machine handles retransmission (resending cached response).
    match state.transaction_manager.handle_server_retransmit(&message) {
        Ok(Some((key, actions))) => {
            debug!(
                method = %method,
                key = %key,
                "request retransmit handled by server transaction"
            );
            // Process actions — typically SendMessage to resend cached response.
            // Look up ProxySession for source routing, fall back to inbound info.
            for action in &actions {
                if let Action::SendMessage(response) = action {
                    // Send response back to the UAC (the original request source)
                    send_message_from(
                        response.clone(),
                        inbound.transport,
                        inbound.remote_addr,
                        inbound.connection_id,
                        Some(inbound.local_addr),
                        state,
                    );
                }
            }
            return;
        }
        Ok(None) => {
            // No existing server transaction — this is a new request, proceed below.
        }
        Err(error) => {
            debug!(method = %method, "failed to check server retransmit: {error}");
        }
    }

    debug!(
        method = %method,
        remote = %inbound.remote_addr,
        "processing request"
    );

    // --- SRS: detect inbound SIPREC INVITEs, ACKs, and BYEs ---
    if let Some(ref srs_manager) = state.srs_manager {
        if method == "INVITE" && is_siprec_invite(&message) {
            handle_srs_invite(inbound, message, Arc::clone(srs_manager), state);
            return;
        }
        let sip_call_id = message.headers.get("Call-ID").map(|s| s.to_string());
        if let Some(ref call_id) = sip_call_id {
            if srs_manager.is_srs_session(call_id) {
                if method == "ACK" {
                    debug!(call_id = %call_id, "SRS: absorbed ACK for recording session");
                    return;
                }
                if method == "BYE" {
                    handle_srs_bye(inbound, message, call_id, Arc::clone(srs_manager), state);
                    return;
                }
            }
        }
    }

    // Graceful drain — reject NEW INVITEs only (in-dialog re-INVITEs identified
    // by To-tag must still flow so active calls can finish their renegotiation).
    // ACK/BYE/PRACK/CANCEL and all responses are unaffected.
    if method == "INVITE"
        && state.is_draining.is_draining.load(std::sync::atomic::Ordering::Relaxed)
    {
        let to_has_tag = message.headers.get("To")
            .map(|t| t.split(';').any(|p| p.trim().starts_with("tag=")))
            .unwrap_or(false);
        if !to_has_tag {
            debug!("draining — rejecting new INVITE with 503 Service Unavailable");
            let response = build_response(
                &message, 503, "Service Unavailable",
                state.server_header.as_deref(), &[],
            );
            send_message_from(response, inbound.transport, inbound.remote_addr, inbound.connection_id, Some(inbound.local_addr), state);
            return;
        }
    }

    // Check if B2BUA mode should handle this INVITE
    let engine_state = state.engine.state();
    if method == "INVITE" && engine_state.has_b2bua_handlers() {
        // Detect re-INVITE (has To-tag + matches existing call)
        let to_tag = message.headers.get("To")
            .and_then(|t| t.split(';')
                .find(|p| p.trim().starts_with("tag="))
                .map(|t| t.trim().trim_start_matches("tag=").to_string()));
        let sip_call_id = message.headers.get("Call-ID").map(|s| s.to_string());

        let is_reinvite = to_tag.is_some()
            && sip_call_id.as_ref()
                .map(|cid| state.call_actors.find_by_sip_call_id(cid).is_some())
                .unwrap_or(false);

        if is_reinvite {
            drop(engine_state);
            handle_b2bua_reinvite(inbound, message, state);
            return;
        }

        drop(engine_state);
        handle_b2bua_invite(inbound, message, state);
        return;
    }
    if method == "BYE" && engine_state.has_b2bua_handlers() {
        // Check if this BYE belongs to a B2BUA call
        let sip_call_id = message.headers.get("Call-ID").map(|s| s.to_string());
        if let Some(ref sip_call_id) = sip_call_id {
            if state.call_actors.find_by_sip_call_id(sip_call_id).is_some() {
                drop(engine_state);
                handle_b2bua_bye(inbound, message, state);
                return;
            }
        }
    }
    // Rf ACR-STOP on inbound proxy BYE (TS 32.299 §6.2.2).  Fires
    // before the script handler so accounting is closed even if the
    // script chooses to drop or reject the BYE; the SIP path itself
    // is unaffected (spawn is fire-and-forget).
    if method == "BYE" {
        spawn_rf_proxy_stop_if_tracked(state, &message);
        // CDR: write the call record on in-dialog BYE (cdr.auto_emit).
        cdr_finalize_proxy_stop(state, &message);
    }
    if method == "UPDATE" && engine_state.has_b2bua_handlers() {
        // RFC 3311 in-dialog UPDATE belonging to a B2BUA call: bridge it
        // across like a re-INVITE. Calls that don't match a tracked B2BUA
        // dialog fall through to proxy mode (correct for stateless UPDATE
        // forwarding by non-B2BUA scripts).
        let sip_call_id = message.headers.get("Call-ID").map(|s| s.to_string());
        if let Some(ref sip_call_id) = sip_call_id {
            if state.call_actors.find_by_sip_call_id(sip_call_id).is_some() {
                drop(engine_state);
                handle_b2bua_update(inbound, message, state);
                return;
            }
        }
    }
    if method == "PRACK" {
        // RFC 3262 §3 — does this PRACK acknowledge a reliable provisional we
        // sent ourselves (script called reply(reliable=True))? If so: cancel
        // retransmits, send 200 OK PRACK, done. Runs in both proxy and B2BUA
        // modes; the B2BUA-specific auto-200 path below only fires when no
        // tracked entry matches (e.g. A-leg PRACKs that originated from the
        // UAC's own 100rel handling, not from us).
        if let Some(rack) = crate::sip::headers::rseq::parse_rack(&message.headers) {
            let sip_call_id = message.headers.get("Call-ID").map(|s| s.to_string()).unwrap_or_default();
            let key = (sip_call_id.clone(), rack.response_number);
            let matched = state.reliable_provisionals.get(&key)
                .map(|r| Arc::clone(r.value()))
                .filter(|entry| entry.cseq_num == rack.cseq_number);
            if let Some(entry) = matched {
                state.reliable_provisionals.remove(&key);
                entry.cancel.notify_one();
                debug!(
                    call_id = %sip_call_id, rseq = rack.response_number,
                    "PRACK matches our reliable 1xx — cancelling retransmits and sending 200 OK"
                );
                let response = build_response(&message, 200, "OK", state.server_header.as_deref(), &[]);
                send_message_from(response, inbound.transport, inbound.remote_addr, inbound.connection_id, Some(inbound.local_addr), state);
                return;
            }
        }

        if engine_state.has_b2bua_handlers() {
            // RFC 3262: the A-leg PRACK acknowledges our reliable provisional.
            // In B2BUA mode siphon already PRACKed the B-leg locally (see the
            // auto-PRACK path in the response handler), so the A-leg PRACK has
            // no upstream peer to relay to — terminate it here with 200 OK.
            let sip_call_id = message.headers.get("Call-ID").map(|s| s.to_string());
            if let Some(ref sip_call_id) = sip_call_id {
                if state.call_actors.find_by_sip_call_id(sip_call_id).is_some() {
                    drop(engine_state);
                    handle_b2bua_prack(inbound, message, state);
                    return;
                }
            }
        }
    }

    // --- Create server transaction ---
    // The server transaction handles retransmission absorption and timer management.
    // ACK is excluded (handled by existing IST), as are requests going to B2BUA.
    let txn_transport = crate::transaction::state::Transport::from(inbound.transport);
    let server_key = match state.transaction_manager.new_server_transaction(&message, txn_transport) {
        Ok((key, actions)) => {
            // Schedule any initial server-side timers
            for action in &actions {
                if let Action::StartTimer(name, duration) = action {
                    let timer_id = format!("{}:{:?}", key, name);
                    state.timer_wheel.insert(timer_id, TimerEntry {
                        key: key.clone(),
                        name: *name,
                        fires_at: std::time::Instant::now() + *duration,
                        // Server transaction timers send responses upstream (to UAC)
                        destination: Some(inbound.remote_addr),
                        transport: Some(inbound.transport),
                        connection_id: Some(inbound.connection_id),
                        // Retransmit cached responses on the same SA's
                        // local endpoint (TS 33.203 §7.4).
                        source_local_addr: Some(inbound.local_addr),
                    });
                }
            }
            Some(key)
        }
        Err(error) => {
            debug!(method = %method, "failed to create server transaction: {error}");
            None
        }
    };

    // --- Max-Forwards enforcement (RFC 3261 §16.3) ---
    // Check BEFORE invoking scripts — if MF == 0, reject immediately.
    if message.headers.max_forwards() == Some(0) {
        debug!(method = %method, "Max-Forwards is 0, rejecting with 483");
        let response = build_response(&message, 483, "Too Many Hops", state.server_header.as_deref(), &[]);
        send_message_from(response, inbound.transport, inbound.remote_addr, inbound.connection_id, Some(inbound.local_addr), state);
        return;
    }

    // Look up matching Python handlers
    let handlers = engine_state.proxy_request_handlers(&method);

    if handlers.is_empty() {
        warn!(method = %method, "no script handler registered");
        let response = build_response(&message, 500, "No Script Handler", state.server_header.as_deref(), &[]);
        send_message_from(response, inbound.transport, inbound.remote_addr, inbound.connection_id, Some(inbound.local_addr), state);
        return;
    }

    // Create PyRequest wrapping the message
    let transport_name = format!("{}", inbound.transport).to_lowercase();
    let message_arc = Arc::new(std::sync::Mutex::new(message));
    let mut request = PyRequest::with_local_domains(
        message_arc.clone(),
        transport_name,
        inbound.remote_addr.ip().to_string(),
        inbound.remote_addr.port(),
        Arc::clone(&state.local_domains),
    );
    // Tag the request with its arrival local port so `is_ipsec_protected`
    // / `matched_sa` can resolve when running as P-CSCF (3GPP TS 33.203).
    request.set_local_port(inbound.local_addr.port());
    // Capture the full inbound flow for token-keyed MT routing
    // (`registrar.save(flow_token=...)` and `request.relay(flow=...)`).
    request.set_inbound_flow(inbound.local_addr, inbound.connection_id.0);

    // Call Python handlers
    let (action, record_routed, on_reply_cb, on_failure_cb, send_via_transport, send_via_target, reply_headers, reply_body) = Python::attach(|python| {
        let py_request = match Py::new(python, request) {
            Ok(py) => py,
            Err(error) => {
                error!("failed to create PyRequest: {error}");
                return (RequestAction::None, false, None, None, None, None, vec![], None);
            }
        };

        // Enable deferred sends so presence.notify() etc. queue messages
        // until after the reply is sent (RFC 3265 §3.1.6.2).
        crate::script::api::proxy_utils::enable_deferred_sends();

        for handler in &handlers {
            let callable = handler.callable.bind(python);
            let result = callable.call1((py_request.bind(python),));
            match result {
                Ok(ret) => {
                    // If the handler is async, the return value is a coroutine — await it.
                    if handler.is_async {
                        if let Err(error) = run_coroutine(python, &ret) {
                            error!("async Python handler error: {error}");
                            return (
                                RequestAction::Reply {
                                    code: 500,
                                    reason: "Script Error".to_string(),
                                    reliable: false,
                                },
                                false,
                                None,
                                None,
                                None,
                                None,
                                vec![],
                                None,
                            );
                        }
                    }
                }
                Err(error) => {
                    error!("Python handler error: {error}");
                    return (
                        RequestAction::Reply {
                            code: 500,
                            reason: "Script Error".to_string(),
                            reliable: false,
                        },
                        false,
                        None,
                        None,
                        None,
                        None,
                        vec![],
                        None,
                    );
                }
            }
        }

        let mut borrowed = py_request.borrow_mut(python);
        let action = borrowed.action().clone();
        let record_routed = borrowed.is_record_routed();
        let on_reply = borrowed.take_on_reply_callback();
        let on_failure = borrowed.take_on_failure_callback();
        let send_via_transport = borrowed.via_transport_override().map(|s| s.to_string());
        let send_via_target = borrowed.via_target_override().map(|s| s.to_string());
        let reply_headers = borrowed.take_reply_headers();
        let reply_body = borrowed.take_reply_body();
        (action, record_routed, on_reply, on_failure, send_via_transport, send_via_target, reply_headers, reply_body)
    });

    // Process the action
    let Ok(message_guard) = message_arc.lock() else {
        error!("message_arc lock poisoned");
        return;
    };
    match &action {
        RequestAction::None => {
            debug!("silent drop (no action from script)");
            // Reap the server transaction created for this request. A NIST/IST
            // whose TU never sends a final response never reaches Terminated
            // (RFC 3261 §17.2 has no absolute server-side timeout — it assumes
            // the TU always responds), so a silent drop would otherwise strand
            // it in the transaction map forever, each entry holding a full
            // SipMessage clone. Under unhandled-request churn (e.g. SUBSCRIBE to
            // a call-only B2BUA) or a scanner / rate-limit flood that is an
            // unbounded leak — and a memory-DoS vector. A dropped request has
            // nothing to retransmit-absorb; a later UDP retransmit just
            // recreates a fresh transaction and re-runs the handler (which drops
            // again). Also drop the auto-100 timer so the wheel entry is freed
            // immediately and the drop stays silent (no synthesized 100 Trying).
            if let Some(ref key) = server_key {
                state.transaction_manager.remove(key);
                state
                    .timer_wheel
                    .remove(&format!("{}:{:?}", key, TimerName::Trying100));
            }
        }
        RequestAction::Reply { code, reason, reliable } => {
            let mut response = build_response(&message_guard, *code, reason, state.server_header.as_deref(), &reply_headers);

            // Script-provided reply body — PIDF-LO, XCAP/Ut, custom failure body, etc.
            if let Some((body_bytes, content_type)) = &reply_body {
                response.headers.set("Content-Type", content_type.clone());
                response.headers.set("Content-Length", body_bytes.len().to_string());
                response.body = body_bytes.clone();
            }

            // RFC 3261 §11.2 — make a 2xx OPTIONS a proper capability response: a
            // Contact (Microsoft Teams Direct Routing rejects an OPTIONS answer
            // carrying neither Contact nor Record-Route) plus an Allow advertising
            // siphon's supported methods (peers read transfer capability from it).
            // Both are added only when absent, so a script-set header still wins.
            if method == "OPTIONS" && (200..300).contains(code) {
                augment_options_response(
                    &mut response,
                    &state.via_host(&inbound.transport),
                    state.via_port(&inbound.transport),
                    inbound.transport,
                );
            }

            // RFC 3262 — script asked for a reliable provisional. Only valid for
            // 101..199 INVITE responses, and only when the UAC advertised 100rel.
            // We attach Require: 100rel + a fresh RSeq, then arm a retransmit
            // task that fires until a matching PRACK arrives or the deadline
            // (32s = 64×T1) elapses.
            let mut reliable_provisional_armed = false;
            if *reliable && (101..200).contains(code) {
                if !crate::sip::headers::rseq::supports_100rel(&message_guard.headers) {
                    warn!(
                        method = %method, code = %code,
                        "reliable=True ignored: UAC didn't advertise 100rel in Supported/Require"
                    );
                } else if method != "INVITE" {
                    warn!(method = %method, code = %code,
                        "reliable=True ignored: only valid on responses to INVITE");
                } else {
                    let rseq = crate::sip::headers::rseq::next_rseq();
                    // Merge 100rel into existing Require if present, else set fresh.
                    let new_require = match response.headers.get("Require") {
                        Some(existing) if existing.split(',').any(|t| t.trim().eq_ignore_ascii_case("100rel")) =>
                            existing.clone(),
                        Some(existing) => format!("{}, 100rel", existing),
                        None => "100rel".to_string(),
                    };
                    response.headers.set("Require", new_require);
                    response.headers.set("RSeq", rseq.to_string());
                    arm_reliable_provisional_retransmit(
                        rseq, &message_guard, response.clone(), &inbound, state,
                    );
                    reliable_provisional_armed = true;
                }
            }
            let _ = reliable_provisional_armed;

            // IPsec Security-Server / SA setup on 401 REGISTER is now driven
            // by the P-CSCF script (see `siphon.ipsec` and `reply.take_av()`).
            // The dispatcher only retains de-register auto-cleanup as a safety
            // net for SA leaks.

            // IPsec: delete SA pair on deregistration (REGISTER with Expires: 0)
            if *code == 200 && method == "REGISTER" {
                if let (Some(ref _ipsec_config), Some(ref ipsec_manager)) =
                    (&state.ipsec_config, &state.ipsec_manager)
                {
                    let is_deregister = message_guard
                        .headers
                        .get("Expires")
                        .map(|value| value.trim() == "0")
                        .unwrap_or(false)
                        || message_guard
                            .headers
                            .get("Contact")
                            .map(|value| value.contains("expires=0"))
                            .unwrap_or(false);

                    if is_deregister {
                        let ue_addr = inbound.remote_addr.ip();
                        let ue_port = inbound.remote_addr.port();
                        let ipsec_manager = Arc::clone(ipsec_manager);
                        tokio::spawn(async move {
                            if let Err(error) = ipsec_manager.delete_sa_pair(&ue_addr, ue_port).await {
                                warn!(ue = %ue_addr, %error, "IPsec: failed to delete SA pair");
                            }
                        });
                    }
                }
            }

            // Feed response into server transaction so it can cache it for
            // retransmit handling and manage Timer J/G/H.
            // The state machine emits SendMessage which process_timer_actions
            // delivers, so we only send manually if the transaction path didn't fire.
            let mut sent_by_transaction = false;
            if let Some(ref key) = server_key {
                let server_event = if *code < 200 {
                    // Provisional
                    if key.method == crate::sip::message::Method::Invite {
                        Some(ServerEvent::Ist(IstEvent::TuProvisional(response.clone())))
                    } else {
                        Some(ServerEvent::Nist(NistEvent::TuProvisional(response.clone())))
                    }
                } else if *code < 300 && key.method == crate::sip::message::Method::Invite {
                    Some(ServerEvent::Ist(IstEvent::Tu2xx(response.clone())))
                } else if key.method == crate::sip::message::Method::Invite {
                    Some(ServerEvent::Ist(IstEvent::TuNon2xxFinal(response.clone())))
                } else {
                    Some(ServerEvent::Nist(NistEvent::TuFinal(response.clone())))
                };

                if let Some(event) = server_event {
                    match state.transaction_manager.process_server_event(key, event) {
                        Ok(actions) => {
                            process_timer_actions(
                                &actions,
                                key,
                                Some(inbound.remote_addr),
                                Some(inbound.transport),
                                Some(inbound.connection_id),
                                Some(inbound.local_addr),
                                state,
                            );
                            sent_by_transaction = actions.iter().any(|a| matches!(a, Action::SendMessage(_)));
                        }
                        Err(error) => {
                            debug!(key = %key, "failed to feed reply to server transaction: {error}");
                        }
                    }
                }
            }
            if !sent_by_transaction {
                send_message_from(response, inbound.transport, inbound.remote_addr, inbound.connection_id, Some(inbound.local_addr), state);
            }

        }
        RequestAction::Relay { next_hop, flow, send_socket } => {
            // RFC 3261 §16.2: a stateful proxy SHOULD send 100 Trying
            // immediately upon receiving an INVITE to stop UAC retransmissions.
            if method == "INVITE" {
                let trying = build_response(&message_guard, 100, "Trying", state.server_header.as_deref(), &[]);
                send_message_from(trying, inbound.transport, inbound.remote_addr, inbound.connection_id, Some(inbound.local_addr), state);
            }
            let send_socket = state.resolve_send_socket(send_socket.as_deref());
            relay_request(
                &message_guard,
                next_hop.as_deref(),
                record_routed,
                &inbound,
                server_key.as_ref(),
                state,
                on_reply_cb,
                on_failure_cb,
                send_via_transport.as_deref(),
                send_via_target.as_deref(),
                flow.as_ref(),
                send_socket.as_ref(),
            );
        }
        RequestAction::Fork { targets, flows, strategy, send_socket } => {
            if targets.is_empty() {
                warn!("fork with empty targets list");
                let response = build_response(&message_guard, 500, "No Targets", state.server_header.as_deref(), &[]);
                send_message_from(response, inbound.transport, inbound.remote_addr, inbound.connection_id, Some(inbound.local_addr), state);
            } else {
                if method == "INVITE" {
                    let trying = build_response(&message_guard, 100, "Trying", state.server_header.as_deref(), &[]);
                    send_message_from(trying, inbound.transport, inbound.remote_addr, inbound.connection_id, Some(inbound.local_addr), state);
                }
                let fork_strategy = match strategy.as_str() {
                    "sequential" => crate::proxy::fork::ForkStrategy::Sequential,
                    _ => crate::proxy::fork::ForkStrategy::Parallel,
                };
                let send_socket = state.resolve_send_socket(send_socket.as_deref());
                relay_fork_request(
                    &message_guard,
                    targets,
                    flows,
                    fork_strategy,
                    record_routed,
                    &inbound,
                    server_key.as_ref(),
                    state,
                    send_socket.as_ref(),
                );
            }
        }
    }

    // CDR: start tracking a relayed/forked INVITE so a record is written when
    // the call ends (cdr.auto_emit). Only a dialog-forming INVITE that the
    // proxy actually forwarded is tracked.
    if method == "INVITE"
        && matches!(
            action,
            RequestAction::Relay { .. } | RequestAction::Fork { .. }
        )
    {
        cdr_track_proxy_start(
            state,
            &message_guard,
            &inbound.remote_addr.ip().to_string(),
            &format!("{}", inbound.transport).to_lowercase(),
        );
    }

    // Flush deferred messages (e.g. in-dialog NOTIFY) after the reply/relay
    // has been dispatched, per RFC 3265 §3.1.6.2 (200 OK before NOTIFY).
    flush_deferred_sends(state);
}

/// Relay a SIP request to its destination.
///
/// 1. Determine target address (explicit next_hop, or Request-URI)
/// 2. Clone the message, add Via, decrement Max-Forwards
/// 3. Store branch in pending map for response routing
/// 4. Send to target
///
/// When `flow` is `Some`, target resolution is bypassed entirely:
/// the destination, transport, and outbound listener are taken from
/// the captured inbound flow.  Used for P-CSCF Path-token MT routing
/// (TS 24.229 §5.2.7.2) where the Contact URI is unreachable and
/// the only path back to the UE is the listener that received the
/// REGISTER.  Via host/port are derived from `flow.local_addr` so
/// the UE's response routes back to the right port (load-bearing for
/// IPSec sec-agree port pairs — 3GPP TS 33.203 §7.4).
fn relay_request(
    message: &SipMessage,
    next_hop: Option<&str>,
    record_routed: bool,
    inbound: &InboundMessage,
    server_key: Option<&TransactionKey>,
    state: &DispatcherState,
    on_reply_callback: Option<Py<PyAny>>,
    on_failure_callback: Option<Py<PyAny>>,
    send_via_transport: Option<&str>,
    send_via_target: Option<&str>,
    flow: Option<&crate::script::api::registrar::PyFlow>,
    send_socket: Option<&crate::transport::SendSocket>,
) {
    // Two ways to know where this request is going:
    //   a) flow=Some — use the captured inbound flow directly,
    //      bypassing DNS resolution of any URI.
    //   b) flow=None — resolve the next_hop / top Route / R-URI as usual.
    let (target_uri_string, destination, mut outbound_transport, flow_local_addr) =
        if let Some(flow) = flow {
            let transport = match flow.transport.as_str() {
                "udp" => Transport::Udp,
                "tcp" => Transport::Tcp,
                "tls" => Transport::Tls,
                "ws" => Transport::WebSocket,
                "wss" => Transport::WebSocketSecure,
                other => {
                    warn!(transport = %other, "flow-relay: unknown transport, falling back to inbound");
                    inbound.transport
                }
            };
            // For diagnostics only — the URI isn't used to pick the destination.
            let uri_string = match &message.start_line {
                StartLine::Request(request_line) => request_line.request_uri.to_string(),
                _ => {
                    error!("flow-relay called on non-request");
                    return;
                }
            };
            (uri_string, flow.source_addr, transport, Some(flow.local_addr))
        } else {
            // Determine target URI string (RFC 3261 §16.6 step 6):
            // 1. Explicit next-hop from script
            // 2. Top Route header URI (loose-routing — remaining after loose_route() popped ours)
            // 3. Request-URI (no Route headers)
            let target_uri_string = match next_hop {
                Some(hop) => hop.to_string(),
                None => {
                    if let Some(route_uri) = core::next_hop_from_route(&message.headers) {
                        route_uri
                    } else {
                        match &message.start_line {
                            StartLine::Request(request_line) => request_line.request_uri.to_string(),
                            _ => {
                                error!("relay called on non-request");
                                return;
                            }
                        }
                    }
                }
            };
            let target = match resolve_target(&target_uri_string, &state.dns_resolver) {
                Some(t) => t,
                None => {
                    // The next hop didn't resolve.  For an in-dialog request to
                    // a WebSocket UE this is expected — its Contact is an
                    // unresolvable `<uuid>.invalid` host (RFC 7118), so fall
                    // back to the connection the dialog was established on
                    // (RFC 5923 / RFC 5626 §5.3).  `send_to_target` then reuses
                    // the live WS/WSS/TLS connection.  Mirrors the 2xx-ACK path
                    // (`handle_ack_via_session`), which already does this — that
                    // is why the ACK reaches the UE but the BYE used to 502.
                    match in_dialog_reuse_destination(message, state) {
                        Some((dest, transport)) => RelayTarget {
                            address: dest,
                            transport: Some(transport),
                            server_name: None,
                        },
                        None => {
                            warn!(target = %target_uri_string, "cannot resolve relay target");
                            let response = build_response(message, 502, "Bad Gateway", state.server_header.as_deref(), &[]);
                            send_message_from(response, inbound.transport, inbound.remote_addr, inbound.connection_id, Some(inbound.local_addr), state);
                            return;
                        }
                    }
                }
            };
            (target_uri_string, target.address, target.transport.unwrap_or(inbound.transport), None)
        };

    // Apply force_send_via transport override from script (non-flow path only;
    // the flow already pins the transport).
    if flow.is_none() {
        if let Some(via_transport) = send_via_transport {
            outbound_transport = match via_transport.to_lowercase().as_str() {
                "udp" => Transport::Udp,
                "tcp" => Transport::Tcp,
                "tls" => Transport::Tls,
                "ws" => Transport::WebSocket,
                "wss" => Transport::WebSocketSecure,
                _ => outbound_transport,
            };
        }
    }

    // Prevent routing loops — don't relay to ourselves
    if state.is_own_address(&destination) {
        // ACK to 2xx is end-to-end and should go to the UAS Contact, not the
        // proxy. If the R-URI still points at us, silently drop rather than
        // generating a response (ACK never gets a response per RFC 3261).
        let is_ack = matches!(
            &message.start_line,
            StartLine::Request(rl) if rl.method == crate::sip::message::Method::Ack
        );
        if is_ack {
            debug!(target = %target_uri_string, "ACK to self — silently dropping");
            return;
        }

        warn!(
            target = %target_uri_string,
            destination = %destination,
            "relay loop detected — destination is ourselves"
        );
        let response = build_response(message, 482, "Loop Detected", state.server_header.as_deref(), &[]);
        send_message_from(response, inbound.transport, inbound.remote_addr, inbound.connection_id, Some(inbound.local_addr), state);
        return;
    }

    // Clone the message for modification
    let mut relayed = message.clone();

    // Decrement Max-Forwards
    if core::decrement_max_forwards(&mut relayed.headers).is_err() {
        let response = build_response(message, 483, "Too Many Hops", state.server_header.as_deref(), &[]);
        send_message_from(response, inbound.transport, inbound.remote_addr, inbound.connection_id, Some(inbound.local_addr), state);
        return;
    }

    // Ask the IPsec module whether this destination is on a registered
    // SA pair — if so, the source (and therefore Via) must reflect the
    // matching P-CSCF port (e.g. `pcscf_port_c` for an MT INVITE landing
    // on the UE's `port_us`) rather than the default per-transport
    // via_host / listener (3GPP TS 33.203 §6.3 / §7.4).  The SA's
    // pinned protocol (UDP/TCP, TS 33.203 §7.2) also overrides whatever
    // transport the URI / inbound suggested: in-dialog BYE/UPDATE often
    // routes via a cached Contact that lacks `;transport=`, and the
    // kernel XFRM selector silently drops every protected frame whose
    // upper-layer protocol doesn't match.  Initial INVITE works without
    // this pin because the script stamps the Path; in-dialog re-uses
    // the dialog route set and that stamp is gone.
    //
    // Applies to both UDP (ESP-over-UDP, the common case) and TCP
    // (ESP-over-TCP, used by some iOS clients).  For TCP the source
    // also drives `pool.send_tcp_from(source, ...)` so the outbound
    // socket binds to the SA's source endpoint instead of ephemeral;
    // an ephemerally-bound socket would never match the kernel
    // selector for SA #3.  Returns `None` for non-IPsec deployments
    // and ordinary destinations — zero impact on the hot path when
    // no IpsecManager is wired.  Computed once here and reused for
    // Via construction and the outbound send.
    let ipsec_source = match outbound_transport {
        Transport::Udp | Transport::Tcp => {
            if let Some((source, sa_transport)) =
                crate::script::api::ipsec::outbound_for(destination, outbound_transport)
            {
                if sa_transport != outbound_transport {
                    debug!(
                        %destination,
                        from = %outbound_transport,
                        to = %sa_transport,
                        "IPsec: pinning outbound transport to SA protocol",
                    );
                    outbound_transport = sa_transport;
                }
                Some(source)
            } else {
                None
            }
        }
        _ => None,
    };

    // Resolve the script `send_socket=` egress pin against the *final*
    // outbound transport (the IPsec block above may have re-pinned it).  It
    // applies only when: there is no captured flow (a flow already pins the
    // egress listener), IPsec has not claimed the source (the kernel XFRM
    // selector must win), and its transport matches the outbound transport.
    // A transport mismatch is an operator config error — warn and ignore it
    // rather than egress on the wrong socket.
    let send_socket = match send_socket {
        _ if flow.is_some() || ipsec_source.is_some() => None,
        Some(pin) if pin.transport == outbound_transport => Some(pin),
        Some(pin) => {
            warn!(
                send_socket = %pin.addr,
                requested_transport = %pin.transport,
                outbound_transport = %outbound_transport,
                "send_socket transport does not match the outbound transport — ignoring the egress pin"
            );
            None
        }
        None => None,
    };

    // Add our Via — use the outbound transport for the Via header.
    // If force_send_via set a target, use it as the Via sent-by address.
    let transport_str = format!("{}", outbound_transport);
    let (via_host, via_port) = if let Some(local) = flow_local_addr {
        // Flow-relay: pin Via to the listener that received the
        // REGISTER.  Critical for IPSec sec-agree where the protected
        // server port (e.g. 5066) is non-default — using the per-
        // transport via_host would emit a Via with the wrong port and
        // the UE's response would land on the wrong listener
        // (3GPP TS 33.203 §7.4).
        (local.ip().to_string(), Some(local.port()))
    } else if let Some(local) = ipsec_source {
        // IPsec auto-source: same correctness invariant as the flow
        // path — the UE's response on SA #4 (UE → port_pc) must land
        // on the Via we advertise, otherwise the kernel selector
        // doesn't match and the response is silently dropped.
        (local.ip().to_string(), Some(local.port()))
    } else if let Some(pin) = send_socket {
        // Script send_socket= egress pin: advertise the selected listener's
        // sent-by (its configured advertise host, else the bound IP) with the
        // listener's port, so the peer's response comes back to this socket.
        let (host, port) = pin.via_sent_by();
        (format_sip_host(&host), Some(port))
    } else if let Some(target_str) = send_via_target {
        // Parse "host:port" or just "host"
        if let Some((host, port_str)) = target_str.rsplit_once(':') {
            (host.to_string(), port_str.parse::<u16>().ok())
        } else {
            (target_str.to_string(), None)
        }
    } else {
        (state.via_host(&outbound_transport), Some(state.via_port(&outbound_transport)))
    };
    let branch = core::add_via(
        &mut relayed.headers,
        &transport_str,
        &via_host,
        via_port,
    );

    // Add Record-Route if the script requested it.
    // When bridging transports (e.g. TLS↔TCP), insert *two* Record-Route
    // headers (r2) so each leg's in-dialog requests use the correct transport.
    if record_routed {
        let internal_host = format_sip_host(&state.local_addr.ip().to_string());
        let inbound_transport_str = format!("{}", inbound.transport).to_lowercase();
        if inbound_transport_str != transport_str.to_lowercase() {
            // Double Record-Route: outbound transport first (topmost after prepend order).
            // Each RR must use the port of the respective transport listener so that
            // in-dialog requests from each leg reach the correct listener.
            // The TLS-facing RR uses the advertised address when set, since
            // external peers may not be able to reach the internal bind IP.
            let outbound_port = state.listen_addrs.get(&outbound_transport).map(|a| a.port()).unwrap_or(state.local_addr.port());
            let inbound_port = state.listen_addrs.get(&inbound.transport).map(|a| a.port()).unwrap_or(state.local_addr.port());
            let outbound_host = state.advertised_addrs.get(&outbound_transport).map(|h| format_sip_host(h)).unwrap_or_else(|| internal_host.clone());
            let inbound_host = state.advertised_addrs.get(&inbound.transport).map(|h| format_sip_host(h)).unwrap_or_else(|| internal_host.clone());
            let rr_outbound = format!("sip:{}:{};transport={}", outbound_host, outbound_port, transport_str.to_lowercase());
            let rr_inbound = format!("sip:{}:{};transport={}", inbound_host, inbound_port, inbound_transport_str);
            core::add_record_route(&mut relayed.headers, &rr_inbound);
            core::add_record_route(&mut relayed.headers, &rr_outbound);
        } else {
            // Single Record-Route (inbound == outbound transport). Reuse the same
            // sent-by as our Via — the advertised host in the normal case, or the
            // pinned listener for IPsec/flow/send_socket egress — instead of the
            // raw bind IP. An external peer must route in-dialog requests back
            // through the exact host:port we advertised: Teams rejects an IP in
            // Record-Route outright, and a P-CSCF's protected port must match or
            // the kernel SA selector drops the in-dialog request.
            let rr_port = via_port.unwrap_or_else(|| state.via_port(&outbound_transport));
            let rr_uri = format!("sip:{}:{};transport={}", via_host, rr_port, transport_str.to_lowercase());
            core::add_record_route(&mut relayed.headers, &rr_uri);
        }
    }

    // Serialize the relayed request
    let data = Bytes::from(relayed.to_bytes());

    debug!(
        branch = %branch,
        destination = %destination,
        transport = %outbound_transport,
        "relaying request"
    );

    // IMPORTANT: register the client transaction and session BEFORE sending.
    // On low-latency transports (loopback, fast LANs), the response can arrive
    // before this code finishes, leaving the response handler with no matching
    // session ("response for unknown branch"). The connection_id stored here is
    // a placeholder for UDP (where send_to_target returns the same value passed
    // in) and is updated below for TCP/TLS once the connection is established.
    let txn_transport = crate::transaction::state::Transport::from(outbound_transport);
    let placeholder_connection_id = inbound.connection_id;
    let mut inserted_session_arc: Option<Arc<RwLock<ProxySession>>> = None;
    let client_key_opt = match state.transaction_manager.new_client_transaction(relayed, txn_transport) {
        Ok((client_key, actions)) => {
            for action in &actions {
                if let Action::StartTimer(name, duration) = action {
                    let timer_id = format!("{}:{:?}", client_key, name);
                    state.timer_wheel.insert(timer_id, TimerEntry {
                        key: client_key.clone(),
                        name: *name,
                        fires_at: std::time::Instant::now() + *duration,
                        destination: Some(destination),
                        transport: Some(outbound_transport),
                        connection_id: Some(placeholder_connection_id),
                        // Client transactions are outbound — no inbound
                        // socket to pin.
                        source_local_addr: None,
                    });
                }
            }

            if let Some(srv_key) = server_key {
                let mut session = ProxySession::new(
                    srv_key.clone(),
                    inbound.remote_addr,
                    inbound.local_addr,
                    inbound.connection_id,
                    inbound.transport,
                    message.clone(),
                    record_routed,
                );
                session.add_client_key(client_key.clone());
                session.set_client_branch(client_key.clone(), ClientBranch {
                    destination,
                    transport: outbound_transport,
                    connection_id: placeholder_connection_id,
                });
                session.on_reply_callback = on_reply_callback;
                session.on_failure_callback = on_failure_callback;
                let arc = state.session_store.insert(session);
                inserted_session_arc = Some(arc);
            }
            Some(client_key)
        }
        Err(error) => {
            debug!(branch = %branch, "failed to create client transaction: {error}");
            None
        }
    };

    // Now actually send.  Two paths:
    //   - Flow-relay: build the OutboundMessage directly with the captured
    //     `(connection_id, transport, destination, source_local_addr)` so
    //     UDP egresses from the right listener and stream transports route
    //     to the live accepted-connection write half registered in
    //     `connection_map`.  No DNS, no pool lookup.
    //   - URI-relay: the legacy path through `send_to_target`.
    let connection_id = if let Some(local) = flow_local_addr {
        let outbound_message = OutboundMessage {
            connection_id: ConnectionId(flow.map(|f| f.connection_id).unwrap_or(0)),
            transport: outbound_transport,
            destination,
            data,
            source_local_addr: Some(local),
            server_name: None,
        };
        let cid = outbound_message.connection_id;
        if let Err(error) = state.outbound.send(outbound_message) {
            error!(
                destination = %destination,
                transport = %outbound_transport,
                "flow-relay outbound send failed: {error}"
            );
        } else {
            debug!(
                destination = %destination,
                transport = %outbound_transport,
                connection_id = ?cid,
                "relayed via captured flow"
            );
        }
        cid
    } else {
        // Build the legacy RelayTarget for the URI path.
        let target = RelayTarget {
            address: destination,
            transport: Some(outbound_transport),
            server_name: None,
        };
        send_to_target(
            data,
            &target,
            inbound.transport,
            inbound.connection_id,
            send_socket.map(|pin| pin.addr),
            state,
        )
    };
    // Patch the session's ClientBranch via the locally-held `Arc` we got
    // back from `session_store.insert(...)` rather than re-looking up
    // through the store: at high CPS on TCP loopback the UAS 200 OK can
    // arrive and trigger `remove_client_key` before `send_to_target`
    // returns here, dropping the by_client_key / server_to_clients index
    // entries — a store-side lookup would then miss and the branch would
    // stay pinned to `placeholder_connection_id` (the inbound UAC's
    // connection_id), routing every later in-dialog send (ACK, BYE) to
    // the UAC instead of the UAS.  The `Arc` keeps the session alive
    // across the index removal, so the write always lands.
    if connection_id != placeholder_connection_id {
        if let (Some(client_key), Some(arc)) = (client_key_opt.as_ref(), inserted_session_arc.as_ref()) {
            if let Ok(mut session) = arc.write() {
                session.set_client_branch(client_key.clone(), ClientBranch {
                    destination,
                    transport: outbound_transport,
                    connection_id,
                });
            }
        }
    }
}

/// Relay a forked request to multiple targets.
///
/// Creates a ProxySession with a ForkAggregator and sends to all targets
/// (parallel) or just the first (sequential, rest tried on failure).
fn relay_fork_request(
    message: &SipMessage,
    targets: &[String],
    flows: &[Option<crate::script::api::registrar::PyFlow>],
    strategy: crate::proxy::fork::ForkStrategy,
    record_routed: bool,
    inbound: &InboundMessage,
    server_key: Option<&TransactionKey>,
    state: &DispatcherState,
    send_socket: Option<&crate::transport::SendSocket>,
) {
    use crate::proxy::fork::ForkAggregator;

    // Parse target URIs
    let target_uris: Vec<crate::sip::uri::SipUri> = targets
        .iter()
        .filter_map(|target| parse_uri_standalone(target).ok())
        .collect();

    if target_uris.is_empty() {
        warn!("fork: no valid target URIs");
        let response = build_response(message, 500, "No Valid Targets", state.server_header.as_deref(), &[]);
        send_message_from(response, inbound.transport, inbound.remote_addr, inbound.connection_id, Some(inbound.local_addr), state);
        return;
    }

    let aggregator = Arc::new(std::sync::Mutex::new(
        ForkAggregator::new(target_uris, strategy),
    ));

    // Create ProxySession (even without server_key, we need the aggregator)
    let srv_key = match server_key {
        Some(key) => key.clone(),
        None => {
            // Fall back to single-target relay if no server transaction —
            // carry the first branch's flow so a single WS contact still routes.
            relay_request(message, targets.first().map(|s| s.as_str()), record_routed, inbound, None, state, None, None, None, None, flows.first().and_then(|f| f.as_ref()), send_socket);
            return;
        }
    };

    let mut session = ProxySession::new(
        srv_key.clone(),
        inbound.remote_addr,
        inbound.local_addr,
        inbound.connection_id,
        inbound.transport,
        message.clone(),
        record_routed,
    );
    session.fork_aggregator = Some(Arc::clone(&aggregator));
    session.fork_flows = flows.to_vec();
    session.fork_send_socket = send_socket.cloned();

    // Determine which branches to start now
    let branches_to_start: Vec<usize> = match strategy {
        crate::proxy::fork::ForkStrategy::Parallel => (0..targets.len()).collect(),
        crate::proxy::fork::ForkStrategy::Sequential => {
            if targets.is_empty() { vec![] } else { vec![0] }
        }
    };

    // Insert the session into the store *before* any branch is sent so the
    // response handler can look it up via by_client_key (after each branch
    // pre-registers itself below). Without this, a fast peer (loopback) can
    // deliver a response before the branch is registered, stranding the call.
    let session_arc = state.session_store.insert_for_fork(session);

    for branch_index in branches_to_start {
        let target = &targets[branch_index];
        relay_fork_branch(
            message,
            target,
            branch_index,
            record_routed,
            inbound,
            &srv_key,
            &session_arc,
            &aggregator,
            flows.get(branch_index).and_then(|f| f.as_ref()),
            send_socket,
            state,
        );
    }
}

/// Relay a single branch of a forked request.
///
/// Resolves the target, adds Via, sends the request, creates a client transaction,
/// and registers the branch in the ProxySession.
fn relay_fork_branch(
    message: &SipMessage,
    target: &str,
    branch_index: usize,
    record_routed: bool,
    inbound: &InboundMessage,
    server_key: &TransactionKey,
    session_arc: &Arc<RwLock<ProxySession>>,
    aggregator: &Arc<std::sync::Mutex<crate::proxy::fork::ForkAggregator>>,
    flow: Option<&crate::script::api::registrar::PyFlow>,
    send_socket: Option<&crate::transport::SendSocket>,
    state: &DispatcherState,
) {
    // Resolve the branch destination + transport: over the captured inbound flow
    // (RFC 5626 §5.3 connection reuse — the only way back to a WebSocket UE,
    // RFC 7118 §5) when one is attached, else by DNS-resolving the target URI.
    let (destination, outbound_transport) = if let Some(flow) = flow {
        let transport = match flow.transport.as_str() {
            "udp" => Transport::Udp,
            "tcp" => Transport::Tcp,
            "tls" => Transport::Tls,
            "ws" => Transport::WebSocket,
            "wss" => Transport::WebSocketSecure,
            other => {
                warn!(target = %target, branch = branch_index, transport = %other, "fork: unknown flow transport");
                return;
            }
        };
        (flow.source_addr, transport)
    } else {
        let relay_target = match resolve_target(target, &state.dns_resolver) {
            Some(t) => t,
            None => {
                warn!(target = %target, branch = branch_index, "fork: cannot resolve target");
                return;
            }
        };
        (relay_target.address, relay_target.transport.unwrap_or(inbound.transport))
    };

    // Loop detection — check all listen addresses (including per-transport)
    if state.is_own_address(&destination) {
        warn!(target = %target, "fork: loop detected");
        return;
    }

    // Clone and modify message
    let mut relayed = message.clone();

    if core::decrement_max_forwards(&mut relayed.headers).is_err() {
        return; // caller handles the error for the whole fork
    }

    // A script send_socket= egress pin applies to this branch only when it has
    // no captured flow (a flow already pins egress) and its transport matches
    // the branch's outbound transport.  When it applies, the Via sent-by is the
    // pinned listener's advertised address so the branch's response comes back
    // to that socket.
    let send_socket = match send_socket {
        _ if flow.is_some() => None,
        Some(pin) if pin.transport == outbound_transport => Some(pin),
        Some(pin) => {
            warn!(
                send_socket = %pin.addr,
                requested_transport = %pin.transport,
                outbound_transport = %outbound_transport,
                branch = branch_index,
                "fork: send_socket transport does not match the branch transport — ignoring"
            );
            None
        }
        None => None,
    };

    let transport_str = format!("{}", outbound_transport);
    let (via_host, via_port) = match send_socket {
        Some(pin) => {
            let (host, port) = pin.via_sent_by();
            (format_sip_host(&host), port)
        }
        None => (state.via_host(&outbound_transport), state.via_port(&outbound_transport)),
    };
    let branch = core::add_via(
        &mut relayed.headers,
        &transport_str,
        &via_host,
        Some(via_port),
    );

    if record_routed {
        let internal_host = format_sip_host(&state.local_addr.ip().to_string());
        let inbound_transport_str = format!("{}", inbound.transport).to_lowercase();
        if inbound_transport_str != transport_str.to_lowercase() {
            let outbound_port = state.listen_addrs.get(&outbound_transport).map(|a| a.port()).unwrap_or(state.local_addr.port());
            let inbound_port = state.listen_addrs.get(&inbound.transport).map(|a| a.port()).unwrap_or(state.local_addr.port());
            let outbound_host = state.advertised_addrs.get(&outbound_transport).map(|h| format_sip_host(h)).unwrap_or_else(|| internal_host.clone());
            let inbound_host = state.advertised_addrs.get(&inbound.transport).map(|h| format_sip_host(h)).unwrap_or_else(|| internal_host.clone());
            let rr_outbound = format!("sip:{}:{};transport={}", outbound_host, outbound_port, transport_str.to_lowercase());
            let rr_inbound = format!("sip:{}:{};transport={}", inbound_host, inbound_port, inbound_transport_str);
            core::add_record_route(&mut relayed.headers, &rr_inbound);
            core::add_record_route(&mut relayed.headers, &rr_outbound);
        } else {
            // Single Record-Route (inbound == outbound transport). Reuse the same
            // sent-by as our Via — the advertised host, or the pinned send_socket
            // listener — instead of the raw bind IP, so an external peer can route
            // in-dialog requests back through the exact host:port we advertised
            // (Teams rejects an IP in Record-Route).
            let rr_uri = format!("sip:{}:{};transport={}", via_host, via_port, transport_str.to_lowercase());
            core::add_record_route(&mut relayed.headers, &rr_uri);
        }
    }

    // Update Request-URI to the fork target (each branch gets its own Contact URI)
    if let Ok(new_uri) = parse_uri_standalone(target) {
        if let StartLine::Request(ref mut request_line) = relayed.start_line {
            request_line.request_uri = new_uri;
        }
    }

    let data = Bytes::from(relayed.to_bytes());

    // Mark branch as Trying in aggregator (before any send, so a synchronous
    // response can find a branch in the right state).
    if let Ok(mut agg) = aggregator.lock() {
        agg.mark_trying(branch_index);
    }

    // Pre-register the client transaction and the branch in the session_store
    // BEFORE sending. The placeholder connection_id is fine for UDP (the
    // listener fd is shared); for TCP/TLS it's updated below once the actual
    // connection is established.
    let txn_transport = crate::transaction::state::Transport::from(outbound_transport);
    let placeholder_connection_id = inbound.connection_id;
    let client_key_opt = match state.transaction_manager.new_client_transaction(relayed, txn_transport) {
        Ok((client_key, actions)) => {
            for action in &actions {
                if let Action::StartTimer(name, duration) = action {
                    let timer_id = format!("{}:{:?}", client_key, name);
                    state.timer_wheel.insert(timer_id, TimerEntry {
                        key: client_key.clone(),
                        name: *name,
                        fires_at: std::time::Instant::now() + *duration,
                        destination: Some(destination),
                        transport: Some(outbound_transport),
                        connection_id: Some(placeholder_connection_id),
                        // Client transactions are outbound — no inbound
                        // socket to pin.
                        source_local_addr: None,
                    });
                }
            }
            state.session_store.register_fork_branch(
                session_arc,
                server_key,
                client_key.clone(),
                ClientBranch {
                    destination,
                    transport: outbound_transport,
                    connection_id: placeholder_connection_id,
                },
                branch_index,
            );
            Some(client_key)
        }
        Err(error) => {
            debug!(branch = %branch, "fork: failed to create client transaction: {error}");
            None
        }
    };

    // Send: over the captured flow (direct OutboundMessage, bypassing DNS/pool
    // — mirrors the relay(flow=...) path) when one is attached, else via the
    // normal resolver/pool path.
    let connection_id = if let Some(flow) = flow {
        let outbound_message = OutboundMessage {
            connection_id: ConnectionId(flow.connection_id),
            transport: outbound_transport,
            destination,
            data,
            source_local_addr: Some(flow.local_addr),
            server_name: None,
        };
        let cid = outbound_message.connection_id;
        if let Err(error) = state.outbound.send(outbound_message) {
            error!(branch = %branch, destination = %destination, transport = %outbound_transport, "fork: flow send failed: {error}");
        }
        cid
    } else {
        let relay_target = RelayTarget { address: destination, transport: Some(outbound_transport), server_name: None };
        send_to_target(data, &relay_target, inbound.transport, inbound.connection_id, send_socket.map(|pin| pin.addr), state)
    };

    debug!(
        branch = %branch,
        target = %target,
        branch_index = branch_index,
        destination = %destination,
        transport = %outbound_transport,
        flow = flow.is_some(),
        "fork: sent branch"
    );

    // For TCP/TLS the actual connection_id may differ from the placeholder
    // — patch the session's ClientBranch so retransmits/CANCEL hit the right
    // connection.
    //
    // Patch via the local `session_arc` rather than re-looking up through
    // `state.session_store.update_branch_connection_id(...)`: under TCP
    // loopback at high CPS, the UAS 200 OK can arrive and be forwarded
    // (which calls `session_store.remove_client_key`) before
    // `send_to_target` returns here.  A store-side lookup would then miss
    // and the branch would stay pinned to `placeholder_connection_id`
    // (the inbound UAC's connection_id).  Subsequent in-dialog ACK relay
    // via `handle_ack_via_session` would route on that placeholder and
    // bounce the ACK back to the UAC — sipp logs it as "ACK CSeq value
    // does NOT match value of related INVITE CSeq -- aborting call" and
    // drops the subsequent BYE 200 OK.  The local `session_arc` survives
    // `remove_client_key`, so this write always lands.
    if connection_id != placeholder_connection_id {
        if let Some(client_key) = client_key_opt.as_ref() {
            if let Ok(mut session) = session_arc.write() {
                if let Some(branch) = session.client_branches.get_mut(client_key) {
                    branch.connection_id = connection_id;
                }
            }
        }
    }
}

/// Handle an inbound SIP response — route back to the original sender.
fn handle_response(
    inbound: InboundMessage,
    mut message: SipMessage,
    status_code: u16,
    state: &DispatcherState,
) {
    // Check if this response matches a UAC request (keepalive, health probe)
    if state.uac_sender.match_response(&message) {
        debug!(status_code = status_code, "UAC response matched");
        return;
    }

    // Check if this response matches an outbound registration (z9hG4bK-reg- branch)
    if let Some(ref registrant) = state.registrant_manager {
        if let Some(top_via_raw) = message.headers.get("Via") {
            if let Ok(vias) = Via::parse_multi(top_via_raw) {
                if let Some(branch) = vias.first().and_then(|v| v.branch.as_deref()) {
                    if branch.starts_with("z9hG4bK-reg-") {
                        handle_registrant_response(registrant, &message, status_code, branch, state);
                        return;
                    }
                }
            }
        }
    }

    // Check if this response matches a SIPREC recording INVITE (z9hG4bK-rec- branch)
    if let Some(top_via_raw) = message.headers.get("Via") {
        if let Ok(vias) = Via::parse_multi(top_via_raw) {
            if let Some(branch) = vias.first().and_then(|v| v.branch.as_deref()) {
                if branch.starts_with("z9hG4bK-rec-") {
                    if let Some(session_id) = state.recording_manager.session_for_branch(branch) {
                        if (200..300).contains(&status_code) {
                            let to_tag = message.headers.get("To")
                                .and_then(|to| to.split("tag=").nth(1))
                                .map(|tag| tag.split(';').next().unwrap_or(tag).trim().to_string());

                            // RTPEngine subscribe_answer: complete the media fork
                            // by sending the SRS's answer SDP back to RTPEngine.
                            if !message.body.is_empty() {
                                if let Some(ref rtpengine_set) = state.rtpengine_set {
                                    if let Some((original_call_id, original_from_tag, original_to_tag)) =
                                        state.recording_manager.original_call_info(&session_id)
                                    {
                                        info!(
                                            session_id = %session_id,
                                            original_call_id = %original_call_id,
                                            from_tag = %original_from_tag,
                                            to_tag = %original_to_tag,
                                            sdp_len = message.body.len(),
                                            "SIPREC: sending subscribe_answer to RTPEngine"
                                        );
                                        let flags = crate::rtpengine::NgFlags::default();
                                        match tokio::task::block_in_place(|| {
                                            tokio::runtime::Handle::current().block_on(
                                                rtpengine_set.subscribe_answer(
                                                    &original_call_id, &original_from_tag, &original_to_tag,
                                                    &message.body, &flags,
                                                )
                                            )
                                        }) {
                                            Ok(_rewritten_sdp) => {
                                                info!(
                                                    session_id = %session_id,
                                                    "SIPREC: RTPEngine subscribe_answer completed, media fork active"
                                                );
                                            }
                                            Err(error) => {
                                                warn!(
                                                    session_id = %session_id,
                                                    %error,
                                                    "SIPREC: RTPEngine subscribe_answer failed"
                                                );
                                            }
                                        }
                                    } else {
                                        warn!(
                                            session_id = %session_id,
                                            "SIPREC: no original call info for subscribe_answer"
                                        );
                                    }
                                }
                            }

                            // Build and send ACK for 2xx (RFC 3261 §13.2.2.4).
                            if let Some((ack, destination, transport)) =
                                state.recording_manager.handle_success(
                                    &session_id, to_tag, state.local_addr,
                                )
                            {
                                let data = Bytes::from(ack.to_bytes());
                                let target = RelayTarget {
                                    address: destination,
                                    transport: Some(transport),
                                    server_name: None,
                                };
                                send_to_target(data, &target, transport, ConnectionId::default(), None, state);
                            }
                        } else if status_code >= 300 {
                            state.recording_manager.handle_failure(&session_id, status_code);
                        }
                    }
                    return;
                }
            }
        }
    }

    // RFC 3261 §16.7 step 3: a proxy MUST NOT forward 100 Trying upstream.
    // It is hop-by-hop; the proxy already sends its own 100 Trying to the UAC.
    //
    // BUT the 100 still has to drive the *client* transaction: RFC 3261
    // §17.1.1.2 says the first provisional moves an INVITE client transaction
    // Calling -> Proceeding and cancels Timer A (the INVITE retransmit timer).
    // Returning here without feeding the FSM (the old behaviour) leaves Timer A
    // armed, so the proxy spuriously retransmits the forwarded INVITE at ~T1
    // (~500 ms) even though it already holds a 100 — wasted signalling, and on a
    // lossy/slow trunk the duplicate can trip the peer's merged-request/loop
    // detection (482). Feed the transaction here (cancelling Timer A / capping
    // Timer E for NICT), then absorb without forwarding.
    //
    // For a B2BUA leg there is no client transaction registered under this key
    // (the B2BUA manages its own legs and does not arm Timer A here), so
    // process_client_event returns Err and this is a harmless no-op.
    if status_code == 100 {
        // Drive only the INVITE client transaction (cancel Timer A). A
        // non-INVITE client transaction (NICT) treats a provisional as a
        // Timer-E cap rather than a stop, and 100 Trying is INVITE-specific in
        // practice, so for non-INVITE we keep the historical absorb-only
        // behaviour to avoid disturbing the NICT retransmit timer's pinned
        // destination.
        if let Ok(key) = TransactionManager::key_from_message(&message) {
            if key.method == crate::sip::message::Method::Invite {
                if let Ok(actions) = state.transaction_manager.process_client_event(
                    &key,
                    ClientEvent::Ict(IctEvent::Provisional(message.clone())),
                ) {
                    for action in &actions {
                        if let Action::CancelTimer(name) = action {
                            state.timer_wheel.remove(&format!("{}:{:?}", key, name));
                        }
                    }
                }
            }
        }
        debug!("absorbing 100 Trying from downstream (cancelled INVITE client Timer A; not forwarded)");
        return;
    }

    // Get the topmost Via to find the branch
    let top_via = match message.headers.get("Via") {
        Some(raw) => match Via::parse_multi(raw) {
            Ok(vias) if !vias.is_empty() => vias[0].clone(),
            _ => {
                warn!("response has unparseable Via header");
                return;
            }
        },
        None => {
            warn!("response has no Via header");
            return;
        }
    };

    let branch = match &top_via.branch {
        Some(branch) => branch.clone(),
        None => {
            warn!("topmost Via has no branch parameter");
            return;
        }
    };

    // Check if this response belongs to a B2BUA call
    if let Some(call_id) = state.call_actors.call_id_for_branch(&branch) {
        handle_b2bua_response(&call_id, &branch, &mut message, status_code, inbound.remote_addr, state);
        return;
    }

    // Post-teardown: re-ACK retransmitted re-INVITE 200 OKs for calls already
    // torn down by BYE. The zombie map holds destination info for B-leg entries
    // that had active re-INVITE tracking when the call was removed.
    if (200..300).contains(&status_code) {
        if let Some(cseq_raw) = message.headers.get("CSeq") {
            if cseq_raw.contains("INVITE") {
                if let Some(sip_call_id) = message.headers.call_id() {
                    if let Some(zombie) = state.call_actors.get_zombie_reinvite(sip_call_id) {
                        let transport_str = format!("{}", zombie.transport).to_uppercase();
                        // Anchor the re-ACK Via to the zombie leg's socket (the A-leg's
                        // arrival listener for a B→A re-INVITE) so it matches the source.
                        let outbound_port = a_leg_advertised_port(
                            zombie.local_addr,
                            state.listen_addrs.get(&zombie.transport)
                                .map(|a| a.port())
                                .unwrap_or(state.local_addr.port()),
                        );
                        let cseq_num = cseq_raw.split_whitespace().next()
                            .unwrap_or("1").to_string();
                        let from = message.headers.from().cloned().unwrap_or_default();
                        let to = message.headers.to().cloned().unwrap_or_default();
                        let ack_uri = SipUri::new(zombie.destination.ip().to_string())
                            .with_port(zombie.destination.port());
                        let ack = match SipMessageBuilder::new()
                            .request(Method::Ack, ack_uri)
                            .via(format!(
                                "SIP/2.0/{} {}:{};branch={}",
                                transport_str,
                                format_sip_host(&state.local_addr.ip().to_string()),
                                outbound_port,
                                TransactionKey::generate_branch(),
                            ))
                            .from(from.to_string())
                            .to(to.to_string())
                            .call_id(sip_call_id.to_string())
                            .cseq(format!("{} ACK", cseq_num))
                            .header("Max-Forwards", "70".to_string())
                            .content_length(0)
                            .build()
                        {
                            Ok(ack) => ack,
                            Err(error) => {
                                error!("B2BUA zombie ACK build failed: {error}");
                                return;
                            }
                        };
                        // Source from the zombie leg's anchored socket (multi-homed
                        // parity); reuse an established connection as before.
                        let data = Bytes::from(ack.to_bytes());
                        let target = RelayTarget {
                            address: zombie.destination,
                            transport: Some(zombie.transport),
                            server_name: None,
                        };
                        send_to_target(data, &target, zombie.transport, ConnectionId::default(), zombie.local_addr, state);
                        debug!(
                            call_id = sip_call_id,
                            "B2BUA: zombie re-ACK for post-teardown re-INVITE 200 OK retransmission"
                        );
                        return;
                    }
                }
            }
        }
    }

    // Post-CANCEL glare (RFC 3261 §9.1): a 2xx that raced an outbound CANCEL.
    // handle_b2bua_cancel removed the call (unregistering the B-leg branch), so
    // this 2xx no longer resolves above. ACK it (§13.2.2.4) and BYE it (§15) via
    // the captured leg so the callee stops retransmitting and the dialog it just
    // established is released.
    if (200..300).contains(&status_code) {
        if let Some(cseq_raw) = message.headers.get("CSeq") {
            if cseq_raw.contains("INVITE") {
                if let Some(sip_call_id) = message.headers.call_id() {
                    if let Some((leg, first_2xx)) =
                        state.call_actors.zombie_cancelled_for_2xx(sip_call_id)
                    {
                        handle_zombie_cancelled_2xx(leg, first_2xx, &message, state);
                        return;
                    }
                }
            }
        }
    }

    // Parse CSeq once for both transaction processing and session routing.
    let sent_by = TransactionKey::format_sent_by(&top_via.host, top_via.port);
    let client_txn_key = message.headers.get("CSeq")
        .and_then(|cseq_raw| crate::sip::headers::cseq::CSeq::parse(cseq_raw).ok())
        .map(|cseq| TransactionKey::new(branch.clone(), cseq.method, sent_by.clone()));

    // Feed response to client transaction (if one exists).
    // The state machine handles retransmit absorption and timer cancellation.
    if let Some(ref key) = client_txn_key {
        let event = if status_code < 200 {
            if key.method == crate::sip::message::Method::Invite {
                Some(ClientEvent::Ict(IctEvent::Provisional(message.clone())))
            } else {
                Some(ClientEvent::Nict(NictEvent::Provisional(message.clone())))
            }
        } else if status_code < 300 && key.method == crate::sip::message::Method::Invite {
            Some(ClientEvent::Ict(IctEvent::Response2xx(message.clone())))
        } else if key.method == crate::sip::message::Method::Invite {
            Some(ClientEvent::Ict(IctEvent::ResponseNon2xx(message.clone())))
        } else {
            Some(ClientEvent::Nict(NictEvent::FinalResponse(message.clone())))
        };

        if let Some(event) = event {
            match state.transaction_manager.process_client_event(key, event) {
                Ok(actions) => {
                    for action in &actions {
                        match action {
                            Action::SendMessage(ack_message) => {
                                // RFC 3261 §17.1.1.3: send ACK for non-2xx back toward
                                // the UAS, from the socket the response arrived on
                                // (multi-homed source-port parity).
                                send_message_from(
                                    ack_message.clone(),
                                    inbound.transport,
                                    inbound.remote_addr,
                                    inbound.connection_id,
                                    Some(inbound.local_addr),
                                    state,
                                );
                            }
                            Action::CancelTimer(name) => {
                                let timer_id = format!("{}:{:?}", key, name);
                                state.timer_wheel.remove(&timer_id);
                            }
                            Action::StartTimer(name, duration) => {
                                let timer_id = format!("{}:{:?}", key, name);
                                state.timer_wheel.insert(timer_id, TimerEntry {
                                    key: key.clone(),
                                    name: *name,
                                    fires_at: std::time::Instant::now() + *duration,
                                    destination: None,
                                    transport: None,
                                    connection_id: None,
                                    source_local_addr: None,
                                });
                            }
                            Action::ProtocolError(message) => {
                                warn!(key = %key, "client transaction protocol error: {message}");
                            }
                            _ => {}
                        }
                    }

                    // If the state machine did NOT produce PassToTu, it absorbed the response
                    let should_forward = actions.iter().any(|a| matches!(a, Action::PassToTu(_)));
                    if !should_forward && status_code >= 200 {
                        debug!(
                            branch = %branch,
                            status = status_code,
                            "response absorbed by client transaction"
                        );
                        return;
                    }
                }
                Err(_) => {
                    // No transaction found — fall through to normal processing
                }
            }
        }
    }

    if let Some(ref client_key) = client_txn_key {
        if let Some(session_arc) = state.session_store.get_by_client_key(client_key) {
            let (source_addr, inbound_local_addr, connection_id, transport, server_key, fork_agg, branch_index, original_request, relay_on_reply, relay_on_failure, client_branch, final_response_sent) = {
                let session = match session_arc.read() {
                    Ok(s) => s,
                    Err(error) => {
                        error!("proxy session lock poisoned: {error}");
                        return;
                    }
                };
                // Free-threaded CPython (3.14t) requires an attached thread to
                // touch a `Py<…>` refcount; clone the relay callbacks through a
                // `Python` token rather than the bare `Clone` impl, which would
                // panic on this (unattached) executor worker. See
                // `ProxySession::clone_relay_callbacks`.
                let (relay_on_reply, relay_on_failure) = session.clone_relay_callbacks();
                (
                    session.source_addr,
                    session.inbound_local_addr,
                    session.connection_id,
                    session.transport,
                    session.server_key.clone(),
                    session.fork_aggregator.clone(),
                    session.branch_index_map.get(client_key).copied(),
                    session.original_request.clone(),
                    relay_on_reply,
                    relay_on_failure,
                    session.client_branches.get(client_key).cloned(),
                    session.final_response_sent,
                )
            };

            // RFC 3261 §17.1.1.3: the client transaction MUST generate an ACK
            // for non-2xx final responses to INVITE, sent hop-by-hop to the
            // same downstream destination.
            if status_code >= 300
                && client_key.method == crate::sip::message::Method::Invite
            {
                match client_branch {
                    Some(ref cb) => {
                        let ack = build_ack_for_non2xx(&original_request, &message, &branch, cb.transport, state.local_addr);
                        send_to_target(
                            ack.to_bytes().into(),
                            &RelayTarget { address: cb.destination, transport: Some(cb.transport), server_name: None },
                            cb.transport,
                            cb.connection_id,
                            None,
                            state,
                        );
                        info!(
                            branch = %branch,
                            destination = %cb.destination,
                            transport = %cb.transport,
                            "ACK for {status_code} sent downstream"
                        );
                    }
                    None => {
                        warn!(
                            branch = %branch,
                            status = status_code,
                            "cannot send ACK for non-2xx: no client branch in session"
                        );
                    }
                }
            }

            // A reply-time `reply.reject()` already committed a final response
            // upstream for this server transaction and CANCELled the pending
            // branch(es).  This response is the straggler that CANCEL drew back
            // (typically the `487` answering it, or a late provisional).  Any
            // non-2xx final was ACKed downstream just above (and by the client
            // transaction), so absorb it here — forwarding it would put a second
            // final response on the wire to the UAC.  The single-target relay
            // path has no fork aggregator to dedup, so this flag is the guard.
            if final_response_sent {
                debug!(
                    status = status_code,
                    branch = %branch,
                    "absorbing straggler after reply-time reject (final already sent)"
                );
                if status_code >= 200 {
                    state.session_store.remove_client_key(client_key);
                }
                return;
            }

            // Strip our topmost Via before forwarding
            core::strip_top_via(&mut message.headers);

            // Run Python reply handlers
            let (updated_message, should_forward, reject_action) = run_reply_handlers(
                message,
                status_code,
                &branch,
                state,
                original_request.clone(),
                source_addr,
                transport,
                inbound.remote_addr,
                inbound_local_addr,
                connection_id,
            );

            // `reply.reject(code, reason)` from `@proxy.on_reply`: fail the
            // in-progress INVITE.  Send the error upstream to the UAC and
            // CANCEL the pending downstream branch(es).  Takes precedence over
            // the relay/drop decision.  Only ever `Some` for a provisional
            // (the PyReply method no-ops on a final), so this never races a
            // real upstream 2xx.
            if let Some((reject_code, reject_reason)) = reject_action {
                reject_pending_invite(
                    &server_key,
                    &session_arc,
                    reject_code,
                    &reject_reason,
                    &original_request,
                    transport,
                    source_addr,
                    connection_id,
                    inbound_local_addr,
                    state,
                );
                return;
            }

            if !should_forward {
                state.session_store.remove_client_key(client_key);
                return;
            }
            message = updated_message;

            // IPsec CK/IK extraction from relayed 401 REGISTER responses is
            // now driven by the P-CSCF script via `reply.take_av()` (see
            // `siphon.ipsec`).  The dispatcher no longer transparently
            // strips/installs SAs on this path.

            // Invoke per-relay on_reply / on_failure callbacks if set
            if relay_on_reply.is_some() || (relay_on_failure.is_some() && status_code >= 400) {
                let msg_arc = Arc::new(std::sync::Mutex::new(message));
                let req_arc = Arc::new(std::sync::Mutex::new(original_request.clone()));
                let (updated_msg, cb_forward, cb_reject): (Option<SipMessage>, bool, Option<(u16, String)>) = Python::attach(|python| {
                    let py_reply_obj = PyReply::new(Arc::clone(&msg_arc))
                        .with_response_source(
                            inbound.remote_addr.ip().to_string(),
                            inbound.remote_addr.port(),
                        );
                    let py_reply = match Py::new(python, py_reply_obj) {
                        Ok(obj) => obj,
                        Err(error) => {
                            error!("failed to create PyReply for relay callback: {error}");
                            return (None, true, None);
                        }
                    };
                    let py_req = {
                        let mut req = PyRequest::new(
                            Arc::clone(&req_arc),
                            transport.to_string(),
                            source_addr.ip().to_string(),
                            source_addr.port(),
                        );
                        // Replay the inbound flow capture so
                        // registrar.save(flow_token=…) /
                        // request.relay(flow=…) called from the
                        // on_reply / on_failure callback see the
                        // same listener context as the on_request
                        // handler did (P-CSCF Path-token MT routing
                        // — see CLAUDE.md / TS 24.229 §5.2.7.2).
                        req.set_local_port(inbound_local_addr.port());
                        req.set_inbound_flow(inbound_local_addr, connection_id.0);
                        match Py::new(python, req) {
                            Ok(obj) => obj,
                            Err(error) => {
                                error!("failed to create PyRequest for relay callback: {error}");
                                return (None, true, None);
                            }
                        }
                    };

                    // on_reply callback: (request, reply)
                    if let Some(ref on_reply) = relay_on_reply {
                        let callable = on_reply.bind(python);
                        match callable.call1((py_req.bind(python), py_reply.bind(python))) {
                            Ok(ret) => {
                                if let Ok(true) = is_coroutine(python, &ret) {
                                    if let Err(error) = run_coroutine(python, &ret) {
                                        error!("async relay on_reply callback error: {error}");
                                    }
                                }
                            }
                            Err(error) => {
                                error!("relay on_reply callback error: {error}");
                            }
                        }
                    }

                    // on_failure callback: (request, code, reason)
                    if status_code >= 400 {
                        if let Some(ref on_failure) = relay_on_failure {
                            let reason = best_error_reason(status_code);
                            let callable = on_failure.bind(python);
                            match callable.call1((py_req.bind(python), status_code, reason)) {
                                Ok(ret) => {
                                    if let Ok(true) = is_coroutine(python, &ret) {
                                        if let Err(error) = run_coroutine(python, &ret) {
                                            error!("async relay on_failure callback error: {error}");
                                        }
                                    }
                                }
                                Err(error) => {
                                    error!("relay on_failure callback error: {error}");
                                }
                            }
                        }
                    }

                    let reply_ref = py_reply.borrow(python);
                    (None, reply_ref.was_forwarded(), reply_ref.reject_action())
                });
                let _ = updated_msg; // unused — message stays in msg_arc
                // A per-relay on_reply callback can reject too (same contract as
                // the global `@proxy.on_reply` handler) — fail the in-progress
                // INVITE upstream + CANCEL downstream.  Reached only when the
                // global handler did not already reject (that path returned).
                if let Some((reject_code, reject_reason)) = cb_reject {
                    reject_pending_invite(
                        &server_key,
                        &session_arc,
                        reject_code,
                        &reject_reason,
                        &original_request,
                        transport,
                        source_addr,
                        connection_id,
                        inbound_local_addr,
                        state,
                    );
                    return;
                }
                if !cb_forward {
                    state.session_store.remove_client_key(client_key);
                    return;
                }
                // Recover the message from the Arc
                message = match Arc::try_unwrap(msg_arc) {
                    Ok(mutex) => mutex.into_inner().unwrap_or_else(|e| e.into_inner()),
                    Err(arc) => arc.lock().unwrap_or_else(|e| e.into_inner()).clone(),
                };
            }

            // --- Fork aggregator decision ---
            if let (Some(ref aggregator), Some(index)) = (&fork_agg, branch_index) {
                let fork_action = match aggregator.lock() {
                    Ok(mut agg) => agg.on_branch_response(index, status_code),
                    Err(_) => {
                        error!("fork aggregator lock poisoned");
                        crate::proxy::fork::ForkAction::ContinueWaiting
                    }
                };

                match fork_action {
                    crate::proxy::fork::ForkAction::ContinueWaiting => {
                        debug!(
                            status = status_code,
                            branch_index = index,
                            "fork: waiting for more branches"
                        );
                        return;
                    }
                    crate::proxy::fork::ForkAction::Forward2xx => {
                        debug!(status = status_code, "fork: forwarding 2xx, cancelling others");
                        cancel_other_fork_branches(client_key, &server_key, state);
                    }
                    crate::proxy::fork::ForkAction::Forward6xx => {
                        debug!(status = status_code, "fork: forwarding 6xx, cancelling others");
                        cancel_other_fork_branches(client_key, &server_key, state);
                    }
                    crate::proxy::fork::ForkAction::ForwardProvisional(_code) => {
                        // Forward provisional upstream (no cleanup)
                    }
                    crate::proxy::fork::ForkAction::ForwardBestError(best_code) => {
                        debug!(best_code = best_code, "fork: all branches failed");
                        let reason = best_error_reason(best_code);
                        let Ok(session) = session_arc.read() else {
                            error!("session_arc read lock poisoned");
                            return;
                        };
                        let original_request = session.original_request.clone();
                        let best_response = build_response(
                            &original_request,
                            best_code,
                            reason,
                            state.server_header.as_deref(),
                            &[],
                        );
                        drop(session);

                        // CDR: capture the dialog key before `original_request`
                        // may be moved into the on_failure PyRequest, so the
                        // failed-call record can be written at the convergence
                        // point below — but only when the failure is actually
                        // forwarded (a handler that retries via request.relay()
                        // returns early and must NOT emit a failed CDR).
                        let cdr_fail_key = if crate::cdr::auto_emit_enabled() {
                            original_request
                                .headers
                                .get("Call-ID")
                                .map(|s| s.to_string())
                                .zip(
                                    original_request
                                        .typed_from()
                                        .ok()
                                        .flatten()
                                        .and_then(|na| na.tag),
                                )
                                .map(|(call_id, tag)| cdr_dialog_key(&call_id, &tag))
                        } else {
                            None
                        };

                        // Invoke @proxy.on_failure handlers before forwarding
                        let engine_state = state.engine.state();
                        let failure_handlers = engine_state.handlers_for(&HandlerKind::ProxyFailure);
                        if !failure_handlers.is_empty() {
                            let response_arc = Arc::new(std::sync::Mutex::new(best_response));
                            let reply = PyReply::new(Arc::clone(&response_arc));
                            let request_arc = Arc::new(std::sync::Mutex::new(original_request));
                            let mut py_request = PyRequest::new(
                                request_arc,
                                transport.to_string(),
                                source_addr.ip().to_string(),
                                source_addr.port(),
                            );
                            // Replay the inbound flow capture so the
                            // failure handler can do Path-token MT
                            // routing (`registrar.lookup_by_token` +
                            // `request.relay(flow=…)`) on retry.
                            py_request.set_local_port(inbound_local_addr.port());
                            py_request.set_inbound_flow(inbound_local_addr, connection_id.0);

                            let forwarded = Python::attach(|python| {
                                let py_reply = match Py::new(python, reply) {
                                    Ok(obj) => obj,
                                    Err(e) => {
                                        error!("failed to create PyReply for on_failure: {e}");
                                        return true;
                                    }
                                };
                                let py_req = match Py::new(python, py_request) {
                                    Ok(obj) => obj,
                                    Err(e) => {
                                        error!("failed to create PyRequest for on_failure: {e}");
                                        return true;
                                    }
                                };

                                for handler in &failure_handlers {
                                    let callable = handler.callable.bind(python);
                                    let result = callable.call1((py_req.bind(python), py_reply.bind(python),));
                                    match result {
                                        Ok(ret) => {
                                            if handler.is_async {
                                                if let Err(e) = run_coroutine(python, &ret) {
                                                    error!("async on_failure handler error: {e}");
                                                    return true;
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            error!("on_failure handler error: {e}");
                                            return true;
                                        }
                                    }
                                }

                                let result = py_reply.borrow(python).was_forwarded();
                                result
                            });

                            if !forwarded {
                                debug!("on_failure handler suppressed error response");
                                state.session_store.remove_by_server_key(&server_key);
                                return;
                            }

                            let final_response = match Arc::try_unwrap(response_arc) {
                                Ok(mutex) => mutex.into_inner().unwrap_or_else(|e| e.into_inner()),
                                Err(arc) => arc.lock().unwrap_or_else(|e| e.into_inner()).clone(),
                            };
                            // 3GPP TS 33.203 §7.4: the relayed-back response
                            // must egress on the same SA's local endpoint
                            // that the request arrived on.  Pass the session's
                            // captured inbound_local_addr so the OutboundRouter
                            // hits the right per-listener UDP channel.
                            send_message_from(final_response, transport, source_addr, connection_id, Some(inbound_local_addr), state);
                        } else {
                            send_message_from(best_response, transport, source_addr, connection_id, Some(inbound_local_addr), state);
                        }

                        // CDR: both forwarded paths converge here (a retrying /
                        // suppressing on_failure handler already returned above),
                        // so the failed-call record is written exactly once.
                        if let Some(key) = &cdr_fail_key {
                            cdr_finalize(
                                state,
                                key,
                                cdr_disconnect_for_failure(best_code),
                                Some(best_code),
                                None,
                            );
                        }

                        state.session_store.remove_by_server_key(&server_key);
                        return;
                    }
                    crate::proxy::fork::ForkAction::TryNext(next_index) => {
                        debug!(next_index = next_index, "fork: trying next branch (sequential)");
                        start_next_fork_branch(
                            next_index,
                            &session_arc,
                            &server_key,
                            state,
                        );
                        return;
                    }
                }
            }

            // Rf ACR-START on INVITE 2xx (TS 32.299 §6.2.2).
            //
            // Fires for both single-destination `request.relay(target)`
            // (which has no fork aggregator) and multi-branch
            // `request.fork(...)` (Forward2xx after the aggregator
            // selects a winner), so any path that lands a 2xx on a
            // confirmed proxy session opens an accounting record.
            // Idempotency inside spawn_rf_proxy_start_if_invite +
            // RfChargingService prevents double-emission if 2xx
            // retransmits arrive on the same session.  Fire-and-forget
            // per TS 32.299 §6.5.
            if (200..300).contains(&status_code)
                && server_key.method == crate::sip::message::Method::Invite
            {
                spawn_rf_proxy_start_if_invite(state, &server_key, &original_request);
                // CDR: stamp the answer time on the tracked call (cdr.auto_emit).
                cdr_mark_proxy_answer(state, &original_request, status_code);
            } else if (300..700).contains(&status_code)
                && status_code != 401
                && status_code != 407
                && server_key.method == crate::sip::message::Method::Invite
            {
                // CDR: a single-relay INVITE received a final non-2xx (not an
                // auth challenge — the UA re-sends those) → the call failed
                // (cdr.auto_emit). Forked failures finalize at ForwardBestError.
                cdr_finalize_proxy_fail(state, &original_request, status_code);
            }

            // Feed the response into the server transaction for caching
            let server_event = if status_code < 200 {
                if server_key.method == crate::sip::message::Method::Invite {
                    Some(ServerEvent::Ist(IstEvent::TuProvisional(message.clone())))
                } else {
                    Some(ServerEvent::Nist(NistEvent::TuProvisional(message.clone())))
                }
            } else if status_code < 300 && server_key.method == crate::sip::message::Method::Invite {
                Some(ServerEvent::Ist(IstEvent::Tu2xx(message.clone())))
            } else if server_key.method == crate::sip::message::Method::Invite {
                Some(ServerEvent::Ist(IstEvent::TuNon2xxFinal(message.clone())))
            } else {
                Some(ServerEvent::Nist(NistEvent::TuFinal(message.clone())))
            };

            // Feed response to server transaction. If the transaction emits
            // SendMessage, it handles delivery — we must not send again ourselves.
            let mut sent_by_transaction = false;
            if let Some(event) = server_event {
                if let Ok(actions) = state.transaction_manager.process_server_event(&server_key, event) {
                    sent_by_transaction = actions.iter().any(|a| matches!(a, Action::SendMessage(_)));
                    process_timer_actions(
                        &actions,
                        &server_key,
                        Some(source_addr),
                        Some(transport),
                        Some(connection_id),
                        Some(inbound_local_addr),
                        state,
                    );
                }
            }

            if !sent_by_transaction {
                debug!(
                    status = status_code,
                    destination = %source_addr,
                    branch = %branch,
                    "forwarding response via session"
                );
                send_message_from(message, transport, source_addr, connection_id, Some(inbound_local_addr), state);
            }

            // Clean up on final response
            if status_code >= 200 {
                state.session_store.remove_client_key(client_key);
            }
            return;
        }
    }

    // No matching session or B2BUA call — response is not ours
    debug!(branch = %branch, "response for unknown branch (not ours)");
}

/// Run `@proxy.on_reply` Python handlers on a response message.
///
/// Returns `(message, forwarded, reject_action)`:
/// - `forwarded` is false when the script chose to drop the response (no
///   `relay()` called).
/// - `reject_action` is `Some((code, reason))` when the script called
///   `reply.reject(code, reason)` on a provisional — the caller then sends a
///   final error upstream and CANCELs the pending downstream branch(es).  When
///   set it takes precedence over `forwarded`.
///
/// `response_source` is the observed source address of the entity that sent
/// this response (for `reply.fix_nated_contact()`).
fn run_reply_handlers(
    message: SipMessage,
    status_code: u16,
    branch: &str,
    state: &DispatcherState,
    original_request: SipMessage,
    source_addr: SocketAddr,
    transport: crate::transport::Transport,
    response_source: SocketAddr,
    inbound_local_addr: SocketAddr,
    inbound_connection_id: ConnectionId,
) -> (SipMessage, bool, Option<(u16, String)>) {
    // Automatic NAT Contact fixup on responses (nat.fix_contact: true).
    // Rewrites the Contact URI host:port with the observed source address
    // of the entity that sent this response — before Python handlers run,
    // so scripts see the corrected Contact.
    let message = if state.nat_fix_contact {
        fix_response_contact(message, response_source)
    } else {
        message
    };

    let engine_state = state.engine.state();
    let reply_handlers = engine_state.handlers_for(&HandlerKind::ProxyReply);

    if reply_handlers.is_empty() {
        return (message, true, None);
    }

    let message_arc = Arc::new(std::sync::Mutex::new(message));
    let reply = PyReply::new(Arc::clone(&message_arc))
        .with_response_source(
            response_source.ip().to_string(),
            response_source.port(),
        );

    // Build a PyRequest from the original request so scripts get (request, reply)
    let request_arc = Arc::new(std::sync::Mutex::new(original_request));
    let mut py_request_obj = PyRequest::new(
        request_arc,
        transport.to_string(),
        source_addr.ip().to_string(),
        source_addr.port(),
    );
    // Replay the inbound flow capture so `@proxy.on_reply` handlers
    // that call `registrar.save(flow_token=…)` /
    // `registrar.save_proxy(flow_token=…)` see the same listener
    // context as the on_request handler did.  Without this,
    // PyContact.flow comes back None on a later
    // `registrar.lookup_by_token` (P-CSCF Path-token MT routing —
    // RFC 3327 §5 / TS 24.229 §5.2.7.2).
    py_request_obj.set_local_port(inbound_local_addr.port());
    py_request_obj.set_inbound_flow(inbound_local_addr, inbound_connection_id.0);

    let (forwarded, reject_action) = Python::attach(|python| {
        let py_reply = match Py::new(python, reply) {
            Ok(obj) => obj,
            Err(error) => {
                error!("failed to create PyReply: {error}");
                return (true, None); // forward on error
            }
        };
        let py_request = match Py::new(python, py_request_obj) {
            Ok(obj) => obj,
            Err(error) => {
                error!("failed to create PyRequest for reply handler: {error}");
                return (true, None);
            }
        };

        for handler in &reply_handlers {
            let callable = handler.callable.bind(python);
            let result = callable.call1((py_request.bind(python), py_reply.bind(python),));
            match result {
                Ok(ret) => {
                    if handler.is_async {
                        if let Err(error) = run_coroutine(python, &ret) {
                            error!("async Python reply handler error: {error}");
                            return (true, None);
                        }
                    }
                }
                Err(error) => {
                    error!("Python reply handler error: {error}");
                    return (true, None); // forward on error to avoid silent drops
                }
            }
        }

        let reply_ref = py_reply.borrow(python);
        (reply_ref.was_forwarded(), reply_ref.reject_action())
    });

    if reject_action.is_none() && !forwarded {
        debug!(
            status = status_code,
            branch = %branch,
            "reply dropped by script (no relay() called)"
        );
    }

    // Extract the (possibly modified) message back.  Under the
    // long-lived asyncio loops in `script::async_pool`, the asyncio
    // Task object retains the coroutine frame — and therefore the
    // `Py<PyReply>` argument — until the loop's next garbage-collection
    // pass.  That keeps `PyReply`'s `Arc::clone` of `message_arc` alive
    // a moment longer than the dispatcher closure, so `Arc::try_unwrap`
    // sometimes hits strong_count > 1 here and falls back to a clone.
    // The clone is correctness-neutral (mutations from the script are
    // visible through the lock) and bounded (one `SipMessage::clone`
    // per response with an async on_reply handler), so the fallback
    // logs at `debug!` rather than `warn!`.
    let extracted = match Arc::try_unwrap(message_arc) {
        Ok(mutex) => mutex.into_inner().unwrap_or_else(|error| {
            warn!("message mutex poisoned in reply handler: {error}");
            error.into_inner()
        }),
        Err(arc) => {
            debug!(
                "PyReply still holds message arc (async Task frame retains \
                 Py<PyReply>); cloning"
            );
            arc.lock().unwrap_or_else(|error| error.into_inner()).clone()
        }
    };

    (extracted, forwarded, reject_action)
}

/// Fire `@proxy.on_cancel` handlers for a relayed INVITE that was CANCELled
/// before any final response (RFC 3261 §9).
///
/// Fire-and-forget cleanup: the 487 to the UAC has already been sent at the
/// transaction layer and is not gated by the script — there is no
/// `relay()`/`reply()` decision. This is the only teardown signal a script
/// gets for a cancelled-before-answer call (neither `on_reply` nor
/// `on_failure` ever fires — the session is torn down with the CANCEL), so it
/// exists to release per-call resources that no BYE will ever clear (Diameter
/// Rx/N5 QoS, rtpengine media).
///
/// Mirrors `run_reply_handlers`' PyRequest construction — including the
/// inbound-flow replay — so the handler sees the same listener context the
/// `on_request` handler did (`registrar.lookup_by_token`, `request.flow`).
fn run_proxy_cancel_handlers(
    original_request: SipMessage,
    transport: crate::transport::Transport,
    source_addr: SocketAddr,
    inbound_local_addr: SocketAddr,
    inbound_connection_id: ConnectionId,
    state: &DispatcherState,
) {
    let engine_state = state.engine.state();
    let handlers = engine_state.handlers_for(&HandlerKind::ProxyCancel);
    if handlers.is_empty() {
        return;
    }

    let request_arc = Arc::new(std::sync::Mutex::new(original_request));
    let mut py_request_obj = PyRequest::new(
        request_arc,
        transport.to_string(),
        source_addr.ip().to_string(),
        source_addr.port(),
    );
    py_request_obj.set_local_port(inbound_local_addr.port());
    py_request_obj.set_inbound_flow(inbound_local_addr, inbound_connection_id.0);

    Python::attach(|python| {
        let py_request = match Py::new(python, py_request_obj) {
            Ok(obj) => obj,
            Err(error) => {
                error!("failed to create PyRequest for on_cancel handler: {error}");
                return;
            }
        };

        for handler in &handlers {
            let callable = handler.callable.bind(python);
            match callable.call1((py_request.bind(python),)) {
                Ok(ret) => {
                    if handler.is_async {
                        if let Err(error) = run_coroutine(python, &ret) {
                            error!("async Python on_cancel handler error: {error}");
                        }
                    }
                }
                Err(error) => {
                    error!("Python on_cancel handler error: {error}");
                }
            }
        }
    });
}

/// Rewrite the Contact URI in a response with the observed source address.
///
/// This is the automatic equivalent of OpenSIPS's `fix_nated_contact()` in
/// onreply_route.  When `nat.fix_contact` is enabled, every response gets
/// its Contact rewritten before forwarding upstream, so in-dialog requests
/// from the upstream UAC will reach the NATed endpoint's public address.
fn fix_response_contact(mut message: SipMessage, source: SocketAddr) -> SipMessage {
    use crate::sip::headers::nameaddr::NameAddr;

    if let Some(raw) = message.headers.get("Contact").cloned() {
        if let Ok(mut nameaddr) = NameAddr::parse(&raw) {
            let host = source.ip().to_string();
            nameaddr.uri.host = if host.contains(':') && !host.starts_with('[') {
                format!("[{host}]")
            } else {
                host
            };
            nameaddr.uri.port = Some(source.port());
            message.headers.set("Contact", nameaddr.to_string());
        }
    }
    message
}

/// Resolve a SIP URI string to a socket address using DNS (RFC 3263).
///
/// Supports numeric IPs, bare `ip:port` strings, and full SIP URIs with
/// DNS A/AAAA/SRV resolution.  Called from synchronous context using
/// `block_in_place` because the callers (relay, fork, B2BUA) are sync
/// functions running on the tokio multi-threaded runtime.
/// Resolved relay target: address + optional transport override.
struct RelayTarget {
    address: SocketAddr,
    /// Transport from URI params or SRV; `None` means use the inbound transport.
    transport: Option<Transport>,
    /// Hostname from the resolved SIP URI, used as TLS SNI / certificate
    /// hostname when a new outbound TLS connection must be opened. `None` for
    /// bare-IP targets (RFC 6066 sends no SNI for an IP literal) and for
    /// in-dialog / failover paths that route by address.
    server_name: Option<String>,
}

/// Resolve a SIP target URI to its full ordered candidate set (RFC 3263).
///
/// A bare `IP:port` short-circuits to a single candidate. A SIP URI is resolved
/// via DNS (SRV → A/AAAA); the order is the resolver's RFC 3263 §4.2 /
/// RFC 2782 selection (A/AAAA Fisher-Yates shuffled per call, SRV
/// weighted-random), so a caller that wants a single target takes
/// `.into_iter().next()` — see [`resolve_target`]. In-dialog connection reuse
/// ([`resolve_in_dialog_flow_uri`]) needs the *whole* set to test whether the
/// dialog's established peer is still among the next hop's members.
fn resolve_candidates(uri_string: &str, resolver: &SipResolver) -> Vec<RelayTarget> {
    // Inject the process-wide gateway manager (the same one `from_gateway`
    // reads) so a next hop that is a configured gateway FQDN can reuse the
    // prober's already-resolved address instead of a per-call DNS lookup.
    resolve_candidates_inner(
        uri_string,
        resolver,
        crate::script::api::gateway_manager().map(|manager| &**manager),
    )
}

/// Map a SIP `transport=` token (or SRV proto hint) to the internal
/// [`Transport`]. Case-insensitive; `None` for an unrecognised token.
fn transport_from_token(token: &str) -> Option<Transport> {
    match token.to_lowercase().as_str() {
        "tcp" => Some(Transport::Tcp),
        "tls" => Some(Transport::Tls),
        "udp" => Some(Transport::Udp),
        "ws" => Some(Transport::WebSocket),
        "wss" => Some(Transport::WebSocketSecure),
        _ => None,
    }
}

/// Core of [`resolve_candidates`] with the gateway address cache injected, so it
/// is unit-testable without the process-wide gateway singleton.
///
/// Before falling back to a blocking DNS resolve, this checks whether the next
/// hop is a configured gateway hostname destination whose address the health
/// prober has already resolved (and `set_address`'d every probe cycle). A hit
/// returns that cached, health-checked address with **zero** DNS on the hot
/// path — the fix for a per-call ~1s stall routing to an FQDN trunk / Teams
/// Direct Routing SBC on a low-traffic node where the resolver's own cache has
/// gone cold between calls. The hostname is preserved as `server_name` so TLS
/// SNI is unchanged, and the R-URI (built elsewhere from the same URI) is
/// untouched.
fn resolve_candidates_inner(
    uri_string: &str,
    resolver: &SipResolver,
    gateway: Option<&crate::gateway::DispatcherManager>,
) -> Vec<RelayTarget> {
    // Try as bare IP:port first (cheapest check)
    if let Ok(addr) = uri_string.parse::<SocketAddr>() {
        return vec![RelayTarget { address: addr, transport: None, server_name: None }];
    }

    // Try parsing as a full SIP URI
    if let Ok(uri) = parse_uri_standalone(uri_string) {
        // Extract transport hint from URI params (e.g. ;transport=tcp)
        let transport_hint = uri.get_param("transport").map(|s| s.to_string());

        // Gateway hot-path shortcut: if this next hop is a gateway hostname
        // destination, reuse the address the prober already resolved instead of
        // a blocking resolver.resolve on every call. Keyed on the same
        // normalized `host:port` the gateway stored (extract_address_from_uri).
        if let Some(gateway) = gateway {
            let host_port = crate::gateway::extract_address_from_uri(uri_string);
            if let Some((address, gateway_transport)) = gateway.cached_address_for(&host_port) {
                // A script-supplied ;transport= wins; else the destination's
                // configured transport.
                let transport = transport_hint
                    .as_deref()
                    .and_then(transport_from_token)
                    .or(Some(gateway_transport));
                return vec![RelayTarget {
                    address,
                    transport,
                    server_name: Some(uri.host.clone()),
                }];
            }
        }

        let results = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(resolver.resolve(
                &uri.host,
                uri.port,
                &uri.scheme,
                transport_hint.as_deref(),
            ))
        });

        return results
            .into_iter()
            .map(|r| {
                let transport = r
                    .transport
                    .as_deref()
                    .or(transport_hint.as_deref())
                    .and_then(transport_from_token);
                // All candidates from one URI share the target hostname — carry
                // it for TLS SNI so a hostname-vhost peer routes the handshake.
                RelayTarget { address: r.address, transport, server_name: Some(uri.host.clone()) }
            })
            .collect();
    }

    Vec::new()
}

/// Resolve a SIP target URI to a single send destination (RFC 3263).
///
/// Returns the first candidate from [`resolve_candidates`] — the resolver has
/// already applied RFC 3263 §4.2 / RFC 2782 ordering, so "first" is a fresh
/// weighted-random / shuffled pick on every call.
fn resolve_target(uri_string: &str, resolver: &SipResolver) -> Option<RelayTarget> {
    resolve_candidates(uri_string, resolver).into_iter().next()
}

/// Send a relayed request to a resolved target, using the connection pool for
/// TCP/TLS when no existing inbound connection is available.
///
/// Returns the `ConnectionId` used (new pool connection or the existing one).
fn send_to_target(
    data: Bytes,
    target: &RelayTarget,
    fallback_transport: Transport,
    fallback_connection_id: ConnectionId,
    send_source: Option<SocketAddr>,
    state: &DispatcherState,
) -> ConnectionId {
    let transport = target.transport.unwrap_or(fallback_transport);
    let destination = target.address;
    // A script `send_socket=` egress pin translated to a bind address:
    // - UDP pins the exact `(ip, port)` listener socket (`source_local_addr`).
    // - TCP/TLS bind the source *IP* with an ephemeral port (`port 0`) — the
    //   listen port would collide on the 4-tuple in `TIME_WAIT`.
    let send_bind_stream = send_source.map(|addr| SocketAddr::new(addr.ip(), 0));

    // HEP capture — outbound (sent to network)
    if let Some(ref hep) = state.hep_sender {
        let local = state.listen_addrs.get(&transport).copied().unwrap_or(state.local_addr);
        hep.capture_outbound(state.hep_local_addr(local, transport), destination, transport, &data);
    }

    match transport {
        Transport::Tcp => {
            // Use connection pool for outbound TCP.  For ESP-over-TCP
            // IPsec destinations (TS 33.203 §7.2 — iOS clients),
            // bind the local socket to the SA-pair source endpoint
            // (`pcscf_addr:pcscf_port_c`) so the kernel egress XFRM
            // selector for SA #3 matches.  An ephemerally-bound socket
            // never matches and the packet is silently dropped.
            let pool = Arc::clone(&state.connection_pool);
            let data_clone = data;
            // IPsec's fixed-port source wins over a script send_socket pin (the
            // kernel XFRM selector requires it); otherwise use the pin's
            // interface IP with an ephemeral source port.
            let source = crate::script::api::ipsec::outbound_local_addr_for(destination)
                .or(send_bind_stream);
            let connect_result = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    match source {
                        Some(source) => pool.send_tcp_from(source, destination, data_clone).await,
                        None => pool.send_tcp(destination, data_clone).await,
                    }
                })
            });
            match connect_result {
                Ok(connection_id) => {
                    debug!(
                        destination = %destination,
                        connection_id = ?connection_id,
                        "relayed via TCP pool"
                    );
                    connection_id
                }
                Err(error) => {
                    // Pool send failed (connect refused, broken pipe, etc.).
                    // DO NOT fall back to the inbound connection_id — for TCP
                    // that's the UAC's connection, and routing the outbound
                    // request to it would echo the message back to the sender.
                    // Return the sentinel ConnectionId::default() so the
                    // caller stores 0 on the ClientBranch; future in-dialog
                    // sends (ACK, BYE) on that branch will miss the
                    // connection_map lookup and be dropped — which is the
                    // correct outcome when we never reached the upstream.
                    error!(
                        destination = %destination,
                        "TCP pool send failed: {error}"
                    );
                    ConnectionId::default()
                }
            }
        }
        Transport::Tls => {
            // Script send_socket= egress pin over TLS: open (or reuse) a
            // source-bound pool connection.  The pool keys on the bind address,
            // so this stays distinct from a default-source connection to the
            // same peer.  We bypass the generic `reuse` below because that
            // ignores the source — reusing a connection off the wrong interface
            // would violate the operator's egress pin.
            if let Some(bind) = send_bind_stream {
                let pool = Arc::clone(&state.connection_pool);
                let server_name = target.server_name.clone();
                let data_clone = data;
                return match tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(pool.send_tls_from(
                        bind,
                        destination,
                        server_name.as_deref(),
                        data_clone,
                    ))
                }) {
                    Ok(connection_id) => {
                        debug!(
                            destination = %destination,
                            connection_id = ?connection_id,
                            bind = %bind,
                            "relayed via source-bound TLS pool (send_socket)"
                        );
                        connection_id
                    }
                    Err(error) => {
                        error!(destination = %destination, "source-bound TLS pool send failed: {error}");
                        ConnectionId::default()
                    }
                };
            }

            // TLS connection reuse: find an existing inbound (or pool-created
            // outbound) TLS connection to the destination (like OpenSIPS
            // connection reuse).  `reuse` tries an exact SocketAddr match, then
            // an IP-only fallback (handles NAT where the Contact-URI port
            // differs from the source port), filtered to TLS.
            let connection_id = state.stream_connections.reuse(destination, Transport::Tls);

            if let Some(connection_id) = connection_id {
                let outbound_message = OutboundMessage {
                    connection_id,
                    transport: Transport::Tls,
                    destination,
                    data,
                    source_local_addr: None,
                    // Connection *reuse* — no TLS handshake, so no SNI needed.
                    server_name: None,
                };
                if let Err(error) = state.outbound.send(outbound_message) {
                    error!(destination = %destination, "TLS connection reuse send failed: {error}");
                } else {
                    debug!(
                        destination = %destination,
                        connection_id = ?connection_id,
                        "relayed via TLS connection reuse"
                    );
                }
                connection_id
            } else {
                // No inbound connection to reuse — create outbound TLS via pool
                let pool = Arc::clone(&state.connection_pool);
                let data_clone = data;
                let server_name = target.server_name.clone();
                match tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current()
                        .block_on(pool.send_tls(destination, server_name.as_deref(), data_clone))
                }) {
                    Ok(connection_id) => {
                        debug!(
                            destination = %destination,
                            connection_id = ?connection_id,
                            "relayed via TLS pool"
                        );
                        connection_id
                    }
                    Err(error) => {
                        // Same rationale as the TCP arm above — never echo to
                        // the inbound connection on outbound failure.
                        error!(destination = %destination, "TLS pool send failed: {error}");
                        ConnectionId::default()
                    }
                }
            }
        }
        Transport::WebSocket | Transport::WebSocketSecure => {
            // WebSocket connection reuse is *mandatory*: the connection is
            // client-initiated and can never be re-opened by the server
            // (RFC 7118 §5 / RFC 5626 §5.3).  Look up the live connection for
            // this UE (exact, then IP-only fallback, filtered to this WS/WSS
            // transport).
            //
            // This URI-relay path only fires when the target resolved to the
            // UE's real address — the primary WS MT path is the captured-flow
            // path (`relay(flow=...)` / forked flow), which bypasses
            // `send_to_target` entirely.  On a miss we DROP (return the
            // sentinel `ConnectionId::default()`) instead of falling back to
            // `fallback_connection_id` (the inbound caller's connection): the
            // UE is simply unreachable, and echoing the request back to the
            // sender — the pre-fix behaviour of the `_` arm — is exactly the
            // bug being closed.
            match state.stream_connections.reuse(destination, transport) {
                Some(connection_id) => {
                    let outbound_message = OutboundMessage {
                        connection_id,
                        transport,
                        destination,
                        data,
                        source_local_addr: None,
                        server_name: None,
                    };
                    if let Err(error) = state.outbound.send(outbound_message) {
                        error!(destination = %destination, %transport, "WS/WSS connection reuse send failed: {error}");
                    } else {
                        debug!(
                            destination = %destination,
                            connection_id = ?connection_id,
                            %transport,
                            "relayed via WS/WSS connection reuse"
                        );
                    }
                    connection_id
                }
                None => {
                    warn!(
                        destination = %destination,
                        %transport,
                        "no live WS/WSS connection to reuse — dropping (client-initiated transport cannot be dialed; use relay(flow=...) for MT routing)"
                    );
                    ConnectionId::default()
                }
            }
        }
        _ => {
            // UDP and other transports: use the existing outbound channel.
            //
            // IPsec auto-source (3GPP TS 33.203 §6.3): when the
            // destination matches an installed SA pair, ask the IPsec
            // module which P-CSCF port to egress from.  Without this,
            // an MT INVITE to an IPsec-protected UE leaves on the
            // default listener (typically port 5060), the kernel
            // selector for SA #3 (src=`port_pc`, dst=`port_us`)
            // doesn't match, and the packet is silently dropped.
            // Returns `None` for non-IPsec deployments and ordinary
            // (non-UE) destinations — i.e. zero impact on the hot
            // path when no IpsecManager is wired.
            // IPsec auto-source wins over a script send_socket pin (kernel XFRM
            // selector); otherwise the pin selects the exact `(ip, port)` UDP
            // listener socket to egress from (routed via `udp_by_local`).
            let source_local_addr =
                crate::script::api::ipsec::outbound_local_addr_for(destination).or(send_source);
            let outbound_message = OutboundMessage {
                connection_id: fallback_connection_id,
                transport,
                destination,
                data,
                source_local_addr,
                server_name: None,
            };
            if let Err(error) = state.outbound.send(outbound_message) {
                error!("failed to enqueue relayed request: {error}");
            }
            fallback_connection_id
        }
    }
}

/// Run a Python coroutine to completion.
///
/// When a handler is `async def`, calling it returns a coroutine object.
/// This function drives it using `asyncio.run()` which creates a fresh
/// event loop, runs the coroutine, and tears it down.
/// Initialize the media-control backend, media session store, and profile
/// registry, and register the Python `siphon.rtpengine` singleton.
///
/// Selects rtpengine NG or the native siphon-rtp engine per `media.backend`.
/// `event_sender` carries async engine events (DTMF, media-timeout) onward to
/// the dispatcher's consumer loop; the native backend forwards events from its
/// control connection over it (the rtpengine backend uses the separate TCP
/// event listener instead). Returns `(None, None, None)` when `media` is not
/// configured or the selected backend cannot be built.
pub fn init_rtpengine(
    config: &Config,
    event_sender: tokio::sync::mpsc::Sender<crate::rtpengine::events::RtpEngineEvent>,
) -> RtpEngineComponents {
    let media_config = match &config.media {
        Some(c) => c,
        None => return (None, None, None),
    };

    let backend = match media_config.backend {
        crate::config::MediaBackendKind::Rtpengine => build_rtpengine_backend(media_config),
        crate::config::MediaBackendKind::SiphonRtp => {
            build_siphon_rtp_backend(media_config, event_sender)
        }
        crate::config::MediaBackendKind::Rtpproxy => build_rtpproxy_backend(media_config),
    };
    let backend = match backend {
        Some(backend) => Arc::new(backend),
        None => return (None, None, None),
    };

    let sessions = Arc::new(crate::rtpengine::session::MediaSessionStore::new());
    // Profile registry from built-in defaults + custom YAML profiles (shared
    // across backends — profiles map to NG flags / proto ProfileFlags alike).
    let registry = Arc::new(crate::rtpengine::ProfileRegistry::from_config(
        &media_config.profiles,
    ));

    // Create the Python-side singleton (shares the same Arcs).
    let py_rtpengine = crate::script::api::rtpengine::PyRtpEngine::new(
        Arc::clone(&backend),
        Arc::clone(&sessions),
        Arc::clone(&registry),
    );
    Python::attach(|python| {
        if let Err(error) = crate::script::api::set_rtpengine_singleton(python, py_rtpengine) {
            error!("failed to store RTPEngine singleton: {error}");
        } else {
            info!(
                instances = backend.instance_count(),
                "media backend registered"
            );
        }
    });

    (Some(backend), Some(sessions), Some(registry))
}

/// Build the rtpengine NG/bencode backend from `media.rtpengine`.
fn build_rtpengine_backend(
    media_config: &crate::config::MediaConfig,
) -> Option<crate::rtpengine::MediaBackend> {
    let rtpengine_config = match &media_config.rtpengine {
        Some(config) => config,
        None => {
            error!("media.backend is 'rtpengine' but no media.rtpengine block is configured");
            return None;
        }
    };

    let instances_config = rtpengine_config.instances();
    let mut instance_tuples = Vec::new();
    for instance in &instances_config {
        match instance.address.parse::<std::net::SocketAddr>() {
            Ok(address) => instance_tuples.push((address, instance.timeout_ms, instance.weight)),
            Err(parse_error) => error!(
                address = %instance.address,
                error = %parse_error,
                "invalid RTPEngine address, skipping"
            ),
        }
    }
    if instance_tuples.is_empty() {
        return None;
    }

    let count = instance_tuples.len();
    let handle = tokio::runtime::Handle::current();
    match tokio::task::block_in_place(|| {
        handle.block_on(crate::rtpengine::client::RtpEngineSet::new(instance_tuples))
    }) {
        Ok(set) => {
            info!(
                instances = count,
                "rtpengine NG backend configured ({count} instance{})",
                if count == 1 { "" } else { "s" }
            );
            Some(crate::rtpengine::MediaBackend::RtpEngine(Arc::new(set)))
        }
        Err(error) => {
            error!(error = %error, "failed to initialize RTPEngine client");
            None
        }
    }
}

/// Build the native siphon-rtp JSON-over-TCP backend from `media.siphon_rtp`.
fn build_siphon_rtp_backend(
    media_config: &crate::config::MediaConfig,
    event_sender: tokio::sync::mpsc::Sender<crate::rtpengine::events::RtpEngineEvent>,
) -> Option<crate::rtpengine::MediaBackend> {
    let siphon_rtp_config = match &media_config.siphon_rtp {
        Some(config) => config,
        None => {
            error!("media.backend is 'siphon-rtp' but no media.siphon_rtp block is configured");
            return None;
        }
    };

    let mut instance_tuples = Vec::new();
    for (address, timeout_ms, weight) in siphon_rtp_config.instances() {
        match address.parse::<std::net::SocketAddr>() {
            Ok(parsed) => instance_tuples.push((parsed, timeout_ms, weight)),
            Err(parse_error) => error!(
                address = %address,
                error = %parse_error,
                "invalid siphon-rtp control address, skipping"
            ),
        }
    }
    if instance_tuples.is_empty() {
        error!("media.backend is 'siphon-rtp' but no valid control address is configured");
        return None;
    }

    let count = instance_tuples.len();
    match crate::rtpengine::SiphonRtpClientSet::new(
        instance_tuples,
        siphon_rtp_config.control_secret.clone(),
        siphon_rtp_config.play_timeout_ms,
        event_sender,
    ) {
        Ok(set) => {
            info!(
                instances = count,
                "siphon-rtp native media backend configured ({count} instance{})",
                if count == 1 { "" } else { "s" }
            );
            Some(crate::rtpengine::MediaBackend::SiphonRtp(set))
        }
        Err(error) => {
            error!(error = %error, "failed to initialize siphon-rtp client set");
            None
        }
    }
}

/// Build the classic rtpproxy text-over-UDP backend from `media.rtpproxy`.
fn build_rtpproxy_backend(
    media_config: &crate::config::MediaConfig,
) -> Option<crate::rtpengine::MediaBackend> {
    let rtpproxy_config = match &media_config.rtpproxy {
        Some(config) => config,
        None => {
            error!("media.backend is 'rtpproxy' but no media.rtpproxy block is configured");
            return None;
        }
    };

    let mut instance_tuples = Vec::new();
    for (address, timeout_ms, weight) in rtpproxy_config.instances() {
        match address.parse::<std::net::SocketAddr>() {
            Ok(parsed) => instance_tuples.push((parsed, timeout_ms, weight)),
            Err(parse_error) => error!(
                address = %address,
                error = %parse_error,
                "invalid rtpproxy control address, skipping"
            ),
        }
    }
    if instance_tuples.is_empty() {
        error!("media.backend is 'rtpproxy' but no valid control address is configured");
        return None;
    }

    let count = instance_tuples.len();
    let retries = rtpproxy_config.retries;
    let handle = tokio::runtime::Handle::current();
    match tokio::task::block_in_place(|| {
        handle.block_on(crate::rtpengine::RtpProxyClientSet::new(instance_tuples, retries))
    }) {
        Ok(set) => {
            info!(
                instances = count,
                "rtpproxy media backend configured ({count} instance{})",
                if count == 1 { "" } else { "s" }
            );
            Some(crate::rtpengine::MediaBackend::RtpProxy(set))
        }
        Err(error) => {
            error!(error = %error, "failed to initialize rtpproxy client set");
            None
        }
    }
}

/// Spawn a background task that pings every RTPEngine instance on a fixed
/// interval and exports per-instance health to Prometheus.
///
/// The first probe runs immediately so the gauges reflect reality from the
/// moment the task starts; subsequent probes run every `interval_secs`
/// seconds.  Pass `interval_secs == 0` to disable health probing entirely.
///
/// Updates these metrics:
/// - `siphon_rtpengine_instances_total` — number of configured instances
/// - `siphon_rtpengine_instances_up` — number that answered the last ping
/// - `siphon_rtpengine_instance_up{address}` — 0/1 for each instance
pub fn spawn_rtpengine_health_check(
    rtpengine_set: Arc<crate::rtpengine::MediaBackend>,
    interval_secs: u64,
) {
    if interval_secs == 0 {
        info!("RTPEngine health probing disabled (interval_secs=0)");
        return;
    }

    let total_instances = rtpengine_set.instance_count();
    let addresses = rtpengine_set.instance_addresses();

    if let Some(metrics) = crate::metrics::try_metrics() {
        metrics.rtpengine_instances_total.set(total_instances as i64);
        // Pre-create the per-instance label series so they appear at zero
        // before the first probe completes.
        for address in &addresses {
            metrics
                .rtpengine_instance_up
                .with_label_values(&[&address.to_string()])
                .set(0);
        }
    }

    info!(
        instances = total_instances,
        interval_secs,
        "starting RTPEngine health probe"
    );

    tokio::spawn(async move {
        let mut ticker =
            tokio::time::interval(std::time::Duration::from_secs(interval_secs));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let results = rtpengine_set.health_check().await;
            let healthy_count = results.iter().filter(|(_, healthy)| *healthy).count();

            for (address, healthy) in &results {
                if !healthy {
                    warn!(
                        address = %address,
                        "RTPEngine instance failed health probe"
                    );
                }
            }

            if let Some(metrics) = crate::metrics::try_metrics() {
                metrics.rtpengine_instances_up.set(healthy_count as i64);
                for (address, healthy) in &results {
                    metrics
                        .rtpengine_instance_up
                        .with_label_values(&[&address.to_string()])
                        .set(if *healthy { 1 } else { 0 });
                }
            }
        }
    });
}

/// Run a Python coroutine to completion.
/// Check if a Python object is a coroutine (awaitable).
fn is_coroutine(python: Python<'_>, obj: &Bound<'_, pyo3::PyAny>) -> PyResult<bool> {
    let asyncio = python.import("asyncio")?;
    let result = asyncio.call_method1("iscoroutine", (obj,))?;
    result.is_truthy()
}

/// Build a SIP response from a request, copying mandatory headers.
fn build_response(
    request: &SipMessage,
    status_code: u16,
    reason: &str,
    server_header: Option<&str>,
    reply_headers: &[(crate::script::api::request::ReplyHeaderOp, String, String)],
) -> SipMessage {
    use crate::script::api::request::ReplyHeaderOp;

    let mut builder = SipMessageBuilder::new()
        .response(status_code, reason.to_string());

    // Copy all Via headers (response routing depends on this)
    if let Some(vias) = request.headers.get_all("Via") {
        for via in vias {
            builder = builder.via(via.clone());
        }
    }

    // Copy From, To, Call-ID, CSeq (mandatory in all responses per RFC 3261 §8.2.6.2)
    if let Some(from) = request.headers.from() {
        builder = builder.from(from.clone());
    }
    if let Some(to) = request.headers.to() {
        builder = builder.to(to.clone());
    }
    if let Some(call_id) = request.headers.call_id() {
        builder = builder.call_id(call_id.clone());
    }
    if let Some(cseq) = request.headers.cseq() {
        builder = builder.cseq(cseq.clone());
    }

    // Copy any auth challenge headers the script may have set
    if let Some(www_auth) = request.headers.get("WWW-Authenticate") {
        builder = builder.header("WWW-Authenticate", www_auth.clone());
    }
    if let Some(proxy_auth) = request.headers.get("Proxy-Authenticate") {
        builder = builder.header("Proxy-Authenticate", proxy_auth.clone());
    }


    // Copy Expires header for REGISTER responses (RFC 3261 §10.3 step 8).
    // The registrar.save() method sets this on the request to communicate
    // the granted expires value to the response builder.
    if let Some(expires) = request.headers.get("Expires") {
        builder = builder.header("Expires", expires.clone());
    }

    // Copy SIP-ETag for PUBLISH responses (RFC 3903 §4.1)
    if let Some(sip_etag) = request.headers.get("SIP-ETag") {
        builder = builder.header("SIP-ETag", sip_etag.clone());
    }

    if let Some(server) = server_header {
        builder = builder.header("Server", server.to_string());
    }

    // Inject script-provided reply headers before Content-Length so that
    // parsers that stop at Content-Length: 0 still see them.
    //
    // Replace semantics for `set_reply_header` are critical here: the
    // mandatory-copy block above already populated To/From/Call-ID/CSeq
    // and the optional-copy block populated Expires/SIP-ETag/Server.
    // A script calling `set_reply_header("To", "<...>;tag=...")` to add
    // a UAS-side To-tag (RFC 3261 §12.1.1.2 / RFC 6665 §4.1.3) MUST end
    // up with exactly one To header — append-only would produce two.
    // `add_reply_header` (op = Add) is reserved for genuinely multi-value
    // headers (Service-Route, P-Associated-URI, Path, etc.).
    for (op, name, value) in reply_headers {
        match op {
            ReplyHeaderOp::Replace => {
                builder = builder.set_header(name, value.clone());
            }
            ReplyHeaderOp::Add => {
                builder = builder.header(name, value.clone());
            }
        }
    }

    builder = builder.content_length(0);

    match builder.build() {
        Ok(message) => message,
        Err(error) => {
            error!("response builder failed (this should not happen): {error}");
            // Construct a minimal valid response directly
            SipMessage {
                start_line: StartLine::Response(StatusLine {
                    version: Version::sip_2_0(),
                    status_code: 500,
                    reason_phrase: "Internal Server Error".to_string(),
                }),
                headers: SipHeaders::new(),
                body: Vec::new(),
            }
        }
    }
}

/// Build an ACK for a non-2xx final response to INVITE (RFC 3261 §17.1.1.3).
///
/// The ACK is hop-by-hop: each proxy generates its own for non-2xx.
/// - Request-URI: same as the original INVITE
/// - Via: only our own Via (the branch that created the client transaction)
/// - From: from the original request
/// - To: from the response (includes To-tag added by UAS)
/// - Call-ID: from the original request
/// - CSeq: same sequence number, ACK method
/// - Route: same as original INVITE (if any)
fn build_ack_for_non2xx(
    original_request: &SipMessage,
    response: &SipMessage,
    branch: &str,
    downstream_transport: Transport,
    local_addr: SocketAddr,
) -> SipMessage {
    let request_uri = match &original_request.start_line {
        StartLine::Request(rl) => rl.request_uri.clone(),
        _ => SipUri::new("invalid".to_string()),
    };

    let mut builder = SipMessageBuilder::new()
        .request(Method::Ack, request_uri);

    // Via: only our own hop with the client transaction branch
    let transport_str = format!("{}", downstream_transport).to_uppercase();
    let host = format_sip_host(&local_addr.ip().to_string());
    builder = builder.via(format!(
        "SIP/2.0/{} {}:{};branch={}",
        transport_str, host, local_addr.port(), branch
    ));

    if let Some(from) = original_request.headers.from() {
        builder = builder.from(from.clone());
    }

    // To: from the response (includes To-tag from UAS)
    if let Some(to) = response.headers.to() {
        builder = builder.to(to.clone());
    }

    if let Some(call_id) = original_request.headers.call_id() {
        builder = builder.call_id(call_id.clone());
    }

    // CSeq: same sequence number, ACK method
    if let Some(cseq) = original_request.headers.cseq() {
        let cseq_num = cseq.split_whitespace().next().unwrap_or("1");
        builder = builder.cseq(format!("{} ACK", cseq_num));
    }

    // Route: copy from original request if present
    if let Some(routes) = original_request.headers.get_all("Route") {
        for route in routes {
            builder = builder.header("Route", route.clone());
        }
    }

    builder = builder.header("Max-Forwards", "70".to_string());
    builder = builder.content_length(0);

    match builder.build() {
        Ok(message) => message,
        Err(error) => {
            error!("ACK builder failed (this should not happen): {error}");
            SipMessage {
                start_line: StartLine::Request(RequestLine {
                    method: Method::Ack,
                    request_uri: SipUri::new("invalid".to_string()),
                    version: Version::sip_2_0(),
                }),
                headers: SipHeaders::new(),
                body: Vec::new(),
            }
        }
    }
}

/// Build an ACK for a non-2xx B-leg response in B2BUA mode (RFC 3261 §17.1.1.3).
///
/// Unlike the proxy path, we don't store the B-leg INVITE. Instead we
/// reconstruct the ACK from the response (which carries the same Call-ID,
/// From, and CSeq as the original B-leg INVITE) plus the B-leg target URI.
/// Extract the bare URI string from the first entry of a dialog route set.
///
/// Route entries are stored in wire form (e.g. `<sip:p.example.com;lr>`); this
/// strips angle brackets and any header-level params and returns
/// `sip:p.example.com;lr` ready to feed to `resolve_target`. Returns `None`
/// if the route set is empty or the first entry cannot be parsed.
fn first_route_uri(route_set: &[String]) -> Option<String> {
    let first = route_set.first()?;
    crate::sip::headers::route::RouteEntry::parse(first)
        .ok()
        .map(|entry| entry.uri.to_string())
}

/// Resolve the destination for a B2BUA in-dialog request per RFC 3261
/// §12.2.1.1 / §16.12, preferring the dialog's established connection
/// (RFC 5923) — see [`resolve_in_dialog_flow_uri`] for the full reasoning.
///
/// The next hop is the first `Route` URI of the dialog route set (or the cached
/// remote target when the route set is empty). When that next hop still
/// resolves to the peer the dialog was established with (`fallback_addr`'s IP),
/// the cached address/transport are returned so the existing send reuses the
/// established connection rather than re-resolving — which, since the RFC 3263
/// §4.2 A/AAAA shuffle, can land on a different member of a load-balanced trunk
/// that holds no dialog state. It still follows the route set to a genuinely
/// different next hop (e.g. an IMS S-CSCF reached via the route set while the
/// INVITE traversed a non-Record-Routing I-CSCF — TS 24.229 §5.3.2).
///
/// The B2BUA send sites already supply the leg's `connection_id` to
/// [`send_message`] (A-leg, where an inbound connection can only be reached by
/// reuse) or reuse the outbound pool connection by address via
/// [`send_b2bua_to_bleg`] (B-leg), so this returns just `(addr, transport)`.
fn resolve_in_dialog_destination(
    route_set: &[String],
    state: &DispatcherState,
    fallback_addr: SocketAddr,
    fallback_transport: Transport,
) -> (SocketAddr, Transport) {
    let next_hop = first_route_uri(route_set);
    let (destination, transport, _connection_id) = resolve_in_dialog_flow_uri(
        next_hop.as_deref(),
        &state.dns_resolver,
        fallback_addr,
        fallback_transport,
        ConnectionId::default(),
    );
    (destination, transport)
}

/// For an in-dialog request whose next hop did not resolve — e.g. a WebSocket
/// UE registered a `<uuid>.invalid` Contact (RFC 7118), so the R-URI can't be
/// DNS-resolved — recover the destination from the connection the dialog was
/// established on (RFC 5923 / RFC 5626 §5.3 connection reuse).
///
/// Returns the established far-end `(destination, transport)`.  The destination
/// is the peer's source address, which the stream-connection registry is keyed
/// on, so [`send_to_target`]'s per-transport reuse (TCP/TLS/WS/WSS arms) then
/// routes the request over the live connection — the only way back to a WS/WSS
/// UE.  Looked up by the dialog key `(Call-ID, From-tag)`; finds the session for
/// any in-dialog request originated by the dialog's creator (the common case:
/// a UAC sending BYE/re-INVITE/UPDATE for its own call).
fn in_dialog_reuse_destination(
    message: &SipMessage,
    state: &DispatcherState,
) -> Option<(SocketAddr, Transport)> {
    let call_id = message.headers.get("Call-ID")?;
    let from_tag = message.typed_from().ok().flatten().and_then(|na| na.tag)?;
    let session_arc = state.session_store.get_by_dialog_key(call_id, &from_tag)?;
    let session = session_arc.read().ok()?;
    let client_key = session.client_keys.first()?;
    let branch = session.get_client_branch(client_key)?;
    Some((branch.destination, branch.transport))
}

/// Pin the outbound transport to a matching IPsec SA's protocol
/// (3GPP TS 33.203 §7.2).  When `destination` matches a registered UE binding,
/// the SA's pinned protocol (UDP vs TCP) overrides whatever the dialog route
/// set or cached transport selected.  In-dialog requests (BYE, UPDATE,
/// in-dialog re-INVITE, end-to-end 2xx ACK) often arrive with a Route URI /
/// cached Contact that lacks `;transport=`, and the kernel XFRM selector
/// silently drops every protected frame whose upper-layer protocol doesn't
/// match.  No-op for non-IPsec deployments and ordinary destinations — zero
/// impact when no IpsecManager is wired.
fn ipsec_pin_transport(destination: SocketAddr, transport: Transport) -> Transport {
    if matches!(transport, Transport::Udp | Transport::Tcp) {
        if let Some((_, sa_transport)) =
            crate::script::api::ipsec::outbound_for(destination, transport)
        {
            if sa_transport != transport {
                debug!(
                    %destination,
                    from = %transport,
                    to = %sa_transport,
                    "IPsec: pinning in-dialog transport to SA protocol",
                );
                return sa_transport;
            }
        }
    }
    transport
}

/// Test whether an in-dialog request should reuse the dialog's established
/// connection (RFC 5923) instead of opening one to a freshly-resolved next hop.
///
/// Reuse when the established peer's IP is among the next hop's resolved
/// candidates — IP-only, because the cached address carries the peer's *source*
/// port (an ephemeral port for an inbound connection, or the pooled outbound
/// socket's peer), not its SIP listening port — or when nothing resolved (the
/// established peer is then the best available target). Returns `false` only
/// when the next hop points at a genuinely different peer (e.g. an IMS S-CSCF
/// reached via the dialog route set while the INVITE was forwarded to a
/// non-Record-Routing I-CSCF).
fn established_peer_in_candidates(cached_ip: std::net::IpAddr, candidates: &[RelayTarget]) -> bool {
    candidates.is_empty() || candidates.iter().any(|target| target.address.ip() == cached_ip)
}

/// Resolve the destination for an in-dialog request, preferring the dialog's
/// established connection (RFC 5923) when the next hop still resolves to the
/// peer the dialog was established with.
///
/// On a connection-oriented transport to a multi-member peer behind one DNS
/// name (a load-balanced Record-Route), the next hop resolves to several
/// siblings; since the RFC 3263 §4.2 A/AAAA shuffle picks one at random per
/// call, a fresh resolution can land on a member that holds no dialog state, so
/// an in-dialog BYE/re-INVITE/UPDATE hits the wrong node and the far leg is
/// never released / the request is never applied. RFC 5923 says to send
/// in-dialog traffic over the connection the dialog was established on; we do
/// exactly that whenever the established peer is still one of the next hop's
/// resolved members.
///
/// Returns `(destination, transport, connection_id)`. On the reuse path the
/// connection_id is the cached one, so [`send_message_from`] routes over the
/// live connection (and the per-transport outbound distributor falls back to
/// the pool against the *same member's* address if it has since closed). On the
/// fresh-resolution path it is [`ConnectionId::default`] (open / pool a new
/// connection). The IPsec transport pin is applied to the final destination in
/// both cases.
fn resolve_in_dialog_flow_uri(
    next_hop_uri: Option<&str>,
    resolver: &SipResolver,
    cached_addr: SocketAddr,
    cached_transport: Transport,
    cached_connection_id: ConnectionId,
) -> (SocketAddr, Transport, ConnectionId) {
    let (destination, transport, connection_id) = match next_hop_uri {
        // No next hop (empty route set) → the cached peer IS the remote target
        // (RFC 3261 §12.2.1.1); reuse its connection.
        None => (cached_addr, cached_transport, cached_connection_id),
        Some(uri) => {
            let candidates = resolve_candidates(uri, resolver);
            if established_peer_in_candidates(cached_addr.ip(), &candidates) {
                (cached_addr, cached_transport, cached_connection_id)
            } else {
                // Genuinely different next hop (IMS route-set divergence) —
                // resolve fresh and open/pool a new connection.
                let target = &candidates[0];
                (
                    target.address,
                    target.transport.unwrap_or(cached_transport),
                    ConnectionId::default(),
                )
            }
        }
    };

    (destination, ipsec_pin_transport(destination, transport), connection_id)
}

/// Choose the wire destination for a B2BUA retry INVITE that supersedes a failed
/// outbound leg in place — the 401/407 credentialed re-INVITE and the RFC 4028
/// 422 higher-Session-Expires re-INVITE both take this path (RFC 5923 connection
/// reuse).
///
/// The CSeq-1 INVITE, its non-2xx final response, and any server nonce all
/// traversed one specific trunk member. The retry is a *fresh* pre-dialog
/// transaction (new Via branch, new CSeq, no To-tag yet), so the in-dialog
/// connection-reuse path doesn't apply to it. Re-resolving the trunk hostname
/// here would re-run the RFC 3263 §4.2 A/AAAA shuffle and can pick a *different*
/// member than the one that issued the challenge — on a strict trunk a 401 retry
/// draws another 401 (auth loop), and even on a lenient trunk it splits one
/// INVITE transaction across two members (fragile CANCEL/BYE/session-timer
/// correlation, per-member state divergence).
///
/// So when the failed leg has a recorded destination, reuse it verbatim
/// (address + transport + connection_id): for TCP/TLS [`send_to_target`] then
/// reuses the pooled connection to that member (keyed by address); for UDP it
/// pins the datagram to the same member. Only when the leg has no recorded
/// destination (defensive — in the live path `b_leg_dest` is derived from the
/// same matched leg as the target URI) do we resolve `target_uri` afresh and
/// open/pool a new connection.
///
/// Returns `(destination, transport, connection_id, relay_target)`, or `None`
/// when there is no leg destination and `target_uri` does not resolve.
fn select_b2bua_retry_destination(
    b_leg_dest: Option<(SocketAddr, Transport)>,
    b_leg_connection_id: ConnectionId,
    target_uri: &str,
    resolver: &SipResolver,
) -> Option<(SocketAddr, Transport, ConnectionId, RelayTarget)> {
    match b_leg_dest {
        Some((member_addr, member_transport)) => Some((
            member_addr,
            member_transport,
            b_leg_connection_id,
            RelayTarget {
                address: member_addr,
                transport: Some(member_transport),
                server_name: None,
            },
        )),
        None => resolve_target(target_uri, resolver).map(|relay_target| {
            let transport = relay_target.transport.unwrap_or(Transport::Udp);
            (
                relay_target.address,
                transport,
                ConnectionId::default(),
                relay_target,
            )
        }),
    }
}

/// Flatten Record-Route header lines into one URI per entry.
///
/// SIP allows multiple URIs per Record-Route header line separated by commas
/// (RFC 3261 §7.3.1), so a Vec of raw header lines can contain anywhere from
/// one URI per element to all URIs on a single element. Splitting on commas
/// preserves wire order; callers reverse only if RFC 3261 §12.1.1 requires it
/// (UAC route-set = Record-Route from 2xx reversed; UAS route-set = in order).
fn flatten_record_route_headers(headers: &[String]) -> Vec<String> {
    let mut routes = Vec::new();
    for header_line in headers {
        for entry in header_line.split(',') {
            let trimmed = entry.trim();
            if !trimmed.is_empty() {
                routes.push(trimmed.to_string());
            }
        }
    }
    routes
}

/// Compute the UAC-side dialog route set (RFC 3261 §12.1.2) from a response's
/// Record-Route header lines: flatten multi-URI lines (RFC 3261 §7.3.1) into one
/// URI per entry, then reverse (the UAC route set is the responder's Record-Route
/// in reverse order). Used for the early dialog (reliable 1xx, RFC 3262 §4) and
/// the confirmed dialog (2xx).
fn uac_route_set_from_record_routes(record_routes: &[String]) -> Vec<String> {
    let mut routes = flatten_record_route_headers(record_routes);
    routes.reverse();
    routes
}

/// Resolve a script-supplied translate-op name (from `call.dial(translate=[(…, "rfc7044")])`)
/// to a [`crate::b2bua::header_policy::TranslateOp`].  Returns `None` for
/// unknown names; the caller is expected to log and skip.
fn parse_translate_op_name(name: &str) -> Option<crate::b2bua::header_policy::TranslateOp> {
    match name.to_ascii_lowercase().as_str() {
        "rfc7044" | "diversion-to-history-info" => {
            Some(crate::b2bua::header_policy::TranslateOp::DiversionToHistoryInfo)
        }
        _ => None,
    }
}

/// Set `Allow` (RFC 3261 §20.5) to the methods siphon supports, but only when the
/// header is absent — never overwrite a caller/script-set `Allow`. Used on
/// siphon's own UA surfaces (OPTIONS 2xx responses, B2BUA responses) so a peer can
/// discover the supported method set, including REFER/NOTIFY for transfer.
fn advertise_supported_methods(headers: &mut SipHeaders) {
    if !headers.has("Allow") {
        headers.set("Allow", crate::sip::SUPPORTED_METHODS.to_string());
    }
}

/// Turn a 2xx OPTIONS into a proper capability response (RFC 3261 §11.2): add a
/// `Contact` at the advertised sent-by and advertise the supported methods via
/// `Allow`. Both are added only when absent, so a script-set `Contact`/`Allow`
/// wins. `via_host`/`via_port` are the advertised sent-by for the transport the
/// OPTIONS arrived on; some peers (Microsoft Teams Direct Routing) reject an
/// OPTIONS answer that carries neither `Contact` nor `Record-Route`.
fn augment_options_response(
    response: &mut SipMessage,
    via_host: &str,
    via_port: u16,
    transport: Transport,
) {
    if !response.headers.has("Contact") {
        response.headers.set(
            "Contact",
            format!(
                "<sip:{}:{};transport={}>",
                via_host,
                via_port,
                transport.to_string().to_lowercase()
            ),
        );
    }
    advertise_supported_methods(&mut response.headers);
}

/// The port siphon advertises to the A-leg (Contact) and anchors the A-leg
/// dialog on: the listener the INVITE actually arrived on when known
/// (`a_leg_local_addr`), else the default per-transport listener port
/// (`default_via_port`).
///
/// On a multi-homed host the two differ — an INVITE to `:5066` while the first
/// configured listener is `:5060`. Advertising the default there sends every
/// in-dialog request to a port the dialog isn't anchored on (over UDP it splits
/// traffic; over a stream transport RFC 5923 connection reuse masks it). On a
/// single-listener host the arrival port equals `default_via_port`, so this is
/// a no-op — which is why passing `None` (arrival socket unknown) is safe.
fn a_leg_advertised_port(a_leg_local_addr: Option<SocketAddr>, default_via_port: u16) -> u16 {
    a_leg_local_addr
        .map(|addr| addr.port())
        .unwrap_or(default_via_port)
}

/// Sanitize a B2BUA response before forwarding it to the A-leg.
///
/// A proper B2BUA terminates and regenerates the dialog, so B-leg-specific
/// headers must not leak to the A-leg. This function:
/// - Replaces Contact with siphon's own address (critical for dialog routing)
/// - Strips User-Agent (UAC header — not for responses), sets Server
/// - Strips the B-leg's Allow-Events/Supported/Require, and replaces Allow with
///   siphon's own supported methods (a B2BUA is a UA in its own right)
/// - Strips B-leg-specific P-Asserted-Identity, P-Charging-Vector
fn sanitize_b2bua_response(
    response: &mut SipMessage,
    state: &DispatcherState,
    a_leg_transport: Transport,
    a_leg_local_addr: Option<SocketAddr>,
    a_leg_supports_100rel: bool,
    call_id: &str,
) {
    // Contact: must point to siphon so in-dialog requests (ACK, BYE, re-INVITE)
    // route through us, not directly to the B-leg.
    // via_host() applies advertised_address fallback and substitutes the
    // sanitized local_addr when bound to 0.0.0.0/[::] — never leak unspecified.
    // The Contact PORT is the listener the A-leg INVITE actually arrived on
    // (`a_leg_local_addr`), NOT via_port() (the first-configured listener): on a
    // multi-homed host that differs (INVITE to :5066, via_port :5060), and a
    // Contact advertising the wrong port sends every in-dialog request (ACK, BYE,
    // re-INVITE) to a port the dialog isn't anchored on. Falls back to via_port()
    // when the arrival socket is unknown (single-listener hosts, where they match).
    let a_leg_host = state.via_host(&a_leg_transport);
    let a_leg_port =
        a_leg_advertised_port(a_leg_local_addr, state.via_port(&a_leg_transport));
    let contact_value = format!(
        "<sip:{}:{};transport={}>",
        a_leg_host,
        a_leg_port,
        a_leg_transport.to_string().to_lowercase(),
    );
    response.headers.set("Contact", contact_value);

    // Framework-auto strip — `Record-Route` carries the B-leg dialog route
    // set; leaking it to the A-leg breaks RFC 3261 §16 dialog independence
    // and topology hiding (two independent reasons).  No preset can opt in.
    //
    // `Proxy-Authenticate` is hop-by-hop per RFC 3261 §22.3 and every
    // built-in preset strips it (transparent-b2bua@2026 included — an
    // intentional behaviour change vs pre-policy siphon, which passed
    // it through as a latent bug).  Done as a preset strip rather than
    // framework-auto so transparent-proxy B2BUAs can opt back in via
    // `call.dial(copy=["Proxy-Authenticate"])` for the rare case.
    response.headers.remove("Record-Route");

    // Framework-auto strip — never present a `100rel` reliability contract to
    // an A-leg that didn't advertise it.  The B-leg's reliable provisional is
    // PRACKed locally (RFC 3262 auto-PRACK, handle_b2bua_response); leaking
    // `Require: 100rel` / `RSeq` to a non-100rel A-leg (e.g. a plain PSTN
    // trunk) makes it CANCEL the call rather than PRACK.  This is a
    // correctness invariant, not topology hygiene, so it runs preset-independent
    // here rather than as a preset override.  Done before `apply_to_response`:
    // a `Copy`/`Rewrite` preset can't resurrect the removed `RSeq`, and the
    // `Require` edit leaves any surviving option-tags for `Copy` to preserve.
    // A 100rel-capable A-leg (gate true) still gets the reliable provisional
    // end-to-end (RFC 3262 §3).
    crate::sip::headers::rseq::strip_100rel_for_unsupported_peer(
        &mut response.headers,
        a_leg_supports_100rel,
    );

    // Apply per-call header policy.  Resolves to the per-call preset (when
    // the script attached one via `call.dial(header_policy=…)`), otherwise
    // the configured `b2bua.default_header_policy` (defaults to
    // `transparent-b2bua@2026`, which reproduces siphon's pre-policy
    // sanitize_b2bua_response strips — Allow/Allow-Events/Supported/Require/
    // RSeq/Content-Disposition/User-Agent strip + Server rewrite).
    let policy = state.resolve_header_policy(call_id);
    let ctx = crate::b2bua::header_policy::PolicyContext {
        b2bua_host: &a_leg_host,
        b2bua_port: a_leg_port,
        user_agent_header: state.user_agent_header.as_deref(),
        server_header: state.server_header.as_deref(),
    };
    crate::b2bua::header_policy::apply_to_response(response, &policy, &ctx);

    // Advertise siphon's own supported methods. The policy above strips the
    // B-leg's Allow (a B2BUA terminates the dialog, so the B-leg's capabilities
    // are not siphon's to relay); replace it with what siphon actually implements
    // as a UA, so a peer that reads transfer capability from the Allow sees
    // REFER/NOTIFY — Microsoft Teams Direct Routing selects its transfer method
    // this way, and without it never hands siphon a REFER. Gated on absence so a
    // script `call.set_header("Allow", …)` (policy precedence 1) still wins.
    advertise_supported_methods(&mut response.headers);

    // Sanitize SDP: mask B-leg identity in o= and s= lines, and rewrite
    // the o= address to our advertised address for topology hiding.
    sanitize_sdp_identity(&mut response.body, &state.sdp_name, Some(&a_leg_host));

    // Update Content-Length after SDP rewrite (o=/s= changes may alter body size)
    if !response.body.is_empty() {
        response.headers.set("Content-Length", response.body.len().to_string());
    }
}

/// Rewrite `o=` and `s=` lines in an SDP body to hide the remote endpoint's
/// identity.  Replaces the username and IP address in `o=` and the session
/// name in `s=` so that neither leg leaks the other's software name, hostname,
/// or network topology.
///
/// When `addr` is `Some(ip)`, the address field in the `o=` line is also
/// rewritten to `ip` (topology hiding).  When `None`, only the username is
/// replaced (backward-compatible behaviour).
/// Collapse whitespace runs to `-` so a value can be safely placed in the
/// SDP `o=` line's `<username>` field (RFC 4566 §5.2 — no whitespace).
fn sanitize_o_username(name: &str) -> String {
    if !name.contains(|c: char| c.is_whitespace()) {
        return name.to_string();
    }
    let collapsed = name.split_whitespace().collect::<Vec<_>>().join("-");
    if collapsed.is_empty() {
        // Pure-whitespace input — fall back to RFC 4566's "no concept of
        // user IDs" sentinel rather than emitting an empty token.
        "-".to_string()
    } else {
        collapsed
    }
}

fn sanitize_sdp_identity(body: &mut Vec<u8>, name: &str, addr: Option<&str>) {
    if body.is_empty() {
        return;
    }
    let Ok(text) = std::str::from_utf8(body) else {
        return;
    };
    // RFC 4566 §5.2: the `o=` <username> field MUST NOT contain whitespace
    // (the line is space-delimited and parsers tokenise on space). Collapse
    // any whitespace runs in the configured name into `-` for the o= line.
    // The s= session-name field permits whitespace (§5.3), so we leave that
    // path using the raw `name`.
    let o_line_name = sanitize_o_username(name);
    let mut changed = false;
    let mut result = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        if line.starts_with("o=") {
            // o=<username> <sess-id> <sess-version> <nettype> <addrtype> <addr>[\r\n]
            // Replace username, and optionally the trailing address.
            if let Some(rest) = line.strip_prefix("o=") {
                if let Some(space_pos) = rest.find(' ') {
                    let after_username = &rest[space_pos..];
                    // Optionally rewrite the address (last field)
                    if let Some(sdp_addr) = addr {
                        // Find the last space before the trailing \r\n
                        let trimmed = after_username.trim_end_matches(['\r', '\n']);
                        if let Some(last_space) = trimmed.rfind(' ') {
                            let line_ending = &after_username[trimmed.len()..];
                            result.push_str("o=");
                            result.push_str(&o_line_name);
                            result.push_str(&trimmed[..last_space + 1]);
                            result.push_str(sdp_addr);
                            result.push_str(line_ending);
                        } else {
                            result.push_str("o=");
                            result.push_str(&o_line_name);
                            result.push_str(after_username);
                        }
                    } else {
                        result.push_str("o=");
                        result.push_str(&o_line_name);
                        result.push_str(after_username);
                    }
                    changed = true;
                    continue;
                }
            }
            result.push_str(line);
        } else if line.starts_with("s=") {
            // s=<session name> — replace entirely
            if line.ends_with("\r\n") {
                result.push_str("s=");
                result.push_str(name);
                result.push_str("\r\n");
            } else if line.ends_with('\n') {
                result.push_str("s=");
                result.push_str(name);
                result.push('\n');
            } else {
                result.push_str("s=");
                result.push_str(name);
            }
            changed = true;
        } else {
            result.push_str(line);
        }
    }
    if changed {
        *body = result.into_bytes();
    }
}

/// Flip SDP direction attributes for an SRS answer.
///
/// The SRC offers `a=sendonly` (it sends forked media to the SRS).  The SRS
/// answer must mirror this as `a=recvonly` (RFC 3264 §5: answerer reverses
/// the direction).  RTPEngine's `offer` response preserves the offer direction,
/// so we flip it before placing the SDP in the 200 OK.
fn fix_srs_answer_sdp_direction(body: &mut Vec<u8>) {
    let Ok(text) = std::str::from_utf8(body) else {
        return;
    };
    // Quick check: nothing to do if no direction attributes.
    if !text.contains("a=sendonly") && !text.contains("a=recvonly") {
        return;
    }
    let mut result = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed == "a=sendonly" {
            result.push_str("a=recvonly");
            result.push_str(&line[trimmed.len()..]);
        } else if trimmed == "a=recvonly" {
            result.push_str("a=sendonly");
            result.push_str(&line[trimmed.len()..]);
        } else {
            result.push_str(line);
        }
    }
    *body = result.into_bytes();
}

fn build_b2bua_ack_for_non2xx(
    response: &SipMessage,
    branch: &str,
    target_uri: Option<&str>,
    downstream_transport: Transport,
    via_host: &str,
    via_port: u16,
) -> SipMessage {
    let request_uri = target_uri
        .and_then(|uri| parse_uri_standalone(uri).ok())
        .unwrap_or_else(|| SipUri::new("invalid".to_string()));

    let mut builder = SipMessageBuilder::new()
        .request(Method::Ack, request_uri);

    // Via: only our own hop with the client transaction branch.
    //
    // The sent-by host:port MUST equal the top Via of the INVITE this ACK
    // acknowledges (RFC 3261 §17.1.1.3).  The trunk's server transaction keys
    // its ACK match on (branch, sent-by host:port, method) per §17.2.3, so the
    // host:port has to be the *advertised* address the INVITE went out with
    // (state.via_host/via_port) — NOT the raw bind address.  When this used
    // `local_addr`, an ACK with an internal sent-by reached a trunk that had
    // only ever seen the advertised one; the ACK never matched, so the trunk
    // kept retransmitting its 401/4xx on Timer G until the credentialed retry
    // happened to succeed.
    let transport_str = format!("{}", downstream_transport).to_uppercase();
    builder = builder.via(format!(
        "SIP/2.0/{} {}:{};branch={}",
        transport_str, via_host, via_port, branch
    ));

    // From: same as in the response (which echoes the B-leg INVITE's From)
    if let Some(from) = response.headers.from() {
        builder = builder.from(from.clone());
    }

    // To: from the response (includes To-tag from UAS)
    if let Some(to) = response.headers.to() {
        builder = builder.to(to.clone());
    }

    // Call-ID: same as in the response (B-leg Call-ID)
    if let Some(call_id) = response.headers.call_id() {
        builder = builder.call_id(call_id.clone());
    }

    // CSeq: same sequence number, ACK method
    if let Some(cseq) = response.headers.cseq() {
        let cseq_num = cseq.split_whitespace().next().unwrap_or("1");
        builder = builder.cseq(format!("{} ACK", cseq_num));
    }

    builder = builder.header("Max-Forwards", "70".to_string());
    builder = builder.content_length(0);

    match builder.build() {
        Ok(message) => message,
        Err(error) => {
            error!("B2BUA ACK builder failed (this should not happen): {error}");
            SipMessage {
                start_line: StartLine::Request(RequestLine {
                    method: Method::Ack,
                    request_uri: SipUri::new("invalid".to_string()),
                    version: Version::sip_2_0(),
                }),
                headers: SipHeaders::new(),
                body: Vec::new(),
            }
        }
    }
}

/// Send raw bytes to a specific destination via the outbound channel,
/// with automatic HEP capture.  Used for connection-affine sends (CANCELs,
/// in-dialog ACKs, registrant retries) that must reuse a specific connection.
fn send_outbound(
    data: Bytes,
    transport: Transport,
    destination: SocketAddr,
    connection_id: ConnectionId,
    state: &DispatcherState,
) {
    send_outbound_from(data, transport, destination, connection_id, None, state);
}

/// Like [`send_outbound`] but pins the local egress address.  Reply
/// paths set `source_local_addr = Some(inbound.local_addr)` so the
/// response leaves on the same SA's local endpoint that the request
/// arrived on (3GPP TS 33.203 §7.4 — required for IPsec-protected
/// REGISTER cycles).
fn send_outbound_from(
    data: Bytes,
    transport: Transport,
    destination: SocketAddr,
    connection_id: ConnectionId,
    source_local_addr: Option<SocketAddr>,
    state: &DispatcherState,
) {
    // HEP capture — outbound (sent to network)
    if let Some(ref hep) = state.hep_sender {
        let local = source_local_addr
            .or_else(|| state.listen_addrs.get(&transport).copied())
            .unwrap_or(state.local_addr);
        hep.capture_outbound(state.hep_local_addr(local, transport), destination, transport, &data);
    }

    let outbound_message = OutboundMessage {
        connection_id,
        transport,
        destination,
        data,
        source_local_addr,
        server_name: None,
    };

    if let Err(error) = state.outbound.send(outbound_message) {
        error!("failed to enqueue outbound message: {error}");
    }
}

/// Serialize a SIP message and send it to a specific destination, pinning the
/// local egress socket via `source_local_addr`.  Used for reply-direction sends
/// (responses to inbound requests, server-transaction retransmits, and
/// siphon-originated in-dialog requests) so the packet leaves on the same local
/// socket the dialog is anchored on — multi-homed source-port parity, and
/// required by 3GPP TS 33.203 §7.4 for IPsec-protected REGISTER / MO INVITE
/// cycles.  Pass `None` to fall back to the default egress (single-listener
/// hosts / no anchor).
fn send_message_from(
    message: SipMessage,
    transport: Transport,
    destination: SocketAddr,
    connection_id: ConnectionId,
    source_local_addr: Option<SocketAddr>,
    state: &DispatcherState,
) {
    let data = Bytes::from(message.to_bytes());

    debug!(
        destination = %destination,
        size = data.len(),
        "sending message"
    );

    send_outbound_from(data, transport, destination, connection_id, source_local_addr, state);
}

/// Drain deferred messages queued by presence.notify() etc. during the handler
/// and send each one via the UacSender.  Called after the reply/relay has been
/// dispatched so ordering is preserved (RFC 3265 §3.1.6.2).
fn flush_deferred_sends(_state: &DispatcherState) {
    let deferred = crate::script::api::proxy_utils::drain_deferred_sends();
    if deferred.is_empty() {
        return;
    }
    if let Some(uac_sender) = crate::script::api::proxy_utils::uac_sender() {
        for msg in deferred {
            uac_sender.send_request(msg.message, msg.destination, msg.transport);
        }
    } else {
        warn!("deferred sends queued but UAC sender not available");
    }
}

/// Send a SIP message to the B-leg, using the TCP connection pool for TCP/TLS
/// or the direct outbound channel for UDP. This ensures in-dialog messages
/// (ACK, BYE) reach the B-leg over the correct transport.
/// Build a clean in-dialog BYE for a B2BUA leg from stored dialog state.
///
/// A B2BUA generates new requests — it does NOT forward the other leg's BYE.
/// The BYE uses only the target leg's dialog identifiers (Call-ID, From/To
/// tags), route set, Contact, and CSeq. No headers from the originating leg
/// are included.
fn build_b2bua_bye(
    leg: &crate::b2bua::actor::Leg,
    state: &DispatcherState,
) -> Option<SipMessage> {
    let dialog = &leg.dialog;

    // R-URI: remote Contact (RFC 3261 §12.2.1.1)
    let ruri = dialog.remote_contact.as_deref()
        .and_then(|uri_str| parse_uri_standalone(uri_str).ok())
        .unwrap_or_else(|| {
            dialog.target_uri.as_deref()
                .and_then(|uri_str| parse_uri_standalone(uri_str).ok())
                .unwrap_or_else(|| SipUri::new("invalid".to_string()))
        });

    let transport_str = format!("{}", leg.transport.transport).to_uppercase();
    let branch = TransactionKey::generate_branch();
    // Via sent-by port is the listener this leg is anchored on (the A-leg's arrival
    // socket on a multi-homed host) so the response comes back to the socket the
    // request left from. Falls back to via_port for the B-leg (local_addr None) and
    // single-listener hosts — no change there.
    let via = format!(
        "SIP/2.0/{} {}:{};branch={}",
        transport_str,
        state.via_host(&leg.transport.transport),
        a_leg_advertised_port(leg.transport.local_addr, state.via_port(&leg.transport.transport)),
        branch,
    );

    // From/To: use stored URI strings from the dialog-creating INVITE
    // and stitch in the dialog tags via ensure_tag. Tags are stored
    // separately (local_tag / remote_tag) and must be present for the
    // remote endpoint to match BYE to the dialog (RFC 3261 §12.2.1.1).
    let from_header = match &dialog.local_from_uri {
        Some(uri) => crate::b2bua::actor::ensure_tag(uri, Some(&dialog.local_tag)),
        None => format!(
            "<{}>;tag={}",
            dialog.local_contact.as_deref().unwrap_or("sip:invalid"),
            dialog.local_tag,
        ),
    };
    let to_header = match &dialog.remote_to_uri {
        Some(uri) => crate::b2bua::actor::ensure_tag(uri, dialog.remote_tag.as_deref()),
        None => {
            let to_uri = dialog.remote_contact.as_deref()
                .unwrap_or(dialog.target_uri.as_deref().unwrap_or("sip:invalid"));
            match &dialog.remote_tag {
                Some(tag) => format!("<{}>;tag={}", to_uri, tag),
                None => format!("<{}>", to_uri),
            }
        }
    };

    let mut builder = SipMessageBuilder::new()
        .request(Method::Bye, ruri)
        .via(via)
        .from(from_header)
        .to(to_header)
        .call_id(dialog.call_id.clone())
        .cseq(format!("{} BYE", dialog.local_cseq))
        .header("Max-Forwards", "70".to_string());

    // Contact: what we advertised to this leg
    if let Some(ref contact) = dialog.local_contact {
        builder = builder.header("Contact", contact.clone());
    }

    // User-Agent / Server header (topology hiding)
    if let Some(ref ua) = state.user_agent_header {
        builder = builder.header("User-Agent", ua.clone());
    } else if let Some(ref srv) = state.server_header {
        builder = builder.header("User-Agent", srv.clone());
    }

    // Route headers from stored dialog route set (RFC 3261 §12.2.1.1)
    for route in &dialog.route_set {
        builder = builder.header("Route", route.clone());
    }

    match builder.content_length(0).build() {
        Ok(msg) => Some(msg),
        Err(error) => {
            warn!("B2BUA: failed to build BYE: {error}");
            None
        }
    }
}

/// Build an in-dialog PRACK request toward a leg, acknowledging the
/// reliable provisional response identified by `rseq`/`response_cseq_num`.
/// Used by the B2BUA's "auto-PRACK" mode (RFC 3262 §4): when the B-leg
/// sends a 1xx with `Require: 100rel`, siphon answers with a PRACK
/// locally rather than relying on the A-leg (which lives in a different
/// dialog) to do it.
///
/// `local_cseq` MUST already have been incremented for the dialog before
/// calling this — the value passed in is used as-is.
fn build_b2bua_prack(
    leg: &crate::b2bua::actor::Leg,
    state: &DispatcherState,
    rseq: u32,
    response_cseq_num: u32,
    response_cseq_method: &str,
    local_cseq: u32,
) -> Option<SipMessage> {
    let dialog = &leg.dialog;

    let ruri = dialog.remote_contact.as_deref()
        .and_then(|uri_str| parse_uri_standalone(uri_str).ok())
        .unwrap_or_else(|| {
            dialog.target_uri.as_deref()
                .and_then(|uri_str| parse_uri_standalone(uri_str).ok())
                .unwrap_or_else(|| SipUri::new("invalid".to_string()))
        });

    let transport_str = format!("{}", leg.transport.transport).to_uppercase();
    let branch = TransactionKey::generate_branch();
    // Via sent-by port is the listener this leg is anchored on (the A-leg's arrival
    // socket on a multi-homed host) so the response comes back to the socket the
    // request left from. Falls back to via_port for the B-leg (local_addr None) and
    // single-listener hosts — no change there.
    let via = format!(
        "SIP/2.0/{} {}:{};branch={}",
        transport_str,
        state.via_host(&leg.transport.transport),
        a_leg_advertised_port(leg.transport.local_addr, state.via_port(&leg.transport.transport)),
        branch,
    );

    let from_header = match &dialog.local_from_uri {
        Some(uri) => crate::b2bua::actor::ensure_tag(uri, Some(&dialog.local_tag)),
        None => format!(
            "<{}>;tag={}",
            dialog.local_contact.as_deref().unwrap_or("sip:invalid"),
            dialog.local_tag,
        ),
    };
    let to_header = match &dialog.remote_to_uri {
        Some(uri) => crate::b2bua::actor::ensure_tag(uri, dialog.remote_tag.as_deref()),
        None => {
            let to_uri = dialog.remote_contact.as_deref()
                .unwrap_or(dialog.target_uri.as_deref().unwrap_or("sip:invalid"));
            match &dialog.remote_tag {
                Some(tag) => format!("<{}>;tag={}", to_uri, tag),
                None => format!("<{}>", to_uri),
            }
        }
    };

    let mut builder = SipMessageBuilder::new()
        .request(Method::Prack, ruri)
        .via(via)
        .from(from_header)
        .to(to_header)
        .call_id(dialog.call_id.clone())
        .cseq(format!("{} PRACK", local_cseq))
        .header("Max-Forwards", "70".to_string())
        // RFC 3262 §7.2: RAck = "<rseq> <cseq-num> <cseq-method>".
        .header("RAck", format!("{rseq} {response_cseq_num} {response_cseq_method}"));

    if let Some(ref contact) = dialog.local_contact {
        builder = builder.header("Contact", contact.clone());
    }
    for route in &dialog.route_set {
        builder = builder.header("Route", route.clone());
    }

    match builder.content_length(0).build() {
        Ok(message) => Some(message),
        Err(error) => {
            warn!("B2BUA: failed to build PRACK: {error}");
            None
        }
    }
}

fn send_b2bua_to_bleg(
    message: SipMessage,
    transport: Transport,
    destination: SocketAddr,
    state: &DispatcherState,
) {
    let data = Bytes::from(message.to_bytes());
    let target = RelayTarget {
        address: destination,
        transport: Some(transport),
        server_name: None,
    };
    send_to_target(data, &target, transport, ConnectionId::default(), None, state);
}

/// Create Rust-backed auth, registrar, log, and proxy utility singletons
/// and inject them into the Python `siphon` module, replacing the Python stubs.
pub fn inject_python_singletons(config: &Config) {
    let dns_resolver = Arc::new(match SipResolver::from_system() {
        Ok(resolver) => resolver,
        Err(error) => {
            error!("failed to initialize DNS resolver for proxy utils: {error}");
            return;
        }
    });
    // Build Registrar from config
    let registrar_config = RegistrarConfig {
        default_expires: config.registrar.default_expires,
        max_expires: config.registrar.max_expires,
        min_expires: config.registrar.min_expires.unwrap_or(60),
        max_contacts: config.registrar.max_contacts.unwrap_or(10) as usize,
        enforce_auth_aor_match: config.registrar.enforce_auth_aor_match,
    };
    let registrar = Arc::new(Registrar::new(registrar_config));
    let py_registrar = PyRegistrar::new(registrar);

    // Build PyAuth from config
    let mut realm_users = std::collections::HashMap::new();
    realm_users.insert(config.auth.realm.clone(), config.auth.users.clone());
    let mut py_auth = PyAuth::new(realm_users, config.auth.realm.clone());
    py_auth.set_backend_type(config.auth.backend.clone());

    // Digest-nonce anti-replay policy (RFC 7616 §3.3). The shared secret, when
    // set, MUST be identical across instances behind the same SIP domain.
    py_auth.set_nonce_policy(
        config
            .auth
            .nonce_secret
            .as_ref()
            .map(|secret| secret.as_bytes().to_vec()),
        config.auth.nonce_ttl_secs.unwrap_or(0),
    );
    if config.auth.nonce_secret.is_none() {
        tracing::info!(
            "digest nonce: timestamp-only (no auth.nonce_secret set); set a shared \
             secret on all instances to reject foreign nonces"
        );
    }

    // Wire HTTP auth backend if configured
    if let Some(http_config) = &config.auth.http {
        if let Err(error) = py_auth.set_http_config(http_config.clone()) {
            tracing::error!(%error, "failed to configure HTTP auth backend");
        }
        info!(
            url = %http_config.url,
            ha1 = http_config.ha1,
            "HTTP auth backend configured"
        );
    }

    // Wire AKA credentials for local Milenage auth (IMS P-CSCF)
    if !config.auth.aka_credentials.is_empty() {
        py_auth.set_aka_credentials(config.auth.aka_credentials.clone());
        info!(
            count = config.auth.aka_credentials.len(),
            "AKA credentials loaded for local Milenage auth"
        );
    }

    // Log namespace
    let py_log = PyLogNamespace::new();

    // Proxy utilities (rate limiter, sanity check, ENUM lookup, memory stats)
    let py_proxy_utils = crate::script::api::proxy_utils::PyProxyUtils::new(
        dns_resolver,
    );

    // Cache namespace (local LRU + optional Redis)
    let cache_manager = std::sync::Arc::new(crate::cache::CacheManager::new(
        config.cache.as_deref().unwrap_or(&[]),
    ));
    let py_cache = crate::script::api::cache::PyCacheNamespace::new(cache_manager);

    // Store singletons in the global so install_siphon_module() will inject
    // them each time it (re-)creates the module.
    Python::attach(|python| {
        if let Err(error) =
            crate::script::api::set_rust_singletons(python, py_auth, py_registrar, py_log, py_proxy_utils, py_cache)
        {
            error!("failed to store Rust singletons: {error}");
        } else {
            info!("Rust-backed auth, registrar, log, proxy utils, and cache registered for injection");
        }
    });

    // RTPEngine Python singleton is now initialized in init_rtpengine() above.
}

// ---------------------------------------------------------------------------
// Rf offline-charging helpers (3GPP TS 32.299) — proxy auto-emit
// ---------------------------------------------------------------------------

/// Extract the IMS-Charging-Identifier from a SIP message's
/// `P-Charging-Vector` header (RFC 7315 §5.6 / TS 32.260 §5.5).
/// Returns `None` when the header is absent or carries no `icid-value`.
fn rf_extract_icid(message: &SipMessage) -> Option<String> {
    let header = message.headers.get("P-Charging-Vector")?;
    crate::sip::headers::charging::ChargingVector::parse(header).icid
}

/// Extract `(Call-ID, From-tag)` from a SIP message — the inputs to
/// the dialog-fallback storage key.  Returns `None` when either is
/// missing (an in-dialog request without a From-tag would be malformed).
fn rf_extract_dialog_parts(message: &SipMessage) -> Option<(String, String)> {
    let call_id = message.headers.get("Call-ID")?.to_string();
    let from_tag = message
        .typed_from()
        .ok()
        .flatten()
        .and_then(|na| na.tag)?;
    Some((call_id, from_tag))
}

/// Predicate factory: returns `true` when a SIP URI / name-addr value
/// belongs to one of the locally-served domains.  Used by the
/// `ims_data_from_request` builder to decide ORIGINATING vs
/// TERMINATING role when no `P-Served-User` is present.
fn rf_local_uri_predicate(local_domains: &Arc<Vec<String>>) -> impl Fn(&str) -> bool {
    let domains: Vec<String> = local_domains
        .iter()
        .map(|d| d.to_ascii_lowercase())
        .collect();
    move |uri: &str| {
        let lower = uri.to_ascii_lowercase();
        domains.iter().any(|d| lower.contains(d))
    }
}

// ---------------------------------------------------------------------------
// Automatic CDR generation (cdr.auto_emit) — INVITE → answer → BYE.
//
// These mirror the Rf auto-emit hooks and fire from the same lifecycle points,
// but track only the fields a CDR needs (parties, timing, disconnect side) in
// `state.cdr_sessions`. Proxy calls key by the SIP dialog `<Call-ID>\0<tag>`;
// B2BUA calls key by the internal call UUID. All entry points no-op cheaply
// when `cdr.auto_emit` is off (the map stays empty).
// ---------------------------------------------------------------------------

/// Dialog CDR key for a proxy call: `<Call-ID>\0<tag>`.
fn cdr_dialog_key(call_id: &str, tag: &str) -> String {
    format!("{call_id}\0{tag}")
}

/// Raw RFC 3326 `Reason:` header value, if present — carried into the CDR's
/// `sip_reason` field.
fn cdr_extract_reason(message: &SipMessage) -> Option<String> {
    message.headers.get("Reason").map(|r| r.to_string())
}

/// disconnect_initiator for an unanswered/failed call, from the final code.
/// 408 → timeout, 487 (CANCEL) → caller, everything else → callee (the far
/// end returned the error).
fn cdr_disconnect_for_failure(code: u16) -> &'static str {
    match code {
        408 => "timeout",
        487 => "caller",
        _ => "callee",
    }
}

/// Build a `CdrSession` from an INVITE. Returns `None` if the INVITE lacks the
/// Call-ID / From-tag needed to key it.
fn cdr_session_from_invite(
    invite: &SipMessage,
    source_ip: &str,
    transport: &str,
    auth_user: Option<String>,
) -> Option<(String, crate::cdr::CdrSession)> {
    let call_id = invite.headers.get("Call-ID")?.to_string();
    let from_na = invite.typed_from().ok().flatten();
    let from_tag = from_na.as_ref().and_then(|na| na.tag.clone())?;
    let from_uri = from_na.map(|na| na.uri.to_string()).unwrap_or_default();
    let to_uri = invite
        .typed_to()
        .ok()
        .flatten()
        .map(|na| na.uri.to_string())
        .unwrap_or_default();
    let ruri = match &invite.start_line {
        StartLine::Request(request_line) => request_line.request_uri.to_string(),
        _ => String::new(),
    };
    let user_agent = invite.headers.get("User-Agent").map(|s| s.to_string());
    let session = crate::cdr::CdrSession::new(
        call_id.clone(),
        from_uri,
        to_uri,
        ruri,
        source_ip.to_string(),
        transport.to_string(),
        user_agent,
        auth_user,
    );
    Some((cdr_dialog_key(&call_id, &from_tag), session))
}

/// Stamp the answer time on a tracked CDR session. No-op if untracked.
fn cdr_mark_answer(state: &DispatcherState, key: &str, response_code: u16) {
    if let Some(mut session) = state.cdr_sessions.get_mut(key) {
        session.mark_answered(response_code);
    }
}

/// Finalize a tracked CDR session (write the record + drop it). No-op if the
/// call was never tracked (auto-emit off, or not an INVITE dialog).
fn cdr_finalize(
    state: &DispatcherState,
    key: &str,
    disconnect_initiator: &str,
    response_code: Option<u16>,
    sip_reason: Option<String>,
) {
    if let Some((_, session)) = state.cdr_sessions.remove(key) {
        let cdr = session.finalize(disconnect_initiator, response_code, sip_reason);
        crate::cdr::write(cdr);
    }
}

/// Emit a REGISTER CDR for a registrar state change (`cdr.auto_emit` +
/// `cdr.include_register`). A point event — no lifecycle tracking. The registrar
/// event stream carries only the AoR and the change type, so the record keys on
/// those, with the change in the `reg_event` extra field.
fn cdr_emit_register(aor: &str, event_type: &str) {
    let cdr = crate::cdr::Cdr::new(
        String::new(), // no Call-ID in the registrar event stream
        aor.to_string(),
        aor.to_string(),
        aor.to_string(),
        "REGISTER".to_string(),
        String::new(), // source IP not carried by the event
        String::new(), // transport not carried by the event
    )
    .with_response_code(200)
    .with_extra("reg_event".to_string(), event_type.to_string());
    crate::cdr::write(cdr);
}

/// Build a media CDR from a media-engine end-of-call summary.
///
/// A `method="MEDIA"` record keyed on the SIP Call-ID so a collector joins it to
/// the SIP-side CDR (which carries the URIs and disconnect side). The SIP URI /
/// source / transport fields are empty — the media summary carries none; the
/// join key is the Call-ID. `duration_secs` is the media call lifetime, with the
/// exact value also in `media_duration_ms`, and `media_reason` records why the
/// call ended (`"delete"` / `"media_timeout"`).
///
/// Each leg's figures are flattened into `extra`: index 0 → `near_`, index 1 →
/// `far_`, any further leg → `leg{n}_`. Unmeasured optional fields (a plain
/// in-kernel relay leg has no MOS/loss/jitter) are omitted, not emitted empty.
fn media_summary_to_cdr(summary: &crate::rtpengine::events::CallSummary) -> crate::cdr::Cdr {
    let mut cdr = crate::cdr::Cdr::new(
        summary.call_id.clone(),
        String::new(), // from_uri — not carried by the media summary
        String::new(), // to_uri
        String::new(), // ruri
        "MEDIA".to_string(),
        String::new(), // source_ip
        String::new(), // transport
    )
    .with_duration(summary.duration_ms as f64 / 1000.0)
    .with_extra("media_reason".to_string(), summary.reason.clone())
    .with_extra(
        "media_duration_ms".to_string(),
        summary.duration_ms.to_string(),
    );

    for (index, leg) in summary.legs.iter().enumerate() {
        let prefix = match index {
            0 => "near".to_string(),
            1 => "far".to_string(),
            n => format!("leg{n}"),
        };
        let extra = &mut cdr.extra;
        let mut put = |suffix: &str, value: String| {
            extra.insert(format!("{prefix}_{suffix}"), value);
        };
        put("tag", leg.tag.clone());
        if let Some(codec) = &leg.codec {
            put("codec", codec.clone());
        }
        put("packets_in", leg.packets_in.to_string());
        put("bytes_in", leg.bytes_in.to_string());
        put("packets_out", leg.packets_out.to_string());
        put("bytes_out", leg.bytes_out.to_string());
        put("packets_dropped", leg.packets_dropped.to_string());
        if let Some(ssrc) = leg.ssrc {
            put("ssrc", ssrc.to_string());
        }
        if let Some(packets_lost) = leg.packets_lost {
            put("packets_lost", packets_lost.to_string());
        }
        if let Some(loss_percent) = leg.loss_percent {
            put("loss_percent", loss_percent.to_string());
        }
        if let Some(jitter_ms) = leg.jitter_ms {
            put("jitter_ms", jitter_ms.to_string());
        }
        if let Some(rtt_ms) = leg.rtt_ms {
            put("rtt_ms", rtt_ms.to_string());
        }
        if let Some(mos_average) = leg.mos_average {
            put("mos_average", mos_average.to_string());
        }
        if let Some(mos_min) = leg.mos_min {
            put("mos_min", mos_min.to_string());
        }
        if let Some(mos_max) = leg.mos_max {
            put("mos_max", mos_max.to_string());
        }
        if let Some(mos_basis) = &leg.mos_basis {
            put("mos_basis", mos_basis.clone());
        }
    }
    cdr
}

/// Proxy CDR START — the proxy is relaying/forking an INVITE. Records the call
/// so a CDR can be emitted when it ends. Deduped so a retransmitted INVITE
/// doesn't reset the start time.
fn cdr_track_proxy_start(
    state: &DispatcherState,
    invite: &SipMessage,
    source_ip: &str,
    transport: &str,
) {
    if !crate::cdr::auto_emit_enabled() {
        return;
    }
    if let Some((key, session)) = cdr_session_from_invite(invite, source_ip, transport, None) {
        state.cdr_sessions.entry(key).or_insert(session);
    }
}

/// Proxy CDR ANSWER — a 2xx for the INVITE was forwarded upstream.
fn cdr_mark_proxy_answer(state: &DispatcherState, invite: &SipMessage, response_code: u16) {
    if !crate::cdr::auto_emit_enabled() {
        return;
    }
    let (Some(call_id), Some(from_tag)) = (
        invite.headers.get("Call-ID").map(|s| s.to_string()),
        invite.typed_from().ok().flatten().and_then(|na| na.tag),
    ) else {
        return;
    };
    cdr_mark_answer(state, &cdr_dialog_key(&call_id, &from_tag), response_code);
}

/// Proxy CDR STOP — an in-dialog BYE ended the call. Resolves the disconnecting
/// side by which tag the BYE arrived under: the BYE's From-tag matches the
/// INVITE's From-tag when the caller hangs up, else the callee did.
fn cdr_finalize_proxy_stop(state: &DispatcherState, bye: &SipMessage) {
    if !crate::cdr::auto_emit_enabled() {
        return;
    }
    let Some(call_id) = bye.headers.get("Call-ID").map(|s| s.to_string()) else {
        return;
    };
    let from_tag = bye.typed_from().ok().flatten().and_then(|na| na.tag);
    let to_tag = bye.typed_to().ok().flatten().and_then(|na| na.tag);
    let sip_reason = cdr_extract_reason(bye);

    // Caller hung up: BYE From-tag == INVITE From-tag (the stored key).
    if let Some(from_tag) = &from_tag {
        let key = cdr_dialog_key(&call_id, from_tag);
        if state.cdr_sessions.contains_key(&key) {
            cdr_finalize(state, &key, "caller", None, sip_reason);
            return;
        }
    }
    // Callee hung up: BYE To-tag == INVITE From-tag.
    if let Some(to_tag) = &to_tag {
        let key = cdr_dialog_key(&call_id, to_tag);
        if state.cdr_sessions.contains_key(&key) {
            cdr_finalize(state, &key, "callee", None, sip_reason);
        }
    }
}

/// Proxy CDR FAIL — a single-relay INVITE got a final non-2xx (the call
/// failed). Forked failures are finalized at `ForkAction::ForwardBestError`;
/// auth challenges (401/407) are excluded by the caller since the UA re-sends.
fn cdr_finalize_proxy_fail(state: &DispatcherState, invite: &SipMessage, response_code: u16) {
    if !crate::cdr::auto_emit_enabled() {
        return;
    }
    let (Some(call_id), Some(from_tag)) = (
        invite.headers.get("Call-ID").map(|s| s.to_string()),
        invite.typed_from().ok().flatten().and_then(|na| na.tag),
    ) else {
        return;
    };
    cdr_finalize(
        state,
        &cdr_dialog_key(&call_id, &from_tag),
        cdr_disconnect_for_failure(response_code),
        Some(response_code),
        None,
    );
}

/// B2BUA CDR START — a new call actor was created for an INVITE.
fn cdr_track_b2bua_start(
    state: &DispatcherState,
    internal_call_id: &str,
    invite: &SipMessage,
    source_ip: &str,
    transport: &str,
) {
    if !crate::cdr::auto_emit_enabled() {
        return;
    }
    // Reuse the INVITE field extraction, but key by the internal call UUID so
    // both legs (A/B, different Call-IDs) resolve to one CDR.
    if let Some((_, session)) = cdr_session_from_invite(invite, source_ip, transport, None) {
        state
            .cdr_sessions
            .entry(internal_call_id.to_string())
            .or_insert(session);
    }
}

/// B2BUA CDR ANSWER — the call transitioned to Answered (2xx to the INVITE).
fn cdr_mark_b2bua_answer(state: &DispatcherState, internal_call_id: &str, response_code: u16) {
    if !crate::cdr::auto_emit_enabled() {
        return;
    }
    cdr_mark_answer(state, internal_call_id, response_code);
}

/// B2BUA CDR STOP — a BYE tore the call down. `from_a_leg` gives the side.
fn cdr_finalize_b2bua_stop(
    state: &DispatcherState,
    internal_call_id: &str,
    from_a_leg: bool,
    bye: &SipMessage,
) {
    if !crate::cdr::auto_emit_enabled() {
        return;
    }
    let disconnect = if from_a_leg { "caller" } else { "callee" };
    cdr_finalize(
        state,
        internal_call_id,
        disconnect,
        None,
        cdr_extract_reason(bye),
    );
}

/// B2BUA CDR FAIL — the call ended before/without a BYE (B-leg failure,
/// answer-timeout, or caller CANCEL). `response_code` is the final code and
/// selects the disconnect side (see [`cdr_disconnect_for_failure`]).
fn cdr_finalize_b2bua_fail(state: &DispatcherState, internal_call_id: &str, response_code: u16) {
    if !crate::cdr::auto_emit_enabled() {
        return;
    }
    cdr_finalize(
        state,
        internal_call_id,
        cdr_disconnect_for_failure(response_code),
        Some(response_code),
        None,
    );
}

/// Spawn ACR-START for the INVITE that just got a 2xx forwarded by the
/// proxy.  No-op when `rf_charger` is unset, auto-emit is disabled, or
/// the original method wasn't INVITE.
///
/// **Keying (TS 32.260 §5.5):** the resulting `RfChargingSession` is
/// co-stored under both an ICID-keyed primary (when the inbound INVITE
/// carries `P-Charging-Vector`) and a SIP-dialog fallback
/// `<Call-ID>\0<From-tag>`.  iFC re-dispatch through MMTel-AS — which
/// rewrites From-tag but preserves ICID — therefore deduplicates on
/// the ICID key, no longer producing the orphan ACR-STARTs that
/// plagued the From-tag-only keying scheme.
///
/// **Intra-S-CSCF dual-ACR (TS 32.260 §5.1):** when both the calling
/// and called parties are locally-served identities, the S-CSCF emits
/// two independent ACR sequences — one ORIGINATING, one TERMINATING.
/// Each sequence has its own Session-Id and Record-Number, and is
/// stored under its own `:orig` / `:term` keys so the BYE handler can
/// stop both in parallel.
fn spawn_rf_proxy_start_if_invite(
    state: &DispatcherState,
    server_key: &TransactionKey,
    original_request: &SipMessage,
) {
    use crate::diameter::rf_service::{
        rf_icid_key, rf_dialog_key as build_rf_dialog_key, rf_session_storage_keys, RfRole,
    };

    let charger = match state.rf_charger.as_ref() {
        Some(c) if c.auto_emit_proxy() => Arc::clone(c),
        Some(_) => {
            debug!("rf: proxy ACR-START skipped — auto_emit_proxy disabled");
            return;
        }
        None => {
            debug!("rf: proxy ACR-START skipped — rf_charger not configured");
            return;
        }
    };
    if server_key.method != crate::sip::message::Method::Invite {
        debug!(
            method = server_key.method.as_str(),
            "rf: proxy ACR-START skipped — non-INVITE method"
        );
        return;
    }
    let (call_id, from_tag) = match rf_extract_dialog_parts(original_request) {
        Some(parts) => parts,
        None => {
            debug!("rf: proxy ACR-START skipped — INVITE has no Call-ID + From-tag");
            return;
        }
    };
    let icid = rf_extract_icid(original_request);

    // Build the IMS data first so we can key the dedupe by the
    // *actual* role (orig vs term) the request resolves to.  Hard-
    // coding `:orig` here used to silently drop the MT leg of an
    // intra-NF call (same ICID, different roles), because both legs
    // hit the same `:orig` key and the second arrival saw the first
    // already filed — even though the second was a TERMINATING
    // record on a distinct From-URI.
    let local_predicate = rf_local_uri_predicate(&state.local_domains);
    let mut ims_data = crate::diameter::rf_service::ims_data_from_request(
        original_request,
        charger.node_functionality(),
        &local_predicate,
    );
    // Apply any script-supplied charging params (set via
    // `request.set_charging_param("outgoing-trunk-group-id", "...")`).
    // Drained from the side-map keyed by the inbound dialog key so a
    // BGCF script that picked a gateway via gateway.select(...) can
    // stamp the trunk-group-id without writing the whole ACR by hand.
    let drained_params = crate::diameter::rf_service::read_rf_charging_params(
        &format!("{}\0{}", call_id, from_tag),
    );
    crate::diameter::rf_service::apply_charging_params(&mut ims_data, drained_params);

    // Resolve the RfRole from the request's role_of_node — defaults
    // to ORIGINATING when ims_data_from_request couldn't detect.
    let primary_role = match ims_data.role_of_node {
        Some(crate::diameter::ro::NodeRole::TerminatingRole) => RfRole::Terminating,
        _ => RfRole::Originating,
    };
    let primary_key = match icid.as_deref() {
        Some(icid) => rf_icid_key(icid, primary_role),
        None => build_rf_dialog_key(&call_id, &from_tag, primary_role),
    };
    if state.rf_sessions.contains_key(&primary_key) {
        debug!(
            primary_key = %primary_key,
            "rf: proxy ACR-START skipped — record already tracked"
        );
        return;
    }
    debug!(
        primary_key = %primary_key,
        role = primary_role.as_suffix(),
        icid = icid.as_deref().unwrap_or("(none)"),
        "rf: proxy ACR-START spawning"
    );

    // Intra-S-CSCF dual-ACR detection (TS 32.260 §5.1): when this
    // INVITE is itself the originating leg AND the called party is
    // *also* locally served by an S-CSCF, emit a parallel
    // terminating record.  Skipped when the primary role is already
    // TERMINATING (the MT-only leg of an intra-NF call) — that path
    // emits a single record under `:term` and the matching ORIG
    // record arrives separately on the MO leg.
    let term_user_name = if primary_role == RfRole::Originating {
        ims_data
            .called_party
            .as_deref()
            .filter(|uri| local_predicate(uri))
            .filter(|_| {
                charger.node_functionality()
                    == Some(crate::diameter::ro::NodeFunctionality::SCscf)
            })
            .map(str::to_owned)
    } else {
        None
    };

    let primary_user_name = ims_data.calling_party.clone();
    let rf_sessions = Arc::clone(&state.rf_sessions);

    if let Some(term_user) = term_user_name {
        // Dual-ACR (TS 32.260 §5.1): spawn the originating record
        // AND a parallel terminating record.  Each gets its own set
        // of storage keys (ICID + dialog fallback, both with `:term`).
        let term_keys = rf_session_storage_keys(
            icid.as_deref(),
            &call_id,
            &from_tag,
            RfRole::Terminating,
        );
        // TERM-side dedupe: an iFC re-dispatch could land on the
        // same dialog with a different role mapping.  Cheap probe of
        // the first storage key (ICID-keyed when present, else
        // dialog fallback) catches the duplicate before we spawn.
        if let Some(first_term_key) = term_keys.first() {
            if state.rf_sessions.contains_key(first_term_key) {
                debug!(
                    term_key = %first_term_key,
                    "rf: dual-ACR TERM skipped — record already tracked"
                );
                // Fall through to spawn the ORIG record.
                let _ = term_user;
            } else {
                let mut ims_term = ims_data.clone();
                ims_term.role_of_node = Some(crate::diameter::ro::NodeRole::TerminatingRole);
                let charger_term = Arc::clone(&charger);
                let rf_sessions_term = Arc::clone(&rf_sessions);
                let term_user_for_record = term_user.clone();
                let term_keys_for_spawn = term_keys.clone();
                tokio::spawn(async move {
                    let session = match charger_term
                        .acr_start(ims_term.clone(), Some(term_user_for_record.clone()))
                        .await
                    {
                        Some(s) => s,
                        None => return,
                    };
                    let entry = Arc::new(ProxyRfState {
                        session,
                        ims_data: ims_term,
                        user_name: Some(term_user_for_record),
                        storage_keys: term_keys_for_spawn.clone(),
                        created_at: std::time::Instant::now(),
                    });
                    for key in term_keys_for_spawn {
                        rf_sessions_term.insert(key, Arc::clone(&entry));
                    }
                });
            }
        }
    }

    // Primary record — emitted under the role this request resolved
    // to (orig for MO legs / S-CSCF dual-ACR primary; term for the
    // standalone MT leg of an intra-NF call where the same NF sees
    // both legs separately).
    let primary_keys = rf_session_storage_keys(
        icid.as_deref(),
        &call_id,
        &from_tag,
        primary_role,
    );
    let mut ims_primary = ims_data;
    // ims_data_from_request always sets a role, but defend against
    // future refactors that might leave it None.
    if ims_primary.role_of_node.is_none() {
        ims_primary.role_of_node = Some(match primary_role {
            RfRole::Originating => crate::diameter::ro::NodeRole::OriginatingRole,
            RfRole::Terminating => crate::diameter::ro::NodeRole::TerminatingRole,
        });
    }
    tokio::spawn(async move {
        let session = match charger
            .acr_start(ims_primary.clone(), primary_user_name.clone())
            .await
        {
            Some(s) => s,
            None => return,
        };
        let entry = Arc::new(ProxyRfState {
            session,
            ims_data: ims_primary,
            user_name: primary_user_name,
            storage_keys: primary_keys.clone(),
            created_at: std::time::Instant::now(),
        });
        for key in primary_keys {
            rf_sessions.insert(key, Arc::clone(&entry));
        }
    });
}

/// Spawn ACR-STOP for the dialog this BYE belongs to.  No-op when no
/// matching Rf session is tracked.
///
/// **Lookup priority (TS 32.260 §5.5):** ICID key first (preserved
/// across iFC chain when P-CSCF is spec-compliant), falling back to
/// SIP-dialog key with both From-tag and To-tag candidates.
///
/// Also handles intra-S-CSCF dual-ACR (TS 32.260 §5.1): both the
/// ORIGINATING and TERMINATING records are stopped in parallel.
///
/// Entries are removed from `rf_sessions` **after** ACR-STOP completes
/// rather than at BYE arrival.  This keeps the entry visible to
/// `cdr.write()` calls from the script's `@proxy.on_request` handler
/// for the BYE so the CDR can be auto-stamped with `rf_session_id` /
/// `rf_result_code` (see `crate::diameter::rf_service::lookup_rf_for_dialog`).
/// Idempotency is enforced inside [`RfChargingService::acr_stop`] —
/// duplicate BYE retransmits short-circuit without re-emitting on the
/// wire.
fn spawn_rf_proxy_stop_if_tracked(state: &DispatcherState, bye: &SipMessage) {
    use crate::diameter::rf_service::{rf_lookup_candidates, RfRole};

    let charger = match state.rf_charger.as_ref() {
        Some(c) if c.auto_emit_proxy() => Arc::clone(c),
        _ => return,
    };

    let icid = rf_extract_icid(bye);
    let call_id = bye.headers.get("Call-ID").cloned();
    let from_tag = bye
        .typed_from()
        .ok()
        .flatten()
        .and_then(|na| na.tag);
    let to_tag = bye
        .typed_to()
        .ok()
        .flatten()
        .and_then(|na| na.tag);

    let candidates = rf_lookup_candidates(
        icid.as_deref(),
        call_id.as_deref(),
        from_tag.as_deref(),
        to_tag.as_deref(),
    );

    // Find the first storage entry the BYE resolves to, then collect
    // every Rf record reachable from there (orig + term in dual-ACR).
    // Using DashMap::get over the candidate list keeps the hot path
    // bounded — at most 8 hashmap probes for a complete BYE.
    let mut found_orig: Option<Arc<ProxyRfState>> = None;
    let mut found_term: Option<Arc<ProxyRfState>> = None;
    for key in &candidates {
        if let Some(entry) = state.rf_sessions.get(key) {
            let role_suffix = key.rsplit(':').next();
            match role_suffix {
                Some("orig") if found_orig.is_none() => {
                    found_orig = Some(Arc::clone(entry.value()));
                }
                Some("term") if found_term.is_none() => {
                    found_term = Some(Arc::clone(entry.value()));
                }
                _ => {}
            }
            if found_orig.is_some() && found_term.is_some() {
                break;
            }
        }
    }
    if found_orig.is_none() && found_term.is_none() {
        return;
    }

    // Pick up the Reason header if present (RFC 3326) — maps SIP cause
    // through to IMS-Information Cause-Code per TS 32.299 §5.2.5.
    let cause_code = bye
        .headers
        .get("Reason")
        .and_then(|r| {
            // Reason: SIP ;cause=200 ;text="..."
            r.split(';')
                .filter_map(|p| p.trim().strip_prefix("cause="))
                .next()
                .and_then(|v| v.split_whitespace().next())
                .and_then(|v| v.parse::<u16>().ok())
        })
        .and_then(crate::diameter::rf::sip_status_to_cause_code);
    let response_timestamp = std::time::SystemTime::now();

    let stop_one =
        |entry: Arc<ProxyRfState>, charger: Arc<crate::diameter::rf_service::RfChargingService>| {
            let rf_sessions = Arc::clone(&state.rf_sessions);
            tokio::spawn(async move {
                let session = entry.session.clone();
                let mut ims_data = entry.ims_data.clone();
                let user_name = entry.user_name.clone();
                ims_data.sip_method = Some("BYE".to_string());
                ims_data.cause_code = cause_code.or(Some(0));
                ims_data.response_timestamp = Some(response_timestamp);
                charger
                    .acr_stop(
                        &session,
                        ims_data,
                        user_name,
                        crate::diameter::rf::termination_cause::DIAMETER_LOGOUT,
                    )
                    .await;
                // ACR-STOP is committed; the CDR-correlation window is
                // now closed.  Drop every alias under which this
                // record was filed.
                for key in &entry.storage_keys {
                    rf_sessions.remove(key);
                }
            });
        };

    let _ = RfRole::Originating; // enum import kept for symmetry with start side
    if let Some(entry) = found_orig {
        stop_one(entry, Arc::clone(&charger));
    }
    if let Some(entry) = found_term {
        stop_one(entry, charger);
    }
}

/// Spawn ACR-START for a B2BUA call when the A-leg INVITE has been
/// answered.  No-op when `rf_charger` is unset or auto-emit disabled.
/// Stores the resulting [`ProxyRfState`] in `state.rf_sessions` keyed
/// by `b2bua:<internal_call_id>` so the BYE handler can find it.
fn spawn_rf_b2bua_start(
    state: &DispatcherState,
    internal_call_id: &str,
    a_leg_invite: &Arc<std::sync::Mutex<SipMessage>>,
) {
    let charger = match state.rf_charger.as_ref() {
        Some(c) if c.auto_emit_b2bua() => Arc::clone(c),
        Some(_) => {
            debug!(
                call_id = %internal_call_id,
                "rf: B2BUA ACR-START skipped — auto_emit_b2bua disabled"
            );
            return;
        }
        None => {
            debug!(
                call_id = %internal_call_id,
                "rf: B2BUA ACR-START skipped — rf_charger not configured"
            );
            return;
        }
    };
    let key = rf_b2bua_key(internal_call_id);
    if state.rf_sessions.contains_key(&key) {
        debug!(
            call_id = %internal_call_id,
            "rf: B2BUA ACR-START skipped — call already tracked"
        );
        return;
    }
    debug!(
        call_id = %internal_call_id,
        "rf: B2BUA ACR-START spawning"
    );
    // Snapshot the A-leg INVITE under the script-side mutex so we
    // build a stable IMS-Information block even if a script later
    // mutates the message.
    let invite_clone = match a_leg_invite.lock() {
        Ok(guard) => guard.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    };
    let local_predicate = rf_local_uri_predicate(&state.local_domains);
    let mut ims_data = crate::diameter::rf_service::ims_data_from_request(
        &invite_clone,
        charger.node_functionality(),
        local_predicate,
    );
    // Drain any script-supplied charging params keyed by the A-leg
    // dialog (BGCF / MGCF auto-emit stamping trunk-group-id, etc.).
    if let Some((call_id, from_tag)) = rf_extract_dialog_parts(&invite_clone) {
        let drained = crate::diameter::rf_service::read_rf_charging_params(
            &format!("{}\0{}", call_id, from_tag),
        );
        crate::diameter::rf_service::apply_charging_params(&mut ims_data, drained);
    }
    // B2BUA mode → Role-of-Node = B2BUA_ROLE per TS 32.299 §7.2.149,
    // overriding the orig/term derived from local-domain matching.
    // Operators that need orig/term semantics (AS-as-B2BUA) can set
    // node_functionality=as in YAML and we still emit B2BUA_ROLE; if
    // they want the role override they can call
    // diameter.rf_acr_* manually with role_of_node=...
    ims_data.role_of_node = Some(crate::diameter::ro::NodeRole::B2buaRole);
    let user_name = ims_data.calling_party.clone();
    let rf_sessions = Arc::clone(&state.rf_sessions);
    tokio::spawn(async move {
        let session = match charger.acr_start(ims_data.clone(), user_name.clone()).await {
            Some(s) => s,
            None => return,
        };
        rf_sessions.insert(
            key.clone(),
            Arc::new(ProxyRfState {
                session,
                ims_data,
                user_name,
                storage_keys: vec![key],
                created_at: std::time::Instant::now(),
            }),
        );
    });
}

/// Spawn ACR-STOP for a B2BUA call when its BYE arrives.  Picks up an
/// optional RFC 3326 `Reason:` header for IMS Cause-Code mapping.
/// Termination-Cause defaults to `DIAMETER_LOGOUT(1)`.
///
/// Removal from `rf_sessions` is deferred until after ACR-STOP
/// completes so script-driven `cdr.write()` calls still see the
/// rf_session for auto-stamping.  See [`spawn_rf_proxy_stop_if_tracked`]
/// for the full rationale.
/// Derive a Diameter Q.850 cause code from an RFC 3326 `Reason:` header, if
/// present. The `cause=` parameter is interpreted as a SIP status code and
/// mapped via [`crate::diameter::rf::sip_status_to_cause_code`] — the historical
/// B2BUA BYE behaviour, kept identical when [`spawn_rf_b2bua_stop`] moved from
/// taking the BYE message to taking the pre-derived cause.
fn parse_reason_cause(message: &SipMessage) -> Option<i32> {
    message
        .headers
        .get("Reason")
        .and_then(|r| {
            r.split(';')
                .filter_map(|p| p.trim().strip_prefix("cause="))
                .next()
                .and_then(|v| v.split_whitespace().next())
                .and_then(|v| v.parse::<u16>().ok())
        })
        .and_then(crate::diameter::rf::sip_status_to_cause_code)
}

fn spawn_rf_b2bua_stop(
    state: &DispatcherState,
    internal_call_id: &str,
    cause_code: Option<i32>,
) {
    let charger = match state.rf_charger.as_ref() {
        Some(c) if c.auto_emit_b2bua() => Arc::clone(c),
        _ => return,
    };
    let key = rf_b2bua_key(internal_call_id);
    if !state.rf_sessions.contains_key(&key) {
        return;
    }

    let response_timestamp = std::time::SystemTime::now();

    let rf_sessions = Arc::clone(&state.rf_sessions);
    tokio::spawn(async move {
        let snapshot = rf_sessions.get(&key).map(|entry| {
            let v = entry.value();
            (v.session.clone(), v.ims_data.clone(), v.user_name.clone())
        });
        let Some((session, mut ims_data, user_name)) = snapshot else {
            return;
        };
        ims_data.sip_method = Some("BYE".to_string());
        ims_data.cause_code = cause_code.or(Some(0));
        ims_data.response_timestamp = Some(response_timestamp);
        charger
            .acr_stop(
                &session,
                ims_data,
                user_name,
                crate::diameter::rf::termination_cause::DIAMETER_LOGOUT,
            )
            .await;
        rf_sessions.remove(&key);
    });
}

// ---------------------------------------------------------------------------
// Fork helpers
// ---------------------------------------------------------------------------

/// Cancel all fork branches except the winning one.
fn cancel_other_fork_branches(
    winning_key: &TransactionKey,
    server_key: &TransactionKey,
    state: &DispatcherState,
) {
    cancel_fork_branches(server_key, Some(winning_key), state);
}

/// CANCEL the pending downstream branches of a proxy session.
///
/// `exclude` skips one branch — the branch that won (`Some(winning_key)`, used
/// by fork aggregation when a 2xx/6xx settles the fork).  Pass `None` to CANCEL
/// every branch, which is what a reply-time `reply.reject(code, reason)` needs:
/// it aborts the whole in-progress INVITE, including the branch whose
/// provisional triggered the reject.
///
/// RFC 3261 §9.1: each branch's CANCEL MUST carry the same topmost Via branch
/// (and CSeq number) siphon used for that branch's INVITE, so we rebuild the
/// per-branch outbound-INVITE view and run it through `build_cancel_from_invite`.
fn cancel_fork_branches(
    server_key: &TransactionKey,
    exclude: Option<&TransactionKey>,
    state: &DispatcherState,
) {
    let session_arc = match state.session_store.get_by_server_key(server_key) {
        Some(arc) => arc,
        None => return,
    };
    let session = match session_arc.read() {
        Ok(s) => s,
        Err(_) => return,
    };

    for client_key in &session.client_keys {
        if Some(client_key) == exclude {
            continue;
        }
        if let Some(client_branch) = session.get_client_branch(client_key) {
            // RFC 3261 §9.1 — the CANCEL on each branch MUST share the
            // topmost Via branch siphon used when sending the INVITE
            // downstream on that branch (which IS client_key.branch),
            // and the same CSeq sequence number as the INVITE.  Build
            // a synthetic outbound-INVITE view (clone of the inbound
            // request with topmost Via swapped for siphon's per-branch
            // Via), then run it through build_cancel_from_invite which
            // enforces every other RFC-§9.1 invariant (single Via, CSeq
            // method=CANCEL, no body, no body-bearing headers).
            let transport_str = format!("{}", client_branch.transport);
            let siphon_via = format!(
                "SIP/2.0/{} {}:{};branch={}",
                transport_str.to_uppercase(),
                state.via_host(&client_branch.transport),
                state.via_port(&client_branch.transport),
                client_key.branch,
            );
            let mut as_outbound_invite = session.original_request.clone();
            as_outbound_invite.headers.set("Via", siphon_via);
            let cancel = match build_cancel_from_invite(&as_outbound_invite) {
                Some(c) => c,
                None => {
                    warn!(
                        client_key = %client_key,
                        "fork: failed to build CANCEL from outbound INVITE view"
                    );
                    continue;
                }
            };

            let data = Bytes::from(cancel.to_bytes());

            debug!(
                client_key = %client_key,
                destination = %client_branch.destination,
                "fork: cancelling branch"
            );

            send_outbound(data, client_branch.transport, client_branch.destination, client_branch.connection_id, state);
        }
    }
}

/// Fail an in-progress proxied INVITE from the reply context.
///
/// Driven by `reply.reject(code, reason)` in a `@proxy.on_reply` handler (the
/// IMS P-CSCF media-authorization reject — N5/Rx fails at answer time, so the
/// leg must be rejected with a SIP error rather than proceed medialess).
///
/// Two halves, in order:
/// 1. Mark the session finalized *first* so any branch response that races in
///    (the `487` the CANCEL draws back, or a late provisional) is absorbed by
///    the straggler guard in `handle_response` rather than forwarded upstream.
/// 2. CANCEL every pending downstream branch (RFC 3261 §9 — we have received a
///    provisional, so CANCEL is well-formed), then send `code reason` upstream
///    to the UAC through the server transaction so retransmission and ACK
///    absorption are handled by the transaction layer.
///
/// The session is deliberately left in the store: the in-flight `487`(s) from
/// the CANCEL still need to resolve to it (to be ACKed downstream and absorbed).
/// Per-branch final cleanup (`remove_client_key`) and the session TTL sweep
/// tear it down afterwards.
fn reject_pending_invite(
    server_key: &TransactionKey,
    session_arc: &Arc<RwLock<ProxySession>>,
    code: u16,
    reason: &str,
    original_request: &SipMessage,
    transport: crate::transport::Transport,
    source_addr: SocketAddr,
    connection_id: ConnectionId,
    inbound_local_addr: SocketAddr,
    state: &DispatcherState,
) {
    // 1. Latch the finalized flag before anything goes on the wire.
    match session_arc.write() {
        Ok(mut session) => session.final_response_sent = true,
        Err(error) => {
            error!("proxy session lock poisoned during reject: {error}");
            return;
        }
    }

    // Hygiene: a rejected INVITE establishes no dialog, so its `by_dialog_key`
    // entry (which exists only to route the end-to-end 2xx ACK) is now dead.
    // Drop it so a stray/non-compliant ACK can't match this rejected call's
    // dialog and reach the ACK relay path.  The client-key indices stay intact
    // so the CANCEL's `487` straggler is still matched and absorbed.
    state.session_store.remove_dialog_key(original_request);

    info!(
        server_key = %server_key,
        code = code,
        "reply-time reject: failing in-progress INVITE and cancelling downstream"
    );

    // 2a. CANCEL all pending downstream branches (no winner to exclude).
    cancel_fork_branches(server_key, None, state);

    // 2b. Build and send the error response upstream via the server
    // transaction (handles retransmission + UAC-ACK absorption for INVITE).
    let response = build_response(
        original_request,
        code,
        reason,
        state.server_header.as_deref(),
        &[],
    );

    let event = ServerEvent::Ist(IstEvent::TuNon2xxFinal(response.clone()));
    let mut sent_by_transaction = false;
    if let Ok(actions) = state.transaction_manager.process_server_event(server_key, event) {
        sent_by_transaction = actions.iter().any(|a| matches!(a, Action::SendMessage(_)));
        process_timer_actions(
            &actions,
            server_key,
            Some(source_addr),
            Some(transport),
            Some(connection_id),
            Some(inbound_local_addr),
            state,
        );
    }

    if !sent_by_transaction {
        // No live server transaction (or it emitted no SendMessage) — send the
        // error directly, pinning the inbound listener's local address so an
        // IPsec-protected response egresses on the right SA (TS 33.203 §7.4).
        send_message_from(response, transport, source_addr, connection_id, Some(inbound_local_addr), state);
    }
}

/// Start the next branch in a sequential fork.
fn start_next_fork_branch(
    next_index: usize,
    session_arc: &Arc<RwLock<ProxySession>>,
    server_key: &TransactionKey,
    state: &DispatcherState,
) {
    let (original_request, record_routed, source_addr, connection_id, transport, agg, branch_flow, send_socket) = {
        let session = match session_arc.read() {
            Ok(s) => s,
            Err(_) => return,
        };
        (
            session.original_request.clone(),
            session.record_routed,
            session.source_addr,
            session.connection_id,
            session.transport,
            session.fork_aggregator.clone(),
            session.fork_flows.get(next_index).cloned().flatten(),
            session.fork_send_socket.clone(),
        )
    };

    let agg = match agg {
        Some(a) => a,
        None => return,
    };

    let target = {
        let agg_lock = match agg.lock() {
            Ok(a) => a,
            Err(_) => return,
        };
        agg_lock.branches.get(next_index).map(|b| b.target.to_string())
    };

    if let Some(target_str) = target {
        let inbound_info = InboundMessage {
            remote_addr: source_addr,
            local_addr: state.local_addr,
            connection_id,
            transport,
            data: Bytes::new(),
        };
        relay_fork_branch(
            &original_request,
            &target_str,
            next_index,
            record_routed,
            &inbound_info,
            server_key,
            session_arc,
            &agg,
            branch_flow.as_ref(),
            send_socket.as_ref(),
            state,
        );
    }
}

/// Map a SIP error code to a reason phrase.
fn best_error_reason(code: u16) -> &'static str {
    match code {
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        408 => "Request Timeout",
        480 => "Temporarily Unavailable",
        486 => "Busy Here",
        487 => "Request Terminated",
        488 => "Not Acceptable Here",
        500 => "Server Internal Error",
        503 => "Service Unavailable",
        600 => "Busy Everywhere",
        603 => "Decline",
        _ => "Error",
    }
}

// ---------------------------------------------------------------------------
// CANCEL handling
// ---------------------------------------------------------------------------

/// Handle an inbound CANCEL request (RFC 3261 §9.2).
///
/// CANCEL shares the same Via branch as the INVITE it cancels.
/// We look up the original INVITE's relay destination and forward CANCEL there.
fn handle_cancel(
    inbound: InboundMessage,
    message: SipMessage,
    uac_branch: Option<&str>,
    uac_sent_by: &str,
    state: &DispatcherState,
) {
    let uac_branch = match uac_branch {
        Some(branch) => branch,
        None => {
            warn!("CANCEL without Via branch — dropping");
            return;
        }
    };

    // Check if this CANCEL belongs to a B2BUA call
    let engine_state = state.engine.state();
    if engine_state.has_b2bua_handlers() {
        let sip_call_id = message.headers.get("Call-ID").map(|s| s.to_string());
        if let Some(ref sip_call_id) = sip_call_id {
            if state.call_actors.find_by_sip_call_id(sip_call_id).is_some() {
                drop(engine_state);
                handle_b2bua_cancel(inbound, message, state);
                return;
            }
        }
    }
    drop(engine_state);

    // --- Try ProxySession-based CANCEL routing first ---
    // CANCEL shares the same Via branch as the INVITE it cancels.
    // Build the server key for the original INVITE transaction.
    let invite_server_key = TransactionKey::new(uac_branch.to_string(), crate::sip::message::Method::Invite, uac_sent_by.to_string());
    if let Some(session_arc) = state.session_store.get_by_server_key(&invite_server_key) {
        handle_cancel_via_session(inbound, message, &invite_server_key, session_arc, state);
        return;
    }

    // No matching session or B2BUA call
    debug!(uac_branch = %uac_branch, "CANCEL for unknown transaction");
    let response = build_response(&message, 481, "Call/Transaction Does Not Exist", state.server_header.as_deref(), &[]);
    send_message_from(response, inbound.transport, inbound.remote_addr, inbound.connection_id, Some(inbound.local_addr), state);
}

// ---------------------------------------------------------------------------
// ProxySession-based ACK (2xx) handling
// ---------------------------------------------------------------------------

/// Determine the next-hop URI for an end-to-end 2xx ACK after the proxy has
/// popped its own Route (RFC 3261 §16.12): the top remaining Route URI, or the
/// Request-URI when the route set is empty.
///
/// This is what makes the ACK follow the dialog route set rather than the
/// cached INVITE forward path. Returns `None` only for a non-request message
/// (an ACK is always a request, so this is a defensive guard).
fn ack_next_hop_uri(headers: &SipHeaders, start_line: &StartLine) -> Option<String> {
    core::next_hop_from_route(headers).or_else(|| match start_line {
        StartLine::Request(request_line) => Some(request_line.request_uri.to_string()),
        _ => None,
    })
}

/// Handle ACK for 2xx responses by relaying it downstream via the ProxySession.
///
/// ACK for 2xx is end-to-end (RFC 3261 §13.2.2.4): the proxy must relay it
/// downstream to the UAS. Unlike ACK for non-2xx (which is hop-by-hop and
/// absorbed by the transaction layer), this ACK has a new Via branch and must
/// be matched by Call-ID.
fn handle_ack_via_session(
    _inbound: InboundMessage,
    message: SipMessage,
    session_arc: Arc<RwLock<ProxySession>>,
    state: &DispatcherState,
) {
    let session = match session_arc.read() {
        Ok(s) => s,
        Err(_) => {
            error!("ProxySession lock poisoned during ACK handling");
            return;
        }
    };

    // Forward ACK to each client branch (typically just one for a completed call)
    for client_key in &session.client_keys {
        if let Some(client_branch) = session.get_client_branch(client_key) {
            let mut ack_downstream = message.clone();

            // Consume our own Route entries (loose routing — RFC 3261 §16.4 /
            // §16.12), mirroring the script-side loose_route() that the
            // in-dialog BYE/UPDATE path uses. Pop the top Route, then any
            // additional Routes that also point to us — a doubly-Record-Routed
            // dialog (transport bridging, e.g. an IMS P-CSCF/S-CSCF spanning
            // UDP and TCP) leaves two consecutive self-Routes, and consuming
            // only the top would leave our own second Route as the apparent
            // next hop (a routing loop). `pop_local_routes` matches the same
            // `local_domains` loose_route() does, so the ACK consumes exactly
            // the self-Routes the BYE on this dialog already consumes.
            if core::check_loose_route(&ack_downstream.headers) {
                core::pop_top_route(&mut ack_downstream.headers);
                if !state.local_domains.is_empty() {
                    core::pop_local_routes(&mut ack_downstream.headers, &state.local_domains);
                }
            }

            // The 2xx ACK is end-to-end (RFC 3261 §13.2.2.4 / §17.1.1.3): it is
            // a new request routed by the *dialog route set*, NOT retraced along
            // the INVITE's forward path. After popping our own Route, the next
            // hop is the top remaining Route URI, or the Request-URI when the
            // route set is empty (RFC 3261 §16.12). For an INVITE forwarded
            // through a hop that did not Record-Route (a transparent iFC AS, an
            // IMS I-CSCF), the cached branch destination and the dialog route set
            // diverge; sending to the cached destination retraces the INVITE
            // path and the ACK never reaches the UAS. This is the proxy-mode
            // sibling of the B2BUA in-dialog route-set fix.
            //
            // `resolve_in_dialog_flow_uri` keeps the established connection
            // (RFC 5923) whenever the route-set next hop still resolves to the
            // member the INVITE was relayed to (`client_branch`): re-resolving a
            // load-balanced trunk domain would, since the RFC 3263 §4.2 shuffle,
            // pick a sibling member at random and `send_to_target` would then ACK
            // the wrong node (or reuse an unrelated keepalive connection to it).
            // It falls back to the cached branch on resolution failure, so
            // non-routed dialogs (loopback baseline) are unaffected.
            let next_hop_uri =
                ack_next_hop_uri(&ack_downstream.headers, &ack_downstream.start_line);
            let (destination, out_transport, ack_connection_id) = resolve_in_dialog_flow_uri(
                next_hop_uri.as_deref(),
                &state.dns_resolver,
                client_branch.destination,
                client_branch.transport,
                client_branch.connection_id,
            );

            // Loop guard (RFC 3261 §16.3): never forward an ACK back to one of
            // our own listen addresses.  A stray/misrouted 2xx ACK whose route
            // set or R-URI resolves to us (e.g. a non-compliant UAC ACKing a
            // final whose R-URI is the proxy, matched here by `by_dialog_key`)
            // would otherwise be re-received and re-relayed, stacking a Via each
            // hop until the datagram exceeds the UDP recv buffer and is dropped
            // on a parse error.  ACK gets no response (RFC 3261 §17.1.1.3), so
            // drop silently — mirroring the relay-path guard in `relay_request`.
            if state.is_own_address(&destination) {
                debug!(
                    client_key = %client_key,
                    %destination,
                    "ACK to self via dialog route set — dropping (loop guard)"
                );
                continue;
            }

            // Add our Via on top (preserving existing Vias), reflecting the
            // transport we will actually send over.
            let transport_str = format!("{out_transport}");
            core::add_via(
                &mut ack_downstream.headers,
                &transport_str,
                &state.via_host(&out_transport),
                Some(state.via_port(&out_transport)),
            );

            let data = Bytes::from(ack_downstream.to_bytes());
            debug!(
                client_key = %client_key,
                %destination,
                transport = %out_transport,
                "relaying ACK for 2xx downstream via dialog route set"
            );

            // Send to the resolved dialog next hop. `send_to_target` picks the
            // right connection per transport (TCP/TLS pool, UDP outbound + IPsec
            // source), using the established connection as the UDP fallback.
            let target = RelayTarget {
                address: destination,
                transport: Some(out_transport),
                server_name: None,
            };
            send_to_target(
                data,
                &target,
                client_branch.transport,
                ack_connection_id,
                None,
                state,
            );
        }
    }
}

// ---------------------------------------------------------------------------
// ProxySession-based CANCEL handling
// ---------------------------------------------------------------------------

/// Build the topmost `Via` value for a CANCEL forwarded on a proxy client
/// branch.
///
/// RFC 3261 §9.1 makes CANCEL the one request that MUST share the topmost
/// `Via` branch of the request it cancels; §16.10 has a stateful proxy
/// generate, for each pending branch, a CANCEL whose single `Via` equals the
/// top `Via` of the INVITE it forwarded on that branch.  The downstream
/// UAS/proxy matches CANCEL→INVITE on that branch + sent-by (RFC 3261 §9.2 /
/// §17.2.3) to find the in-progress INVITE server transaction.
///
/// The proxy's client transaction key already holds exactly the branch and
/// sent-by siphon stamped on that INVITE's topmost `Via` (see
/// [`TransactionManager::key_from_message`]), so we reuse them verbatim —
/// reusing `sent_by` also keeps the CANCEL aligned with the INVITE in the
/// IPsec / flow / `force_send_via` cases where the advertised sent-by differs
/// from the default per-transport `via_host`.  Minting a fresh branch here
/// (as siphon did before) makes the forwarded CANCEL unmatchable downstream:
/// it is dropped, the INVITE leg below is never torn down, and the callee
/// keeps ringing after the caller abandons during alerting.
fn cancel_via_for_client_branch(client_key: &TransactionKey, transport: Transport) -> String {
    format!(
        "SIP/2.0/{} {};branch={}",
        format!("{transport}").to_uppercase(),
        client_key.sent_by,
        client_key.branch,
    )
}

/// Handle CANCEL using ProxySession — forwards CANCEL to all client branches
/// and sends 487 Request Terminated upstream.
fn handle_cancel_via_session(
    inbound: InboundMessage,
    message: SipMessage,
    invite_server_key: &TransactionKey,
    session_arc: Arc<RwLock<ProxySession>>,
    state: &DispatcherState,
) {
    let session = match session_arc.read() {
        Ok(s) => s,
        Err(_) => {
            error!("ProxySession lock poisoned during CANCEL handling");
            let response = build_response(&message, 500, "Internal Server Error", state.server_header.as_deref(), &[]);
            send_message_from(response, inbound.transport, inbound.remote_addr, inbound.connection_id, Some(inbound.local_addr), state);
            return;
        }
    };

    // Send 200 OK to CANCEL (RFC 3261 §9.2: always 200) on the arrival socket —
    // the 487 below already pins `session.inbound_local_addr`; keep the 200 on the
    // same listener so a multi-homed UDP host answers both from one source port.
    let cancel_response = build_response(&message, 200, "OK", state.server_header.as_deref(), &[]);
    send_message_from(
        cancel_response,
        inbound.transport,
        inbound.remote_addr,
        inbound.connection_id,
        Some(inbound.local_addr),
        state,
    );

    // Forward CANCEL to each client branch
    for client_key in &session.client_keys {
        if let Some(client_branch) = session.get_client_branch(client_key) {
            let mut cancel_downstream = message.clone();
            // RFC 3261 §9.1 / §16.10: the forwarded CANCEL MUST carry the SAME
            // topmost Via branch (and sent-by) as the INVITE siphon sent on
            // this branch, so the downstream matches CANCEL→INVITE (RFC 3261
            // §9.2 / §17.2.3) and tears the alerting branch down.  Minting a
            // fresh branch makes the CANCEL unmatchable: it's dropped, the
            // INVITE leg below is never cancelled, and the callee keeps
            // ringing after the caller abandons.  `headers.set` collapses the
            // inbound CANCEL's Via stack to this single Via (§9.1 — a proxy
            // CANCEL carries exactly one Via).
            let via_value = cancel_via_for_client_branch(client_key, client_branch.transport);
            cancel_downstream.headers.set("Via", via_value);

            let data = Bytes::from(cancel_downstream.to_bytes());

            debug!(
                client_key = %client_key,
                destination = %client_branch.destination,
                "forwarding CANCEL downstream via session"
            );

            send_outbound(data, client_branch.transport, client_branch.destination, client_branch.connection_id, state);
        }
    }

    // Send 487 Request Terminated upstream using the original INVITE from the session
    let response_487 = build_response(
        &session.original_request,
        487,
        "Request Terminated",
        state.server_header.as_deref(),
        &[],
    );
    send_message_from(
        response_487,
        session.transport,
        session.source_addr,
        session.connection_id,
        Some(session.inbound_local_addr),
        state,
    );

    // Fire @proxy.on_cancel before the session is evicted so scripts can
    // release per-call resources (Diameter Rx/N5 QoS, rtpengine media) that
    // no BYE will ever clear — the only teardown signal for a
    // CANCELled-before-answer INVITE (RFC 3261 §9). Guard the clone: the
    // common no-handler path stays allocation-free.
    let server_key = invite_server_key.clone();
    let has_cancel_handlers = !state
        .engine
        .state()
        .handlers_for(&HandlerKind::ProxyCancel)
        .is_empty();
    if has_cancel_handlers {
        let cancel_request = session.original_request.clone();
        let cancel_transport = session.transport;
        let cancel_source_addr = session.source_addr;
        let cancel_inbound_local_addr = session.inbound_local_addr;
        let cancel_connection_id = session.connection_id;
        drop(session);
        run_proxy_cancel_handlers(
            cancel_request,
            cancel_transport,
            cancel_source_addr,
            cancel_inbound_local_addr,
            cancel_connection_id,
            state,
        );
    } else {
        drop(session);
    }

    state.session_store.remove_by_server_key(&server_key);
}

// ---------------------------------------------------------------------------
// B2BUA CANCEL handling
// ---------------------------------------------------------------------------

/// Build a CANCEL for an outbound INVITE per RFC 3261 §9.1.
///
/// The CANCEL MUST share the topmost Via branch and CSeq sequence number
/// of the request being cancelled — that is the contract that lets the
/// downstream UAS (and every proxy on the path) match the CANCEL to the
/// in-progress server transaction of the INVITE.  Building a CANCEL with
/// a fresh branch, or with the wrong CSeq number, makes every proxy hop
/// return 481 Call/Transaction Does Not Exist and the UAS keeps ringing.
///
/// The caller passes the outbound INVITE as siphon put it on the wire —
/// for B2BUA that's [Leg::b_leg_invite]; for proxy fork it's a clone of
/// the inbound request with the topmost Via swapped for siphon's
/// per-branch Via.
///
/// Other headers (From, To, Call-ID, R-URI, Max-Forwards, Route) are
/// preserved verbatim from the INVITE.  Content-Length is forced to 0;
/// the body is dropped.  Everything else (Contact, Allow, Supported,
/// PAI, Session-Expires, SDP, …) is stripped — CANCEL is hop-by-hop and
/// carries no payload.
fn build_cancel_from_invite(invite: &SipMessage) -> Option<SipMessage> {
    // Method swap: INVITE → CANCEL on the request line.
    let mut cancel = invite.clone();
    let request_uri = match &mut cancel.start_line {
        StartLine::Request(rl) => {
            rl.method = crate::sip::message::Method::Cancel;
            rl.request_uri.clone()
        }
        StartLine::Response(_) => return None,
    };
    let _ = request_uri; // touched only to enforce the variant guard above

    // CSeq: keep the INVITE's sequence number, swap the method to CANCEL
    // (RFC 3261 §9.1 — "MUST contain the same value for the sequence
    //  number as was present in the request being cancelled, but the
    //  method parameter MUST be equal to CANCEL").
    let cseq_seq = invite
        .headers
        .cseq()?
        .split_whitespace()
        .next()?
        .to_string();
    cancel.headers.set("CSeq", format!("{} CANCEL", cseq_seq));

    // Topmost Via only.  The stashed B-leg INVITE has exactly one Via
    // (siphon overwrites Via on B-leg INVITE build), so set_all with a
    // single value is fine — but be defensive in case the assumption
    // ever drifts.
    if let Some(vias) = invite.headers.get_all("Via") {
        if let Some(top) = vias.first() {
            cancel.headers.set("Via", top.clone());
        }
    }

    // Drop the payload — CANCEL never carries a body.
    cancel.body.clear();
    cancel.headers.set("Content-Length", "0".to_string());

    // Strip headers that have no place on a CANCEL.  We keep:
    //   Via (topmost only — set above)
    //   From, To, Call-ID, CSeq, Max-Forwards, Route
    //   Content-Length
    // Everything else is dropped per RFC 3261 §9.1 + §20 (CANCEL is
    // hop-by-hop, carries no offer/answer, no dialog-establishing data).
    const KEEP: &[&str] = &[
        "via", "from", "to", "call-id", "cseq",
        "max-forwards", "route", "content-length",
    ];
    let to_remove: Vec<String> = cancel
        .headers
        .iter()
        .map(|(name, _)| name.clone())
        .filter(|n| !KEEP.contains(&n.as_str()))
        .collect();
    for name in to_remove {
        cancel.headers.remove(&name);
    }

    Some(cancel)
}

/// Handle CANCEL for a B2BUA call — cancel all pending B-legs.
fn handle_b2bua_cancel(
    inbound: InboundMessage,
    message: SipMessage,
    state: &DispatcherState,
) {
    let sip_call_id = message.headers.get("Call-ID")
        .map(|s| s.to_string())
        .unwrap_or_default();

    let call_id = match state.call_actors.find_by_sip_call_id(&sip_call_id) {
        Some(id) => id,
        None => {
            warn!(sip_call_id = %sip_call_id, "B2BUA CANCEL: no matching call");
            let response = build_response(&message, 481, "Call/Transaction Does Not Exist", state.server_header.as_deref(), &[]);
            send_message_from(response, inbound.transport, inbound.remote_addr, inbound.connection_id, Some(inbound.local_addr), state);
            return;
        }
    };

    // We need a mutable handle: per-leg we either (a) send the CANCEL
    // immediately from the stashed B-leg INVITE, or (b) flag the leg
    // with pending_cancel=true so the CANCEL is emitted the moment
    // b2bua_send_b_leg_invite finishes stashing the INVITE (race
    // between the upstream CANCEL and the script's call.dial() actually
    // putting the B-leg INVITE on the wire).
    let mut call = match state.call_actors.get_call_mut(&call_id) {
        Some(c) => c,
        None => return,
    };

    // Only cancel if call is still in Calling or Ringing state
    if call.state != CallState::Calling && call.state != CallState::Ringing {
        debug!(call_id = %call_id, state = ?call.state, "B2BUA CANCEL: call already answered/terminated");
        let response = build_response(&message, 200, "OK", state.server_header.as_deref(), &[]);
        send_message_from(response, inbound.transport, inbound.remote_addr, inbound.connection_id, Some(inbound.local_addr), state);
        drop(call);
        return;
    }

    // Send 200 OK to CANCEL (on the socket the CANCEL arrived on — the same
    // listener the INVITE landed on, per RFC 3261 §9: the caller sends CANCEL to
    // the INVITE's next hop). Pins the source port for multi-homed UDP.
    let cancel_response = build_response(&message, 200, "OK", state.server_header.as_deref(), &[]);
    send_message_from(
        cancel_response,
        inbound.transport,
        inbound.remote_addr,
        inbound.connection_id,
        Some(inbound.local_addr),
        state,
    );

    // Send CANCEL to all pending B-legs.
    //
    // RFC 3261 §9.1 — the CANCEL on each B-leg MUST share the *B-leg
    // INVITE*'s topmost Via branch and CSeq sequence number, NOT the
    // inbound A-leg CANCEL's.  Rebuild from the stashed B-leg INVITE
    // ([Leg::b_leg_invite], populated at the end of
    // [b2bua_send_b_leg_invite]).  Legs whose INVITE hasn't been sent
    // yet get marked pending_cancel; the CANCEL drains automatically
    // once the stash lands.
    let mut bleg_targets: Vec<(SipMessage, Transport, SocketAddr)> = Vec::new();
    for b_leg in call.b_legs.iter_mut() {
        match b_leg.b_leg_invite.as_ref() {
            Some(invite_arc) => {
                let invite = match invite_arc.lock() {
                    Ok(guard) => guard.clone(),
                    Err(_) => {
                        warn!(call_id = %call_id, "B2BUA CANCEL: b_leg_invite mutex poisoned, skipping leg");
                        continue;
                    }
                };
                match build_cancel_from_invite(&invite) {
                    Some(cancel_msg) => {
                        bleg_targets.push((
                            cancel_msg,
                            b_leg.transport.transport,
                            b_leg.transport.remote_addr,
                        ));
                    }
                    None => {
                        warn!(call_id = %call_id, "B2BUA CANCEL: failed to build CANCEL from stashed INVITE");
                    }
                }
            }
            None => {
                // Race: CANCEL arrived before this B-leg's INVITE was
                // actually sent.  Defer — b2bua_send_b_leg_invite drains
                // pending_cancel after stashing b_leg_invite.
                debug!(
                    call_id = %call_id,
                    leg_id = %b_leg.id,
                    "B2BUA CANCEL: deferred (b_leg_invite not yet stashed)"
                );
                b_leg.pending_cancel = true;
            }
        }
    }

    // Send Cancel to all B-leg actor handles
    for handle in call.b_leg_handles.iter().flatten() {
        let _ = handle.tx.try_send(crate::b2bua::actor::LegMessage::Cancel);
    }

    // Send 487 Request Terminated to A-leg for the original INVITE.
    // Capture the stored A-leg INVITE + source before dropping the call ref so
    // @b2bua.on_cancel can run after the lock is released (no DashMap reentry).
    let a_leg = call.a_leg.clone();
    let cancel_a_leg_invite = call.a_leg_invite.clone();
    let cancel_a_leg_source_ip = call.a_leg.transport.remote_addr.ip().to_string();
    let cancel_a_leg_transport = format!("{}", call.a_leg.transport.transport).to_lowercase();
    drop(call);

    // Emit the prepared CANCELs after dropping the call lock so the
    // outbound path doesn't reenter the DashMap.
    for (cancel_msg, b_transport, b_dest) in bleg_targets {
        send_b2bua_to_bleg(cancel_msg, b_transport, b_dest, state);
    }

    // The 487 to the A-leg leaves on the socket the CANCEL (== the INVITE) arrived
    // on, so a multi-homed UDP host answers with a consistent source port.
    let response_487 = build_response(&message, 487, "Request Terminated", state.server_header.as_deref(), &[]);
    send_message_from(
        response_487,
        a_leg.transport.transport,
        a_leg.transport.remote_addr,
        a_leg.transport.connection_id,
        Some(inbound.local_addr),
        state,
    );

    // Fire @b2bua.on_cancel before tearing the call out of the registry so a
    // script can release per-call resources (rtpengine media, QoS) that no BYE
    // will ever clear — the only teardown signal for a cancelled-before-answer
    // B2BUA call (RFC 3261 §9). A 2xx that races this CANCEL is independently
    // ACK+BYE'd by handle_zombie_cancelled_2xx and never delivered on_answer,
    // so this only ever fires for a genuinely abandoned call.
    run_b2bua_cancel_handlers(
        &call_id,
        cancel_a_leg_invite,
        cancel_a_leg_source_ip,
        cancel_a_leg_transport,
        state,
    );

    // CDR: the caller CANCELled before answer (cdr.auto_emit) → 487.
    cdr_finalize_b2bua_fail(state, &call_id, 487);

    state.call_actors.set_state(&call_id, CallState::Terminated);
    // remove_call_after_cancel sends Shutdown to remaining actors, cleans the
    // registry, and preserves still-pending B-legs as zombie-cancelled entries
    // so a 2xx that raced this CANCEL (RFC 3261 §9.1) can still be ACKed + BYEd
    // by handle_response → handle_zombie_cancelled_2xx instead of being dropped
    // as an unknown branch (which leaves the callee retransmitting 200 OK then
    // BYEing the half-open dialog).
    if state.call_actors.remove_call_after_cancel(&call_id) {
        schedule_zombie_cancelled_cleanup(state.call_actors.clone());
    }
    state.call_event_receivers.remove(&call_id);
}

/// Fire `@b2bua.on_cancel` handlers for an unanswered call (Calling/Ringing)
/// that was CANCELled.
///
/// Fire-and-forget cleanup — the 487 to the A-leg has already been sent and
/// the call is being torn down regardless. This is the B2BUA teardown signal
/// that `on_failure` (B-leg error) and `on_bye` (answered call) never cover,
/// so a script can release per-call resources that no BYE will clear
/// (rtpengine media, QoS). Mirrors the `on_bye` PyCall construction.
fn run_b2bua_cancel_handlers(
    call_id: &str,
    a_leg_invite: Option<Arc<std::sync::Mutex<SipMessage>>>,
    a_leg_source_ip: String,
    a_leg_transport: String,
    state: &DispatcherState,
) {
    let engine_state = state.engine.state();
    let handlers = engine_state.handlers_for(&HandlerKind::B2buaCancel);
    if handlers.is_empty() {
        return;
    }

    let invite_arc = match &a_leg_invite {
        Some(arc) => Arc::clone(arc),
        None => {
            warn!(call_id = %call_id, "B2BUA: no stored A-leg INVITE for on_cancel");
            return;
        }
    };

    let py_call = PyCall::new(call_id.to_string(), invite_arc, a_leg_source_ip, a_leg_transport);

    Python::attach(|python| {
        let call_obj = match Py::new(python, py_call) {
            Ok(obj) => obj,
            Err(error) => {
                error!("failed to create PyCall for on_cancel: {error}");
                return;
            }
        };

        for handler in &handlers {
            let callable = handler.callable.bind(python);
            match callable.call1((call_obj.bind(python),)) {
                Ok(ret) => {
                    if handler.is_async {
                        if let Err(error) = run_coroutine(python, &ret) {
                            error!("async B2BUA on_cancel handler error: {error}");
                        }
                    }
                }
                Err(error) => {
                    error!("B2BUA on_cancel handler error: {error}");
                }
            }
        }
    });
}

/// Arm the answer-timeout for a B2BUA call from a `call.fork`/`call.dial`
/// `timeout=` (seconds).
///
/// `timeout == 0` disables the application timeout (the 24h orphan sweep stays
/// the only backstop). Otherwise the orphan sweep fails the call if it is still
/// un-answered `timeout` seconds from now — see [`fail_b2bua_call_on_timeout`].
fn set_b2bua_answer_deadline(call_id: &str, timeout_secs: u32, state: &DispatcherState) {
    if timeout_secs == 0 {
        return;
    }
    let deadline =
        std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs as u64);
    state.call_actors.set_answer_deadline(call_id, deadline);
}

/// Fail a B2BUA call whose answer deadline passed while it was still
/// un-answered — the B-leg never produced a final 2xx (dead/partitioned trunk,
/// or a B-leg that silently went away).
///
/// Mirrors the B-leg error teardown in [`handle_b2bua_response`]: CANCEL every
/// pending B-leg (RFC 3261 §9.1), fire `@b2bua.on_failure(call, 408, …)`, send
/// `408 Request Timeout` to the A-leg, then tear the call down via
/// [`CallActorStore::remove_call_after_cancel`] (so a 2xx that raced our CANCEL
/// is still ACK+BYEd). Driven from [`sweep_stale_entries`].
fn fail_b2bua_call_on_timeout(call_id: &str, state: &DispatcherState) {
    // Snapshot everything needed, then drop the DashMap ref before the CANCEL
    // sends, Python, and the A-leg response.
    let (a_leg, a_leg_invite, a_leg_local_addr, cancel_targets, handle_txs) =
        match state.call_actors.get_call(call_id) {
            Some(call) => {
                // Re-check under the lock: the call may have answered or started
                // tearing down between take_timed_out_calls and here.
                if !matches!(call.state, CallState::Calling | CallState::Ringing) {
                    return;
                }
                let mut targets: Vec<(SipMessage, Transport, SocketAddr)> = Vec::new();
                for b_leg in &call.b_legs {
                    if let Some(invite_arc) = b_leg.b_leg_invite.as_ref() {
                        if let Ok(invite) = invite_arc.lock() {
                            if let Some(cancel_msg) = build_cancel_from_invite(&invite) {
                                targets.push((
                                    cancel_msg,
                                    b_leg.transport.transport,
                                    b_leg.transport.remote_addr,
                                ));
                            }
                        }
                    }
                }
                let handle_txs: Vec<_> = call
                    .b_leg_handles
                    .iter()
                    .flatten()
                    .map(|handle| handle.tx.clone())
                    .collect();
                (
                    call.a_leg.clone(),
                    call.a_leg_invite.clone(),
                    call.a_leg_local_addr,
                    targets,
                    handle_txs,
                )
            }
            None => return,
        };

    warn!(
        call_id = %call_id,
        "B2BUA: answer timeout — no final response from B-leg, failing call with 408",
    );

    // CDR: the call timed out before answer (cdr.auto_emit).
    cdr_finalize_b2bua_fail(state, call_id, 408);

    // CANCEL each pending B-leg transaction (RFC 3261 §9.1).
    for (cancel_msg, transport, dest) in cancel_targets {
        send_b2bua_to_bleg(cancel_msg, transport, dest, state);
    }
    for tx in &handle_txs {
        let _ = tx.try_send(crate::b2bua::actor::LegMessage::Cancel);
    }

    // Fire @b2bua.on_failure(call, 408, "Request Timeout").
    if let Some(invite_arc) = &a_leg_invite {
        let engine_state = state.engine.state();
        let handlers = engine_state.handlers_for(&HandlerKind::B2buaFailure);
        if !handlers.is_empty() {
            let py_call = PyCall::new(
                call_id.to_string(),
                Arc::clone(invite_arc),
                a_leg.transport.remote_addr.ip().to_string(),
                format!("{}", a_leg.transport.transport).to_lowercase(),
            );
            Python::attach(|python| {
                let call_obj = match Py::new(python, py_call) {
                    Ok(obj) => obj,
                    Err(error) => {
                        error!("failed to create PyCall for timeout on_failure: {error}");
                        return;
                    }
                };
                for handler in &handlers {
                    let callable = handler.callable.bind(python);
                    match callable.call1((call_obj.bind(python), 408u16, "Request Timeout")) {
                        Ok(ret) => {
                            if handler.is_async {
                                if let Err(error) = run_coroutine(python, &ret) {
                                    error!("async B2BUA timeout on_failure handler error: {error}");
                                }
                            }
                        }
                        Err(error) => {
                            error!("B2BUA timeout on_failure handler error: {error}");
                        }
                    }
                }
            });
        }
    }

    // Send 408 Request Timeout to the A-leg (final response to its INVITE).
    if let Some(invite_arc) = &a_leg_invite {
        if let Ok(invite) = invite_arc.lock() {
            let mut response =
                build_response(&invite, 408, "Request Timeout", state.server_header.as_deref(), &[]);
            // Carry the UAS To-tag we assigned the A-leg dialog (the A-leg saw it
            // on our 1xx) so the final response terminates the same dialog.
            if let Some(to) = response.headers.to() {
                let to_with_tag =
                    crate::b2bua::actor::ensure_tag(to, Some(&a_leg.dialog.local_tag));
                response.headers.set("To", to_with_tag);
            }
            // Pin the A-leg's arrival socket so the 408 leaves the port the caller
            // sent the INVITE to (multi-homed UDP symmetric signalling).
            send_message_from(
                response,
                a_leg.transport.transport,
                a_leg.transport.remote_addr,
                a_leg.transport.connection_id,
                a_leg_local_addr,
                state,
            );
        }
    }

    // RTPEngine safety-net cleanup (mirrors the B-leg failure path).
    let a_sip_call_id = a_leg.dialog.call_id.clone();
    if let (Some(rtpengine_set), Some(media_sessions)) =
        (&state.rtpengine_set, &state.rtpengine_sessions)
    {
        if let Some(session) = media_sessions.remove(&a_sip_call_id) {
            let set = Arc::clone(rtpengine_set);
            tokio::spawn(async move {
                if let Err(error) = set.delete(&session.call_id, &session.from_tag).await {
                    if error.is_call_not_found() {
                        debug!(call_id = %session.call_id, "safety-net RTPEngine delete (timeout): call already gone ({error})");
                    } else {
                        warn!(call_id = %session.call_id, "safety-net RTPEngine delete failed (timeout): {error}");
                    }
                }
            });
        }
    }

    // Tear down, preserving still-pending legs for a 2xx that races the CANCEL.
    if state.call_actors.remove_call_after_cancel(call_id) {
        schedule_zombie_cancelled_cleanup(state.call_actors.clone());
    }
    state.call_event_receivers.remove(call_id);
}

// ---------------------------------------------------------------------------
// B2BUA handlers
// ---------------------------------------------------------------------------

/// Handle an INVITE in B2BUA mode.
///
/// Creates a Call object, invokes `@b2bua.on_invite`, and processes the
/// script's action (dial, fork, reject).
fn handle_b2bua_invite(
    inbound: InboundMessage,
    message: SipMessage,
    state: &DispatcherState,
) {
    let sip_call_id = message.headers.get("Call-ID")
        .unwrap_or(&"unknown".to_string())
        .clone();
    let from_tag = message.headers.get("From")
        .and_then(|f| {
            f.split(';').find(|p| p.trim().starts_with("tag="))
                .map(|t| t.trim().trim_start_matches("tag=").to_string())
        })
        .unwrap_or_default();

    let via_branch = message.headers.get("Via")
        .and_then(|raw| Via::parse_multi(raw).ok())
        .and_then(|vias| vias.into_iter().next())
        .and_then(|v| v.branch)
        .unwrap_or_default();

    // Snapshot the A-leg peer's reliable-provisional capability from the
    // on-wire INVITE, BEFORE the `@b2bua.on_invite` handler runs.  The script
    // may add `Supported: 100rel` to the shared INVITE to advertise reliable
    // provisionals toward the B-leg (IR.92 UEs need it to alert) — that must
    // not poison the gate that decides whether to strip `Require:100rel`/`RSeq`
    // from provisionals relayed back to this A-leg.  See CallActor.a_leg_supports_100rel.
    let a_leg_supports_100rel = crate::sip::headers::rseq::supports_100rel(&message.headers);

    // Guard against INVITE retransmissions: if we already have a call for this
    // SIP Call-ID, this is a retransmission — absorb it silently.
    // Without this check, each UDP retransmission would create a new call and
    // spawn duplicate B-leg INVITEs.
    if state.call_actors.find_by_sip_call_id(&sip_call_id).is_some() {
        debug!(
            call_id = %sip_call_id,
            "B2BUA: absorbing INVITE retransmission (call already exists)"
        );
        return;
    }

    // RFC 3891: if the INVITE carries a `Replaces` header it must match an
    // existing dialog, otherwise we MUST reject with 481 Call/Transaction
    // Does Not Exist. Silently treating it as a fresh INVITE would defeat
    // the attended-transfer semantics (the referrer expects the old dialog
    // to go away once this INVITE succeeds).
    if let Some(replaces_raw) = message.headers.get("Replaces") {
        match crate::sip::headers::refer::parse_replaces(replaces_raw) {
            Ok(replaces) => {
                match state.call_actors.find_call_by_replaces_dialog(
                    &replaces.call_id,
                    &replaces.from_tag,
                    &replaces.to_tag,
                ) {
                    Some(matched_call_id) => {
                        // Dialog found — full attended-transfer bridging
                        // (terminating the matched dialog and bridging the
                        // remote party with the new INVITE's originator) is
                        // still TODO. For now the INVITE flows through as a
                        // normal new call so at least the caller reaches the
                        // UAS; a dedicated ticket tracks the bridge step.
                        debug!(
                            call_id = %sip_call_id,
                            matched_call = %matched_call_id,
                            "B2BUA: INVITE with Replaces matched an existing dialog (bridge TODO)"
                        );
                    }
                    None => {
                        debug!(
                            call_id = %sip_call_id,
                            replaces_call_id = %replaces.call_id,
                            "B2BUA: rejecting INVITE with 481 — Replaces target dialog does not exist"
                        );
                        let response = build_response(
                            &message,
                            481,
                            "Call/Transaction Does Not Exist",
                            state.server_header.as_deref(),
                            &[],
                        );
                        send_message_from(response, inbound.transport, inbound.remote_addr, inbound.connection_id, Some(inbound.local_addr), state);
                        return;
                    }
                }
            }
            Err(error) => {
                debug!(
                    call_id = %sip_call_id,
                    error = %error,
                    "B2BUA: rejecting INVITE with 400 — malformed Replaces header"
                );
                let response = build_response(
                    &message,
                    400,
                    "Bad Replaces Header",
                    state.server_header.as_deref(),
                    &[],
                );
                send_message_from(response, inbound.transport, inbound.remote_addr, inbound.connection_id, Some(inbound.local_addr), state);
                return;
            }
        }
    }

    // Send 100 Trying immediately to suppress A-leg retransmissions
    // (RFC 3261 §8.2.6.1: SHOULD send 100 within 200ms for INVITE)
    let trying = build_response(&message, 100, "Trying", state.server_header.as_deref(), &[]);
    // Answer on the same listener the request arrived on so a multi-homed UDP
    // host keeps a symmetric source port (a peer that sent to :5066 rejects a
    // reply sourced from :5060). No-op for stream transports / single listener.
    send_message_from(
        trying,
        inbound.transport,
        inbound.remote_addr,
        inbound.connection_id,
        Some(inbound.local_addr),
        state,
    );

    // Create the call in the manager
    let mut a_leg = Leg::new_a_leg(
        sip_call_id.clone(),
        from_tag,
        via_branch,
        LegTransport {
            remote_addr: inbound.remote_addr,
            connection_id: inbound.connection_id,
            transport: inbound.transport,
            // Anchor the A-leg on the listener the INVITE arrived on (multi-homed
            // source-port parity for siphon-originated requests + Via/Contact).
            local_addr: Some(inbound.local_addr),
        },
    );

    // Store our Contact for the A-leg direction (what we advertise to the caller).
    // via_host() applies the advertised_address fallback and substitutes the
    // sanitized local_addr when bound to 0.0.0.0/[::]. The PORT is the listener the
    // INVITE arrived on (`inbound.local_addr.port()`), NOT via_port() (the
    // first-configured listener), so a multi-homed host anchors the dialog on the
    // socket the call actually landed on — matches sanitize_b2bua_response's Contact.
    a_leg.dialog.local_contact = Some(format!(
        "<sip:{}:{};transport={}>",
        state.via_host(&inbound.transport),
        inbound.local_addr.port(),
        inbound.transport.to_string().to_lowercase(),
    ));

    // Capture the caller's Contact URI (remote_contact for A-leg)
    if let Some(contact) = message.headers.get("Contact")
        .or_else(|| message.headers.get("m"))
    {
        a_leg.dialog.remote_contact = Some(crate::b2bua::actor::extract_contact_uri(contact));
    }

    // Store A-leg's remote AoR host (caller's From URI host) for in-dialog To headers.
    if let Some(from) = message.headers.from() {
        let from_str = crate::b2bua::actor::extract_contact_uri(from);
        if let Ok(parsed) = parse_uri_standalone(&from_str) {
            a_leg.dialog.remote_aor_host = Some(if let Some(port) = parsed.port {
                format!("{}:{}", parsed.host, port)
            } else {
                parsed.host.clone()
            });
        }
    }

    // Store A-leg From/To for mid-dialog requests. As UAS, our From in BYE
    // is the INVITE's To (with our local_tag), our To is the INVITE's From.
    if let Some(to) = message.headers.to() {
        // Replace/add our tag (the INVITE's To may not have a tag yet)
        let tag_stripped = to.split(";tag=").next().unwrap_or(to);
        a_leg.dialog.local_from_uri = Some(format!("{};tag={}", tag_stripped, a_leg.dialog.local_tag));
    }
    if let Some(from) = message.headers.from() {
        a_leg.dialog.remote_to_uri = Some(from.clone());
    }

    let call_id = state.call_actors.create_call(a_leg);

    // Create the event channel for B-leg actors → dispatcher.
    // All B-leg actors for this call share the same sender.
    let (event_tx, event_rx) = tokio::sync::mpsc::channel::<CallEvent>(64);
    if let Some(mut call) = state.call_actors.get_call_mut(&call_id) {
        call.event_tx = Some(event_tx);
        // Persist the pre-handler on-wire 100rel capability (immutable for the
        // call's life) so the reliable-1xx strip gate can't be defeated by the
        // script mutating the shared INVITE for B-leg header shaping.
        call.a_leg_supports_100rel = a_leg_supports_100rel;
        // Listener the INVITE arrived on, so an imperative call.answer() /
        // call.progress() (which has no `inbound` in scope) sends the UAS
        // response back out the same socket.
        call.a_leg_local_addr = Some(inbound.local_addr);
    }
    state.call_event_receivers.insert(call_id.clone(), event_rx);

    // CDR: start tracking this call at INVITE time (cdr.auto_emit).
    cdr_track_b2bua_start(
        state,
        &call_id,
        &message,
        &inbound.remote_addr.ip().to_string(),
        &format!("{}", inbound.transport).to_lowercase(),
    );

    // Invoke @b2bua.on_invite
    let message_arc = Arc::new(std::sync::Mutex::new(message));
    let py_call = PyCall::new(
        call_id.clone(),
        Arc::clone(&message_arc),
        inbound.remote_addr.ip().to_string(),
        format!("{}", inbound.transport).to_lowercase(),
    );

    let engine_state = state.engine.state();
    let handlers = engine_state.handlers_for(&HandlerKind::B2buaInvite);

    let (
        action,
        timer_override,
        credentials,
        li_record,
        preserve_call_id,
        policy_input,
        from_host_override,
        to_host_override,
        contact_user_override,
        contact_override,
        auth_passthrough,
    ) = Python::attach(|python| {
        let call_obj = match Py::new(python, py_call) {
            Ok(obj) => obj,
            Err(error) => {
                error!("failed to create PyCall: {error}");
                return (CallAction::None, None, None, false, false, None, None, None, None, None, false);
            }
        };

        for handler in &handlers {
            let callable = handler.callable.bind(python);
            match callable.call1((call_obj.bind(python),)) {
                Ok(ret) => {
                    if handler.is_async {
                        if let Err(error) = run_coroutine(python, &ret) {
                            error!("async B2BUA on_invite handler error: {error}");
                            return (CallAction::Reject {
                                code: 500,
                                reason: "Script Error".to_string(),
                            }, None, None, false, false, None, None, None, None, None, false);
                        }
                    }
                }
                Err(error) => {
                    error!("B2BUA on_invite handler error: {error}");
                    return (CallAction::Reject {
                        code: 500,
                        reason: "Script Error".to_string(),
                    }, None, None, false, false, None, None, None, None, None, false);
                }
            }
        }

        let borrowed = call_obj.borrow(python);
        let action = borrowed.action().clone();
        let timer_override = borrowed.session_timer_override().cloned();
        let credentials = borrowed.outbound_credentials().map(|(u, p)| (u.to_string(), p.to_string()));
        let li_record = borrowed.li_record();
        let preserve_cid = borrowed.preserve_call_id();
        let policy_input = borrowed.header_policy_input().cloned();
        let from_host_ovr = borrowed.from_host_override().map(String::from);
        let to_host_ovr = borrowed.to_host_override().map(String::from);
        let contact_user_ovr = borrowed.contact_user_override().map(String::from);
        let contact_ovr = borrowed.contact_override().map(String::from);
        let auth_passthrough = borrowed.auth_passthrough();
        (action, timer_override, credentials, li_record, preserve_cid, policy_input, from_host_ovr, to_host_ovr, contact_user_ovr, contact_ovr, auth_passthrough)
    });

    // Store the A-leg INVITE for later use by on_answer/on_failure/on_bye handlers
    state.call_actors.set_a_leg_invite(&call_id, Arc::clone(&message_arc));

    // Resolve script-side header policy input into a per-call ResolvedPolicy.
    // Done outside the call_actors lock so the registry lookup + delta
    // translation doesn't hold the actor mutex.
    let resolved_policy = policy_input.map(|input| {
        let preset = match input.policy_name.as_deref() {
            Some(name) => match state.header_policy_registry.get(name) {
                Some(p) => p.clone(),
                None => {
                    warn!(
                        call_id = %call_id,
                        requested = %name,
                        "unknown header_policy preset — falling back to default"
                    );
                    state.default_header_policy.clone()
                }
            },
            None => state.default_header_policy.clone(),
        };
        let mut resolved = crate::b2bua::header_policy::ResolvedPolicy::from_preset(preset);
        resolved.deltas_copy = input.deltas_copy;
        resolved.deltas_strip = input.deltas_strip;
        resolved.deltas_translate = input
            .deltas_translate
            .into_iter()
            .filter_map(|(header, op_name)| {
                parse_translate_op_name(&op_name)
                    .map(|op| (header, op))
                    .or_else(|| {
                        warn!(
                            call_id = %call_id,
                            op = %op_name,
                            "unknown translate op — entry dropped"
                        );
                        None
                    })
            })
            .collect();
        Arc::new(resolved)
    });

    // auth_passthrough (relay the challenge for the endpoint to answer) and
    // set_credentials (siphon answers the challenge itself) are mutually
    // exclusive uses of the same 401/407 handling. If both are set, credentials
    // win (the auth_passthrough branch is only reachable when there are none) —
    // warn so the misconfiguration is visible.
    if credentials.is_some() && auth_passthrough {
        warn!(
            call_id = %call_id,
            "call has both set_credentials() and auth_passthrough=True — credentials win; ignoring auth_passthrough"
        );
    }

    // Store per-call overrides from script
    if timer_override.is_some()
        || credentials.is_some()
        || li_record
        || preserve_call_id
        || resolved_policy.is_some()
        || from_host_override.is_some()
        || to_host_override.is_some()
        || contact_user_override.is_some()
        || contact_override.is_some()
        || auth_passthrough
    {
        if let Some(mut call) = state.call_actors.get_call_mut(&call_id) {
            if let Some(override_config) = timer_override {
                call.session_timer_override = Some(override_config);
            }
            if credentials.is_some() {
                call.outbound_credentials = credentials;
            }
            if li_record {
                call.li_record = true;
            }
            call.preserve_call_id = preserve_call_id;
            if resolved_policy.is_some() {
                call.resolved_header_policy = resolved_policy;
            }
            if from_host_override.is_some() {
                call.from_host_override = from_host_override;
            }
            if to_host_override.is_some() {
                call.to_host_override = to_host_override;
            }
            if contact_user_override.is_some() {
                call.contact_user_override = contact_user_override;
            }
            if contact_override.is_some() {
                call.contact_override = contact_override;
            }
            call.auth_passthrough = auth_passthrough;
        }
    }

    let Ok(message_guard) = message_arc.lock() else {
        error!("message_arc lock poisoned in B2BUA invite handler");
        return;
    };

    match action {
        CallAction::None => {
            debug!(call_id = %call_id, "B2BUA: silent drop (no action from script)");
            state.call_actors.remove_call(&call_id);
            state.call_event_receivers.remove(&call_id);
        }
        CallAction::Reject { code, reason } => {
            debug!(call_id = %call_id, code, "B2BUA: rejecting call");
            let response = build_response(&message_guard, code, &reason, state.server_header.as_deref(), &[]);
            send_message_from(response, inbound.transport, inbound.remote_addr, inbound.connection_id, Some(inbound.local_addr), state);
            state.call_actors.remove_call(&call_id);
            state.call_event_receivers.remove(&call_id);
        }
        CallAction::Dial { target, next_hop, flow, route, send_socket, timeout } => {
            debug!(
                call_id = %call_id,
                target = %target,
                next_hop = ?next_hop,
                flow = flow.is_some(),
                routes = route.len(),
                "B2BUA: dialling B-leg",
            );
            let send_socket = state.resolve_send_socket(send_socket.as_deref());
            b2bua_send_b_leg_invite(
                &call_id,
                &target,
                next_hop.as_deref(),
                flow.as_ref(),
                &route,
                send_socket.as_ref(),
                &message_guard,
                &inbound,
                state,
            );
            set_b2bua_answer_deadline(&call_id, timeout, state);
        }
        CallAction::Fork { targets, flows, strategy: _, send_socket, timeout } => {
            debug!(call_id = %call_id, targets = ?targets, "B2BUA: forking B-legs");
            let send_socket = state.resolve_send_socket(send_socket.as_deref());
            for (index, target) in targets.iter().enumerate() {
                b2bua_send_b_leg_invite(
                    &call_id,
                    target,
                    None,
                    flows.get(index).and_then(|f| f.as_ref()),
                    &[],
                    send_socket.as_ref(),
                    &message_guard,
                    &inbound,
                    state,
                );
            }
            set_b2bua_answer_deadline(&call_id, timeout, state);
        }
        CallAction::Terminate => {
            debug!(call_id = %call_id, "B2BUA: terminate on invite (unusual)");
            state.call_actors.remove_call(&call_id);
            state.call_event_receivers.remove(&call_id);
        }
        CallAction::AcceptRefer => {
            debug!(call_id = %call_id, "B2BUA: AcceptRefer during INVITE (no-op)");
        }
        CallAction::RejectRefer { code, reason } => {
            debug!(call_id = %call_id, code, reason = %reason, "B2BUA: RejectRefer during INVITE (no-op)");
        }
        CallAction::Answered => {
            // The script called call.answer() imperatively — the 2xx has already
            // been sent (see b2bua_answer_call). This marker only tells the
            // dispatcher the actor was answered so the CallAction::None arm above
            // doesn't remove_call() it as a silent drop. The A-leg dialog is
            // confirmed and @b2bua.on_bye takes over when the UAC BYEs.
            debug!(call_id = %call_id, "B2BUA: UAS-mode answer already sent (imperative)");
        }
    }
}

/// Build the B-leg Contact header value.
///
/// Default is siphon's own userless address `<sip:host:port;transport=…>` — RFC
/// 3261 §8.1.1.8 puts no identity in the Contact userpart, and siphon's address
/// is all that's needed as the §12.2.1.1 in-dialog remote target. A script may
/// override it via `call.set_contact_user()` (inject a userpart, keep siphon's
/// host:port — in-dialog routing intact) or `call.set_contact_uri()` (replace
/// the whole URI — edge/GRUU deployments that front siphon). The full-URI
/// override wins over the userpart one; an empty userpart override collapses to
/// the userless default.
fn build_b_leg_contact(
    host: &str,
    port: u16,
    transport: Transport,
    contact_user_override: Option<&str>,
    contact_override: Option<&str>,
) -> String {
    if let Some(uri) = contact_override {
        format!("<{uri}>")
    } else if let Some(user) = contact_user_override.filter(|user| !user.is_empty()) {
        format!(
            "<sip:{}@{}:{};transport={}>",
            user,
            host,
            port,
            transport.to_string().to_lowercase(),
        )
    } else {
        format!(
            "<sip:{}:{};transport={}>",
            host,
            port,
            transport.to_string().to_lowercase(),
        )
    }
}

/// Send a B-leg INVITE for a B2BUA call.
///
/// `target_uri` drives the new INVITE's R-URI (so the called party's IMPU
/// shape is preserved on the wire).  `next_hop`, when set, is used for the
/// wire destination instead of `target_uri` — IMS edge use-case where the
/// R-URI must carry the canonical home-domain IMPU but the message has to
/// be routed via a fixed next-hop (BGCF, I-CSCF, outbound proxy, …).
#[allow(clippy::too_many_arguments)]
fn b2bua_send_b_leg_invite(
    call_id: &str,
    target_uri: &str,
    next_hop: Option<&str>,
    flow: Option<&crate::script::api::registrar::PyFlow>,
    b_leg_route: &[String],
    send_socket: Option<&crate::transport::SendSocket>,
    original_request: &SipMessage,
    _inbound: &InboundMessage,
    state: &DispatcherState,
) {
    // Resolve the wire destination: over the captured inbound flow (RFC 5626
    // §5.3 connection reuse — the only way to reach a WebSocket callee, RFC
    // 7118 §5) when one is attached, else from next_hop when set, else from
    // target.  R-URI construction below still uses target_uri unconditionally —
    // that split is the whole point of next_hop.
    let (destination, outbound_transport) = if let Some(flow) = flow {
        let transport = match flow.transport.as_str() {
            "udp" => Transport::Udp,
            "tcp" => Transport::Tcp,
            "tls" => Transport::Tls,
            "ws" => Transport::WebSocket,
            "wss" => Transport::WebSocketSecure,
            other => {
                warn!(call_id = %call_id, transport = %other, "B2BUA: unknown flow transport");
                return;
            }
        };
        (flow.source_addr, transport)
    } else {
        let routing_uri = next_hop.unwrap_or(target_uri);
        let relay_target = match resolve_target(routing_uri, &state.dns_resolver) {
            Some(t) => t,
            None => {
                warn!(
                    call_id = %call_id,
                    target = %target_uri,
                    next_hop = ?next_hop,
                    "B2BUA: cannot resolve destination",
                );
                return;
            }
        };
        (relay_target.address, relay_target.transport.unwrap_or(Transport::Udp))
    };

    // A script send_socket= egress pin applies to the B-leg only when it has no
    // captured flow (a flow already pins egress) and its transport matches the
    // B-leg's outbound transport.  When it applies, the B-leg Via sent-by is the
    // pinned listener's advertised address so the callee's response comes back
    // to that socket.
    let send_socket = match send_socket {
        _ if flow.is_some() => None,
        Some(pin) if pin.transport == outbound_transport => Some(pin),
        Some(pin) => {
            warn!(
                call_id = %call_id,
                send_socket = %pin.addr,
                requested_transport = %pin.transport,
                outbound_transport = %outbound_transport,
                "B2BUA: send_socket transport does not match the B-leg transport — ignoring"
            );
            None
        }
        None => None,
    };

    // Build a new INVITE for the B-leg
    let branch = TransactionKey::generate_branch();
    let (via_host, via_port) = match send_socket {
        Some(pin) => {
            let (host, port) = pin.via_sent_by();
            (format_sip_host(&host), port)
        }
        None => (state.via_host(&outbound_transport), state.via_port(&outbound_transport)),
    };
    let via_value = format!(
        "SIP/2.0/{} {}:{};branch={}",
        outbound_transport,
        via_host,
        via_port,
        branch,
    );

    let mut b_leg_invite = original_request.clone();

    // Framework-auto strips — `Record-Route` and `Route` carry the A-leg
    // dialog routing state, independent of B-leg per RFC 3261 §16.  No
    // preset can opt them in (the dialog model breaks if they cross).
    //
    // `Authorization` (RFC 3261 §22.2, end-to-end) and `Proxy-Authorization`
    // (RFC 3261 §22.3, hop-by-hop) are both policy-managed.  Every built-in
    // preset strips them by default; scripts can opt in via
    // `call.dial(copy=[…])` for transparent-federation / transparent-proxy
    // cases (preset validator rejects combinations that would break
    // the Digest hash).
    b_leg_invite.headers.remove("Record-Route");
    b_leg_invite.headers.remove("Route");

    // Script-supplied Route set (`call.dial(route=[…])`) — the captured IMS
    // Service-Route on MO calls, prepended here *after* the A-leg Route strip so
    // the B-leg traverses the originating S-CSCF (RFC 3608 / TS 24.229).
    if !b_leg_route.is_empty() {
        b_leg_invite.headers.set_all("Route", b_leg_route.to_vec());
    }

    // Replace Via with our own (set preserves header position)
    b_leg_invite.headers.set("Via", via_value);
    // Update Request-URI: use dial target for routing (host/port/transport) but
    // preserve the called party's user part from the A-leg RURI.
    // The dial target is a routing destination, not the called party.
    // If the script dials `sip:specific-user@host`, that user is respected.
    if let Ok(mut target_parsed) = parse_uri_standalone(target_uri) {
        if target_parsed.user.is_none() {
            if let StartLine::Request(ref orig_rl) = original_request.start_line {
                target_parsed.user = orig_rl.request_uri.user.clone();
            }
        }
        b_leg_invite.start_line = StartLine::Request(crate::sip::message::RequestLine {
            method: crate::sip::message::Method::Invite,
            request_uri: target_parsed,
            version: crate::sip::message::Version::sip_2_0(),
        });
    }

    // Generate fresh dialog identifiers for the B-leg (proper B2BUA behavior).
    // Call-ID is new by default unless the script called call.preserve_call_id().
    // From-tag is always unique per B-leg regardless.
    let (
        per_call_override,
        preserve_call_id,
        a_leg_call_id,
        a_leg_from_tag,
        from_host_override,
        to_host_override,
        contact_user_override,
        contact_override,
    ) = match state.call_actors.get_call(call_id) {
        Some(c) => (
            c.session_timer_override.clone(),
            c.preserve_call_id,
            c.a_leg.dialog.call_id.clone(),
            c.a_leg.dialog.remote_tag.clone().unwrap_or_default(),
            c.from_host_override.clone(),
            c.to_host_override.clone(),
            c.contact_user_override.clone(),
            c.contact_override.clone(),
        ),
        None => (None, false, String::new(), String::new(), None, None, None, None),
    };

    let b_leg_call_id = if preserve_call_id {
        a_leg_call_id
    } else {
        crate::b2bua::actor::generate_call_id()
    };
    let b_leg_from_tag = crate::b2bua::actor::generate_tag();

    // Rewrite Call-ID for B-leg dialog
    b_leg_invite.headers.set("Call-ID", b_leg_call_id.clone());

    // Rewrite From for B-leg dialog:
    //  - Replace the tag with a fresh B-leg tag
    //  - Rewrite the URI host (default: mask A-leg identity with our own host)
    if let Some(from) = b_leg_invite.headers.get("From")
        .or_else(|| b_leg_invite.headers.get("f"))
    {
        let old_pattern = format!("tag={}", a_leg_from_tag);
        let new_pattern = format!("tag={}", b_leg_from_tag);
        let mut new_from = from.replace(&old_pattern, &new_pattern);

        // Rewrite the host in the From URI.  Default: the B2BUA advertised
        // address (topology hiding — mask A-leg identity).  When the script
        // pinned a host via `call.set_from_host()`, use that instead — opt
        // out of From topology-hiding for multitenant edges that select the
        // tenant from the From domain (a domainless call would otherwise land
        // in the downstream's unauthenticated/default routing context).
        // From header format: ["Display" ]<sip:user@host[:port][;params]>[;tag=...]
        let from_host = from_host_override
            .unwrap_or_else(|| state.via_host(&outbound_transport));
        if let Some(at_pos) = new_from.find('@') {
            // Find the end of the host: first occurrence of '>', ':', or ';' after '@'
            let after_at = &new_from[at_pos + 1..];
            let host_end = after_at.find(['>', ';', ':'])
                .unwrap_or(after_at.len());
            let end_pos = at_pos + 1 + host_end;
            new_from = format!("{}{}{}", &new_from[..at_pos + 1], from_host, &new_from[end_pos..]);
        }

        b_leg_invite.headers.set("From", new_from);
    }

    // Set Contact to siphon's own address so in-dialog requests route through us.
    // via_host()/via_port() apply advertised_address fallback and substitute the
    // sanitized local_addr when the bind is 0.0.0.0/[::] — never leak unspecified.
    //
    // The Contact is userless by default (RFC 3261 §8.1.1.8 puts no identity in
    // the Contact userpart; siphon's own address is all that's needed for the
    // §12.2.1.1 in-dialog remote target). A script may override it:
    //   set_contact_user() → keep our host:port, inject a userpart (safe — we
    //     still receive in-dialog requests, the userpart just rides along, e.g.
    //     for a downstream that keys a tenant/extension off the Contact user);
    //   set_contact_uri()  → replace the whole URI (edge/GRUU deployments that
    //     front siphon — the deployment owns routing the in-dialog target back).
    let b_contact_host = state.via_host(&outbound_transport);
    let b_contact_port = state.via_port(&outbound_transport);
    let b_contact_value = build_b_leg_contact(
        &b_contact_host,
        b_contact_port,
        outbound_transport,
        contact_user_override.as_deref(),
        contact_override.as_deref(),
    );
    b_leg_invite.headers.set("Contact", b_contact_value.clone());

    // User-Agent rewrite is policy-managed (see `transparent-b2bua@2026`
    // → User-Agent: Rewrite(ReplaceWithUserAgentHeader)).  Topology-hiding
    // presets at trust boundaries do the same.

    // Strip any To-tag (B-leg INVITE should not have one) and rewrite the To URI
    // host to match the dial target (topology hiding — A-leg advertised address
    // must not leak to B-leg).
    if let Some(to) = b_leg_invite.headers.get("To")
        .or_else(|| b_leg_invite.headers.get("t"))
    {
        let mut new_to = to.clone();
        if let Some(tag_start) = new_to.find(";tag=") {
            new_to = new_to[..tag_start].to_string();
        }
        // Rewrite the To URI host.
        if let Some(ref pinned) = to_host_override {
            // Script pinned a host via `call.set_to_host()`: host only — the
            // original To port and URI params are preserved (documented
            // `set_to_host` contract: `value` is a bare host, no port).
            new_to = crate::b2bua::actor::rewrite_uri_host(&new_to, pinned);
        } else if let Ok(target_parsed) = parse_uri_standalone(target_uri) {
            // Default: topology-hide the To to the dial-target authority.  The
            // original To host+port is siphon's own inbound address (leaked
            // from the A-leg) and is meaningless on the B-leg, so replace host
            // AND port with the target's `host[:port]`.  Replacing host-only
            // here would leave the old `:port` in place and, when the target
            // carries a port, emit a malformed `host:newport:oldport`
            // (RFC 3261 §19.1.1 — a URI carries at most one port), which SBCs
            // reject as `400 Wrong URI`.
            let target_authority = match target_parsed.port {
                Some(port) => format!("{}:{}", target_parsed.host, port),
                None => target_parsed.host.clone(),
            };
            new_to = crate::b2bua::actor::rewrite_uri_authority(&new_to, &target_authority);
        }
        // Unparseable target and no override — leave the To host untouched.
        b_leg_invite.headers.set("To", new_to);
    }

    // Regenerate CSeq for B-leg dialog (independent CSeq space, RFC 3261)
    b_leg_invite.headers.set("CSeq", "1 INVITE".to_string());

    // Decrement Max-Forwards (RFC 7332 — B2BUAs MUST decrement)
    let _ = crate::proxy::core::decrement_max_forwards(&mut b_leg_invite.headers);

    // Apply per-call header policy.  Resolves to the per-call preset (when
    // the script attached one via `call.dial(header_policy=…)`), otherwise
    // the configured `b2bua.default_header_policy` (defaults to
    // `transparent-b2bua@2026`, which reproduces siphon's pre-policy B-leg
    // INVITE construction — Authorization strip + User-Agent/PAI rewrite).
    {
        let policy = state.resolve_header_policy(call_id);
        let ctx = crate::b2bua::header_policy::PolicyContext {
            b2bua_host: &b_contact_host,
            b2bua_port: b_contact_port,
            user_agent_header: state.user_agent_header.as_deref(),
            server_header: state.server_header.as_deref(),
        };
        crate::b2bua::header_policy::apply_to_request(&mut b_leg_invite, &policy, &ctx);
    }

    // Inject RFC 4028 session timer headers if configured.
    // Per-call override (from call.session_timer()) takes precedence over global config.
    if let Some(ref override_config) = per_call_override {
        b_leg_invite.headers.add("Supported", "timer".to_string());
        b_leg_invite.headers.add(
            "Session-Expires",
            format!("{};refresher=uac", override_config.session_expires),
        );
        b_leg_invite.headers.add("Min-SE", override_config.min_se.to_string());
    } else if let Some(ref timer_config) = state.session_timer_config {
        if timer_config.enabled {
            b_leg_invite.headers.add("Supported", "timer".to_string());
            b_leg_invite.headers.add(
                "Session-Expires",
                format!("{};refresher=uac", timer_config.session_expires),
            );
            b_leg_invite.headers.add("Min-SE", timer_config.min_se.to_string());
        }
    }

    // Sanitize SDP: mask A-leg identity in o= and s= lines, and rewrite
    // the o= address to our advertised address for topology hiding.
    let sdp_addr = state.via_host(&outbound_transport);
    sanitize_sdp_identity(&mut b_leg_invite.body, &state.sdp_name, Some(&sdp_addr));

    // Update Content-Length after SDP rewrite (o=/s= changes may alter body size)
    if !b_leg_invite.body.is_empty() {
        b_leg_invite.headers.set("Content-Length", b_leg_invite.body.len().to_string());
    }

    // Register B-leg with call manager (Contact built above; local_contact must
    // match the wire Contact so siphon's own mid-dialog requests advertise the
    // same address the callee will target).
    let mut b_leg = Leg::new_b_leg(
        b_leg_call_id,
        b_leg_from_tag,
        target_uri.to_string(),
        branch.clone(),
        LegTransport {
            remote_addr: destination,
            connection_id: flow.map(|f| ConnectionId(f.connection_id)).unwrap_or_default(),
            transport: outbound_transport,
            local_addr: None,
        },
    );
    b_leg.dialog.local_contact = Some(b_contact_value);
    // Store From/To URIs for mid-dialog requests (BYE, re-INVITE).
    // These must match the dialog-creating INVITE's From/To exactly.
    b_leg.dialog.local_from_uri = b_leg_invite.headers.from().cloned();
    b_leg.dialog.remote_to_uri = b_leg_invite.headers.to().cloned();
    debug!(
        call_id = %call_id,
        b_leg_from = ?b_leg.dialog.local_from_uri,
        b_leg_to = ?b_leg.dialog.remote_to_uri,
        "B2BUA: stored B-leg dialog From/To",
    );
    // Store the B-leg's remote AoR host (from dial target) for in-dialog To headers.
    // In-dialog To uses the original AoR, NOT the remote Contact (which is for RURI).
    if let Ok(target_parsed) = parse_uri_standalone(target_uri) {
        b_leg.dialog.remote_aor_host = Some(if let Some(port) = target_parsed.port {
            format!("{}:{}", target_parsed.host, port)
        } else {
            target_parsed.host.clone()
        });
    }
    state.call_actors.add_b_leg(call_id, b_leg.clone());
    spawn_b_leg_actor(call_id, &b_leg, state);

    let data = Bytes::from(b_leg_invite.to_bytes());

    // Send: over the captured flow (direct OutboundMessage, bypassing DNS/pool —
    // mirrors the proxy relay(flow=...) path) when one is attached, else via the
    // resolver/pool path.
    if let Some(flow) = flow {
        let outbound_message = OutboundMessage {
            connection_id: ConnectionId(flow.connection_id),
            transport: outbound_transport,
            destination,
            data,
            source_local_addr: Some(flow.local_addr),
            server_name: None,
        };
        if let Err(error) = state.outbound.send(outbound_message) {
            error!(call_id = %call_id, destination = %destination, transport = %outbound_transport, "B2BUA: flow send failed: {error}");
        }
    } else {
        let relay_target = RelayTarget { address: destination, transport: Some(outbound_transport), server_name: None };
        send_to_target(data, &relay_target, outbound_transport, ConnectionId::default(), send_socket.map(|pin| pin.addr), state);
    }

    // Persist the fully hygiene-processed B-leg INVITE on the leg.
    // The 401/407 auto-retry path rebuilds the retry from this — rebuilding
    // from the A-leg INVITE would leak A-leg headers (Record-Route, Route,
    // Authorization), the original Call-ID/CSeq/From-host, and the un-anchored
    // SDP back to the B-leg. Increment B-leg local CSeq after sending the
    // initial INVITE (CSeq 1 is now used); subsequent requests (re-INVITE,
    // BYE, 401/407 retry) use CSeq >= 2.
    //
    // Also drain a deferred CANCEL on this leg, if one was queued by
    // handle_b2bua_cancel while the INVITE was still being assembled
    // (RFC 3261 §9.1 — CANCEL must share the INVITE's Via branch + CSeq
    // seq, so we can only emit it after the INVITE is on the wire and
    // its hygiene-processed form is stashed).
    let stored_invite = Arc::new(Mutex::new(b_leg_invite));
    let deferred_cancel: Option<(SipMessage, Transport, SocketAddr)> =
        if let Some(mut call) = state.call_actors.get_call_mut(call_id) {
            let result = if let Some(b_leg) = call.b_legs.last_mut() {
                b_leg.dialog.local_cseq += 1;
                b_leg.b_leg_invite = Some(stored_invite.clone());
                if b_leg.pending_cancel {
                    b_leg.pending_cancel = false;
                    match stored_invite.lock() {
                        Ok(guard) => build_cancel_from_invite(&guard).map(|c| (
                            c,
                            b_leg.transport.transport,
                            b_leg.transport.remote_addr,
                        )),
                        Err(_) => {
                            warn!(call_id = %call_id, "B2BUA: pending CANCEL drain — stored INVITE mutex poisoned");
                            None
                        }
                    }
                } else {
                    None
                }
            } else {
                None
            };
            result
        } else {
            None
        };

    if let Some((cancel_msg, b_transport, b_dest)) = deferred_cancel {
        debug!(call_id = %call_id, "B2BUA: draining deferred CANCEL after INVITE stash");
        send_b2bua_to_bleg(cancel_msg, b_transport, b_dest, state);
    }
}

/// Apply 401/407 digest-retry edits to a previously sent B-leg INVITE.
///
/// Clones `original` and returns a copy with:
///   - `Via` replaced (carries the new client-transaction branch).
///   - `CSeq` bumped to `cseq` (RFC 3261 §22.2 — retry uses an incremented
///     sequence number within the same dialog).
///   - Both `Authorization` and `Proxy-Authorization` removed, then
///     `auth_header` (one of those two) added with `auth_value`.
///
/// Every other header — `Contact`, `Call-ID`, `From`, `To`, the Request-URI,
/// `User-Agent`, `P-Asserted-Identity`, the absence of `Record-Route`/`Route`,
/// and the (possibly rtpengine-anchored) SDP body — is preserved verbatim
/// from the prior B-leg INVITE. This is the core fix for the 401/407 retry
/// leak: the prior INVITE was already fully hygiene-processed by
/// [`b2bua_send_b_leg_invite`], so we must not rebuild from the raw A-leg
/// INVITE.
fn build_digest_retry_invite(
    original: &SipMessage,
    new_via: String,
    cseq: u32,
    auth_header: &str,
    auth_value: String,
) -> SipMessage {
    let mut retry = original.clone();
    retry.headers.set("Via", new_via);
    retry.headers.set("CSeq", format!("{cseq} INVITE"));
    retry.headers.remove("Authorization");
    retry.headers.remove("Proxy-Authorization");
    retry.headers.add(auth_header, auth_value);
    retry
}

/// Spawn a [`LegActor`] for a B-leg and store its handle in the call.
///
/// The actor classifies inbound SIP messages into [`CallEvent`]s.
/// Call this after `add_b_leg` — uses the last B-leg index.
fn spawn_b_leg_actor(call_id: &str, b_leg: &Leg, state: &DispatcherState) {
    if let Some(call) = state.call_actors.get_call(call_id) {
        if let Some(event_tx) = &call.event_tx {
            let (actor, handle) = LegActor::new(b_leg.clone(), event_tx.clone());
            let b_leg_index = call.b_legs.len().saturating_sub(1);
            drop(call);
            tokio::spawn(actor.run());
            if let Some(mut call) = state.call_actors.get_call_mut(call_id) {
                call.set_b_leg_handle(b_leg_index, handle);
            }
        }
    }
}

/// Spawn a [`LegActor`] for a B-leg whose slot is at an explicit `index`.
///
/// Like [`spawn_b_leg_actor`] but stores the handle at `index` rather than the
/// last B-leg. Used by the 401/407 and 422 retry paths, which *supersede* the
/// failed leg in place (via `CallActorStore::replace_b_leg`) instead of
/// appending — so the retry's actor handle must land on the same slot the
/// retry leg occupies.
fn spawn_b_leg_actor_at(call_id: &str, b_leg: &Leg, index: usize, state: &DispatcherState) {
    if let Some(call) = state.call_actors.get_call(call_id) {
        if let Some(event_tx) = &call.event_tx {
            let (actor, handle) = LegActor::new(b_leg.clone(), event_tx.clone());
            drop(call);
            tokio::spawn(actor.run());
            if let Some(mut call) = state.call_actors.get_call_mut(call_id) {
                call.set_b_leg_handle(index, handle);
            }
        }
    }
}

/// Receive the next B-leg response classification from the shared per-call
/// event channel, discarding stale `CallEvent::Terminated` notifications.
///
/// Every [`LegActor`] emits `CallEvent::Terminated` as it falls out of its run
/// loop. A 401/407/422 outbound retry supersedes the failed B-leg in place
/// (`CallActorStore::replace_b_leg`), which drops the old leg's actor handle;
/// that actor then exits and pushes a `Terminated` onto the SHARED per-call
/// channel — the very channel the dispatcher block-recvs for each response's
/// classification.
///
/// `Terminated` is a lifecycle notification, never a response classification,
/// and nothing else consumes this channel. Taking one here as though it
/// classified the response just handed to the live actor desyncs the stream by
/// one: the next 200 OK then reads the previous 18x's `Provisional` event, so
/// the 2xx is misclassified as provisional — `set_winner` and the deferred
/// B-leg ACK are skipped, the trunk's 200 OK is never ACKed, and it retransmits
/// until the dialog collapses (BYE storm ~5 s after answer). Filtering
/// `Terminated` out restores the strict one-response/one-classification
/// invariant the caller relies on.
///
/// The caller block-recvs only after a successful `try_send` of the response to
/// the live actor, so exactly one non-`Terminated` classification event is
/// always forthcoming and this loop terminates.
fn recv_b_leg_classification_event(
    rx: &mut tokio::sync::mpsc::Receiver<CallEvent>,
) -> Option<CallEvent> {
    loop {
        match rx.blocking_recv() {
            Some(CallEvent::Terminated { .. }) => continue,
            other => return other,
        }
    }
}

/// Extract the `expires=` parameter value from a Contact header value.
///
/// Skips URI parameters inside angle brackets so that only Contact-level
/// parameters (after the closing `>`) are considered.  Handles both
/// unquoted (`expires=3600`) and quoted (`expires="3600"`) forms.
fn parse_contact_expires(contact: &str) -> Option<u32> {
    // If the Contact contains angle brackets, only look at params after '>'
    let params_part = if let Some(pos) = contact.find('>') {
        &contact[pos + 1..]
    } else {
        contact
    };
    params_part.split(';').find_map(|param| {
        let param = param.trim();
        param
            .strip_prefix("expires=")
            .and_then(|value| value.trim().trim_matches('"').parse::<u32>().ok())
    })
}

/// Handle a response to an outbound registration (z9hG4bK-reg- branch).
fn handle_registrant_response(
    registrant: &Arc<crate::registrant::RegistrantManager>,
    message: &SipMessage,
    status_code: u16,
    _branch: &str,
    state: &DispatcherState,
) {
    // Match response to a registration entry by Call-ID
    let call_id = match message.headers.get("Call-ID") {
        Some(cid) => cid.clone(),
        None => {
            warn!("registrant response has no Call-ID");
            return;
        }
    };

    let aor = match registrant.find_by_call_id(&call_id) {
        Some(aor) => aor,
        None => {
            debug!(call_id = %call_id, "registrant response: no matching entry");
            return;
        }
    };

    let is_aka =
        registrant.auth_mode(&aor) == Some(crate::registrant::AuthMode::Aka);

    // A carrier / Teams Direct Routing registrar that rejects with a Retry-After
    // (RFC 3261 §20.33) is telling us exactly when to re-REGISTER — thread it
    // into the failure handler so it schedules the next attempt at that cooldown
    // instead of the local exponential backoff.
    let retry_after = crate::sip::headers::retry_after::parse_retry_after(&message.headers);

    match status_code {
        200 => {
            // Parse granted expires: top-level Expires header first,
            // then Contact expires= parameter (RFC 3261 §10.2.4),
            // finally fall back to the originally requested value.
            let expires = message.headers.get("Expires")
                .and_then(|v| v.trim().parse::<u32>().ok())
                .or_else(|| {
                    message.headers.get("Contact")
                        .and_then(|contact| parse_contact_expires(contact))
                })
                .unwrap_or(registrant.default_interval);

            // IMS: capture the Service-Route / P-Associated-URI / Path the
            // S-CSCF granted, for MO call routing and implicit-set resolution
            // (Phase 3). Only for AKA entries so the carrier-trunk path is
            // byte-identical.
            if is_aka {
                registrant.store_registration_routes(
                    &aor,
                    collect_route_set(message, "Service-Route"),
                    collect_route_set(message, "P-Associated-URI"),
                    collect_route_set(message, "Path"),
                );
            }

            // IPsec: tighten the kernel SA hard-lifetime from the placeholder
            // installed on the 401 path down to the registrar's granted Expires
            // (+ RFC 3261 Timer F grace), so the SAs track the registration
            // lifetime (TS 33.203 §7.4).
            if is_aka && registrant.is_ipsec_entry(&aor) {
                if let (Some(ipsec_manager), Some(ue_port_c)) =
                    (state.ipsec_manager.clone(), registrant.ue_protected_client_port(&aor))
                {
                    let ue_addr = state.local_addr.ip();
                    let hard_lifetime = (expires as u64) + 32;
                    tokio::spawn(async move {
                        if let Err(error) = ipsec_manager
                            .update_sa_pair_lifetime(&ue_addr, ue_port_c, Some(hard_lifetime))
                            .await
                        {
                            warn!(%error, "IPsec UE: failed to tighten SA lifetime");
                        }
                    });
                }
            }

            registrant.handle_success(&aor, expires);
        }
        401 | 407 => {
            // Parse challenge header
            let header_name = if status_code == 401 {
                "WWW-Authenticate"
            } else {
                "Proxy-Authenticate"
            };

            let challenge_raw = match message.headers.get(header_name) {
                Some(raw) => raw.clone(),
                None => {
                    warn!(aor = %aor, status_code, "registrant: {status_code} without {header_name}");
                    registrant.handle_failure(&aor, status_code, retry_after);
                    return;
                }
            };

            if let Some(challenge) = crate::auth::parse_challenge(&challenge_raw) {
                // IMS AKA + IPsec sec-agree: parse the P-CSCF's Security-Server,
                // build the protected re-REGISTER (which stashes CK/IK), install
                // the UE SAs, then send over the SA. The install MUST precede the
                // send so the kernel encrypts the protected REGISTER — both run
                // ordered inside one spawned task (TS 33.203 §7.4).
                if is_aka && registrant.is_ipsec_entry(&aor) {
                    handle_registrant_ipsec_challenge(registrant, message, &aor, &challenge, status_code, retry_after, state);
                    return;
                }

                // IMS AKA entries run Milenage over the RAND/AUTN in the nonce;
                // carrier-trunk entries use password digest. The IMS challenge
                // always arrives as a 401 (WWW-Authenticate).
                let built = if is_aka {
                    registrant.build_register_aka(
                        &aor,
                        state.local_addr,
                        &state.listen_addrs,
                        &challenge,
                        registrant.default_interval,
                        None,
                    )
                } else {
                    registrant.build_register_with_auth(
                        &aor,
                        state.local_addr,
                        &state.listen_addrs,
                        &challenge,
                        status_code == 407,
                        registrant.default_interval,
                    )
                };

                if let Some((retry_message, _retry_branch, destination, transport)) = built {
                    let data = bytes::Bytes::from(retry_message.to_bytes());
                    send_outbound(data, transport, destination, crate::transport::ConnectionId::default(), state);
                } else {
                    registrant.handle_failure(&aor, status_code, retry_after);
                }
            } else {
                warn!(aor = %aor, "failed to parse digest challenge from {header_name}");
                registrant.handle_failure(&aor, status_code, retry_after);
            }
        }
        _ => {
            registrant.handle_failure(&aor, status_code, retry_after);
        }
    }
}

/// Handle a 401 challenge for an IPsec sec-agree (UE) registration.
///
/// Records the P-CSCF's Security-Server answer, builds the protected
/// re-REGISTER (which stashes CK/IK on the entry), then installs the four UE
/// SAs and sends the REGISTER over them. The SA install and the send run
/// ordered inside one spawned task so the kernel encrypts the protected
/// REGISTER (3GPP TS 33.203 §7.4) — sourced from the UE protected client port
/// so the outbound XFRM selector matches.
fn handle_registrant_ipsec_challenge(
    registrant: &Arc<crate::registrant::RegistrantManager>,
    message: &SipMessage,
    aor: &str,
    challenge: &crate::auth::DigestChallenge,
    status_code: u16,
    retry_after: Option<std::time::Duration>,
    state: &DispatcherState,
) {
    match message.headers.get("Security-Server").cloned() {
        Some(server_raw) => match crate::ipsec::parse_security_client(&server_raw) {
            Some(server) => registrant.store_security_server(aor, &server, &server_raw),
            None => {
                warn!(aor = %aor, "IPsec UE: unparseable Security-Server, failing registration");
                registrant.handle_failure(aor, status_code, retry_after);
                return;
            }
        },
        None => {
            warn!(aor = %aor, "IPsec UE: 401 without Security-Server, failing registration");
            registrant.handle_failure(aor, status_code, retry_after);
            return;
        }
    }

    // build_register_aka stashes CK/IK and targets the P-CSCF protected server
    // port; the Security-Verify echoes the Security-Server recorded above.
    let verify = registrant.security_server_value(aor);
    let built = registrant.build_register_aka(
        aor,
        state.local_addr,
        &state.listen_addrs,
        challenge,
        registrant.default_interval,
        verify.as_deref(),
    );
    let (retry_message, destination, transport) = match built {
        Some((retry_message, _branch, destination, transport)) => (retry_message, destination, transport),
        None => {
            registrant.handle_failure(aor, status_code, retry_after);
            return;
        }
    };

    let ue_addr = state.local_addr.ip();
    let pcscf_addr = destination.ip();
    let ue_port_c = registrant.ue_protected_client_port(aor).unwrap_or(0);
    // Placeholder lifetime; tightened to the granted Expires on the 200 OK.
    let sa = registrant.ue_sa_pair(
        aor,
        ue_addr,
        pcscf_addr,
        Some(registrant.default_interval as u64),
        crate::ipsec::SaProtocol::Any,
    );

    let ipsec_manager = match state.ipsec_manager.clone() {
        Some(manager) => manager,
        None => {
            warn!(aor = %aor, "IPsec UE: no IpsecManager configured, failing registration");
            registrant.handle_failure(aor, status_code, retry_after);
            return;
        }
    };

    let source = std::net::SocketAddr::new(ue_addr, ue_port_c);
    let data = bytes::Bytes::from(retry_message.to_bytes());
    let outbound = state.outbound.clone();
    let registrant_task = Arc::clone(registrant);
    let aor_task = aor.to_string();

    tokio::spawn(async move {
        let sa = match sa {
            Some(sa) => sa,
            None => {
                warn!(aor = %aor_task, "IPsec UE: missing CK/IK or Security-Server, protected REGISTER not sent");
                registrant_task.handle_failure(&aor_task, 0, None);
                return;
            }
        };
        // Re-REGISTER rekey: tear down any prior SA pair on the same UE
        // protected client port before installing the new one. The UE keeps
        // fixed protected ports, so old and new cannot overlap (their XFRM
        // policy selectors would collide) — delete-before-install avoids the
        // collision and the leak; no-op on the first registration. (Full
        // TS 33.203 §6.3 old/new overlap would need fresh ports per
        // registration, i.e. runtime listener binding.)
        let _ = ipsec_manager.delete_sa_pair(&ue_addr, ue_port_c).await;
        if let Err(error) = ipsec_manager.create_ue_sa_pair(sa).await {
            warn!(aor = %aor_task, %error, "IPsec UE: SA install failed, protected REGISTER not sent");
            registrant_task.handle_failure(&aor_task, 0, None);
            return;
        }
        let outbound_message = crate::transport::OutboundMessage {
            connection_id: crate::transport::ConnectionId::default(),
            transport,
            destination,
            data,
            source_local_addr: Some(source),
            server_name: None,
        };
        if let Err(error) = outbound.send(outbound_message) {
            warn!(aor = %aor_task, %error, "IPsec UE: failed to send protected REGISTER");
        }
    });
}

/// Expand a route-set header (Service-Route, P-Associated-URI, Path) into its
/// individual values: each header line plus any comma-folded values within it,
/// splitting only on top-level commas (not inside `<...>` or quotes).
fn collect_route_set(message: &SipMessage, header_name: &str) -> Vec<String> {
    let mut values = Vec::new();
    if let Some(lines) = message.headers.get_all(header_name) {
        for line in lines {
            let mut start = 0;
            let mut depth = 0i32;
            let mut in_quotes = false;
            for (index, byte) in line.bytes().enumerate() {
                match byte {
                    b'"' => in_quotes = !in_quotes,
                    b'<' if !in_quotes => depth += 1,
                    b'>' if !in_quotes => depth -= 1,
                    b',' if !in_quotes && depth == 0 => {
                        let part = line[start..index].trim();
                        if !part.is_empty() {
                            values.push(part.to_string());
                        }
                        start = index + 1;
                    }
                    _ => {}
                }
            }
            let tail = line[start..].trim();
            if !tail.is_empty() {
                values.push(tail.to_string());
            }
        }
    }
    values
}

/// Maximum credentialed outbound INVITEs the B2BUA will send on the 401/407
/// digest auto-retry path per call before treating further challenges as a
/// persistent auth failure and surfacing the response upstream. RFC has no
/// fixed number; 2 covers the normal single-challenge (and one stale-nonce
/// re-challenge) case while bounding a misconfigured-credentials loop.
const MAX_B2BUA_AUTH_RETRIES: u32 = 2;

/// Handle a response to a B2BUA B-leg INVITE.
fn handle_b2bua_response(
    call_id: &str,
    branch: &str,
    message: &mut SipMessage,
    status_code: u16,
    response_source: SocketAddr,
    state: &DispatcherState,
) {
    debug!(
        call_id = %call_id,
        branch = %branch,
        status = status_code,
        "B2BUA: received B-leg response"
    );

    // Get the A-leg info and stored INVITE for handler reconstruction.
    // Extract everything we need then drop the DashMap ref before entering Python.
    let (a_leg, a_leg_invite, b_leg_target, b_leg_remote_contact, _b_leg_local_contact, b_leg_dialog, b_leg_dest, b_leg_connection_id, b_leg_index, b_leg_stored_vias, b_leg_stored_cseq, call_state, outbound_credentials, li_record, b_leg_handle_tx, b_leg_stored_invite, b_leg_local_cseq, a_leg_supports_100rel, a_leg_local_addr) = match state.call_actors.get_call(call_id) {
        Some(call) => {
            let matching_b_idx = call.b_legs.iter().position(|b| b.branch == branch);
            let matching_b = matching_b_idx.map(|i| &call.b_legs[i]);
            let target = matching_b.map(|b| b.dialog.target_uri.clone().unwrap_or_default());
            let remote_contact = matching_b.and_then(|b| b.dialog.remote_contact.clone());
            let local_contact = matching_b.and_then(|b| b.dialog.local_contact.clone());
            let dialog = matching_b.map(|b| (b.dialog.call_id.clone(), b.dialog.local_tag.clone()));
            let dest = matching_b.map(|b| (b.transport.remote_addr, b.transport.transport));
            // The connection_id the original B-leg INVITE was sent on — reused
            // by the 401/407 retry path so the credentialed re-INVITE stays on
            // the same trunk member that issued the nonce (RFC 5923).
            let connection_id = matching_b.map(|b| b.transport.connection_id).unwrap_or_default();
            let stored_vias = matching_b.map(|b| b.stored_vias.clone()).unwrap_or_default();
            let stored_cseq = matching_b.and_then(|b| b.stored_cseq.clone());
            let handle_tx = matching_b_idx
                .and_then(|i| call.b_leg_handles.get(i))
                .and_then(|h| h.as_ref())
                .map(|h| h.tx.clone());
            let stored_invite = matching_b.and_then(|b| b.b_leg_invite.clone());
            let local_cseq = matching_b.map(|b| b.dialog.local_cseq).unwrap_or(2);
            (call.a_leg.clone(), call.a_leg_invite.clone(), target, remote_contact, local_contact, dialog, dest, connection_id, matching_b_idx, stored_vias, stored_cseq, call.state.clone(), call.outbound_credentials.clone(), call.li_record, handle_tx, stored_invite, local_cseq, call.a_leg_supports_100rel, call.a_leg_local_addr)
        }
        None => {
            warn!(call_id = %call_id, "B2BUA: response for unknown call");
            return;
        }
    };

    // The A-leg peer's advertised reliable-provisional capability (RFC 3262 §3),
    // snapshotted from the on-wire INVITE at receipt (CallActor.a_leg_supports_100rel)
    // — NOT re-derived from `a_leg_invite`, which the `@b2bua.on_invite` script
    // can mutate via `call.set_header` to advertise 100rel toward the B-leg.
    // Drives the framework-auto `100rel` strip in `sanitize_b2bua_response` so we
    // never forward a reliable provisional to an A-leg (e.g. a PSTN trunk) that
    // can't PRACK it.  Passed to every sanitize call: the responses sanitized
    // below all flow to the A-leg (or, for the B→A re-INVITE/UPDATE direction,
    // are produced by the A-leg — so a non-100rel A-leg never emits the markers
    // and the strip is a no-op there anyway).

    // RFC 3262 auto-PRACK for the B-leg side: when the B-leg sends a
    // reliable provisional response (`Require: 100rel` + `RSeq: <n>`),
    // the B2BUA must answer with a PRACK. We do that locally here using
    // the B-leg dialog state so a non-100rel A-leg sees an ordinary 1xx (the
    // `Require`/`RSeq` headers are stripped in `sanitize_b2bua_response` when
    // the A-leg didn't advertise 100rel — preset-independent).
    // We don't track a client transaction for the PRACK — the B-leg's
    // 200 OK PRACK that comes back will hit the response handler with no
    // matching session and be dropped, which is the correct behavior here.
    let needs_prack = (100..200).contains(&status_code)
        && status_code != 100
        && crate::sip::headers::rseq::requires_100rel(&message.headers);
    if needs_prack {
        if let (Some(rseq), Some(idx)) = (
            crate::sip::headers::rseq::parse_rseq(&message.headers),
            b_leg_index,
        ) {
            // Skip if we've already PRACKed this RSeq — the B-leg is just
            // retransmitting the reliable 1xx because our PRACK is in
            // flight or got delayed; one PRACK per RSeq is correct.
            if !state.call_actors.try_mark_prack_acked(call_id, idx, rseq.response_number) {
                debug!(
                    call_id = %call_id,
                    rseq = rseq.response_number,
                    "B2BUA: already PRACKed this RSeq, skipping"
                );
                // Still need to strip Require/RSeq from forwarded 1xx (done
                // in sanitize_b2bua_response below); fall through.
                let _ = ();
                // We DO want to fall through to the rest of the function so
                // the 1xx still reaches the A-leg.
            } else {
            // RFC 3262 §4 + RFC 3261 §12.1.2: a reliable provisional response
            // establishes the early dialog, whose route set is THIS response's
            // Record-Route reversed (UAC side). The confirmed-dialog route set
            // isn't captured until the 200 OK, so without this the PRACK is built
            // with no Route header and sent to the cached INVITE next-hop (e.g. an
            // IMS I-CSCF that doesn't Record-Route and rejects the in-dialog PRACK
            // with 406). Establish it once (§12.1.2 — not updated by later
            // responses), so build_b2bua_prack and resolve_in_dialog_destination
            // both pick the route-set first hop (the S-CSCF).
            let early_routes = uac_route_set_from_record_routes(
                &message.headers.get_all("Record-Route").cloned().unwrap_or_default(),
            );
            if !early_routes.is_empty() {
                if let Some(mut call) = state.call_actors.get_call_mut(call_id) {
                    if let Some(leg) = call.b_legs.get_mut(idx) {
                        if leg.dialog.route_set.is_empty() {
                            leg.dialog.route_set = early_routes;
                        }
                    }
                }
            }

            // Pull CSeq num + method from the 1xx (it echoes the INVITE's).
            let response_cseq_num: u32 = message.headers.cseq()
                .and_then(|c| c.split_whitespace().next())
                .and_then(|n| n.parse().ok())
                .unwrap_or(1);
            let response_cseq_method = message.headers.cseq()
                .and_then(|c| c.split_whitespace().nth(1))
                .map(|s| s.to_string())
                .unwrap_or_else(|| "INVITE".to_string());

            if let Some(prack_cseq) = state.call_actors.next_b_leg_local_cseq(call_id, idx) {
                // Re-snapshot the leg now that we may have mutated it.
                let prack = state.call_actors.get_call(call_id).and_then(|call| {
                    let leg = call.b_legs.get(idx)?;
                    build_b2bua_prack(
                        leg,
                        state,
                        rseq.response_number,
                        response_cseq_num,
                        &response_cseq_method,
                        prack_cseq,
                    )
                });
                if let Some(prack) = prack {
                    if let Some((dest, transport)) = b_leg_dest {
                        // PRACK follows the early-dialog route set (RFC 3262 §4
                        // + RFC 3261 §12.2.1.1), captured from this reliable
                        // 1xx's Record-Route just above. When the 1xx carried no
                        // Record-Route (direct B-leg, no proxies) the set is
                        // empty and resolve_in_dialog_destination falls back to
                        // the cached destination, which is correct there.
                        let leg_route_set = state.call_actors.get_call(call_id)
                            .and_then(|call| {
                                call.b_legs.get(idx).map(|leg| leg.dialog.route_set.clone())
                            })
                            .unwrap_or_default();
                        let (destination, prack_transport) = resolve_in_dialog_destination(
                            &leg_route_set,
                            state,
                            dest,
                            transport,
                        );
                        debug!(
                            call_id = %call_id,
                            rseq = rseq.response_number,
                            %destination,
                            "B2BUA: sending auto-PRACK for reliable 1xx from B-leg"
                        );
                        send_b2bua_to_bleg(prack, prack_transport, destination, state);
                    }
                }
            }
            } // close `else` (first-time-this-RSeq branch)
        }
    }

    // Absorb the B-leg's 200 OK PRACK so it never gets forwarded to the
    // A-leg (the A-leg never sent a PRACK — siphon did, locally). The
    // CSeq method on the response distinguishes it from the INVITE 200.
    if (200..300).contains(&status_code)
        && message.headers.cseq()
            .and_then(|c| c.split_whitespace().nth(1))
            .map(|m| m.eq_ignore_ascii_case("PRACK"))
            .unwrap_or(false)
    {
        debug!(
            call_id = %call_id,
            "B2BUA: absorbing B-leg 200 OK PRACK"
        );
        return;
    }

    // Handle retransmitted 200 OK for already-completed re-INVITEs.
    // The entry was marked "reinvite_done:<dir>" after the first 200 OK was processed.
    // Just re-ACK the responder to stop retransmissions — don't forward again.
    if let Some(done_direction) = b_leg_target.as_deref().and_then(|t| t.strip_prefix("reinvite_done:")) {
        if (200..300).contains(&status_code) {
            let is_a2b = done_direction == "a2b";
            if let Some((responder_dest, responder_transport)) = b_leg_dest {
                if let Some((ref responder_cid, ref _responder_ftag)) = b_leg_dialog {
                    let transport_str = format!("{}", responder_transport).to_uppercase();
                    // ACK Via sent-by port: the responder's anchored listener. When
                    // the responder is the A-leg (B→A re-INVITE, !is_a2b) that's the
                    // arrival socket on a multi-homed host; otherwise the default.
                    let outbound_port = a_leg_advertised_port(
                        if is_a2b { None } else { a_leg.transport.local_addr },
                        state.listen_addrs.get(&responder_transport)
                            .map(|a| a.port())
                            .unwrap_or(state.local_addr.port()),
                    );
                    let cseq_num = message.headers.cseq()
                        .and_then(|c| c.split_whitespace().next().map(|s| s.to_string()))
                        .unwrap_or_else(|| "1".to_string());
                    let from = message.headers.from().cloned().unwrap_or_default();
                    let to = message.headers.to().cloned().unwrap_or_default();
                    // RURI: extract Contact from the 200 OK message directly
                    // (RFC 3261 §12.2.1.1), with fallback to stored remote_contact.
                    let ack_uri = message.headers.get("Contact")
                        .or_else(|| message.headers.get("m"))
                        .map(|c| crate::b2bua::actor::extract_contact_uri(c))
                        .and_then(|u| parse_uri_standalone(&u).ok())
                        .or_else(|| if is_a2b {
                            b_leg_remote_contact.as_deref()
                                .and_then(|u| parse_uri_standalone(u).ok())
                        } else {
                            a_leg.dialog.remote_contact.as_deref()
                                .and_then(|u| parse_uri_standalone(u).ok())
                        })
                        .unwrap_or_else(|| SipUri::new(responder_dest.ip().to_string())
                            .with_port(responder_dest.port()));
                    let ack = match SipMessageBuilder::new()
                        .request(Method::Ack, ack_uri)
                        .via(format!(
                            "SIP/2.0/{} {}:{};branch={}",
                            transport_str,
                            format_sip_host(&state.local_addr.ip().to_string()),
                            outbound_port,
                            TransactionKey::generate_branch(),
                        ))
                        .from(from.to_string())
                        .to(to.to_string())
                        .call_id(responder_cid.clone())
                        .cseq(format!("{} ACK", cseq_num))
                        .header("Max-Forwards", "70".to_string())
                        .content_length(0)
                        .build()
                    {
                        Ok(ack) => ack,
                        Err(error) => {
                            error!("B2BUA ACK for re-INVITE 2xx retransmit build failed: {error}");
                            return;
                        }
                    };
                    if is_a2b {
                        send_b2bua_to_bleg(ack, responder_transport, responder_dest, state);
                    } else {
                        // ACK to the A-leg responder — source it from the A-leg's
                        // anchored socket (multi-homed source-port parity; Via above
                        // matches). No-op for single-listener hosts.
                        send_message_from(ack, responder_transport, responder_dest, a_leg.transport.connection_id, a_leg.transport.local_addr, state);
                    }
                    debug!(
                        call_id = %call_id,
                        "B2BUA: re-ACKed retransmitted 200 OK for completed re-INVITE"
                    );
                }
            }
        } else {
            debug!(
                call_id = %call_id,
                status = status_code,
                "B2BUA: absorbing retransmitted non-2xx for completed re-INVITE"
            );
        }
        return;
    }

    // Handle retransmitted responses for already-completed UPDATEs.
    // Per RFC 3311 §5.4 there is no ACK for UPDATE — just absorb the dup
    // and let the responder's non-INVITE server transaction stop on its own.
    if b_leg_target.as_deref().is_some_and(|t| t.starts_with("update_done:")) {
        debug!(
            call_id = %call_id,
            status = status_code,
            "B2BUA: absorbing retransmitted response for completed UPDATE"
        );
        return;
    }

    // Detect re-INVITE responses: target_uri starts with "reinvite:".
    // Re-INVITE tracking legs don't have actors — handled directly below.
    let reinvite_direction = b_leg_target.as_deref().and_then(|t| t.strip_prefix("reinvite:"));

    if let Some(direction) = reinvite_direction {
        let is_a2b = direction == "a2b";

        // Determine where to route the response: back to the leg that sent the re-INVITE.
        // A→B re-INVITE: response goes to A-leg, rewrite B-leg→A-leg headers
        // B→A re-INVITE: response goes to B-leg, rewrite A-leg→B-leg headers
        let (resp_dest, resp_transport, resp_conn_id) = if is_a2b {
            (a_leg.transport.remote_addr, a_leg.transport.transport, a_leg.transport.connection_id)
        } else {
            // B→A: send response to winning B-leg
            match state.call_actors.get_call(call_id) {
                Some(call) => {
                    let winner = call.winner.and_then(|i| call.b_legs.get(i));
                    if let Some(b) = winner {
                        (b.transport.remote_addr, b.transport.transport, ConnectionId::default())
                    } else {
                        warn!(call_id = %call_id, "B2BUA re-INVITE response: no winning B-leg");
                        return;
                    }
                }
                None => return,
            }
        };

        if is_a2b {
            // A→B: response from B-leg → rewrite B-leg identifiers back to A-leg
            if let Some((ref _b_cid, ref b_ftag)) = b_leg_dialog {
                crate::b2bua::actor::Dialog::rewrite_headers(
                    message,
                    &a_leg.dialog.call_id,
                    b_ftag,
                    a_leg.dialog.remote_tag.as_deref().unwrap_or(""),
                    Some(&a_leg.dialog.local_tag),
                );
            }
        } else {
            // B→A: response from A-leg → rewrite A-leg identifiers back to B-leg
            if let Some(call) = state.call_actors.get_call(call_id) {
                if let Some(winner) = call.winner.and_then(|i| call.b_legs.get(i)) {
                    crate::b2bua::actor::Dialog::rewrite_headers(
                        message,
                        &winner.dialog.call_id,
                        a_leg.dialog.remote_tag.as_deref().unwrap_or(""),
                        &winner.dialog.local_tag,
                        winner.dialog.remote_tag.as_deref(),
                    );
                }
            }
        }

        // Capture responder's CSeq before we overwrite it with the originator's.
        // The ACK sent to the responder must use the responder's CSeq (the one used
        // in the forwarded re-INVITE), not the originator's.
        let responder_cseq_num = message.headers.cseq()
            .and_then(|c| c.split_whitespace().next().map(|s| s.to_string()))
            .unwrap_or_else(|| "1".to_string());

        // Replace Via(s) and CSeq — restore the originator's Via headers and CSeq
        // from the re-INVITE (stored_vias/stored_cseq), NOT from the initial INVITE.
        // Both A→B and B→A use stored values captured when the re-INVITE arrived.
        message.headers.set_all("Via", b_leg_stored_vias.clone());
        // Restore originator's CSeq (RFC 3261 §8.2.6.2 — response CSeq MUST
        // match the request being responded to, which is the originator's re-INVITE).
        if let Some(ref cseq) = b_leg_stored_cseq {
            message.headers.set("CSeq", cseq.clone());
        }

        // A-facing (is_a2b) response: anchor Contact to the A-leg's arrival socket;
        // B-facing: leave it to via_port (the B-side advertised address).
        sanitize_b2bua_response(message, state, resp_transport, if is_a2b { a_leg_local_addr } else { None }, a_leg_supports_100rel, call_id);

        // RTPEngine: rewrite re-INVITE 2xx response SDP through answer.
        // Mirrors the offer processing done on the request side.
        if (200..300).contains(&status_code) && !message.body.is_empty() {
            if let (Some(ref rtpengine_set), Some(ref media_sessions), Some(ref profiles)) =
                (&state.rtpengine_set, &state.rtpengine_sessions, &state.rtpengine_profiles)
            {
                let a_sip_call_id = &a_leg.dialog.call_id;
                if let Some(session) = media_sessions.get(a_sip_call_id) {
                    if let Some(profile) = profiles.get(&session.profile) {
                        // The answer comes from the opposite side of the offer.
                        // In RTPEngine: from_tag = offerer, to_tag = answerer.
                        let (answer_from, answer_to) = if is_a2b {
                            // A→B re-INVITE: A offered (from_tag), B answers (to_tag)
                            (session.from_tag.as_str(), session.to_tag.as_deref().unwrap_or(""))
                        } else {
                            // B→A re-INVITE: B offered (to_tag), A answers (from_tag)
                            (session.to_tag.as_deref().unwrap_or(session.from_tag.as_str()), session.from_tag.as_str())
                        };
                        let answer_flags = profile.answer.clone();
                        match tokio::task::block_in_place(|| {
                            tokio::runtime::Handle::current().block_on(
                                rtpengine_set.answer(&session.call_id, answer_from, answer_to, &message.body, &answer_flags)
                            )
                        }) {
                            Ok(rewritten_sdp) => {
                                message.body = rewritten_sdp;
                                message.headers.set("Content-Length", message.body.len().to_string());
                                debug!(call_id = %call_id, "RTPEngine: rewrote re-INVITE response SDP (answer)");
                            }
                            Err(error) => {
                                warn!(call_id = %call_id, "RTPEngine answer for re-INVITE failed: {error}");
                            }
                        }
                    }
                }
            }
        }

        // Helper: build and send ACK to the responder of the re-INVITE.
        // For 2xx: ACK uses a NEW branch (end-to-end, RFC 3261 §13.2.2.4).
        // For non-2xx: ACK uses the SAME branch (hop-by-hop, RFC 3261 §17.1.1.3).
        let send_reinvite_ack = |ack_branch: String, state: &DispatcherState| {
            if let Some((responder_dest, responder_transport)) = b_leg_dest {
                if let Some((ref responder_cid, ref _responder_ftag)) = b_leg_dialog {
                    let transport_str = format!("{}", responder_transport).to_uppercase();
                    // ACK Via sent-by port: the responder's anchored listener. When
                    // the responder is the A-leg (B→A re-INVITE, !is_a2b) that's the
                    // arrival socket on a multi-homed host; otherwise the default.
                    let outbound_port = a_leg_advertised_port(
                        if is_a2b { None } else { a_leg.transport.local_addr },
                        state.listen_addrs.get(&responder_transport)
                            .map(|a| a.port())
                            .unwrap_or(state.local_addr.port()),
                    );
                    // Use the responder's CSeq (captured before originator CSeq restoration).
                    let cseq_num = responder_cseq_num.clone();
                    let from = message.headers.from().cloned().unwrap_or_default();
                    let to = message.headers.to().cloned().unwrap_or_default();
                    // RURI: extract Contact from the 200 OK message directly
                    // (RFC 3261 §12.2.1.1), with fallback to stored remote_contact.
                    let ack_uri = message.headers.get("Contact")
                        .or_else(|| message.headers.get("m"))
                        .map(|c| crate::b2bua::actor::extract_contact_uri(c))
                        .and_then(|u| parse_uri_standalone(&u).ok())
                        .or_else(|| if is_a2b {
                            b_leg_remote_contact.as_deref()
                                .and_then(|u| parse_uri_standalone(u).ok())
                        } else {
                            a_leg.dialog.remote_contact.as_deref()
                                .and_then(|u| parse_uri_standalone(u).ok())
                        })
                        .unwrap_or_else(|| SipUri::new(responder_dest.ip().to_string())
                            .with_port(responder_dest.port()));
                    let ack = match SipMessageBuilder::new()
                        .request(Method::Ack, ack_uri)
                        .via(format!(
                            "SIP/2.0/{} {}:{};branch={}",
                            transport_str,
                            format_sip_host(&state.local_addr.ip().to_string()),
                            outbound_port,
                            ack_branch,
                        ))
                        .from(from.to_string())
                        .to(to.to_string())
                        .call_id(responder_cid.clone())
                        .cseq(format!("{} ACK", cseq_num))
                        .header("Max-Forwards", "70".to_string())
                        .content_length(0)
                        .build()
                    {
                        Ok(ack) => ack,
                        Err(error) => {
                            error!("B2BUA ACK for re-INVITE build failed: {error}");
                            return;
                        }
                    };
                    if is_a2b {
                        send_b2bua_to_bleg(ack, responder_transport, responder_dest, state);
                    } else {
                        // ACK to the A-leg responder — source it from the A-leg's
                        // anchored socket (multi-homed source-port parity; Via above
                        // matches). No-op for single-listener hosts.
                        send_message_from(ack, responder_transport, responder_dest, a_leg.transport.connection_id, a_leg.transport.local_addr, state);
                    }
                }
            }
        };

        if (200..300).contains(&status_code) {
            // ACK the responder with a new branch (end-to-end ACK for 2xx)
            send_reinvite_ack(TransactionKey::generate_branch(), state);
            debug!(
                call_id = %call_id,
                direction = direction,
                "B2BUA: sent ACK to responder for re-INVITE 2xx"
            );

            // Reset session timer on successful re-INVITE
            state.call_actors.reset_session_timer(call_id);

            // Mark the re-INVITE B-leg entry as done (not removed!) so that
            // retransmitted 200 OKs can still be matched and re-ACKed.
            // The entry will be cleaned up when the call terminates.
            if let Some(idx) = b_leg_index {
                state.call_actors.set_b_leg_target_uri(call_id, idx, format!("reinvite_done:{}", direction));
            }
            // RFC 3261 §14.1: the re-INVITE toward the target leg has
            // completed — clear the pending flag so a subsequent re-INVITE
            // (from either side) is allowed to start. `is_a2b` means the
            // re-INVITE was forwarded TOWARD the B-leg, so the pending flag
            // was set on the B-leg.
            state.call_actors.set_pending_reinvite(call_id, /*on_a_leg=*/ !is_a2b, false);
        } else if status_code >= 300 {
            // Non-2xx: ACK is hop-by-hop — reuse the SAME branch as the
            // forwarded re-INVITE (RFC 3261 §17.1.1.3).
            send_reinvite_ack(branch.to_string(), state);
            debug!(
                call_id = %call_id,
                direction = direction,
                status = status_code,
                "B2BUA: sent ACK to responder for re-INVITE non-2xx"
            );

            // Remove the re-INVITE B-leg entry — no retransmission expected
            // since the IST will transition Completed→Confirmed on our ACK.
            if let Some(idx) = b_leg_index {
                state.call_actors.remove_b_leg(call_id, idx);
            }
            // Clear pending-reinvite on the target leg (see comment above).
            state.call_actors.set_pending_reinvite(call_id, /*on_a_leg=*/ !is_a2b, false);
        }

        // Forward response to the originator
        if is_a2b {
            // A→B re-INVITE: the response goes to the A-leg — pin its arrival socket.
            send_message_from(message.clone(), resp_transport, resp_dest, resp_conn_id, a_leg_local_addr, state);
        } else {
            send_b2bua_to_bleg(message.clone(), resp_transport, resp_dest, state);
        }

        debug!(
            call_id = %call_id,
            status = status_code,
            direction = direction,
            "B2BUA: forwarded re-INVITE response"
        );
        return;
    }

    // Detect UPDATE responses: target_uri starts with "update:".
    // Mirrors the re-INVITE response routing — but no ACK is sent (RFC 3311
    // §5.4: UPDATE is a non-INVITE transaction). Body-aware media handling
    // matches the request side: SDP rewrite via rtpengine.answer only when
    // the response carries SDP (session-timer refresh has empty body).
    let update_direction = b_leg_target.as_deref().and_then(|t| t.strip_prefix("update:"));

    if let Some(direction) = update_direction {
        let is_a2b = direction == "a2b";

        let (resp_dest, resp_transport, resp_conn_id) = if is_a2b {
            (a_leg.transport.remote_addr, a_leg.transport.transport, a_leg.transport.connection_id)
        } else {
            match state.call_actors.get_call(call_id) {
                Some(call) => {
                    let winner = call.winner.and_then(|i| call.b_legs.get(i));
                    if let Some(b) = winner {
                        (b.transport.remote_addr, b.transport.transport, ConnectionId::default())
                    } else {
                        warn!(call_id = %call_id, "B2BUA UPDATE response: no winning B-leg");
                        return;
                    }
                }
                None => return,
            }
        };

        if is_a2b {
            if let Some((ref _b_cid, ref b_ftag)) = b_leg_dialog {
                crate::b2bua::actor::Dialog::rewrite_headers(
                    message,
                    &a_leg.dialog.call_id,
                    b_ftag,
                    a_leg.dialog.remote_tag.as_deref().unwrap_or(""),
                    Some(&a_leg.dialog.local_tag),
                );
            }
        } else if let Some(call) = state.call_actors.get_call(call_id) {
            if let Some(winner) = call.winner.and_then(|i| call.b_legs.get(i)) {
                crate::b2bua::actor::Dialog::rewrite_headers(
                    message,
                    &winner.dialog.call_id,
                    a_leg.dialog.remote_tag.as_deref().unwrap_or(""),
                    &winner.dialog.local_tag,
                    winner.dialog.remote_tag.as_deref(),
                );
            }
        }

        // Restore originator's Via and CSeq (RFC 3261 §8.2.6.2).
        message.headers.set_all("Via", b_leg_stored_vias.clone());
        if let Some(ref cseq) = b_leg_stored_cseq {
            message.headers.set("CSeq", cseq.clone());
        }

        // A-facing (is_a2b) response: anchor Contact to the A-leg's arrival socket;
        // B-facing: leave it to via_port (the B-side advertised address).
        sanitize_b2bua_response(message, state, resp_transport, if is_a2b { a_leg_local_addr } else { None }, a_leg_supports_100rel, call_id);

        // RTPEngine answer for UPDATE 2xx with SDP body (codec/precondition
        // re-negotiation). Empty-body 2xx (session-timer refresh) bypasses.
        if (200..300).contains(&status_code) && !message.body.is_empty() {
            if let (Some(ref rtpengine_set), Some(ref media_sessions), Some(ref profiles)) =
                (&state.rtpengine_set, &state.rtpengine_sessions, &state.rtpengine_profiles)
            {
                let a_sip_call_id = &a_leg.dialog.call_id;
                if let Some(session) = media_sessions.get(a_sip_call_id) {
                    if let Some(profile) = profiles.get(&session.profile) {
                        let (answer_from, answer_to) = if is_a2b {
                            (session.from_tag.as_str(), session.to_tag.as_deref().unwrap_or(""))
                        } else {
                            (session.to_tag.as_deref().unwrap_or(session.from_tag.as_str()), session.from_tag.as_str())
                        };
                        let answer_flags = profile.answer.clone();
                        match tokio::task::block_in_place(|| {
                            tokio::runtime::Handle::current().block_on(
                                rtpengine_set.answer(&session.call_id, answer_from, answer_to, &message.body, &answer_flags)
                            )
                        }) {
                            Ok(rewritten_sdp) => {
                                message.body = rewritten_sdp;
                                message.headers.set("Content-Length", message.body.len().to_string());
                                debug!(call_id = %call_id, "RTPEngine: rewrote UPDATE response SDP (answer)");
                            }
                            Err(error) => {
                                warn!(call_id = %call_id, "RTPEngine answer for UPDATE failed: {error}");
                            }
                        }
                    }
                }
            }
        }

        if (200..300).contains(&status_code) {
            // Session timer refresh on successful UPDATE (RFC 4028 §10).
            state.call_actors.reset_session_timer(call_id);

            // Mark the UPDATE entry done so retransmitted 2xx can be absorbed.
            if let Some(idx) = b_leg_index {
                state.call_actors.set_b_leg_target_uri(call_id, idx, format!("update_done:{}", direction));
            }
        } else if status_code >= 300 {
            // Non-2xx UPDATE — no ACK (UPDATE is non-INVITE), just remove the
            // tracking entry. The responder's non-INVITE server transaction
            // self-terminates (RFC 3261 §17.2.2).
            if let Some(idx) = b_leg_index {
                state.call_actors.remove_b_leg(call_id, idx);
            }
        }

        // Forward response to the originator.
        if is_a2b {
            // A→B UPDATE: the response goes to the A-leg — pin its arrival socket.
            send_message_from(message.clone(), resp_transport, resp_dest, resp_conn_id, a_leg_local_addr, state);
        } else {
            send_b2bua_to_bleg(message.clone(), resp_transport, resp_dest, state);
        }

        debug!(
            call_id = %call_id,
            status = status_code,
            direction = direction,
            "B2BUA: forwarded UPDATE response"
        );
        return;
    }

    // Route response through B-leg actor for classification.
    // The actor classifies the SIP response into a CallEvent (Provisional,
    // Answered, Failed). We send the message, block-recv the event, then
    // use the event to drive response handling below.
    // Re-INVITE tracking legs and retry legs may not have actors — fall
    // back to raw status_code classification in that case.
    let actor_event: Option<CallEvent> = if let Some(handle_tx) = &b_leg_handle_tx {
        let leg_transport = b_leg_dest.map(|(addr, transport)| LegTransport {
            remote_addr: addr,
            connection_id: ConnectionId::default(),
            transport,
            local_addr: None,
        }).unwrap_or_else(|| LegTransport {
            remote_addr: state.local_addr,
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: None,
        });
        match handle_tx.try_send(crate::b2bua::actor::LegMessage::SipInbound {
            message: message.clone(),
            source: leg_transport,
        }) {
            Ok(()) => {
                // Temporarily extract receiver to block on it.
                // Safe: dispatcher processes messages sequentially.
                // Skip stale CallEvent::Terminated from a superseded leg's
                // actor (401/407/422 retry → replace_b_leg) — see
                // recv_b_leg_classification_event for why consuming one here
                // would misclassify the B-leg 200 OK as provisional.
                if let Some((_, mut rx)) = state.call_event_receivers.remove(call_id) {
                    let event = recv_b_leg_classification_event(&mut rx);
                    state.call_event_receivers.insert(call_id.to_string(), rx);
                    event
                } else {
                    None
                }
            }
            Err(_) => {
                debug!(call_id = %call_id, "B2BUA: actor mailbox full, classifying directly");
                None
            }
        }
    } else {
        None
    };

    // On 2xx: sync remote_tag and remote_contact from response back to canonical CallActor.
    // The LegActor extracts this on its clone, but we need to update the
    // authoritative copy in the CallActorStore.
    if matches!(&actor_event, Some(CallEvent::Answered { .. })) {
        if let Some(idx) = b_leg_index {
            if let Some(mut call) = state.call_actors.get_call_mut(call_id) {
                if let Some(b_leg) = call.b_legs.get_mut(idx) {
                    if let Some(to_tag) = crate::b2bua::actor::extract_to_tag(message) {
                        // Splice the to-tag into remote_to_uri so in-dialog
                        // requests (UPDATE, re-INVITE, BYE) toward this leg
                        // can build a proper tagged To: header (RFC 3261
                        // §12.1.1). remote_to_uri was captured from the
                        // outbound INVITE which had no tag yet.
                        if let Some(ref to_uri) = b_leg.dialog.remote_to_uri {
                            if !to_uri.contains(";tag=") {
                                b_leg.dialog.remote_to_uri =
                                    Some(format!("{};tag={}", to_uri.trim_end(), to_tag));
                            }
                        }
                        b_leg.dialog.remote_tag = Some(to_tag);
                    }
                    // Capture B-leg's remote Contact (RFC 3261 §12.1.2: remote target from 2xx)
                    if let Some(contact) = message.headers.get("Contact")
                        .or_else(|| message.headers.get("m"))
                    {
                        b_leg.dialog.remote_contact = Some(
                            crate::b2bua::actor::extract_contact_uri(contact),
                        );
                    }
                }
            }
        }
    }

    // Event-driven response classification.
    // Actor events are authoritative when available; fall back to status_code.
    #[derive(Debug)]
    enum ResponseClass { Answered, Provisional, Failed }

    let class = match &actor_event {
        Some(CallEvent::Answered { .. }) => ResponseClass::Answered,
        Some(CallEvent::Provisional { status_code: code, .. }) if *code >= 180 => {
            ResponseClass::Provisional
        }
        Some(CallEvent::Failed { .. }) => ResponseClass::Failed,
        _ => {
            // No actor, filtered provisional (<180), or unexpected event
            if (200..300).contains(&status_code) { ResponseClass::Answered }
            else if (180..200).contains(&status_code) { ResponseClass::Provisional }
            else if status_code >= 300 { ResponseClass::Failed }
            else { return; } // 100 Trying from B-leg — absorb
        }
    };

    match class { ResponseClass::Answered => {
    // --- 2xx answer handling ---
    if (200..300).contains(&status_code) {
        // Absorb 200 OK retransmissions: if the call is already answered,
        // this is a retransmit from the B-leg (it hasn't received our ACK yet).
        // Only re-ACK if the B-leg has been ACKed (late ACK complete).
        // If still waiting for A-leg ACK, absorb silently.
        if call_state == CallState::Answered {
            // Check if B-leg has been ACKed yet (late ACK pattern)
            let b_leg_acked = b_leg_index
                .and_then(|idx| state.call_actors.get_call(call_id)
                    .and_then(|call| call.b_legs.get(idx).map(|b| b.initial_acked)))
                .unwrap_or(false);
            if !b_leg_acked {
                debug!(
                    call_id = %call_id,
                    "B2BUA: absorbing 200 OK retransmission (waiting for A-leg ACK)"
                );
                return;
            }
            debug!(
                call_id = %call_id,
                "B2BUA: absorbing 200 OK retransmission (already answered)"
            );
            // Re-send ACK to B-leg to stop retransmissions
            if let Some((b_dest, b_transport)) = b_leg_dest {
                if let Some((ref b_cid, _b_ftag)) = b_leg_dialog {
                    // Build a clean ACK from scratch — do NOT clone the 200 OK
                    // (cloning leaks response headers like User-Agent, Contact,
                    // Allow, Supported, etc. from the remote UA).
                    let request_uri = message.headers.get("Contact")
                        .or_else(|| message.headers.get("m"))
                        .map(|c| crate::b2bua::actor::extract_contact_uri(c))
                        .and_then(|u| parse_uri_standalone(&u).ok())
                        .or_else(|| b_leg_remote_contact.as_deref()
                            .and_then(|u| parse_uri_standalone(u).ok()))
                        .or_else(|| b_leg_target.as_deref()
                            .and_then(|u| parse_uri_standalone(u).ok()))
                        .unwrap_or_else(|| SipUri::new("invalid".to_string()));
                    let transport_str = format!("{}", b_transport).to_uppercase();
                    let outbound_port = state.listen_addrs.get(&b_transport)
                        .map(|a| a.port())
                        .unwrap_or(state.local_addr.port());
                    let cseq_num = message.headers.cseq()
                        .and_then(|c| c.split_whitespace().next().map(|s| s.to_string()))
                        .unwrap_or_else(|| "1".to_string());
                    let from = message.headers.from().cloned().unwrap_or_default();
                    let to = message.headers.to().cloned().unwrap_or_default();
                    let ack = match SipMessageBuilder::new()
                        .request(Method::Ack, request_uri)
                        .via(format!(
                            "SIP/2.0/{} {}:{};branch={}",
                            transport_str,
                            format_sip_host(&state.local_addr.ip().to_string()),
                            outbound_port,
                            TransactionKey::generate_branch(),
                        ))
                        .from(from.to_string())
                        .to(to.to_string())
                        .call_id(b_cid.clone())
                        .cseq(format!("{} ACK", cseq_num))
                        .header("Max-Forwards", "70".to_string())
                        .content_length(0)
                        .build()
                    {
                        Ok(ack) => ack,
                        Err(error) => {
                            error!("B2BUA ACK for 200 OK retransmission build failed: {error}");
                            return;
                        }
                    };
                    send_b2bua_to_bleg(ack, b_transport, b_dest, state);
                }
            }
            return;
        }

        // 2xx — call answered; record the winning B-leg
        state.call_actors.set_state(call_id, CallState::Answered);
        if let Some(idx) = b_leg_index {
            state.call_actors.set_winner(call_id, idx);
        }

        // CDR: stamp the answer time (cdr.auto_emit).
        cdr_mark_b2bua_answer(state, call_id, status_code);

        // Rf ACR-START on B2BUA call answer (TS 32.299 §6.2.2).
        // Fire-and-forget per TS 32.299 §6.5.
        if let Some(invite_arc) = &a_leg_invite {
            spawn_rf_b2bua_start(state, call_id, invite_arc);
        }

        // Wrap the 200 OK in Arc<Mutex<>> so Python handlers can modify SDP in-place
        let response_arc = Arc::new(std::sync::Mutex::new(message.clone()));

        // Invoke @b2bua.on_answer handlers with (PyCall, PyReply)
        let engine_state = state.engine.state();
        let handlers = engine_state.handlers_for(&HandlerKind::B2buaAnswer);
        if !handlers.is_empty() {
            if let Some(invite_arc) = &a_leg_invite {
                let py_call = PyCall::new(
                    call_id.to_string(),
                    Arc::clone(invite_arc),
                    a_leg.transport.remote_addr.ip().to_string(),
                    format!("{}", a_leg.transport.transport).to_lowercase(),
                );
                let py_reply = PyReply::new(Arc::clone(&response_arc))
                    .with_a_leg(Arc::clone(invite_arc))
                    .with_response_source(
                        response_source.ip().to_string(),
                        response_source.port(),
                    );

                Python::attach(|python| {
                    let call_obj = match Py::new(python, py_call) {
                        Ok(obj) => obj,
                        Err(error) => {
                            error!("failed to create PyCall for on_answer: {error}");
                            return;
                        }
                    };
                    let reply_obj = match Py::new(python, py_reply) {
                        Ok(obj) => obj,
                        Err(error) => {
                            error!("failed to create PyReply for on_answer: {error}");
                            return;
                        }
                    };

                    for handler in &handlers {
                        let callable = handler.callable.bind(python);
                        match callable.call1((call_obj.bind(python), reply_obj.bind(python))) {
                            Ok(ret) => {
                                if handler.is_async {
                                    if let Err(error) = run_coroutine(python, &ret) {
                                        error!("async B2BUA on_answer handler error: {error}");
                                    }
                                }
                            }
                            Err(error) => {
                                error!("B2BUA on_answer handler error: {error}");
                            }
                        }
                    }
                });
            } else {
                warn!(call_id = %call_id, "B2BUA: no stored A-leg INVITE for on_answer");
            }
        }
        // Resolve SRS URI from config when li.record() was called
        let li_srs_uri = if li_record { state.li_siprec_srs_uri.as_deref() } else { None };

        // RFC 4028: Activate session timer from negotiated 200 OK headers
        if let Some(ref timer_config) = state.session_timer_config {
            if timer_config.enabled {
                // Parse Session-Expires from 200 OK (e.g. "1800;refresher=uas")
                let Ok(response_lock) = response_arc.lock() else {
                    error!("response_arc lock poisoned during session timer parsing");
                    return;
                };
                let (negotiated_expires, negotiated_refresher) =
                    if let Some(se_header) = response_lock.headers.get("Session-Expires") {
                        let parts: Vec<&str> = se_header.split(';').collect();
                        let expires = parts[0].trim().parse::<u32>()
                            .unwrap_or(timer_config.session_expires);
                        let refresher = parts.iter()
                            .find(|p| p.trim().starts_with("refresher="))
                            .map(|p| p.trim().trim_start_matches("refresher=").to_string())
                            .unwrap_or_else(|| "b2bua".to_string());
                        (expires, refresher)
                    } else {
                        // Remote didn't include Session-Expires — use our config defaults
                        (timer_config.session_expires, "b2bua".to_string())
                    };
                drop(response_lock);

                let timer_state = crate::b2bua::actor::SessionTimerState {
                    session_expires: negotiated_expires,
                    refresher: negotiated_refresher.clone(),
                    last_refresh: std::time::Instant::now(),
                };
                state.call_actors.set_session_timer(call_id, timer_state);

                debug!(
                    call_id = %call_id,
                    session_expires = negotiated_expires,
                    refresher = %negotiated_refresher,
                    "B2BUA: session timer activated"
                );
            }
        }

        // Extract the (possibly SDP-modified) response and forward to A-leg
        let mut response = match Arc::try_unwrap(response_arc) {
            Ok(mutex) => mutex.into_inner().unwrap_or_else(|error| error.into_inner()),
            Err(arc) => arc.lock().unwrap_or_else(|error| error.into_inner()).clone(),
        };

        // Inject session timer headers into response forwarded to A-leg
        if let Some(ref timer_config) = state.session_timer_config {
            if timer_config.enabled {
                if response.headers.get("Supported").is_none() {
                    response.headers.add("Supported", "timer".to_string());
                }
                if response.headers.get("Session-Expires").is_none() {
                    response.headers.add(
                        "Session-Expires",
                        format!("{};refresher=uac", timer_config.session_expires),
                    );
                }
            }
        }

        // Rewrite B-leg dialog headers back to A-leg identifiers.
        // The To-tag MUST be rewritten to A-leg's local_tag (RFC 3261 §12.2.1.1):
        // B-leg 2xx carries the B-leg far end's tag in To, but the A-leg far
        // end will store whatever it sees there as its dialog's remote-tag and
        // match in-dialog requests against it. Without this rewrite, the BYE
        // we later send toward A — built with a_leg.dialog.local_tag (the
        // freshly generated sb-... tag) in its From — would mismatch the
        // stored remote tag and get 481 Call/Transaction Does Not Exist.
        if let Some((ref b_cid, ref b_ftag)) = b_leg_dialog {
            crate::b2bua::actor::Dialog::rewrite_headers(
                &mut response,
                &a_leg.dialog.call_id,
                b_ftag,
                a_leg.dialog.remote_tag.as_deref().unwrap_or(""),
                Some(&a_leg.dialog.local_tag),
            );
            let _ = (b_cid,); // Call-ID already set by rewrite_dialog_headers
        }

        // Replace B-leg Via(s) with A-leg Via(s) from the stored INVITE.
        // The B-leg response only carries our Via; the A-leg caller expects its own.
        // Also restore the A-leg's original CSeq (RFC 3261 §8.2.6.2 — response
        // CSeq MUST equal the request CSeq). The B-leg response carries the B-leg
        // CSeq which is in an independent numbering space.
        if let Some(invite_arc) = &a_leg_invite {
            if let Ok(invite) = invite_arc.lock() {
                if let Some(vias) = invite.headers.get_all("Via") {
                    response.headers.set_all("Via", vias.clone());
                }
                if let Some(cseq) = invite.headers.cseq() {
                    response.headers.set("CSeq", cseq.clone());
                }
            }
        }

        // Extract B-leg Record-Route BEFORE sanitization — needed for B-leg ACK Route set.
        // Per RFC 3261 §12.1.1, the ACK route set is the Record-Route from the 200 OK reversed.
        let b_leg_record_routes = response.headers.get_all("Record-Route")
            .cloned()
            .unwrap_or_default();

        // Sanitize B-leg headers before forwarding to A-leg
        sanitize_b2bua_response(&mut response, state, a_leg.transport.transport, a_leg_local_addr, a_leg_supports_100rel, call_id);

        // Restore A-leg Record-Route from the stored INVITE (same pattern as Via).
        // sanitize_b2bua_response strips all Record-Route (B-leg path). The A-leg
        // 200 OK must contain the A-leg Record-Route so the UAC can build its route set.
        if let Some(ref invite_arc) = a_leg_invite {
            if let Ok(invite) = invite_arc.lock() {
                if let Some(rrs) = invite.headers.get_all("Record-Route") {
                    response.headers.set_all("Record-Route", rrs.clone());
                }
            }
        }

        // Persist dialog route sets for in-dialog requests (BYE, re-INVITE).
        // Must happen before we consume the Record-Routes for ACK building.
        {
            // B-leg route set from B-leg 200 OK Record-Route, reversed per RFC 3261
            // §12.1.1. Reversal MUST happen after flattening — multiple URIs sharing one
            // header line stay in wire order until then.
            let b_routes = uac_route_set_from_record_routes(&b_leg_record_routes);
            // A-leg route set from stored INVITE's Record-Route (in order for UAS)
            let a_routes = a_leg_invite.as_ref()
                .and_then(|arc| arc.lock().ok())
                .and_then(|invite| invite.headers.get_all("Record-Route").cloned())
                .map(|rrs| flatten_record_route_headers(&rrs))
                .unwrap_or_default();

            if let Some(mut call) = state.call_actors.get_call_mut(call_id) {
                if let Some(winner) = call.winner {
                    if let Some(b_leg) = call.b_legs.get_mut(winner) {
                        debug!(
                            call_id = %call_id,
                            b_routes_count = b_routes.len(),
                            "B2BUA: stored B-leg dialog route set",
                        );
                        b_leg.dialog.route_set = b_routes.clone();
                    }
                }
                debug!(
                    call_id = %call_id,
                    a_routes_count = a_routes.len(),
                    "B2BUA: stored A-leg dialog route set",
                );
                call.a_leg.dialog.route_set = a_routes;
            }
        }

        // Late ACK pattern (RFC 3261 §14.1 compliant): do NOT ACK the B-leg
        // immediately. Instead, forward the 200 OK to A-leg and wait for A-leg's
        // ACK before ACKing B-leg. This keeps the B-leg INVITE transaction alive,
        // preventing the B-leg from sending re-INVITEs before the A-leg has ACKed.
        // The B-leg will retransmit 200 OK (Timer G) — we absorb those silently
        // until A-leg ACKs and we send our ACK to B-leg.
        if let Some((b_dest, b_transport)) = b_leg_dest {
            if let Some((ref b_cid, ref _b_ftag)) = b_leg_dialog {
                let ack_uri = message.headers.get("Contact")
                    .or_else(|| message.headers.get("m"))
                    .map(|c| crate::b2bua::actor::extract_contact_uri(c))
                    .and_then(|u| parse_uri_standalone(&u).ok())
                    .or_else(|| b_leg_remote_contact.as_deref()
                        .and_then(|u| parse_uri_standalone(u).ok()))
                    .or_else(|| b_leg_target.as_deref()
                        .and_then(|u| parse_uri_standalone(u).ok()))
                    .unwrap_or_else(|| SipUri::new("invalid".to_string()));
                let transport_str = format!("{}", b_transport).to_uppercase();
                let cseq_num = message.headers.cseq()
                    .and_then(|c| c.split_whitespace().next().map(|s| s.to_string()))
                    .unwrap_or_else(|| "1".to_string());
                let from = message.headers.from().cloned().unwrap_or_default();
                let to = message.headers.to().cloned().unwrap_or_default();

                // Build B-leg Route set from Record-Route (reversed per RFC 3261 §12.2.1.1).
                // Flatten BEFORE reversing — see flatten_record_route_headers comment.
                let b_leg_routes = uac_route_set_from_record_routes(&b_leg_record_routes);

                let mut ack_builder = SipMessageBuilder::new()
                    .request(Method::Ack, ack_uri)
                    .via(format!(
                        "SIP/2.0/{} {}:{};branch={}",
                        transport_str,
                        state.via_host(&b_transport),
                        state.via_port(&b_transport),
                        TransactionKey::generate_branch(),
                    ))
                    .from(from.to_string())
                    .to(to.to_string())
                    .call_id(b_cid.clone())
                    .cseq(format!("{} ACK", cseq_num))
                    .header("Max-Forwards", "70".to_string());

                // Add Route headers from reversed B-leg Record-Route
                for route in &b_leg_routes {
                    ack_builder = ack_builder.header("Route", route.clone());
                }

                if let Ok(ack) = ack_builder
                    .content_length(0)
                    .build()
                {
                    // ACK to 2xx is end-to-end and follows the dialog route set
                    // (RFC 3261 §13.2.2.4). Use the first Route URI as next hop
                    // rather than the cached B-leg destination, which may be an
                    // upstream that doesn't Record-Route (e.g. IMS I-CSCF).
                    let (ack_dest, ack_transport) = resolve_in_dialog_destination(
                        &b_leg_routes,
                        state,
                        b_dest,
                        b_transport,
                    );
                    if let Some(mut call) = state.call_actors.get_call_mut(call_id) {
                        call.pending_b_leg_ack = Some((ack, ack_transport, ack_dest));
                    }
                    debug!(call_id = %call_id, destination = %ack_dest, "B2BUA: deferred B-leg ACK until A-leg ACKs");
                }
            }
        }

        // Extract SDP body before forwarding (needed for SIPREC)
        let sdp_body = response.body.clone();

        // Clone the sanitized 2xx before it is moved into send_message so the
        // A-leg retransmit is byte-identical (RFC 3261 §13.3.1.4).
        let retransmit_2xx = response.clone();

        // Pin the reply egress socket to the listener the A-leg INVITE arrived on
        // (`a_leg_local_addr`) so a multi-homed UDP host answers on the same port
        // it received on — a peer doing symmetric signalling drops a 2xx sourced
        // from a different local port. No-op for TCP/TLS/WS/WSS (routed by the
        // accepted connection) and for a single-listener host (`udp_by_local` empty).
        send_message_from(
            response,
            a_leg.transport.transport,
            a_leg.transport.remote_addr,
            a_leg.transport.connection_id,
            a_leg_local_addr,
            state,
        );

        // Arm A-leg 2xx retransmission — the B2BUA has no IST for the A-leg, so
        // nothing else recovers a lost 200. Cancelled by the caller's ACK in the
        // late-ACK handler (search `uas_2xx_retransmits`). Done before the SIPREC
        // block below so its early returns can't skip it.
        arm_b2bua_2xx_retransmit(
            call_id,
            retransmit_2xx,
            a_leg.transport.transport,
            a_leg.transport.remote_addr,
            a_leg.transport.connection_id,
            a_leg_local_addr,
            state,
        );

        // SIPREC: start recording if configured for this call
        if let Some(srs_uri) = li_srs_uri {
            let sdp = &sdp_body;
            if let Some(invite_arc) = &a_leg_invite {
                let Ok(invite) = invite_arc.lock() else {
                    error!(call_id = %call_id, "invite_arc lock poisoned during SIPREC start");
                    return;
                };
                let caller_uri = invite.headers.get("From")
                    .map(|from| from.to_string())
                    .unwrap_or_default();
                let callee_uri = invite.headers.get("To")
                    .map(|to| to.to_string())
                    .unwrap_or_default();
                drop(invite);

                // RTPEngine subscribe: fork media to the recording leg.
                // Uses SIPREC-mode subscribe with from-tags containing both
                // monologue tags so RTPEngine returns a combined SDP with
                // 2 m= lines (one per call direction).
                let a_sip_call_id = a_leg.dialog.call_id.clone();

                // Look up the MediaSession to get both monologue tags that
                // RTPEngine knows about (from_tag = A-leg, to_tag = B-leg).
                let media_tags: Option<(String, String)> = state.rtpengine_sessions.as_ref()
                    .and_then(|sessions| sessions.get(&a_sip_call_id))
                    .and_then(|session| {
                        session.to_tag.as_ref().map(|to_tag| {
                            (session.from_tag.clone(), to_tag.clone())
                        })
                    });

                // Look up the SIPREC SRC RTPEngine profile for additional subscribe flags.
                let siprec_src_profile = state.li_siprec_rtpengine_profile.as_deref()
                    .and_then(|name| {
                        state.rtpengine_profiles.as_ref()
                            .and_then(|registry| registry.get(name).cloned())
                    });
                let siprec_src_flags = siprec_src_profile.as_ref().map(|profile| &profile.offer);

                let (mut caller_sdp, mut callee_sdp, subscriber_to_tag) = if let Some(ref rtpengine_set) = state.rtpengine_set {
                    // Build from-tags list with both monologue tags.
                    let from_tags: Vec<&str> = match &media_tags {
                        Some((from_tag, to_tag)) => vec![from_tag.as_str(), to_tag.as_str()],
                        None => {
                            warn!(call_id = %call_id, "SIPREC: no MediaSession tags found, subscribe may return only 1 stream");
                            vec![]
                        }
                    };

                    let result = tokio::task::block_in_place(|| {
                        tokio::runtime::Handle::current().block_on(
                            rtpengine_set.subscribe_request_siprec(&a_sip_call_id, &from_tags, siprec_src_flags)
                        )
                    });
                    match result {
                        Ok((sdp, to_tag)) => {
                            debug!(call_id = %call_id, sdp_len = sdp.len(), subscriber_to_tag = %to_tag, "SIPREC: subscribe_request_siprec OK");
                            // Fix direction (recvonly→sendonly) and add a=label per m= section.
                            let processed = crate::siprec::fix_siprec_subscribe_sdp(&sdp);
                            // Split the dual-m= SDP into per-direction parts so
                            // start_recording builds a proper 2-stream INVITE.
                            let (sdp1, sdp2) = crate::siprec::split_dual_sdp(&processed);
                            let has_two = sdp1 != sdp2;
                            if has_two {
                                (Some(sdp1), Some(sdp2), Some(to_tag))
                            } else {
                                // Single m= line — split returned two identical copies.
                                (Some(sdp1), None, Some(to_tag))
                            }
                        }
                        Err(error) => {
                            warn!(call_id = %call_id, %error, "SIPREC: subscribe_request_siprec failed");
                            (None, None, None)
                        }
                    }
                } else {
                    (None, None, None)
                };

                // Sanitize the subscribe SDPs to hide the original call's identity
                // (o=/s= lines may leak FreeSWITCH, Oracle, etc.).
                let local_ip = state.local_addr.ip().to_string();
                if let Some(ref mut sdp_bytes) = caller_sdp {
                    sanitize_sdp_identity(sdp_bytes, "siphon", Some(&local_ip));
                }
                if let Some(ref mut sdp_bytes) = callee_sdp {
                    sanitize_sdp_identity(sdp_bytes, "siphon", Some(&local_ip));
                }

                // For unsubscribe on BYE: SIPREC-mode uses empty from-tag and
                // the subscriber to-tag returned by RTPEngine.
                let tags_for_unsubscribe = subscriber_to_tag.as_ref().map(|tt| (String::new(), tt.clone()));
                let tags_ref = tags_for_unsubscribe.as_ref().map(|(ft, tt)| (ft.as_str(), tt.as_str()));
                if let Some((_session_id, rec_invite, destination, transport)) =
                    state.recording_manager.start_recording(
                        call_id, srs_uri, &caller_uri, &callee_uri, sdp, state.local_addr,
                        caller_sdp.as_deref(), callee_sdp.as_deref(),
                        Some(&a_sip_call_id), tags_ref,
                        state.user_agent_header.as_deref(),
                    )
                {
                    let data = Bytes::from(rec_invite.to_bytes());
                    let target = RelayTarget {
                        address: destination,
                        transport: Some(transport),
                        server_name: None,
                    };
                    send_to_target(data, &target, transport, ConnectionId::default(), None, state);
                }
            }
        }
    } // end 2xx guard

    } ResponseClass::Provisional => {
    // --- 1xx provisional handling ---
    {
        // 1xx provisional — forward to A-leg
        state.call_actors.set_state(call_id, CallState::Ringing);

        // Invoke @b2bua.on_early_media handlers when provisional has SDP body.
        // This lets scripts process early media through RTPEngine before forwarding.
        let has_sdp_body = !message.body.is_empty();
        if has_sdp_body {
            let engine_state = state.engine.state();
            let handlers = engine_state.handlers_for(&HandlerKind::B2buaEarlyMedia);
            if !handlers.is_empty() {
                if let Some(invite_arc) = &a_leg_invite {
                    let response_arc = Arc::new(std::sync::Mutex::new(message.clone()));
                    let py_call = PyCall::new(
                        call_id.to_string(),
                        Arc::clone(invite_arc),
                        a_leg.transport.remote_addr.ip().to_string(),
                        format!("{}", a_leg.transport.transport).to_lowercase(),
                    );
                    let py_reply = PyReply::new(Arc::clone(&response_arc))
                        .with_a_leg(Arc::clone(invite_arc))
                        .with_response_source(
                            response_source.ip().to_string(),
                            response_source.port(),
                        );

                    Python::attach(|python| {
                        let call_obj = match Py::new(python, py_call) {
                            Ok(obj) => obj,
                            Err(error) => {
                                error!("failed to create PyCall for on_early_media: {error}");
                                return;
                            }
                        };
                        let reply_obj = match Py::new(python, py_reply) {
                            Ok(obj) => obj,
                            Err(error) => {
                                error!("failed to create PyReply for on_early_media: {error}");
                                return;
                            }
                        };

                        for handler in &handlers {
                            let callable = handler.callable.bind(python);
                            match callable.call1((call_obj.bind(python), reply_obj.bind(python))) {
                                Ok(ret) => {
                                    if handler.is_async {
                                        if let Err(error) = run_coroutine(python, &ret) {
                                            error!("async B2BUA on_early_media handler error: {error}");
                                        }
                                    }
                                }
                                Err(error) => {
                                    error!("B2BUA on_early_media handler error: {error}");
                                }
                            }
                        }
                    });

                    // Replace message with potentially modified version (e.g. RTPEngine-rewritten SDP)
                    if let Ok(modified) = response_arc.lock() {
                        *message = modified.clone();
                    };
                } else {
                    warn!(call_id = %call_id, "B2BUA: no stored A-leg INVITE for on_early_media");
                }
            }
        }

        // Rewrite B-leg dialog headers back to A-leg identifiers.
        // For provisional responses that carry a To-tag (early dialogs —
        // 180/183 with tag), the rewrite ensures A-leg's view of the early
        // dialog matches its later view of the confirmed dialog (200 OK).
        if let Some((ref _b_cid, ref b_ftag)) = b_leg_dialog {
            crate::b2bua::actor::Dialog::rewrite_headers(
                message,
                &a_leg.dialog.call_id,
                b_ftag,
                a_leg.dialog.remote_tag.as_deref().unwrap_or(""),
                Some(&a_leg.dialog.local_tag),
            );
        }
        // Replace B-leg Via(s) and CSeq with A-leg originals from stored INVITE
        // (RFC 3261 §8.2.6.2 — response CSeq MUST equal request CSeq).
        if let Some(invite_arc) = &a_leg_invite {
            if let Ok(invite) = invite_arc.lock() {
                if let Some(vias) = invite.headers.get_all("Via") {
                    message.headers.set_all("Via", vias.clone());
                }
                if let Some(cseq) = invite.headers.cseq() {
                    message.headers.set("CSeq", cseq.clone());
                }
            }
        }
        // Sanitize B-leg headers before forwarding to A-leg
        sanitize_b2bua_response(message, state, a_leg.transport.transport, a_leg_local_addr, a_leg_supports_100rel, call_id);
        // Pin the reply egress socket to the A-leg INVITE's arrival listener
        // (`a_leg_local_addr`) so a multi-homed UDP host answers on the port it
        // received on. No-op for stream transports and single-listener hosts.
        send_message_from(
            message.clone(),
            a_leg.transport.transport,
            a_leg.transport.remote_addr,
            a_leg.transport.connection_id,
            a_leg_local_addr,
            state,
        );
    }

    } ResponseClass::Failed => {
    // --- 3xx+ error handling ---
    {
        // RFC 4028: 422 "Session Interval Too Small" — retry with higher Session-Expires
        if status_code == 422 {
            if let Some(ref timer_config) = state.session_timer_config {
                if timer_config.enabled {
                    let remote_min_se = message.headers.get("Min-SE")
                        .and_then(|v| v.split(';').next())
                        .and_then(|v| v.trim().parse::<u32>().ok());

                    if let (Some(min_se), Some(target_uri), Some(invite_arc)) =
                        (remote_min_se, &b_leg_target, &a_leg_invite)
                    {
                        if min_se > timer_config.session_expires {
                            info!(
                                call_id = %call_id,
                                min_se = min_se,
                                "B2BUA: 422 received, retrying with Session-Expires={min_se}"
                            );

                            // RFC 5923 connection reuse: keep the higher-
                            // Session-Expires retry on the SAME trunk member the
                            // 422'd INVITE traversed, instead of re-resolving the
                            // trunk hostname and round-robining onto a sibling
                            // member (see select_b2bua_retry_destination).
                            {
                                let (destination, transport, reuse_connection_id, relay_target) =
                                    match select_b2bua_retry_destination(
                                        b_leg_dest,
                                        b_leg_connection_id,
                                        target_uri,
                                        &state.dns_resolver,
                                    ) {
                                        Some(resolved) => resolved,
                                        None => return,
                                    };

                                // Build retry INVITE from stored A-leg INVITE
                                let Ok(original) = invite_arc.lock() else {
                                    error!(call_id = %call_id, "invite_arc lock poisoned during fork retry");
                                    return;
                                };
                                let mut retry = original.clone();
                                drop(original);

                                // Replace Via with new branch
                                let new_branch = TransactionKey::generate_branch();
                                let via_value = format!(
                                    "SIP/2.0/{} {}:{};branch={}",
                                    transport,
                                    state.via_host(&transport),
                                    state.via_port(&transport),
                                    new_branch,
                                );
                                retry.headers.set("Via", via_value);

                                // Update Request-URI
                                if let Ok(target_parsed) = parse_uri_standalone(target_uri) {
                                    retry.start_line = StartLine::Request(
                                        crate::sip::message::RequestLine {
                                            method: crate::sip::message::Method::Invite,
                                            request_uri: target_parsed,
                                            version: crate::sip::message::Version::sip_2_0(),
                                        },
                                    );
                                }

                                // Set updated session timer headers
                                retry.headers.remove("Session-Expires");
                                retry.headers.remove("Min-SE");
                                retry.headers.add(
                                    "Session-Expires",
                                    format!("{};refresher=uac", min_se),
                                );
                                retry.headers.add("Min-SE", min_se.to_string());

                                // Reuse B-leg dialog identifiers from the failed attempt.
                                // Retry source is the original A-leg INVITE — out-of-dialog,
                                // To has no tag, so pass None for new_to_tag.
                                let (retry_call_id, retry_from_tag) = b_leg_dialog.clone()
                                    .unwrap_or_else(|| (a_leg.dialog.call_id.clone(), a_leg.dialog.remote_tag.clone().unwrap_or_default()));
                                crate::b2bua::actor::Dialog::rewrite_headers(
                                    &mut retry,
                                    &retry_call_id,
                                    a_leg.dialog.remote_tag.as_deref().unwrap_or(""),
                                    &retry_from_tag,
                                    None,
                                );

                                let mut b_leg = Leg::new_b_leg(
                                    retry_call_id,
                                    retry_from_tag,
                                    target_uri.clone(),
                                    new_branch,
                                    LegTransport {
                                        remote_addr: destination,
                                        connection_id: reuse_connection_id,
                                        transport,
                                        local_addr: None,
                                    },
                                );
                                // Stash the retry INVITE so a caller CANCEL during
                                // alerting can rebuild the CANCEL from it (RFC 3261
                                // §9.1 — same Via branch + CSeq). The original 422'd
                                // leg's stash is discarded by the in-place supersede
                                // below; without re-stashing here the live retry
                                // transaction would be left un-cancellable.
                                b_leg.b_leg_invite = Some(Arc::new(Mutex::new(retry.clone())));

                                // RFC 4028: the 422'd INVITE transaction is complete,
                                // so the higher-Session-Expires retry continues the
                                // same logical B-leg — supersede in place rather than
                                // append (see the 401/407 path for why appending
                                // strands a dead leg that a later CANCEL hits).
                                match b_leg_index {
                                    Some(idx) => {
                                        state.call_actors.replace_b_leg(call_id, idx, b_leg.clone());
                                        spawn_b_leg_actor_at(call_id, &b_leg, idx, state);
                                    }
                                    None => {
                                        state.call_actors.add_b_leg(call_id, b_leg.clone());
                                        spawn_b_leg_actor(call_id, &b_leg, state);
                                    }
                                }

                                let data = Bytes::from(retry.to_bytes());
                                send_to_target(data, &relay_target, transport, reuse_connection_id, None, state);
                            }
                            return; // don't forward 422 to A-leg or fire on_failure
                        }
                    }
                }
            }
        }

        // 401/407 — auto-retry with digest credentials if available.
        //
        // The retry MUST be built from the B-leg's last-sent INVITE, NOT the
        // raw A-leg INVITE. The first B-leg INVITE went through the full
        // hygiene chain in `b2bua_send_b_leg_invite` (strip Record-Route /
        // Route / Authorization, replace Via / Contact / User-Agent, rewrite
        // From / To / P-Asserted-Identity host, regenerate Call-ID, set
        // CSeq=1, decrement Max-Forwards, sanitize SDP origin), plus any
        // script-side mutations applied before send. Cloning the A-leg INVITE
        // and only patching Via / RURI / Authorization (the old behaviour)
        // leaks every other A-leg header back to the B-leg.
        if status_code == 401 || status_code == 407 {
            // Cap credentialed retries per call. The per-leg dedup below stops a
            // *retransmitted* challenge from spawning a duplicate INVITE, but a
            // trunk that rejects every *fresh* credentialed attempt (wrong
            // password, or a new nonce each time) would otherwise re-auth
            // forever — each retry lands on a new branch, so there's no 482 to
            // self-terminate the loop (that was the pre-dedup failure mode).
            // Once MAX_B2BUA_AUTH_RETRIES credentialed INVITEs have gone out,
            // treat a further challenge as a persistent auth failure: ACK it and
            // surface the response upstream (fall through to @b2bua.on_failure +
            // forward to the A-leg) instead of looping. The per-leg dedup makes
            // this one-shot — retransmits of the surfaced challenge are absorbed.
            if outbound_credentials.is_some()
                && state.call_actors.auth_retry_count(call_id) >= MAX_B2BUA_AUTH_RETRIES
            {
                if let Some((b_dest, b_transport)) = b_leg_dest {
                    let ack = build_b2bua_ack_for_non2xx(
                        message,
                        branch,
                        b_leg_target.as_deref(),
                        b_transport,
                        &state.via_host(&b_transport),
                        state.via_port(&b_transport),
                    );
                    send_b2bua_to_bleg(ack, b_transport, b_dest, state);
                }
                let first = b_leg_index
                    .map(|idx| state.call_actors.try_mark_auth_challenged(call_id, idx))
                    .unwrap_or(true);
                if !first {
                    // Retransmit of an already-surfaced challenge — absorb.
                    return;
                }
                warn!(
                    call_id = %call_id,
                    status = status_code,
                    limit = MAX_B2BUA_AUTH_RETRIES,
                    "B2BUA: outbound auth retry limit reached — surfacing {status_code} upstream instead of re-authing"
                );
                // fall through to the failure path (on_failure + forward to A-leg)
            } else if let Some((username, password)) = &outbound_credentials {
                let challenge_header = if status_code == 401 {
                    message.headers.get("WWW-Authenticate")
                } else {
                    message.headers.get("Proxy-Authenticate")
                };

                if let Some(challenge_value) = challenge_header {
                    if let Some(challenge) = crate::auth::parse_challenge(challenge_value) {
                        if let (Some(target_uri), Some(stored_invite_arc)) = (&b_leg_target, &b_leg_stored_invite) {
                            // RFC 3261 §17.1.1.3: the INVITE client transaction
                            // MUST ACK every non-2xx final response on the branch
                            // it arrived on — the first 401/407 AND every
                            // retransmit. The trunk's server transaction keeps
                            // retransmitting the challenge until this ACK lands;
                            // skipping it (the old behaviour — this path returned
                            // before the non-2xx ACK below) leaves the trunk
                            // retransmitting until Timer B and feeds the re-retry
                            // bug guarded against next.
                            if let Some((b_dest, b_transport)) = b_leg_dest {
                                let ack = build_b2bua_ack_for_non2xx(
                                    message,
                                    branch,
                                    b_leg_target.as_deref(),
                                    b_transport,
                                    &state.via_host(&b_transport),
                                    state.via_port(&b_transport),
                                );
                                send_b2bua_to_bleg(ack, b_transport, b_dest, state);
                            }

                            // Only the FIRST challenge on this leg drives a retry.
                            // A retransmitted 401/407 on the same branch is the
                            // trunk re-sending its non-2xx (we just re-ACKed it),
                            // NOT a fresh challenge. Re-challenging would emit a
                            // second authenticated INVITE at the same CSeq on a
                            // new branch; the trunk sees a merged request
                            // (RFC 3261 §8.2.2.2) and replies 482, and we end up
                            // with two outstanding UAC branches where the real
                            // 2xx lands on the first while our state tracks the
                            // second — the 2xx then never gets ACKed and the
                            // trunk BYEs the call. A chained re-challenge (stale
                            // nonce) lands on the *retry* leg's branch, a distinct
                            // B-leg, so legitimate re-auth still proceeds.
                            let first_challenge = b_leg_index
                                .map(|idx| state.call_actors.try_mark_auth_challenged(call_id, idx))
                                .unwrap_or(true);
                            if !first_challenge {
                                debug!(
                                    call_id = %call_id,
                                    branch = %branch,
                                    status = status_code,
                                    "B2BUA: absorbing retransmitted challenge (auth retry already sent on this leg)"
                                );
                                return;
                            }

                            // Count this committed credentialed retry against the
                            // per-call cap checked at the top of the 401/407
                            // block. Placed after the per-leg dedup so retransmits
                            // (which returned above) never inflate the count.
                            state.call_actors.incr_auth_retry_count(call_id);

                            // RFC 7616 §3.3: nc starts at 1 for a fresh server
                            // nonce and increments on every reuse. The
                                // per-call NonceCounter resets internally when
                            // the nonce changes, so this is correct for both
                            // first challenge and same-nonce re-challenge
                            // (e.g. authenticated re-INVITE in the dialog).
                            let nc = state
                                .call_actors
                                .get_call(call_id)
                                .map(|call| call.digest_nc.next_for(&challenge.nonce))
                                .unwrap_or(1);

                            info!(
                                call_id = %call_id,
                                status = status_code,
                                realm = %challenge.realm,
                                nc = nc,
                                "B2BUA: {status_code} received, retrying with credentials"
                            );

                            let credentials = crate::auth::DigestCredentials {
                                username: username.clone(),
                                password: password.clone(),
                            };

                            let auth_header_name = if status_code == 401 {
                                "Authorization"
                            } else {
                                "Proxy-Authorization"
                            };

                            let auth_value = crate::auth::format_authorization_header(
                                &challenge,
                                &credentials,
                                "INVITE",
                                target_uri,
                                Some(nc),
                                None,
                            );

                            // RFC 5923 connection reuse: keep the authenticated
                            // retry on the SAME trunk member the CSeq-1 INVITE
                            // (and its 401 + nonce) traversed, instead of
                            // re-resolving the trunk hostname and round-robining
                            // onto a sibling member that never issued the nonce.
                            // See select_b2bua_retry_destination for the full
                            // rationale; it falls back to a fresh DNS resolution
                            // only when the leg has no recorded destination.
                            {
                                let (destination, transport, reuse_connection_id, relay_target) =
                                    match select_b2bua_retry_destination(
                                        b_leg_dest,
                                        b_leg_connection_id,
                                        target_uri,
                                        &state.dns_resolver,
                                    ) {
                                        Some(resolved) => resolved,
                                        None => return,
                                    };

                                // Build retry from the stored, hygiene-processed B-leg INVITE.
                                // Call-ID, From-tag, From-host, To, RURI, Contact, User-Agent,
                                // P-Asserted-Identity, Record-Route stripping, and the SDP body
                                // (anchored by rtpengine if applicable) are all already correct.
                                let new_branch = TransactionKey::generate_branch();
                                let via_value = format!(
                                    "SIP/2.0/{} {}:{};branch={}",
                                    transport,
                                    state.via_host(&transport),
                                    state.via_port(&transport),
                                    new_branch,
                                );
                                let retry = {
                                    let Ok(original) = stored_invite_arc.lock() else {
                                        error!(call_id = %call_id, "b_leg_invite lock poisoned during 401/407 retry");
                                        return;
                                    };
                                    // RFC 3261 §22.2: incremented CSeq for the retried request.
                                    // local_cseq was bumped past the original after first send,
                                    // so it now points at the next number to use.
                                    build_digest_retry_invite(
                                        &original,
                                        via_value,
                                        b_leg_local_cseq,
                                        auth_header_name,
                                        auth_value,
                                    )
                                };

                                // Reuse the failed B-leg's dialog identity (Call-ID +
                                // From-tag); the stored INVITE already carries them.
                                let (retry_call_id, retry_from_tag) = b_leg_dialog.clone()
                                    .unwrap_or_else(|| (a_leg.dialog.call_id.clone(), a_leg.dialog.remote_tag.clone().unwrap_or_default()));

                                let mut b_leg = Leg::new_b_leg(
                                    retry_call_id,
                                    retry_from_tag,
                                    target_uri.clone(),
                                    new_branch,
                                    LegTransport {
                                        remote_addr: destination,
                                        connection_id: reuse_connection_id,
                                        transport,
                                        local_addr: None,
                                    },
                                );
                                // Preserve dialog state from the failed attempt:
                                //  - local_cseq advances past the retry CSeq.
                                //  - local_contact / from_uri / to_uri stay so mid-dialog
                                //    requests on this leg work.
                                b_leg.dialog.local_cseq = b_leg_local_cseq.saturating_add(1);
                                b_leg.dialog.local_contact = retry.headers.get("Contact").cloned();
                                b_leg.dialog.local_from_uri = retry.headers.from().cloned();
                                b_leg.dialog.remote_to_uri = retry.headers.to().cloned();
                                if let Ok(target_parsed) = parse_uri_standalone(target_uri) {
                                    b_leg.dialog.remote_aor_host = Some(if let Some(port) = target_parsed.port {
                                        format!("{}:{}", target_parsed.host, port)
                                    } else {
                                        target_parsed.host.clone()
                                    });
                                }
                                // Persist the retry INVITE so a chained re-challenge
                                // (e.g. nonce stale) rebuilds from the right snapshot.
                                b_leg.b_leg_invite = Some(Arc::new(Mutex::new(retry.clone())));

                                // RFC 3261 §9.1: the CSeq-1 INVITE transaction is
                                // complete after its 401/407 + ACK, so the retry is
                                // the *same* logical B-leg continuing with credentials
                                // — supersede the failed leg in place rather than
                                // appending. Appending leaves the dead leg in
                                // `b_legs`, so a later CANCEL fans out to its
                                // already-final-responded transaction too (→ a
                                // spurious 481). `b_leg_index` is the slot the
                                // challenged response matched; it is always Some here
                                // (a B-leg response only reaches this path with a
                                // matched leg), but fall back to append defensively.
                                match b_leg_index {
                                    Some(idx) => {
                                        state.call_actors.replace_b_leg(call_id, idx, b_leg.clone());
                                        spawn_b_leg_actor_at(call_id, &b_leg, idx, state);
                                    }
                                    None => {
                                        state.call_actors.add_b_leg(call_id, b_leg.clone());
                                        spawn_b_leg_actor(call_id, &b_leg, state);
                                    }
                                }

                                let data = Bytes::from(retry.to_bytes());
                                send_to_target(data, &relay_target, transport, reuse_connection_id, None, state);
                            }
                            return; // don't forward 401/407 to A-leg or fire on_failure
                        }
                    }
                }
            }
        }

        // auth_passthrough: a B-leg 401/407 with no siphon-side credentials is a
        // NON-terminal challenge that we relay to the caller for end-to-end
        // authentication (RFC 3261 §22.3). We still ACK the B-leg and forward the
        // challenge to the A-leg below (unconditionally), but must NOT treat the
        // call as failed: skip the CDR, @b2bua.on_failure, and the media teardown.
        // The call actor is still removed (the caller re-INVITEs as a fresh call);
        // the media session — keyed by SIP Call-ID, which the re-INVITE reuses —
        // is deliberately left in place. The caller's ACK for the forwarded
        // challenge matches no live call and is dropped by the unmatched-ACK guard
        // (never answered with a 502).
        let relay_challenge = (status_code == 401 || status_code == 407)
            && outbound_credentials.is_none()
            && state
                .call_actors
                .get_call(call_id)
                .map(|call| call.auth_passthrough)
                .unwrap_or(false);
        if relay_challenge {
            debug!(
                call_id = %call_id,
                status = status_code,
                "B2BUA: relaying auth challenge to A-leg (auth_passthrough) — not a failure"
            );
        }

        // CDR: the call failed before answer (cdr.auto_emit). Fire regardless of
        // whether a @b2bua.on_failure handler is registered — the record must be
        // written for the failed call either way. Skipped for a relayed challenge
        // (the call has not failed).
        if !relay_challenge {
            cdr_finalize_b2bua_fail(state, call_id, status_code);
        }

        // Error response — invoke @b2bua.on_failure with (PyCall, code, reason).
        // Skipped for a relayed challenge (not a failure — the caller authenticates).
        let engine_state = state.engine.state();
        let handlers = engine_state.handlers_for(&HandlerKind::B2buaFailure);
        if !relay_challenge && !handlers.is_empty() {
            let reason = match &message.start_line {
                StartLine::Response(status_line) => status_line.reason_phrase.clone(),
                _ => "Unknown".to_string(),
            };

            if let Some(invite_arc) = &a_leg_invite {
                let py_call = PyCall::new(
                    call_id.to_string(),
                    Arc::clone(invite_arc),
                    a_leg.transport.remote_addr.ip().to_string(),
                    format!("{}", a_leg.transport.transport).to_lowercase(),
                );

                Python::attach(|python| {
                    let call_obj = match Py::new(python, py_call) {
                        Ok(obj) => obj,
                        Err(error) => {
                            error!("failed to create PyCall for on_failure: {error}");
                            return;
                        }
                    };

                    for handler in &handlers {
                        let callable = handler.callable.bind(python);
                        match callable.call1((
                            call_obj.bind(python),
                            status_code,
                            reason.as_str(),
                        )) {
                            Ok(ret) => {
                                if handler.is_async {
                                    if let Err(error) = run_coroutine(python, &ret) {
                                        error!("async B2BUA on_failure handler error: {error}");
                                    }
                                }
                            }
                            Err(error) => {
                                error!("B2BUA on_failure handler error: {error}");
                            }
                        }
                    }
                });
            } else {
                warn!(call_id = %call_id, "B2BUA: no stored A-leg INVITE for on_failure");
            }
        }

        // Send ACK to B-leg for non-2xx final response (RFC 3261 §17.1.1.3).
        // The B2BUA must acknowledge non-2xx responses hop-by-hop.
        // Use send_b2bua_to_bleg (not send_message) so TCP goes through the pool.
        if let Some((b_dest, b_transport)) = b_leg_dest {
            let ack = build_b2bua_ack_for_non2xx(
                message,
                branch,
                b_leg_target.as_deref(),
                b_transport,
                &state.via_host(&b_transport),
                state.via_port(&b_transport),
            );
            send_b2bua_to_bleg(ack, b_transport, b_dest, state);
        }

        // Forward error to A-leg — rewrite B-leg dialog headers back to A-leg
        if let Some((ref _b_cid, ref b_ftag)) = b_leg_dialog {
            crate::b2bua::actor::Dialog::rewrite_headers(
                message,
                &a_leg.dialog.call_id,
                b_ftag,
                a_leg.dialog.remote_tag.as_deref().unwrap_or(""),
                Some(&a_leg.dialog.local_tag),
            );
        }
        // Replace B-leg Via(s) with A-leg Via(s) from the stored INVITE.
        if let Some(invite_arc) = &a_leg_invite {
            if let Ok(invite) = invite_arc.lock() {
                if let Some(vias) = invite.headers.get_all("Via") {
                    message.headers.set_all("Via", vias.clone());
                }
                // Restore A-leg CSeq (RFC 3261 §8.2.6.2 — response CSeq MUST
                // equal the request CSeq). B-leg has independent CSeq numbering.
                if let Some(cseq) = invite.headers.cseq() {
                    message.headers.set("CSeq", cseq.clone());
                }
            }
        }
        // Sanitize B-leg headers before forwarding to A-leg
        sanitize_b2bua_response(message, state, a_leg.transport.transport, a_leg_local_addr, a_leg_supports_100rel, call_id);
        // Pin the reply egress socket to the A-leg INVITE's arrival listener
        // (`a_leg_local_addr`) so a multi-homed UDP host answers on the port it
        // received on. No-op for stream transports and single-listener hosts.
        send_message_from(
            message.clone(),
            a_leg.transport.transport,
            a_leg.transport.remote_addr,
            a_leg.transport.connection_id,
            a_leg_local_addr,
            state,
        );

        // Safety-net: if RTPEngine was offered but call failed, clean up the session.
        // Only runs when the call is truly ending (script called reject, not retry).
        // Skipped for a relayed auth challenge: the imminent authenticated
        // re-INVITE reuses the media session (keyed by SIP Call-ID), so deleting
        // it here would just force a needless re-offer (and could race that offer).
        if !relay_challenge {
            let a_sip_call_id = a_leg.dialog.call_id.clone();
            if let (Some(rtpengine_set), Some(media_sessions)) =
                (&state.rtpengine_set, &state.rtpengine_sessions)
            {
                if let Some(session) = media_sessions.remove(&a_sip_call_id) {
                    let set = Arc::clone(rtpengine_set);
                    tokio::spawn(async move {
                        if let Err(error) = set.delete(&session.call_id, &session.from_tag).await {
                            if error.is_call_not_found() {
                                debug!(call_id = %session.call_id, "safety-net RTPEngine delete: call already gone ({error})");
                            } else {
                                warn!(call_id = %session.call_id, "safety-net RTPEngine delete failed: {error}");
                            }
                        }
                    });
                }
            }
        }

        state.call_actors.remove_call(call_id);
        state.call_event_receivers.remove(call_id);
    }

    } // end ResponseClass::Failed
    } // end match class
}

/// Schedule cleanup of zombie re-INVITE entries after Timer H (32 seconds).
///
/// Called after `remove_call()` which may have moved `reinvite_done:` or
/// `reinvite:` B-leg entries to the zombie map. After 32 seconds the remote
/// UAS stops retransmitting per RFC 3261 §17.2.1, so the entries are no longer needed.
fn schedule_zombie_reinvite_cleanup(call_actors: &crate::b2bua::actor::CallActorStore) {
    if call_actors.zombie_reinvites.is_empty() {
        return;
    }
    let zombie_map = call_actors.zombie_reinvites.clone();
    let zombie_keys: Vec<String> = zombie_map.iter()
        .map(|entry| entry.key().clone())
        .collect();
    if !zombie_keys.is_empty() {
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(32)).await;
            for key in zombie_keys {
                zombie_map.remove(&key);
            }
        });
    }
}

/// Expire post-CANCEL glare entries after 32 s (Timer H / 64·T1).
///
/// Unlike [`schedule_zombie_reinvite_cleanup`], this removes from the *shared*
/// store via the `Arc` rather than from a `DashMap` clone, so entries that
/// never see a racing 2xx (the CANCEL won the race) are still reaped.
fn schedule_zombie_cancelled_cleanup(call_actors: Arc<crate::b2bua::actor::CallActorStore>) {
    let keys: Vec<String> = call_actors
        .zombie_cancelled
        .iter()
        .map(|entry| entry.key().clone())
        .collect();
    if keys.is_empty() {
        return;
    }
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(32)).await;
        for key in keys {
            call_actors.zombie_cancelled.remove(&key);
        }
    });
}

/// Build an ACK for a 2xx INVITE response on a B2BUA B-leg (RFC 3261 §13.2.2.4).
///
/// The ACK for a 2xx is its own transaction: a fresh Via branch, R-URI set to
/// the response's Contact (the remote target), and the INVITE's CSeq number
/// with method ACK. From / To / Call-ID are echoed from the 2xx (its To already
/// carries the remote tag).
///
/// Pure w.r.t. dispatcher state — the caller supplies the local `via_host` /
/// `via_port` (from `DispatcherState::via_host`/`via_port`) so this is directly
/// unit-testable.
fn build_b2bua_ack_for_2xx(
    response: &SipMessage,
    transport: Transport,
    via_host: &str,
    via_port: u16,
) -> Option<SipMessage> {
    let request_uri = response.headers.get("Contact")
        .map(|c| crate::b2bua::actor::extract_contact_uri(c))
        .and_then(|u| parse_uri_standalone(&u).ok())
        .unwrap_or_else(|| SipUri::new("invalid".to_string()));
    let transport_str = format!("{}", transport).to_uppercase();
    let cseq_num = response.headers.cseq()
        .and_then(|c| c.split_whitespace().next().map(|s| s.to_string()))
        .unwrap_or_else(|| "1".to_string());
    let from = response.headers.from().cloned().unwrap_or_default();
    let to = response.headers.to().cloned().unwrap_or_default();
    let call_id = response.headers.call_id().map(|s| s.to_string()).unwrap_or_default();
    match SipMessageBuilder::new()
        .request(Method::Ack, request_uri)
        .via(format!(
            "SIP/2.0/{} {}:{};branch={}",
            transport_str,
            via_host,
            via_port,
            TransactionKey::generate_branch(),
        ))
        .from(from.to_string())
        .to(to.to_string())
        .call_id(call_id)
        .cseq(format!("{} ACK", cseq_num))
        .header("Max-Forwards", "70".to_string())
        .content_length(0)
        .build()
    {
        Ok(ack) => Some(ack),
        Err(error) => {
            warn!("B2BUA: failed to build ACK for raced 2xx: {error}");
            None
        }
    }
}

/// Handle a 2xx that raced an outbound CANCEL (RFC 3261 §9.1 glare).
///
/// The callee answered the B-leg INVITE before our CANCEL landed, so the 2xx
/// established a dialog even though the call is gone. ACK it (§13.2.2.4) to stop
/// the 200 OK retransmissions, then — on the first 2xx only — BYE it (§15) to
/// release the session. All dialog state comes from the captured leg plus this
/// response (the remote tag / Contact were unknown when the INVITE was CANCELled).
fn handle_zombie_cancelled_2xx(
    mut leg: crate::b2bua::actor::Leg,
    first_2xx: bool,
    response: &SipMessage,
    state: &DispatcherState,
) {
    let transport = leg.transport.transport;
    let destination = leg.transport.remote_addr;

    // ACK the 2xx on every match — a lost ACK leaves the callee retransmitting.
    if let Some(ack) = build_b2bua_ack_for_2xx(
        response,
        transport,
        &state.via_host(&transport),
        state.via_port(&transport),
    ) {
        send_b2bua_to_bleg(ack, transport, destination, state);
    }

    if !first_2xx {
        return; // retransmit — re-ACK only; the BYE already went out.
    }

    // Fill the remote dialog identity from the 2xx (unknown at CANCEL time).
    if let Some(tag) = crate::b2bua::actor::extract_to_tag(response) {
        leg.dialog.remote_tag = Some(tag);
    }
    if let Some(contact) = response.headers.get("Contact") {
        leg.dialog.remote_contact = Some(crate::b2bua::actor::extract_contact_uri(contact));
    }
    // The BYE CSeq must exceed the INVITE's; derive it from the 2xx's CSeq.
    let invite_cseq = response.headers.cseq()
        .and_then(|c| c.split_whitespace().next())
        .and_then(|n| n.parse::<u32>().ok())
        .unwrap_or(leg.dialog.local_cseq);
    leg.dialog.local_cseq = invite_cseq.saturating_add(1);

    if let Some(bye) = build_b2bua_bye(&leg, state) {
        send_b2bua_to_bleg(bye, transport, destination, state);
        debug!(
            sip_call_id = %leg.dialog.call_id,
            "B2BUA: ACK+BYE for a 2xx that raced our CANCEL (RFC 3261 §9.1 glare)"
        );
    }
}

/// Handle a BYE for a B2BUA call — bridge to the other leg.
fn handle_b2bua_bye(
    inbound: InboundMessage,
    message: SipMessage,
    state: &DispatcherState,
) {
    let sip_call_id = message.headers.get("Call-ID")
        .map(|s| s.to_string())
        .unwrap_or_default();

    let call_id = match state.call_actors.find_by_sip_call_id(&sip_call_id) {
        Some(id) => id,
        None => {
            warn!(sip_call_id = %sip_call_id, "B2BUA BYE: no matching call");
            return;
        }
    };

    // Extract everything from the DashMap ref and drop it before entering Python
    let (from_a_leg, a_leg_invite, a_leg_source_ip, a_leg_transport) =
        match state.call_actors.get_call(&call_id) {
            Some(call) => {
                let from_a = inbound.remote_addr == call.a_leg.transport.remote_addr;
                (
                    from_a,
                    call.a_leg_invite.clone(),
                    call.a_leg.transport.remote_addr.ip().to_string(),
                    format!("{}", call.a_leg.transport.transport).to_lowercase(),
                )
            }
            None => return,
        };

    // Invoke @b2bua.on_bye handlers with (PyCall, PyByeInitiator)
    let engine_state = state.engine.state();
    let handlers = engine_state.handlers_for(&HandlerKind::B2buaBye);
    if !handlers.is_empty() {
        let side = if from_a_leg { "a".to_string() } else { "b".to_string() };

        if let Some(invite_arc) = &a_leg_invite {
            let py_call = PyCall::new(
                call_id.clone(),
                Arc::clone(invite_arc),
                a_leg_source_ip,
                a_leg_transport,
            );
            let initiator = PyByeInitiator { side };

            Python::attach(|python| {
                let call_obj = match Py::new(python, py_call) {
                    Ok(obj) => obj,
                    Err(error) => {
                        error!("failed to create PyCall for on_bye: {error}");
                        return;
                    }
                };
                let initiator_obj = match Py::new(python, initiator) {
                    Ok(obj) => obj,
                    Err(error) => {
                        error!("failed to create PyByeInitiator: {error}");
                        return;
                    }
                };

                for handler in &handlers {
                    let callable = handler.callable.bind(python);
                    match callable.call1((call_obj.bind(python), initiator_obj.bind(python))) {
                        Ok(ret) => {
                            if handler.is_async {
                                if let Err(error) = run_coroutine(python, &ret) {
                                    error!("async B2BUA on_bye handler error: {error}");
                                }
                            }
                        }
                        Err(error) => {
                            error!("B2BUA on_bye handler error: {error}");
                        }
                    }
                }
            });
        } else {
            warn!(call_id = %call_id, "B2BUA: no stored A-leg INVITE for on_bye");
        }
    }

    // Rf ACR-STOP on B2BUA BYE (TS 32.299 §6.2.2).  Fire before the
    // 200 OK is sent so the accounting record reflects the moment the
    // proxy committed to tearing the call down; the SIP path is
    // unaffected (spawn is fire-and-forget per §6.5).
    spawn_rf_b2bua_stop(state, &call_id, parse_reason_cause(&message));

    // CDR: write the call record on BYE (cdr.auto_emit). `from_a_leg` gives the
    // disconnecting side (caller vs callee).
    cdr_finalize_b2bua_stop(state, &call_id, from_a_leg, &message);

    // Re-acquire the call ref for BYE bridging
    let call = match state.call_actors.get_call(&call_id) {
        Some(c) => c,
        None => return,
    };

    // Send 200 OK to the BYE sender on the socket the BYE arrived on (multi-homed
    // UDP source-port parity — the in-dialog BYE now lands on the A-leg's anchored
    // listener after the Contact fix, so its 200 must leave from there too).
    let bye_response = build_response(&message, 200, "OK", state.server_header.as_deref(), &[]);
    send_message_from(
        bye_response,
        inbound.transport,
        inbound.remote_addr,
        inbound.connection_id,
        Some(inbound.local_addr),
        state,
    );

    // Forward BYE to the other leg with full B2BUA header rewriting:
    // - Dialog headers (Call-ID, From/To tags)
    // - From URI host (topology hiding)
    // - CSeq (independent per dialog, RFC 3261)
    // - Max-Forwards (decrement per RFC 7332)
    if from_a_leg {
        // BYE from A → generate new B-leg BYE from stored dialog state.
        // A B2BUA MUST NOT forward the A-leg BYE — it generates a fresh request
        // using only B-leg dialog identifiers, route set, and Contact.
        if let Some(winner_index) = call.winner {
            if let Some(b_leg) = call.b_legs.get(winner_index) {
                if let Some(bye) = build_b2bua_bye(b_leg, state) {
                    // RFC 3261 §12.2.1.1: next hop is the first Route URI, not
                    // the cached destination of the original INVITE (which may
                    // have traversed nodes — e.g. an IMS I-CSCF — that don't
                    // Record-Route and so aren't in the dialog route set).
                    let (destination, transport) = resolve_in_dialog_destination(
                        &b_leg.dialog.route_set,
                        state,
                        b_leg.transport.remote_addr,
                        b_leg.transport.transport,
                    );
                    debug!(call_id = %call_id, %destination, "B2BUA: sending BYE to B-leg");
                    send_b2bua_to_bleg(bye, transport, destination, state);
                } else {
                    warn!(call_id = %call_id, "B2BUA: failed to build B-leg BYE");
                }
            } else {
                warn!(call_id = %call_id, "B2BUA: no winning B-leg for BYE");
            }
        } else {
            warn!(call_id = %call_id, "B2BUA: no winner set for BYE");
        }
    } else {
        // BYE from B → generate new A-leg BYE from stored dialog state.
        if let Some(bye) = build_b2bua_bye(&call.a_leg, state) {
            let (destination, transport) = resolve_in_dialog_destination(
                &call.a_leg.dialog.route_set,
                state,
                call.a_leg.transport.remote_addr,
                call.a_leg.transport.transport,
            );
            // Source the siphon-originated BYE from the A-leg's anchored socket so a
            // strict peer sees it from the port the dialog runs on (Via matches — see
            // build_b2bua_bye). No-op for single-listener hosts.
            send_message_from(
                bye,
                transport,
                destination,
                call.a_leg.transport.connection_id,
                call.a_leg.transport.local_addr,
                state,
            );
        }
    }

    drop(call);

    // Safety-net: if an RTPEngine media session exists for this call but the
    // script didn't delete it, clean up in the background.
    if let (Some(rtpengine_set), Some(media_sessions)) =
        (&state.rtpengine_set, &state.rtpengine_sessions)
    {
        if let Some(session) = media_sessions.remove(&sip_call_id) {
            let set = Arc::clone(rtpengine_set);
            tokio::spawn(async move {
                if let Err(error) = set.delete(&session.call_id, &session.from_tag).await {
                    if error.is_call_not_found() {
                        debug!(call_id = %session.call_id, "safety-net RTPEngine delete: call already gone ({error})");
                    } else {
                        warn!(call_id = %session.call_id, "safety-net RTPEngine delete failed: {error}");
                    }
                }
            });
        }
    }

    // SIPREC: stop any active recording sessions for this call.
    b2bua_stop_siprec(&call_id, state);

    state.call_actors.set_state(&call_id, CallState::Terminated);
    // remove_call sends Shutdown to any remaining actors, cleans up registry,
    // and moves re-INVITE tracking entries to the zombie map
    state.call_actors.remove_call(&call_id);
    state.call_event_receivers.remove(&call_id);
    schedule_zombie_reinvite_cleanup(&state.call_actors);
}

/// Sweep all active calls for session timer expiry (RFC 4028).
///
/// Called every ~5 seconds from a background task. For each call:
/// - If `elapsed > session_expires`: tear down the call (both legs).
/// - If `elapsed > session_expires / 2` and refresher is "b2bua": send refresh re-INVITE.
fn session_timer_sweep(state: &DispatcherState) {
    let now = std::time::Instant::now();

    // Collect calls needing action (avoid holding DashMap ref during send)
    let mut calls_to_refresh: Vec<String> = Vec::new();
    let mut calls_to_terminate: Vec<String> = Vec::new();

    // Iterate all calls — only look at Answered calls with a session timer
    for entry in state.call_actors.iter_calls() {
        let call = entry.value();
        if call.state != CallState::Answered {
            continue;
        }
        if let Some(ref timer) = call.session_timer {
            let elapsed = now.duration_since(timer.last_refresh);
            let expires = std::time::Duration::from_secs(timer.session_expires as u64);
            let half_expires = expires / 2;

            if elapsed >= expires {
                // Session expired — terminate
                calls_to_terminate.push(call.id.clone());
            } else if elapsed >= half_expires && timer.refresher == "b2bua" {
                // Time to refresh
                calls_to_refresh.push(call.id.clone());
            }
        }
    }

    // Send refresh re-INVITEs
    for call_id in calls_to_refresh {
        b2bua_send_refresh_reinvite(&call_id, state);
    }

    // Terminate expired calls
    for call_id in calls_to_terminate {
        info!(call_id = %call_id, "B2BUA: session timer expired, terminating call");
        b2bua_session_timer_terminate(&call_id, state);
    }
}

/// Send a B2BUA-initiated refresh re-INVITE to the B-leg.
fn b2bua_send_refresh_reinvite(call_id: &str, state: &DispatcherState) {
    let (a_leg_invite, a_leg_from_tag, winner_b_leg, session_expires) = match state.call_actors.get_call(call_id) {
        Some(call) => {
            let b_leg = call.winner.and_then(|i| call.b_legs.get(i).cloned());
            let se = call.session_timer.as_ref().map(|t| t.session_expires).unwrap_or(1800);
            (call.a_leg_invite.clone(), call.a_leg.dialog.remote_tag.clone().unwrap_or_default(), b_leg, se)
        }
        None => return,
    };

    let (invite_arc, b_leg) = match (a_leg_invite, winner_b_leg) {
        (Some(invite), Some(b_leg)) => (invite, b_leg),
        _ => {
            debug!(call_id = %call_id, "B2BUA refresh: missing invite or B-leg");
            return;
        }
    };

    let Ok(original) = invite_arc.lock() else {
        error!(call_id = %call_id, "invite_arc lock poisoned during session timer refresh");
        return;
    };
    let mut reinvite = original.clone();
    drop(original);

    // New Via/branch
    let branch = TransactionKey::generate_branch();
    let transport_str = format!("{}", b_leg.transport.transport).to_uppercase();
    let via_value = format!(
        "SIP/2.0/{} {}:{};branch={}",
        transport_str,
        state.via_host(&b_leg.transport.transport),
        state.via_port(&b_leg.transport.transport),
        branch,
    );
    reinvite.headers.set("Via", via_value);

    // Update Request-URI to B-leg's remote Contact (RFC 3261 §12.2.1.1),
    // falling back to the original dial target if Contact is not yet captured.
    let reinvite_ruri = b_leg.dialog.remote_contact.as_deref()
        .or(b_leg.dialog.target_uri.as_deref())
        .unwrap_or_default();
    if !reinvite_ruri.is_empty() {
        if let Ok(target_parsed) = parse_uri_standalone(reinvite_ruri) {
            reinvite.start_line = StartLine::Request(crate::sip::message::RequestLine {
                method: crate::sip::message::Method::Invite,
                request_uri: target_parsed,
                version: crate::sip::message::Version::sip_2_0(),
            });
        }
    }

    // Rewrite A-leg dialog headers → B-leg dialog headers.
    // Source is the original out-of-dialog A-leg INVITE (no To-tag), so
    // pass None — the refresh re-INVITE's To-tag, if needed, is set by
    // the in-dialog construction logic elsewhere.
    crate::b2bua::actor::Dialog::rewrite_headers(
        &mut reinvite,
        &b_leg.dialog.call_id,
        &a_leg_from_tag,
        &b_leg.dialog.local_tag,
        None,
    );

    // Rewrite From URI host to our advertised address (topology hiding)
    let b2bua_host = state.via_host(&b_leg.transport.transport);
    if let Some(from) = reinvite.headers.get("From").or_else(|| reinvite.headers.get("f")) {
        reinvite.headers.set("From", crate::b2bua::actor::rewrite_uri_host(from, &b2bua_host));
    }

    // Regenerate CSeq for B-leg dialog
    reinvite.headers.set("CSeq", format!("{} INVITE", b_leg.dialog.local_cseq));

    // Decrement Max-Forwards (RFC 7332)
    let _ = crate::proxy::core::decrement_max_forwards(&mut reinvite.headers);

    // Set Contact to what we advertised to B-leg
    if let Some(ref contact) = b_leg.dialog.local_contact {
        reinvite.headers.set("Contact", contact.clone());
    }

    // Set session timer headers
    reinvite.headers.remove("Session-Expires");
    reinvite.headers.remove("Min-SE");
    reinvite.headers.add(
        "Session-Expires",
        format!("{};refresher=uac", session_expires),
    );
    if let Some(ref timer_config) = state.session_timer_config {
        reinvite.headers.add("Min-SE", timer_config.min_se.to_string());
    }
    if reinvite.headers.get("Supported").is_none() {
        reinvite.headers.add("Supported", "timer".to_string());
    }

    // Register new branch for response routing (reuse B-leg dialog identifiers)
    // Mark as re-INVITE so the response handler doesn't absorb it as a retransmission
    let mut new_b_leg = Leg::new_b_leg(
        b_leg.dialog.call_id.clone(),
        b_leg.dialog.local_tag.clone(),
        "reinvite:a2b".to_string(),
        branch.clone(),
        LegTransport {
            remote_addr: b_leg.transport.remote_addr,
            connection_id: ConnectionId::default(),
            transport: b_leg.transport.transport,
            local_addr: None,
        },
    );
    new_b_leg.stored_vias = vec![];
    state.call_actors.add_b_leg(call_id, new_b_leg);

    // Reset timer preemptively (will be confirmed on 200 OK)
    state.call_actors.reset_session_timer(call_id);

    debug!(call_id = %call_id, "B2BUA: sending session timer refresh re-INVITE");
    send_b2bua_to_bleg(reinvite, b_leg.transport.transport, b_leg.transport.remote_addr, state);

    // Increment B-leg CSeq after sending
    if let Some(mut call) = state.call_actors.get_call_mut(call_id) {
        if let Some(winner_idx) = call.winner {
            if let Some(b_leg) = call.b_legs.get_mut(winner_idx) {
                b_leg.dialog.local_cseq += 1;
            }
        }
    }
}

/// Stop and tear down any SIPREC recording sessions for a B2BUA call: send the
/// SRC-side BYE to each SRS and unsubscribe the RTPEngine media fork. Shared by
/// the inbound-BYE teardown ([`handle_b2bua_bye`]) and the framework-initiated
/// teardown ([`b2bua_terminate_call_inner`]).
fn b2bua_stop_siprec(internal_call_id: &str, state: &DispatcherState) {
    // Collect RTPEngine subscribe info before stop_recording cleans up sessions.
    let siprec_infos = state.recording_manager.active_session_infos(internal_call_id);
    let bye_messages = state
        .recording_manager
        .stop_recording(internal_call_id, state.local_addr);
    for (bye_msg, destination, transport) in bye_messages {
        let data = Bytes::from(bye_msg.to_bytes());
        let target = RelayTarget {
            address: destination,
            transport: Some(transport),
            server_name: None,
        };
        send_to_target(data, &target, transport, ConnectionId::default(), None, state);
    }
    // RTPEngine unsubscribe: stop media forking for each recording session.
    if let Some(ref rtpengine_set) = state.rtpengine_set {
        for (original_call_id, original_from_tag, original_to_tag) in siprec_infos {
            let set = Arc::clone(rtpengine_set);
            tokio::spawn(async move {
                if let Err(error) = set
                    .unsubscribe(&original_call_id, &original_from_tag, &original_to_tag)
                    .await
                {
                    warn!(
                        call_id = %original_call_id,
                        "SIPREC: RTPEngine unsubscribe failed: {error}"
                    );
                }
            });
        }
    }
}

/// Build an RFC 3326 `Reason:` header value for a graceful, script-initiated
/// call teardown. Q.850 cause 16 = normal call clearing; the script-supplied
/// text rides along in `text=` (embedded quotes stripped so the header stays
/// well-formed).
fn format_normal_clearing_reason(reason: &str) -> String {
    let text = reason.replace('"', "");
    format!("Q.850;cause=16;text=\"{text}\"")
}

/// Full B2BUA call teardown initiated by the framework — session-timer expiry or
/// an imperative `b2bua.terminate` — NOT by an inbound BYE. Sends an in-dialog
/// BYE to BOTH legs from stored dialog state (a single-leg UAS call degrades to
/// just the A-leg), emits Rf ACR-STOP + a CDR + stops SIPREC (matching the
/// inbound-BYE teardown in [`handle_b2bua_bye`] so those per-call stores drain
/// here too), tears down media, and removes all dialog/registry state.
///
/// `reason_header` is a full RFC 3326 `Reason:` value added to each BYE and
/// recorded as the CDR `sip_reason`. `disconnect_initiator` is the CDR
/// disconnecting side (`"b2bua"` for a script terminate, `"timeout"` for
/// session-timer expiry). Returns `true` if the call existed.
fn b2bua_terminate_call_inner(
    internal_call_id: &str,
    reason_header: Option<&str>,
    disconnect_initiator: &str,
    state: &DispatcherState,
) -> bool {
    let (a_leg, winner_b_leg, sip_call_id) = match state.call_actors.get_call(internal_call_id) {
        Some(call) => {
            let b_leg = call.winner.and_then(|i| call.b_legs.get(i).cloned());
            (call.a_leg.clone(), b_leg, call.a_leg.dialog.call_id.clone())
        }
        None => return false,
    };

    // Rf ACR-STOP (TS 32.299 §6.2.2). A framework-initiated teardown maps to the
    // Diameter "normal" cause (None → 0); the RFC 3326 Reason on the BYE is
    // informational only here (its Q.850 cause is not a SIP status).
    spawn_rf_b2bua_stop(state, internal_call_id, None);

    // CDR (cdr.auto_emit): write the record with the framework as the
    // disconnecting side and the Reason header as sip_reason.
    if crate::cdr::auto_emit_enabled() {
        cdr_finalize(
            state,
            internal_call_id,
            disconnect_initiator,
            None,
            reason_header.map(|r| r.to_string()),
        );
    }

    // Build + send BYE to each leg using the shared build_b2bua_bye helper.
    // Destination derived from the dialog route set (RFC 3261 §12.2.1.1) — see
    // resolve_in_dialog_destination for why the cached transport.remote_addr is
    // wrong for routes that don't match the original INVITE next-hop.
    let build_bye = |leg: &Leg| -> Option<SipMessage> {
        let mut bye = build_b2bua_bye(leg, state)?;
        if let Some(reason) = reason_header {
            bye.headers.add("Reason", reason.to_string());
        }
        Some(bye)
    };
    if let Some(bye_msg) = build_bye(&a_leg) {
        let (destination, transport) = resolve_in_dialog_destination(
            &a_leg.dialog.route_set,
            state,
            a_leg.transport.remote_addr,
            a_leg.transport.transport,
        );
        // Source the framework BYE from the A-leg's anchored socket (Via matches).
        send_message_from(bye_msg, transport, destination, a_leg.transport.connection_id, a_leg.transport.local_addr, state);
    }
    if let Some(b_leg) = &winner_b_leg {
        if let Some(bye_msg) = build_bye(b_leg) {
            let (destination, transport) = resolve_in_dialog_destination(
                &b_leg.dialog.route_set,
                state,
                b_leg.transport.remote_addr,
                b_leg.transport.transport,
            );
            send_b2bua_to_bleg(bye_msg, transport, destination, state);
        }
    }

    // Safety-net RTPEngine cleanup.
    if let (Some(rtpengine_set), Some(media_sessions)) =
        (&state.rtpengine_set, &state.rtpengine_sessions)
    {
        if let Some(session) = media_sessions.remove(&sip_call_id) {
            let set = Arc::clone(rtpengine_set);
            tokio::spawn(async move {
                if let Err(error) = set.delete(&session.call_id, &session.from_tag).await {
                    if error.is_call_not_found() {
                        debug!(call_id = %session.call_id, "safety-net RTPEngine delete: call already gone ({error})");
                    } else {
                        warn!(call_id = %session.call_id, "safety-net RTPEngine delete failed: {error}");
                    }
                }
            });
        }
    }

    // SIPREC: stop any active recording sessions for this call.
    b2bua_stop_siprec(internal_call_id, state);

    state.call_actors.set_state(internal_call_id, CallState::Terminated);
    // remove_call sends Shutdown to any remaining actors, cleans up registry,
    // and moves re-INVITE tracking entries to the zombie map.
    state.call_actors.remove_call(internal_call_id);
    state.call_event_receivers.remove(internal_call_id);
    schedule_zombie_reinvite_cleanup(&state.call_actors);
    true
}

/// Terminate a call due to session timer expiry (RFC 4028) — BYE both legs and
/// run the full framework teardown (Rf ACR-STOP + CDR + SIPREC + media), the
/// same funnel the imperative `b2bua.terminate` uses.
fn b2bua_session_timer_terminate(call_id: &str, state: &DispatcherState) {
    // Q.850 cause 102 = "recovery on timer expiry".
    b2bua_terminate_call_inner(
        call_id,
        Some("Q.850;cause=102;text=\"Session timer expired\""),
        "timeout",
        state,
    );
}

/// Handle to the running dispatcher, published once at startup so imperative
/// script APIs (e.g. `b2bua.terminate`) can reach dialog state and the tokio
/// runtime from any thread — an event-callback driver, a timer, or an async-pool
/// loop, none of which are tokio workers.
struct B2buaControlHandle {
    state: Arc<DispatcherState>,
    runtime: tokio::runtime::Handle,
}

static B2BUA_CONTROL: std::sync::OnceLock<B2buaControlHandle> = std::sync::OnceLock::new();

/// Imperatively tear down a B2BUA call identified by its SIP Call-ID, sending a
/// BYE to every leg and running the full teardown ([`b2bua_terminate_call_inner`]).
///
/// Safe to call from any thread/context (event callbacks like `@rtpengine.on_dtmf`,
/// timers, async handlers) — unlike the deferred `call.terminate()`, which only
/// applies when its own handler returns. Returns `false` (never panics) when the
/// call-id is unknown / already gone or the dispatcher is not running, so an IVR
/// that races a caller-initiated BYE is a clean no-op.
pub fn b2bua_terminate_call(sip_call_id: &str, reason: Option<&str>) -> bool {
    let Some(control) = B2BUA_CONTROL.get() else {
        return false;
    };
    let Some(internal_call_id) = control.state.call_actors.find_by_sip_call_id(sip_call_id) else {
        return false;
    };
    // The caller may be on a thread with no tokio context (async-pool asyncio
    // loop, rtpengine event driver); enter the runtime so the teardown's
    // tokio::spawn calls (RTPEngine delete, Rf ACR-STOP, SIPREC unsubscribe) are
    // valid.
    let _enter = control.runtime.enter();
    let reason_header = reason.map(format_normal_clearing_reason);
    b2bua_terminate_call_inner(
        &internal_call_id,
        reason_header.as_deref(),
        "b2bua",
        &control.state,
    )
}

/// Build and send a UAS response (final 2xx or provisional 1xx) for a B2BUA call
/// from an imperative `call.answer()` / `call.progress()`.
///
/// Unlike the bridged path, the script owns the A-leg dialog and answers it
/// directly. The response is built from `invite` (the A-leg INVITE, passed from
/// the `PyCall` because `a_leg_invite` isn't stored on the actor until after the
/// handler returns) and sent out the listener the INVITE arrived on. For any
/// code > 100 the To header is tagged with the A-leg dialog's `local_tag`
/// (RFC 3261 §12.1.1 — a dialog-creating 2xx and an early-dialog 18x both need
/// it, and it's what makes a later siphon-originated in-dialog BYE match the
/// caller instead of being 481-rejected).
///
/// `final_response` marks the call `Answered` and stamps the CDR answer time.
/// Returns `false` (never panics) if the call is gone or the dispatcher isn't
/// running.
fn b2bua_send_uas_response(
    internal_call_id: &str,
    invite: &SipMessage,
    code: u16,
    reason: &str,
    body: Option<Vec<u8>>,
    content_type: Option<&str>,
    final_response: bool,
) -> bool {
    let Some(control) = B2BUA_CONTROL.get() else {
        return false;
    };
    let state = &control.state;
    let (transport, remote_addr, connection_id, local_addr, local_tag) =
        match state.call_actors.get_call(internal_call_id) {
            Some(call) => (
                call.a_leg.transport.transport,
                call.a_leg.transport.remote_addr,
                call.a_leg.transport.connection_id,
                call.a_leg_local_addr,
                call.a_leg.dialog.local_tag.clone(),
            ),
            None => return false,
        };
    // The send path may spawn (TCP/TLS connect) and the caller may be on a
    // non-tokio thread (async-pool asyncio loop), so establish the runtime.
    let _enter = control.runtime.enter();

    // RFC 3261 §12.1.1: tag the To header with the A-leg dialog local_tag for any
    // dialog-establishing response (2xx) or early-dialog provisional (18x).
    let mut reply_headers: Vec<(crate::script::api::request::ReplyHeaderOp, String, String)> =
        Vec::new();
    if code > 100 {
        if let Some(to_value) = invite.headers.to() {
            if !to_value.contains(";tag=") {
                reply_headers.push((
                    crate::script::api::request::ReplyHeaderOp::Replace,
                    "To".to_string(),
                    crate::b2bua::actor::ensure_tag(to_value, Some(&local_tag)),
                ));
            }
        }
    }

    let mut response =
        build_response(invite, code, reason, state.server_header.as_deref(), &reply_headers);
    if let Some(body_bytes) = body {
        if let Some(ct) = content_type {
            response.headers.set("Content-Type", ct.to_string());
        }
        response.headers.set("Content-Length", body_bytes.len().to_string());
        response.body = body_bytes;
    }
    send_message_from(response, transport, remote_addr, connection_id, local_addr, state);

    if final_response {
        // Confirm the A-leg dialog and mark the CDR answered (tracked at INVITE
        // by cdr_track_b2bua_start) so a later BYE/terminate CDR shows duration.
        state.call_actors.set_state(internal_call_id, CallState::Answered);
        if crate::cdr::auto_emit_enabled() {
            cdr_mark_answer(state, internal_call_id, code);
        }
    }
    true
}

/// Imperatively send the final 2xx for a UAS-mode B2BUA call (`call.answer()`).
/// `code` must be 2xx. Returns `false` if the call is gone / dispatcher down.
pub fn b2bua_answer_call(
    internal_call_id: &str,
    invite: &SipMessage,
    code: u16,
    reason: &str,
    body: Option<Vec<u8>>,
    content_type: Option<&str>,
) -> bool {
    b2bua_send_uas_response(internal_call_id, invite, code, reason, body, content_type, true)
}

/// Imperatively send a provisional (1xx) for a UAS-mode B2BUA call
/// (`call.progress()`) — e.g. a 183 with early-media SDP. Does not answer the
/// call. Returns `false` if the call is gone / dispatcher down.
pub fn b2bua_progress_call(
    internal_call_id: &str,
    invite: &SipMessage,
    code: u16,
    reason: &str,
    body: Option<Vec<u8>>,
    content_type: Option<&str>,
) -> bool {
    b2bua_send_uas_response(internal_call_id, invite, code, reason, body, content_type, false)
}

/// Arm the RFC 3262 §3 retransmit task for a reliable provisional response.
///
/// Stores a [`ReliableProvisional`] entry in the dispatcher state under
/// `(Call-ID, RSeq)` and spawns a background task that resends `response`
/// every interval (T1 = 500 ms doubling up to T2 = 4 s, max 64×T1 = 32 s).
/// The task watches the entry's [`tokio::sync::Notify`] and exits as soon
/// as the inbound-PRACK handler signals a match — see the proxy PRACK
/// short-circuit in [`run`].
///
/// The transport-layer write goes through `state.outbound`, the same channel
/// the dispatcher uses, so retransmits look identical to the original send.
fn arm_reliable_provisional_retransmit(
    rseq: u32,
    request: &SipMessage,
    response: SipMessage,
    inbound: &InboundMessage,
    state: &DispatcherState,
) {
    let call_id = request.headers.call_id().cloned().unwrap_or_default();
    let cseq_num = request.headers.cseq()
        .and_then(|c| c.split_whitespace().next())
        .and_then(|n| n.parse::<u32>().ok())
        .unwrap_or(1);
    let entry = Arc::new(ReliableProvisional {
        cancel: tokio::sync::Notify::new(),
        cseq_num,
    });
    state.reliable_provisionals.insert((call_id.clone(), rseq), Arc::clone(&entry));

    let store = Arc::clone(&state.reliable_provisionals);
    let outbound = Arc::clone(&state.outbound);
    let destination = inbound.remote_addr;
    let transport = inbound.transport;
    let connection_id = inbound.connection_id;
    // Retransmit the reliable 1xx on the same listener the request arrived on so a
    // multi-homed UDP host keeps a consistent source port (matches the initial send).
    let source_local_addr = Some(inbound.local_addr);
    let key = (call_id.clone(), rseq);

    tokio::spawn(async move {
        // RFC 3262 §3 timing: start at T1 = 500 ms, double on each retransmit
        // up to T2 = 4 s, give up after 64 × T1 = 32 s if no PRACK.
        let mut interval = std::time::Duration::from_millis(500);
        let cap = std::time::Duration::from_secs(4);
        let started = tokio::time::Instant::now();
        let deadline = started + std::time::Duration::from_secs(32);
        let bytes = bytes::Bytes::from(response.to_bytes());

        loop {
            let sleep = tokio::time::sleep(interval);
            tokio::pin!(sleep);
            tokio::select! {
                _ = entry.cancel.notified() => break,
                _ = &mut sleep => {
                    if tokio::time::Instant::now() >= deadline {
                        warn!(
                            call_id = %key.0, rseq = key.1,
                            "RFC 3262: no PRACK after 32s — giving up reliable 1xx retransmits"
                        );
                        store.remove(&key);
                        break;
                    }
                    debug!(
                        call_id = %key.0, rseq = key.1, interval_ms = interval.as_millis() as u64,
                        "retransmitting reliable 1xx (RFC 3262)"
                    );
                    let _ = outbound.send(OutboundMessage {
                        connection_id,
                        transport,
                        destination,
                        data: bytes.clone(),
                        source_local_addr,
                        server_name: None,
                    });
                    interval = (interval * 2).min(cap);
                }
            }
        }
    });
}

/// Arm B2BUA A-leg 2xx retransmission (RFC 3261 §13.3.1.4).
///
/// The B2BUA intercepts the A-leg INVITE before a server transaction is
/// created (see `handle_b2bua_invite`), so the transaction layer never
/// retransmits the A-leg 2xx — and the IST would step aside on 2xx anyway
/// ("TU owns retransmissions"). Without this, a single lost 200 leaves the
/// caller ringing until it CANCELs. Stores a `Notify` under the internal call
/// ID and spawns a task that resends `response` on the RFC 3261 §17.2.1 UAS
/// schedule (T1 = 500 ms doubling to T2 = 4 s, give up after 64×T1 = 32 s).
/// The late-ACK handler fires the `Notify` when the caller's ACK arrives.
///
/// Mirrors [`arm_reliable_provisional_retransmit`]. On give-up it removes its
/// own entry and warns (a genuinely abandoned answered call is reclaimed by the
/// session timer / orphan sweep) rather than tearing down from the task, which
/// would need a `&DispatcherState` the spawned future cannot hold.
fn arm_b2bua_2xx_retransmit(
    internal_call_id: &str,
    response: SipMessage,
    transport: Transport,
    destination: SocketAddr,
    connection_id: ConnectionId,
    source_local_addr: Option<SocketAddr>,
    state: &DispatcherState,
) {
    let entry = Arc::new(tokio::sync::Notify::new());
    state
        .uas_2xx_retransmits
        .insert(internal_call_id.to_string(), Arc::clone(&entry));

    let store = Arc::clone(&state.uas_2xx_retransmits);
    let outbound = Arc::clone(&state.outbound);
    let key = internal_call_id.to_string();

    tokio::spawn(async move {
        // RFC 3261 §17.2.1 UAS timing: start at T1 = 500 ms, double on each
        // retransmit up to T2 = 4 s, give up after 64 × T1 = 32 s if no ACK.
        let mut interval = std::time::Duration::from_millis(500);
        let cap = std::time::Duration::from_secs(4);
        let started = tokio::time::Instant::now();
        let deadline = started + std::time::Duration::from_secs(32);
        let bytes = bytes::Bytes::from(response.to_bytes());

        loop {
            let sleep = tokio::time::sleep(interval);
            tokio::pin!(sleep);
            tokio::select! {
                _ = entry.notified() => break,
                _ = &mut sleep => {
                    if tokio::time::Instant::now() >= deadline {
                        warn!(
                            call_id = %key,
                            "RFC 3261 §13.3.1.4: no ACK after 32s — giving up A-leg 2xx retransmits"
                        );
                        store.remove(&key);
                        break;
                    }
                    debug!(
                        call_id = %key, interval_ms = interval.as_millis() as u64,
                        "retransmitting A-leg 2xx (RFC 3261 §13.3.1.4)"
                    );
                    let _ = outbound.send(OutboundMessage {
                        connection_id,
                        transport,
                        destination,
                        data: bytes.clone(),
                        source_local_addr,
                        server_name: None,
                    });
                    interval = (interval * 2).min(cap);
                }
            }
        }
    });
}

/// Handle an A-leg PRACK in a B2BUA call (RFC 3262).
///
/// The B2BUA strips Require/RSeq from forwarded reliable provisionals (see
/// sanitize_b2bua_response) so a well-behaved A-leg never sends PRACK in
/// the first place. This handler exists for A-legs that PRACK anyway —
/// either because the original INVITE carried Require: 100rel, or because
/// the UAC is configured to PRACK whenever it sent Supported: 100rel. The
/// B-leg side is already PRACKed locally by the auto-PRACK path in the
/// response handler, so all that's left is to terminate the A-leg PRACK
/// transaction with 200 OK.
fn handle_b2bua_prack(
    inbound: InboundMessage,
    message: SipMessage,
    state: &DispatcherState,
) {
    let response = build_response(&message, 200, "OK", state.server_header.as_deref(), &[]);
    debug!(
        call_id = %message.headers.get("Call-ID").map(|s| s.as_str()).unwrap_or(""),
        "B2BUA: auto-200 OK for A-leg PRACK",
    );
    // Answer the PRACK on its arrival socket (multi-homed UDP source-port parity).
    send_message_from(
        response,
        inbound.transport,
        inbound.remote_addr,
        inbound.connection_id,
        Some(inbound.local_addr),
        state,
    );
}

/// Handle a mid-dialog re-INVITE for a B2BUA call.
///
/// Re-INVITEs are used for session timer refreshes (RFC 4028), hold/resume,
/// and codec renegotiation. They are forwarded to the other leg transparently.
fn handle_b2bua_reinvite(
    inbound: InboundMessage,
    message: SipMessage,
    state: &DispatcherState,
) {
    let sip_call_id = message.headers.get("Call-ID")
        .map(|s| s.to_string())
        .unwrap_or_default();

    let call_id = match state.call_actors.find_by_sip_call_id(&sip_call_id) {
        Some(id) => id,
        None => {
            warn!(sip_call_id = %sip_call_id, "B2BUA re-INVITE: no matching call");
            return;
        }
    };

    // Determine direction and extract routing info + per-leg contacts
    let (from_a_leg, a_leg, winner_b_leg) = match state.call_actors.get_call(&call_id) {
        Some(call) => {
            let from_a = inbound.remote_addr == call.a_leg.transport.remote_addr;
            let b_leg = call.winner.and_then(|i| call.b_legs.get(i).cloned());
            (from_a, call.a_leg.clone(), b_leg)
        }
        None => return,
    };

    // Per-leg Contact URIs for RURI and Contact rewriting (RFC 3261 §12.2.1.1)
    let (target_remote_contact, target_local_contact, _target_remote_aor_host) = if from_a_leg {
        // A→B: target is B-leg
        winner_b_leg.as_ref().map(|b| (b.dialog.remote_contact.clone(), b.dialog.local_contact.clone(), b.dialog.remote_aor_host.clone()))
            .unwrap_or((None, None, None))
    } else {
        // B→A: target is A-leg
        (a_leg.dialog.remote_contact.clone(), a_leg.dialog.local_contact.clone(), a_leg.dialog.remote_aor_host.clone())
    };

    // Glare prevention (RFC 3261 §14.1):
    //  (a) Don't forward a re-INVITE if the target hasn't ACKed the initial
    //      INVITE yet — the offer/answer from the initial transaction is
    //      still in flight.
    //  (b) Don't forward a second re-INVITE while one is already pending
    //      toward the same leg — two concurrent offer/answer exchanges
    //      would leave the media state undefined.
    // In either case we respond 491 Request Pending so the originator can
    // retry after a random delay per the RFC.
    let target_acked = if from_a_leg {
        winner_b_leg.as_ref().map(|b| b.initial_acked).unwrap_or(false)
    } else {
        a_leg.initial_acked
    };
    if !target_acked {
        debug!(
            call_id = %call_id,
            from_a_leg = from_a_leg,
            "B2BUA: rejecting re-INVITE with 491 — target leg not yet ACKed"
        );
        let response = build_response(&message, 491, "Request Pending", state.server_header.as_deref(), &[]);
        send_message_from(response, inbound.transport, inbound.remote_addr, inbound.connection_id, Some(inbound.local_addr), state);
        return;
    }

    // `on_a_leg = !from_a_leg` because the "target" of the re-INVITE is the
    // OPPOSITE side from where it arrived. A re-INVITE from the A-leg is
    // forwarded toward the B-leg (and vice versa). Take-and-set the pending
    // flag atomically so the glare check races against nothing.
    let already_pending = state
        .call_actors
        .set_pending_reinvite(&call_id, /*on_a_leg=*/ !from_a_leg, true);
    if already_pending {
        debug!(
            call_id = %call_id,
            from_a_leg = from_a_leg,
            "B2BUA: rejecting re-INVITE with 491 — another re-INVITE already pending toward target"
        );
        let response = build_response(&message, 491, "Request Pending", state.server_header.as_deref(), &[]);
        send_message_from(response, inbound.transport, inbound.remote_addr, inbound.connection_id, Some(inbound.local_addr), state);
        return;
    }

    debug!(
        call_id = %call_id,
        from_a_leg = from_a_leg,
        "B2BUA: forwarding re-INVITE"
    );

    // Send 100 Trying to the re-INVITE sender
    let trying = build_response(&message, 100, "Trying", state.server_header.as_deref(), &[]);
    // Answer on the same listener the request arrived on so a multi-homed UDP
    // host keeps a symmetric source port (a peer that sent to :5066 rejects a
    // reply sourced from :5060). No-op for stream transports / single listener.
    send_message_from(
        trying,
        inbound.transport,
        inbound.remote_addr,
        inbound.connection_id,
        Some(inbound.local_addr),
        state,
    );

    // Build the forwarded re-INVITE with new Via/branch
    let branch = TransactionKey::generate_branch();

    let mut forwarded = message.clone();
    // Register this branch for response routing back to the re-INVITE sender
    let reinvite_target = if from_a_leg {
        // A→B: forward to winning B-leg, rewrite A-leg → B-leg dialog headers
        if let Some(b_leg) = &winner_b_leg {
            crate::b2bua::actor::Dialog::rewrite_headers(
                &mut forwarded,
                &b_leg.dialog.call_id,
                a_leg.dialog.remote_tag.as_deref().unwrap_or(""),
                &b_leg.dialog.local_tag,
                b_leg.dialog.remote_tag.as_deref(),
            );
            Some((b_leg.transport.remote_addr, b_leg.transport.transport, b_leg.transport.local_addr, b_leg.dialog.call_id.clone(), b_leg.dialog.local_tag.clone()))
        } else {
            warn!(call_id = %call_id, "B2BUA re-INVITE: no winning B-leg");
            return;
        }
    } else {
        // B→A: forward to A-leg, rewrite B-leg → A-leg dialog headers
        if let Some(b_leg) = &winner_b_leg {
            crate::b2bua::actor::Dialog::rewrite_headers(
                &mut forwarded,
                &a_leg.dialog.call_id,
                &b_leg.dialog.local_tag,
                a_leg.dialog.remote_tag.as_deref().unwrap_or(""),
                Some(&a_leg.dialog.local_tag),
            );
        }
        Some((a_leg.transport.remote_addr, a_leg.transport.transport, a_leg.transport.local_addr, a_leg.dialog.call_id.clone(), a_leg.dialog.remote_tag.clone().unwrap_or_default()))
    };

    if let Some((destination, transport, target_local_addr, leg_call_id, leg_from_tag)) = reinvite_target {
        // Set Via with correct transport for the target leg
        let transport_str = format!("{}", transport).to_uppercase();
        let via_value = format!(
            "SIP/2.0/{} {}:{};branch={}",
            transport_str,
            state.via_host(&transport),
            // Via port = the target leg's anchored listener (A-leg's arrival socket
            // when forwarding B→A on a multi-homed host); via_port for the B-leg.
            a_leg_advertised_port(target_local_addr, state.via_port(&transport)),
            branch,
        );
        forwarded.headers.set("Via", via_value);

        // Sanitize: strip headers that leak the other leg's identity/capabilities.
        // A B2BUA terminates the dialog — no cross-leg headers should pass through.
        if let Some(ref ua) = state.user_agent_header {
            forwarded.headers.set("User-Agent", ua.clone());
        } else {
            forwarded.headers.remove("User-Agent");
        }
        forwarded.headers.remove("Server");
        forwarded.headers.remove("Allow");
        forwarded.headers.remove("Allow-Events");
        forwarded.headers.remove("Supported");
        forwarded.headers.remove("Require");
        forwarded.headers.remove("Proxy-Require");
        forwarded.headers.remove("P-Asserted-Identity");
        forwarded.headers.remove("P-Access-Network-Info");
        forwarded.headers.remove("Security-Verify");
        forwarded.headers.remove("Security-Client");
        forwarded.headers.remove("Authorization");
        forwarded.headers.remove("Proxy-Authorization");
        // Strip cross-leg Record-Route and Route — replace with target leg's route set
        forwarded.headers.remove("Record-Route");
        forwarded.headers.remove("Route");

        // Add target leg's dialog route set as Route headers
        let target_route_set = if from_a_leg {
            winner_b_leg.as_ref().map(|b| b.dialog.route_set.clone()).unwrap_or_default()
        } else {
            a_leg.dialog.route_set.clone()
        };
        for route in &target_route_set {
            forwarded.headers.add("Route", route.clone());
        }

        // From/To: stitch URI string with dialog tag (RFC 3261 §12.2 —
        // dialog identity requires the tag). The URIs are captured at
        // INVITE-send time without tags; tags arrive in the 2xx and are
        // stored separately. ensure_tag survives the URI being reset by
        // a 401/407 retry path (which re-captures the bare URI).
        let (target_from_uri, target_from_tag, target_to_uri, target_to_tag) = if from_a_leg {
            let b = winner_b_leg.as_ref();
            (
                b.and_then(|b| b.dialog.local_from_uri.clone()),
                b.map(|b| b.dialog.local_tag.clone()),
                b.and_then(|b| b.dialog.remote_to_uri.clone()),
                b.and_then(|b| b.dialog.remote_tag.clone()),
            )
        } else {
            (
                a_leg.dialog.local_from_uri.clone(),
                Some(a_leg.dialog.local_tag.clone()),
                a_leg.dialog.remote_to_uri.clone(),
                a_leg.dialog.remote_tag.clone(),
            )
        };
        if let Some(uri) = target_from_uri {
            forwarded.headers.set(
                "From",
                crate::b2bua::actor::ensure_tag(&uri, target_from_tag.as_deref()),
            );
        }
        if let Some(uri) = target_to_uri {
            forwarded.headers.set(
                "To",
                crate::b2bua::actor::ensure_tag(&uri, target_to_tag.as_deref()),
            );
        }

        // Regenerate CSeq for the target leg's dialog (RFC 3261 — independent CSeq per dialog)
        let target_cseq = if from_a_leg {
            winner_b_leg.as_ref().map(|b| b.dialog.local_cseq).unwrap_or(1)
        } else {
            a_leg.dialog.local_cseq
        };
        forwarded.headers.set("CSeq", format!("{} INVITE", target_cseq));

        // Decrement Max-Forwards (RFC 7332 — B2BUAs MUST decrement)
        let _ = crate::proxy::core::decrement_max_forwards(&mut forwarded.headers);

        // Sanitize SDP: mask other leg's identity in o= and s= lines, and
        // rewrite the o= address for topology hiding.
        let sdp_addr = state.via_host(&transport);
        sanitize_sdp_identity(&mut forwarded.body, &state.sdp_name, Some(&sdp_addr));

        // RTPEngine: rewrite re-INVITE SDP through offer to maintain media anchoring.
        // Without this, re-INVITE SDP passes through unmodified — if the remote side
        // includes stale or cross-wired RTP ports, media breaks (one-way audio).
        if !forwarded.body.is_empty() {
            if let (Some(ref rtpengine_set), Some(ref media_sessions), Some(ref profiles)) =
                (&state.rtpengine_set, &state.rtpengine_sessions, &state.rtpengine_profiles)
            {
                let a_sip_call_id = &a_leg.dialog.call_id;
                if let Some(session) = media_sessions.get(a_sip_call_id) {
                    if let Some(profile) = profiles.get(&session.profile) {
                        // Use the tag of whichever side is sending the offer
                        let offer_tag = if from_a_leg {
                            session.from_tag.as_str()
                        } else {
                            session.to_tag.as_deref().unwrap_or(session.from_tag.as_str())
                        };
                        let offer_flags = profile.offer.clone();
                        match tokio::task::block_in_place(|| {
                            tokio::runtime::Handle::current().block_on(
                                rtpengine_set.offer(&session.call_id, offer_tag, &forwarded.body, &offer_flags)
                            )
                        }) {
                            Ok(rewritten_sdp) => {
                                forwarded.body = rewritten_sdp;
                                debug!(call_id = %call_id, "RTPEngine: rewrote re-INVITE SDP (offer)");
                            }
                            Err(error) => {
                                warn!(call_id = %call_id, "RTPEngine offer for re-INVITE failed: {error}");
                            }
                        }
                    }
                }
            }
        }

        // Update Content-Length after SDP rewrite (o=/s= and RTPEngine changes may alter body size)
        if !forwarded.body.is_empty() {
            forwarded.headers.set("Content-Length", forwarded.body.len().to_string());
        }

        // Rewrite RURI to target leg's remote Contact (RFC 3261 §12.2.1.1).
        // In-dialog requests MUST use the remote target from the last 2xx/INVITE.
        if let Some(ref uri_str) = target_remote_contact {
            if let Ok(parsed) = parse_uri_standalone(uri_str) {
                forwarded.start_line = StartLine::Request(crate::sip::message::RequestLine {
                    method: crate::sip::message::Method::Invite,
                    request_uri: parsed,
                    version: crate::sip::message::Version::sip_2_0(),
                });
            }
        }

        // Rewrite Contact to what we advertised to the target leg
        if let Some(ref contact) = target_local_contact {
            forwarded.headers.set("Contact", contact.clone());
        }

        // In-dialog requests follow the dialog route set (RFC 3261 §12.2.1.1):
        // send to the route-set first hop, not the cached INVITE next-hop. In an
        // IMS topology the INVITE was sent to a non-Record-Routing I-CSCF while
        // the dialog routes via the S-CSCF, so the cached leg destination is the
        // wrong target for an in-dialog re-INVITE (mirrors the PRACK/ACK/BYE
        // paths). Falls back to the cached destination when there is no route set.
        let (send_dest, send_transport) =
            resolve_in_dialog_destination(&target_route_set, state, destination, transport);

        // Track the re-INVITE branch → call_id for response routing.
        // Encode the direction so the response handler knows where to relay.
        // Store the originator's Via(s) so we can restore them on the response.
        let direction = if from_a_leg { "reinvite:a2b" } else { "reinvite:b2a" };
        let originator_vias = message.headers.get_all("Via")
            .map(|v| v.to_vec())
            .unwrap_or_default();
        let mut reinvite_leg = Leg::new_b_leg(
            leg_call_id,
            leg_from_tag,
            direction.to_string(),
            branch.clone(),
            LegTransport {
                remote_addr: send_dest,
                connection_id: ConnectionId::default(),
                transport: send_transport,
                // Anchor the tracking leg on the target's socket (the A-leg's arrival
                // listener for B→A) so a post-teardown zombie re-ACK to this leg
                // still leaves from the right port on a multi-homed host.
                local_addr: target_local_addr,
            },
        );
        reinvite_leg.stored_vias = originator_vias;
        reinvite_leg.stored_cseq = message.headers.cseq().map(|c| c.to_string());
        state.call_actors.add_b_leg(&call_id, reinvite_leg);

        // Forward B→A on the A-leg's anchored socket (multi-homed source-port
        // parity — pins the UDP egress; connection selection is unchanged, same as
        // send_b2bua_to_bleg). A→B (target_local_addr None) egresses as before.
        if let Some(source) = target_local_addr {
            let data = Bytes::from(forwarded.to_bytes());
            let target = RelayTarget {
                address: send_dest,
                transport: Some(send_transport),
                server_name: None,
            };
            send_to_target(data, &target, send_transport, ConnectionId::default(), Some(source), state);
        } else {
            send_b2bua_to_bleg(forwarded, send_transport, send_dest, state);
        }

        // Increment the target leg's local CSeq after sending the re-INVITE
        if let Some(mut call) = state.call_actors.get_call_mut(&call_id) {
            if from_a_leg {
                if let Some(winner_idx) = call.winner {
                    if let Some(b_leg) = call.b_legs.get_mut(winner_idx) {
                        b_leg.dialog.local_cseq += 1;
                    }
                }
            } else {
                call.a_leg.dialog.local_cseq += 1;
            }
        }
    }

    // Reset session timer on successful re-INVITE (timer reset happens on 200 OK
    // via handle_b2bua_response which calls set_state — we reset the timer there)
}

/// Bridge an in-dialog UPDATE (RFC 3311) across the B2BUA.
///
/// Mirrors `handle_b2bua_reinvite` minus the INVITE-specific bits:
///   * no 491 glare gate — RFC 3311 §5.2 explicitly permits UPDATE before
///     the initial INVITE is ACKed, and §5.1 places no analogue of RFC 3261
///     §14.1's pending-offer rule on UPDATE
///   * no ACK on 2xx — RFC 3311 §5.4: UPDATE is a normal non-INVITE
///     transaction; the 2xx ACK rule applies to INVITE only
///   * SDP / RTPEngine path is conditional on a non-empty body — empty-body
///     UPDATEs (RFC 4028 session-timer refresh — the common case) bridge
///     headers only
///
/// Tracking uses the `update:` / `update_done:` target_uri prefixes so that
/// concurrent re-INVITE and UPDATE on the same dialog don't collide on a
/// single B-leg slot.
fn handle_b2bua_update(
    inbound: InboundMessage,
    message: SipMessage,
    state: &DispatcherState,
) {
    let sip_call_id = message.headers.get("Call-ID")
        .map(|s| s.to_string())
        .unwrap_or_default();

    let call_id = match state.call_actors.find_by_sip_call_id(&sip_call_id) {
        Some(id) => id,
        None => {
            warn!(sip_call_id = %sip_call_id, "B2BUA UPDATE: no matching call");
            return;
        }
    };

    let (from_a_leg, a_leg, winner_b_leg) = match state.call_actors.get_call(&call_id) {
        Some(call) => {
            let from_a = inbound.remote_addr == call.a_leg.transport.remote_addr;
            let b_leg = call.winner.and_then(|i| call.b_legs.get(i).cloned());
            (from_a, call.a_leg.clone(), b_leg)
        }
        None => return,
    };

    let (target_remote_contact, target_local_contact) = if from_a_leg {
        winner_b_leg.as_ref()
            .map(|b| (b.dialog.remote_contact.clone(), b.dialog.local_contact.clone()))
            .unwrap_or((None, None))
    } else {
        (a_leg.dialog.remote_contact.clone(), a_leg.dialog.local_contact.clone())
    };

    debug!(
        call_id = %call_id,
        from_a_leg = from_a_leg,
        has_body = !message.body.is_empty(),
        "B2BUA: forwarding UPDATE"
    );

    // Send 100 Trying so the originator stops T1-backoff retransmits while we
    // forward. UPDATE responses are usually fast, but the 100 keeps the
    // request-side UAC quiet over UDP if the far end stalls.
    let trying = build_response(&message, 100, "Trying", state.server_header.as_deref(), &[]);
    // Answer on the same listener the request arrived on so a multi-homed UDP
    // host keeps a symmetric source port (a peer that sent to :5066 rejects a
    // reply sourced from :5060). No-op for stream transports / single listener.
    send_message_from(
        trying,
        inbound.transport,
        inbound.remote_addr,
        inbound.connection_id,
        Some(inbound.local_addr),
        state,
    );

    let branch = TransactionKey::generate_branch();
    let mut forwarded = message.clone();

    let update_target = if from_a_leg {
        if let Some(b_leg) = &winner_b_leg {
            crate::b2bua::actor::Dialog::rewrite_headers(
                &mut forwarded,
                &b_leg.dialog.call_id,
                a_leg.dialog.remote_tag.as_deref().unwrap_or(""),
                &b_leg.dialog.local_tag,
                b_leg.dialog.remote_tag.as_deref(),
            );
            Some((b_leg.transport.remote_addr, b_leg.transport.transport, b_leg.transport.local_addr, b_leg.dialog.call_id.clone(), b_leg.dialog.local_tag.clone()))
        } else {
            warn!(call_id = %call_id, "B2BUA UPDATE: no winning B-leg");
            return;
        }
    } else {
        if let Some(b_leg) = &winner_b_leg {
            crate::b2bua::actor::Dialog::rewrite_headers(
                &mut forwarded,
                &a_leg.dialog.call_id,
                &b_leg.dialog.local_tag,
                a_leg.dialog.remote_tag.as_deref().unwrap_or(""),
                Some(&a_leg.dialog.local_tag),
            );
        }
        Some((a_leg.transport.remote_addr, a_leg.transport.transport, a_leg.transport.local_addr, a_leg.dialog.call_id.clone(), a_leg.dialog.remote_tag.clone().unwrap_or_default()))
    };

    if let Some((destination, transport, target_local_addr, leg_call_id, leg_from_tag)) = update_target {
        let transport_str = format!("{}", transport).to_uppercase();
        let via_value = format!(
            "SIP/2.0/{} {}:{};branch={}",
            transport_str,
            state.via_host(&transport),
            // Via port = the target leg's anchored listener (A-leg's arrival socket
            // when forwarding B→A on a multi-homed host); via_port for the B-leg.
            a_leg_advertised_port(target_local_addr, state.via_port(&transport)),
            branch,
        );
        forwarded.headers.set("Via", via_value);

        // Strip cross-leg headers (same set as re-INVITE bridging).
        if let Some(ref ua) = state.user_agent_header {
            forwarded.headers.set("User-Agent", ua.clone());
        } else {
            forwarded.headers.remove("User-Agent");
        }
        forwarded.headers.remove("Server");
        forwarded.headers.remove("Allow");
        forwarded.headers.remove("Allow-Events");
        forwarded.headers.remove("Supported");
        forwarded.headers.remove("Require");
        forwarded.headers.remove("Proxy-Require");
        forwarded.headers.remove("P-Asserted-Identity");
        forwarded.headers.remove("P-Access-Network-Info");
        forwarded.headers.remove("Security-Verify");
        forwarded.headers.remove("Security-Client");
        forwarded.headers.remove("Authorization");
        forwarded.headers.remove("Proxy-Authorization");
        forwarded.headers.remove("Record-Route");
        forwarded.headers.remove("Route");

        let target_route_set = if from_a_leg {
            winner_b_leg.as_ref().map(|b| b.dialog.route_set.clone()).unwrap_or_default()
        } else {
            a_leg.dialog.route_set.clone()
        };
        for route in &target_route_set {
            forwarded.headers.add("Route", route.clone());
        }

        // From/To: stitch the target leg's URI string with the dialog tag.
        // The URI strings are captured at INVITE-send time without tags;
        // the tags arrive in the 2xx response and are stored separately
        // (see the splice at the 2xx capture path). Use ensure_tag so
        // we're robust to the splice not having run (e.g. a 401/407
        // retry path that resets remote_to_uri after the original 2xx,
        // or an early-dialog UPDATE before the 2xx — RFC 3311 §5.2).
        let (target_from_uri, target_from_tag, target_to_uri, target_to_tag) = if from_a_leg {
            let b = winner_b_leg.as_ref();
            (
                b.and_then(|b| b.dialog.local_from_uri.clone()),
                b.map(|b| b.dialog.local_tag.clone()),
                b.and_then(|b| b.dialog.remote_to_uri.clone()),
                b.and_then(|b| b.dialog.remote_tag.clone()),
            )
        } else {
            (
                a_leg.dialog.local_from_uri.clone(),
                Some(a_leg.dialog.local_tag.clone()),
                a_leg.dialog.remote_to_uri.clone(),
                a_leg.dialog.remote_tag.clone(),
            )
        };
        if let Some(uri) = target_from_uri {
            forwarded.headers.set(
                "From",
                crate::b2bua::actor::ensure_tag(&uri, target_from_tag.as_deref()),
            );
        }
        if let Some(uri) = target_to_uri {
            forwarded.headers.set(
                "To",
                crate::b2bua::actor::ensure_tag(&uri, target_to_tag.as_deref()),
            );
        }

        // CSeq: target leg's local sequence + UPDATE method. Per RFC 3311
        // §6, UPDATE shares the dialog's CSeq sequence with INVITE/BYE.
        let target_cseq = if from_a_leg {
            winner_b_leg.as_ref().map(|b| b.dialog.local_cseq).unwrap_or(1)
        } else {
            a_leg.dialog.local_cseq
        };
        forwarded.headers.set("CSeq", format!("{} UPDATE", target_cseq));

        let _ = crate::proxy::core::decrement_max_forwards(&mut forwarded.headers);

        // Body-aware media handling: empty-body UPDATE (session-timer
        // refresh) bypasses SDP rewrite and rtpengine entirely.
        if !forwarded.body.is_empty() {
            let sdp_addr = state.via_host(&transport);
            sanitize_sdp_identity(&mut forwarded.body, &state.sdp_name, Some(&sdp_addr));

            if let (Some(ref rtpengine_set), Some(ref media_sessions), Some(ref profiles)) =
                (&state.rtpengine_set, &state.rtpengine_sessions, &state.rtpengine_profiles)
            {
                let a_sip_call_id = &a_leg.dialog.call_id;
                if let Some(session) = media_sessions.get(a_sip_call_id) {
                    if let Some(profile) = profiles.get(&session.profile) {
                        let offer_tag = if from_a_leg {
                            session.from_tag.as_str()
                        } else {
                            session.to_tag.as_deref().unwrap_or(session.from_tag.as_str())
                        };
                        let offer_flags = profile.offer.clone();
                        match tokio::task::block_in_place(|| {
                            tokio::runtime::Handle::current().block_on(
                                rtpengine_set.offer(&session.call_id, offer_tag, &forwarded.body, &offer_flags)
                            )
                        }) {
                            Ok(rewritten_sdp) => {
                                forwarded.body = rewritten_sdp;
                                debug!(call_id = %call_id, "RTPEngine: rewrote UPDATE SDP (offer)");
                            }
                            Err(error) => {
                                warn!(call_id = %call_id, "RTPEngine offer for UPDATE failed: {error}");
                            }
                        }
                    }
                }
            }
            forwarded.headers.set("Content-Length", forwarded.body.len().to_string());
        }

        // RURI = target leg's remote Contact (RFC 3261 §12.2.1.1).
        if let Some(ref uri_str) = target_remote_contact {
            if let Ok(parsed) = parse_uri_standalone(uri_str) {
                forwarded.start_line = StartLine::Request(crate::sip::message::RequestLine {
                    method: crate::sip::message::Method::Update,
                    request_uri: parsed,
                    version: crate::sip::message::Version::sip_2_0(),
                });
            }
        }

        if let Some(ref contact) = target_local_contact {
            forwarded.headers.set("Contact", contact.clone());
        }

        // In-dialog requests follow the dialog route set (RFC 3261 §12.2.1.1):
        // send to the route-set first hop, not the cached INVITE next-hop. In an
        // IMS topology the INVITE was sent to a non-Record-Routing I-CSCF while
        // the dialog routes via the S-CSCF, so the cached leg destination is the
        // wrong target for an in-dialog UPDATE (mirrors the PRACK/ACK/BYE paths).
        // Falls back to the cached destination when there is no route set.
        let (send_dest, send_transport) =
            resolve_in_dialog_destination(&target_route_set, state, destination, transport);

        // Track the UPDATE branch under "update:" so the response handler
        // routes the cross-leg response correctly without colliding with a
        // concurrent re-INVITE on the same dialog.
        let direction = if from_a_leg { "update:a2b" } else { "update:b2a" };
        let originator_vias = message.headers.get_all("Via")
            .map(|v| v.to_vec())
            .unwrap_or_default();
        let mut update_leg = Leg::new_b_leg(
            leg_call_id,
            leg_from_tag,
            direction.to_string(),
            branch.clone(),
            LegTransport {
                remote_addr: send_dest,
                connection_id: ConnectionId::default(),
                transport: send_transport,
                // Anchor the tracking leg on the target's socket (the A-leg's arrival
                // listener for B→A) so a post-teardown zombie re-ACK to this leg
                // still leaves from the right port on a multi-homed host.
                local_addr: target_local_addr,
            },
        );
        update_leg.stored_vias = originator_vias;
        update_leg.stored_cseq = message.headers.cseq().map(|c| c.to_string());
        state.call_actors.add_b_leg(&call_id, update_leg);

        // Forward B→A on the A-leg's anchored socket (multi-homed source-port
        // parity — pins the UDP egress; connection selection is unchanged, same as
        // send_b2bua_to_bleg). A→B (target_local_addr None) egresses as before.
        if let Some(source) = target_local_addr {
            let data = Bytes::from(forwarded.to_bytes());
            let target = RelayTarget {
                address: send_dest,
                transport: Some(send_transport),
                server_name: None,
            };
            send_to_target(data, &target, send_transport, ConnectionId::default(), Some(source), state);
        } else {
            send_b2bua_to_bleg(forwarded, send_transport, send_dest, state);
        }

        // Bump local CSeq on the target leg after sending.
        if let Some(mut call) = state.call_actors.get_call_mut(&call_id) {
            if from_a_leg {
                if let Some(winner_idx) = call.winner {
                    if let Some(b_leg) = call.b_legs.get_mut(winner_idx) {
                        b_leg.dialog.local_cseq += 1;
                    }
                }
            } else {
                call.a_leg.dialog.local_cseq += 1;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SRS — Session Recording Server handlers
// ---------------------------------------------------------------------------

/// Check if an incoming INVITE is a SIPREC recording request.
///
/// Detection: Content-Type is `multipart/mixed` AND the body contains
/// `application/rs-metadata+xml`.
fn is_siprec_invite(message: &SipMessage) -> bool {
    let content_type = match message.headers.get("Content-Type") {
        Some(content_type) => content_type,
        None => return false,
    };

    if !content_type.to_ascii_lowercase().contains("multipart/mixed") {
        return false;
    }

    // Quick check: does the body contain the metadata content type?
    if message.body.is_empty() {
        return false;
    }
    let body_str = String::from_utf8_lossy(&message.body);
    body_str.contains("application/rs-metadata+xml")
}

/// Handle an inbound SIPREC INVITE (SRC → SRS).
///
/// Parses the multipart body, extracts SDP and recording metadata,
/// creates an SRS session, optionally sets up RTPEngine recording,
/// and sends 200 OK back to the SRC.
fn handle_srs_invite(
    inbound: InboundMessage,
    message: SipMessage,
    srs_manager: Arc<crate::srs::SrsManager>,
    state: &Arc<DispatcherState>,
) {
    let state = Arc::clone(state);
    tokio::spawn(async move {
        let call_id = message.headers.get("Call-ID")
            .map(|s| s.to_string())
            .unwrap_or_default();
        let from_tag = message.headers.get("From")
            .and_then(|from| from.split("tag=").nth(1))
            .map(|tag| tag.split(';').next().unwrap_or(tag).trim().to_string())
            .unwrap_or_default();

        info!(
            call_id = %call_id,
            remote = %inbound.remote_addr,
            "SRS: received SIPREC INVITE"
        );

        // Parse the multipart body.
        let content_type = match message.headers.get("Content-Type") {
            Some(content_type) => content_type.clone(),
            None => {
                warn!(call_id = %call_id, "SRS: SIPREC INVITE missing Content-Type");
                let response = build_response(&message, 400, "Bad Request", state.server_header.as_deref(), &[]);
                send_message_from(response, inbound.transport, inbound.remote_addr, inbound.connection_id, Some(inbound.local_addr), &state);
                return;
            }
        };

        if message.body.is_empty() {
            warn!(call_id = %call_id, "SRS: SIPREC INVITE has no body");
            let response = build_response(&message, 400, "Bad Request", state.server_header.as_deref(), &[]);
            send_message_from(response, inbound.transport, inbound.remote_addr, inbound.connection_id, Some(inbound.local_addr), &state);
            return;
        }
        let body = message.body.clone();

        let parts = match crate::siprec::multipart::parse_multipart(&content_type, &body) {
            Ok(parts) => parts,
            Err(error) => {
                warn!(call_id = %call_id, error = %error, "SRS: failed to parse multipart body");
                let response = build_response(&message, 400, "Bad Request", state.server_header.as_deref(), &[]);
                send_message_from(response, inbound.transport, inbound.remote_addr, inbound.connection_id, Some(inbound.local_addr), &state);
                return;
            }
        };

        // Extract SDP and metadata parts.
        let sdp_part = crate::siprec::multipart::find_part(&parts, "application/sdp");
        let metadata_part = crate::siprec::multipart::find_part(&parts, "application/rs-metadata");

        let metadata_xml = match metadata_part {
            Some(part) => String::from_utf8_lossy(&part.body).to_string(),
            None => {
                warn!(call_id = %call_id, "SRS: no rs-metadata+xml part in SIPREC INVITE");
                let response = build_response(&message, 400, "Bad Request", state.server_header.as_deref(), &[]);
                send_message_from(response, inbound.transport, inbound.remote_addr, inbound.connection_id, Some(inbound.local_addr), &state);
                return;
            }
        };

        // Parse the recording metadata XML.
        let metadata = match crate::siprec::metadata::parse_recording_metadata(&metadata_xml) {
            Ok(metadata) => metadata,
            Err(error) => {
                warn!(call_id = %call_id, error = %error, "SRS: failed to parse recording metadata");
                let response = build_response(&message, 400, "Bad Request", state.server_header.as_deref(), &[]);
                send_message_from(response, inbound.transport, inbound.remote_addr, inbound.connection_id, Some(inbound.local_addr), &state);
                return;
            }
        };

        info!(
            call_id = %call_id,
            session_id = %metadata.session_id,
            participants = metadata.participants.len(),
            streams = metadata.streams.len(),
            "SRS: parsed SIPREC metadata"
        );

        // Invoke Python @srs.on_invite handler if registered.
        let should_accept = {
            let engine_state = state.engine.state();
            let srs_handlers = engine_state.handlers_for(&HandlerKind::SrsOnInvite);
            if !srs_handlers.is_empty() {
                let py_metadata = crate::script::api::srs::PyRecordingMetadata::from_metadata(&metadata);
                let result = pyo3::Python::attach(|python| {
                    let py_meta = match pyo3::Py::new(python, py_metadata) {
                        Ok(meta) => meta,
                        Err(error) => {
                            warn!(call_id = %call_id, error = %error, "SRS: failed to create PyRecordingMetadata");
                            return true; // Accept on error
                        }
                    };
                    for handler in &srs_handlers {
                        match handler.callable.call1(python, (py_meta.clone_ref(python),)) {
                            Ok(result) => {
                                if let Ok(accepted) = result.extract::<bool>(python) {
                                    if !accepted {
                                        return false;
                                    }
                                }
                            }
                            Err(error) => {
                                warn!(call_id = %call_id, error = %error, "SRS: on_invite handler error");
                            }
                        }
                    }
                    true
                });
                drop(engine_state);
                result
            } else {
                drop(engine_state);
                true
            }
        };

        if !should_accept {
            info!(call_id = %call_id, "SRS: recording rejected by script");
            let response = build_response(&message, 403, "Forbidden", state.server_header.as_deref(), &[]);
            send_message_from(response, inbound.transport, inbound.remote_addr, inbound.connection_id, Some(inbound.local_addr), &state);
            return;
        }

        // Check if this is a re-INVITE for an existing session.
        let is_reinvite = srs_manager.is_srs_session(&call_id);

        let (session_id, to_tag) = if is_reinvite {
            // Re-INVITE: update existing session metadata, reuse to-tag.
            match srs_manager.update_session(&call_id, metadata) {
                Some(to_tag) => {
                    let session_id = srs_manager.session_for_call_id(&call_id)
                        .unwrap_or_default();
                    (session_id, to_tag)
                }
                None => {
                    warn!(call_id = %call_id, "SRS: re-INVITE but session not found");
                    let response = build_response(&message, 481, "Call/Transaction Does Not Exist", state.server_header.as_deref(), &[]);
                    send_message_from(response, inbound.transport, inbound.remote_addr, inbound.connection_id, Some(inbound.local_addr), &state);
                    return;
                }
            }
        } else {
            // Initial INVITE: create a new session.
            match srs_manager.create_session(&call_id, &from_tag, metadata) {
                Some(result) => result,
                None => {
                    warn!(call_id = %call_id, "SRS: session creation failed (max sessions?)");
                    let response = build_response(&message, 503, "Service Unavailable", state.server_header.as_deref(), &[]);
                    send_message_from(response, inbound.transport, inbound.remote_addr, inbound.connection_id, Some(inbound.local_addr), &state);
                    return;
                }
            }
        };

        // Set up RTPEngine recording if available.
        let answer_sdp = if let (Some(ref rtpengine_set), Some(sdp_part)) = (&state.rtpengine_set, sdp_part) {
            let profile_name = srs_manager.rtpengine_profile();
            let profile_registry = crate::rtpengine::profile::ProfileRegistry::new();
            let profile = profile_registry.get(profile_name);

            if let Some(profile) = profile {
                // Create recording directory for RTPEngine.
                if let Some(recording_dir) = srs_manager.recording_dir(&session_id) {
                    let _ = tokio::fs::create_dir_all(&recording_dir).await;

                    let recording_dir_str = recording_dir.display().to_string();

                    // Split the dual-m= SDP into two single-m= SDPs (one per
                    // call direction).  RTPEngine needs a separate offer/answer
                    // pair to fully activate both media legs for recording.
                    let (sdp1, sdp2) = crate::siprec::split_dual_sdp(&sdp_part.body);

                    let mut offer_flags = profile.offer.clone();
                    offer_flags.record_call = true;
                    offer_flags.record_path = Some(recording_dir_str.clone());

                    let mut answer_flags = profile.answer.clone();
                    answer_flags.record_call = true;
                    answer_flags.record_path = Some(recording_dir_str);

                    // Step 1: offer() with first m= line (caller stream).
                    let offer_result = rtpengine_set.offer(
                        &call_id, &from_tag, &sdp1, &offer_flags,
                    ).await;

                    match offer_result {
                        Ok(offer_response_sdp) => {
                            // Step 2: answer() with second m= line (callee stream).
                            let srs_to_tag = format!("srs-{}", uuid::Uuid::new_v4().as_simple());
                            let answer_result = rtpengine_set.answer(
                                &call_id, &from_tag, &srs_to_tag, &sdp2, &answer_flags,
                            ).await;

                            match answer_result {
                                Ok(answer_response_sdp) => {
                                    // Combine both response SDPs into a single
                                    // recvonly SDP with 2 labeled m= lines.
                                    let combined = crate::siprec::combine_srs_answer_sdps(
                                        &offer_response_sdp,
                                        &answer_response_sdp,
                                    );
                                    srs_manager.activate_session(&session_id);
                                    Some(combined)
                                }
                                Err(error) => {
                                    warn!(
                                        call_id = %call_id,
                                        session_id = %session_id,
                                        error = %error,
                                        "SRS: RTPEngine answer failed"
                                    );
                                    srs_manager.fail_session(&session_id, &error.to_string());
                                    None
                                }
                            }
                        }
                        Err(error) => {
                            warn!(
                                call_id = %call_id,
                                session_id = %session_id,
                                error = %error,
                                "SRS: RTPEngine offer failed"
                            );
                            srs_manager.fail_session(&session_id, &error.to_string());
                            None
                        }
                    }
                } else {
                    None
                }
            } else {
                warn!(
                    call_id = %call_id,
                    profile = %profile_name,
                    "SRS: unknown RTPEngine profile"
                );
                None
            }
        } else {
            // No RTPEngine — accept without media anchoring.
            srs_manager.activate_session(&session_id);
            None
        };

        // Build 200 OK response.
        let mut response_builder = SipMessageBuilder::new()
            .response(200, "OK".to_string());

        // Copy Via, From headers.
        if let Some(vias) = message.headers.get_all("Via") {
            for via in vias {
                response_builder = response_builder.via(via.clone());
            }
        }
        if let Some(from) = message.headers.from() {
            response_builder = response_builder.from(from.clone());
        }

        // Set To with our generated tag.
        if let Some(to) = message.headers.to() {
            let to_with_tag = if to.contains("tag=") {
                to.clone()
            } else {
                format!("{to};tag={to_tag}")
            };
            response_builder = response_builder.to(to_with_tag);
        }

        if let Some(call_id_header) = message.headers.get("Call-ID") {
            response_builder = response_builder.call_id(call_id_header.clone());
        }
        if let Some(cseq) = message.headers.get("CSeq") {
            response_builder = response_builder.cseq(cseq.clone());
        }

        // Add Contact header.
        response_builder = response_builder.header(
            "Contact",
            format!("<sip:srs@{}>", state.local_addr),
        );

        // Add SDP body (from RTPEngine or echo back original).
        // Sanitize o=/s= lines to hide the SRC's identity (e.g. "FreeSWITCH").
        // Flip SDP direction for the answer: the SRC offered sendonly (it sends
        // forked media), so the SRS answer must be recvonly (we receive it).
        // RTPEngine's offer response preserves the offer direction — we must flip
        // it since this SDP goes into the SIP 200 OK answer (RFC 3264 §5).
        let local_ip = state.local_addr.ip().to_string();
        if let Some(mut sdp) = answer_sdp {
            // combine_srs_answer_sdps already sets a=recvonly — no direction
            // flip needed.  Only sanitize the o=/s= identity lines.
            sanitize_sdp_identity(&mut sdp, "siphon", Some(&local_ip));
            response_builder = response_builder
                .header("Content-Type", "application/sdp".to_string())
                .body(sdp);
        } else if let Some(sdp_part) = sdp_part {
            let mut sdp = sdp_part.body.clone();
            fix_srs_answer_sdp_direction(&mut sdp);
            sanitize_sdp_identity(&mut sdp, "siphon", Some(&local_ip));
            response_builder = response_builder
                .header("Content-Type", "application/sdp".to_string())
                .body(sdp);
        } else {
            response_builder = response_builder.content_length(0);
        }

        if let Some(ref server) = state.server_header {
            response_builder = response_builder.header("Server", server.clone());
        }

        match response_builder.build() {
            Ok(response) => {
                info!(
                    call_id = %call_id,
                    session_id = %session_id,
                    "SRS: sending 200 OK to SRC"
                );
                send_message_from(response, inbound.transport, inbound.remote_addr, inbound.connection_id, Some(inbound.local_addr), &state);
            }
            Err(error) => {
                error!(call_id = %call_id, error = %error, "SRS: failed to build 200 OK");
                srs_manager.fail_session(&session_id, &error.to_string());
            }
        }
    });
}

/// Handle a BYE for an active SRS recording session.
fn handle_srs_bye(
    inbound: InboundMessage,
    message: SipMessage,
    call_id: &str,
    srs_manager: Arc<crate::srs::SrsManager>,
    state: &Arc<DispatcherState>,
) {
    let call_id = call_id.to_string();
    let state = Arc::clone(state);
    tokio::spawn(async move {
        info!(call_id = %call_id, "SRS: received BYE from SRC");

        // Stop recording via RTPEngine.
        if let Some(ref rtpengine_set) = state.rtpengine_set {
            let from_tag = message.headers.get("From")
                .and_then(|from| from.split("tag=").nth(1))
                .map(|tag| tag.split(';').next().unwrap_or(tag).trim().to_string())
                .unwrap_or_default();

            if let Err(error) = rtpengine_set.delete(&call_id, &from_tag).await {
                warn!(
                    call_id = %call_id,
                    error = %error,
                    "SRS: RTPEngine delete failed (session may have already ended)"
                );
            }
        }

        // Stop the SRS session and get the recording record.
        let record = srs_manager.stop_session(&call_id);

        // Send 200 OK for the BYE.
        let response = build_response(&message, 200, "OK", state.server_header.as_deref(), &[]);
        send_message_from(response, inbound.transport, inbound.remote_addr, inbound.connection_id, Some(inbound.local_addr), &state);

        // Store recording metadata via configured backend.
        if let Some(record) = record {
            // Invoke @srs.on_session_end hook.
            {
                let engine_state = state.engine.state();
                let end_handlers = engine_state.handlers_for(&HandlerKind::SrsOnSessionEnd);
                if !end_handlers.is_empty() {
                    let py_session = crate::script::api::srs::PySrsSession::from_record(&record);
                    pyo3::Python::attach(|python| {
                        if let Ok(py_sess) = pyo3::Py::new(python, py_session) {
                            for handler in &end_handlers {
                                if let Err(error) = handler.callable.call1(python, (py_sess.clone_ref(python),)) {
                                    warn!(call_id = %call_id, error = %error, "SRS: on_session_end handler error");
                                }
                            }
                        }
                    });
                }
            }

            crate::srs::storage::store_recording(srs_manager.config(), &record).await;
        }
    });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sip::message::Method;
    use crate::sip::parser::parse_sip_message;
    use crate::sip::uri::SipUri;
    use crate::sip::builder::SipMessageBuilder;

    // -----------------------------------------------------------------------
    // Media CDR from an end-of-call summary (media.backend: siphon-rtp)
    // -----------------------------------------------------------------------

    #[test]
    fn media_summary_to_cdr_flattens_legs() {
        use crate::rtpengine::events::{CallLegSummary, CallSummary};

        fn measured_leg(tag: &str, codec: &str) -> CallLegSummary {
            CallLegSummary {
                tag: tag.to_string(),
                codec: Some(codec.to_string()),
                packets_in: 2100,
                bytes_in: 336_000,
                packets_out: 2098,
                bytes_out: 335_680,
                packets_dropped: 2,
                ssrc: Some(0x0102_0304),
                packets_lost: Some(6),
                loss_percent: Some(0.3),
                jitter_ms: Some(4.2),
                rtt_ms: Some(21.0),
                mos_average: Some(4.11),
                mos_min: Some(3.9),
                mos_max: Some(4.3),
                mos_basis: Some("full".to_string()),
            }
        }

        // A counters-only far leg (plain in-kernel relay, no actor) — every
        // quality field is None and must be omitted from the CDR, not empty.
        let far = CallLegSummary {
            tag: "far-tag".to_string(),
            codec: None,
            packets_in: 2099,
            bytes_in: 335_840,
            packets_out: 2100,
            bytes_out: 336_000,
            packets_dropped: 0,
            ssrc: None,
            packets_lost: None,
            loss_percent: None,
            jitter_ms: None,
            rtt_ms: None,
            mos_average: None,
            mos_min: None,
            mos_max: None,
            mos_basis: None,
        };

        let summary = CallSummary {
            call_id: "call-9".to_string(),
            reason: "delete".to_string(),
            duration_ms: 42_500,
            legs: vec![measured_leg("near-tag", "AMR-WB"), far],
        };

        let cdr = media_summary_to_cdr(&summary);

        assert_eq!(cdr.call_id, "call-9");
        assert_eq!(cdr.method, "MEDIA");
        assert_eq!(cdr.response_code, 0);
        // Media lifetime surfaces both as the standard duration and precisely.
        assert!((cdr.duration_secs - 42.5).abs() < 1e-9);
        assert_eq!(cdr.extra.get("media_duration_ms").map(String::as_str), Some("42500"));
        assert_eq!(cdr.extra.get("media_reason").map(String::as_str), Some("delete"));

        // Near (measured) leg — counters + quality present under `near_`.
        assert_eq!(cdr.extra.get("near_tag").map(String::as_str), Some("near-tag"));
        assert_eq!(cdr.extra.get("near_codec").map(String::as_str), Some("AMR-WB"));
        assert_eq!(cdr.extra.get("near_packets_in").map(String::as_str), Some("2100"));
        assert_eq!(cdr.extra.get("near_bytes_out").map(String::as_str), Some("335680"));
        assert_eq!(cdr.extra.get("near_packets_dropped").map(String::as_str), Some("2"));
        assert_eq!(cdr.extra.get("near_packets_lost").map(String::as_str), Some("6"));
        assert_eq!(cdr.extra.get("near_loss_percent").map(String::as_str), Some("0.3"));
        assert_eq!(cdr.extra.get("near_mos_average").map(String::as_str), Some("4.11"));
        assert_eq!(cdr.extra.get("near_mos_basis").map(String::as_str), Some("full"));

        // Far (counters-only) leg — quality fields omitted entirely.
        assert_eq!(cdr.extra.get("far_tag").map(String::as_str), Some("far-tag"));
        assert_eq!(cdr.extra.get("far_packets_in").map(String::as_str), Some("2099"));
        assert!(!cdr.extra.contains_key("far_codec"));
        assert!(!cdr.extra.contains_key("far_ssrc"));
        assert!(!cdr.extra.contains_key("far_mos_average"));
        assert!(!cdr.extra.contains_key("far_mos_basis"));
    }

    #[test]
    fn media_summary_to_cdr_indexes_extra_legs() {
        use crate::rtpengine::events::{CallLegSummary, CallSummary};

        fn bare_leg(tag: &str) -> CallLegSummary {
            CallLegSummary {
                tag: tag.to_string(),
                codec: None,
                packets_in: 1,
                bytes_in: 2,
                packets_out: 3,
                bytes_out: 4,
                packets_dropped: 0,
                ssrc: None,
                packets_lost: None,
                loss_percent: None,
                jitter_ms: None,
                rtt_ms: None,
                mos_average: None,
                mos_min: None,
                mos_max: None,
                mos_basis: None,
            }
        }

        // A third leg (MPTY / conference) indexes as `leg2_`, not near/far.
        let summary = CallSummary {
            call_id: "conf-1".to_string(),
            reason: "media_timeout".to_string(),
            duration_ms: 1_000,
            legs: vec![bare_leg("a"), bare_leg("b"), bare_leg("c")],
        };
        let cdr = media_summary_to_cdr(&summary);
        assert_eq!(cdr.extra.get("near_tag").map(String::as_str), Some("a"));
        assert_eq!(cdr.extra.get("far_tag").map(String::as_str), Some("b"));
        assert_eq!(cdr.extra.get("leg2_tag").map(String::as_str), Some("c"));
        assert_eq!(cdr.extra.get("media_reason").map(String::as_str), Some("media_timeout"));
    }

    // -----------------------------------------------------------------------
    // A-leg advertised port (multi-homed Contact / reply-socket anchoring)
    // -----------------------------------------------------------------------

    #[test]
    fn a_leg_advertised_port_prefers_arrival_socket() {
        // Multi-homed host: INVITE arrived on :5066 while the default listener is
        // :5060. The A-leg Contact / dialog anchor must be the arrival port, else
        // in-dialog requests are directed to a port the dialog isn't on.
        let arrival: SocketAddr = "172.31.24.94:5066".parse().unwrap();
        assert_eq!(a_leg_advertised_port(Some(arrival), 5060), 5066);
    }

    #[test]
    fn a_leg_advertised_port_falls_back_to_via_port_when_unknown() {
        // Single-listener host (or arrival socket not captured): fall back to the
        // default per-transport listener port — where the two are the same anyway.
        assert_eq!(a_leg_advertised_port(None, 5060), 5060);
        // And when the arrival socket happens to equal the default, still correct.
        let same: SocketAddr = "10.0.0.1:5060".parse().unwrap();
        assert_eq!(a_leg_advertised_port(Some(same), 5060), 5060);
    }

    // -----------------------------------------------------------------------
    // Imperative B2BUA terminate helpers (b2bua.terminate / session timer)
    // -----------------------------------------------------------------------

    #[test]
    fn format_normal_clearing_reason_is_q850_cause_16() {
        assert_eq!(
            format_normal_clearing_reason("Normal Clearing"),
            "Q.850;cause=16;text=\"Normal Clearing\"",
        );
        // Embedded quotes are stripped so the header stays well-formed.
        assert_eq!(
            format_normal_clearing_reason("say \"hi\""),
            "Q.850;cause=16;text=\"say hi\"",
        );
    }

    #[test]
    fn parse_reason_cause_maps_sip_status_or_none() {
        // Build a BYE with an optional RFC 3326 Reason header via the parser
        // (the builder setters take String; raw parse matches the other fixtures).
        fn bye_with_reason(reason: Option<&str>) -> SipMessage {
            let mut raw = String::from("BYE sip:b@host SIP/2.0\r\n");
            raw.push_str("Via: SIP/2.0/UDP host:5060;branch=z9hG4bK1\r\n");
            raw.push_str("From: <sip:a@host>;tag=a\r\n");
            raw.push_str("To: <sip:b@host>;tag=b\r\n");
            raw.push_str("Call-ID: c@host\r\n");
            raw.push_str("CSeq: 1 BYE\r\n");
            if let Some(value) = reason {
                raw.push_str(&format!("Reason: {value}\r\n"));
            }
            raw.push_str("Content-Length: 0\r\n\r\n");
            parse_sip_message(&raw).expect("test fixture must parse").1
        }

        // SIP;cause=<status> maps via sip_status_to_cause_code.
        assert_eq!(
            parse_reason_cause(&bye_with_reason(Some("SIP;cause=486;text=\"Busy Here\""))),
            crate::diameter::rf::sip_status_to_cause_code(486),
        );
        // No Reason header → None.
        assert_eq!(parse_reason_cause(&bye_with_reason(None)), None);
        // Reason without a cause= param → None.
        assert_eq!(
            parse_reason_cause(&bye_with_reason(Some("SIP;text=\"no cause\""))),
            None,
        );
    }

    #[test]
    fn b2bua_terminate_call_unknown_id_is_false_no_panic() {
        // Unknown SIP Call-ID (and no running dispatcher in the test binary) is a
        // clean no-op — never panics, returns false — so an IVR racing a
        // caller-initiated BYE degrades gracefully.
        assert!(!b2bua_terminate_call("does-not-exist@nowhere", None));
        assert!(!b2bua_terminate_call(
            "does-not-exist@nowhere",
            Some("Normal Clearing")
        ));
    }

    #[test]
    fn b2bua_answer_and_progress_unknown_id_is_false_no_panic() {
        // Imperative call.answer()/progress() against an unknown call (and no
        // running dispatcher in the test binary) is a clean no-op — returns
        // false, never panics.
        let raw = concat!(
            "INVITE sip:echo@example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1\r\n",
            "From: <sip:alice@example.com>;tag=a\r\n",
            "To: <sip:echo@example.com>\r\n",
            "Call-ID: unknown-ivr@example.com\r\n",
            "CSeq: 1 INVITE\r\n",
            "Max-Forwards: 70\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        );
        let invite = parse_sip_message(raw).expect("test fixture must parse").1;
        assert!(!b2bua_answer_call("nope", &invite, 200, "OK", None, None));
        assert!(!b2bua_progress_call("nope", &invite, 183, "Session Progress", None, None));
    }

    /// Save a stream P-CSCF cache binding directly against a bare `Registrar`,
    /// so the flow-close decision helpers can be exercised without a running
    /// server.  `ue_ip` is the UE source address the SA-liveness set matches on.
    fn save_stream_binding(
        registrar: &crate::registrar::Registrar,
        aor: &str,
        user: &str,
        ue_ip: &str,
        connection_id: u64,
    ) {
        registrar
            .save_full(
                aor,
                SipUri::new(ue_ip.to_string()).with_user(user.to_string()),
                3600,
                1.0,
                format!("call-{user}"),
                1,
                Some(format!("{ue_ip}:5060").parse().unwrap()),
                Some("tcp".to_string()),
                None,
                None,
                vec![],
                crate::registrar::FlowCapture {
                    flow_token: Some(format!("tok-{user}")),
                    inbound_local_addr: None,
                    inbound_connection_id: Some(connection_id),
                },
                Vec::new(),
            )
            .unwrap();
    }

    #[test]
    fn flow_close_keep_set_retains_ipsec_ues() {
        // A closed IPsec flow is a recoverable RFC 5626 flow failure: the UE's
        // SA is still warm, so the binding must be retained (deferred to the
        // SA-idle sweep) rather than network-deregistered on the FIN.
        let registrar = crate::registrar::Registrar::default();
        save_stream_binding(&registrar, "sip:alice@ims.example.com", "alice", "100.65.0.2", 7);
        let bindings = registrar.bindings_for_connection(7);
        assert_eq!(bindings.len(), 1);

        let mut sa_ips = std::collections::HashSet::new();
        sa_ips.insert("100.65.0.2".parse::<std::net::IpAddr>().unwrap());

        let keep = flow_close_keep_set(&bindings, &sa_ips);
        assert_eq!(keep.len(), 1);
        assert!(keep.contains(&bindings[0].1.uri.to_string()));

        // Committing the close with that keep set detaches, never deregisters.
        assert!(registrar.close_flow(7, &keep).is_empty());
        assert!(registrar.is_registered("sip:alice@ims.example.com"));
    }

    #[test]
    fn flow_close_keep_set_deregs_non_ipsec() {
        // No SA for the UE IP (plain TCP / WSS WebRTC) — the stream close stays
        // an authoritative death signal, so nothing is retained and the binding
        // is removed immediately.
        let registrar = crate::registrar::Registrar::default();
        save_stream_binding(&registrar, "sip:bob@example.com", "bob", "100.65.0.9", 9);
        let bindings = registrar.bindings_for_connection(9);

        let keep = flow_close_keep_set(&bindings, &std::collections::HashSet::new());
        assert!(keep.is_empty());

        let removed = registrar.close_flow(9, &keep);
        assert_eq!(removed.len(), 1);
        assert!(!registrar.is_registered("sip:bob@example.com"));
    }

    // -----------------------------------------------------------------------
    // Registrar-liveness SA-idle sweep — SIP last-seen fold-in + probe
    // hysteresis (Part B, prodcore-1 false-dereg fix)
    // -----------------------------------------------------------------------

    fn ip(addr: &str) -> std::net::IpAddr {
        addr.parse().expect("test fixture IP must parse")
    }

    #[test]
    fn liveness_last_active_folds_sip_over_stale_kernel() {
        // The prod scenario: the kernel XFRM use-time is stuck at an old value
        // (never advances on the inbound-answered SA) while siphon's SIP
        // last-seen is fresh.  Folding takes the max, so the fresh SIP signal
        // wins and the binding reads as active.
        let stale_kernel = 1_000;
        let fresh_sip = 1_890;
        assert_eq!(liveness_last_active(stale_kernel, fresh_sip), 1_890);
        // Either input alone still yields the most recent evidence.
        assert_eq!(liveness_last_active(0, 42), 42);
        assert_eq!(liveness_last_active(42, 0), 42);
    }

    #[test]
    fn liveness_churn_fresh_sip_keeps_binding_active() {
        // A UE answered its keepalive 5 s ago (SIP stamp), but the kernel
        // use-time is stuck 300 s in the past.  With a 90 s idle window the
        // folded signal must read as recently-active → NOT re-probed.
        let now = 10_000u64;
        let idle_window = 90u64;
        let stale_kernel = now - 300;
        let fresh_sip = now - 5;
        let last_active = liveness_last_active(stale_kernel, fresh_sip);
        assert!(liveness_recently_active(now, last_active, idle_window));
        // Without the SIP fold-in the stale kernel value alone would look idle
        // and the UE would be probed every sweep — the bug being fixed.
        assert!(!liveness_recently_active(now, stale_kernel, idle_window));
    }

    #[test]
    fn liveness_recently_active_boundary() {
        let now = 1_000u64;
        // Exactly at the window edge counts as active (inclusive).
        assert!(liveness_recently_active(now, now - 90, 90));
        // One second past the window is idle.
        assert!(!liveness_recently_active(now, now - 91, 90));
        // A last_active in the future (clock skew) is never idle.
        assert!(liveness_recently_active(now, now + 10, 90));
    }

    #[test]
    fn liveness_miss_outcome_survives_then_reaps_at_threshold() {
        // threshold 2: sweep N is the first miss → keep (counter 1); sweep N+1
        // is the second consecutive miss → reap (counter reset to 0).  A UE
        // racing an ECM-IDLE→paging window misses one sweep and answers the
        // next, so it never reaches the reap.
        assert_eq!(liveness_miss_outcome(0, 2), (1, false));
        assert_eq!(liveness_miss_outcome(1, 2), (0, true));
    }

    #[test]
    fn liveness_miss_outcome_threshold_floor_of_one() {
        // A misconfigured threshold of 0 must not silently disable reaping — it
        // is floored to 1 (reap on the first miss), matching threshold == 1.
        assert_eq!(liveness_miss_outcome(0, 0), (0, true));
        assert_eq!(liveness_miss_outcome(0, 1), (0, true));
    }

    #[test]
    fn liveness_note_alive_stamps_and_clears_strike() {
        // The answered-probe / inbound side effect: record last-seen for the UE
        // IP and wipe any partial miss strike so a later transient miss starts
        // from zero.
        let last_seen: DashMap<std::net::IpAddr, u64> = DashMap::new();
        let misses: DashMap<String, u64> = DashMap::new();
        let aor = "sip:alice@ims.example.com";
        misses.insert(aor.to_string(), 1); // one strike already accrued

        liveness_note_alive(&last_seen, &misses, ip("100.65.0.2"), aor, 12_345);

        assert_eq!(last_seen.get(&ip("100.65.0.2")).map(|v| *v), Some(12_345));
        assert!(!misses.contains_key(aor), "answer must clear the miss strike");
    }

    #[test]
    fn liveness_hysteresis_survive_then_reset_on_answer() {
        // Model the two-sweep sequence against the real maps + decision helper:
        // sweep N misses (strike 1, kept), then the UE answers on sweep N+1
        // (strike cleared) — the binding survives with a clean slate.
        let last_seen: DashMap<std::net::IpAddr, u64> = DashMap::new();
        let misses: DashMap<String, u64> = DashMap::new();
        let aor = "sip:alice@ims.example.com";

        // Sweep N: probe unanswered.
        let before = misses.get(aor).map(|v| *v).unwrap_or(0);
        let (count, reap) = liveness_miss_outcome(before, 2);
        assert!(!reap, "first miss is within grace");
        misses.insert(aor.to_string(), count);
        assert_eq!(misses.get(aor).map(|v| *v), Some(1));

        // Sweep N+1: UE answers (paging completed) → strike cleared, survives.
        liveness_note_alive(&last_seen, &misses, ip("100.65.0.2"), aor, 20_000);
        assert!(!misses.contains_key(aor));
    }

    #[test]
    fn liveness_hysteresis_reaps_after_consecutive_misses() {
        // A genuinely gone UE misses every sweep: strike 1 (kept), strike 2 →
        // reap.  The vanish path is preserved, just delayed by the grace.
        let misses: DashMap<String, u64> = DashMap::new();
        let aor = "sip:gone@ims.example.com";

        let (count, reap) = liveness_miss_outcome(misses.get(aor).map(|v| *v).unwrap_or(0), 2);
        assert_eq!((count, reap), (1, false));
        misses.insert(aor.to_string(), count);

        let (count, reap) = liveness_miss_outcome(misses.get(aor).map(|v| *v).unwrap_or(0), 2);
        assert_eq!((count, reap), (0, true), "second consecutive miss reaps");
        if reap {
            misses.remove(aor);
        }
        assert!(!misses.contains_key(aor));
    }

    #[test]
    fn liveness_gc_drains_bookkeeping_for_gone_ues() {
        // Leak guard: entries for UEs whose SA is gone (deregistered / vanished)
        // must drain to baseline.  Reconciling against empty live sets clears
        // both maps entirely — the "drains to 0" invariant.
        let last_seen: DashMap<std::net::IpAddr, u64> = DashMap::new();
        let misses: DashMap<String, u64> = DashMap::new();
        last_seen.insert(ip("100.65.0.2"), 1);
        last_seen.insert(ip("100.65.0.3"), 2);
        misses.insert("sip:a@ims".to_string(), 1);
        misses.insert("sip:b@ims".to_string(), 1);

        // One UE still live (IP .2 / AoR a), the other gone.
        let mut live_ips = std::collections::HashSet::new();
        live_ips.insert(ip("100.65.0.2"));
        let mut live_aors = std::collections::HashSet::new();
        live_aors.insert("sip:a@ims".to_string());

        liveness_gc(&last_seen, &misses, &live_ips, &live_aors);
        assert_eq!(last_seen.len(), 1);
        assert!(last_seen.contains_key(&ip("100.65.0.2")));
        assert_eq!(misses.len(), 1);
        assert!(misses.contains_key("sip:a@ims"));

        // All UEs gone → both maps drain to baseline (0).
        liveness_gc(
            &last_seen,
            &misses,
            &std::collections::HashSet::new(),
            &std::collections::HashSet::new(),
        );
        assert_eq!(last_seen.len(), 0);
        assert_eq!(misses.len(), 0);
    }

    #[test]
    fn registrar_liveness_config_defaults_bias_toward_patience() {
        // The false-dereg fix ships new defaults: 2-sweep hysteresis and a 4 s
        // per-attempt probe timeout (one paging + reconnect).  An existing
        // pcscf.yaml that omits these picks them up via #[serde(default)].
        let defaults = crate::config::RegistrarLivenessConfig::default();
        assert_eq!(defaults.miss_threshold, 2);
        assert_eq!(defaults.probe_timeout_ms, 4000);
    }

    #[test]
    fn advertise_supported_methods_sets_allow_when_absent() {
        let mut headers = SipHeaders::new();
        advertise_supported_methods(&mut headers);
        let allow = headers.get("Allow").expect("Allow must be set");
        assert_eq!(allow, crate::sip::SUPPORTED_METHODS);
        // The whole point: peers read transfer capability from here.
        assert!(allow.contains("REFER") && allow.contains("NOTIFY"));
    }

    #[test]
    fn advertise_supported_methods_preserves_existing_allow() {
        let mut headers = SipHeaders::new();
        headers.set("Allow", "INVITE, ACK, BYE".to_string());
        advertise_supported_methods(&mut headers);
        assert_eq!(headers.get("Allow").unwrap(), "INVITE, ACK, BYE");
    }

    #[test]
    fn augment_options_response_adds_contact_and_allow() {
        let mut response = SipMessageBuilder::new()
            .response(200, "OK".to_string())
            .build()
            .unwrap();
        augment_options_response(&mut response, "sbc.example.org", 5061, Transport::Tls);
        assert_eq!(
            response.headers.get("Contact").unwrap(),
            "<sip:sbc.example.org:5061;transport=tls>"
        );
        assert_eq!(
            response.headers.get("Allow").unwrap(),
            crate::sip::SUPPORTED_METHODS
        );
    }

    #[test]
    fn augment_options_response_preserves_script_contact() {
        let mut response = SipMessageBuilder::new()
            .response(200, "OK".to_string())
            .contact("<sip:custom@host:5060>".to_string())
            .build()
            .unwrap();
        augment_options_response(&mut response, "sbc.example.org", 5061, Transport::Udp);
        // Script-set Contact must not be clobbered; Allow is still advertised.
        assert_eq!(
            response.headers.get("Contact").unwrap(),
            "<sip:custom@host:5060>"
        );
        assert_eq!(
            response.headers.get("Allow").unwrap(),
            crate::sip::SUPPORTED_METHODS
        );
    }

    #[test]
    fn b_leg_contact_default_is_userless() {
        // RFC 3261 §8.1.1.8 — no identity in the Contact userpart by default.
        let contact = build_b_leg_contact("proxy.example.com", 5060, Transport::Udp, None, None);
        assert_eq!(contact, "<sip:proxy.example.com:5060;transport=udp>");
    }

    #[test]
    fn b_leg_contact_user_override_keeps_host_port() {
        // set_contact_user() injects a userpart, siphon's host:port unchanged.
        let contact =
            build_b_leg_contact("proxy.example.com", 5060, Transport::Tcp, Some("1001"), None);
        assert_eq!(contact, "<sip:1001@proxy.example.com:5060;transport=tcp>");
    }

    #[test]
    fn b_leg_contact_empty_user_override_collapses_to_userless() {
        // set_contact_user("") explicitly forces the userless form.
        let contact =
            build_b_leg_contact("proxy.example.com", 5060, Transport::Udp, Some(""), None);
        assert_eq!(contact, "<sip:proxy.example.com:5060;transport=udp>");
    }

    #[test]
    fn b_leg_contact_full_uri_override_wins_over_user() {
        // set_contact_uri() takes precedence over set_contact_user().
        let contact = build_b_leg_contact(
            "proxy.example.com",
            5060,
            Transport::Udp,
            Some("1001"),
            Some("sip:gruu@edge.example.com:5080"),
        );
        assert_eq!(contact, "<sip:gruu@edge.example.com:5080>");
    }

    #[test]
    fn collect_route_set_splits_lines_and_top_level_commas() {
        let mut message = SipMessageBuilder::new()
            .request(Method::Register, SipUri::new("example.com".to_string()))
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-reg-x".to_string())
            .to("<sip:alice@example.com>".to_string())
            .from("<sip:alice@example.com>;tag=t".to_string())
            .call_id("c".to_string())
            .cseq("1 REGISTER".to_string())
            .content_length(0)
            .build()
            .expect("builds");

        // One plain header line and one comma-folded line → three route values,
        // with the comma inside <...> of a uri-param left untouched.
        message.headers.set_all(
            "Service-Route",
            vec![
                "<sip:scscf1.example.com;lr>".to_string(),
                "<sip:scscf2.example.com;lr>, <sip:scscf3.example.com;lr>".to_string(),
            ],
        );

        let routes = collect_route_set(&message, "Service-Route");
        assert_eq!(
            routes,
            vec![
                "<sip:scscf1.example.com;lr>".to_string(),
                "<sip:scscf2.example.com;lr>".to_string(),
                "<sip:scscf3.example.com;lr>".to_string(),
            ]
        );

        // Missing header → empty.
        assert!(collect_route_set(&message, "P-Associated-URI").is_empty());
    }

    #[test]
    fn build_dereg_register_has_expires_zero_routes_and_aor() {
        let destination = "192.0.2.5:6060".parse().unwrap();
        let routes = vec!["<sip:scscf.example.com:6060;lr>".to_string()];
        let message = build_dereg_register(
            "sip:alice@example.com",
            "sip:alice@10.0.0.1:5060",
            &routes,
            destination,
        )
        .expect("de-REGISTER builds");
        let wire = String::from_utf8(message.to_bytes()).unwrap();

        // R-URI is the registrar domain (AoR host), not the contact.
        assert!(
            wire.starts_with("REGISTER sip:example.com SIP/2.0\r\n"),
            "request line wrong:\n{wire}"
        );
        assert!(wire.contains("Expires: 0\r\n"), "missing Expires: 0:\n{wire}");
        assert!(
            wire.contains("Contact: <sip:alice@10.0.0.1:5060>;expires=0"),
            "missing deregistering Contact:\n{wire}"
        );
        assert!(
            wire.contains("Route: <sip:scscf.example.com:6060;lr>"),
            "missing Service-Route:\n{wire}"
        );
        assert!(wire.contains("To: <sip:alice@example.com>"), "missing To:\n{wire}");
        assert!(
            wire.contains("From: <sip:alice@example.com>;tag=liveness-"),
            "missing From with liveness tag:\n{wire}"
        );
        assert!(wire.contains("CSeq: 1 REGISTER"), "missing CSeq:\n{wire}");
        // Must carry the integrity-protected marker so the S-CSCF skips the
        // IMS-AKA re-challenge (TS 24.229 §5.4.1.2.2) and actually completes
        // the de-registration.
        assert!(
            wire.contains("integrity-protected=\"ip-assoc-yes\""),
            "missing integrity-protected marker in Authorization:\n{wire}"
        );
        assert!(
            wire.contains("Authorization: Digest username=\"alice@example.com\""),
            "Authorization username should be the IMPI-shaped public id:\n{wire}"
        );
    }

    #[test]
    fn transport_from_name_maps_known_transports_else_udp() {
        assert!(matches!(transport_from_name(Some("tcp")), Transport::Tcp));
        assert!(matches!(transport_from_name(Some("TLS")), Transport::Tls));
        assert!(matches!(transport_from_name(Some("ws")), Transport::WebSocket));
        assert!(matches!(
            transport_from_name(Some("WSS")),
            Transport::WebSocketSecure
        ));
        assert!(matches!(transport_from_name(Some("udp")), Transport::Udp));
        // Unknown / absent transport falls back to UDP.
        assert!(matches!(transport_from_name(None), Transport::Udp));
        assert!(matches!(transport_from_name(Some("sctp")), Transport::Udp));
    }

    #[test]
    fn parse_route_uri_strips_brackets_and_keeps_hostport() {
        let uri = parse_route_uri("<sip:scscf.example.com:6060;lr>").expect("parses");
        assert_eq!(uri.host, "scscf.example.com");
        assert_eq!(uri.port, Some(6060));

        let secure = parse_route_uri("  <sips:scscf2.example.com;lr>  ").expect("parses");
        assert_eq!(secure.scheme, "sips");
        assert_eq!(secure.host, "scscf2.example.com");
        assert_eq!(secure.port, None);
    }

    #[test]
    fn drain_state_default_counts_zero_when_managers_unset() {
        let drain = DrainState::new();
        assert_eq!(drain.active_counts(), (0, 0));
        assert!(!drain.is_draining.load(std::sync::atomic::Ordering::Relaxed));
    }

    #[test]
    fn drain_state_reports_counts_after_register() {
        let drain = DrainState::new();
        let tm = Arc::new(TransactionManager::new(crate::transaction::timer::TimerConfig::default()));
        let ca = Arc::new(CallActorStore::new());
        drain.transaction_manager.set(Arc::clone(&tm)).ok();
        drain.call_actors.set(Arc::clone(&ca)).ok();
        // Both empty initially.
        assert_eq!(drain.active_counts(), (0, 0));
    }

    fn sample_invite() -> SipMessage {
        SipMessageBuilder::new()
            .request(
                Method::Invite,
                SipUri::new("biloxi.com".to_string()).with_user("bob".to_string()),
            )
            .via("SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds".to_string())
            .to("Bob <sip:bob@biloxi.com>".to_string())
            .from("Alice <sip:alice@atlanta.com>;tag=1928301774".to_string())
            .call_id("a84b4c76e66710@pc33.atlanta.com".to_string())
            .cseq("314159 INVITE".to_string())
            .max_forwards(70)
            .content_length(0)
            .build()
            .unwrap()
    }

    #[test]
    fn first_route_uri_strips_angle_brackets() {
        let route_set = vec![
            "<sip:scscf.example.com:6060;lr;transport=udp>".to_string(),
            "<sip:pcscf.example.com:5060;lr;transport=tcp>".to_string(),
        ];
        let uri = first_route_uri(&route_set);
        assert_eq!(uri.as_deref(), Some("sip:scscf.example.com:6060;lr;transport=udp"));
    }

    #[test]
    fn uac_route_set_from_record_routes_flattens_and_reverses() {
        // Mix of one-URI-per-line and a comma-joined multi-URI line (RFC 3261
        // §7.3.1). The UAC route set is the responder's Record-Route in reverse
        // wire order (RFC 3261 §12.1.2), computed after flattening.
        let record_routes = vec![
            "<sip:p1.example.com;lr>, <sip:p2.example.com;lr>".to_string(),
            "<sip:p3.example.com;lr>".to_string(),
        ];
        let route_set = uac_route_set_from_record_routes(&record_routes);
        assert_eq!(
            route_set,
            vec![
                "<sip:p3.example.com;lr>".to_string(),
                "<sip:p2.example.com;lr>".to_string(),
                "<sip:p1.example.com;lr>".to_string(),
            ],
        );
    }

    #[test]
    fn uac_route_set_from_record_routes_empty() {
        assert!(uac_route_set_from_record_routes(&[]).is_empty());
    }

    #[test]
    fn early_dialog_route_set_first_hop_is_proxy_not_cached_next_hop() {
        // Regression for the B2BUA auto-PRACK 406: a reliable 183 arrives via the
        // S-CSCF, which Record-Routes. The early-dialog route set must be derived
        // from THIS response's Record-Route so the PRACK's Route header and
        // resolve_in_dialog_destination both target the S-CSCF — not the cached
        // INVITE next-hop (an IMS I-CSCF that doesn't Record-Route and rejects the
        // in-dialog PRACK with 406, killing the 100rel handshake).
        let record_routes = vec!["<sip:scscf.ims.example.com:6060;lr;transport=udp>".to_string()];
        let route_set = uac_route_set_from_record_routes(&record_routes);
        assert_eq!(
            first_route_uri(&route_set).as_deref(),
            Some("sip:scscf.ims.example.com:6060;lr;transport=udp"),
            "PRACK must follow the early-dialog route set to the S-CSCF",
        );
    }

    #[test]
    fn first_route_uri_empty_route_set() {
        assert!(first_route_uri(&[]).is_none());
    }

    #[test]
    fn first_route_uri_malformed_entry() {
        // Missing angle brackets — RouteEntry::parse returns Err, so we get None
        // and the caller falls back to the cached destination.
        let route_set = vec!["sip:bad.example.com".to_string()];
        assert!(first_route_uri(&route_set).is_none());
    }

    #[test]
    fn first_route_uri_picks_first_only() {
        // Each route_set entry is one URI (flatten_record_route_headers
        // guarantees that). first_route_uri must NOT split commas inside the
        // first entry — that's the previous layer's responsibility.
        let route_set = vec![
            "<sip:first.example.com;lr>".to_string(),
            "<sip:second.example.com;lr>".to_string(),
        ];
        let uri = first_route_uri(&route_set);
        assert_eq!(uri.as_deref(), Some("sip:first.example.com;lr"));
    }

    fn ack_request_with_route(route: Option<&str>) -> SipMessage {
        let ruri = parse_uri_standalone("sip:5111@100.65.0.2:7000").unwrap();
        let mut builder = SipMessageBuilder::new()
            .request(Method::Ack, ruri)
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-e2e-ack".to_string())
            .to("<sip:5111@ims.example.com>;tag=uas-tag".to_string())
            .from("<sip:trunk@example.com>;tag=uac-tag".to_string())
            .call_id("ack-e2e-route-set".to_string())
            .cseq("1 ACK".to_string())
            .content_length(0);
        if let Some(route) = route {
            builder = builder.header("Route", route.to_string());
        }
        builder.build().unwrap()
    }

    #[test]
    fn ack_next_hop_prefers_remaining_route_over_ruri() {
        // The end-to-end 2xx ACK must follow the dialog route set: when a Route
        // remains (after the proxy popped its own), that Route is the next hop —
        // NOT the Request-URI (the UE Contact) and NOT the cached INVITE branch.
        let ack = ack_request_with_route(Some(
            "<sip:172.16.0.101:5060;transport=udp;lr>, <sip:172.16.0.101:5060;transport=tcp;lr>",
        ));
        let next_hop = ack_next_hop_uri(&ack.headers, &ack.start_line).expect("ACK has a next hop");
        let parsed = parse_uri_standalone(&next_hop).unwrap();
        assert_eq!(parsed.host, "172.16.0.101");
        assert_eq!(parsed.port, Some(5060));
        assert_ne!(
            parsed.host, "100.65.0.2",
            "must not short-circuit the ACK to the Request-URI when a Route remains",
        );
    }

    #[test]
    fn ack_next_hop_falls_back_to_ruri_when_route_set_empty() {
        // No Route header → the next hop is the Request-URI (the remote target),
        // resolved per RFC 3261 §16.12 — still derived from the message, never
        // the cached INVITE branch destination.
        let ack = ack_request_with_route(None);
        let next_hop = ack_next_hop_uri(&ack.headers, &ack.start_line);
        let ruri = parse_uri_standalone("sip:5111@100.65.0.2:7000").unwrap();
        assert_eq!(next_hop, Some(ruri.to_string()));
    }

    #[test]
    fn ack_2xx_follows_route_set_after_popping_self() {
        // Field regression (siphon as S-CSCF): the 2xx ACK arrives with a route
        // set of [S-CSCF (self), P-CSCF]. After loose-routing pops our own top
        // Route, the next hop is the P-CSCF — not the cached INVITE branch (which
        // pointed at a non-Record-Routing MMTel-AS) and not the UE Contact in the
        // Request-URI. The cached-branch path mis-delivered the ACK so the UAS
        // never confirmed the dialog.
        let mut ack = ack_request_with_route(Some(
            "<sip:172.16.0.121:6060;lr>, <sip:172.16.0.101:5060;transport=udp;lr>",
        ));

        // Mirror handle_ack_via_session: pop our own (top) Route entry.
        assert!(core::check_loose_route(&ack.headers));
        core::pop_top_route(&mut ack.headers);

        let next_hop = ack_next_hop_uri(&ack.headers, &ack.start_line).expect("next hop");
        let parsed = parse_uri_standalone(&next_hop).unwrap();
        assert_eq!(
            parsed.host, "172.16.0.101",
            "ACK must follow the dialog route set to the P-CSCF",
        );
        assert_eq!(parsed.port, Some(5060));
        assert_ne!(
            parsed.host, "100.65.0.2",
            "ACK must not short-circuit to the UE Contact in the Request-URI",
        );
    }

    #[test]
    fn ack_2xx_consumes_double_self_record_route_then_follows_route_set() {
        // Transport-bridging double Record-Route: siphon appears twice at the
        // top of the dialog route set, followed by the real next hop (P-CSCF).
        // Consuming only the top self-Route would leave our own second Route as
        // the apparent next hop — a routing loop. The ACK must consume both
        // self-Routes (via pop_local_routes) and forward to the P-CSCF, exactly
        // as loose_route() does for the in-dialog BYE on this dialog.
        let local_domains = vec!["172.16.0.121".to_string()];
        let mut ack = ack_request_with_route(Some(
            "<sip:172.16.0.121:6060;transport=tcp;lr>, \
             <sip:172.16.0.121:6060;transport=udp;lr>, \
             <sip:172.16.0.101:5060;transport=udp;lr>",
        ));

        // Mirror handle_ack_via_session's route consumption.
        assert!(core::check_loose_route(&ack.headers));
        core::pop_top_route(&mut ack.headers);
        core::pop_local_routes(&mut ack.headers, &local_domains);

        let next_hop = ack_next_hop_uri(&ack.headers, &ack.start_line).expect("next hop");
        let parsed = parse_uri_standalone(&next_hop).unwrap();
        assert_eq!(
            parsed.host, "172.16.0.101",
            "ACK must skip our own double Record-Route and follow the route set",
        );
        assert_eq!(parsed.port, Some(5060));
    }

    #[test]
    fn flatten_record_route_headers_single_line_multi_uri() {
        // RFC 3261 §7.3.1 allows multiple comma-separated URIs on a single header line.
        // B2BUA must split them so the route-set has one URI per entry — a precondition
        // for reversal to produce the RFC §12.1.1 UAC route order.
        let headers = vec![
            "<sip:p1.example.com:5060;lr;transport=tcp>, \
             <sip:p2.example.com:5060;lr;transport=udp>, \
             <sip:p3.example.com:6060;lr;transport=udp>".to_string(),
        ];
        let routes = flatten_record_route_headers(&headers);
        assert_eq!(routes.len(), 3);
        assert_eq!(routes[0], "<sip:p1.example.com:5060;lr;transport=tcp>");
        assert_eq!(routes[1], "<sip:p2.example.com:5060;lr;transport=udp>");
        assert_eq!(routes[2], "<sip:p3.example.com:6060;lr;transport=udp>");
    }

    #[test]
    fn flatten_record_route_headers_multi_line_one_uri_each() {
        let headers = vec![
            "<sip:p1.example.com;lr>".to_string(),
            "<sip:p2.example.com;lr>".to_string(),
            "<sip:p3.example.com;lr>".to_string(),
        ];
        let routes = flatten_record_route_headers(&headers);
        assert_eq!(routes, vec![
            "<sip:p1.example.com;lr>".to_string(),
            "<sip:p2.example.com;lr>".to_string(),
            "<sip:p3.example.com;lr>".to_string(),
        ]);
    }

    #[test]
    fn flatten_record_route_headers_mixed_lines() {
        let headers = vec![
            "<sip:a;lr>, <sip:b;lr>".to_string(),
            "<sip:c;lr>".to_string(),
            "<sip:d;lr>, <sip:e;lr>".to_string(),
        ];
        let routes = flatten_record_route_headers(&headers);
        assert_eq!(routes, vec![
            "<sip:a;lr>".to_string(),
            "<sip:b;lr>".to_string(),
            "<sip:c;lr>".to_string(),
            "<sip:d;lr>".to_string(),
            "<sip:e;lr>".to_string(),
        ]);
    }

    #[test]
    fn flatten_record_route_headers_then_reverse_matches_rfc_12_1_1() {
        // The bug: B2BUA was calling .iter().rev() on the Vec<String> before flattening.
        // For a typical IMS 200 OK where all RR URIs come back on a single header line,
        // the outer reverse was a no-op and the UAC route-set ended up in wire order
        // instead of reversed — sending in-dialog BYE through P-CSCF instead of I-CSCF.
        let single_line = vec![
            "<sip:pcscf;lr;transport=tcp>, <sip:pcscf;lr;transport=udp>, \
             <sip:scscf;lr;transport=udp>".to_string(),
        ];
        let mut routes = flatten_record_route_headers(&single_line);
        routes.reverse();
        assert_eq!(routes[0], "<sip:scscf;lr;transport=udp>");
        assert_eq!(routes[2], "<sip:pcscf;lr;transport=tcp>");
    }

    #[test]
    fn flatten_record_route_headers_ignores_empty_entries() {
        let headers = vec![
            "".to_string(),
            "<sip:a;lr>,".to_string(),
            ",  ,".to_string(),
        ];
        let routes = flatten_record_route_headers(&headers);
        assert_eq!(routes, vec!["<sip:a;lr>".to_string()]);
    }

    #[test]
    fn build_response_copies_mandatory_headers() {
        let request = sample_invite();
        let response = build_response(&request, 200, "OK", None, &[]);

        assert!(response.is_response());
        assert_eq!(response.status_code(), Some(200));

        // Via must be copied
        let vias = response.headers.get_all("Via").unwrap();
        assert_eq!(vias.len(), 1);
        assert!(vias[0].contains("pc33.atlanta.com"));

        // From/To/Call-ID/CSeq must be copied
        assert!(response.headers.from().unwrap().contains("alice@atlanta.com"));
        assert!(response.headers.to().unwrap().contains("bob@biloxi.com"));
        assert_eq!(
            response.headers.call_id().unwrap(),
            "a84b4c76e66710@pc33.atlanta.com"
        );
        assert!(response.headers.cseq().unwrap().contains("INVITE"));
    }

    #[test]
    fn build_response_sets_content_length_zero() {
        let request = sample_invite();
        let response = build_response(&request, 404, "Not Found", None, &[]);
        assert_eq!(response.headers.get("Content-Length").unwrap(), "0");
    }

    #[test]
    fn build_response_copies_multiple_vias() {
        let mut request = sample_invite();
        request.headers.add(
            "Via",
            "SIP/2.0/UDP proxy1.example.com;branch=z9hG4bK-proxy".to_string(),
        );

        let response = build_response(&request, 200, "OK", None, &[]);
        let vias = response.headers.get_all("Via").unwrap();
        assert_eq!(vias.len(), 2);
    }

    #[test]
    fn build_response_serializes_to_valid_sip() {
        let request = sample_invite();
        let response = build_response(&request, 200, "OK", None, &[]);
        let bytes = response.to_bytes();
        let text = String::from_utf8(bytes).unwrap();

        assert!(text.starts_with("SIP/2.0 200 OK\r\n"));
        assert!(text.contains("Via:"));
        assert!(text.contains("From:"));
        assert!(text.contains("To:"));
        assert!(text.contains("Call-ID:"));
        assert!(text.contains("CSeq:"));
        assert!(text.ends_with("\r\n\r\n"));
    }

    #[test]
    fn build_response_includes_server_header_when_configured() {
        let request = sample_invite();
        let response = build_response(&request, 401, "Unauthorized", Some("SIPhon/0.1.0"), &[]);
        assert_eq!(response.headers.get("Server").unwrap(), "SIPhon/0.1.0");
    }

    #[test]
    fn build_response_omits_server_header_when_none() {
        let request = sample_invite();
        let response = build_response(&request, 200, "OK", None, &[]);
        assert!(response.headers.get("Server").is_none());
    }

    #[test]
    fn build_response_copies_expires_header() {
        let mut request = sample_invite();
        request.headers.set("Expires", "600".to_string());
        let response = build_response(&request, 200, "OK", None, &[]);
        assert_eq!(
            response.headers.get("Expires").unwrap(),
            "600",
            "Expires header should be copied from request to response"
        );
    }

    #[test]
    fn build_response_omits_expires_when_absent() {
        let request = sample_invite();
        let response = build_response(&request, 200, "OK", None, &[]);
        assert!(
            response.headers.get("Expires").is_none(),
            "Expires should not appear in response when not set on request"
        );
    }

    // --- Reply-header replace/add semantics --------------------------------
    //
    // Regression coverage for the `set_reply_header` append bug:
    // build_response must apply Replace ops via `set_header` so that
    // a script-supplied To-tag (RFC 3261 §12.1.1.2 / RFC 6665 §4.1.3)
    // ends up as exactly one To header in the wire response.

    #[test]
    fn build_response_replace_op_overwrites_copied_to_header() {
        use crate::script::api::request::ReplyHeaderOp;
        let request = sample_invite();
        let to_with_tag = format!(
            "{};tag=scscf-abc123",
            request.headers.to().unwrap()
        );
        let reply_headers = vec![(
            ReplyHeaderOp::Replace,
            "To".to_string(),
            to_with_tag.clone(),
        )];
        let response = build_response(&request, 200, "OK", None, &reply_headers);

        // Exactly one To header — not two.
        let tos = response.headers.get_all("To").unwrap();
        assert_eq!(
            tos.len(),
            1,
            "set_reply_header(\"To\", …) must replace, not append; got {:?}",
            tos,
        );
        assert!(tos[0].contains(";tag=scscf-abc123"));

        // Wire-format check — only one "To:" line in the serialized response.
        let bytes = response.to_bytes();
        let text = String::from_utf8(bytes).unwrap();
        let to_line_count = text.lines().filter(|line| line.starts_with("To:")).count();
        assert_eq!(to_line_count, 1, "wire output must carry exactly one To header");
    }

    #[test]
    fn build_response_add_op_appends_multi_value_headers() {
        use crate::script::api::request::ReplyHeaderOp;
        let request = sample_invite();
        let reply_headers = vec![
            (ReplyHeaderOp::Add, "Service-Route".to_string(), "<sip:orig@scscf:6060;lr>".to_string()),
            (ReplyHeaderOp::Add, "Service-Route".to_string(), "<sip:term@scscf:6060;lr>".to_string()),
            (ReplyHeaderOp::Add, "P-Associated-URI".to_string(), "<sip:alice@ims.example.com>".to_string()),
        ];
        let response = build_response(&request, 200, "OK", None, &reply_headers);

        let routes = response.headers.get_all("Service-Route").unwrap();
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0], "<sip:orig@scscf:6060;lr>");
        assert_eq!(routes[1], "<sip:term@scscf:6060;lr>");

        let assoc = response.headers.get_all("P-Associated-URI").unwrap();
        assert_eq!(assoc.len(), 1);
    }

    #[test]
    fn build_response_replace_overrides_copied_expires() {
        use crate::script::api::request::ReplyHeaderOp;
        let mut request = sample_invite();
        request.headers.set("Expires", "3600".to_string()); // copied by build_response
        let reply_headers = vec![(
            ReplyHeaderOp::Replace,
            "Expires".to_string(),
            "60".to_string(),
        )];
        let response = build_response(&request, 200, "OK", None, &reply_headers);

        let expires = response.headers.get_all("Expires").unwrap();
        assert_eq!(expires.len(), 1, "Expires must not duplicate when replaced");
        assert_eq!(expires[0], "60");
    }

    #[test]
    fn build_response_replace_then_add_for_same_header_keeps_replace_then_appends() {
        use crate::script::api::request::ReplyHeaderOp;
        let request = sample_invite();
        // Pathological but well-defined: replace clears prior values,
        // subsequent add accumulates on top.
        let reply_headers = vec![
            (ReplyHeaderOp::Replace, "Warning".to_string(), "399 siphon \"first\"".to_string()),
            (ReplyHeaderOp::Add, "Warning".to_string(), "399 siphon \"second\"".to_string()),
        ];
        let response = build_response(&request, 200, "OK", None, &reply_headers);
        let warns = response.headers.get_all("Warning").unwrap();
        assert_eq!(warns.len(), 2);
        assert!(warns[0].contains("first"));
        assert!(warns[1].contains("second"));
    }

    #[test]
    fn build_ack_for_non2xx_has_correct_headers() {
        let request = sample_invite();
        let response = build_response(&request, 480, "Temporarily Unavailable", None, &[]);
        let local_addr: SocketAddr = "10.0.0.1:5060".parse().unwrap();

        let ack = build_ack_for_non2xx(
            &request,
            &response,
            "z9hG4bK-proxy-branch",
            Transport::Tcp,
            local_addr,
        );

        // Must be an ACK request
        assert!(ack.is_request());
        let bytes = String::from_utf8(ack.to_bytes()).unwrap();
        assert!(bytes.starts_with("ACK sip:bob@biloxi.com SIP/2.0\r\n"));

        // Via: our own hop only (not the UAC's)
        let via = ack.headers.via().unwrap();
        assert!(via.contains("z9hG4bK-proxy-branch"));
        assert!(via.contains("TCP"));
        assert!(via.contains("10.0.0.1:5060"));

        // From: same as original request
        assert_eq!(ack.headers.from().unwrap(), request.headers.from().unwrap());

        // To: from the response (may have To-tag)
        assert_eq!(ack.headers.to().unwrap(), response.headers.to().unwrap());

        // Call-ID: same as original
        assert_eq!(ack.headers.call_id().unwrap(), request.headers.call_id().unwrap());

        // CSeq: same number, ACK method
        let cseq = ack.headers.cseq().unwrap();
        assert!(cseq.contains("314159"));
        assert!(cseq.contains("ACK"));
        assert!(!cseq.contains("INVITE"));

        // Max-Forwards present
        assert_eq!(ack.headers.get("Max-Forwards").unwrap(), "70");

        // Content-Length: 0
        assert_eq!(ack.headers.content_length(), Some(0));
    }

    /// Build a representative B-leg INVITE — i.e. one that has already been
    /// through the hygiene chain in `b2bua_send_b_leg_invite`: stripped
    /// Record-Route/Route/Authorization, our own Via and Contact, rewritten
    /// From host, fresh Call-ID, CSeq=1, decremented Max-Forwards, and an
    /// SDP body with the o= line rewritten to our advertised address.
    fn hygiene_processed_b_leg_invite() -> SipMessage {
        let sdp = "v=0\r\n\
o=siphon 0 0 IN IP4 192.0.2.10\r\n\
s=siphon\r\n\
c=IN IP4 192.0.2.10\r\n\
t=0 0\r\n\
m=audio 30054 RTP/SAVPF 8\r\n\
a=rtpmap:8 PCMA/8000\r\n";
        let mut msg = SipMessageBuilder::new()
            .request(
                Method::Invite,
                SipUri::new("biloxi.com".to_string()).with_user("bob".to_string()),
            )
            .via("SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-old".to_string())
            .to("Bob <sip:bob@biloxi.com>".to_string())
            .from("Alice <sip:alice@siphon.example.org>;tag=b-leg-tag-99".to_string())
            .call_id("b2b-bbbbbbbb-cccc-dddd-eeee-ffffffffffff".to_string())
            .cseq("1 INVITE".to_string())
            .max_forwards(69)
            .content_length(sdp.len())
            .build()
            .unwrap();
        msg.headers.set("Contact", "<sip:192.0.2.10:5060;transport=udp>".to_string());
        msg.headers.set("User-Agent", "SIPhon/test".to_string());
        msg.headers.set(
            "P-Asserted-Identity",
            "<sip:alice@siphon.example.org>".to_string(),
        );
        msg.body = sdp.as_bytes().to_vec();
        msg
    }

    #[test]
    fn build_digest_retry_invite_replaces_via() {
        let original = hygiene_processed_b_leg_invite();
        let retry = build_digest_retry_invite(
            &original,
            "SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-new".to_string(),
            2,
            "Proxy-Authorization",
            "Digest username=\"alice\", realm=\"realm\"".to_string(),
        );
        assert_eq!(
            retry.headers.via().unwrap(),
            "SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-new"
        );
    }

    #[test]
    fn build_digest_retry_invite_bumps_cseq() {
        let original = hygiene_processed_b_leg_invite();
        let retry = build_digest_retry_invite(
            &original,
            "SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-new".to_string(),
            2,
            "Proxy-Authorization",
            "Digest x".to_string(),
        );
        assert_eq!(retry.headers.cseq().unwrap(), "2 INVITE");
    }

    #[test]
    fn build_digest_retry_invite_sets_proxy_auth_header() {
        let original = hygiene_processed_b_leg_invite();
        let retry = build_digest_retry_invite(
            &original,
            "SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-new".to_string(),
            2,
            "Proxy-Authorization",
            "Digest username=\"alice\"".to_string(),
        );
        assert!(retry.headers.get("Proxy-Authorization").is_some());
        assert!(retry.headers.get("Authorization").is_none());
    }

    #[test]
    fn build_digest_retry_invite_replaces_existing_auth() {
        // A previous 401 added Authorization with stale credentials — the
        // helper must drop both Authorization and Proxy-Authorization before
        // adding the fresh challenge response.
        let mut original = hygiene_processed_b_leg_invite();
        original.headers.add("Authorization", "Digest stale".to_string());
        original
            .headers
            .add("Proxy-Authorization", "Digest also-stale".to_string());

        let retry = build_digest_retry_invite(
            &original,
            "SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-new".to_string(),
            3,
            "Authorization",
            "Digest fresh".to_string(),
        );

        let auths = retry.headers.get_all("Authorization").expect("Authorization present");
        assert_eq!(auths.len(), 1);
        assert_eq!(auths[0], "Digest fresh");
        assert!(retry.headers.get("Proxy-Authorization").is_none());
    }

    /// This is the regression test for the leak fix: every header we expect
    /// the prior B-leg INVITE to carry (post-hygiene) MUST be preserved.
    #[test]
    fn build_digest_retry_invite_preserves_all_other_headers() {
        let original = hygiene_processed_b_leg_invite();
        let retry = build_digest_retry_invite(
            &original,
            "SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-new".to_string(),
            2,
            "Proxy-Authorization",
            "Digest x".to_string(),
        );

        // Identity / dialog headers
        assert_eq!(retry.headers.from(), original.headers.from());
        assert_eq!(retry.headers.to(), original.headers.to());
        assert_eq!(retry.headers.call_id(), original.headers.call_id());

        // Topology + UA hygiene must survive
        assert_eq!(
            retry.headers.get("Contact"),
            original.headers.get("Contact"),
        );
        assert_eq!(
            retry.headers.get("User-Agent"),
            original.headers.get("User-Agent"),
        );
        assert_eq!(
            retry.headers.get("P-Asserted-Identity"),
            original.headers.get("P-Asserted-Identity"),
        );

        // Max-Forwards must NOT silently increment back up.
        assert_eq!(retry.headers.get("Max-Forwards").map(|s| s.as_str()), Some("69"));

        // Record-Route and Route must remain absent (they were stripped by
        // hygiene; the retry must not bring them back).
        assert!(retry.headers.get("Record-Route").is_none());
        assert!(retry.headers.get("Route").is_none());

        // RURI is the dial target — unchanged.
        match (&retry.start_line, &original.start_line) {
            (StartLine::Request(rl_retry), StartLine::Request(rl_orig)) => {
                assert_eq!(rl_retry.request_uri.user, rl_orig.request_uri.user);
                assert_eq!(rl_retry.request_uri.host, rl_orig.request_uri.host);
            }
            _ => panic!("expected Request start lines"),
        }

        // SDP body untouched (rtpengine had already anchored ports/crypto).
        assert_eq!(retry.body, original.body);
    }

    /// The B2BUA must ACK a 401/407 on the outbound leg before (and while)
    /// retrying with credentials — RFC 3261 §17.1.1.3. Prior to the fix the
    /// 401-retry path returned without ever building this ACK, so the trunk
    /// kept retransmitting the challenge. The ACK must reuse the original
    /// INVITE's Via branch (hop-by-hop) and carry the UAS To-tag from the 401.
    ///
    /// Critically, the ACK's Via sent-by host:port must be the *advertised*
    /// address the INVITE went out with — not the internal bind address — or
    /// the trunk's server transaction can't match the ACK (RFC 3261 §17.2.3)
    /// and keeps retransmitting its 401 on Timer G.  The caller passes
    /// `state.via_host`/`via_port` (advertised); behind NAT/edge that differs
    /// from the bind address.
    #[test]
    fn build_b2bua_ack_for_401_uses_invite_branch_and_response_to_tag() {
        let response = SipMessageBuilder::new()
            .response(401, "Unauthorized".to_string())
            .via("SIP/2.0/UDP 203.0.113.7:5060;branch=z9hG4bK-orig".to_string())
            .from("<sip:alice@siphon.example.org>;tag=b-leg-from".to_string())
            .to("<sip:bob@trunk.example.net>;tag=uas-12345".to_string())
            .call_id("b2b-aaaa-bbbb".to_string())
            .cseq("1 INVITE".to_string())
            .content_length(0)
            .build()
            .unwrap();

        // Advertised (public) address the B-leg INVITE used in its Via.  An
        // internal bind address (e.g. 10.x) would be a *different* value — the
        // regression was that the ACK leaked the internal one.
        let advertised_host = "203.0.113.7";
        let advertised_port = 5060;
        let ack = build_b2bua_ack_for_non2xx(
            &response,
            "z9hG4bK-orig",
            Some("sip:bob@trunk.example.net"),
            Transport::Udp,
            advertised_host,
            advertised_port,
        );

        // Method line is ACK to the dial target.
        match &ack.start_line {
            StartLine::Request(rl) => {
                assert_eq!(rl.method, Method::Ack);
                assert_eq!(rl.request_uri.host, "trunk.example.net");
            }
            _ => panic!("expected an ACK request line"),
        }

        // Same Via branch as the INVITE it acknowledges, and the advertised
        // sent-by host:port (RFC 3261 §17.1.1.3 / §17.2.3).
        assert_eq!(
            ack.headers.via().unwrap(),
            "SIP/2.0/UDP 203.0.113.7:5060;branch=z9hG4bK-orig"
        );
        // To header carries the UAS tag from the 401 — without it the trunk's
        // server transaction would not match the ACK.
        assert!(ack.headers.to().unwrap().contains("tag=uas-12345"));
        // CSeq number echoes the INVITE; method becomes ACK.
        assert_eq!(ack.headers.cseq().unwrap(), "1 ACK");
        assert_eq!(ack.headers.call_id().unwrap(), "b2b-aaaa-bbbb");
    }

    /// Regression: an outbound INVITE to an authenticating trunk draws a 401,
    /// is ACKed, and re-sent with credentials on a new branch + CSeq. The retry
    /// supersedes the failed B-leg in place (`replace_b_leg`), dropping the old
    /// leg's actor handle — so that actor exits and emits `CallEvent::Terminated`
    /// onto the SHARED per-call event channel. The dispatcher block-recvs that
    /// channel to classify each response; consuming the stale `Terminated` as a
    /// classification desynced the stream so the live retry leg's 200 OK was
    /// read as the previous 18x's `Provisional` event. That skipped
    /// `set_winner` + the deferred B-leg ACK, leaving the trunk's 200 OK unacked
    /// until the dialog collapsed (BYE storm ~5 s after answer).
    ///
    /// `recv_b_leg_classification_event` must skip the stale `Terminated` and
    /// return the live leg's `Answered` for the 200 OK.
    #[tokio::test(flavor = "multi_thread")]
    async fn b_leg_200_classifies_as_answered_after_auth_retry_supersede() {
        use crate::b2bua::actor::{Leg, LegActor, LegMessage, TransportInfo as LegTransport};
        use crate::transport::{ConnectionId, Transport};

        // The shared per-call channel, mirroring CallActor.event_tx and the
        // dispatcher's call_event_receivers entry.
        let (event_tx, mut event_rx) = tokio::sync::mpsc::channel::<CallEvent>(64);

        let transport = LegTransport {
            remote_addr: "10.0.0.2:5060".parse().unwrap(),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: None,
        };

        // CSeq-1 B-leg: drew the 401 and is now superseded. Dropping its handle
        // closes the actor's mailbox, so the actor exits and pushes a
        // CallEvent::Terminated onto the shared channel — the stale event that
        // used to desync the classifier.
        let cseq1 = Leg::new_b_leg(
            "b2b-supersede-desync@test".to_string(),
            "from-tag-1".to_string(),
            "sip:bob@10.0.0.2:5060".to_string(),
            "z9hG4bK-cseq1-desync".to_string(),
            transport.clone(),
        );
        let (actor1, handle1) = LegActor::new(cseq1, event_tx.clone());
        let actor1_task = tokio::spawn(actor1.run());
        drop(handle1);
        // Await the old actor so its Terminated is on the channel ahead of the
        // live leg's Answered — the ordering that triggered the bug.
        actor1_task.await.unwrap();

        // CSeq-2 B-leg (the live retry). Its 200 OK must classify as Answered.
        let cseq2 = Leg::new_b_leg(
            "b2b-supersede-desync@test".to_string(),
            "from-tag-2".to_string(),
            "sip:bob@10.0.0.2:5060".to_string(),
            "z9hG4bK-cseq2-desync".to_string(),
            transport.clone(),
        );
        let (actor2, handle2) = LegActor::new(cseq2, event_tx.clone());
        let actor2_task = tokio::spawn(actor2.run());

        let ok_200 = parse_sip_message(concat!(
            "SIP/2.0 200 OK\r\n",
            "Via: SIP/2.0/UDP 10.0.0.9:5060;branch=z9hG4bK-cseq2-desync\r\n",
            "From: <sip:alice@10.0.0.1>;tag=from-tag-2\r\n",
            "To: <sip:bob@10.0.0.2>;tag=uas-2\r\n",
            "Call-ID: b2b-supersede-desync@test\r\n",
            "CSeq: 2 INVITE\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ))
        .expect("200 OK fixture parses")
        .1;
        handle2
            .tx
            .send(LegMessage::SipInbound {
                message: ok_200,
                source: transport,
            })
            .await
            .unwrap();

        // The channel now holds [Terminated (stale), Answered]. The classifier
        // must skip Terminated and return Answered; the pre-fix code returned
        // Terminated, which the dispatcher misreads as a non-answer.
        let event = tokio::task::spawn_blocking(move || {
            recv_b_leg_classification_event(&mut event_rx)
        })
        .await
        .unwrap();

        assert!(
            matches!(event, Some(CallEvent::Answered { .. })),
            "200 OK on the live retry leg must classify as Answered, not the \
             stale Terminated from the superseded leg; got {event:?}"
        );

        handle2.tx.send(LegMessage::Shutdown).await.ok();
        let _ = actor2_task.await;
    }

    fn test_resolver() -> SipResolver {
        SipResolver::from_system().unwrap()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn resolve_target_ip_with_port() {
        let resolver = test_resolver();
        let result = resolve_target("sip:alice@192.168.1.100:5080", &resolver).unwrap();
        assert_eq!(result.address, "192.168.1.100:5080".parse::<SocketAddr>().unwrap());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn resolve_target_ip_default_port() {
        let resolver = test_resolver();
        let result = resolve_target("sip:alice@10.0.0.1", &resolver).unwrap();
        assert_eq!(result.address, "10.0.0.1:5060".parse::<SocketAddr>().unwrap());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn resolve_target_localhost() {
        let resolver = test_resolver();
        let result = resolve_target("sip:bob@localhost:5090", &resolver).unwrap();
        assert_eq!(result.address.port(), 5090);
        assert!(result.address.ip().is_loopback());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn resolve_target_bare_socketaddr() {
        let resolver = test_resolver();
        let result = resolve_target("10.0.0.1:5060", &resolver).unwrap();
        assert_eq!(result.address, "10.0.0.1:5060".parse::<SocketAddr>().unwrap());
        assert!(result.transport.is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn resolve_candidates_carries_hostname_for_sni() {
        let resolver = test_resolver();
        // A SIP URI with a hostname → every candidate carries the host so a new
        // outbound TLS connection presents it as SNI / certificate hostname.
        let hosted = resolve_target("sip:alice@localhost:5090", &resolver)
            .expect("localhost must resolve");
        assert_eq!(hosted.server_name.as_deref(), Some("localhost"));

        // A bare IP:port short-circuits → no SNI (RFC 6066 emits none for an IP).
        let bare = resolve_target("192.0.2.1:5060", &resolver).expect("bare ip target");
        assert!(bare.server_name.is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn resolve_target_transport_tcp() {
        let resolver = test_resolver();
        let result = resolve_target("sip:alice@10.0.0.1:5060;transport=tcp", &resolver).unwrap();
        assert_eq!(result.address, "10.0.0.1:5060".parse::<SocketAddr>().unwrap());
        assert_eq!(result.transport, Some(Transport::Tcp));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn resolve_target_unresolvable_domain() {
        let resolver = test_resolver();
        assert!(resolve_target("sip:alice@this-domain-should-not-exist-xyzzy.invalid", &resolver).is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn resolve_candidates_inner_uses_gateway_cache_without_dns() {
        use crate::gateway::{Algorithm, Destination, DispatcherGroup, DispatcherManager};
        let resolver = test_resolver();
        // `.invalid` never resolves in DNS (RFC 6761), so a fallthrough to
        // resolver.resolve returns an empty set — a non-empty result here proves
        // the gateway cache served the address with zero DNS.
        let destination = Destination::new(
            "sip:gw.test.invalid:5061;transport=tls".to_string(),
            "127.0.0.9:5061".parse().unwrap(),
            Transport::Tls,
            1,
            1,
        )
        .with_address_str("gw.test.invalid:5061".to_string());
        let group =
            DispatcherGroup::new("teams".to_string(), Algorithm::Weighted, vec![destination]);
        // Simulate the health prober having resolved the FQDN.
        let resolved: SocketAddr = "203.0.113.77:5061".parse().unwrap();
        group.all_destinations()[0].set_address(resolved);
        let manager = DispatcherManager::new();
        manager.add_group(group);

        let candidates = resolve_candidates_inner(
            "sip:gw.test.invalid:5061;transport=tls",
            &resolver,
            Some(&manager),
        );
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].address, resolved);
        // Hostname preserved for TLS SNI to the FQDN peer.
        assert_eq!(candidates[0].server_name.as_deref(), Some("gw.test.invalid"));
        assert_eq!(candidates[0].transport, Some(Transport::Tls));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn resolve_candidates_inner_falls_through_when_host_not_a_gateway() {
        use crate::gateway::{Algorithm, Destination, DispatcherGroup, DispatcherManager};
        let resolver = test_resolver();
        let destination = Destination::new(
            "sip:gw.test.invalid:5061;transport=tls".to_string(),
            "127.0.0.9:5061".parse().unwrap(),
            Transport::Tls,
            1,
            1,
        )
        .with_address_str("gw.test.invalid:5061".to_string());
        let group =
            DispatcherGroup::new("teams".to_string(), Algorithm::Weighted, vec![destination]);
        let manager = DispatcherManager::new();
        manager.add_group(group);

        // A different unresolvable host is not a gateway member → no cache hit →
        // DNS fallthrough → empty (does NOT borrow the gateway's cached address).
        let candidates = resolve_candidates_inner(
            "sip:other.host.invalid:5061;transport=tls",
            &resolver,
            Some(&manager),
        );
        assert!(candidates.is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn resolve_candidates_inner_bare_ip_short_circuits_before_gateway() {
        let resolver = test_resolver();
        let candidates = resolve_candidates_inner("203.0.113.5:5060", &resolver, None);
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].address,
            "203.0.113.5:5060".parse::<SocketAddr>().unwrap()
        );
        assert!(candidates[0].server_name.is_none());
    }

    // --- In-dialog connection reuse (RFC 5923) ---

    fn candidate(addr: &str) -> RelayTarget {
        RelayTarget { address: addr.parse().unwrap(), transport: None, server_name: None }
    }

    #[test]
    fn established_peer_in_candidates_ip_match() {
        // Load-balanced trunk: the established peer's IP is one of the members
        // the route-set domain resolves to → reuse the established connection.
        let candidates = [candidate("198.51.100.26:5061"), candidate("198.51.100.34:5061")];
        let cached = "198.51.100.26:5061".parse::<SocketAddr>().unwrap();
        assert!(established_peer_in_candidates(cached.ip(), &candidates));
    }

    #[test]
    fn established_peer_in_candidates_ip_match_ignores_port() {
        // The cached address carries the peer's source / ephemeral port while a
        // candidate carries the SIP listening port — the match must be IP-only.
        let candidates = [candidate("198.51.100.26:5061")];
        let cached = "198.51.100.26:41897".parse::<SocketAddr>().unwrap();
        assert!(established_peer_in_candidates(cached.ip(), &candidates));
    }

    #[test]
    fn established_peer_not_in_candidates() {
        // IMS divergence: the route set points at the S-CSCF while the
        // established peer is the I-CSCF the INVITE traversed → resolve fresh.
        let candidates = [candidate("203.0.113.20:5060")]; // S-CSCF
        let icscf = "203.0.113.10:5060".parse::<SocketAddr>().unwrap();
        assert!(!established_peer_in_candidates(icscf.ip(), &candidates));
    }

    #[test]
    fn established_peer_in_empty_candidates() {
        // Resolution failure: nothing to compare against, so the established
        // peer is the best available target → reuse.
        let cached = "203.0.113.7:5060".parse::<SocketAddr>().unwrap();
        assert!(established_peer_in_candidates(cached.ip(), &[]));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn in_dialog_flow_none_next_hop_reuses_cached() {
        // Empty route set → the cached peer is the remote target; reuse it
        // verbatim, including the connection_id.
        let resolver = test_resolver();
        let cached = "10.1.2.3:6000".parse::<SocketAddr>().unwrap();
        let connection_id = ConnectionId(42);
        let (destination, transport, out_connection_id) =
            resolve_in_dialog_flow_uri(None, &resolver, cached, Transport::Tls, connection_id);
        assert_eq!(destination, cached);
        assert_eq!(transport, Transport::Tls);
        assert_eq!(out_connection_id, connection_id);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn in_dialog_flow_reuses_established_member_over_resolved_port() {
        // Next hop is a literal IP equal to the established peer but on its SIP
        // listening port, while the cached address is the same peer on its
        // source port. RFC 5923: keep the established connection (cached address
        // + connection_id), not the re-resolved listening-port address. This is
        // the load-balanced-trunk fix in miniature.
        let resolver = test_resolver();
        let cached = "192.0.2.50:33333".parse::<SocketAddr>().unwrap();
        let connection_id = ConnectionId(7);
        let (destination, transport, out_connection_id) = resolve_in_dialog_flow_uri(
            Some("sip:192.0.2.50:5061;transport=tls"),
            &resolver,
            cached,
            Transport::Tls,
            connection_id,
        );
        assert_eq!(destination, cached, "must keep the established peer's connection address");
        assert_eq!(transport, Transport::Tls);
        assert_eq!(out_connection_id, connection_id, "must reuse the established connection_id");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn in_dialog_flow_resolves_fresh_for_divergent_next_hop() {
        // Next hop is a genuinely different peer than the established one (IMS
        // S-CSCF via the route set vs the I-CSCF the INVITE traversed): resolve
        // fresh and drop the established connection_id so a new connection is
        // opened/pooled.
        let resolver = test_resolver();
        let cached = "203.0.113.10:5060".parse::<SocketAddr>().unwrap(); // I-CSCF (established)
        let connection_id = ConnectionId(7);
        let (destination, _transport, out_connection_id) = resolve_in_dialog_flow_uri(
            Some("sip:203.0.113.20:5060"), // S-CSCF (route set)
            &resolver,
            cached,
            Transport::Udp,
            connection_id,
        );
        assert_eq!(destination, "203.0.113.20:5060".parse::<SocketAddr>().unwrap());
        assert_eq!(
            out_connection_id,
            ConnectionId::default(),
            "fresh resolution must not reuse the established connection_id",
        );
    }

    // --- B2BUA 401/407/422 retry connection reuse (RFC 5923) ---

    #[tokio::test(flavor = "multi_thread")]
    async fn b2bua_retry_reuses_established_member_not_resolved_sibling() {
        // The 401'd CSeq-1 INVITE (and the nonce) went to trunk member A.  The
        // dial target resolves to a *different* member B (the RFC 3263 A/AAAA
        // shuffle on a multi-member trunk behind one DNS name).  The retry MUST
        // stay on member A — the member that issued the nonce — so a strict
        // trunk doesn't 401 again and the INVITE isn't split across members.
        let resolver = test_resolver();
        let member_a = "198.51.100.10:5061".parse::<SocketAddr>().unwrap();
        let member_b_uri = "sip:trunk@198.51.100.20:5061;transport=tls";
        let leg_connection_id = ConnectionId(99);

        let (destination, transport, connection_id, relay_target) =
            select_b2bua_retry_destination(
                Some((member_a, Transport::Tls)),
                leg_connection_id,
                member_b_uri,
                &resolver,
            )
            .expect("established leg destination is always selectable");

        assert_eq!(
            destination, member_a,
            "retry must reuse the nonce-issuing member, not re-resolve onto a sibling",
        );
        assert_eq!(transport, Transport::Tls);
        assert_eq!(
            relay_target.address, member_a,
            "send target must point at the established member so the TLS pool reuses its connection",
        );
        assert_eq!(relay_target.transport, Some(Transport::Tls));
        // RFC 5923: the retry rides the connection the original INVITE was sent on.
        assert_eq!(connection_id, leg_connection_id);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn b2bua_retry_resolves_fresh_when_leg_has_no_destination() {
        // Defensive fallback: with no recorded leg destination, resolve the
        // target afresh and open/pool a new connection (default connection_id).
        let resolver = test_resolver();
        let (destination, transport, connection_id, relay_target) =
            select_b2bua_retry_destination(
                None,
                ConnectionId(99),
                "sip:bob@192.0.2.50:5061;transport=tls",
                &resolver,
            )
            .expect("a resolvable literal-IP target yields a destination");

        assert_eq!(destination, "192.0.2.50:5061".parse::<SocketAddr>().unwrap());
        assert_eq!(transport, Transport::Tls);
        assert_eq!(relay_target.address, destination);
        assert_eq!(
            connection_id,
            ConnectionId::default(),
            "fresh resolution must not claim a reused connection_id",
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn b2bua_retry_none_when_no_dest_and_unresolvable_target() {
        // No leg destination and an unresolvable target → None, so the caller
        // drops the retry rather than sending to a bogus address.
        let resolver = test_resolver();
        let result = select_b2bua_retry_destination(
            None,
            ConnectionId::default(),
            "sip:bob@this-domain-should-not-exist-xyzzy.invalid",
            &resolver,
        );
        assert!(result.is_none());
    }

    // --- CANCEL tests ---

    fn sample_cancel() -> SipMessage {
        SipMessageBuilder::new()
            .request(
                Method::Cancel,
                SipUri::new("biloxi.com".to_string()).with_user("bob".to_string()),
            )
            .via("SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds".to_string())
            .to("Bob <sip:bob@biloxi.com>".to_string())
            .from("Alice <sip:alice@atlanta.com>;tag=1928301774".to_string())
            .call_id("a84b4c76e66710@pc33.atlanta.com".to_string())
            .cseq("314159 CANCEL".to_string())
            .max_forwards(70)
            .content_length(0)
            .build()
            .unwrap()
    }

    #[test]
    fn build_cancel_response_200() {
        let cancel = sample_cancel();
        let response = build_response(&cancel, 200, "OK", None, &[]);
        assert_eq!(response.status_code(), Some(200));
        assert!(response.headers.cseq().unwrap().contains("CANCEL"));
    }

    #[test]
    fn build_cancel_response_481() {
        let cancel = sample_cancel();
        let response = build_response(&cancel, 481, "Call/Transaction Does Not Exist", None, &[]);
        assert_eq!(response.status_code(), Some(481));
    }

    #[test]
    fn build_487_response() {
        let invite = sample_invite();
        let response = build_response(&invite, 487, "Request Terminated", None, &[]);
        assert_eq!(response.status_code(), Some(487));
        assert!(response.headers.cseq().unwrap().contains("INVITE"));
    }

    // --- build_cancel_from_invite (RFC 3261 §9.1) ---

    fn b_leg_invite_sample() -> SipMessage {
        // Realistic B-leg INVITE as siphon would put it on the wire after
        // hygiene: single topmost Via, B-leg Call-ID, fresh From-tag,
        // To unchanged from the original RURI shape, Route set, SDP body.
        SipMessageBuilder::new()
            .request(
                Method::Invite,
                SipUri::new("ims.example.com".to_string())
                    .with_user("5111".to_string()),
            )
            .via("SIP/2.0/UDP siphon.example.com:6060;branch=z9hG4bK-bleg-INVITE-BRANCH".to_string())
            .to("<sip:5111@ims.example.com>".to_string())
            .from("<sip:+31621376327@siphon.example.com>;tag=b2bua-from-tag-XYZ".to_string())
            .call_id("b2b-call-id-bleg".to_string())
            .cseq("1 INVITE".to_string())
            .max_forwards(70)
            .header("Route", "<sip:icscf.example.com:5060;lr>".to_string())
            .header("Contact", "<sip:siphon@siphon.example.com:6060>".to_string())
            .header("Allow", "INVITE,ACK,BYE,CANCEL".to_string())
            .header("Supported", "timer,100rel".to_string())
            .header("Session-Expires", "1800".to_string())
            .header("Content-Type", "application/sdp".to_string())
            .body(b"v=0\r\no=- 0 0 IN IP4 1.2.3.4\r\n".to_vec())
            .build()
            .unwrap()
    }

    #[test]
    fn cancel_preserves_invite_via_branch() {
        let invite = b_leg_invite_sample();
        let cancel = build_cancel_from_invite(&invite).unwrap();
        let via = cancel.headers.via().unwrap();
        assert!(
            via.contains("branch=z9hG4bK-bleg-INVITE-BRANCH"),
            "CANCEL Via must reuse the INVITE branch (RFC 3261 §9.1): {via}",
        );
    }

    #[test]
    fn cancel_preserves_invite_cseq_number() {
        let invite = b_leg_invite_sample();
        let cancel = build_cancel_from_invite(&invite).unwrap();
        let cseq = cancel.headers.cseq().unwrap();
        assert_eq!(
            cseq, "1 CANCEL",
            "CANCEL CSeq must keep INVITE's sequence number and swap method to CANCEL",
        );
    }

    #[test]
    fn cancel_keeps_from_to_callid_verbatim() {
        let invite = b_leg_invite_sample();
        let cancel = build_cancel_from_invite(&invite).unwrap();
        assert_eq!(
            cancel.headers.from().unwrap(),
            "<sip:+31621376327@siphon.example.com>;tag=b2bua-from-tag-XYZ",
        );
        assert_eq!(
            cancel.headers.to().unwrap(),
            "<sip:5111@ims.example.com>",
        );
        assert_eq!(cancel.headers.call_id().unwrap(), "b2b-call-id-bleg");
    }

    #[test]
    fn cancel_request_line_method_is_cancel_with_invite_ruri() {
        let invite = b_leg_invite_sample();
        let cancel = build_cancel_from_invite(&invite).unwrap();
        match &cancel.start_line {
            StartLine::Request(rl) => {
                assert_eq!(rl.method, Method::Cancel);
                assert_eq!(rl.request_uri.user.as_deref(), Some("5111"));
                assert_eq!(rl.request_uri.host, "ims.example.com");
            }
            StartLine::Response(_) => panic!("expected request"),
        }
    }

    #[test]
    fn cancel_strips_body_and_body_bearing_headers() {
        let invite = b_leg_invite_sample();
        let cancel = build_cancel_from_invite(&invite).unwrap();
        assert!(cancel.body.is_empty(), "CANCEL must carry no body");
        assert_eq!(cancel.headers.content_length(), Some(0));
        assert!(
            !cancel.headers.has("Content-Type"),
            "CANCEL must not carry Content-Type"
        );
        assert!(
            !cancel.headers.has("Contact"),
            "CANCEL is hop-by-hop — Contact must be stripped"
        );
        assert!(
            !cancel.headers.has("Allow"),
            "CANCEL must not carry Allow"
        );
        assert!(
            !cancel.headers.has("Supported"),
            "CANCEL must not carry Supported"
        );
        assert!(
            !cancel.headers.has("Session-Expires"),
            "CANCEL must not carry Session-Expires"
        );
    }

    #[test]
    fn cancel_keeps_route_set() {
        let invite = b_leg_invite_sample();
        let cancel = build_cancel_from_invite(&invite).unwrap();
        assert_eq!(
            cancel.headers.get("Route").map(String::as_str),
            Some("<sip:icscf.example.com:5060;lr>"),
            "CANCEL must follow the same Route set as the INVITE it cancels",
        );
    }

    #[test]
    fn cancel_keeps_max_forwards() {
        let invite = b_leg_invite_sample();
        let cancel = build_cancel_from_invite(&invite).unwrap();
        assert_eq!(cancel.headers.max_forwards(), Some(70));
    }

    #[test]
    fn cancel_returns_none_for_response_input() {
        // Defensive: build_cancel_from_invite must reject responses.
        let response = build_response(&b_leg_invite_sample(), 100, "Trying", None, &[]);
        assert!(build_cancel_from_invite(&response).is_none());
    }

    // --- 2xx-after-CANCEL glare: ACK builder (RFC 3261 §13.2.2.4) ---

    #[test]
    fn build_ack_for_2xx_echoes_dialog_and_targets_contact() {
        // The ACK siphon sends when a 2xx races our CANCEL must be its own
        // transaction: R-URI = the 2xx Contact, CSeq = the INVITE's number with
        // method ACK, From/To/Call-ID echoed (To carries the remote tag), and a
        // fresh Via on our supplied host:port.
        let response = SipMessageBuilder::new()
            .response(200, "OK".to_string())
            .via("SIP/2.0/UDP 10.0.0.9:5060;branch=z9hG4bK-bleg".to_string())
            .from("<sip:alice@10.0.0.50>;tag=our-tag".to_string())
            .to("<sip:bob@10.0.0.2>;tag=their-tag".to_string())
            .call_id("glare-call@10.0.0.50".to_string())
            .cseq("5 INVITE".to_string())
            .header("Contact", "<sip:bob@10.0.0.2:5070>".to_string())
            .content_length(0)
            .build()
            .unwrap();

        let ack = build_b2bua_ack_for_2xx(&response, Transport::Udp, "10.0.0.9", 5060)
            .expect("ACK builds");
        let wire = String::from_utf8(ack.to_bytes()).unwrap();

        // R-URI is the 2xx Contact (the remote target), method ACK.
        assert!(
            wire.starts_with("ACK sip:bob@10.0.0.2:5070 SIP/2.0\r\n"),
            "request line wrong:\n{wire}"
        );
        // Same CSeq number as the INVITE, method ACK (RFC 3261 §13.2.2.4).
        assert!(wire.contains("CSeq: 5 ACK\r\n"), "CSeq wrong:\n{wire}");
        // Dialog identifiers echoed from the 2xx, including the remote To-tag.
        assert!(wire.contains("Call-ID: glare-call@10.0.0.50\r\n"), "Call-ID:\n{wire}");
        assert!(wire.contains(";tag=their-tag"), "To-tag must survive:\n{wire}");
        assert!(wire.contains(";tag=our-tag"), "From-tag must survive:\n{wire}");
        // Fresh Via on the supplied local host:port.
        assert!(
            wire.contains("Via: SIP/2.0/UDP 10.0.0.9:5060;branch="),
            "Via host:port wrong:\n{wire}"
        );
    }

    #[test]
    fn build_ack_for_2xx_falls_back_when_contact_absent() {
        // No Contact on the 2xx → R-URI degrades to a placeholder rather than
        // panicking; CSeq number is still preserved from the response.
        let response = SipMessageBuilder::new()
            .response(200, "OK".to_string())
            .via("SIP/2.0/UDP 10.0.0.9:5060;branch=z9hG4bK-x".to_string())
            .from("<sip:alice@10.0.0.50>;tag=a".to_string())
            .to("<sip:bob@10.0.0.2>;tag=b".to_string())
            .call_id("no-contact@10.0.0.50".to_string())
            .cseq("9 INVITE".to_string())
            .content_length(0)
            .build()
            .unwrap();

        let ack = build_b2bua_ack_for_2xx(&response, Transport::Udp, "10.0.0.9", 5060)
            .expect("ACK builds even without Contact");
        let wire = String::from_utf8(ack.to_bytes()).unwrap();
        assert!(wire.starts_with("ACK "), "must still be an ACK:\n{wire}");
        assert!(wire.contains("CSeq: 9 ACK\r\n"), "CSeq preserved:\n{wire}");
    }

    // --- Proxy-forwarded CANCEL Via (RFC 3261 §9.1 / §16.10) ---
    //
    // Regression: handle_cancel_via_session used to mint a fresh branch
    // (TransactionKey::generate_branch()) for the forwarded CANCEL, so the
    // downstream proxy/UAS could not match CANCEL→INVITE and dropped it — the
    // INVITE leg below was never torn down and the callee kept ringing after
    // the caller abandoned during alerting.

    #[test]
    fn proxy_cancel_via_reuses_invite_branch_and_sent_by() {
        // The proxy forwarded an INVITE on this client branch; its transaction
        // key holds exactly the branch + sent-by siphon stamped on that
        // INVITE's topmost Via.
        let client_key = TransactionKey::new(
            "z9hG4bK-invite-branch-B".to_string(),
            Method::Invite,
            "172.16.0.111:4060".to_string(),
        );
        let via = cancel_via_for_client_branch(&client_key, Transport::Udp);
        assert_eq!(
            via, "SIP/2.0/UDP 172.16.0.111:4060;branch=z9hG4bK-invite-branch-B",
            "forwarded CANCEL must reuse the INVITE's top Via branch + sent-by (RFC 3261 §9.1)",
        );
    }

    #[test]
    fn proxy_cancel_via_branch_is_deterministic_not_fresh() {
        // Guards the exact regression: TransactionKey::generate_branch() would
        // yield a different (and non-matching) branch on every call.
        let client_key = TransactionKey::new(
            "z9hG4bK-stored-branch".to_string(),
            Method::Invite,
            "10.0.0.1:5060".to_string(),
        );
        let via_first = cancel_via_for_client_branch(&client_key, Transport::Tcp);
        let via_second = cancel_via_for_client_branch(&client_key, Transport::Tcp);
        assert_eq!(
            via_first, via_second,
            "forwarded CANCEL Via must derive from the stored client branch, \
             never a freshly generated one",
        );
        assert!(
            via_first.ends_with(";branch=z9hG4bK-stored-branch"),
            "CANCEL branch must equal the stored INVITE branch: {via_first}",
        );
    }

    #[test]
    fn proxy_cancel_via_preserves_transport_and_ipv6_sent_by() {
        // sent_by is reused verbatim from the client key — this covers the
        // IPsec / flow / force_send_via cases where the advertised sent-by
        // (here an IPv6 literal with a non-default protected port) differs
        // from the default per-transport via_host.
        let client_key = TransactionKey::new(
            "z9hG4bK-tls-branch".to_string(),
            Method::Invite,
            "[2001:db8::1]:5061".to_string(),
        );
        let via = cancel_via_for_client_branch(&client_key, Transport::Tls);
        assert_eq!(
            via, "SIP/2.0/TLS [2001:db8::1]:5061;branch=z9hG4bK-tls-branch",
        );
    }

    // --- Transaction integration tests ---

    #[test]
    fn transaction_manager_creates_client_transaction() {
        let manager = TransactionManager::default();
        let invite = sample_invite();
        let txn_transport = crate::transaction::state::Transport::Udp;
        let (key, actions) = manager.new_client_transaction(invite, txn_transport).unwrap();
        assert_eq!(key.method, Method::Invite);
        assert_eq!(manager.count(), 1);
        // Should have SendMessage + StartTimer(B) + StartTimer(A) for UDP
        assert!(actions.iter().any(|a| matches!(a, Action::SendMessage(_))));
        assert!(actions.iter().any(|a| matches!(a, Action::StartTimer(TimerName::B, _))));
        assert!(actions.iter().any(|a| matches!(a, Action::StartTimer(TimerName::A, _))));
    }

    /// Regression for the spurious-INVITE-retransmit bug: a forwarded INVITE
    /// arms Timer A, and the downstream 100 Trying MUST cancel it (RFC 3261
    /// §17.1.1.2). The historical bug was the dispatcher `return`ing on
    /// status==100 (RFC 3261 §16.7 "don't forward 100 upstream") *before*
    /// feeding the client transaction, so Timer A stayed armed and the proxy
    /// retransmitted the INVITE ~T1 (~500 ms) despite holding a provisional.
    ///
    /// Two properties must hold for the dispatcher's absorb-the-100 path
    /// (which now feeds the FSM) to actually stop the retransmit:
    ///   1. the key derived from the echoed 100 matches the key the client
    ///      transaction was registered under (RFC 3261 §17.1.3), and
    ///   2. feeding that 100 as a Provisional emits CancelTimer(A).
    #[test]
    fn provisional_100_cancels_invite_client_timer_a() {
        let manager = TransactionManager::default();
        let invite = SipMessageBuilder::new()
            .request(
                Method::Invite,
                SipUri::new("biloxi.com".to_string()).with_user("bob".to_string()),
            )
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-timera".to_string())
            .to("Bob <sip:bob@biloxi.com>".to_string())
            .from("Alice <sip:alice@atlanta.com>;tag=99".to_string())
            .call_id("timera-call@10.0.0.1".to_string())
            .cseq("1 INVITE".to_string())
            .max_forwards(70)
            .content_length(0)
            .build()
            .unwrap();

        let (key, start_actions) = manager
            .new_client_transaction(invite, crate::transaction::state::Transport::Udp)
            .unwrap();
        assert!(
            start_actions.iter().any(|a| matches!(a, Action::StartTimer(TimerName::A, _))),
            "UDP INVITE client transaction must arm Timer A"
        );

        // Downstream 100 Trying echoing the forwarded INVITE's top Via verbatim.
        let trying = SipMessageBuilder::new()
            .response(100, "Trying".to_string())
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-timera".to_string())
            .to("Bob <sip:bob@biloxi.com>".to_string())
            .from("Alice <sip:alice@atlanta.com>;tag=99".to_string())
            .call_id("timera-call@10.0.0.1".to_string())
            .cseq("1 INVITE".to_string())
            .content_length(0)
            .build()
            .unwrap();

        // (1) The 100 must map to the same transaction key the ICT was
        //     registered under — else the dispatcher's process_client_event
        //     lookup misses and Timer A is never cancelled.
        let response_key = TransactionManager::key_from_message(&trying).unwrap();
        assert_eq!(response_key, key, "100 response key must match the ICT key");

        // (2) Feeding the 100 as a provisional cancels Timer A.
        let actions = manager
            .process_client_event(&response_key, ClientEvent::Ict(IctEvent::Provisional(trying)))
            .unwrap();
        assert!(
            actions.iter().any(|a| matches!(a, Action::CancelTimer(TimerName::A))),
            "100 Trying must cancel the INVITE retransmit Timer A"
        );
    }

    #[test]
    fn transaction_manager_creates_server_transaction() {
        let manager = TransactionManager::default();
        let invite = sample_invite();
        let txn_transport = crate::transaction::state::Transport::Udp;
        let (key, actions) = manager.new_server_transaction(&invite, txn_transport).unwrap();
        assert_eq!(key.method, Method::Invite);
        assert_eq!(manager.count(), 1);
        assert!(actions.iter().any(|a| matches!(a, Action::PassToTu(_))));
    }

    #[test]
    fn timer_entry_created_with_correct_fields() {
        let key = TransactionKey::new("z9hG4bK-test".to_string(), Method::Invite, "10.0.0.1:5060".to_string());
        let entry = TimerEntry {
            key: key.clone(),
            name: TimerName::A,
            fires_at: std::time::Instant::now() + std::time::Duration::from_millis(500),
            destination: Some("10.0.0.1:5060".parse().unwrap()),
            transport: Some(Transport::Udp),
            connection_id: Some(ConnectionId::default()),
            source_local_addr: None,
        };
        assert_eq!(entry.key, key);
        assert_eq!(entry.name, TimerName::A);
        assert!(entry.destination.is_some());
    }

    #[test]
    fn transport_conversion_udp() {
        let txn = crate::transaction::state::Transport::from(Transport::Udp);
        assert_eq!(txn, crate::transaction::state::Transport::Udp);
    }

    #[test]
    fn transport_conversion_tcp_is_reliable() {
        let txn = crate::transaction::state::Transport::from(Transport::Tcp);
        assert_eq!(txn, crate::transaction::state::Transport::Reliable);
    }

    #[test]
    fn transport_conversion_tls_is_reliable() {
        let txn = crate::transaction::state::Transport::from(Transport::Tls);
        assert_eq!(txn, crate::transaction::state::Transport::Reliable);
    }

    // --- B2BUA call manager tests ---

    #[test]
    fn call_manager_create_and_cancel() {
        let manager = CallActorStore::new();
        let a_leg = Leg::new_a_leg(
            "call-1".to_string(),
            "tag-1".to_string(),
            "z9hG4bK-a1".to_string(),
            LegTransport {
                remote_addr: "10.0.0.1:5060".parse().unwrap(),
                connection_id: ConnectionId::default(),
                transport: Transport::Udp,
                local_addr: None,
            },
        );
        let call_id = manager.create_call(a_leg);
        assert_eq!(manager.count(), 1);

        // Simulate cancel: set state and remove
        manager.set_state(&call_id, CallState::Terminated);
        manager.remove_call(&call_id);
        assert_eq!(manager.count(), 0);
    }

    #[test]
    fn call_manager_b_leg_response_routing() {
        let manager = CallActorStore::new();
        let a_leg = Leg::new_a_leg(
            "call-1".to_string(),
            "tag-1".to_string(),
            "z9hG4bK-a1".to_string(),
            LegTransport {
                remote_addr: "10.0.0.1:5060".parse().unwrap(),
                connection_id: ConnectionId::default(),
                transport: Transport::Udp,
                local_addr: None,
            },
        );
        let call_id = manager.create_call(a_leg);

        let b_leg = Leg::new_b_leg(
            "b2b-test-1".to_string(),
            "sb-test-1".to_string(),
            "sip:bob@10.0.0.2".to_string(),
            "z9hG4bK-b1".to_string(),
            LegTransport {
                remote_addr: "10.0.0.2:5060".parse().unwrap(),
                connection_id: ConnectionId::default(),
                transport: Transport::Udp,
                local_addr: None,
            },
        );
        manager.add_b_leg(&call_id, b_leg);

        // Can route response via B-leg branch
        assert_eq!(manager.call_id_for_branch("z9hG4bK-b1"), Some(call_id.clone()));

        // Set winner and verify answered state
        manager.set_winner(&call_id, 0);
        let call = manager.get_call(&call_id).unwrap();
        assert_eq!(call.state, CallState::Answered);
        assert_eq!(call.winner, Some(0));
    }

    /// Verify that next_hop routing does not clobber the Request-URI.
    ///
    /// The relay_request function uses next_hop only for DNS resolution /
    /// packet routing, keeping the original R-URI (including user part) intact.
    /// This test validates the invariant at the message level.
    #[test]
    fn next_hop_does_not_overwrite_request_uri() {
        let invite = sample_invite();
        // Original R-URI: sip:bob@biloxi.com
        let original_ruri = match &invite.start_line {
            StartLine::Request(rl) => rl.request_uri.to_string(),
            _ => panic!("expected request"),
        };
        assert!(original_ruri.contains("bob@"), "original R-URI should have user part: {original_ruri}");

        // Simulate what relay_request does: clone, add Via/RR, but do NOT overwrite R-URI
        let relayed = invite.clone();
        let ruri_after = match &relayed.start_line {
            StartLine::Request(rl) => rl.request_uri.to_string(),
            _ => panic!("expected request"),
        };
        assert_eq!(original_ruri, ruri_after,
            "R-URI must be preserved when next_hop is used for routing only");
    }

    // --- Bug fix regression tests ---

    /// Bug 1: INVITE retransmissions should be detected via find_by_sip_call_id.
    #[test]
    fn retransmission_guard_detects_duplicate_call_id() {
        let manager = CallActorStore::new();
        let a_leg = Leg::new_a_leg(
            "retransmit-test@host".to_string(),
            "tag-orig".to_string(),
            "z9hG4bK-orig".to_string(),
            LegTransport {
                remote_addr: "10.0.0.1:5060".parse().unwrap(),
                connection_id: ConnectionId::default(),
                transport: Transport::Udp,
                local_addr: None,
            },
        );
        let _call_id = manager.create_call(a_leg);

        // Second INVITE with same SIP Call-ID (retransmission) should be detected
        assert!(
            manager.find_by_sip_call_id("retransmit-test@host").is_some(),
            "retransmission guard must detect existing call by SIP Call-ID"
        );
        // Different Call-ID should not match
        assert!(manager.find_by_sip_call_id("different-call@host").is_none());
    }

    /// Bug 2: build_b2bua_ack_for_non2xx constructs a valid ACK from a B-leg error response.
    #[test]
    fn build_b2bua_ack_for_non2xx_constructs_valid_ack() {
        // Build a 486 response as if from B-leg
        let response = SipMessageBuilder::new()
            .response(486, "Busy Here".to_string())
            .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-b2b-branch".to_string())
            .from("<sip:alice@example.com>;tag=b-leg-ftag".to_string())
            .to("<sip:bob@example.com>;tag=bob-tag".to_string())
            .call_id("b-leg-call-id".to_string())
            .cseq("1 INVITE".to_string())
            .content_length(0)
            .build()
            .unwrap();

        let ack = build_b2bua_ack_for_non2xx(
            &response,
            "z9hG4bK-b2b-branch",
            Some("sip:bob@10.0.0.2:5060"),
            Transport::Udp,
            "198.51.100.20",
            5060,
        );

        assert!(ack.is_request());
        let bytes = String::from_utf8(ack.to_bytes()).unwrap();
        assert!(bytes.starts_with("ACK sip:bob@10.0.0.2:5060 SIP/2.0\r\n"));

        // Via uses our branch (same as client transaction) and the advertised
        // sent-by host:port supplied by the caller (state.via_host/via_port).
        let via = ack.headers.via().unwrap();
        assert!(via.contains("z9hG4bK-b2b-branch"));
        assert!(via.contains("UDP"));
        assert!(via.contains("198.51.100.20:5060"));

        // From/To/Call-ID from the response
        assert!(ack.headers.from().unwrap().contains("b-leg-ftag"));
        assert!(ack.headers.to().unwrap().contains("bob-tag"));
        assert_eq!(ack.headers.call_id().unwrap(), "b-leg-call-id");

        // CSeq: same number, ACK method
        let cseq = ack.headers.cseq().unwrap();
        assert!(cseq.contains("1"));
        assert!(cseq.contains("ACK"));
        assert!(!cseq.contains("INVITE"));

        assert_eq!(ack.headers.content_length(), Some(0));
    }

    /// Bug 3: Winner is recorded and can be used to find the winning B-leg for ACK bridging.
    #[test]
    fn winner_tracks_answered_b_leg_for_ack_bridging() {
        let manager = CallActorStore::new();
        let a_leg = Leg::new_a_leg(
            "ack-bridge-test@host".to_string(),
            "a-tag".to_string(),
            "z9hG4bK-a1".to_string(),
            LegTransport {
                remote_addr: "10.0.0.1:5060".parse().unwrap(),
                connection_id: ConnectionId::default(),
                transport: Transport::Udp,
                local_addr: None,
            },
        );
        let call_id = manager.create_call(a_leg);

        // Add two B-legs (forked call)
        let b_leg_0 = Leg::new_b_leg(
            "b-cid-0".to_string(),
            "b-ftag-0".to_string(),
            "sip:bob@10.0.0.2".to_string(),
            "z9hG4bK-b0".to_string(),
            LegTransport {
                remote_addr: "10.0.0.2:5060".parse().unwrap(),
                connection_id: ConnectionId::default(),
                transport: Transport::Udp,
                local_addr: None,
            },
        );
        let b_leg_1 = Leg::new_b_leg(
            "b-cid-1".to_string(),
            "b-ftag-1".to_string(),
            "sip:bob@10.0.0.3".to_string(),
            "z9hG4bK-b1".to_string(),
            LegTransport {
                remote_addr: "10.0.0.3:5060".parse().unwrap(),
                connection_id: ConnectionId::default(),
                transport: Transport::Udp,
                local_addr: None,
            },
        );
        manager.add_b_leg(&call_id, b_leg_0);
        manager.add_b_leg(&call_id, b_leg_1);

        // B-leg 1 answers first
        manager.set_winner(&call_id, 1);
        manager.set_state(&call_id, CallState::Answered);

        let call = manager.get_call(&call_id).unwrap();
        assert_eq!(call.winner, Some(1));
        let winner = &call.b_legs[call.winner.unwrap()];
        assert_eq!(winner.dialog.call_id, "b-cid-1");
        assert_eq!(winner.dialog.local_tag, "b-ftag-1");
        assert_eq!(winner.transport.remote_addr, "10.0.0.3:5060".parse::<SocketAddr>().unwrap());

        // ACK bridging would use find_by_sip_call_id to locate the call
        assert_eq!(
            manager.find_by_sip_call_id("ack-bridge-test@host"),
            Some(call_id),
        );
    }

    #[test]
    fn sanitize_sdp_identity_rewrites_o_and_s_lines() {
        let sdp = "v=0\r\no=FreeSWITCH 123 456 IN IP4 10.0.0.1\r\ns=FreeSWITCH\r\nt=0 0\r\nm=audio 8000 RTP/AVP 0\r\n";
        let mut body = sdp.as_bytes().to_vec();
        sanitize_sdp_identity(&mut body, "Test SBC", None);
        let result = std::str::from_utf8(&body).unwrap();
        // o= username is space-delimited (RFC 4566 §5.2) — whitespace in the
        // configured name MUST collapse to `-`.
        assert!(result.contains("o=Test-SBC 123 456 IN IP4 10.0.0.1\r\n"));
        // s= permits whitespace (§5.3) — preserved verbatim.
        assert!(result.contains("s=Test SBC\r\n"));
        assert!(!result.contains("FreeSWITCH"));
        // Other lines unchanged
        assert!(result.contains("v=0\r\n"));
        assert!(result.contains("m=audio 8000 RTP/AVP 0\r\n"));
    }

    #[test]
    fn sanitize_sdp_identity_rewrites_o_line_address() {
        let sdp = "v=0\r\no=FreeSWITCH 123 456 IN IP4 10.0.0.1\r\ns=FreeSWITCH\r\nt=0 0\r\nm=audio 8000 RTP/AVP 0\r\n";
        let mut body = sdp.as_bytes().to_vec();
        sanitize_sdp_identity(&mut body, "SIPhon", Some("203.0.113.1"));
        let result = std::str::from_utf8(&body).unwrap();
        assert!(result.contains("o=SIPhon 123 456 IN IP4 203.0.113.1\r\n"), "o= line should have rewritten address, got: {result}");
        assert!(result.contains("s=SIPhon\r\n"));
        assert!(!result.contains("10.0.0.1"));
        assert!(!result.contains("FreeSWITCH"));
    }

    #[test]
    fn sanitize_sdp_identity_no_op_on_empty_body() {
        let mut body = Vec::new();
        sanitize_sdp_identity(&mut body, "SIPhon", None);
        assert!(body.is_empty());
    }

    /// Regression: an `sdp_name` configured with internal whitespace
    /// (multi-word product / role name) was being written verbatim into the
    /// SDP `o=` line. RFC 4566 §5.2 splits o= on spaces, so a value like
    /// `o=Foo Bar 123 456 IN IP4 ...` has a malformed username token and
    /// downstream parsers (FreeSWITCH, kamailio) reject the whole SDP body.
    #[test]
    fn sanitize_sdp_identity_collapses_whitespace_in_o_username() {
        let sdp = "v=0\r\no=- 1 2 IN IP4 10.0.0.1\r\ns=-\r\nt=0 0\r\nm=audio 8000 RTP/AVP 0\r\n";
        let mut body = sdp.as_bytes().to_vec();
        sanitize_sdp_identity(&mut body, "Foo Bar", Some("203.0.113.5"));
        let result = std::str::from_utf8(&body).unwrap();
        assert!(
            result.contains("o=Foo-Bar 1 2 IN IP4 203.0.113.5\r\n"),
            "o= username must collapse whitespace; got: {result}",
        );
        // RFC 4566 token count check: o= line must have exactly 6 fields.
        let o_line = result.lines().find(|l| l.starts_with("o=")).unwrap();
        assert_eq!(
            o_line.split(' ').count(),
            6,
            "o= line must have exactly 6 space-separated fields; got: {o_line}",
        );
    }

    #[test]
    fn sanitize_o_username_collapses_internal_whitespace() {
        assert_eq!(sanitize_o_username("Foo Bar"), "Foo-Bar");
        assert_eq!(sanitize_o_username("Foo  Bar"), "Foo-Bar");
        assert_eq!(sanitize_o_username("a b c"), "a-b-c");
        assert_eq!(sanitize_o_username("siphon"), "siphon");
        assert_eq!(sanitize_o_username("SIPhon\tProxy"), "SIPhon-Proxy");
    }

    #[test]
    fn sanitize_o_username_handles_pure_whitespace() {
        // "All whitespace" → fall back to the RFC 4566 "no user ID" sentinel.
        assert_eq!(sanitize_o_username("   "), "-");
        assert_eq!(sanitize_o_username(""), "");
    }

    /// Verify that fork targets DO update the R-URI (each branch gets its Contact).
    #[test]
    fn fork_branch_updates_request_uri() {
        let invite = sample_invite();
        let mut relayed = invite.clone();

        // Simulate fork branch updating R-URI to registered contact
        let target = "sip:bob@192.168.1.50:5060;transport=tls";
        if let Ok(new_uri) = parse_uri_standalone(target) {
            if let StartLine::Request(ref mut rl) = relayed.start_line {
                rl.request_uri = new_uri;
            }
        }

        let ruri = match &relayed.start_line {
            StartLine::Request(rl) => rl.request_uri.to_string(),
            _ => panic!("expected request"),
        };
        assert!(ruri.contains("bob@192.168.1.50"),
            "fork branch R-URI should be updated to target contact: {ruri}");
    }

    #[test]
    fn srs_answer_flips_sendonly_to_recvonly() {
        let sdp = concat!(
            "v=0\r\n",
            "o=- 1234 5678 IN IP4 10.0.0.1\r\n",
            "s=-\r\n",
            "t=0 0\r\n",
            "m=audio 10000 RTP/AVP 8 101\r\n",
            "c=IN IP4 10.0.0.1\r\n",
            "a=sendonly\r\n",
            "m=audio 10002 RTP/AVP 8 101\r\n",
            "c=IN IP4 10.0.0.1\r\n",
            "a=sendonly\r\n",
        );
        let mut body = sdp.as_bytes().to_vec();
        fix_srs_answer_sdp_direction(&mut body);
        let result = String::from_utf8(body).unwrap();
        assert!(!result.contains("a=sendonly"), "sendonly should be flipped");
        assert_eq!(result.matches("a=recvonly").count(), 2);
    }

    #[test]
    fn srs_answer_flips_recvonly_to_sendonly() {
        let sdp = concat!(
            "v=0\r\n",
            "o=- 1234 5678 IN IP4 10.0.0.1\r\n",
            "s=-\r\n",
            "t=0 0\r\n",
            "m=audio 10000 RTP/AVP 8\r\n",
            "a=recvonly\r\n",
        );
        let mut body = sdp.as_bytes().to_vec();
        fix_srs_answer_sdp_direction(&mut body);
        let result = String::from_utf8(body).unwrap();
        assert!(result.contains("a=sendonly"));
        assert!(!result.contains("a=recvonly"));
    }

    #[test]
    fn srs_answer_leaves_sendrecv_unchanged() {
        let sdp = concat!(
            "v=0\r\n",
            "o=- 1234 5678 IN IP4 10.0.0.1\r\n",
            "s=-\r\n",
            "t=0 0\r\n",
            "m=audio 10000 RTP/AVP 8\r\n",
            "a=sendrecv\r\n",
        );
        let mut body = sdp.as_bytes().to_vec();
        fix_srs_answer_sdp_direction(&mut body);
        let result = String::from_utf8(body).unwrap();
        assert!(result.contains("a=sendrecv"));
    }

    #[test]
    fn srs_answer_no_direction_unchanged() {
        let sdp = concat!(
            "v=0\r\n",
            "o=- 1234 5678 IN IP4 10.0.0.1\r\n",
            "s=-\r\n",
            "t=0 0\r\n",
            "m=audio 10000 RTP/AVP 8\r\n",
            "c=IN IP4 10.0.0.1\r\n",
        );
        let mut body = sdp.as_bytes().to_vec();
        let original = body.clone();
        fix_srs_answer_sdp_direction(&mut body);
        assert_eq!(body, original);
    }

    // --- parse_contact_expires tests ---

    #[test]
    fn contact_expires_bare_param() {
        assert_eq!(parse_contact_expires("<sip:trunk@10.0.0.1:5060>;expires=3600"), Some(3600));
    }

    #[test]
    fn contact_expires_quoted_value() {
        assert_eq!(parse_contact_expires("<sip:trunk@10.0.0.1:5060>;expires=\"1800\""), Some(1800));
    }

    #[test]
    fn contact_expires_ignores_uri_param() {
        // expires= inside angle brackets is a URI parameter, not a Contact parameter
        assert_eq!(
            parse_contact_expires("<sip:trunk@10.0.0.1:5060;expires=0>;expires=3600"),
            Some(3600),
        );
    }

    #[test]
    fn contact_expires_uri_param_only_ignored() {
        // Only URI-level expires=, no Contact-level — should return None
        assert_eq!(parse_contact_expires("<sip:trunk@10.0.0.1:5060;expires=0>"), None);
    }

    #[test]
    fn contact_expires_no_angle_brackets() {
        assert_eq!(parse_contact_expires("sip:trunk@10.0.0.1:5060;expires=600"), Some(600));
    }

    #[test]
    fn contact_expires_missing() {
        assert_eq!(parse_contact_expires("<sip:trunk@10.0.0.1:5060>"), None);
    }

    #[test]
    fn contact_expires_with_other_params() {
        assert_eq!(
            parse_contact_expires("<sip:trunk@10.0.0.1:5060>;q=0.8;expires=900;+sip.instance=\"<urn:uuid:abc>\""),
            Some(900),
        );
    }

    // -----------------------------------------------------------------------
    // MediaTimeout bookkeeping — clear siphon-sip's own media session so the
    // downstream safety-net delete (gated on a present record) is a no-op.
    // -----------------------------------------------------------------------

    fn media_session_fixture(call_id: &str) -> crate::rtpengine::session::MediaSession {
        crate::rtpengine::session::MediaSession {
            call_id: call_id.to_string(),
            from_tag: "a-tag".to_string(),
            to_tag: None,
            profile: "srtp_to_rtp".to_string(),
            created_at: std::time::Instant::now(),
        }
    }

    #[test]
    fn clear_media_session_on_timeout_removes_the_record() {
        let store = Arc::new(crate::rtpengine::session::MediaSessionStore::new());
        store.insert(media_session_fixture("1-1354742@host"));
        assert_eq!(store.len(), 1);

        // The event's call_id equals the store key (engine call-id == SIP Call-ID).
        let cleared = clear_media_session_on_timeout(Some(&store), "1-1354742@host");

        // Record removed → returns true and the store is empty. Because every
        // safety-net delete site is gated on `if let Some(session) =
        // media_sessions.remove(&…)`, an empty store means the later teardown
        // (e.g. via b2bua.terminate) issues NO `set.delete` — no round-trip, no
        // "unknown call" warn. (MediaBackend is a concrete enum with no trait to
        // mock, so store-is-empty is the structurally-equivalent assertion to a
        // spy that expects zero delete calls.)
        assert!(cleared);
        assert!(store.get("1-1354742@host").is_none());
        assert!(store.is_empty());
    }

    #[test]
    fn clear_media_session_on_timeout_no_record_is_noop() {
        let store = Arc::new(crate::rtpengine::session::MediaSessionStore::new());
        // Unknown call_id → nothing to clear, returns false, does not panic.
        assert!(!clear_media_session_on_timeout(Some(&store), "no-such-call@host"));
        assert!(store.is_empty());
    }

    #[test]
    fn clear_media_session_on_timeout_no_store_is_noop() {
        // Media backend not configured (rtpengine_sessions is None) → false.
        assert!(!clear_media_session_on_timeout(None, "1-1354742@host"));
    }

}
