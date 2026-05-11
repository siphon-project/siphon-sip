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
use crate::sip::parser::{parse_sip_message, parse_sip_message_bytes, parse_uri_standalone};
use crate::sip::uri::format_sip_host;
use crate::transaction::key::TransactionKey;
use crate::transaction::state::{
    Action, TimerName,
    IstEvent, NistEvent, IctEvent, NictEvent,
};
use crate::transaction::{TransactionManager, ServerEvent, ClientEvent};
use crate::transaction::timer::TimerConfig;
use crate::hep::HepSender;
use crate::transport::{ConnectionId, InboundMessage, OutboundMessage, OutboundRouter, Transport};
use crate::transport::pool::ConnectionPool;
use crate::uac::UacSender;

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
    /// RTPEngine client set (None when media.rtpengine is not configured).
    rtpengine_set: Option<Arc<crate::rtpengine::client::RtpEngineSet>>,
    /// RTPEngine media session store (None when media.rtpengine is not configured).
    rtpengine_sessions: Option<Arc<crate::rtpengine::session::MediaSessionStore>>,
    /// RTPEngine media profile registry (None when media.rtpengine is not configured).
    rtpengine_profiles: Option<Arc<crate::rtpengine::ProfileRegistry>>,
    /// RFC 4028 session timer configuration (None when not configured).
    session_timer_config: Option<crate::config::SessionTimerConfig>,
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
    /// Outbound TCP/TLS connection pool for relay to new destinations.
    connection_pool: Arc<ConnectionPool>,
    /// Reverse map: TLS remote SocketAddr → ConnectionId for connection reuse.
    /// Populated by the TLS listener; used by send_to_target to reuse inbound
    /// TLS connections when relaying to registered endpoints (like OpenSIPS).
    tls_addr_map: Arc<DashMap<SocketAddr, ConnectionId>>,
    /// RFC 5626 CRLF pong tracker (None when crlf_keepalive is not configured).
    crlf_pong_tracker: Option<Arc<crate::transport::crlf_keepalive::CrlfPongTracker>>,
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
#[allow(clippy::too_many_arguments)]
pub async fn run(
    inbound_rx: flume::Receiver<InboundMessage>,
    outbound: Arc<OutboundRouter>,
    engine: Arc<ScriptEngine>,
    config: Arc<Config>,
    local_addr: SocketAddr,
    listen_addrs: std::collections::HashMap<Transport, SocketAddr>,
    advertised_addrs: std::collections::HashMap<Transport, String>,
    hep_sender: Option<Arc<HepSender>>,
    uac_sender: Arc<UacSender>,
    connection_pool: Arc<ConnectionPool>,
    pre_rtpengine: (
        Option<Arc<crate::rtpengine::client::RtpEngineSet>>,
        Option<Arc<crate::rtpengine::session::MediaSessionStore>>,
        Option<Arc<crate::rtpengine::ProfileRegistry>>,
    ),
    registrant_manager: Option<Arc<crate::registrant::RegistrantManager>>,
    ipsec_manager: Option<Arc<crate::ipsec::IpsecManager>>,
    ipsec_config: Option<crate::config::IpsecConfig>,
    tls_addr_map: Arc<DashMap<SocketAddr, ConnectionId>>,
    crlf_pong_tracker: Option<Arc<crate::transport::crlf_keepalive::CrlfPongTracker>>,
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

    let timer_config = TimerConfig::default();
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

    let state = Arc::new(DispatcherState {
        engine,
        outbound,
        local_domains: Arc::new(config.domain.local.clone()),
        local_addr: via_addr,
        advertised_addrs: merged_advertised,
        listen_addrs,
        server_header,
        user_agent_header,
        transaction_timeout,
        call_actors: Arc::new(CallActorStore::new()),
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
        connection_pool,
        tls_addr_map,
        crlf_pong_tracker,
        nat_fix_contact: config.nat.as_ref().map(|n| n.fix_contact).unwrap_or(false),
        sdp_name: config.media.as_ref()
            .and_then(|m| m.sdp_name.clone())
            .unwrap_or_else(|| product_name.to_string()),
        call_event_receivers: Arc::new(DashMap::new()),
        reliable_provisionals: Arc::new(DashMap::new()),
        is_draining: drain.clone(),
        rf_charger,
        rf_sessions: Arc::new(DashMap::new()),
    });

    // Hand the freshly-constructed manager handles to the drain coordinator
    // so the server's drain loop can poll active counts on shutdown.
    let _ = drain.transaction_manager.set(Arc::clone(&state.transaction_manager));
    let _ = drain.call_actors.set(Arc::clone(&state.call_actors));

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
                        sweep_stale_entries(&state);
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
                tokio::task::spawn_blocking(move || {
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
                .await
                .ok();
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
                tokio::task::spawn_blocking(move || {
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
                .await
                .ok();
            }
        });
    }

    // Spawn background task: incoming Diameter requests (RTR from HSS, etc.)
    {
        let mut diameter_rx = diameter_incoming_rx;
        let state_for_diameter = Arc::clone(&state);
        tokio::spawn(async move {
            while let Some((incoming, peer)) = diameter_rx.recv().await {
                let engine_state = state_for_diameter.engine.state();
                match incoming.command_code {
                    crate::diameter::dictionary::CMD_REGISTRATION_TERMINATION => {
                        if engine_state
                            .handlers_for(&HandlerKind::DiameterOnRtr)
                            .is_empty()
                        {
                            // No handler registered — still send RTA to be protocol-correct
                            let config = peer.config();
                            let rta = crate::diameter::cx::build_rta(
                                &config.origin_host,
                                &config.origin_realm,
                                &incoming.avps.get("Session-Id")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or(""),
                                incoming.hop_by_hop,
                                incoming.end_to_end,
                            );
                            if let Err(error) = peer.send_response(rta).await {
                                tracing::warn!(%error, "failed to send RTA (no handler)");
                            }
                            continue;
                        }

                        let parsed = crate::diameter::cx::parse_rtr(&incoming);
                        let state_ref = Arc::clone(&state_for_diameter);
                        let peer_for_rta = Arc::clone(&peer);

                        tokio::task::spawn_blocking(move || {
                            let engine_state = state_ref.engine.state();
                            let handlers = engine_state.handlers_for(&HandlerKind::DiameterOnRtr);

                            let (session_id, public_identity, reason_code, reason_info) =
                                match parsed {
                                    Some(rtr) => (
                                        rtr.session_id,
                                        rtr.public_identity,
                                        rtr.reason_code,
                                        rtr.reason_info,
                                    ),
                                    None => {
                                        tracing::warn!("failed to parse incoming RTR");
                                        return;
                                    }
                                };

                            pyo3::Python::attach(|python| {
                                let py_reason_info: pyo3::Py<pyo3::PyAny> = match &reason_info {
                                    Some(info) => info.as_str().into_pyobject(python)
                                        .map(|s| s.into_any().into())
                                        .unwrap_or_else(|_| python.None().into()),
                                    None => python.None().into(),
                                };

                                for handler in handlers {
                                    let callable = handler.callable.bind(python);
                                    let result = callable.call1((
                                        public_identity.as_str(),
                                        reason_code,
                                        py_reason_info.bind(python),
                                    ));
                                    match result {
                                        Ok(ret) => {
                                            if handler.is_async {
                                                if let Err(error) = run_coroutine(python, &ret) {
                                                    tracing::error!(
                                                        %error,
                                                        "async diameter.on_rtr handler error"
                                                    );
                                                }
                                            }
                                        }
                                        Err(error) => {
                                            tracing::error!(
                                                %error,
                                                "diameter.on_rtr handler failed"
                                            );
                                        }
                                    }
                                }
                            });

                            // Auto-send RTA after handler completes
                            let config = peer_for_rta.config();
                            let rta = crate::diameter::cx::build_rta(
                                &config.origin_host,
                                &config.origin_realm,
                                &session_id,
                                incoming.hop_by_hop,
                                incoming.end_to_end,
                            );
                            let runtime = tokio::runtime::Handle::current();
                            runtime.block_on(async {
                                if let Err(error) = peer_for_rta.send_response(rta).await {
                                    tracing::warn!(%error, "failed to send RTA");
                                }
                            });
                        })
                        .await
                        .ok();
                    }
                    crate::diameter::dictionary::CMD_RE_AUTH => {
                        // RAR from PCRF — policy change notification (TS 29.214 §4.4.6)
                        let parsed = crate::diameter::rx::parse_policy_change(&incoming);
                        let config = peer.config();

                        if engine_state
                            .handlers_for(&HandlerKind::DiameterOnRar)
                            .is_empty()
                        {
                            let raa = crate::diameter::rx::build_policy_change_answer(
                                &config.origin_host,
                                &config.origin_realm,
                                crate::diameter::dictionary::DIAMETER_SUCCESS,
                                incoming.hop_by_hop,
                                incoming.end_to_end,
                            );
                            if let Err(error) = peer.send_response(raa).await {
                                tracing::warn!(%error, "failed to send RAA (no handler)");
                            }
                            continue;
                        }

                        let state_ref = Arc::clone(&state_for_diameter);
                        let peer_for_raa = Arc::clone(&peer);

                        tokio::task::spawn_blocking(move || {
                            let engine_state = state_ref.engine.state();
                            let handlers = engine_state.handlers_for(&HandlerKind::DiameterOnRar);

                            pyo3::Python::attach(|python| {
                                let py_session_id: pyo3::Py<pyo3::PyAny> = match &parsed.session_id {
                                    Some(sid) => sid.as_str().into_pyobject(python)
                                        .map(|s| s.into_any().into())
                                        .unwrap_or_else(|_| python.None().into()),
                                    None => python.None().into(),
                                };
                                let py_abort_cause: pyo3::Py<pyo3::PyAny> = match parsed.abort_cause {
                                    Some(ac) => ac.into_pyobject(python)
                                        .map(|v| v.into_any().into())
                                        .unwrap_or_else(|_| python.None().into()),
                                    None => python.None().into(),
                                };
                                let py_actions = pyo3::types::PyList::new(
                                    python,
                                    parsed.specific_actions.iter().map(|a| *a),
                                ).unwrap_or_else(|_| pyo3::types::PyList::empty(python));

                                for handler in handlers {
                                    let callable = handler.callable.bind(python);
                                    let result = callable.call1((
                                        py_session_id.bind(python),
                                        py_abort_cause.bind(python),
                                        &py_actions,
                                    ));
                                    match result {
                                        Ok(ret) => {
                                            if handler.is_async {
                                                if let Err(error) = run_coroutine(python, &ret) {
                                                    tracing::error!(
                                                        %error,
                                                        "async diameter.on_rar handler error"
                                                    );
                                                }
                                            }
                                        }
                                        Err(error) => {
                                            tracing::error!(
                                                %error,
                                                "diameter.on_rar handler failed"
                                            );
                                        }
                                    }
                                }
                            });

                            // Auto-send RAA after handler completes
                            let config = peer_for_raa.config();
                            let raa = crate::diameter::rx::build_policy_change_answer(
                                &config.origin_host,
                                &config.origin_realm,
                                crate::diameter::dictionary::DIAMETER_SUCCESS,
                                incoming.hop_by_hop,
                                incoming.end_to_end,
                            );
                            let runtime = tokio::runtime::Handle::current();
                            runtime.block_on(async {
                                if let Err(error) = peer_for_raa.send_response(raa).await {
                                    tracing::warn!(%error, "failed to send RAA");
                                }
                            });
                        })
                        .await
                        .ok();
                    }
                    crate::diameter::dictionary::CMD_ABORT_SESSION => {
                        // ASR from PCRF — forced session teardown (TS 29.214 §4.4.7)
                        let parsed = crate::diameter::rx::parse_session_abort(&incoming);
                        let config = peer.config();

                        if engine_state
                            .handlers_for(&HandlerKind::DiameterOnAsr)
                            .is_empty()
                        {
                            let asa = crate::diameter::rx::build_session_abort_answer(
                                &config.origin_host,
                                &config.origin_realm,
                                crate::diameter::dictionary::DIAMETER_SUCCESS,
                                incoming.hop_by_hop,
                                incoming.end_to_end,
                            );
                            if let Err(error) = peer.send_response(asa).await {
                                tracing::warn!(%error, "failed to send ASA (no handler)");
                            }
                            continue;
                        }

                        let state_ref = Arc::clone(&state_for_diameter);
                        let peer_for_asa = Arc::clone(&peer);

                        tokio::task::spawn_blocking(move || {
                            let engine_state = state_ref.engine.state();
                            let handlers = engine_state.handlers_for(&HandlerKind::DiameterOnAsr);

                            pyo3::Python::attach(|python| {
                                let py_session_id: pyo3::Py<pyo3::PyAny> = match &parsed.session_id {
                                    Some(sid) => sid.as_str().into_pyobject(python)
                                        .map(|s| s.into_any().into())
                                        .unwrap_or_else(|_| python.None().into()),
                                    None => python.None().into(),
                                };
                                let py_abort_cause: pyo3::Py<pyo3::PyAny> = match parsed.abort_cause {
                                    Some(ac) => ac.into_pyobject(python)
                                        .map(|v| v.into_any().into())
                                        .unwrap_or_else(|_| python.None().into()),
                                    None => python.None().into(),
                                };
                                let py_origin_host: pyo3::Py<pyo3::PyAny> = match &parsed.origin_host {
                                    Some(host) => host.as_str().into_pyobject(python)
                                        .map(|s| s.into_any().into())
                                        .unwrap_or_else(|_| python.None().into()),
                                    None => python.None().into(),
                                };

                                for handler in handlers {
                                    let callable = handler.callable.bind(python);
                                    let result = callable.call1((
                                        py_session_id.bind(python),
                                        py_abort_cause.bind(python),
                                        py_origin_host.bind(python),
                                    ));
                                    match result {
                                        Ok(ret) => {
                                            if handler.is_async {
                                                if let Err(error) = run_coroutine(python, &ret) {
                                                    tracing::error!(
                                                        %error,
                                                        "async diameter.on_asr handler error"
                                                    );
                                                }
                                            }
                                        }
                                        Err(error) => {
                                            tracing::error!(
                                                %error,
                                                "diameter.on_asr handler failed"
                                            );
                                        }
                                    }
                                }
                            });

                            // Auto-send ASA after handler completes
                            let config = peer_for_asa.config();
                            let asa = crate::diameter::rx::build_session_abort_answer(
                                &config.origin_host,
                                &config.origin_realm,
                                crate::diameter::dictionary::DIAMETER_SUCCESS,
                                incoming.hop_by_hop,
                                incoming.end_to_end,
                            );
                            let runtime = tokio::runtime::Handle::current();
                            runtime.block_on(async {
                                if let Err(error) = peer_for_asa.send_response(asa).await {
                                    tracing::warn!(%error, "failed to send ASA");
                                }
                            });
                        })
                        .await
                        .ok();
                    }
                    crate::diameter::dictionary::CMD_SH_PUSH_NOTIFICATION => {
                        // PNR from HSS — Sh push notification (TS 29.328 §6.1.7)
                        let parsed = crate::diameter::sh::parse_push_notification(&incoming);
                        let config = peer.config();

                        if engine_state
                            .handlers_for(&HandlerKind::DiameterOnPnr)
                            .is_empty()
                        {
                            let session_id = incoming
                                .avps
                                .get("Session-Id")
                                .and_then(|v| v.as_str())
                                .unwrap_or("");
                            let pna = crate::diameter::sh::build_push_notification_answer(
                                &config.origin_host,
                                &config.origin_realm,
                                session_id,
                                crate::diameter::dictionary::DIAMETER_SUCCESS,
                                incoming.hop_by_hop,
                                incoming.end_to_end,
                            );
                            if let Err(error) = peer.send_response(pna).await {
                                tracing::warn!(%error, "failed to send PNA (no handler)");
                            }
                            continue;
                        }

                        let state_ref = Arc::clone(&state_for_diameter);
                        let peer_for_pna = Arc::clone(&peer);

                        tokio::task::spawn_blocking(move || {
                            let engine_state = state_ref.engine.state();
                            let handlers = engine_state.handlers_for(&HandlerKind::DiameterOnPnr);

                            let (session_id, public_identity, user_data_xml) = match parsed {
                                Some(pnr) => {
                                    (pnr.session_id, pnr.public_identity, pnr.user_data_xml)
                                }
                                None => {
                                    tracing::warn!("failed to parse incoming Sh PNR");
                                    return;
                                }
                            };

                            pyo3::Python::attach(|python| {
                                let py_user_data: pyo3::Py<pyo3::PyAny> = match &user_data_xml {
                                    Some(xml) => xml
                                        .as_str()
                                        .into_pyobject(python)
                                        .map(|s| s.into_any().into())
                                        .unwrap_or_else(|_| python.None().into()),
                                    None => python.None().into(),
                                };

                                for handler in handlers {
                                    let callable = handler.callable.bind(python);
                                    let result = callable.call1((
                                        public_identity.as_str(),
                                        py_user_data.bind(python),
                                    ));
                                    match result {
                                        Ok(ret) => {
                                            if handler.is_async {
                                                if let Err(error) = run_coroutine(python, &ret) {
                                                    tracing::error!(
                                                        %error,
                                                        "async diameter.on_pnr handler error"
                                                    );
                                                }
                                            }
                                        }
                                        Err(error) => {
                                            tracing::error!(
                                                %error,
                                                "diameter.on_pnr handler failed"
                                            );
                                        }
                                    }
                                }
                            });

                            let config = peer_for_pna.config();
                            let pna = crate::diameter::sh::build_push_notification_answer(
                                &config.origin_host,
                                &config.origin_realm,
                                &session_id,
                                crate::diameter::dictionary::DIAMETER_SUCCESS,
                                incoming.hop_by_hop,
                                incoming.end_to_end,
                            );
                            let runtime = tokio::runtime::Handle::current();
                            runtime.block_on(async {
                                if let Err(error) = peer_for_pna.send_response(pna).await {
                                    tracing::warn!(%error, "failed to send PNA");
                                }
                            });
                        })
                        .await
                        .ok();
                    }
                    crate::diameter::dictionary::CMD_ALERT_SERVICE_CENTRE => {
                        // S6c ALR from HSS — UE is now reachable; drain pending MT-SMS.
                        let parsed = crate::diameter::s6c::parse_alr(&incoming);
                        let config = peer.config();

                        if engine_state
                            .handlers_for(&HandlerKind::DiameterOnAlr)
                            .is_empty()
                        {
                            let session_id = incoming
                                .avps
                                .get("Session-Id")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let ala = crate::diameter::s6c::build_ala_success(
                                &config.origin_host,
                                &config.origin_realm,
                                &session_id,
                                incoming.hop_by_hop,
                                incoming.end_to_end,
                            );
                            if let Err(error) = peer.send_response(ala).await {
                                tracing::warn!(%error, "failed to send ALA (no handler)");
                            }
                            continue;
                        }

                        let state_ref = Arc::clone(&state_for_diameter);
                        let peer_for_ala = Arc::clone(&peer);

                        tokio::task::spawn_blocking(move || {
                            let engine_state = state_ref.engine.state();
                            let handlers = engine_state.handlers_for(&HandlerKind::DiameterOnAlr);

                            let (session_id, public_identity, msisdn) = match parsed {
                                Some(alr) => (
                                    alr.session_id,
                                    alr.user_name.unwrap_or_default(),
                                    alr.msisdn.unwrap_or_default(),
                                ),
                                None => {
                                    tracing::warn!("failed to parse incoming ALR");
                                    return;
                                }
                            };

                            pyo3::Python::attach(|python| {
                                for handler in handlers {
                                    let callable = handler.callable.bind(python);
                                    let result = callable.call1((
                                        public_identity.as_str(),
                                        msisdn.as_str(),
                                    ));
                                    match result {
                                        Ok(ret) => {
                                            if handler.is_async {
                                                if let Err(error) = run_coroutine(python, &ret) {
                                                    tracing::error!(
                                                        %error,
                                                        "async diameter.on_alr handler error"
                                                    );
                                                }
                                            }
                                        }
                                        Err(error) => {
                                            tracing::error!(
                                                %error,
                                                "diameter.on_alr handler failed"
                                            );
                                        }
                                    }
                                }
                            });

                            let config = peer_for_ala.config();
                            let ala = crate::diameter::s6c::build_ala_success(
                                &config.origin_host,
                                &config.origin_realm,
                                &session_id,
                                incoming.hop_by_hop,
                                incoming.end_to_end,
                            );
                            let runtime = tokio::runtime::Handle::current();
                            runtime.block_on(async {
                                if let Err(error) = peer_for_ala.send_response(ala).await {
                                    tracing::warn!(%error, "failed to send ALA");
                                }
                            });
                        })
                        .await
                        .ok();
                    }
                    crate::diameter::dictionary::CMD_MO_FORWARD_SHORT_MESSAGE => {
                        // SGd OFR from MME — UE-originated SMS into the SMSC.
                        let parsed = crate::diameter::sgd::parse_ofr(&incoming);
                        let config = peer.config();

                        if engine_state
                            .handlers_for(&HandlerKind::DiameterOnOfr)
                            .is_empty()
                        {
                            let session_id = incoming
                                .avps
                                .get("Session-Id")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let ofa = crate::diameter::sgd::build_ofa_success(
                                &config.origin_host,
                                &config.origin_realm,
                                &session_id,
                                incoming.hop_by_hop,
                                incoming.end_to_end,
                            );
                            if let Err(error) = peer.send_response(ofa).await {
                                tracing::warn!(%error, "failed to send OFA (no handler)");
                            }
                            continue;
                        }

                        let state_ref = Arc::clone(&state_for_diameter);
                        let peer_for_ofa = Arc::clone(&peer);

                        tokio::task::spawn_blocking(move || {
                            let engine_state = state_ref.engine.state();
                            let handlers = engine_state.handlers_for(&HandlerKind::DiameterOnOfr);

                            let (session_id, user_name, sc_address, sm_rp_ui) = match parsed {
                                Some(ofr) => (
                                    ofr.session_id,
                                    ofr.user_name.unwrap_or_default(),
                                    ofr.sc_address.unwrap_or_default(),
                                    ofr.sm_rp_ui.unwrap_or_default(),
                                ),
                                None => {
                                    tracing::warn!("failed to parse incoming OFR");
                                    return;
                                }
                            };

                            pyo3::Python::attach(|python| {
                                let py_pdu: pyo3::Py<pyo3::PyAny> =
                                    pyo3::types::PyBytes::new(python, &sm_rp_ui)
                                        .into_any()
                                        .unbind();
                                for handler in handlers {
                                    let callable = handler.callable.bind(python);
                                    let result = callable.call1((
                                        user_name.as_str(),
                                        sc_address.as_str(),
                                        py_pdu.bind(python),
                                    ));
                                    match result {
                                        Ok(ret) => {
                                            if handler.is_async {
                                                if let Err(error) = run_coroutine(python, &ret) {
                                                    tracing::error!(
                                                        %error,
                                                        "async diameter.on_ofr handler error"
                                                    );
                                                }
                                            }
                                        }
                                        Err(error) => {
                                            tracing::error!(
                                                %error,
                                                "diameter.on_ofr handler failed"
                                            );
                                        }
                                    }
                                }
                            });

                            let config = peer_for_ofa.config();
                            let ofa = crate::diameter::sgd::build_ofa_success(
                                &config.origin_host,
                                &config.origin_realm,
                                &session_id,
                                incoming.hop_by_hop,
                                incoming.end_to_end,
                            );
                            let runtime = tokio::runtime::Handle::current();
                            runtime.block_on(async {
                                if let Err(error) = peer_for_ofa.send_response(ofa).await {
                                    tracing::warn!(%error, "failed to send OFA");
                                }
                            });
                        })
                        .await
                        .ok();
                    }
                    _ => {
                        // Generic @diameter.on_command(...) fallback. Lets
                        // scripts/addons handle apps that aren't covered by
                        // the typed match arms above (cx/sh/rx/s6c/sgd today,
                        // anything else tomorrow) without per-command
                        // dispatcher edits.
                        let kind = match crate::script::api::diameter::custom_handler_kind(
                            incoming.application_id,
                            incoming.command_code,
                        ) {
                            Some(k) => k,
                            None => {
                                tracing::debug!(
                                    command_code = incoming.command_code,
                                    application_id = incoming.application_id,
                                    "unhandled incoming Diameter request (unknown app/cmd)"
                                );
                                continue;
                            }
                        };
                        let custom_handlers = engine_state.handlers_for_custom(&kind);
                        if custom_handlers.is_empty() {
                            tracing::debug!(
                                command_code = incoming.command_code,
                                application_id = incoming.application_id,
                                kind = %kind,
                                "no @on_command handler registered for incoming request"
                            );
                            continue;
                        }
                        // Snapshot the bits the spawn_blocking task needs.
                        let session_id = incoming
                            .avps
                            .get("Session-Id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let avps_json = incoming.avps.clone();
                        let app_id = incoming.application_id;
                        let cmd_code = incoming.command_code;
                        let hbh = incoming.hop_by_hop;
                        let e2e = incoming.end_to_end;
                        let state_ref = Arc::clone(&state_for_diameter);
                        let peer_for_answer = Arc::clone(&peer);
                        let kind_clone = kind.clone();

                        tokio::task::spawn_blocking(move || {
                            let engine_state = state_ref.engine.state();
                            let handlers = engine_state.handlers_for_custom(&kind_clone);

                            pyo3::Python::attach(|python| {
                                // Build the kwargs dict from the parsed AVPs.
                                let kwargs = match crate::script::api::diameter::avps_json_to_pydict(
                                    python,
                                    &avps_json,
                                ) {
                                    Ok(dict) => dict,
                                    Err(error) => {
                                        tracing::warn!(
                                            %error,
                                            "failed to convert AVPs to kwargs for on_command"
                                        );
                                        return;
                                    }
                                };
                                for handler in handlers {
                                    let callable = handler.callable.bind(python);
                                    let args = pyo3::types::PyTuple::empty(python);
                                    let result = callable.call(&args, Some(&kwargs));
                                    match result {
                                        Ok(ret) => {
                                            if handler.is_async {
                                                if let Err(error) = run_coroutine(python, &ret) {
                                                    tracing::error!(
                                                        %error,
                                                        kind = %kind_clone,
                                                        "async @diameter.on_command handler error"
                                                    );
                                                }
                                            }
                                        }
                                        Err(error) => {
                                            tracing::error!(
                                                %error,
                                                kind = %kind_clone,
                                                "@diameter.on_command handler failed"
                                            );
                                        }
                                    }
                                }
                            });

                            // Auto-send a generic 2001-success answer.
                            let config = peer_for_answer.config();
                            let answer = crate::diameter::codec::encode_generic_answer(
                                &config.origin_host,
                                &config.origin_realm,
                                &session_id,
                                cmd_code,
                                app_id,
                                crate::diameter::dictionary::DIAMETER_SUCCESS,
                                hbh,
                                e2e,
                            );
                            let runtime = tokio::runtime::Handle::current();
                            runtime.block_on(async {
                                if let Err(error) = peer_for_answer.send_response(answer).await {
                                    tracing::warn!(
                                        %error,
                                        kind = %kind_clone,
                                        "failed to send generic answer"
                                    );
                                }
                            });
                        })
                        .await
                        .ok();
                    }
                }
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
                        tokio::task::spawn_blocking(move || {
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
                        .await
                        .ok();
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
        // (on_request and on_reply), so use spawn_blocking for both
        // to avoid starving the tokio worker pool with GIL contention.
        tokio::task::spawn_blocking(move || {
            handle_inbound(inbound, &state);
        });
    }

    info!("dispatcher shutting down (inbound channel closed)");
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
        let event = match entry.name {
            // Server transaction timers
            TimerName::J => Some(ServerEvent::Nist(NistEvent::TimerJ)),
            TimerName::G => Some(ServerEvent::Ist(IstEvent::TimerG)),
            TimerName::H => Some(ServerEvent::Ist(IstEvent::TimerH)),
            TimerName::I => Some(ServerEvent::Ist(IstEvent::TimerI)),
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

/// Sweep stale proxy sessions.
fn sweep_stale_entries(state: &DispatcherState) {
    let ttl = state.transaction_timeout;
    let expired_sessions = state.session_store.sweep_stale(ttl) as u64;

    if expired_sessions > 0 {
        info!(
            expired_sessions,
            sessions = state.session_store.session_count(),
            transactions = state.transaction_manager.count(),
            "stale entry cleanup"
        );
    }
}

/// Handle a single inbound SIP message (request or response).
fn handle_inbound(inbound: InboundMessage, state: &Arc<DispatcherState>) {
    // RFC 5626 §3.5.1 / §4.4.1: CRLF keep-alive (check raw bytes before parsing).
    // Real SIP messages start with an uppercase ASCII letter (a method like
    // "INVITE…" or the response start "SIP/2.0…"). Only do the all-bytes
    // whitespace scan when the first byte LOOKS like a keepalive — at 30k+
    // cps a per-message full-buffer scan was a measurable hot path.
    if matches!(inbound.data.first(), Some(b'\r' | b'\n' | b' ')) {
        let all_whitespace = inbound.data.iter()
            .all(|b| matches!(b, b'\r' | b'\n' | b' '));
        if all_whitespace {
            // Record pong for CRLF keepalive tracker (TCP/TLS only).
            if matches!(inbound.transport, Transport::Tcp | Transport::Tls) {
                if let Some(ref tracker) = state.crlf_pong_tracker {
                    tracker.record_pong(inbound.connection_id);
                }
            }
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
            inbound.local_addr,
            inbound.transport,
            &inbound.data,
        );
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
                debug!("ACK has no matching IST or session — passing through");
            }
            Err(error) => {
                debug!("failed to match ACK to transaction: {error}");
            }
        }
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
        }
        RequestAction::Reply { code, reason, reliable } => {
            let mut response = build_response(&message_guard, *code, reason, state.server_header.as_deref(), &reply_headers);

            // Script-provided reply body — PIDF-LO, XCAP/Ut, custom failure body, etc.
            if let Some((body_bytes, content_type)) = &reply_body {
                response.headers.set("Content-Type", content_type.clone());
                response.headers.set("Content-Length", body_bytes.len().to_string());
                response.body = body_bytes.clone();
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
        RequestAction::Relay { next_hop, flow } => {
            // RFC 3261 §16.2: a stateful proxy SHOULD send 100 Trying
            // immediately upon receiving an INVITE to stop UAC retransmissions.
            if method == "INVITE" {
                let trying = build_response(&message_guard, 100, "Trying", state.server_header.as_deref(), &[]);
                send_message_from(trying, inbound.transport, inbound.remote_addr, inbound.connection_id, Some(inbound.local_addr), state);
            }
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
            );
        }
        RequestAction::Fork { targets, strategy } => {
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
                relay_fork_request(
                    &message_guard,
                    targets,
                    fork_strategy,
                    record_routed,
                    &inbound,
                    server_key.as_ref(),
                    state,
                );
            }
        }
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
#[allow(clippy::too_many_arguments)]
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
                    warn!(target = %target_uri_string, "cannot resolve relay target");
                    let response = build_response(message, 502, "Bad Gateway", state.server_header.as_deref(), &[]);
                    send_message_from(response, inbound.transport, inbound.remote_addr, inbound.connection_id, Some(inbound.local_addr), state);
                    return;
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
    // via_host / listener (3GPP TS 33.203 §6.3 / §7.4).
    //
    // Applies to both UDP (ESP-over-UDP, the common case) and TCP
    // (ESP-over-TCP, TS 33.203 §7.2 — used by some iOS clients).  For
    // TCP this also drives `pool.send_tcp_from(source, ...)` so the
    // outbound socket binds to the SA's source endpoint instead of
    // ephemeral; an ephemerally-bound socket would never match the
    // kernel selector for SA #3.  Returns `None` for non-IPsec
    // deployments and ordinary destinations — zero impact on the hot
    // path when no IpsecManager is wired.  Computed once here and
    // reused for Via construction and the outbound send.
    let ipsec_source = match outbound_transport {
        Transport::Udp | Transport::Tcp => {
            crate::script::api::ipsec::outbound_local_addr_for(destination)
        }
        _ => None,
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
            let rr_uri = format!("sip:{}:{};transport={}", internal_host, state.local_addr.port(), transport_str.to_lowercase());
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
                state.session_store.insert(session);
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
        };
        send_to_target(data, &target, inbound.transport, inbound.connection_id, state)
    };
    if connection_id != placeholder_connection_id {
        if let (Some(srv_key), Some(client_key)) = (server_key, client_key_opt.as_ref()) {
            if let Some(session_arc) = state.session_store.get_by_server_key(srv_key) {
                if let Ok(mut session) = session_arc.write() {
                    session.set_client_branch(client_key.clone(), ClientBranch {
                        destination,
                        transport: outbound_transport,
                        connection_id,
                    });
                }
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
    strategy: crate::proxy::fork::ForkStrategy,
    record_routed: bool,
    inbound: &InboundMessage,
    server_key: Option<&TransactionKey>,
    state: &DispatcherState,
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
            // Fall back to single-target relay if no server transaction
            relay_request(message, targets.first().map(|s| s.as_str()), record_routed, inbound, None, state, None, None, None, None, None);
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
            state,
        );
    }
}

/// Relay a single branch of a forked request.
///
/// Resolves the target, adds Via, sends the request, creates a client transaction,
/// and registers the branch in the ProxySession.
#[allow(clippy::too_many_arguments)]
fn relay_fork_branch(
    message: &SipMessage,
    target: &str,
    branch_index: usize,
    record_routed: bool,
    inbound: &InboundMessage,
    server_key: &TransactionKey,
    session_arc: &Arc<RwLock<ProxySession>>,
    aggregator: &Arc<std::sync::Mutex<crate::proxy::fork::ForkAggregator>>,
    state: &DispatcherState,
) {
    // Resolve target
    let relay_target = match resolve_target(target, &state.dns_resolver) {
        Some(t) => t,
        None => {
            warn!(target = %target, branch = branch_index, "fork: cannot resolve target");
            return;
        }
    };
    let destination = relay_target.address;
    let outbound_transport = relay_target.transport.unwrap_or(inbound.transport);

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

    let transport_str = format!("{}", outbound_transport);
    let branch = core::add_via(
        &mut relayed.headers,
        &transport_str,
        &state.via_host(&outbound_transport),
        Some(state.via_port(&outbound_transport)),
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
            let rr_uri = format!("sip:{}:{};transport={}", internal_host, state.local_addr.port(), transport_str.to_lowercase());
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

    // Send via pool for TCP/TLS, direct channel for UDP
    let connection_id = send_to_target(data, &relay_target, inbound.transport, inbound.connection_id, state);

    debug!(
        branch = %branch,
        target = %target,
        branch_index = branch_index,
        destination = %destination,
        transport = %outbound_transport,
        "fork: sent branch"
    );

    // For TCP/TLS the actual connection_id may differ from the placeholder
    // — patch the session's ClientBranch so retransmits/CANCEL hit the right
    // connection.
    if connection_id != placeholder_connection_id {
        if let Some(client_key) = client_key_opt.as_ref() {
            state.session_store.update_branch_connection_id(client_key, connection_id);
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
                                };
                                send_to_target(data, &target, transport, ConnectionId::default(), state);
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
    if status_code == 100 {
        debug!("absorbing 100 Trying from downstream");
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
        handle_b2bua_response(&call_id, &branch, &mut message, status_code, state);
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
                        let outbound_port = state.listen_addrs.get(&zombie.transport)
                            .map(|a| a.port())
                            .unwrap_or(state.local_addr.port());
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
                        send_b2bua_to_bleg(ack, zombie.transport, zombie.destination, state);
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
                                // RFC 3261 §17.1.1.3: send ACK for non-2xx back toward the UAS
                                send_message(
                                    ack_message.clone(),
                                    inbound.transport,
                                    inbound.remote_addr,
                                    inbound.connection_id,
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
            let (source_addr, inbound_local_addr, connection_id, transport, server_key, fork_agg, branch_index, original_request, relay_on_reply, relay_on_failure, client_branch) = {
                let session = match session_arc.read() {
                    Ok(s) => s,
                    Err(error) => {
                        error!("proxy session lock poisoned: {error}");
                        return;
                    }
                };
                (
                    session.source_addr,
                    session.inbound_local_addr,
                    session.connection_id,
                    session.transport,
                    session.server_key.clone(),
                    session.fork_aggregator.clone(),
                    session.branch_index_map.get(client_key).copied(),
                    session.original_request.clone(),
                    session.on_reply_callback.clone(),
                    session.on_failure_callback.clone(),
                    session.client_branches.get(client_key).cloned(),
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
                            &RelayTarget { address: cb.destination, transport: Some(cb.transport) },
                            cb.transport,
                            cb.connection_id,
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

            // Strip our topmost Via before forwarding
            core::strip_top_via(&mut message.headers);

            // Run Python reply handlers
            let (updated_message, should_forward) = run_reply_handlers(
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
                let (updated_msg, cb_forward): (Option<SipMessage>, bool) = Python::attach(|python| {
                    let py_reply_obj = PyReply::new(Arc::clone(&msg_arc));
                    let py_reply = match Py::new(python, py_reply_obj) {
                        Ok(obj) => obj,
                        Err(error) => {
                            error!("failed to create PyReply for relay callback: {error}");
                            return (None, true);
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
                                return (None, true);
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

                    let forwarded = py_reply.borrow(python).was_forwarded();
                    (None, forwarded)
                });
                let _ = updated_msg; // unused — message stays in msg_arc
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
/// Returns `(message, forwarded)` — if `forwarded` is false, the script
/// chose to drop the response (no `relay()` called).
///
/// `response_source` is the observed source address of the entity that sent
/// this response (for `reply.fix_nated_contact()`).
#[allow(clippy::too_many_arguments)]
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
) -> (SipMessage, bool) {
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
        return (message, true);
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

    let forwarded = Python::attach(|python| {
        let py_reply = match Py::new(python, reply) {
            Ok(obj) => obj,
            Err(error) => {
                error!("failed to create PyReply: {error}");
                return true; // forward on error
            }
        };
        let py_request = match Py::new(python, py_request_obj) {
            Ok(obj) => obj,
            Err(error) => {
                error!("failed to create PyRequest for reply handler: {error}");
                return true;
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
                            return true;
                        }
                    }
                }
                Err(error) => {
                    error!("Python reply handler error: {error}");
                    return true; // forward on error to avoid silent drops
                }
            }
        }

        let result = py_reply.borrow(python).was_forwarded();
        result
    });

    if !forwarded {
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

    (extracted, forwarded)
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
}

fn resolve_target(uri_string: &str, resolver: &SipResolver) -> Option<RelayTarget> {
    // Try as bare IP:port first (cheapest check)
    if let Ok(addr) = uri_string.parse::<SocketAddr>() {
        return Some(RelayTarget { address: addr, transport: None });
    }

    // Try parsing as a full SIP URI
    if let Ok(uri) = parse_uri_standalone(uri_string) {
        // Extract transport hint from URI params (e.g. ;transport=tcp)
        let transport_hint = uri.get_param("transport").map(|s| s.to_string());

        let results = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(resolver.resolve(
                &uri.host,
                uri.port,
                &uri.scheme,
                transport_hint.as_deref(),
            ))
        });

        return results.into_iter().next().map(|r| {
            let transport = r.transport.as_deref()
                .or(transport_hint.as_deref())
                .and_then(|t| match t.to_lowercase().as_str() {
                    "tcp" => Some(Transport::Tcp),
                    "tls" => Some(Transport::Tls),
                    "udp" => Some(Transport::Udp),
                    "ws" => Some(Transport::WebSocket),
                    "wss" => Some(Transport::WebSocketSecure),
                    _ => None,
                });
            RelayTarget { address: r.address, transport }
        });
    }

    None
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
    state: &DispatcherState,
) -> ConnectionId {
    let transport = target.transport.unwrap_or(fallback_transport);
    let destination = target.address;

    // HEP capture — outbound (sent to network)
    if let Some(ref hep) = state.hep_sender {
        let local = state.listen_addrs.get(&transport).copied().unwrap_or(state.local_addr);
        hep.capture_outbound(local, destination, transport, &data);
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
            let ipsec_source = crate::script::api::ipsec::outbound_local_addr_for(destination);
            let connect_result = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    match ipsec_source {
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
            // TLS connection reuse: find an existing inbound TLS connection
            // to the destination (like OpenSIPS connection reuse).
            // First try exact SocketAddr match, then fall back to IP-only match
            // (handles NAT where Contact URI port differs from source port).
            let connection_id = state.tls_addr_map.get(&destination).map(|r| *r.value())
                .or_else(|| {
                    // IP-only fallback: find any TLS connection from the same IP
                    let target_ip = destination.ip();
                    state.tls_addr_map.iter()
                        .find(|entry| entry.key().ip() == target_ip)
                        .map(|entry| *entry.value())
                });

            if let Some(connection_id) = connection_id {
                let outbound_message = OutboundMessage {
                    connection_id,
                    transport: Transport::Tls,
                    destination,
                    data,
                    source_local_addr: None,
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
                match tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current()
                        .block_on(pool.send_tls(destination, data_clone))
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
            let source_local_addr =
                crate::script::api::ipsec::outbound_local_addr_for(destination);
            let outbound_message = OutboundMessage {
                connection_id: fallback_connection_id,
                transport,
                destination,
                data,
                source_local_addr,
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
/// Initialize the RTPEngine client set and media session store.
///
/// Returns `(None, None)` when `media.rtpengine` is not configured.
/// Also registers the Python `siphon.rtpengine` singleton for script use.
pub fn init_rtpengine(
    config: &Config,
) -> (
    Option<Arc<crate::rtpengine::client::RtpEngineSet>>,
    Option<Arc<crate::rtpengine::session::MediaSessionStore>>,
    Option<Arc<crate::rtpengine::ProfileRegistry>>,
) {
    let media_config = match &config.media {
        Some(c) => c,
        None => return (None, None, None),
    };

    let instances_config = media_config.rtpengine.instances();
    let mut instance_tuples = Vec::new();

    for instance in &instances_config {
        match instance.address.parse::<std::net::SocketAddr>() {
            Ok(address) => {
                instance_tuples.push((address, instance.timeout_ms, instance.weight));
            }
            Err(parse_error) => {
                error!(
                    address = %instance.address,
                    error = %parse_error,
                    "invalid RTPEngine address, skipping"
                );
            }
        }
    }

    if instance_tuples.is_empty() {
        return (None, None, None);
    }

    let handle = tokio::runtime::Handle::current();
    match tokio::task::block_in_place(|| {
        handle.block_on(crate::rtpengine::client::RtpEngineSet::new(instance_tuples))
    }) {
        Ok(rtpengine_set) => {
            let rtpengine_set = Arc::new(rtpengine_set);
            let sessions = Arc::new(crate::rtpengine::session::MediaSessionStore::new());

            // Build profile registry from built-in defaults + custom YAML profiles
            let registry = Arc::new(
                crate::rtpengine::ProfileRegistry::from_config(&media_config.profiles),
            );

            // Create the Python-side singleton (shares the same Arcs)
            let py_rtpengine = crate::script::api::rtpengine::PyRtpEngine::new(
                Arc::clone(&rtpengine_set),
                Arc::clone(&sessions),
                Arc::clone(&registry),
            );

            Python::attach(|python| {
                if let Err(error) =
                    crate::script::api::set_rtpengine_singleton(python, py_rtpengine)
                {
                    error!("failed to store RTPEngine singleton: {error}");
                } else {
                    let count = instances_config.len();
                    info!(
                        instances = count,
                        "RTPEngine client registered ({count} instance{})",
                        if count == 1 { "" } else { "s" }
                    );
                }
            });

            (Some(rtpengine_set), Some(sessions), Some(registry))
        }
        Err(rtpengine_error) => {
            error!(error = %rtpengine_error, "failed to initialize RTPEngine client");
            (None, None, None)
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
    rtpengine_set: Arc<crate::rtpengine::client::RtpEngineSet>,
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

/// Sanitize a B2BUA response before forwarding it to the A-leg.
///
/// A proper B2BUA terminates and regenerates the dialog, so B-leg-specific
/// headers must not leak to the A-leg. This function:
/// - Replaces Contact with siphon's own address (critical for dialog routing)
/// - Strips User-Agent (UAC header — not for responses), sets Server
/// - Removes Allow, Allow-Events, Supported, Require
/// - Strips B-leg-specific P-Asserted-Identity, P-Charging-Vector
fn sanitize_b2bua_response(
    response: &mut SipMessage,
    state: &DispatcherState,
    a_leg_transport: Transport,
) {
    // Contact: must point to siphon so in-dialog requests (ACK, BYE, re-INVITE)
    // route through us, not directly to the B-leg.
    // via_host()/via_port() apply advertised_address fallback and substitute the
    // sanitized local_addr when bound to 0.0.0.0/[::] — never leak unspecified.
    let contact_value = format!(
        "<sip:{}:{};transport={}>",
        state.via_host(&a_leg_transport),
        state.via_port(&a_leg_transport),
        a_leg_transport.to_string().to_lowercase(),
    );
    response.headers.set("Contact", contact_value);

    // Remove User-Agent — responses use Server, not User-Agent (RFC 3261 §20.35/§20.41).
    // Leaving it would leak B-leg topology to the A-leg.
    response.headers.remove("User-Agent");
    response.headers.remove("Server");
    if let Some(ref srv) = state.server_header {
        response.headers.set("Server", srv.clone());
    }

    // P-Asserted-Identity, P-Charging-Vector, P-Charging-Function-Addresses:
    // Per RFC 3325 / RFC 3455, these are trust-domain headers that B2BUAs
    // within the trust domain SHOULD forward. Keep them.

    // Record-Route from the B-leg path must never leak to the A-leg.
    // Each leg has its own independent dialog and route set (RFC 3261 §16).
    response.headers.remove("Record-Route");

    // Strip B-leg capability headers — siphon terminates the dialog.
    // These reveal the remote endpoint's feature set and break topology hiding.
    response.headers.remove("Allow");
    response.headers.remove("Allow-Events");
    response.headers.remove("Supported");
    response.headers.remove("Content-Disposition");
    // Strip RFC 3262 100rel state from forwarded responses: in "auto-PRACK"
    // mode the B2BUA terminates the reliable provisional locally on the
    // B-leg side (sending its own PRACK) and presents an ordinary 1xx to
    // the A-leg. Without this the A-leg would see a Require: 100rel and
    // think it has to PRACK back — but the dialog identifiers it would use
    // belong to the A-leg dialog, not B-leg, so the PRACK could never reach
    // the originating UAS.
    response.headers.remove("Require");
    response.headers.remove("RSeq");

    // Sanitize SDP: mask B-leg identity in o= and s= lines, and rewrite
    // the o= address to our advertised address for topology hiding.
    let sdp_addr = state.via_host(&a_leg_transport);
    sanitize_sdp_identity(&mut response.body, &state.sdp_name, Some(&sdp_addr));

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
                        let trimmed = after_username.trim_end_matches(|c| c == '\r' || c == '\n');
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
                result.push_str("\n");
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
        let trimmed = line.trim_end_matches(|c: char| c == '\r' || c == '\n');
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
    local_addr: SocketAddr,
) -> SipMessage {
    let request_uri = target_uri
        .and_then(|uri| parse_uri_standalone(uri).ok())
        .unwrap_or_else(|| SipUri::new("invalid".to_string()));

    let mut builder = SipMessageBuilder::new()
        .request(Method::Ack, request_uri);

    // Via: only our own hop with the client transaction branch
    let transport_str = format!("{}", downstream_transport).to_uppercase();
    let host = format_sip_host(&local_addr.ip().to_string());
    builder = builder.via(format!(
        "SIP/2.0/{} {}:{};branch={}",
        transport_str, host, local_addr.port(), branch
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
        hep.capture_outbound(local, destination, transport, &data);
    }

    let outbound_message = OutboundMessage {
        connection_id,
        transport,
        destination,
        data,
        source_local_addr,
    };

    if let Err(error) = state.outbound.send(outbound_message) {
        error!("failed to enqueue outbound message: {error}");
    }
}

/// Serialize a SIP message and send it to a specific destination.
fn send_message(
    message: SipMessage,
    transport: Transport,
    destination: SocketAddr,
    connection_id: ConnectionId,
    state: &DispatcherState,
) {
    send_message_from(message, transport, destination, connection_id, None, state);
}

/// Like [`send_message`] but pins the local egress address.  Used for
/// reply-direction sends (responses to inbound requests, server-
/// transaction retransmits) so the packet leaves on the same SA's
/// local endpoint that the request arrived on — required by 3GPP
/// TS 33.203 §7.4 for IPsec-protected REGISTER / MO INVITE cycles.
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
fn flush_deferred_sends(state: &DispatcherState) {
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
    let via = format!(
        "SIP/2.0/{} {}:{};branch={}",
        transport_str,
        state.via_host(&leg.transport.transport),
        state.via_port(&leg.transport.transport),
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
    let via = format!(
        "SIP/2.0/{} {}:{};branch={}",
        transport_str,
        state.via_host(&leg.transport.transport),
        state.via_port(&leg.transport.transport),
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
    };
    send_to_target(data, &target, transport, ConnectionId::default(), state);
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
    };
    let registrar = Arc::new(Registrar::new(registrar_config));
    let py_registrar = PyRegistrar::new(registrar);

    // Build PyAuth from config
    let mut realm_users = std::collections::HashMap::new();
    realm_users.insert(config.auth.realm.clone(), config.auth.users.clone());
    let mut py_auth = PyAuth::new(realm_users, config.auth.realm.clone());
    py_auth.set_backend_type(config.auth.backend.clone());

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
fn spawn_rf_b2bua_stop(
    state: &DispatcherState,
    internal_call_id: &str,
    bye: &SipMessage,
) {
    let charger = match state.rf_charger.as_ref() {
        Some(c) if c.auto_emit_b2bua() => Arc::clone(c),
        _ => return,
    };
    let key = rf_b2bua_key(internal_call_id);
    if !state.rf_sessions.contains_key(&key) {
        return;
    }

    let cause_code = bye
        .headers
        .get("Reason")
        .and_then(|r| {
            r.split(';')
                .filter_map(|p| p.trim().strip_prefix("cause="))
                .next()
                .and_then(|v| v.split_whitespace().next())
                .and_then(|v| v.parse::<u16>().ok())
        })
        .and_then(crate::diameter::rf::sip_status_to_cause_code);
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
    let session_arc = match state.session_store.get_by_server_key(server_key) {
        Some(arc) => arc,
        None => return,
    };
    let session = match session_arc.read() {
        Ok(s) => s,
        Err(_) => return,
    };

    for client_key in &session.client_keys {
        if client_key == winning_key {
            continue;
        }
        if let Some(client_branch) = session.get_client_branch(client_key) {
            // Build a CANCEL for this branch
            let cancel_branch = TransactionKey::generate_branch();
            let transport_str = format!("{}", client_branch.transport);
            let via_value = format!(
                "SIP/2.0/{} {}:{};branch={}",
                transport_str.to_uppercase(),
                state.via_host(&client_branch.transport),
                state.via_port(&client_branch.transport),
                cancel_branch,
            );

            // Build minimal CANCEL from original request
            let mut cancel = session.original_request.clone();
            if let StartLine::Request(ref mut rl) = cancel.start_line {
                rl.method = crate::sip::message::Method::Cancel;
            }
            cancel.headers.set("Via", via_value);

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

/// Start the next branch in a sequential fork.
fn start_next_fork_branch(
    next_index: usize,
    session_arc: &Arc<RwLock<ProxySession>>,
    server_key: &TransactionKey,
    state: &DispatcherState,
) {
    let (original_request, record_routed, source_addr, connection_id, transport, agg) = {
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
            &session_arc,
            &agg,
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

            // Pop our own Route entry (loose routing — RFC 3261 §16.12)
            if core::check_loose_route(&ack_downstream.headers) {
                core::pop_top_route(&mut ack_downstream.headers);
            }

            // Add our Via on top (preserving existing Vias)
            let transport_str = format!("{}", client_branch.transport);
            core::add_via(
                &mut ack_downstream.headers,
                &transport_str,
                &state.via_host(&client_branch.transport),
                Some(state.via_port(&client_branch.transport)),
            );

            let data = Bytes::from(ack_downstream.to_bytes());
            debug!(
                client_key = %client_key,
                destination = %client_branch.destination,
                "relaying ACK for 2xx downstream via session"
            );

            send_outbound(data, client_branch.transport, client_branch.destination, client_branch.connection_id, state);
        }
    }
}

// ---------------------------------------------------------------------------
// ProxySession-based CANCEL handling
// ---------------------------------------------------------------------------

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

    // Send 200 OK to CANCEL (RFC 3261 §9.2: always 200)
    let cancel_response = build_response(&message, 200, "OK", state.server_header.as_deref(), &[]);
    send_message(
        cancel_response,
        inbound.transport,
        inbound.remote_addr,
        inbound.connection_id,
        state,
    );

    // Forward CANCEL to each client branch
    for client_key in &session.client_keys {
        if let Some(client_branch) = session.get_client_branch(client_key) {
            let mut cancel_downstream = message.clone();
            // CANCEL gets its own branch (different transaction) but we derive it
            // from the client branch so it's traceable.
            let cancel_branch = TransactionKey::generate_branch();
            let transport_str = format!("{}", client_branch.transport);
            let via_value = format!(
                "SIP/2.0/{} {}:{};branch={}",
                transport_str.to_uppercase(),
                state.via_host(&client_branch.transport),
                state.via_port(&client_branch.transport),
                cancel_branch,
            );
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

    // Clean up session
    let server_key = invite_server_key.clone();
    drop(session);
    state.session_store.remove_by_server_key(&server_key);
}

// ---------------------------------------------------------------------------
// B2BUA CANCEL handling
// ---------------------------------------------------------------------------

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

    let call = match state.call_actors.get_call(&call_id) {
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

    // Send 200 OK to CANCEL
    let cancel_response = build_response(&message, 200, "OK", state.server_header.as_deref(), &[]);
    send_message(
        cancel_response,
        inbound.transport,
        inbound.remote_addr,
        inbound.connection_id,
        state,
    );

    // Send CANCEL to all pending B-legs
    for b_leg in &call.b_legs {
        let cancel_branch = TransactionKey::generate_branch();
        let b_transport = b_leg.transport.transport;
        let via_value = format!(
            "SIP/2.0/{} {}:{};branch={}",
            format!("{}", b_transport).to_uppercase(),
            state.via_host(&b_transport),
            state.via_port(&b_transport),
            cancel_branch,
        );

        // Build CANCEL for the B-leg (same Request-URI as the B-leg INVITE)
        let cancel_uri = match parse_uri_standalone(&b_leg.dialog.target_uri.clone().unwrap_or_default()) {
            Ok(uri) => uri,
            Err(_) => continue,
        };
        let cancel_request = SipMessageBuilder::new()
            .request(crate::sip::message::Method::Cancel, cancel_uri)
            .via(via_value)
            .header("Call-ID", b_leg.dialog.call_id.clone())
            .content_length(0);

        // Copy From (with B-leg From-tag), To, CSeq from original
        let cancel_msg = if let Some(from) = message.headers.from() {
            // Rewrite From-tag from A-leg to B-leg
            let b_from = from.replace(
                &format!("tag={}", call.a_leg.dialog.remote_tag.as_deref().unwrap_or("")),
                &format!("tag={}", b_leg.dialog.local_tag),
            );
            cancel_request.from(b_from)
        } else {
            cancel_request
        };
        let cancel_msg = if let Some(to) = message.headers.to() {
            cancel_msg.to(to.clone())
        } else {
            cancel_msg
        };
        // CSeq for CANCEL uses same sequence number but CANCEL method
        let cancel_msg = if let Some(cseq_raw) = message.headers.cseq() {
            if let Some(seq_num) = cseq_raw.split_whitespace().next() {
                cancel_msg.cseq(format!("{} CANCEL", seq_num))
            } else {
                cancel_msg
            }
        } else {
            cancel_msg
        };

        if let Ok(cancel_built) = cancel_msg.build() {
            send_b2bua_to_bleg(cancel_built, b_leg.transport.transport, b_leg.transport.remote_addr, state);
        }
    }

    // Send Cancel to all B-leg actor handles
    for handle in call.b_leg_handles.iter().flatten() {
        let _ = handle.tx.try_send(crate::b2bua::actor::LegMessage::Cancel);
    }

    // Send 487 Request Terminated to A-leg for the original INVITE
    let a_leg = call.a_leg.clone();
    drop(call);

    let response_487 = build_response(&message, 487, "Request Terminated", state.server_header.as_deref(), &[]);
    send_message(
        response_487,
        a_leg.transport.transport,
        a_leg.transport.remote_addr,
        a_leg.transport.connection_id,
        state,
    );

    state.call_actors.set_state(&call_id, CallState::Terminated);
    // remove_call sends Shutdown to any remaining actors and cleans up registry
    state.call_actors.remove_call(&call_id);
    state.call_event_receivers.remove(&call_id);
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
        match crate::sip::headers::refer::parse_replaces(&replaces_raw) {
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
    send_message(
        trying,
        inbound.transport,
        inbound.remote_addr,
        inbound.connection_id,
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
        },
    );

    // Store our Contact for the A-leg direction (what we advertise to the caller).
    // via_host()/via_port() apply advertised_address fallback and substitute the
    // sanitized local_addr when bound to 0.0.0.0/[::].
    a_leg.dialog.local_contact = Some(format!(
        "<sip:{}:{};transport={}>",
        state.via_host(&inbound.transport),
        state.via_port(&inbound.transport),
        inbound.transport.to_string().to_lowercase(),
    ));

    // Capture the caller's Contact URI (remote_contact for A-leg)
    if let Some(contact) = message.headers.get("Contact")
        .or_else(|| message.headers.get("m"))
    {
        a_leg.dialog.remote_contact = Some(crate::b2bua::actor::extract_contact_uri(&contact));
    }

    // Store A-leg's remote AoR host (caller's From URI host) for in-dialog To headers.
    if let Some(from) = message.headers.from() {
        let from_str = crate::b2bua::actor::extract_contact_uri(&from);
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
    }
    state.call_event_receivers.insert(call_id.clone(), event_rx);

    // Invoke @b2bua.on_invite
    let message_arc = Arc::new(std::sync::Mutex::new(message));
    let py_call = PyCall::new(
        call_id.clone(),
        Arc::clone(&message_arc),
        inbound.remote_addr.ip().to_string(),
    );

    let engine_state = state.engine.state();
    let handlers = engine_state.handlers_for(&HandlerKind::B2buaInvite);

    let (action, timer_override, credentials, li_record, preserve_call_id) = Python::attach(|python| {
        let call_obj = match Py::new(python, py_call) {
            Ok(obj) => obj,
            Err(error) => {
                error!("failed to create PyCall: {error}");
                return (CallAction::None, None, None, false, false);
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
                            }, None, None, false, false);
                        }
                    }
                }
                Err(error) => {
                    error!("B2BUA on_invite handler error: {error}");
                    return (CallAction::Reject {
                        code: 500,
                        reason: "Script Error".to_string(),
                    }, None, None, false, false);
                }
            }
        }

        let borrowed = call_obj.borrow(python);
        let action = borrowed.action().clone();
        let timer_override = borrowed.session_timer_override().cloned();
        let credentials = borrowed.outbound_credentials().map(|(u, p)| (u.to_string(), p.to_string()));
        let li_record = borrowed.li_record();
        let preserve_cid = borrowed.preserve_call_id();
        (action, timer_override, credentials, li_record, preserve_cid)
    });

    // Store the A-leg INVITE for later use by on_answer/on_failure/on_bye handlers
    state.call_actors.set_a_leg_invite(&call_id, Arc::clone(&message_arc));

    // Store per-call overrides from script
    if timer_override.is_some() || credentials.is_some() || li_record || preserve_call_id {
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
        CallAction::Dial { target, next_hop, timeout: _ } => {
            debug!(
                call_id = %call_id,
                target = %target,
                next_hop = ?next_hop,
                "B2BUA: dialling B-leg",
            );
            b2bua_send_b_leg_invite(
                &call_id,
                &target,
                next_hop.as_deref(),
                &message_guard,
                &inbound,
                state,
            );
        }
        CallAction::Fork { targets, strategy: _, timeout: _ } => {
            debug!(call_id = %call_id, targets = ?targets, "B2BUA: forking B-legs");
            for target in &targets {
                b2bua_send_b_leg_invite(
                    &call_id,
                    target,
                    None,
                    &message_guard,
                    &inbound,
                    state,
                );
            }
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
        CallAction::Answer { code, reason, body, content_type } => {
            debug!(call_id = %call_id, code, "B2BUA: UAS-mode answer");
            let mut response = build_response(
                &message_guard, code, &reason, state.server_header.as_deref(), &[],
            );
            if let Some(body_bytes) = body {
                if let Some(ct) = content_type {
                    response.headers.set("Content-Type", ct);
                }
                response.headers.set("Content-Length", body_bytes.len().to_string());
                response.body = body_bytes;
            }
            send_message_from(response, inbound.transport, inbound.remote_addr, inbound.connection_id, Some(inbound.local_addr), state);
            // Actor stays alive — the A-leg dialog is now confirmed and the
            // @b2bua.on_bye handler takes over when the UAC BYEs.
        }
    }
}

/// Send a B-leg INVITE for a B2BUA call.
///
/// `target_uri` drives the new INVITE's R-URI (so the called party's IMPU
/// shape is preserved on the wire).  `next_hop`, when set, is used for the
/// wire destination instead of `target_uri` — IMS edge use-case where the
/// R-URI must carry the canonical home-domain IMPU but the message has to
/// be routed via a fixed next-hop (BGCF, I-CSCF, outbound proxy, …).
fn b2bua_send_b_leg_invite(
    call_id: &str,
    target_uri: &str,
    next_hop: Option<&str>,
    original_request: &SipMessage,
    _inbound: &InboundMessage,
    state: &DispatcherState,
) {
    // Resolve the wire destination from next_hop when set, else from target.
    // R-URI construction below still uses target_uri unconditionally — this
    // is the whole point of the split.
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
    let destination = relay_target.address;
    let outbound_transport = relay_target.transport.unwrap_or(Transport::Udp);

    // Build a new INVITE for the B-leg
    let branch = TransactionKey::generate_branch();
    let via_value = format!(
        "SIP/2.0/{} {}:{};branch={}",
        outbound_transport,
        state.via_host(&outbound_transport),
        state.via_port(&outbound_transport),
        branch,
    );

    let mut b_leg_invite = original_request.clone();

    // B2BUA: strip A-leg headers that must not leak to the B-leg.
    // Record-Route/Route belong to the A-leg dialog (independent dialog, RFC 3261).
    // Authorization/Proxy-Authorization are A-leg credentials — forwarding them is
    // both a security leak and protocol-incorrect (B-leg hasn't challenged us).
    b_leg_invite.headers.remove("Record-Route");
    b_leg_invite.headers.remove("Route");
    b_leg_invite.headers.remove("Authorization");
    b_leg_invite.headers.remove("Proxy-Authorization");

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
    let (per_call_override, preserve_call_id, a_leg_call_id, a_leg_from_tag) =
        match state.call_actors.get_call(call_id) {
            Some(c) => (
                c.session_timer_override.clone(),
                c.preserve_call_id,
                c.a_leg.dialog.call_id.clone(),
                c.a_leg.dialog.remote_tag.clone().unwrap_or_default(),
            ),
            None => (None, false, String::new(), String::new()),
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
    //  - Rewrite the URI host to the B2BUA's own domain (mask A-leg identity)
    if let Some(from) = b_leg_invite.headers.get("From")
        .or_else(|| b_leg_invite.headers.get("f"))
    {
        let old_pattern = format!("tag={}", a_leg_from_tag);
        let new_pattern = format!("tag={}", b_leg_from_tag);
        let mut new_from = from.replace(&old_pattern, &new_pattern);

        // Rewrite the host in the From URI to the B2BUA's advertised address.
        // From header format: ["Display" ]<sip:user@host[:port][;params]>[;tag=...]
        let b2bua_host = state.via_host(&outbound_transport);
        if let Some(at_pos) = new_from.find('@') {
            // Find the end of the host: first occurrence of '>', ':', or ';' after '@'
            let after_at = &new_from[at_pos + 1..];
            let host_end = after_at.find(|c: char| c == '>' || c == ';' || c == ':')
                .unwrap_or(after_at.len());
            let end_pos = at_pos + 1 + host_end;
            new_from = format!("{}{}{}", &new_from[..at_pos + 1], b2bua_host, &new_from[end_pos..]);
        }

        b_leg_invite.headers.set("From", new_from);
    }

    // Set Contact to siphon's own address so in-dialog requests route through us.
    // via_host()/via_port() apply advertised_address fallback and substitute the
    // sanitized local_addr when the bind is 0.0.0.0/[::] — never leak unspecified.
    let b_contact_host = state.via_host(&outbound_transport);
    let b_contact_port = state.via_port(&outbound_transport);
    b_leg_invite.headers.set("Contact", format!(
        "<sip:{}:{};transport={}>",
        b_contact_host, b_contact_port,
        outbound_transport.to_string().to_lowercase(),
    ));

    // Replace User-Agent with our own
    if let Some(ref ua) = state.user_agent_header {
        b_leg_invite.headers.set("User-Agent", ua.clone());
    }

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
        // Rewrite To URI host to the dial target's host
        if let Ok(target_parsed) = parse_uri_standalone(target_uri) {
            if let Some(at_pos) = new_to.find('@') {
                let after_at = &new_to[at_pos + 1..];
                let host_end = after_at.find(|c: char| c == '>' || c == ';' || c == ':')
                    .unwrap_or(after_at.len());
                let end_pos = at_pos + 1 + host_end;
                let target_host = &target_parsed.host;
                // Include port if present in target
                let host_with_port = if let Some(port) = target_parsed.port {
                    format!("{}:{}", target_host, port)
                } else {
                    target_host.clone()
                };
                new_to = format!("{}{}{}", &new_to[..at_pos + 1], host_with_port, &new_to[end_pos..]);
            }
        }
        b_leg_invite.headers.set("To", new_to);
    }

    // Regenerate CSeq for B-leg dialog (independent CSeq space, RFC 3261)
    b_leg_invite.headers.set("CSeq", "1 INVITE".to_string());

    // Decrement Max-Forwards (RFC 7332 — B2BUAs MUST decrement)
    let _ = crate::proxy::core::decrement_max_forwards(&mut b_leg_invite.headers);

    // Rewrite P-Asserted-Identity host to our advertised address (topology hiding).
    // The PAI user part is kept as-is (it's the asserted identity), but the host
    // must not leak the A-leg's internal/private IP to the B-leg.
    {
        let b2bua_host = state.via_host(&outbound_transport);
        if let Some(pai) = b_leg_invite.headers.get("P-Asserted-Identity") {
            b_leg_invite.headers.set(
                "P-Asserted-Identity",
                crate::b2bua::actor::rewrite_uri_host(&pai, &b2bua_host),
            );
        }
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

    // Register B-leg with call manager
    let b_contact_value = format!(
        "<sip:{}:{};transport={}>",
        b_contact_host, b_contact_port,
        outbound_transport.to_string().to_lowercase(),
    );
    let mut b_leg = Leg::new_b_leg(
        b_leg_call_id,
        b_leg_from_tag,
        target_uri.to_string(),
        branch.clone(),
        LegTransport {
            remote_addr: destination,
            connection_id: ConnectionId::default(),
            transport: outbound_transport,
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

    // Send via pool for TCP/TLS, direct channel for UDP
    send_to_target(data, &relay_target, outbound_transport, ConnectionId::default(), state);

    // Persist the fully hygiene-processed B-leg INVITE on the leg.
    // The 401/407 auto-retry path rebuilds the retry from this — rebuilding
    // from the A-leg INVITE would leak A-leg headers (Record-Route, Route,
    // Authorization), the original Call-ID/CSeq/From-host, and the un-anchored
    // SDP back to the B-leg. Increment B-leg local CSeq after sending the
    // initial INVITE (CSeq 1 is now used); subsequent requests (re-INVITE,
    // BYE, 401/407 retry) use CSeq >= 2.
    let stored_invite = Arc::new(Mutex::new(b_leg_invite));
    if let Some(mut call) = state.call_actors.get_call_mut(call_id) {
        if let Some(b_leg) = call.b_legs.last_mut() {
            b_leg.dialog.local_cseq += 1;
            b_leg.b_leg_invite = Some(stored_invite);
        }
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
                    registrant.handle_failure(&aor, status_code);
                    return;
                }
            };

            if let Some(challenge) = crate::auth::parse_challenge(&challenge_raw) {
                let is_proxy_auth = status_code == 407;
                if let Some((retry_message, _retry_branch, destination, transport)) =
                    registrant.build_register_with_auth(
                        &aor,
                        state.local_addr,
                        &state.listen_addrs,
                        &challenge,
                        is_proxy_auth,
                        registrant.default_interval,
                    )
                {
                    let data = bytes::Bytes::from(retry_message.to_bytes());
                    send_outbound(data, transport, destination, crate::transport::ConnectionId::default(), state);
                } else {
                    registrant.handle_failure(&aor, status_code);
                }
            } else {
                warn!(aor = %aor, "failed to parse digest challenge from {header_name}");
                registrant.handle_failure(&aor, status_code);
            }
        }
        _ => {
            registrant.handle_failure(&aor, status_code);
        }
    }
}

/// Handle a response to a B2BUA B-leg INVITE.
fn handle_b2bua_response(
    call_id: &str,
    branch: &str,
    message: &mut SipMessage,
    status_code: u16,
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
    let (a_leg, a_leg_invite, b_leg_target, b_leg_remote_contact, _b_leg_local_contact, b_leg_dialog, b_leg_dest, b_leg_index, b_leg_stored_vias, b_leg_stored_cseq, call_state, outbound_credentials, li_record, b_leg_handle_tx, b_leg_stored_invite, b_leg_local_cseq) = match state.call_actors.get_call(call_id) {
        Some(call) => {
            let matching_b_idx = call.b_legs.iter().position(|b| b.branch == branch);
            let matching_b = matching_b_idx.map(|i| &call.b_legs[i]);
            let target = matching_b.map(|b| b.dialog.target_uri.clone().unwrap_or_default());
            let remote_contact = matching_b.and_then(|b| b.dialog.remote_contact.clone());
            let local_contact = matching_b.and_then(|b| b.dialog.local_contact.clone());
            let dialog = matching_b.map(|b| (b.dialog.call_id.clone(), b.dialog.local_tag.clone()));
            let dest = matching_b.map(|b| (b.transport.remote_addr, b.transport.transport));
            let stored_vias = matching_b.map(|b| b.stored_vias.clone()).unwrap_or_default();
            let stored_cseq = matching_b.and_then(|b| b.stored_cseq.clone());
            let handle_tx = matching_b_idx
                .and_then(|i| call.b_leg_handles.get(i))
                .and_then(|h| h.as_ref())
                .map(|h| h.tx.clone());
            let stored_invite = matching_b.and_then(|b| b.b_leg_invite.clone());
            let local_cseq = matching_b.map(|b| b.dialog.local_cseq).unwrap_or(2);
            (call.a_leg.clone(), call.a_leg_invite.clone(), target, remote_contact, local_contact, dialog, dest, matching_b_idx, stored_vias, stored_cseq, call.state.clone(), call.outbound_credentials.clone(), call.li_record, handle_tx, stored_invite, local_cseq)
        }
        None => {
            warn!(call_id = %call_id, "B2BUA: response for unknown call");
            return;
        }
    };

    // RFC 3262 auto-PRACK for the B-leg side: when the B-leg sends a
    // reliable provisional response (`Require: 100rel` + `RSeq: <n>`),
    // the B2BUA must answer with a PRACK. We do that locally here using
    // the B-leg dialog state so the A-leg sees an ordinary 1xx (the
    // `Require`/`RSeq` headers are stripped in `sanitize_b2bua_response`).
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
                        debug!(
                            call_id = %call_id,
                            rseq = rseq.response_number,
                            "B2BUA: sending auto-PRACK for reliable 1xx from B-leg"
                        );
                        send_b2bua_to_bleg(prack, transport, dest, state);
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
                    let outbound_port = state.listen_addrs.get(&responder_transport)
                        .map(|a| a.port())
                        .unwrap_or(state.local_addr.port());
                    let cseq_num = message.headers.cseq()
                        .and_then(|c| c.split_whitespace().next().map(|s| s.to_string()))
                        .unwrap_or_else(|| "1".to_string());
                    let from = message.headers.from().cloned().unwrap_or_default();
                    let to = message.headers.to().cloned().unwrap_or_default();
                    // RURI: extract Contact from the 200 OK message directly
                    // (RFC 3261 §12.2.1.1), with fallback to stored remote_contact.
                    let ack_uri = message.headers.get("Contact")
                        .or_else(|| message.headers.get("m"))
                        .map(|c| crate::b2bua::actor::extract_contact_uri(&c))
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
                        send_message(ack, responder_transport, responder_dest, a_leg.transport.connection_id, state);
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
                    &a_leg.dialog.remote_tag.as_deref().unwrap_or(""),
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

        sanitize_b2bua_response(message, state, resp_transport);

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
                    let outbound_port = state.listen_addrs.get(&responder_transport)
                        .map(|a| a.port())
                        .unwrap_or(state.local_addr.port());
                    // Use the responder's CSeq (captured before originator CSeq restoration).
                    let cseq_num = responder_cseq_num.clone();
                    let from = message.headers.from().cloned().unwrap_or_default();
                    let to = message.headers.to().cloned().unwrap_or_default();
                    // RURI: extract Contact from the 200 OK message directly
                    // (RFC 3261 §12.2.1.1), with fallback to stored remote_contact.
                    let ack_uri = message.headers.get("Contact")
                        .or_else(|| message.headers.get("m"))
                        .map(|c| crate::b2bua::actor::extract_contact_uri(&c))
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
                        send_message(ack, responder_transport, responder_dest, a_leg.transport.connection_id, state);
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
            send_message(message.clone(), resp_transport, resp_dest, resp_conn_id, state);
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
                    &a_leg.dialog.remote_tag.as_deref().unwrap_or(""),
                    Some(&a_leg.dialog.local_tag),
                );
            }
        } else {
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

        // Restore originator's Via and CSeq (RFC 3261 §8.2.6.2).
        message.headers.set_all("Via", b_leg_stored_vias.clone());
        if let Some(ref cseq) = b_leg_stored_cseq {
            message.headers.set("CSeq", cseq.clone());
        }

        sanitize_b2bua_response(message, state, resp_transport);

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
            send_message(message.clone(), resp_transport, resp_dest, resp_conn_id, state);
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
        }).unwrap_or_else(|| LegTransport {
            remote_addr: state.local_addr,
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
        });
        match handle_tx.try_send(crate::b2bua::actor::LegMessage::SipInbound {
            message: message.clone(),
            source: leg_transport,
        }) {
            Ok(()) => {
                // Temporarily extract receiver to block on it.
                // Safe: dispatcher processes messages sequentially.
                if let Some((_, mut rx)) = state.call_event_receivers.remove(call_id) {
                    let event = rx.blocking_recv();
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
                            crate::b2bua::actor::extract_contact_uri(&contact),
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
                if let Some((ref b_cid, ref b_ftag)) = b_leg_dialog {
                    // Build a clean ACK from scratch — do NOT clone the 200 OK
                    // (cloning leaks response headers like User-Agent, Contact,
                    // Allow, Supported, etc. from the remote UA).
                    let request_uri = message.headers.get("Contact")
                        .or_else(|| message.headers.get("m"))
                        .map(|c| crate::b2bua::actor::extract_contact_uri(&c))
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
                );
                let py_reply = PyReply::new(Arc::clone(&response_arc))
                    .with_a_leg(Arc::clone(invite_arc));

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
                &a_leg.dialog.remote_tag.as_deref().unwrap_or(""),
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
        sanitize_b2bua_response(&mut response, state, a_leg.transport.transport);

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
            let mut b_routes = flatten_record_route_headers(&b_leg_record_routes);
            b_routes.reverse();
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
                    .map(|c| crate::b2bua::actor::extract_contact_uri(&c))
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
                let mut b_leg_routes: Vec<String> = Vec::new();
                for rr_value in b_leg_record_routes.iter().rev() {
                    // Each Record-Route value can contain multiple comma-separated entries
                    for entry in rr_value.split(',') {
                        let trimmed = entry.trim();
                        if !trimmed.is_empty() {
                            b_leg_routes.push(trimmed.to_string());
                        }
                    }
                }

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
                    // Store the pre-built ACK (route sets already persisted above).
                    if let Some(mut call) = state.call_actors.get_call_mut(call_id) {
                        call.pending_b_leg_ack = Some((ack, b_transport, b_dest));
                    }
                    debug!(call_id = %call_id, "B2BUA: deferred B-leg ACK until A-leg ACKs");
                }
            }
        }

        // Extract SDP body before forwarding (needed for SIPREC)
        let sdp_body = response.body.clone();

        send_message(
            response,
            a_leg.transport.transport,
            a_leg.transport.remote_addr,
            a_leg.transport.connection_id,
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
                    };
                    send_to_target(data, &target, transport, ConnectionId::default(), state);
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
                    );
                    let py_reply = PyReply::new(Arc::clone(&response_arc))
                        .with_a_leg(Arc::clone(invite_arc));

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
                &a_leg.dialog.remote_tag.as_deref().unwrap_or(""),
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
        sanitize_b2bua_response(message, state, a_leg.transport.transport);
        send_message(
            message.clone(),
            a_leg.transport.transport,
            a_leg.transport.remote_addr,
            a_leg.transport.connection_id,
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

                            // Resolve target
                            if let Some(relay_target) = resolve_target(target_uri, &state.dns_resolver) {
                                let destination = relay_target.address;
                                let b_leg_transport = b_leg_dest.map(|(_, t)| t).unwrap_or(Transport::Udp);
                                let transport = relay_target.transport.unwrap_or(b_leg_transport);

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
                                    &a_leg.dialog.remote_tag.as_deref().unwrap_or(""),
                                    &retry_from_tag,
                                    None,
                                );

                                let b_leg = Leg::new_b_leg(
                                    retry_call_id,
                                    retry_from_tag,
                                    target_uri.clone(),
                                    new_branch,
                                    LegTransport {
                                        remote_addr: destination,
                                        connection_id: ConnectionId::default(),
                                        transport,
                                    },
                                );
                                state.call_actors.add_b_leg(call_id, b_leg.clone());
                                spawn_b_leg_actor(call_id, &b_leg, state);

                                let data = Bytes::from(retry.to_bytes());
                                send_to_target(data, &relay_target, transport, ConnectionId::default(), state);
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
            if let Some((username, password)) = &outbound_credentials {
                let challenge_header = if status_code == 401 {
                    message.headers.get("WWW-Authenticate")
                } else {
                    message.headers.get("Proxy-Authenticate")
                };

                if let Some(challenge_value) = challenge_header {
                    if let Some(challenge) = crate::auth::parse_challenge(challenge_value) {
                        if let (Some(target_uri), Some(stored_invite_arc)) = (&b_leg_target, &b_leg_stored_invite) {
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

                            // Resolve target
                            if let Some(relay_target) = resolve_target(target_uri, &state.dns_resolver) {
                                let destination = relay_target.address;
                                let b_leg_transport = b_leg_dest.map(|(_, t)| t).unwrap_or(Transport::Udp);
                                let transport = relay_target.transport.unwrap_or(b_leg_transport);

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
                                        connection_id: ConnectionId::default(),
                                        transport,
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

                                state.call_actors.add_b_leg(call_id, b_leg.clone());
                                spawn_b_leg_actor(call_id, &b_leg, state);

                                let data = Bytes::from(retry.to_bytes());
                                send_to_target(data, &relay_target, transport, ConnectionId::default(), state);
                            }
                            return; // don't forward 401/407 to A-leg or fire on_failure
                        }
                    }
                }
            }
        }

        // Error response — invoke @b2bua.on_failure with (PyCall, code, reason)
        let engine_state = state.engine.state();
        let handlers = engine_state.handlers_for(&HandlerKind::B2buaFailure);
        if !handlers.is_empty() {
            let reason = match &message.start_line {
                StartLine::Response(status_line) => status_line.reason_phrase.clone(),
                _ => "Unknown".to_string(),
            };

            if let Some(invite_arc) = &a_leg_invite {
                let py_call = PyCall::new(
                    call_id.to_string(),
                    Arc::clone(invite_arc),
                    a_leg.transport.remote_addr.ip().to_string(),
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
                state.local_addr,
            );
            send_b2bua_to_bleg(ack, b_transport, b_dest, state);
        }

        // Forward error to A-leg — rewrite B-leg dialog headers back to A-leg
        if let Some((ref _b_cid, ref b_ftag)) = b_leg_dialog {
            crate::b2bua::actor::Dialog::rewrite_headers(
                message,
                &a_leg.dialog.call_id,
                b_ftag,
                &a_leg.dialog.remote_tag.as_deref().unwrap_or(""),
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
        sanitize_b2bua_response(message, state, a_leg.transport.transport);
        send_message(
            message.clone(),
            a_leg.transport.transport,
            a_leg.transport.remote_addr,
            a_leg.transport.connection_id,
            state,
        );

        // Safety-net: if RTPEngine was offered but call failed, clean up the session.
        // Only runs when the call is truly ending (script called reject, not retry).
        let a_sip_call_id = a_leg.dialog.call_id.clone();
        if let (Some(rtpengine_set), Some(media_sessions)) =
            (&state.rtpengine_set, &state.rtpengine_sessions)
        {
            if let Some(session) = media_sessions.remove(&a_sip_call_id) {
                let set = Arc::clone(rtpengine_set);
                tokio::spawn(async move {
                    if let Err(error) = set.delete(&session.call_id, &session.from_tag).await {
                        warn!(call_id = %session.call_id, "safety-net RTPEngine delete failed: {error}");
                    }
                });
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
    let (from_a_leg, a_leg_invite, a_leg_source_ip) = match state.call_actors.get_call(&call_id) {
        Some(call) => {
            let from_a = inbound.remote_addr == call.a_leg.transport.remote_addr;
            (from_a, call.a_leg_invite.clone(), call.a_leg.transport.remote_addr.ip().to_string())
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
    spawn_rf_b2bua_stop(state, &call_id, &message);

    // Re-acquire the call ref for BYE bridging
    let call = match state.call_actors.get_call(&call_id) {
        Some(c) => c,
        None => return,
    };

    // Send 200 OK to the BYE sender
    let bye_response = build_response(&message, 200, "OK", state.server_header.as_deref(), &[]);
    send_message(
        bye_response,
        inbound.transport,
        inbound.remote_addr,
        inbound.connection_id,
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
                    debug!(call_id = %call_id, destination = %b_leg.transport.remote_addr, "B2BUA: sending BYE to B-leg");
                    send_b2bua_to_bleg(bye, b_leg.transport.transport, b_leg.transport.remote_addr, state);
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
            send_message(
                bye,
                call.a_leg.transport.transport,
                call.a_leg.transport.remote_addr,
                call.a_leg.transport.connection_id,
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
                    warn!(call_id = %session.call_id, "safety-net RTPEngine delete failed: {error}");
                }
            });
        }
    }

    // SIPREC: stop any active recording sessions for this call.
    // First, collect RTPEngine subscribe info before stop_recording cleans up sessions.
    let siprec_infos = state.recording_manager.active_session_infos(&call_id);
    let bye_messages = state.recording_manager.stop_recording(&call_id, state.local_addr);
    for (bye_msg, destination, transport) in bye_messages {
        let data = Bytes::from(bye_msg.to_bytes());
        let target = RelayTarget {
            address: destination,
            transport: Some(transport),
        };
        send_to_target(data, &target, transport, ConnectionId::default(), state);
    }
    // RTPEngine unsubscribe: stop media forking for each recording session.
    if let Some(ref rtpengine_set) = state.rtpengine_set {
        for (original_call_id, original_from_tag, original_to_tag) in siprec_infos {
            let set = Arc::clone(rtpengine_set);
            tokio::spawn(async move {
                if let Err(error) = set.unsubscribe(&original_call_id, &original_from_tag, &original_to_tag).await {
                    warn!(
                        call_id = %original_call_id,
                        "SIPREC: RTPEngine unsubscribe failed: {error}"
                    );
                }
            });
        }
    }

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
        reinvite.headers.set("From", crate::b2bua::actor::rewrite_uri_host(&from, &b2bua_host));
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

/// Terminate a call due to session timer expiry — send BYE to both legs.
fn b2bua_session_timer_terminate(call_id: &str, state: &DispatcherState) {
    let (a_leg, winner_b_leg, sip_call_id) = match state.call_actors.get_call(call_id) {
        Some(call) => {
            let b_leg = call.winner.and_then(|i| call.b_legs.get(i).cloned());
            (call.a_leg.clone(), b_leg, call.a_leg.dialog.call_id.clone())
        }
        None => return,
    };

    // Build BYE for each leg using the shared build_b2bua_bye helper.
    if let Some(bye_msg) = build_b2bua_bye(&a_leg, state) {
        send_message(bye_msg, a_leg.transport.transport, a_leg.transport.remote_addr, a_leg.transport.connection_id, state);
    }
    if let Some(b_leg) = &winner_b_leg {
        if let Some(bye_msg) = build_b2bua_bye(b_leg, state) {
            send_b2bua_to_bleg(bye_msg, b_leg.transport.transport, b_leg.transport.remote_addr, state);
        }
    }

    // Safety-net RTPEngine cleanup
    if let (Some(rtpengine_set), Some(media_sessions)) =
        (&state.rtpengine_set, &state.rtpengine_sessions)
    {
        if let Some(session) = media_sessions.remove(&sip_call_id) {
            let set = Arc::clone(rtpengine_set);
            tokio::spawn(async move {
                if let Err(error) = set.delete(&session.call_id, &session.from_tag).await {
                    warn!(call_id = %session.call_id, "safety-net RTPEngine delete failed: {error}");
                }
            });
        }
    }

    state.call_actors.set_state(call_id, CallState::Terminated);
    state.call_actors.remove_call(call_id);
    state.call_event_receivers.remove(call_id);
    schedule_zombie_reinvite_cleanup(&state.call_actors);
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
                        source_local_addr: None,
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
    send_message(
        response,
        inbound.transport,
        inbound.remote_addr,
        inbound.connection_id,
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
    let (target_remote_contact, target_local_contact, target_remote_aor_host) = if from_a_leg {
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
    send_message(
        trying,
        inbound.transport,
        inbound.remote_addr,
        inbound.connection_id,
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
            Some((b_leg.transport.remote_addr, b_leg.transport.transport, b_leg.dialog.call_id.clone(), b_leg.dialog.local_tag.clone()))
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
        Some((a_leg.transport.remote_addr, a_leg.transport.transport, a_leg.dialog.call_id.clone(), a_leg.dialog.remote_tag.clone().unwrap_or_default()))
    };

    if let Some((destination, transport, leg_call_id, leg_from_tag)) = reinvite_target {
        // Set Via with correct transport for the target leg
        let transport_str = format!("{}", transport).to_uppercase();
        let via_value = format!(
            "SIP/2.0/{} {}:{};branch={}",
            transport_str,
            state.via_host(&transport),
            state.via_port(&transport),
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
                remote_addr: destination,
                connection_id: ConnectionId::default(),
                transport,
            },
        );
        reinvite_leg.stored_vias = originator_vias;
        reinvite_leg.stored_cseq = message.headers.cseq().map(|c| c.to_string());
        state.call_actors.add_b_leg(&call_id, reinvite_leg);

        send_b2bua_to_bleg(forwarded, transport, destination, state);

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
    send_message(
        trying,
        inbound.transport,
        inbound.remote_addr,
        inbound.connection_id,
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
            Some((b_leg.transport.remote_addr, b_leg.transport.transport, b_leg.dialog.call_id.clone(), b_leg.dialog.local_tag.clone()))
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
        Some((a_leg.transport.remote_addr, a_leg.transport.transport, a_leg.dialog.call_id.clone(), a_leg.dialog.remote_tag.clone().unwrap_or_default()))
    };

    if let Some((destination, transport, leg_call_id, leg_from_tag)) = update_target {
        let transport_str = format!("{}", transport).to_uppercase();
        let via_value = format!(
            "SIP/2.0/{} {}:{};branch={}",
            transport_str,
            state.via_host(&transport),
            state.via_port(&transport),
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
                remote_addr: destination,
                connection_id: ConnectionId::default(),
                transport,
            },
        );
        update_leg.stored_vias = originator_vias;
        update_leg.stored_cseq = message.headers.cseq().map(|c| c.to_string());
        state.call_actors.add_b_leg(&call_id, update_leg);

        send_b2bua_to_bleg(forwarded, transport, destination, state);

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
    use crate::sip::uri::SipUri;
    use crate::sip::builder::SipMessageBuilder;

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

        let local_addr: SocketAddr = "10.0.0.1:5060".parse().unwrap();
        let ack = build_b2bua_ack_for_non2xx(
            &response,
            "z9hG4bK-b2b-branch",
            Some("sip:bob@10.0.0.2:5060"),
            Transport::Udp,
            local_addr,
        );

        assert!(ack.is_request());
        let bytes = String::from_utf8(ack.to_bytes()).unwrap();
        assert!(bytes.starts_with("ACK sip:bob@10.0.0.2:5060 SIP/2.0\r\n"));

        // Via uses our branch (same as client transaction)
        let via = ack.headers.via().unwrap();
        assert!(via.contains("z9hG4bK-b2b-branch"));
        assert!(via.contains("UDP"));

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

}
