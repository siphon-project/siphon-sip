//! Core request dispatcher — glue between transport and script engine.
//!
//! Receives raw SIP bytes from the transport layer, parses them, invokes
//! Python script handlers, and sends responses back through the transport.
//! Implements stateless proxy relay with Via-based response routing.

use std::borrow::Cow;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, RwLock};

use bytes::Bytes;
use dashmap::DashMap;
use pyo3::prelude::*;
use tracing::{debug, error, info, warn};

use crate::b2bua::actor::{
    CallActorStore, CallEvent, CallState, Leg, LegActor, TransportInfo as LegTransport,
};
use crate::config::Config;
use crate::dns::SipResolver;
use crate::hep::HepSender;
use crate::proxy::core;
use crate::proxy::session::{ClientBranch, ProxySession, ProxySessionStore};
use crate::registrar::{Registrar, RegistrarConfig};
use crate::script::api::auth::PyAuth;
use crate::script::api::call::{CallAction, PyByeInitiator, PyCall};
use crate::script::api::log::PyLogNamespace;
use crate::script::api::registrar::PyRegistrar;
use crate::script::api::reply::PyReply;
use crate::script::api::request::{LocalDomains, PyRequest, RequestAction};
use crate::script::engine::{run_coroutine, HandlerKind, ScriptEngine};
use crate::sip::builder::SipMessageBuilder;
use crate::sip::headers::via::Via;
use crate::sip::headers::SipHeaders;
use crate::sip::message::{Method, RequestLine, SipMessage, StartLine, StatusLine, Version};
use crate::sip::parser::{parse_sip_message_bytes, parse_uri_standalone};
use crate::sip::uri::SipUri;
use crate::sip::uri::{format_sip_host, split_host_port, strip_ipv6_brackets};
use crate::transaction::key::TransactionKey;
use crate::transaction::state::{Action, IctEvent, IstEvent, NictEvent, NistEvent, TimerName};
use crate::transaction::timer::TimerConfig;
use crate::transaction::{ClientEvent, ServerEvent, TransactionManager};
use crate::transport::pool::ConnectionPool;
use crate::transport::{
    ConnectionId, InboundMessage, OutboundMessage, OutboundRouter, StreamConnections, Transport,
};
use crate::uac::UacSender;

// Leaf helpers extracted from this file. Private modules: the split must not
// add public paths. `init_rtpengine` and `spawn_rtpengine_health_check` are
// re-exported because `server.rs` and the Python bindings reach them as
// `siphon::dispatcher::…`.
mod b2bua;
mod cancel_ack;
mod cdr;
mod charging;
mod failure;
mod identity;
mod in_dialog;
mod inbound;
mod intercept;
mod liveness;
mod media_init;
mod registrant;
mod relay;
mod request;
mod response;
mod response_builder;
mod rtpengine_events;
mod sanitize;
mod send;
mod srs;
mod state;
mod sweep;
mod target;
mod tasks;
mod timers;

#[cfg(test)]
mod b_leg_2xx_ack_tests;
#[cfg(test)]
mod b_leg_capability_tests;
#[cfg(test)]
mod delayed_offer_ack_tests;
#[cfg(test)]
mod held_bye_tests;
#[cfg(test)]
mod late_provisional_tests;
#[cfg(test)]
mod lcr_number_policy_tests;
#[cfg(test)]
mod lcr_ring_timeout_tests;
#[cfg(test)]
mod lcr_route_bookkeeping_tests;
#[cfg(test)]
mod originate_tests;
#[cfg(test)]
mod public_api_surface;
#[cfg(test)]
mod relayed_identity_tests;
#[cfg(test)]
mod retransmit_capture_tests;
#[cfg(test)]
mod ro_orphan_backstop_tests;
#[cfg(test)]
mod sdp_strip_tests;
#[cfg(test)]
mod teardown_race_tests;
#[cfg(test)]
mod test_dispatcher;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod transfer_bye_tests;
#[cfg(test)]
mod unacked_answer_tests;

// The imperative call-control surface the scripting, admin and control-plane
// layers reach as `siphon::dispatcher::…`. It lives in `b2bua/` now, so each
// name is re-exported here rather than declared here — the paths are frozen
// for 1.9.0 and `public_api_surface` pins them.
pub use b2bua::{
    b2bua_accept_refer_call, b2bua_answer_call, b2bua_answer_call_anchored, b2bua_bridge_calls,
    b2bua_cancel_originated_call, b2bua_early_media_sdp, b2bua_local_tag,
    b2bua_media_set_ws_bridge_attached, b2bua_media_set_ws_tee, b2bua_media_target,
    b2bua_originate, b2bua_originate_dial, b2bua_originate_prepare, b2bua_progress_call,
    b2bua_progress_call_anchored, b2bua_refer_call, b2bua_reject_call, b2bua_reject_refer_call,
    b2bua_replace_peer, b2bua_route_call, b2bua_terminate_call, b2bua_unbridge_call,
    BridgeAccepted, BridgeParams, OriginateError, OriginateMedia, OriginateParams,
    PreparedOriginate, RouteError, RouteTarget,
};
// Crate-internal, not published: only the SIP control adapter calls these, so
// they are deliberately not part of `siphon::dispatcher`'s API. Counted by
// `public_api_surface` all the same — the point of the count is that the module
// does not grow a surface by accident, published or not.
pub(crate) use b2bua::{b2bua_dial_call, dial_targets_for_aor, DialError, DialTarget};
pub use charging::{ro_authorize_b2bua, RoAuthorizeOutcome};
pub(crate) use liveness::liveness_on_flow_close;
pub use media_init::{init_rtpengine, spawn_rtpengine_health_check};
pub(crate) use state::ProxyRfState;
pub use state::{publish_store_gauges, DrainState, ReliableProvisional};

use b2bua::*;
use cancel_ack::*;
use cdr::*;
use charging::*;
use failure::*;
use identity::*;
use in_dialog::*;
use inbound::*;
use intercept::*;
use liveness::*;
use media_init::*;
use registrant::*;
use relay::*;
use request::*;
use response::*;
use response_builder::*;
use rtpengine_events::*;
use sanitize::*;
use send::*;
use srs::*;
use state::*;
use sweep::*;
use target::*;
use tasks::*;
use timers::*;

/// RTPEngine wiring produced by [`init_rtpengine`]: the media-control backend
/// (rtpengine NG or native siphon-rtp), the media session store, and the
/// profile registry. Each component is present only when `media` is configured
/// (otherwise all three are `None`).
type RtpEngineComponents = (
    Option<Arc<crate::rtpengine::MediaBackend>>,
    Option<Arc<crate::rtpengine::session::MediaSessionStore>>,
    Option<Arc<crate::rtpengine::ProfileRegistry>>,
);

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
    registrar_event_rx: Option<
        tokio::sync::broadcast::Receiver<crate::registrar::RegistrationEvent>,
    >,
    diameter_incoming_rx: tokio::sync::mpsc::Receiver<(
        crate::diameter::peer::IncomingRequest,
        std::sync::Arc<crate::diameter::peer::DiameterPeer>,
    )>,
    rtpengine_events_rx: tokio::sync::mpsc::Receiver<crate::rtpengine::events::RtpEngineEvent>,
    rf_charger: Option<Arc<crate::diameter::rf_service::RfChargingService>>,
    ro_charger: Option<Arc<crate::diameter::ro_service::RoChargingService>>,
    drain: Arc<DrainState>,
    product_name: &'static str,
    product_version: &'static str,
) {
    // Resolve the generic local address for Via insertion. When bound to a
    // wildcard (0.0.0.0 / [::]), the shared resolver prefers an explicit global
    // `advertised_address`, else the host's auto-detected routable IP, else
    // loopback. Pass an empty per-transport map: this is the transport-agnostic
    // fallback (`state.local_addr`); `via_host` layers per-transport advertised
    // addresses on top of it. The transport arg is therefore a throwaway.
    let via_addr = crate::uac::resolve_via_addr(
        local_addr,
        &Transport::Udp,
        &std::collections::HashMap::new(),
        config.advertised_address.as_deref(),
    );
    if local_addr.ip().is_unspecified() && config.advertised_address.is_none() {
        if via_addr.ip().is_loopback() {
            warn!(
                bind = %local_addr,
                "bound to an unspecified address with no `advertised_address` and no routable \
                 local IP detected — Via/Contact will use loopback; remote peers cannot reach \
                 this instance. Set `advertised_address`."
            );
        } else {
            warn!(
                bind = %local_addr,
                advertised = %via_addr.ip(),
                "bound to an unspecified address with no `advertised_address` — using the \
                 auto-detected local IP for Via/Contact. Behind NAT, set `advertised_address` \
                 to the public address."
            );
        }
    }

    // RFC 3261 §18.1.1 MTU floor sanity check.  Below the 576-byte IPv4 minimum
    // (mtu-200 ≈ 376), almost every request crosses the threshold and switches
    // to TCP — very likely a typo (e.g. `mtu: 128`).
    if let Some(mtu) = config.listen.mtu {
        if mtu < 576 {
            warn!(
                mtu,
                "listen.mtu is below the 576-byte IPv4 minimum — nearly every request will \
                 exceed mtu-200 and be relayed over TCP; is this intended?"
            );
        }
    }

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
    // `map_or(true, …)` not `is_none_or` — the latter is stable since 1.82 and
    // the crate's MSRV is 1.80 (clippy::incompatible_msrv gates on it).
    #[allow(clippy::unnecessary_map_or)]
    let auto_options = config.server.as_ref().map_or(true, |s| s.auto_options);

    let tx_config = config.transaction.as_ref();
    let transaction_timeout = std::time::Duration::from_secs(
        tx_config
            .map(|t| t.invite_timeout_secs as u64)
            .unwrap_or(30)
            + 2,
    );
    let _non_invite_timeout =
        std::time::Duration::from_secs(tx_config.map(|t| t.timeout_secs as u64).unwrap_or(5));

    let timer_config = {
        let mut config = TimerConfig::default();
        if let Some(tx) = tx_config {
            config.auto_100_trying = tx.auto_emit_100_trying;
            config.auto_100_delay =
                std::time::Duration::from_millis(tx.auto_emit_100_trying_delay_ms);
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
            merged_advertised
                .entry(transport)
                .or_insert_with(|| global_adv.clone());
        }
    }

    // A TLS or WSS listener advertising an IP literal its certificate does not
    // carry fails every peer that reconnects to it, and siphon never sees the
    // failure. Say so once, here, where the advertised hosts and the listener set
    // are final. TLS/WSS listeners only start when a `tls:` block is configured.
    if let Some(ref tls) = config.tls {
        warn_secure_listeners_advertising_ip_literals(
            &tls.certificate,
            &listener_registry,
            &merged_advertised,
            &listen_addrs,
            via_addr.ip(),
        );
    }

    // B2BUA header policy library: the built-in presets plus every
    // operator-defined policy from `header_policies:`.  Both were already
    // resolved and validated at config load, so neither arm below should be
    // reachable on a config that parsed — they exist so a future caller that
    // builds a DispatcherState from a hand-made Config cannot panic.
    let header_policy_registry = Arc::new(
        match crate::b2bua::header_policy::build_registry(&config.header_policies) {
            Ok(registry) => registry,
            Err(error) => {
                error!(
                    %error,
                    "header_policies failed to resolve — continuing with built-in presets only"
                );
                crate::b2bua::header_policy::builtin_presets()
            }
        },
    );
    let default_policy_name = config.b2bua.resolved_default_header_policy();
    let default_header_policy = header_policy_registry
        .get(default_policy_name)
        .cloned()
        .unwrap_or_else(|| {
            warn!(
                requested = %default_policy_name,
                fallback = %crate::b2bua::header_policy::DEFAULT_PRESET_NAME,
                "b2bua.default_header_policy unknown — falling back"
            );
            crate::b2bua::header_policy::default_preset()
        });

    // Publish the call store for read-only observability (admin `/admin/calls`)
    // before it's moved into the dispatcher state.
    let call_actors = Arc::new(CallActorStore::new());
    crate::b2bua::actor::set_global_call_store(Arc::clone(&call_actors));

    let self_identity = Arc::new(build_self_identity(
        &config.domain.local,
        config
            .ipsec
            .as_ref()
            .map(|ipsec| (ipsec.pcscf_port_c, ipsec.pcscf_port_s)),
        config
            .ipsec
            .as_ref()
            .and_then(|ipsec| ipsec.path_host.as_deref()),
        &listener_registry,
        &merged_advertised,
        &listen_addrs,
        via_addr,
    ));
    debug!(entries = ?self_identity.entries(), "route self-identity");

    let state = Arc::new(DispatcherState {
        engine,
        outbound,
        local_domains: Arc::new(config.domain.local.clone()),
        self_identity,
        local_addr: via_addr,
        advertised_addrs: merged_advertised,
        listen_addrs,
        listener_registry,
        server_header,
        auto_options,
        user_agent_header,
        transaction_timeout,
        call_actors,
        transaction_manager,
        timer_wheel: Arc::new(DashMap::new()),
        b2bua_retransmits: Arc::new(crate::b2bua::retransmit::B2buaRetransmits::new(
            timer_config,
        )),
        session_store: Arc::new(ProxySessionStore::new()),
        dns_resolver,
        hep_sender,
        uac_sender,
        rtpengine_set,
        rtpengine_sessions,
        rtpengine_profiles,
        control_inbound: config
            .control
            .as_ref()
            .and_then(|control| control.inbound.clone()),
        session_timer_config: config.session_timer.clone(),
        mtu: config.listen.mtu,
        header_policy_registry,
        default_header_policy,
        default_refer_mode: config.b2bua.resolved_default_refer_mode(),
        accept_replaces: config.b2bua.replaces_takeover_enabled(),
        log_dial: config.b2bua.log_dial_enabled(),
        default_max_call_duration_secs: config.b2bua.resolved_max_call_duration_secs(),
        registrant_manager,
        recording_manager: Arc::new(crate::siprec::RecordingManager::new(
            product_name,
            product_version,
        )),
        li_siprec_srs_uri: config
            .lawful_intercept
            .as_ref()
            .and_then(|li| li.siprec.as_ref())
            .map(|siprec| siprec.srs_uri.clone()),
        li_siprec_rtpengine_profile: config
            .lawful_intercept
            .as_ref()
            .and_then(|li| li.siprec.as_ref())
            .map(|siprec| siprec.rtpengine_profile.clone()),
        srs_manager: config
            .srs
            .as_ref()
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
        sdp_name: config
            .media
            .as_ref()
            .and_then(|m| m.sdp_name.clone())
            .unwrap_or_else(|| product_name.to_string()),
        sdp_strip_attributes: config
            .media
            .as_ref()
            .map(|media| media.sdp_strip_attributes.clone())
            .unwrap_or_default(),
        call_event_receivers: Arc::new(DashMap::new()),
        reliable_provisionals: Arc::new(DashMap::new()),
        uas_2xx_retransmits: Arc::new(DashMap::new()),
        held_byes: Arc::new(DashMap::new()),
        cancelled_invites: Arc::new(DashMap::new()),
        is_draining: drain.clone(),
        rf_charger,
        rf_sessions: Arc::new(DashMap::new()),
        rf_pending_starts: Arc::new(DashMap::new()),
        ro_charger,
        ro_sessions: Arc::new(DashMap::new()),
        cdr_sessions: Arc::new(DashMap::new()),
        pending_inbound_refer: Arc::new(PendingInboundReferStore::default()),
        deferred_referrer_bye: Arc::new(DeferredReferrerByeStore::default()),
        // Interception is enforced here, not in the script. `LI_MANAGER` is
        // set by `init_li` before the dispatcher is built when
        // `lawful_intercept.enabled` is true.
        li_manager: crate::server::li_manager(),
    });

    // Hand the freshly-constructed manager handles to the drain coordinator
    // so the server's drain loop can poll active counts on shutdown.
    let _ = drain
        .transaction_manager
        .set(Arc::clone(&state.transaction_manager));
    let _ = drain.call_actors.set(Arc::clone(&state.call_actors));

    install_charging_hooks(&state);

    spawn_timer_sweep(&state);

    spawn_session_timer_refresh(&state);

    spawn_registrar_events(&state, registrar_event_rx);

    spawn_registrant_events(&state);

    spawn_diameter_incoming(&state, diameter_incoming_rx);

    spawn_rtpengine_events(&state, rtpengine_events_rx);

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
    let py_registrar = PyRegistrar::new(Arc::clone(&registrar));

    // Build PyAuth from config
    let mut realm_users = std::collections::HashMap::new();
    realm_users.insert(config.auth.realm.clone(), config.auth.users.clone());
    let mut py_auth = PyAuth::new(realm_users, config.auth.realm.clone());
    py_auth.set_backend_type(config.auth.backend.clone());
    // The same registrar scripts save into: `auth.verify_integrity_protected`
    // trusts a protected REGISTER only from the identity that saved the binding.
    py_auth.set_registrar(registrar);

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

    // Wire the SQL auth backend if configured. Config load refuses
    // `backend: database` without this block, so a missing one here means the
    // operator selected another backend and left the block behind.
    if let Some(database_config) = &config.auth.database {
        py_auth.set_database_config(database_config.clone());
        info!(
            query = %database_config.query,
            ha1 = database_config.ha1,
            cache_ttl_secs = database_config.cache_ttl_secs,
            "database auth backend configured"
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
    let py_proxy_utils = crate::script::api::proxy_utils::PyProxyUtils::new(dns_resolver);

    // Cache namespace (local LRU + optional Redis)
    let cache_manager = std::sync::Arc::new(crate::cache::CacheManager::new(
        config.cache.as_deref().unwrap_or(&[]),
    ));
    let py_cache = crate::script::api::cache::PyCacheNamespace::new(cache_manager);

    // Store singletons in the global so install_siphon_module() will inject
    // them each time it (re-)creates the module.
    Python::attach(|python| {
        if let Err(error) = crate::script::api::set_rust_singletons(
            python,
            py_auth,
            py_registrar,
            py_log,
            py_proxy_utils,
            py_cache,
        ) {
            error!("failed to store Rust singletons: {error}");
        } else {
            info!(
                "Rust-backed auth, registrar, log, proxy utils, and cache registered for injection"
            );
        }
    });

    // RTPEngine Python singleton is now initialized in init_rtpengine() above.
}

/// Maximum credentialed outbound INVITEs the B2BUA will send on the 401/407
/// digest auto-retry path per call before treating further challenges as a
/// persistent auth failure and surfacing the response upstream. RFC has no
/// fixed number; 2 covers the normal single-challenge (and one stale-nonce
/// re-challenge) case while bounding a misconfigured-credentials loop.
const MAX_B2BUA_AUTH_RETRIES: u32 = 2;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
