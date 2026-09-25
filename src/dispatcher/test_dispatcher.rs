//! A [`DispatcherState`] for tests that drive the dispatcher's own send paths
//! and read back what went on the wire.
//!
//! Configured with no more than a B2BUA call needs: no script handlers unless the test passes a script, no media
//! engine, no charging. Its UDP egress is a channel the test reads, so a test
//! asserts on the bytes a peer would have been sent rather than on an
//! intermediate value.

use super::*;
use std::collections::HashMap;

/// A dispatcher under test and the receiving end of its UDP egress.
pub(super) struct TestDispatcher {
    pub(super) state: DispatcherState,
    pub(super) udp: flume::Receiver<OutboundMessage>,
}

/// Build a [`TestDispatcher`] bound to `192.0.2.1:5060`.
pub(super) fn test_dispatcher() -> TestDispatcher {
    test_dispatcher_with_script("")
}

/// [`test_dispatcher`] running `source` as its script, for a test that needs a
/// handler (`@b2bua.on_failure`, say) to run.
pub(super) fn test_dispatcher_with_script(source: &str) -> TestDispatcher {
    // The connection pool's TLS client config needs a process-wide provider.
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();

    let local_addr: SocketAddr = "192.0.2.1:5060".parse().expect("a literal address");
    let (udp_sender, udp) = flume::unbounded();
    let (stream_sender, _) = flume::unbounded();
    let outbound = Arc::new(OutboundRouter {
        udp: udp_sender.into(),
        udp_by_local: HashMap::new(),
        tcp: stream_sender.clone(),
        tls: stream_sender.clone(),
        ws: stream_sender.clone(),
        wss: stream_sender.clone(),
        sctp: stream_sender,
    });
    let timer_config = TimerConfig::default();
    let connection_pool = Arc::new(ConnectionPool::new(
        Arc::new(DashMap::new()),
        flume::unbounded().0,
        local_addr,
        None,
        None,
        None,
        crate::transport::pool::build_outbound_tls_config(
            None,
            crate::config::TlsMethod::default(),
        )
        .expect("an outbound TLS config"),
    ));
    let state = DispatcherState {
        engine: Arc::new(ScriptEngine::new_embedded(source).expect("the test script compiles")),
        outbound: Arc::clone(&outbound),
        local_domains: Arc::new(vec!["siphon.example.com".to_string()]),
        self_identity: Arc::new(crate::proxy::core::SelfIdentity::new()),
        local_addr,
        advertised_addrs: HashMap::new(),
        advertised_ports: HashMap::new(),
        listen_addrs: HashMap::new(),
        listener_registry: crate::transport::ListenerRegistry::from_entries(Vec::new()),
        mtu: None,
        server_header: None,
        auto_options: true,
        user_agent_header: None,
        transaction_timeout: std::time::Duration::from_secs(34),
        call_actors: Arc::new(CallActorStore::new()),
        transaction_manager: Arc::new(TransactionManager::new(timer_config)),
        timer_wheel: Arc::new(DashMap::new()),
        b2bua_retransmits: Arc::new(crate::b2bua::retransmit::B2buaRetransmits::new(
            timer_config,
        )),
        session_store: Arc::new(ProxySessionStore::new()),
        dns_resolver: Arc::new(SipResolver::from_system().expect("a system resolver")),
        hep_sender: None,
        uac_sender: Arc::new(UacSender::new(
            outbound,
            local_addr,
            HashMap::new(),
            HashMap::new(),
            None,
            None,
            None,
        )),
        rtpengine_set: None,
        rtpengine_sessions: None,
        rtpengine_profiles: None,
        control_inbound: None,
        session_timer_config: None,
        header_policy_registry: Arc::new(crate::b2bua::header_policy::builtin_presets()),
        default_header_policy: crate::b2bua::header_policy::default_preset(),
        default_refer_mode: crate::script::api::call::ReferMode::Terminate,
        accept_replaces: false,
        log_dial: false,
        default_max_call_duration_secs: None,
        // The production default, so a test that does not care about identity
        // still exercises the shape a deployment runs.
        assert_identity: true,
        registrant_manager: None,
        recording_manager: Arc::new(crate::siprec::RecordingManager::new("siphon", "test")),
        li_siprec_srs_uri: None,
        li_siprec_rtpengine_profile: None,
        srs_manager: None,
        ipsec_manager: None,
        ipsec_config: None,
        registrar_liveness: crate::config::RegistrarLivenessConfig::default(),
        liveness_last_seen: Arc::new(DashMap::new()),
        liveness_misses: Arc::new(DashMap::new()),
        connection_pool,
        stream_connections: StreamConnections::new(),
        nat_fix_contact: false,
        sdp_name: "siphon".to_string(),
        sdp_strip_attributes: Vec::new(),
        call_event_receivers: Arc::new(DashMap::new()),
        reliable_provisionals: Arc::new(DashMap::new()),
        uas_2xx_retransmits: Arc::new(DashMap::new()),
        held_byes: Arc::new(DashMap::new()),
        pending_reinvite_acks: Arc::new(DashMap::new()),
        cancelled_invites: Arc::new(DashMap::new()),
        is_draining: Arc::new(DrainState::new()),
        rf_charger: None,
        rf_sessions: Arc::new(DashMap::new()),
        rf_pending_starts: Arc::new(DashMap::new()),
        ro_charger: None,
        ro_sessions: Arc::new(DashMap::new()),
        cdr_sessions: Arc::new(DashMap::new()),
        pending_inbound_refer: Arc::new(PendingInboundReferStore::default()),
        deferred_referrer_bye: Arc::new(DeferredReferrerByeStore::default()),
        li_manager: None,
    };
    TestDispatcher { state, udp }
}
