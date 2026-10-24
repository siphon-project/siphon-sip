//! A P-CSCF's registrar liveness de-registering an idle protected binding with
//! `network_dereg`: the S-CSCF answers the de-REGISTER with a NOTIFY for the
//! UE's own reg-event subscription, which has to reach the UE over its
//! security associations (3GPP TS 24.229 clause 5.2.5.2: "the P-CSCF shall
//! shorten any security associations or TLS sessions towards the UE", NOTE 2:
//! "shortened to a value that will allow the NOTIFY request containing the
//! deregistration event to reach the UE"). So the pair is kept for a grace and
//! goes when the UE answers a NOTIFY or the grace is over. Once it is gone a
//! request to the UE's protected ports is refused at egress, never sent in
//! clear from a plaintext listener (TS 33.203 clause 7.1).
//!
//! Before: the pair was deleted a millisecond after the de-REGISTER left, and
//! the NOTIFY went to the UE's protected server port in clear.

use std::net::SocketAddr;
use std::time::Duration;

use super::ipsec_lifecycle_tests::{install, p_cscf, ANSWER};
use super::ipsec_request_flow_tests::{
    addr, assert_over_port_pc_to_port_us, drain, relay, terminating,
};
use super::*;

const AOR: &str = "sip:001010000000001@ims.example.invalid";

/// The UE's binding as a P-CSCF caches it: registered from its protected
/// client port, over UDP, with a flow token (what makes it a proxy cache
/// binding that `network_dereg` de-registers upstream).
fn registrar_with_binding(ue: SocketAddr) -> Arc<crate::registrar::Registrar> {
    let registrar = Arc::new(crate::registrar::Registrar::default());
    registrar
        .save_full(
            AOR,
            crate::sip::parser::parse_uri_standalone(&format!(
                "sip:001010000000001@{}:{}",
                ue.ip(),
                ue.port() + 1
            ))
            .expect("a URI"),
            3600,
            1.0,
            "liveness-call".to_string(),
            1,
            Some(ue),
            Some(Transport::Udp),
            None,
            None,
            vec![],
            crate::registrar::FlowCapture {
                client_transport: None,
                flow_token: Some("tok-liveness".into()),
                inbound_local_addr: Some(addr("192.0.2.1:5060")),
                inbound_connection_id: None,
            },
            Vec::new(),
        )
        .expect("the binding is saved");
    registrar
}

/// Liveness gives up on the UE and de-registers it with `network_dereg`.
async fn liveness_gives_up(
    proxy_state: &DispatcherState,
    registrar: &Arc<crate::registrar::Registrar>,
    ue: SocketAddr,
    grace: Duration,
) {
    let contact = registrar.lookup(AOR).into_iter().next().expect("bound");
    let mut context = LivenessDeregCtx::from_state(proxy_state, Arc::clone(registrar));
    context.dereg_mode = crate::config::LivenessDeregMode::NetworkDereg;
    context.network_dereg_sa_grace = grace;
    liveness_dereg_contact(
        &context,
        AOR,
        &contact,
        Some(ue.port()),
        "ipsec idle (no OPTIONS answer, grace exhausted)",
    )
    .await;
    assert!(!registrar.is_registered(AOR), "the binding is gone");
}

async fn gone_within(
    manager: &crate::ipsec::IpsecManager,
    ue: SocketAddr,
    within: Duration,
) -> bool {
    let deadline = std::time::Instant::now() + within;
    while std::time::Instant::now() < deadline {
        if !manager.has_sa(&ue.ip(), ue.port()) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    !manager.has_sa(&ue.ip(), ue.port())
}

/// The NOTIFY reporting the de-registration leaves over the pair within the
/// grace; after it a request to the UE's protected server port is refused,
/// logged, counted, and nothing reaches the plaintext listener.
#[tokio::test(flavor = "multi_thread")]
async fn the_de_registration_notify_rides_the_pair_and_nothing_follows_in_clear() {
    crate::metrics::init().expect("the metrics registry builds");
    let (proxy, manager) = p_cscf(ANSWER);
    let ue = addr("198.51.100.130:6100");
    install(&manager, ue).await;
    let registrar = registrar_with_binding(ue);

    liveness_gives_up(&proxy.state, &registrar, ue, Duration::from_millis(400)).await;
    assert!(
        manager.has_sa(&ue.ip(), ue.port()),
        "the pair is kept for the de-registration NOTIFY"
    );
    let _ = drain(&proxy.udp);

    let notify = terminating("NOTIFY", ue, "dereg-130", ";tag=ue-tag");
    relay(&proxy, &notify, None);
    assert_over_port_pc_to_port_us(drain(&proxy.udp), ue, Method::Notify);

    assert!(
        gone_within(&manager, ue, Duration::from_secs(3)).await,
        "the pair goes once the grace is over"
    );
    assert!(
        !registrar.is_registered(AOR),
        "nothing brought the binding back"
    );

    let before = crate::metrics::ipsec::unprotected_sends_refused().expect("initialised");
    let port_us = SocketAddr::new(ue.ip(), ue.port() + 1);
    let late = OutboundMessage {
        connection_id: ConnectionId::default(),
        transport: Transport::Udp,
        destination: port_us,
        data: Bytes::from(notify.to_bytes()),
        source_local_addr: Some(addr("192.0.2.1:5060")),
        server_name: None,
        verify_server: None,
        followups: None,
    };
    let log = crate::log_capture::LogBuffer::default();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_max_level(tracing::Level::WARN)
        .with_writer(log.clone())
        .finish();
    let refused = tracing::subscriber::with_default(subscriber, || {
        tracing::callsite::rebuild_interest_cache();
        proxy
            .state
            .outbound
            .send_guarded(late, Some(&manager))
            .is_err()
    });
    let log = log.rendered();
    assert!(refused, "a request to the gone pair's port is refused");
    assert!(
        log.contains("WARN") && log.contains(&port_us.to_string()) && log.contains("6101"),
        "{log}"
    );
    assert!(
        drain(&proxy.udp).is_empty(),
        "nothing reached the plaintext listener"
    );
    assert!(crate::metrics::ipsec::unprotected_sends_refused().expect("initialised") > before);
}

/// The UE answering the NOTIFY ends its transaction: the pair goes then, not at
/// the end of the grace.
#[tokio::test(flavor = "multi_thread")]
async fn the_ue_answering_its_notify_ends_the_grace() {
    let (proxy, manager) = p_cscf(ANSWER);
    let ue = addr("198.51.100.131:6100");
    install(&manager, ue).await;
    let registrar = registrar_with_binding(ue);

    liveness_gives_up(&proxy.state, &registrar, ue, Duration::from_secs(60)).await;
    assert!(manager.has_sa(&ue.ip(), ue.port()));

    let port_us = SocketAddr::new(ue.ip(), ue.port() + 1);
    let raw = concat!(
        "SIP/2.0 200 OK\r\n",
        "Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-answer-131\r\n",
        "From: <sip:caller@ims.example.invalid>;tag=core-tag\r\n",
        "To: <sip:001010000000001@ims.example.invalid>;tag=ue-tag\r\n",
        "Call-ID: dereg-131\r\n",
        "CSeq: 2 NOTIFY\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    );
    let response = parse_sip_message_bytes(raw.as_bytes()).expect("the response parses");
    let inbound = InboundMessage {
        client_transport: None,
        connection_id: ConnectionId::default(),
        transport: Transport::Udp,
        local_addr: addr("192.0.2.1:5064"),
        remote_addr: port_us,
        data: Bytes::from(raw),
    };
    tokio::task::block_in_place(|| handle_response(inbound, response, 200, &proxy.state));
    assert!(
        gone_within(&manager, ue, Duration::from_secs(2)).await,
        "the pair goes once the UE answered its NOTIFY"
    );
}
