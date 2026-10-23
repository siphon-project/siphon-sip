//! Bindings restored without their security associations, driven against the
//! in-memory kernel and a backend restore: which bindings are dropped, what
//! they leave behind, and the egress refusal that keeps a UE's protected ports
//! from being reached in clear.

use super::*;
use std::net::{Ipv4Addr, SocketAddr};

use bytes::Bytes;

use crate::registrar::backend::{self, MemoryBackend, RegistrarBackend, StoredContact};
use crate::registrar::{FlowCapture, Registrar};
use crate::sip::uri::SipUri;
use crate::transport::{ConnectionId, OutboundMessage, OutboundRouter, Transport};

const PCSCF: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
const PORT_PC: u16 = 5064;
const PORT_PS: u16 = 5066;
const UE_PORT_C: u16 = 6100;
const UE_PORT_S: u16 = 6101;
const IMPU: &str = "sip:001010000000001@ims.example.com";

fn ue(last_octet: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(198, 51, 100, last_octet))
}

fn manager() -> IpsecManager {
    IpsecManager::with_mock_kernel()
}

fn pair(manager: &IpsecManager, ue_addr: IpAddr) -> SecurityAssociationPair {
    let (spi_pc, spi_ps) = manager.allocate_spi_pair().expect("room in the partition");
    SecurityAssociationPair {
        ue_addr,
        pcscf_addr: PCSCF,
        ue_port_c: UE_PORT_C,
        ue_port_s: UE_PORT_S,
        pcscf_port_c: PORT_PC,
        pcscf_port_s: PORT_PS,
        spi_uc: 80_000,
        spi_us: 90_000,
        spi_pc,
        spi_ps,
        ealg: EncryptionAlgorithm::Null,
        aalg: IntegrityAlgorithm::HmacSha1,
        encryption_key: String::new(),
        integrity_key: "00112233445566778899aabbccddeeff".to_string(),
        hard_lifetime_secs: Some(3600),
        protocol: SaProtocol::Any,
        expires_at: Instant::now(),
        created_at: Instant::now(),
        role: SaRole::PCscf,
        impi: None,
        security_server: None,
    }
}

/// What a previous process left in the backend: one binding of `IMPU` from
/// `ue_addr`, accepted on local port `local_port` (a protected port when it is
/// `PORT_PS`).
async fn previous_process_backend(ue_addr: IpAddr, local_port: u16) -> MemoryBackend {
    let previous = Registrar::default();
    previous
        .save_full(
            IMPU,
            SipUri::new(ue_addr.to_string())
                .with_user("001010000000001".to_string())
                .with_port(UE_PORT_S),
            3600,
            1.0,
            "call-1".into(),
            1,
            Some(SocketAddr::new(ue_addr, UE_PORT_C)),
            Some(Transport::Udp),
            None,
            None,
            vec![],
            FlowCapture {
                client_transport: None,
                flow_token: Some("tok-1".into()),
                inbound_local_addr: Some(SocketAddr::new(PCSCF, local_port)),
                inbound_connection_id: None,
            },
            Vec::new(),
        )
        .expect("saved");
    let stored: Vec<StoredContact> = previous
        .lookup_all(IMPU)
        .iter()
        .map(StoredContact::from_contact)
        .collect();
    let store = MemoryBackend::new();
    store.save(IMPU, &stored).await.expect("stored");
    store
}

/// The restart: the registrar restored from `store` the way bootstrap does
/// it, with the write-through recorded.
async fn restored(store: &MemoryBackend) -> (Registrar, backend::RecordedWrites) {
    let registrar = Registrar::default();
    backend::restore_from_backend(store, &registrar)
        .await
        .expect("restored");
    let (writer, writes) = backend::recording_writer();
    registrar.set_backend_writer(writer);
    (registrar, writes)
}

fn options_to(destination: SocketAddr) -> OutboundMessage {
    let request = format!(
        "OPTIONS sip:001010000000001@{destination} SIP/2.0\r\n\
         Via: SIP/2.0/UDP 192.0.2.1:{PORT_PC};branch=z9hG4bK-1\r\n\
         Call-ID: probe-1\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n"
    );
    message_to(destination, request)
}

fn message_to(destination: SocketAddr, text: String) -> OutboundMessage {
    OutboundMessage {
        connection_id: ConnectionId::default(),
        transport: Transport::Udp,
        destination,
        data: Bytes::from(text),
        source_local_addr: None,
        server_name: None,
        verify_server: None,
        followups: None,
    }
}

fn router() -> (OutboundRouter, flume::Receiver<OutboundMessage>) {
    let (udp_tx, udp_rx) = flume::unbounded();
    let (tcp_tx, _) = flume::unbounded();
    let (tls_tx, _) = flume::unbounded();
    let (ws_tx, _) = flume::unbounded();
    let (wss_tx, _) = flume::unbounded();
    let router = OutboundRouter {
        udp: udp_tx.into(),
        udp_by_local: std::collections::HashMap::new(),
        udp_dynamic: None,
        tcp: tcp_tx,
        tls: tls_tx,
        ws: ws_tx,
        wss: wss_tx,
        sctp: None,
    };
    (router, udp_rx)
}

fn captured<T>(level: tracing::Level, work: impl FnOnce() -> T) -> (T, String) {
    let log = crate::log_capture::LogBuffer::default();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_max_level(level)
        .with_writer(log.clone())
        .finish();
    // A callsite another test thread reached first with no subscriber can stay
    // cached as disabled; re-evaluate interest once this scoped subscriber is
    // in place, or the WARN under test is silently filtered in a parallel run.
    let result = tracing::subscriber::with_default(subscriber, || {
        tracing::callsite::rebuild_interest_cache();
        work()
    });
    (result, log.rendered())
}

/// The defect: a protected binding restored with no SA pair behind it. It is
/// not live afterwards (no lookup, no flow token, nothing for the liveness
/// sweep to probe), the backend forgets it, and the drop is logged and counted.
#[tokio::test]
async fn a_protected_binding_restored_without_its_sas_is_dropped() {
    crate::metrics::init().expect("the metrics registry builds");
    let ue_addr = ue(10);
    let store = previous_process_backend(ue_addr, PORT_PS).await;
    let (registrar, mut writes) = restored(&store).await;
    assert_eq!(
        registrar.lookup(IMPU).len(),
        1,
        "the restore brought it back"
    );
    let manager = manager();
    let before = crate::metrics::ipsec::restored_without_sa().expect("initialised");

    let (dropped, log) = captured(tracing::Level::WARN, || {
        manager.drop_restored_bindings_without_sa(&registrar, PORT_PC, PORT_PS)
    });

    assert_eq!(dropped, 1);
    assert!(
        log.contains("WARN") && log.contains(IMPU) && log.contains("198.51.100.10"),
        "{log}"
    );
    assert!(
        crate::metrics::ipsec::restored_without_sa().expect("initialised") > before,
        "counted"
    );
    // A terminating request finds no binding, by AoR or by Path token, so the
    // registrar path answers it as for an unregistered user.
    assert!(registrar.lookup(IMPU).is_empty());
    assert!(registrar.lookup_by_token("tok-1").is_none());
    assert!(!registrar.is_registered(IMPU));
    // Nothing is left for the liveness sweep: it walks the bindings against
    // the manager's SA rows, and there are neither.
    assert!(registrar.all_contacts().is_empty());
    assert!(manager.liveness_snapshot().is_empty());
    assert_eq!(manager.active_count(), 0);
    // The backend is told, so the next restore does not bring it back.
    assert_eq!(writes.drain(), vec![format!("remove {IMPU}")]);
    // Both UE protected ports are barred from requests in clear.
    assert_eq!(manager.orphaned_flow_count(), 2);
}

/// A protected binding whose SA pair the manager does hold is restored as
/// before.
#[tokio::test]
async fn a_protected_binding_with_its_sa_pair_is_kept() {
    let ue_addr = ue(11);
    let store = previous_process_backend(ue_addr, PORT_PS).await;
    let (registrar, mut writes) = restored(&store).await;
    let manager = manager();
    manager
        .create_sa_pair(pair(&manager, ue_addr))
        .await
        .expect("installed");

    assert_eq!(
        manager.drop_restored_bindings_without_sa(&registrar, PORT_PC, PORT_PS),
        0
    );
    assert_eq!(registrar.lookup(IMPU).len(), 1);
    assert!(registrar.lookup_by_token("tok-1").is_some());
    assert!(writes.drain().is_empty());
    assert_eq!(manager.orphaned_flow_count(), 0);
}

/// A binding that never was protected is restored as before.
#[tokio::test]
async fn an_unprotected_binding_is_kept() {
    let store = previous_process_backend(ue(12), 5060).await;
    let (registrar, mut writes) = restored(&store).await;
    let manager = manager();

    assert_eq!(
        manager.drop_restored_bindings_without_sa(&registrar, PORT_PC, PORT_PS),
        0
    );
    assert_eq!(registrar.lookup(IMPU).len(), 1);
    assert!(writes.drain().is_empty());
    assert_eq!(manager.orphaned_flow_count(), 0);
}

/// Defence in depth: whatever path still targets the UE's protected server
/// port, the request is refused at egress, logged at ERROR, and never queued
/// for the wire.
#[tokio::test]
async fn a_request_to_a_barred_protected_port_never_leaves_in_clear() {
    crate::metrics::init().expect("the metrics registry builds");
    let ue_addr = ue(13);
    let store = previous_process_backend(ue_addr, PORT_PS).await;
    let (registrar, _writes) = restored(&store).await;
    let manager = manager();
    manager.drop_restored_bindings_without_sa(&registrar, PORT_PC, PORT_PS);
    let (router, wire) = router();
    let before = crate::metrics::ipsec::unprotected_sends_refused().expect("initialised");

    for port in [UE_PORT_S, UE_PORT_C] {
        let destination = SocketAddr::new(ue_addr, port);
        let (refused, log) = captured(tracing::Level::ERROR, || {
            router
                .send_guarded(options_to(destination), Some(&manager))
                .is_err()
        });
        assert!(refused, "refused to {destination}");
        assert!(
            log.contains("ERROR") && log.contains(&destination.to_string()),
            "{log}"
        );
    }
    assert!(wire.try_recv().is_err(), "nothing reached the transport");
    assert!(crate::metrics::ipsec::unprotected_sends_refused().expect("initialised") >= before + 2);
    // Another destination is untouched.
    router
        .send_guarded(
            options_to(SocketAddr::new(ue(99), UE_PORT_S)),
            Some(&manager),
        )
        .expect("sent");
    assert!(wire.try_recv().is_ok());
}

/// The UE's recovery is an unprotected initial REGISTER; the response to it
/// goes back unprotected, as TS 33.203 has it, so responses are not refused.
#[tokio::test]
async fn a_response_to_a_barred_port_is_sent() {
    let ue_addr = ue(14);
    let store = previous_process_backend(ue_addr, PORT_PS).await;
    let (registrar, _writes) = restored(&store).await;
    let manager = manager();
    manager.drop_restored_bindings_without_sa(&registrar, PORT_PC, PORT_PS);
    let (router, wire) = router();
    let response = "SIP/2.0 401 Unauthorized\r\n\
                    Via: SIP/2.0/UDP 198.51.100.14:6100;branch=z9hG4bK-2\r\n\
                    Call-ID: reg-1\r\nCSeq: 1 REGISTER\r\nContent-Length: 0\r\n\r\n";

    router
        .send_guarded(
            message_to(SocketAddr::new(ue_addr, UE_PORT_C), response.to_string()),
            Some(&manager),
        )
        .expect("sent");
    assert!(wire.try_recv().is_ok());
}

/// Once the UE has registered again over a new SA pair on the same ports, the
/// bar lifts: requests go out over that pair, and the endpoint is forgotten.
#[tokio::test]
async fn a_new_sa_pair_lifts_the_bar() {
    let ue_addr = ue(15);
    let store = previous_process_backend(ue_addr, PORT_PS).await;
    let (registrar, _writes) = restored(&store).await;
    let manager = manager();
    manager.drop_restored_bindings_without_sa(&registrar, PORT_PC, PORT_PS);
    manager
        .create_sa_pair(pair(&manager, ue_addr))
        .await
        .expect("installed");
    let (router, wire) = router();

    router
        .send_guarded(
            options_to(SocketAddr::new(ue_addr, UE_PORT_S)),
            Some(&manager),
        )
        .expect("sent");
    assert!(wire.try_recv().is_ok());
    assert_eq!(
        manager.orphaned_flow_count(),
        1,
        "the other port is still held"
    );
}

/// The bar lasts as long as the binding would have, and the sweep drains it.
#[test]
fn the_sweep_forgets_endpoints_past_their_binding() {
    let manager = manager();
    let past = Instant::now()
        .checked_sub(Duration::from_secs(1))
        .unwrap_or_else(Instant::now);
    manager
        .orphaned_flows
        .endpoints
        .insert(SocketAddr::new(ue(16), UE_PORT_S), past);
    manager.orphaned_flows.endpoints.insert(
        SocketAddr::new(ue(16), UE_PORT_C),
        Instant::now() + Duration::from_secs(60),
    );

    manager.prune_orphaned_flows();

    assert_eq!(manager.orphaned_flow_count(), 1);
}
