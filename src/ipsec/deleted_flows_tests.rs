//! A request to a UE port of a pair the manager deleted, for any reason, is
//! refused at egress while no pair covers that port (TS 33.203 clause 7.1):
//! logged at WARN with the UE and its ports, counted, never handed to a
//! transport. Responses still go. The record drains.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use bytes::Bytes;

use super::*;
use crate::transport::{ConnectionId, OutboundMessage, OutboundRouter, Transport};

const PCSCF: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

fn ue(last_octet: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(198, 51, 100, last_octet))
}

fn pair(manager: &IpsecManager, ue_addr: IpAddr, ue_port_c: u16) -> SecurityAssociationPair {
    let (spi_pc, spi_ps) = manager.allocate_spi_pair().expect("room in the partition");
    SecurityAssociationPair {
        ue_addr,
        pcscf_addr: PCSCF,
        ue_port_c,
        ue_port_s: ue_port_c + 1,
        pcscf_port_c: 5064,
        pcscf_port_s: 5066,
        spi_uc: 80_000 + u32::from(ue_port_c),
        spi_us: 90_000 + u32::from(ue_port_c),
        spi_pc,
        spi_ps,
        ealg: EncryptionAlgorithm::Null,
        aalg: IntegrityAlgorithm::HmacSha1,
        encryption_key: String::new(),
        integrity_key: "00112233445566778899aabbccddeeff".to_string(),
        hard_lifetime_secs: Some(3600),
        protocol: SaProtocol::Any,
        expires_at: Instant::now() + Duration::from_secs(3600),
        created_at: Instant::now(),
        role: SaRole::PCscf,
        impi: Some("001010000000001@ims.example.invalid".to_string()),
        security_server: None,
    }
}

fn router() -> (OutboundRouter, flume::Receiver<OutboundMessage>) {
    let (udp, wire) = flume::unbounded();
    let (other, _) = flume::unbounded();
    (
        OutboundRouter {
            udp: udp.into(),
            udp_by_local: std::collections::HashMap::new(),
            udp_dynamic: None,
            tcp: other.clone(),
            tls: other.clone(),
            ws: other.clone(),
            wss: other,
            sctp: None,
        },
        wire,
    )
}

fn to(destination: SocketAddr, text: &str) -> OutboundMessage {
    OutboundMessage {
        connection_id: ConnectionId::default(),
        transport: Transport::Udp,
        destination,
        data: Bytes::from(text.to_string()),
        source_local_addr: None,
        server_name: None,
        verify_server: None,
        followups: None,
    }
}

const BYE: &str = "BYE sip:ue@198.51.100.140:6101 SIP/2.0\r\nCall-ID: d-1\r\nCSeq: 3 BYE\r\nContent-Length: 0\r\n\r\n";
const OK: &str = "SIP/2.0 200 OK\r\nCall-ID: d-1\r\nCSeq: 3 BYE\r\nContent-Length: 0\r\n\r\n";

/// A pair deleted for a reason of its own (a de-REGISTER, the expiry sweep),
/// then an in-dialog request toward the UE: refused to both of its ports.
#[tokio::test]
async fn an_in_dialog_request_to_a_deleted_pairs_port_is_refused() {
    crate::metrics::init().expect("the metrics registry builds");
    let manager = IpsecManager::with_mock_kernel();
    let ue_addr = ue(140);
    manager
        .create_sa_pair(pair(&manager, ue_addr, 6100))
        .await
        .expect("installed");
    let (router, wire) = router();
    router
        .send_guarded(to(SocketAddr::new(ue_addr, 6101), BYE), Some(&manager))
        .expect("over a live pair it is sent");
    assert!(wire.try_recv().is_ok());

    manager
        .delete_sa_pair(&ue_addr, 6100)
        .await
        .expect("deleted");
    let before = crate::metrics::ipsec::unprotected_sends_refused().expect("initialised");
    for port in [6101, 6100] {
        let destination = SocketAddr::new(ue_addr, port);
        let log = crate::log_capture::LogBuffer::default();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_max_level(tracing::Level::WARN)
            .with_writer(log.clone())
            .finish();
        let refused = tracing::subscriber::with_default(subscriber, || {
            tracing::callsite::rebuild_interest_cache();
            router
                .send_guarded(to(destination, BYE), Some(&manager))
                .is_err()
        });
        let log = log.rendered();
        assert!(refused, "refused to {destination}");
        assert!(
            log.contains("WARN")
                && log.contains(&destination.to_string())
                && log.contains("001010000000001@ims.example.invalid"),
            "{log}"
        );
    }
    assert!(wire.try_recv().is_err(), "nothing reached the transport");
    assert!(crate::metrics::ipsec::unprotected_sends_refused().expect("initialised") >= before + 2);

    // A response still goes back where its request came from.
    router
        .send_guarded(to(SocketAddr::new(ue_addr, 6101), OK), Some(&manager))
        .expect("a response is sent");
    assert!(wire.try_recv().is_ok());
}

/// A new pair over the same port lifts the bar, and the record drains.
#[tokio::test]
async fn the_record_of_a_deleted_pair_drains() {
    let manager = IpsecManager::with_mock_kernel();
    let ue_addr = ue(141);
    manager
        .create_sa_pair(pair(&manager, ue_addr, 6100))
        .await
        .expect("installed");
    manager
        .delete_sa_pair(&ue_addr, 6100)
        .await
        .expect("deleted");
    assert_eq!(manager.deleted_flow_count(), 2);

    manager
        .create_sa_pair(pair(&manager, ue_addr, 6100))
        .await
        .expect("re-installed");
    let (router, wire) = router();
    router
        .send_guarded(to(SocketAddr::new(ue_addr, 6101), BYE), Some(&manager))
        .expect("a live pair covers the port again");
    assert!(wire.try_recv().is_ok());
    assert_eq!(
        manager.deleted_flow_count(),
        1,
        "the covered port is forgotten"
    );

    manager
        .deleted_flows
        .prune(Instant::now() + Duration::from_secs(48 * 60 * 60));
    assert_eq!(manager.deleted_flow_count(), 0, "drained");
}

/// Shortened for a network de-registration: kept until the grace is over, or
/// until the UE answers a NOTIFY; the waiting entry drains either way.
#[tokio::test(flavor = "multi_thread")]
async fn a_network_de_registration_keeps_the_pair_for_its_grace_only() {
    let manager = Arc::new(IpsecManager::with_mock_kernel());
    let ue_addr = ue(142);
    manager
        .create_sa_pair(pair(&manager, ue_addr, 6100))
        .await
        .expect("installed");
    assert!(manager.shorten_for_network_dereg(ue_addr, 6100, Duration::from_millis(200)));
    assert!(manager.has_sa(&ue_addr, 6100));
    let deadline = Instant::now() + Duration::from_secs(3);
    while manager.has_sa(&ue_addr, 6100) && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(!manager.has_sa(&ue_addr, 6100), "gone after the grace");
    assert_eq!(manager.network_dereg.len(), 0, "drained");

    let other = ue(143);
    manager
        .create_sa_pair(pair(&manager, other, 6100))
        .await
        .expect("installed");
    assert!(manager.shorten_for_network_dereg(other, 6100, Duration::from_secs(60)));
    assert!(
        !manager.notify_answered(SocketAddr::new(ue(99), 6101)),
        "another UE"
    );
    assert!(manager.notify_answered(SocketAddr::new(other, 6101)));
    let deadline = Instant::now() + Duration::from_secs(3);
    while manager.has_sa(&other, 6100) && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        !manager.has_sa(&other, 6100),
        "gone once the NOTIFY was answered"
    );
    assert_eq!(manager.network_dereg.len(), 0, "drained");
}
