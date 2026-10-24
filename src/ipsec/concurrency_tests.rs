//! The manager under concurrent REGISTER traffic: pairs installed, taken into
//! use, retired and deleted for UEs that share addresses (so their keys land in
//! the same map shards), while requests and responses to them go through the
//! egress checks and the switch hold. A guard of one of the manager's maps held
//! across a call back into the same map deadlocks silently, every thread parked
//! on the shard; so does a blocking wait on a thread the awaited work needs.
//! Bounded by a timeout, so a regression fails here instead of hanging.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use bytes::Bytes;

use super::retire::RetireCondition;
use super::*;
use crate::transport::{ConnectionId, OutboundMessage, OutboundRouter, Transport};

const PCSCF: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

fn pair(
    manager: &IpsecManager,
    ue_addr: IpAddr,
    ue_port_c: u16,
    ue_port_s: u16,
) -> Option<SecurityAssociationPair> {
    let (spi_pc, spi_ps) = manager.allocate_spi_pair().ok()?;
    Some(SecurityAssociationPair {
        ue_addr,
        pcscf_addr: PCSCF,
        ue_port_c,
        ue_port_s,
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
        expires_at: Instant::now(),
        created_at: Instant::now(),
        role: SaRole::PCscf,
        impi: None,
        security_server: None,
    })
}

fn router() -> (OutboundRouter, flume::Receiver<OutboundMessage>) {
    let (udp, received) = flume::unbounded::<OutboundMessage>();
    let (other, _) = flume::unbounded();
    (
        OutboundRouter {
            udp: udp.into(),
            udp_by_local: std::collections::HashMap::new(),
            udp_dynamic: None,
            tcp: other.clone(),
            tls: other.clone(),
            ws: other.clone(),
            wss: other.clone(),
            sctp: Some(other),
        },
        received,
    )
}

fn message(destination: SocketAddr, data: &'static [u8]) -> OutboundMessage {
    OutboundMessage {
        connection_id: ConnectionId(0),
        transport: Transport::Udp,
        destination,
        data: Bytes::from_static(data),
        source_local_addr: None,
        server_name: None,
        verify_server: None,
        followups: None,
    }
}

/// One UE's re-authentications: the set in use, a new pending pair beside it
/// sharing the protected server port, the new one taken into use with its
/// messages held, the old one retired, everything queried and sent to along
/// the way, and finally both deleted.
async fn churn(
    manager: Arc<IpsecManager>,
    outbound: Arc<OutboundRouter>,
    ue_addr: IpAddr,
    base: u16,
    rounds: u16,
) {
    for round in 0..rounds {
        let old_port = base + round * 4;
        let new_port = old_port + 2;
        let server_port = base + 1;
        let Some(old) = pair(&manager, ue_addr, old_port, server_port) else {
            continue;
        };
        let _ = manager.create_sa_pair(old).await;
        manager.note_registered(&ue_addr, old_port);
        let Some(new) = pair(&manager, ue_addr, new_port, server_port) else {
            continue;
        };
        let _ = manager.create_sa_pair(new).await;
        manager.record_predecessor(
            &ue_addr,
            old_port,
            &[IpsecManager::contact_key(&ue_addr, new_port)],
        );

        // The 2xx path: hold, switch, send, release.
        super::switch::hold(ue_addr);
        let _ = manager.is_pending(&ue_addr, new_port);
        let destination = SocketAddr::new(ue_addr, server_port);
        let _ = outbound.send_guarded(message(destination, b"SIP/2.0 200 OK\r\n"), Some(&manager));
        let _ = manager.take_into_use(&ue_addr, new_port).await;
        super::switch::unhold(ue_addr);
        while let Some(batch) = super::switch::release(ue_addr) {
            for held in batch {
                let _ = outbound.deliver(held);
            }
        }

        // Everything else that reads the maps while others write them.
        let _ =
            manager.refuses_unprotected_send(&message(destination, b"OPTIONS sip:ue SIP/2.0\r\n"));
        let _ = manager.find_sa_by_ue(&ue_addr, server_port);
        let _ = manager.has_sa(&ue_addr, old_port);
        let _ = manager.reconcile_registrations(Duration::from_millis(1));
        manager.retire_pair(
            ue_addr,
            old_port,
            Duration::from_millis(1),
            RetireCondition::Always,
            "stress",
        );
        manager
            .supersede_pairs_for_ue(&ue_addr, new_port, Duration::from_millis(1))
            .await;
        let _ = manager
            .update_sa_pair_lifetime(&ue_addr, new_port, Some(600))
            .await;
        let _ = manager.delete_sa_pair(&ue_addr, old_port).await;
        let _ = manager
            .retire_ue_now(ue_addr, Some(new_port), "stress")
            .await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_re_authentications_never_deadlock_the_manager() {
    let manager = Arc::new(IpsecManager::with_mock_kernel_partition(100_000, 8192));
    let (router, received) = router();
    let outbound = Arc::new(router);
    // Few UE addresses, many ports each: keys collide on shards.
    let mut tasks = Vec::new();
    for worker in 0..32u16 {
        let ue_addr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 200 + (worker % 4) as u8));
        let base = 10_000 + worker * 500;
        tasks.push(tokio::spawn(churn(
            Arc::clone(&manager),
            Arc::clone(&outbound),
            ue_addr,
            base,
            25,
        )));
    }
    let all = async {
        for task in tasks {
            task.await.expect("a churn task panicked");
        }
    };
    tokio::time::timeout(Duration::from_secs(60), all)
        .await
        .expect("the manager deadlocked under concurrent REGISTER traffic");

    // Every held 2xx went out once its switch was over.
    let sent = received.try_iter().count();
    assert!(sent > 0, "the held responses were sent");
    for octet in 200..204u8 {
        assert!(!super::switch::is_held(IpAddr::V4(Ipv4Addr::new(
            198, 51, 100, octet
        ))));
    }
}
