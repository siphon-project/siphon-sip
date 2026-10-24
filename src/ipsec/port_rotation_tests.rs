//! A P-CSCF protected client port per authentication (TS 33.203 clauses 7.4.0
//! and 7.4.2a), on the in-memory kernel.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::retire::{Pending, SA_RETIRE_GRACE};
use super::{
    EncryptionAlgorithm, FlowToUe, IntegrityAlgorithm, IpsecManager, SaProtocol, SaRole,
    SecurityAssociationPair,
};

const POOL: [u16; 2] = [5064, 5068];

fn ip(text: &str) -> IpAddr {
    text.parse().expect("an IP literal")
}

fn socket(text: &str) -> SocketAddr {
    text.parse().expect("a socket address")
}

/// A P-CSCF pair of the UE at `ue`, server port 6101 (kept across
/// re-authentications, TS 33.203 clause 7.4.0), client port `ue_port_c`,
/// P-CSCF client port `pcscf_port_c`, SPIs from `spi_base`.
fn pair_of(ue: &str, ue_port_c: u16, pcscf_port_c: u16, spi_base: u32) -> SecurityAssociationPair {
    SecurityAssociationPair {
        ue_addr: ip(ue),
        pcscf_addr: ip("198.51.100.10"),
        ue_port_c,
        ue_port_s: 6101,
        pcscf_port_c,
        pcscf_port_s: 5066,
        spi_uc: spi_base,
        spi_us: spi_base + 1,
        spi_pc: spi_base + 2,
        spi_ps: spi_base + 3,
        ealg: EncryptionAlgorithm::Null,
        aalg: IntegrityAlgorithm::HmacSha1,
        encryption_key: String::new(),
        integrity_key: "00".repeat(20),
        hard_lifetime_secs: Some(240),
        protocol: SaProtocol::Any,
        expires_at: Instant::now(),
        created_at: Instant::now(),
        role: SaRole::PCscf,
        impi: None,
        security_server: None,
    }
}

/// Install the next pair of `ue` on port `ue_port_c`, with the protected
/// client port the manager picks out of `ports`.
async fn authenticate(
    manager: &IpsecManager,
    ue: &str,
    ue_port_c: u16,
    spi_base: u32,
    ports: &[u16],
) -> SecurityAssociationPair {
    let port = manager
        .pick_pcscf_port_c(&ip(ue), ports)
        .expect("a port to pick");
    let sa = pair_of(ue, ue_port_c, port, spi_base);
    manager.create_sa_pair(sa.clone()).await.expect("installed");
    // Distinct install instants, so "newest" is well defined.
    std::thread::sleep(Duration::from_millis(2));
    sa
}

fn policy_keys(sa: &SecurityAssociationPair) -> Vec<String> {
    super::kernel_objects::kernel_objects(sa)
        .iter()
        .filter_map(|object| match object {
            super::kernel_objects::KernelObject::Policy {
                source,
                source_port,
                destination,
                destination_port,
                direction,
                ..
            } => Some(format!(
                "policy:{source}:{source_port}->{destination}:{destination_port}:{}",
                super::policy_dir_str(*direction)
            )),
            super::kernel_objects::KernelObject::State { .. } => None,
        })
        .collect()
}

fn protected(local: &str, destination: &str) -> FlowToUe {
    FlowToUe::Protected {
        local: socket(local),
        destination: socket(destination),
    }
}

async fn advance(after: Duration) {
    tokio::time::sleep(after).await;
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
}

/// Two authentications of one UE take different protected client ports, so
/// the old and the new set hold disjoint policies (no shared template), each
/// naming its own SAs.
#[tokio::test]
async fn a_re_authentication_takes_another_client_port_and_shares_no_policy() {
    let manager = IpsecManager::with_test_kernel();
    let old = authenticate(&manager, "192.0.2.77", 6100, 70_000, &POOL).await;
    let new = authenticate(&manager, "192.0.2.77", 6102, 71_000, &POOL).await;
    assert_eq!(old.pcscf_port_c, 5064);
    assert_eq!(
        new.pcscf_port_c, 5068,
        "TS 33.203 clause 7.4.0: port_pc changes"
    );

    let (old_keys, new_keys) = (policy_keys(&old), policy_keys(&new));
    assert!(
        old_keys.iter().all(|key| !new_keys.contains(key)),
        "disjoint selectors: {old_keys:?} / {new_keys:?}"
    );
    assert_eq!(manager.test_kernel_live_count(), 16, "two sets of eight");
    let old_out = "policy:198.51.100.10:5064->192.0.2.77:6101:out";
    let new_out = "policy:198.51.100.10:5068->192.0.2.77:6101:out";
    assert_eq!(
        manager.test_kernel_policy_template(old_out),
        Some(old.spi_us)
    );
    assert_eq!(
        manager.test_kernel_policy_template(new_out),
        Some(new.spi_us)
    );
    // Each set's SA #4 accepts only its own SAs on its own port.
    assert!(manager.test_kernel_accepts_inbound(
        socket("192.0.2.77:6101"),
        socket("198.51.100.10:5068"),
        new.spi_pc
    ));
    assert_eq!(
        manager.pending_how(&new.ue_addr, 6102),
        Some(Pending::Challenged)
    );
    assert_eq!(manager.pending_how(&old.ue_addr, 6100), None);
}

/// Ports may repeat across UEs (clause 7.1 rule 3 is per UE address).
#[tokio::test]
async fn another_ue_reuses_a_client_port() {
    let manager = IpsecManager::with_test_kernel();
    let first = authenticate(&manager, "192.0.2.77", 6100, 70_000, &POOL).await;
    let other = authenticate(&manager, "192.0.2.78", 6100, 72_000, &POOL).await;
    assert_eq!(first.pcscf_port_c, 5064);
    assert_eq!(other.pcscf_port_c, 5064);
    assert_eq!(manager.pending_how(&other.ue_addr, 6100), None);
}

/// A single port is always that port: the 1.15.3 shared-policy path.
#[tokio::test]
async fn a_single_port_is_shared_as_before() {
    let manager = IpsecManager::with_test_kernel();
    let old = authenticate(&manager, "192.0.2.77", 6100, 70_000, &[5064]).await;
    let new = authenticate(&manager, "192.0.2.77", 6102, 71_000, &[5064]).await;
    assert_eq!((old.pcscf_port_c, new.pcscf_port_c), (5064, 5064));
    assert_eq!(
        manager.pending_how(&new.ue_addr, 6102),
        Some(Pending::SharedPolicy)
    );
    assert_eq!(
        manager.test_kernel_policy_template("policy:198.51.100.10:5064->192.0.2.77:6101:out"),
        Some(old.spi_us),
        "the shared outbound policy still names the set in use"
    );
    assert_eq!(manager.pick_pcscf_port_c(&ip("192.0.2.77"), &[]), None);
}

/// With every port held by the UE, a port no pair in use holds is shared.
#[tokio::test]
async fn a_full_pool_shares_the_port_of_a_pair_not_in_use() {
    let manager = IpsecManager::with_test_kernel();
    authenticate(&manager, "192.0.2.77", 6100, 70_000, &POOL).await;
    authenticate(&manager, "192.0.2.77", 6102, 71_000, &POOL).await;
    assert_eq!(
        manager.pick_pcscf_port_c(&ip("192.0.2.77"), &POOL),
        Some(5068),
        "5068 is held by the pending pair only"
    );
}

/// The 401 to a re-authentication goes over the old set (the response to the
/// REGISTER from the old client port), the 200 over the new (the response to
/// the REGISTER from the new one); requests to the UE stay on the old set
/// until a message arrives over the new, then move, and the old set goes
/// after 64*T1 (TS 33.203 clause 7.4.2a).
#[tokio::test(start_paused = true)]
async fn requests_move_to_the_new_set_once_a_message_arrives_over_it() {
    let manager = Arc::new(IpsecManager::with_test_kernel());
    let old = authenticate(&manager, "192.0.2.77", 6100, 70_000, &POOL).await;
    let new = authenticate(&manager, "192.0.2.77", 6102, 71_000, &POOL).await;
    let ue = old.ue_addr;
    let (old_flow, new_flow) = (
        protected("198.51.100.10:5064", "192.0.2.77:6101"),
        protected("198.51.100.10:5068", "192.0.2.77:6101"),
    );

    // SM6 answers the REGISTER from 6100, SM12 the one from 6102.
    assert_eq!(manager.udp_flow_to_ue(socket("192.0.2.77:6100")), old_flow);
    assert_eq!(manager.udp_flow_to_ue(socket("192.0.2.77:6102")), new_flow);
    // A request over the new flow, before it is in use, takes the old set.
    for destination in ["192.0.2.77:6100", "192.0.2.77:6102"] {
        assert_eq!(
            manager.udp_request_flow_to_ue(socket(destination)),
            old_flow
        );
        assert_eq!(manager.tcp_flow_to_ue(socket(destination)), old_flow);
    }
    assert_eq!(
        manager.find_sa_by_ue(&ue, 6101).map(|sa| sa.pcscf_port_c),
        Some(5064)
    );

    // SM7 itself, before the 2xx, takes nothing into use.
    manager.note_protected_inbound(socket("192.0.2.77:6102"), 5066);
    assert_eq!(manager.pending_how(&ue, 6102), Some(Pending::Challenged));

    assert!(manager.confirm_registration(&ue, 6102));
    assert_eq!(manager.pending_how(&ue, 6102), Some(Pending::Registered));
    assert_eq!(
        manager.udp_request_flow_to_ue(socket("192.0.2.77:6102")),
        old_flow
    );
    // A message over another UE's pair, or the old set, moves nothing.
    manager.note_protected_inbound(socket("192.0.2.77:6100"), 5066);
    manager.note_protected_inbound(socket("192.0.2.77:6101"), 5064);
    assert_eq!(manager.pending_how(&ue, 6102), Some(Pending::Registered));

    // A further message over the new inbound SA #1.
    manager.note_protected_inbound(socket("192.0.2.77:6102"), 5066);
    assert_eq!(manager.pending_how(&ue, 6102), None);
    assert_eq!(
        manager.udp_request_flow_to_ue(socket("192.0.2.77:6102")),
        new_flow
    );
    assert_eq!(
        manager.find_sa_by_ue(&ue, 6101).map(|sa| sa.pcscf_port_c),
        Some(5068)
    );
    assert_eq!(manager.lifecycle.sizes().2, 1, "the old set is shortened");

    advance(SA_RETIRE_GRACE / 2).await;
    assert!(
        manager.has_sa(&ue, 6100),
        "kept for its pending transactions"
    );
    advance(SA_RETIRE_GRACE).await;
    assert!(!manager.has_sa(&ue, 6100));
    assert!(manager.has_sa(&ue, new.ue_port_c));
    assert_eq!(manager.test_kernel_live_count(), 8, "the new set's eight");
}

/// A response over the new set's SA #4 (port_us -> its own port_pc) counts.
#[tokio::test(start_paused = true)]
async fn a_response_over_the_new_client_port_takes_it_into_use() {
    let manager = Arc::new(IpsecManager::with_test_kernel());
    authenticate(&manager, "192.0.2.77", 6100, 70_000, &POOL).await;
    authenticate(&manager, "192.0.2.77", 6102, 71_000, &POOL).await;
    let ue = ip("192.0.2.77");
    manager.confirm_registration(&ue, 6102);
    manager.note_protected_inbound(socket("192.0.2.77:6101"), 5068);
    assert_eq!(manager.pending_how(&ue, 6102), None);
}

/// "When the old SAs expire without a further SIP message protected by the
/// new SAs, the new SAs are taken into use for outbound messages."
#[tokio::test]
async fn the_old_set_going_takes_the_registered_one_into_use() {
    let manager = Arc::new(IpsecManager::with_test_kernel());
    authenticate(&manager, "192.0.2.77", 6100, 70_000, &POOL).await;
    authenticate(&manager, "192.0.2.77", 6102, 71_000, &POOL).await;
    let ue = ip("192.0.2.77");
    manager.confirm_registration(&ue, 6102);
    manager.delete_sa_pair(&ue, 6100).await.expect("deleted");
    assert_eq!(manager.pending_how(&ue, 6102), None);
    assert_eq!(manager.lifecycle.registered_pending_len(), 0);
    assert_eq!(
        manager.udp_request_flow_to_ue(socket("192.0.2.77:6102")),
        protected("198.51.100.10:5068", "192.0.2.77:6101")
    );
}

/// A 2xx with no set in use left beside the pair takes it into use at once;
/// `take_into_use` on a pair with its own port retires the old set.
#[tokio::test(start_paused = true)]
async fn confirming_with_no_old_set_or_taking_into_use_needs_no_traffic() {
    let manager = Arc::new(IpsecManager::with_test_kernel());
    authenticate(&manager, "192.0.2.77", 6100, 70_000, &POOL).await;
    authenticate(&manager, "192.0.2.77", 6102, 71_000, &POOL).await;
    let ue = ip("192.0.2.77");
    manager.delete_sa_pair(&ue, 6100).await.expect("deleted");
    assert!(manager.confirm_registration(&ue, 6102));
    assert_eq!(manager.pending_how(&ue, 6102), None);

    authenticate(&manager, "192.0.2.77", 6104, 72_000, &POOL).await;
    assert_eq!(manager.pending_how(&ue, 6104), Some(Pending::Challenged));
    assert!(manager.take_into_use(&ue, 6104).await.expect("taken"));
    assert_eq!(manager.pending_how(&ue, 6104), None);
    advance(SA_RETIRE_GRACE * 2).await;
    assert!(!manager.has_sa(&ue, 6102), "the old set went after 64*T1");
    assert!(manager.has_sa(&ue, 6104));
}

/// Deleting the old set closes the connection the P-CSCF opened from its own
/// protected client port, and leaves the new set's, on the same UE server
/// port, open.
#[tokio::test]
async fn deleting_the_old_set_closes_only_its_own_client_port_connection() {
    use crate::transport::disconnect::ConnectionCloser;
    use crate::transport::{ConnectionId, Transport};

    let manager = Arc::new(IpsecManager::with_test_kernel());
    let ue = "192.0.2.79";
    authenticate(&manager, ue, 6100, 70_000, &POOL).await;
    authenticate(&manager, ue, 6102, 71_000, &POOL).await;
    let peer = socket("192.0.2.79:6101");
    let spawn = |id: u64, local_port: u16| {
        let closer = ConnectionCloser::register_outbound(
            ConnectionId(id),
            peer,
            Transport::Tcp,
            Some(local_port),
        );
        tokio::spawn(async move { closer.closed().await })
    };
    let old_connection = spawn(990_001, 5064);
    let new_connection = spawn(990_002, 5068);

    manager
        .delete_sa_pair(&ip(ue), 6100)
        .await
        .expect("deleted");
    tokio::time::timeout(Duration::from_secs(1), old_connection)
        .await
        .expect("the old set's connection closes")
        .expect("its task ends");
    tokio::task::yield_now().await;
    assert!(!new_connection.is_finished(), "the new set keeps its own");
    new_connection.abort();
}

/// Leak gate: re-authentication after re-authentication with a 2-port pool
/// alternates the ports, leaves one set's eight kernel objects, and drains to
/// nothing once the last goes.
#[tokio::test(start_paused = true)]
async fn repeated_re_authentications_alternate_ports_and_drain() {
    let manager = Arc::new(IpsecManager::with_test_kernel());
    let ue = ip("192.0.2.77");
    let first = authenticate(&manager, "192.0.2.77", 6100, 70_000, &POOL).await;
    let mut in_use = (6100, first.pcscf_port_c);
    for cycle in 1..=20u16 {
        let port_c = 6100 + 2 * cycle;
        let next = authenticate(
            &manager,
            "192.0.2.77",
            port_c,
            70_000 + 10 * u32::from(cycle),
            &POOL,
        )
        .await;
        assert_ne!(
            next.pcscf_port_c, in_use.1,
            "cycle {cycle}: port_pc changes"
        );
        assert!(manager.confirm_registration(&ue, port_c));
        manager.note_protected_inbound(SocketAddr::new(ue, port_c), 5066);
        advance(SA_RETIRE_GRACE * 2).await;
        assert!(!manager.has_sa(&ue, in_use.0), "cycle {cycle}");
        assert_eq!(manager.active_count(), 1);
        assert_eq!(manager.test_kernel_live_count(), 8);
        assert_eq!(manager.lifecycle.pending_len(), 0);
        in_use = (port_c, next.pcscf_port_c);
    }
    manager
        .delete_sa_pair(&ue, in_use.0)
        .await
        .expect("deleted");
    assert_eq!(manager.test_kernel_live_count(), 0);
    assert_eq!(manager.test_spi_owner_count(), 0);
    assert_eq!(manager.lifecycle.sizes(), (0, 0, 0));
    assert_eq!(manager.lifecycle.pending_len(), 0);
    assert_eq!(manager.lifecycle.registered_pending_len(), 0);
    assert!(manager.lifecycle.none_pending());
}

/// The egress points the dispatcher, the UAC and the outbound router send
/// through use the pair's own port_pc: a response from its request's set, a
/// request (UDP or TCP) from the set in use.
#[tokio::test]
async fn egress_paths_send_from_the_pairs_own_client_port() {
    use crate::transport::{ConnectionId, OutboundMessage, Transport};

    let manager = Arc::new(IpsecManager::with_test_kernel());
    authenticate(&manager, "192.0.2.77", 6100, 70_000, &POOL).await;
    authenticate(&manager, "192.0.2.77", 6102, 71_000, &POOL).await;
    let ue = ip("192.0.2.77");
    manager.confirm_registration(&ue, 6102);
    let from_port_ps = Some(socket("198.51.100.10:5066"));
    let to_port_us = socket("192.0.2.77:6101");
    let egress = |destination: &str, request: bool| {
        super::pcscf_udp_egress(
            &manager,
            5066,
            Transport::Udp,
            socket(destination),
            from_port_ps,
            request,
        )
    };
    let tcp_request = || {
        super::pcscf_tcp_request_egress(
            &manager,
            5066,
            OutboundMessage {
                connection_id: ConnectionId(7),
                transport: Transport::Tcp,
                destination: socket("192.0.2.77:6102"),
                data: bytes::Bytes::from_static(b"OPTIONS sip:ue@192.0.2.77 SIP/2.0\r\n\r\n"),
                source_local_addr: from_port_ps,
                server_name: None,
                verify_server: None,
                followups: None,
            },
        )
        .source_local_addr
    };

    assert_eq!(
        egress("192.0.2.77:6102", false),
        (to_port_us, Some(socket("198.51.100.10:5068"))),
        "a response to the new set's request leaves from its port_pc"
    );
    assert_eq!(
        egress("192.0.2.77:6102", true),
        (to_port_us, Some(socket("198.51.100.10:5064"))),
        "a request stays on the set in use"
    );
    assert_eq!(tcp_request(), Some(socket("198.51.100.10:5064")));

    manager.note_protected_inbound(socket("192.0.2.77:6102"), 5066);
    assert_eq!(
        egress("192.0.2.77:6102", true),
        (to_port_us, Some(socket("198.51.100.10:5068")))
    );
    assert_eq!(tcp_request(), Some(socket("198.51.100.10:5068")));
}
