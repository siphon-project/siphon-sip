//! When a UE's security associations go, driven against the in-memory kernel:
//! scheduled retirement and what it re-checks when due, the registrar
//! reconciliation that carries a network-initiated de-registration or an
//! expiry to the associations, the old pair of a re-registration, the
//! connections a pair carried, and kernel objects two pairs of one UE share.
//!
//! The registrar is the process one (`test_registrar`), shared by every test in
//! the binary, so each test uses UE addresses of its own.

use super::retire::{RetireCondition, SA_RETIRE_GRACE};
use super::*;
use std::net::{Ipv4Addr, SocketAddr};

use crate::transport::disconnect::{close_peer, ConnectionCloser};
use crate::transport::{ConnectionId, Transport};

const PCSCF: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
const DELAY: Duration = Duration::from_secs(5);

fn ue(last_octet: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(198, 51, 100, last_octet))
}

fn manager() -> Arc<IpsecManager> {
    Arc::new(IpsecManager::with_mock_kernel())
}

/// A P-CSCF pair for the UE's ports, with the P-CSCF SPIs the manager hands
/// out and UE SPIs of its own per client port.
fn pair(
    manager: &IpsecManager,
    ue_addr: IpAddr,
    ue_port_c: u16,
    ue_port_s: u16,
) -> SecurityAssociationPair {
    let (spi_pc, spi_ps) = manager.allocate_spi_pair().expect("room in the partition");
    SecurityAssociationPair {
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
    }
}

async fn install(
    manager: &IpsecManager,
    ue_addr: IpAddr,
    ue_port_c: u16,
    ue_port_s: u16,
) -> SecurityAssociationPair {
    let sa = pair(manager, ue_addr, ue_port_c, ue_port_s);
    manager.create_sa_pair(sa.clone()).await.expect("installed");
    // Distinct install instants, as two REGISTERs a round trip apart have.
    std::thread::sleep(std::time::Duration::from_millis(2));
    manager.get_sa(&ue_addr, ue_port_c).expect("stored")
}

fn policy_key(
    source: IpAddr,
    source_port: u16,
    destination: IpAddr,
    destination_port: u16,
    direction: &str,
) -> String {
    format!("policy:{source}:{source_port}->{destination}:{destination_port}:{direction}")
}

/// The kernel keys of the four policies of `sa`.
fn policies(sa: &SecurityAssociationPair) -> [String; 4] {
    [
        policy_key(
            sa.ue_addr,
            sa.ue_port_c,
            sa.pcscf_addr,
            sa.pcscf_port_s,
            "in",
        ),
        policy_key(
            sa.pcscf_addr,
            sa.pcscf_port_s,
            sa.ue_addr,
            sa.ue_port_c,
            "out",
        ),
        policy_key(
            sa.pcscf_addr,
            sa.pcscf_port_c,
            sa.ue_addr,
            sa.ue_port_s,
            "out",
        ),
        policy_key(
            sa.ue_addr,
            sa.ue_port_s,
            sa.pcscf_addr,
            sa.pcscf_port_c,
            "in",
        ),
    ]
}

fn states(sa: &SecurityAssociationPair) -> Vec<String> {
    sa.state_keys()
        .iter()
        .map(|(destination, spi)| format!("sa:{destination}:{spi}"))
        .collect()
}

fn live(manager: &IpsecManager, key: &str) -> bool {
    manager.mock().live.contains(key)
}

fn nothing_left_of(manager: &IpsecManager, sa: &SecurityAssociationPair) -> bool {
    !manager.has_sa(&sa.ue_addr, sa.ue_port_c) && states(sa).iter().all(|key| !live(manager, key))
}

fn register_binding(aor: &str, from: SocketAddr) {
    crate::script::api::test_registrar()
        .save_with_source(
            aor,
            crate::sip::parser::parse_uri_standalone(&format!("sip:ue@{from}")).expect("a URI"),
            3600,
            1.0,
            format!("{aor}-call"),
            1,
            Some(from),
            Some(Transport::Udp),
        )
        .expect("the REGISTER is accepted");
}

/// Let every retirement due by `after` from now run.
async fn advance(after: Duration) {
    tokio::time::sleep(after).await;
    // The retirement task runs its kernel calls after its timer fires.
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
}

// ---------------------------------------------------------------------------
// Kernel objects two pairs of one UE share
// ---------------------------------------------------------------------------

/// The P-CSCF's protected ports are fixed and the UE keeps its protected
/// server port across a re-registration (TS 33.203 clause 7.4.0), so the old
/// and the new pair have one policy selector for SA #3 and #4. Deleting the
/// old pair after the new one is in use must leave those to the new one.
///
/// Before: the old pair's teardown deleted them, and every request the P-CSCF
/// sent the UE from then on left unprotected.
#[tokio::test]
async fn deleting_the_old_pair_leaves_the_new_pairs_shared_policies() {
    let manager = manager();
    let old = install(&manager, ue(10), 6100, 6101).await;
    let new = install(&manager, ue(10), 6200, 6101).await;

    manager
        .delete_sa_pair(&ue(10), 6100)
        .await
        .expect("deleted");

    assert!(nothing_left_of(&manager, &old));
    let [old_uc_in, old_uc_out, ..] = policies(&old);
    assert!(!live(&manager, &old_uc_in) && !live(&manager, &old_uc_out));
    for key in policies(&new) {
        assert!(live(&manager, &key), "the new pair lost {key}");
    }
    for key in states(&new) {
        assert!(live(&manager, &key), "the new pair lost {key}");
    }
}

/// The other way round: the new pair goes (its authentication failed, TS
/// 33.203 clause 7.4.2a) while the old one still protects. The shared policies
/// were the new pair's; the old pair's are put back.
#[tokio::test]
async fn deleting_the_newer_pair_gives_the_shared_policies_back_to_the_older() {
    let manager = manager();
    let old = install(&manager, ue(11), 6100, 6101).await;
    let new = install(&manager, ue(11), 6200, 6101).await;
    let [_, _, shared_out, shared_in] = policies(&old);

    manager.mock().ops.clear();
    manager
        .delete_sa_pair(&ue(11), 6200)
        .await
        .expect("deleted");

    assert!(nothing_left_of(&manager, &new));
    for key in policies(&old) {
        assert!(live(&manager, &key), "the old pair lost {key}");
    }
    let ops = manager.mock().ops.clone();
    for key in [shared_out, shared_in] {
        let deleted = ops
            .iter()
            .position(|op| *op == format!("del_policy {key}"))
            .expect("the new pair's version is deleted");
        let given_back = ops
            .iter()
            .position(|op| *op == format!("add_policy {key}"))
            .expect("the old pair's version is installed again");
        assert!(deleted < given_back, "{key}: delete, then give back");
    }
}

// ---------------------------------------------------------------------------
// Scheduled retirement
// ---------------------------------------------------------------------------

/// Not before its time, then everything: the pair, its kernel objects and the
/// connections with the UE's ports.
#[tokio::test(start_paused = true)]
async fn a_scheduled_pair_goes_when_due_with_its_connections() {
    let manager = manager();
    let sa = install(&manager, ue(20), 6100, 6101).await;
    let client = ConnectionCloser::register(
        ConnectionId(20_001),
        SocketAddr::new(ue(20), 6100),
        Transport::Tcp,
    );
    let server = ConnectionCloser::register_outbound(
        ConnectionId(20_002),
        SocketAddr::new(ue(20), 6101),
        Transport::Tcp,
    );

    assert!(manager.retire_pair(ue(20), 6100, DELAY, RetireCondition::Always, "a test"));
    advance(DELAY - Duration::from_millis(1)).await;
    assert!(manager.has_sa(&ue(20), 6100), "kept until it is due");

    advance(Duration::from_millis(1)).await;
    assert!(nothing_left_of(&manager, &sa));
    for key in policies(&sa) {
        assert!(!live(&manager, &key), "{key} left behind");
    }
    for closer in [&client, &server] {
        tokio::time::timeout(Duration::from_millis(1), closer.closed())
            .await
            .expect("a connection with the UE's ports is closed");
    }
    assert_eq!(manager.lifecycle.sizes(), (0, 0, 0));
}

/// Another public user identity of the UE still registered over the pair
/// keeps it (TS 33.203 clause 7.4.2a: "once all the associated IMPUs are
/// de-registered").
#[tokio::test(start_paused = true)]
async fn an_unregistered_retirement_spares_a_pair_a_binding_still_holds() {
    let manager = manager();
    install(&manager, ue(21), 6100, 6101).await;
    register_binding("sip:impu-21@example.invalid", SocketAddr::new(ue(21), 6100));

    assert!(manager.retire_pair(ue(21), 6100, DELAY, RetireCondition::Unregistered, "a test"));
    advance(DELAY).await;
    assert!(
        manager.has_sa(&ue(21), 6100),
        "a registration still holds it"
    );

    crate::script::api::test_registrar().remove_all("sip:impu-21@example.invalid");
    assert!(manager.retire_pair(ue(21), 6100, DELAY, RetireCondition::Unregistered, "a test"));
    advance(DELAY).await;
    assert!(!manager.has_sa(&ue(21), 6100), "nothing holds it now");
}

/// A pair re-created under the same UE address and port since is another
/// installation, and is not taken.
#[tokio::test(start_paused = true)]
async fn a_retirement_never_takes_a_pair_re_created_since() {
    let manager = manager();
    install(&manager, ue(22), 6100, 6101).await;
    assert!(manager.retire_pair(ue(22), 6100, DELAY, RetireCondition::Always, "a test"));

    let again = install(&manager, ue(22), 6100, 6101).await;
    advance(DELAY).await;
    let kept = manager
        .get_sa(&ue(22), 6100)
        .expect("the re-created pair stays");
    assert_eq!((kept.spi_pc, kept.spi_ps), (again.spi_pc, again.spi_ps));
}

/// Scheduling again never pushes a pair's deletion later; an earlier one
/// wins.
#[tokio::test(start_paused = true)]
async fn the_earliest_retirement_of_a_pair_wins() {
    let manager = manager();
    install(&manager, ue(23), 6100, 6101).await;
    assert!(manager.retire_pair(ue(23), 6100, DELAY, RetireCondition::Always, "a test"));
    assert!(!manager.retire_pair(ue(23), 6100, DELAY * 4, RetireCondition::Always, "a test"));
    assert!(manager.retire_pair(ue(23), 6100, DELAY / 5, RetireCondition::Always, "a test"));

    advance(DELAY / 5).await;
    assert!(!manager.has_sa(&ue(23), 6100));
    advance(DELAY * 4).await;
    assert_eq!(
        manager.lifecycle.sizes(),
        (0, 0, 0),
        "every schedule drained"
    );
}

/// `retire_ue_now` deletes every pair of the UE, or the one named, and no
/// other UE's.
#[tokio::test]
async fn retiring_a_ue_now_takes_its_pairs_only() {
    let manager = manager();
    install(&manager, ue(24), 6100, 6101).await;
    install(&manager, ue(24), 6200, 6201).await;
    install(&manager, ue(25), 6100, 6101).await;

    assert_eq!(manager.retire_ue_now(ue(24), Some(6200), "a test").await, 1);
    assert!(manager.has_sa(&ue(24), 6100));
    assert_eq!(manager.retire_ue_now(ue(24), None, "a test").await, 1);
    assert!(!manager.has_sa(&ue(24), 6100));
    assert!(manager.has_sa(&ue(25), 6100));
    assert_eq!(manager.retire_ue_now(ue(24), None, "a test").await, 0);
}

// ---------------------------------------------------------------------------
// The registrar reconciliation
// ---------------------------------------------------------------------------

/// The script removed the binding on a reg-event NOTIFY that ended the
/// registration (TS 24.229 clause 5.2.5.2): the next sweep shortens the pair
/// to the delay and then deletes it. A pair no binding was ever seen on (a
/// pending one, between the 401 and the 200) is left alone.
#[tokio::test(start_paused = true)]
async fn a_pair_whose_binding_left_the_registrar_is_retired_after_the_delay() {
    let manager = manager();
    let registered = install(&manager, ue(30), 6100, 6101).await;
    install(&manager, ue(31), 6100, 6101).await; // pending
    let aor = "sip:impu-30@example.invalid";
    register_binding(aor, SocketAddr::new(ue(30), 6100));

    assert_eq!(manager.reconcile_registrations(DELAY), 0);
    assert_eq!(manager.lifecycle.sizes().0, 1, "the registration is noted");

    crate::script::api::test_registrar().remove_all(aor);
    assert_eq!(manager.reconcile_registrations(DELAY), 1);
    assert_eq!(
        manager.reconcile_registrations(DELAY),
        0,
        "a later sweep does not reschedule it"
    );
    advance(DELAY - Duration::from_millis(1)).await;
    assert!(
        manager.has_sa(&ue(30), 6100),
        "the NOTIFY to the UE still gets through"
    );
    advance(Duration::from_millis(1)).await;
    assert!(nothing_left_of(&manager, &registered));
    assert!(
        manager.has_sa(&ue(31), 6100),
        "a pending pair is not touched"
    );
}

/// The UE registers again before the shortened pair is due: it is kept.
#[tokio::test(start_paused = true)]
async fn a_binding_back_before_the_delay_keeps_the_pair() {
    let manager = manager();
    install(&manager, ue(32), 6100, 6101).await;
    let aor = "sip:impu-32@example.invalid";
    register_binding(aor, SocketAddr::new(ue(32), 6100));
    manager.reconcile_registrations(DELAY);
    crate::script::api::test_registrar().remove_all(aor);
    assert_eq!(manager.reconcile_registrations(DELAY), 1);

    register_binding(aor, SocketAddr::new(ue(32), 6100));
    advance(DELAY).await;
    assert!(manager.has_sa(&ue(32), 6100));
}

// ---------------------------------------------------------------------------
// Re-registration
// ---------------------------------------------------------------------------

/// TS 33.203 clause 7.4.2a, after the 200 of a re-registration whose REGISTER
/// came protected: the old pair it came over stays until its pending
/// transactions can be done, every other old pair goes at once, and the new
/// pair keeps the policies it shares with the old.
///
/// Before: every old pair was deleted at once, and a transaction the UE had in
/// flight over the old one got its responses unprotected.
#[tokio::test(start_paused = true)]
async fn a_re_registration_keeps_the_pair_its_register_came_over_for_the_grace() {
    let manager = manager();
    let incomplete = install(&manager, ue(40), 6000, 6001).await;
    let old = install(&manager, ue(40), 6100, 6101).await;
    let new = install(&manager, ue(40), 6200, 6101).await;
    manager.record_predecessor(&ue(40), 6100, &["198.51.100.40:6200".to_string()]);
    let old_connection = ConnectionCloser::register(
        ConnectionId(40_001),
        SocketAddr::new(ue(40), 6100),
        Transport::Tcp,
    );
    let shared_connection = ConnectionCloser::register_outbound(
        ConnectionId(40_002),
        SocketAddr::new(ue(40), 6101),
        Transport::Tcp,
    );

    manager
        .supersede_pairs_for_ue(&ue(40), 6200, SA_RETIRE_GRACE)
        .await;
    assert!(
        nothing_left_of(&manager, &incomplete),
        "any other old pair goes now"
    );
    assert!(
        manager.has_sa(&ue(40), 6100),
        "the old pair stays for its transactions"
    );

    advance(SA_RETIRE_GRACE).await;
    assert!(nothing_left_of(&manager, &old));
    tokio::time::timeout(Duration::from_millis(1), old_connection.closed())
        .await
        .expect("the old client port's connection is closed");
    assert!(
        tokio::time::timeout(Duration::from_millis(1), shared_connection.closed())
            .await
            .is_err(),
        "the protected server port carries the new pair's connection now"
    );
    for key in policies(&new).iter().chain(states(&new).iter()) {
        assert!(live(&manager, key), "the new pair lost {key}");
    }
    assert_eq!(manager.lifecycle.sizes(), (0, 0, 0));
    close_peer(SocketAddr::new(ue(40), 6101), "test cleanup");
}

/// A REGISTER that came unprotected: the P-CSCF "assumes UE does not have
/// those old SAs" and removes them at once (clause 7.4.2a).
#[tokio::test]
async fn a_registration_that_came_unprotected_removes_every_old_pair_at_once() {
    let manager = manager();
    let old = install(&manager, ue(41), 6100, 6101).await;
    install(&manager, ue(41), 6200, 6201).await;

    manager
        .supersede_pairs_for_ue(&ue(41), 6200, SA_RETIRE_GRACE)
        .await;
    assert!(nothing_left_of(&manager, &old));
    assert!(manager.has_sa(&ue(41), 6200));
}

// ---------------------------------------------------------------------------
// Leak
// ---------------------------------------------------------------------------

/// Complete registration cycles — register, note the binding, re-register over
/// the old pair, de-register — leave every lifecycle store and the pair map
/// at their baseline.
#[tokio::test(start_paused = true)]
async fn lifecycle_stores_drain_after_complete_cycles() {
    let manager = manager();
    for cycle in 0..50u16 {
        let address = IpAddr::V4(Ipv4Addr::new(203, 0, 113, (cycle % 200) as u8 + 1));
        let first = 6100 + cycle;
        let second = 7100 + cycle;
        install(&manager, address, first, 6001).await;
        assert!(manager.note_registered(&address, first));
        install(&manager, address, second, 6001).await;
        manager.record_predecessor(&address, first, &[format!("{address}:{second}")]);
        manager
            .supersede_pairs_for_ue(&address, second, DELAY)
            .await;
        assert!(manager.note_registered(&address, second));
        assert!(manager.retire_pair(
            address,
            second,
            DELAY,
            RetireCondition::Unregistered,
            "a test"
        ));
    }
    advance(DELAY).await;
    assert_eq!(manager.active_count(), 0);
    assert_eq!(manager.lifecycle.sizes(), (0, 0, 0));
}
