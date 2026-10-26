//! A pair is deleted by the installation it is (its SPIs), not by the UE's
//! address and protected client port, wherever the caller holds a particular
//! installation: the pending-pair cleanups, a retirement, the expiry sweep. A
//! newer pair on the same port, or beside it, is never taken with it (3GPP TS
//! 33.203 clause 7.4).

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::{
    EncryptionAlgorithm, IntegrityAlgorithm, IpsecManager, SaProtocol, SaRole,
    SecurityAssociationPair,
};

const UE: &str = "192.0.2.77";
const PCSCF: &str = "198.51.100.10";

fn ip(text: &str) -> IpAddr {
    text.parse().expect("an IP literal")
}

fn socket(address: &str, port: u16) -> SocketAddr {
    SocketAddr::new(ip(address), port)
}

/// A P-CSCF pair of the UE: client port `ue_port_c`, server port 6101, the
/// P-CSCF's protected client port `pcscf_port_c` and server port 5066.
fn pair(ue_port_c: u16, pcscf_port_c: u16, spi_base: u32) -> SecurityAssociationPair {
    SecurityAssociationPair {
        ue_addr: ip(UE),
        pcscf_addr: ip(PCSCF),
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
        hard_lifetime_secs: Some(600),
        protocol: SaProtocol::Any,
        expires_at: Instant::now(),
        created_at: Instant::now(),
        role: SaRole::PCscf,
        impi: None,
        security_server: None,
    }
}

/// The kernel decrypts what the UE sends over `sa` to either protected port
/// of the P-CSCF.
fn carries_traffic(manager: &IpsecManager, sa: &SecurityAssociationPair) -> bool {
    manager.test_kernel_accepts_inbound(
        socket(UE, sa.ue_port_c),
        socket(PCSCF, sa.pcscf_port_s),
        sa.spi_ps,
    ) && manager.test_kernel_accepts_inbound(
        socket(UE, sa.ue_port_s),
        socket(PCSCF, sa.pcscf_port_c),
        sa.spi_pc,
    )
}

/// With a protected client port per pair (`ipsec.pcscf_port_c` listing
/// several), a retransmitted challenge on the same UE client port replaces the
/// first pair with one on another P-CSCF client port. The first one's
/// policies of SA #3 and #4 on its own port go with it, at once: none of its
/// eight kernel objects is left behind.
#[tokio::test]
async fn a_pair_replaced_on_its_client_port_leaves_none_of_its_policies_behind() {
    let manager = IpsecManager::with_test_kernel();
    let first = pair(6100, 5062, 4_000_000);
    let second = pair(6100, 5064, 4_000_010);
    manager.create_sa_pair(first.clone()).await.expect("first");
    manager
        .create_sa_pair(second.clone())
        .await
        .expect("second");

    assert!(carries_traffic(&manager, &second));
    assert_eq!(
        manager.test_kernel_live_count(),
        8,
        "only the second pair's eight kernel objects: {:?}",
        manager.test_kernel_ops()
    );
    manager
        .delete_sa_pair(&second.ue_addr, 6100)
        .await
        .expect("deleted");
    assert_eq!(manager.test_kernel_live_count(), 0);
    assert_eq!(manager.test_spi_owner_count(), 0);
}

/// A challenge that fails beside the set in use (the UE's other client port,
/// its own P-CSCF client port) is deleted. The protected server port both
/// share stays the set in use's: it is not recorded as a deleted flow, and
/// the set in use still carries traffic.
#[tokio::test]
async fn deleting_a_pair_beside_the_set_in_use_records_only_its_own_port() {
    let manager = IpsecManager::with_test_kernel();
    let in_use = pair(6100, 5062, 4_000_100);
    let challenged = pair(6102, 5064, 4_000_110);
    manager
        .create_sa_pair(in_use.clone())
        .await
        .expect("in use");
    manager
        .create_sa_pair(challenged.clone())
        .await
        .expect("challenged");
    assert!(manager.is_pending(&challenged.ue_addr, 6102));

    manager
        .delete_sa_pair(&challenged.ue_addr, 6102)
        .await
        .expect("deleted");

    assert_eq!(
        manager.deleted_flow_count(),
        1,
        "only the challenged pair's own client port"
    );
    assert!(carries_traffic(&manager, &in_use));
    assert_eq!(manager.test_kernel_live_count(), 8);
}

/// Deleting an installation that a newer pair on the same client port has
/// replaced is a no-op; the newer pair is untouched. Deleting the one held
/// takes it.
#[tokio::test]
async fn deleting_a_replaced_installation_leaves_the_newer_pair() {
    let manager = IpsecManager::with_test_kernel();
    let first = pair(6100, 5064, 4_000_200);
    let second = pair(6100, 5064, 4_000_210);
    manager.create_sa_pair(first.clone()).await.expect("first");
    manager
        .create_sa_pair(second.clone())
        .await
        .expect("second");

    assert!(!manager.holds_installation(&first));
    assert!(!manager.delete_installation(&first).await);
    assert!(carries_traffic(&manager, &second));
    assert_eq!(manager.test_kernel_live_count(), 8);
    assert_eq!(manager.deleted_flow_count(), 0);
    assert_eq!(manager.test_spi_owner_count(), 2);

    assert!(manager.holds_installation(&second));
    assert!(manager.delete_installation(&second).await);
    assert_eq!(manager.test_kernel_live_count(), 0);
    assert_eq!(manager.test_spi_owner_count(), 0);
    assert_eq!(manager.active_count(), 0);
}

/// Two challenges in a row on different client ports, the second answered and
/// taken into use: the first, never used, goes at once, by its own SPIs, and
/// the second keeps all of its kernel objects.
#[tokio::test]
async fn taking_the_second_challenge_into_use_removes_the_first_at_once() {
    let manager = Arc::new(IpsecManager::with_test_kernel());
    let first = pair(6102, 5064, 4_000_300);
    let second = pair(6100, 5064, 4_000_310);
    manager.create_sa_pair(first.clone()).await.expect("first");
    manager
        .create_sa_pair(second.clone())
        .await
        .expect("second");

    manager
        .supersede_pairs_for_ue(&second.ue_addr, 6100, Duration::from_secs(32))
        .await;

    assert!(!manager.has_sa(&first.ue_addr, 6102));
    assert!(carries_traffic(&manager, &second));
    assert_eq!(manager.test_kernel_live_count(), 8);
    assert_eq!(manager.test_spi_owner_count(), 2);
}

/// The code that holds a particular installation (the `PendingSA` cleanups,
/// the retirement, the expiry sweep) deletes it by that installation, never by
/// the UE's address and client port, which a newer pair may hold by then.
#[test]
fn no_installation_holder_deletes_by_port() {
    for (file, source) in [
        (
            "src/script/api/ipsec.rs",
            include_str!("../script/api/ipsec.rs"),
        ),
        ("src/ipsec/retire.rs", include_str!("retire.rs")),
        (
            "src/registrant/protected.rs",
            include_str!("../registrant/protected.rs"),
        ),
    ] {
        let production = source.split("#[cfg(test)]\nmod ").next().unwrap_or(source);
        assert!(
            !production.contains("delete_sa_pair("),
            "{file} deletes a pair by UE address and client port"
        );
    }
    let sweep = include_str!("mod.rs");
    let sweep = sweep
        .split("pub async fn sweep_expired_reaped")
        .nth(1)
        .and_then(|rest| rest.split("\n    }\n").next())
        .expect("the expiry sweep");
    assert!(
        !sweep.contains("delete_sa_pair("),
        "the expiry sweep deletes a pair by UE address and client port"
    );
}
