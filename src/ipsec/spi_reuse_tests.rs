//! The manager never installs an SA over one another UE still holds: SPIs
//! come back only once their pair is gone, a full partition refuses, and SAs a
//! restart left in the kernel keep their SPIs. Driven against the in-memory
//! kernel, so each test can count the states every UE still has.

use super::*;
use std::net::Ipv4Addr;

const PCSCF: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

fn ue(index: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(198, 51, 100, index))
}

/// A P-CSCF pair for `ue_addr` with the SPIs the manager allocated, as
/// `ipsec.allocate` builds it. Each UE offers its own two SPIs.
fn pair(ue_addr: IpAddr, spi_pc: u32, spi_ps: u32) -> SecurityAssociationPair {
    let ue_spi = match ue_addr {
        IpAddr::V4(address) => 70_000 + 2 * u32::from(address.octets()[3]),
        IpAddr::V6(_) => 70_000,
    };
    SecurityAssociationPair {
        ue_addr,
        pcscf_addr: PCSCF,
        ue_port_c: 6100,
        ue_port_s: 6101,
        pcscf_port_c: 5064,
        pcscf_port_s: 5066,
        spi_uc: ue_spi,
        spi_us: ue_spi + 1,
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

/// Allocate and install a pair for `ue_addr`, the way `ipsec.allocate` does.
async fn register(manager: &IpsecManager, ue_addr: IpAddr) -> Result<(u32, u32), IpsecError> {
    let (spi_pc, spi_ps) = manager.allocate_spi_pair()?;
    manager
        .create_sa_pair(pair(ue_addr, spi_pc, spi_ps))
        .await?;
    Ok((spi_pc, spi_ps))
}

/// Whether all four states of `sa` are in the mock kernel.
fn installed(manager: &IpsecManager, sa: &SecurityAssociationPair) -> bool {
    let kernel = manager.mock();
    sa.state_keys()
        .iter()
        .all(|(destination, spi)| kernel.live.contains(&format!("sa:{destination}:{spi}")))
}

fn state_count(manager: &IpsecManager) -> usize {
    manager
        .mock()
        .live
        .iter()
        .filter(|key| key.starts_with("sa:"))
        .count()
}

/// The reproduction: a partition of 2N SPIs holds N UEs. Before the fix the
/// counter wrapped and UE N+1 got UE 1's SPIs, so installing it replaced UE
/// 1's inbound states (N+1 pairs, 4N+2 states). Now UE N+1 is refused, every
/// state survives, and once UE 1 leaves its SPIs are what UE N+1 gets.
#[tokio::test]
async fn ue_n_plus_one_never_takes_a_live_ues_spis() {
    let manager = IpsecManager::with_mock_kernel_partition(10_000, 8);
    let mut first_spis = None;
    for index in 1..=4 {
        let spis = register(&manager, ue(index))
            .await
            .expect("room for four UEs");
        first_spis.get_or_insert(spis);
    }
    assert_eq!(state_count(&manager), 16);

    let refused = register(&manager, ue(5)).await;
    assert!(
        matches!(
            refused,
            Err(IpsecError::SpiExhausted {
                start: 10_000,
                count: 8
            })
        ),
        "a full partition refuses, got {refused:?}"
    );
    assert_eq!(state_count(&manager), 16, "the refusal touched no state");
    for index in 1..=4 {
        let sa = manager.get_sa(&ue(index), 6100).expect("still registered");
        assert!(installed(&manager, &sa), "UE {index} kept all four states");
    }

    manager.delete_sa_pair(&ue(1), 6100).await.expect("delete");
    let reused = register(&manager, ue(5))
        .await
        .expect("UE 1's SPIs are free");
    assert_eq!(
        Some(reused),
        first_spis,
        "UE 5 reuses exactly what UE 1 freed"
    );
    assert_eq!(state_count(&manager), 16);
    for index in 2..=5 {
        let sa = manager.get_sa(&ue(index), 6100).expect("registered");
        assert!(installed(&manager, &sa), "UE {index} has all four states");
    }
    assert_eq!(manager.spi_usage(), (8, 8));
}

/// Registrations that keep rotating SPIs, as re-registrations do, run round
/// the partition many times without ever landing on a live UE.
#[tokio::test]
async fn rotating_registrations_wrap_without_touching_live_ues() {
    let manager = IpsecManager::with_mock_kernel_partition(10_000, 10);
    for index in 1..=4 {
        register(&manager, ue(index)).await.expect("room");
    }
    // One slot of two SPIs left: a fifth UE re-registers over and over.
    for _ in 0..50 {
        manager.delete_sa_pair(&ue(5), 6100).await.expect("delete");
        register(&manager, ue(5))
            .await
            .expect("its own SPIs come back");
        for index in 1..=4 {
            let sa = manager.get_sa(&ue(index), 6100).expect("registered");
            assert!(installed(&manager, &sa), "UE {index} untouched");
        }
    }
    assert_eq!(state_count(&manager), 20);
}

/// An install whose SPI another live pair owns is refused before the kernel
/// is touched, so that pair keeps its states.
#[tokio::test]
async fn an_install_over_another_pairs_spi_is_refused() {
    let manager = IpsecManager::with_mock_kernel_partition(10_000, 64);
    let (spi_pc, spi_ps) = register(&manager, ue(1)).await.expect("room");
    let operations = manager.mock().ops.len();

    let result = manager
        .create_sa_pair(pair(ue(2), spi_pc + 10, spi_ps))
        .await;
    assert!(matches!(result, Err(IpsecError::SpiInUse(spi)) if spi == spi_ps));
    assert_eq!(manager.mock().ops.len(), operations, "no kernel op ran");
    let sa = manager.get_sa(&ue(1), 6100).expect("registered");
    assert!(installed(&manager, &sa));
    assert!(!manager.has_sa(&ue(2), 6100));
}

/// A failed install gives back the SPIs it was allocated.
#[tokio::test]
async fn a_failed_install_frees_its_spis() {
    let manager = IpsecManager::with_mock_kernel_partition(10_000, 64);
    manager.mock().fail_add_at = Some(3);
    assert!(register(&manager, ue(1)).await.is_err());
    assert_eq!(manager.spi_usage().0, 0);
    register(&manager, ue(1)).await.expect("the retry installs");
    assert_eq!(manager.spi_usage().0, 2);
}

/// A pair re-created under the same UE address and port with new SPIs (a new
/// authentication from the same flow) frees the old SPIs and deletes the old
/// states, and a re-key that keeps the SPIs keeps them owned.
#[tokio::test]
async fn replacing_a_pair_frees_the_spis_it_no_longer_uses() {
    let manager = IpsecManager::with_mock_kernel_partition(10_000, 64);
    let (old_pc, old_ps) = register(&manager, ue(1)).await.expect("room");
    let (new_pc, new_ps) = register(&manager, ue(1)).await.expect("room");
    assert_ne!((old_pc, old_ps), (new_pc, new_ps));
    assert_eq!(
        manager.spi_usage().0,
        2,
        "only the new pair's SPIs are held"
    );
    {
        let kernel = manager.mock();
        assert!(!kernel.live.contains(&format!("sa:{PCSCF}:{old_ps}")));
        assert!(!kernel.live.contains(&format!("sa:{PCSCF}:{old_pc}")));
    }

    // A re-key (PendingSA.refresh) re-installs the same SPIs.
    manager
        .create_sa_pair(pair(ue(1), new_pc, new_ps))
        .await
        .expect("re-key");
    assert_eq!(manager.spi_usage().0, 2);
    let sa = manager.get_sa(&ue(1), 6100).expect("registered");
    assert!(installed(&manager, &sa));
}

/// The sweep frees the SPIs of the pairs it reaps.
#[tokio::test]
async fn swept_pairs_free_their_spis() {
    let manager = IpsecManager::with_mock_kernel_partition(10_000, 4);
    register(&manager, ue(1)).await.expect("room");
    register(&manager, ue(2)).await.expect("room");
    assert!(register(&manager, ue(3)).await.is_err());
    if let Some(mut entry) = manager.associations.get_mut("198.51.100.1:6100") {
        entry.expires_at = Instant::now();
    }
    assert_eq!(manager.sweep_expired().await, 1);
    register(&manager, ue(3))
        .await
        .expect("the swept pair's SPIs are free");
}

/// Restart: the kernel still holds the previous process's states, and this
/// process knows none of them. Their SPIs are held, so nothing new is
/// installed over them, and each comes back once the kernel drops it.
#[tokio::test]
async fn spis_of_sas_a_restart_left_behind_are_not_reallocated() {
    let manager = IpsecManager::with_mock_kernel_partition(10_000, 4);
    {
        let mut kernel = manager.mock();
        for key in [
            format!("sa:{PCSCF}:10000"),
            format!("sa:{PCSCF}:10001"),
            // Another instance's partition, and a policy: neither is ours.
            format!("sa:{PCSCF}:20000"),
            "policy:198.51.100.9:6100->192.0.2.1:5066:in".to_string(),
        ] {
            kernel.live.insert(key);
        }
    }
    assert_eq!(manager.adopt_surviving_kernel_sas().await, 2);
    assert_eq!(manager.spi_usage(), (2, 4));

    let (spi_pc, spi_ps) = register(&manager, ue(1)).await.expect("two are free");
    assert!(![spi_pc, spi_ps].contains(&10_000) && ![spi_pc, spi_ps].contains(&10_001));
    assert!(
        manager.mock().live.contains(&format!("sa:{PCSCF}:10000")),
        "survivor kept"
    );
    assert!(register(&manager, ue(2)).await.is_err());

    // The kernel reaps the survivors on their hard lifetime; the next sweep
    // notices and frees their SPIs.
    {
        let mut kernel = manager.mock();
        kernel.live.remove(&format!("sa:{PCSCF}:10000"));
        kernel.live.remove(&format!("sa:{PCSCF}:10001"));
    }
    manager.sweep_expired().await;
    assert_eq!(manager.spi_usage(), (2, 4));
    register(&manager, ue(2))
        .await
        .expect("the survivors' SPIs are free again");
}

/// A re-pin that races a delete must not bring the deleted pair back, or its
/// SPIs would be listed as a live pair's while free in the partition.
#[tokio::test]
async fn a_lifetime_update_never_resurrects_a_deleted_pair() {
    let manager = IpsecManager::with_mock_kernel_partition(10_000, 64);
    register(&manager, ue(1)).await.expect("room");
    manager.delete_sa_pair(&ue(1), 6100).await.expect("delete");
    manager
        .update_sa_pair_lifetime(&ue(1), 6100, Some(600))
        .await
        .expect("a no-op for a missing pair");
    assert!(!manager.has_sa(&ue(1), 6100));
}

/// Many tasks registering at once all get distinct SPIs and every UE keeps
/// all four states.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_registrations_get_distinct_spis() {
    let manager = Arc::new(IpsecManager::with_mock_kernel_partition(10_000, 512));
    let tasks: Vec<_> = (1..=200u8)
        .map(|index| {
            let manager = Arc::clone(&manager);
            tokio::spawn(async move { register(&manager, ue(index)).await })
        })
        .collect();
    let mut seen = std::collections::HashSet::new();
    for task in tasks {
        let (spi_pc, spi_ps) = task.await.expect("the task ran").expect("room");
        assert!(
            seen.insert(spi_pc) && seen.insert(spi_ps),
            "an SPI handed out twice"
        );
    }
    for index in 1..=200u8 {
        let sa = manager.get_sa(&ue(index), 6100).expect("registered");
        assert!(installed(&manager, &sa));
    }
    assert_eq!(manager.spi_usage().0, 400);
}

/// Linux XFRM, end to end: with a partition of 2N SPIs, N UEs install, UE
/// N+1 is refused, and the kernel still holds every state of the first N.
/// Then one leaves and UE N+1 takes its place without disturbing the others.
///
/// Needs `CAP_NET_ADMIN` over a network namespace of its own, so it never
/// touches the host's XFRM tables:
/// `unshare -rn cargo test --lib ipsec::spi_reuse_tests -- --ignored`.
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "requires CAP_NET_ADMIN (run under `unshare -rn`)"]
async fn every_kernel_sa_survives_ue_n_plus_one_in_a_netns() {
    const UES: u8 = 4;
    let manager = IpsecManager::with_partition(XfrmBackend::Netlink, 10_000, 2 * u32::from(UES));
    let kernel_states = || async {
        netlink::dump_sa_use_times()
            .await
            .expect("the namespace's SAs can be dumped")
    };
    assert!(
        kernel_states().await.is_empty(),
        "run in a fresh network namespace"
    );

    for index in 1..=UES {
        register(&manager, ue(index)).await.expect("room for N UEs");
    }
    // Every UE offers its own SPIs, so each state has an SPI of its own and
    // the dump (keyed by SPI) counts states. Before the fix, UE N+1 reused UE
    // 1's SPIs and its install replaced UE 1's two inbound states: 4N + 2.
    let check_all = |states: std::collections::HashMap<u32, u64>, ues: &[u8]| {
        for index in ues {
            let sa = manager.get_sa(&ue(*index), 6100).expect("registered");
            for spi in [sa.spi_ps, sa.spi_pc, sa.spi_uc, sa.spi_us] {
                assert!(states.contains_key(&spi), "UE {index} state {spi} survives");
            }
        }
        assert_eq!(states.len(), 4 * ues.len());
    };
    check_all(kernel_states().await, &[1, 2, 3, 4]);

    assert!(matches!(
        register(&manager, ue(UES + 1)).await,
        Err(IpsecError::SpiExhausted { .. })
    ));
    check_all(kernel_states().await, &[1, 2, 3, 4]);

    manager.delete_sa_pair(&ue(1), 6100).await.expect("delete");
    register(&manager, ue(UES + 1))
        .await
        .expect("UE 1's SPIs are free");
    check_all(kernel_states().await, &[2, 3, 4, 5]);

    for index in 2..=UES + 1 {
        manager
            .delete_sa_pair(&ue(index), 6100)
            .await
            .expect("delete");
    }
    assert!(kernel_states().await.is_empty(), "nothing left behind");
}
