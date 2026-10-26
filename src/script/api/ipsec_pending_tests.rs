//! A pending pair abandoned by the script (its stash entry expiring or being
//! displaced, `PendingSA.activate` after a newer pair took its place) is named
//! by its own SPIs, never by the UE's address and protected client port: a UE
//! that retransmits its initial REGISTER gets a second challenge, and a second
//! pending pair on the same client port, which replaces the first. Taking that
//! second one into use and then cleaning up the first must leave the second,
//! now in use, alone (3GPP TS 33.203 clause 7.4: an unused set is removed by
//! its own SPIs and never touches a set in use).

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::*;
use crate::ipsec::SaRole;

const UE: &str = "192.0.2.77";
const PCSCF: &str = "198.51.100.10";

fn ip(text: &str) -> IpAddr {
    text.parse().expect("an IP literal")
}

fn socket(address: &str, port: u16) -> SocketAddr {
    SocketAddr::new(ip(address), port)
}

/// The pair one challenge of `ue` installs: the UE's client port 6100 and
/// server port 6101 with the UE's own SPIs (the same in a retransmission of
/// the REGISTER, which carries the same `Security-Client`), the P-CSCF's
/// fixed protected ports and the two SPIs this challenge allocated.
fn challenge_pair(ue: &str, spi_pc: u32) -> SecurityAssociationPair {
    SecurityAssociationPair {
        ue_addr: ip(ue),
        pcscf_addr: ip(PCSCF),
        ue_port_c: 6100,
        ue_port_s: 6101,
        pcscf_port_c: 5064,
        pcscf_port_s: 5066,
        spi_uc: 3_000_001,
        spi_us: 3_000_002,
        spi_pc,
        spi_ps: spi_pc + 1,
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

fn params_for(sa: &SecurityAssociationPair) -> PySecurityServerParams {
    PySecurityServerParams {
        mechanism: "ipsec-3gpp".into(),
        alg: "hmac-sha-1-96".into(),
        ealg: "null".into(),
        spi_c: sa.spi_pc,
        spi_s: sa.spi_ps,
        port_c: sa.pcscf_port_c,
        port_s: sa.pcscf_port_s,
        protocol: "any".into(),
    }
}

fn namespace(manager: &Arc<IpsecManager>, stash_ttl: Duration) -> PyIpsec {
    let config = Arc::new(IpsecConfig {
        pcscf_port_c: 5064.into(),
        pcscf_port_s: 5066,
        backend: crate::config::IpsecBackend::Netlink,
        spi_range_start: None,
        spi_range_count: 8192,
        path_host: None,
    });
    let mut ipsec = PyIpsec::new(Arc::clone(manager), config, Some(ip(PCSCF)), None);
    ipsec.stash_ttl = stash_ttl;
    ipsec
}

/// Install the pair of one challenge, as `ipsec.allocate` does, and hand
/// back its `PendingSA`.
async fn challenge(manager: &Arc<IpsecManager>, sa: &SecurityAssociationPair) -> Py<PyPendingSA> {
    manager
        .create_sa_pair(sa.clone())
        .await
        .expect("pair installed");
    let pending = PyPendingSA::new(Arc::clone(manager), sa.clone(), params_for(sa));
    Python::attach(|python| Py::new(python, pending).expect("PendingSA object"))
}

fn activate(pending: &Py<PyPendingSA>, hard_lifetime_secs: Option<u64>) {
    Python::attach(|python| {
        pending
            .borrow(python)
            .activate(hard_lifetime_secs)
            .expect("activated")
    });
}

/// Let every task spawned so far run as far as it can: to completion, or to
/// the timer it waits on, which is then armed from the current (paused) time.
async fn settle() {
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
}

/// The pair `sa` is installed and carries traffic: the manager holds it at
/// its client port, the kernel decrypts a request the UE sends over it to the
/// P-CSCF's protected server port and a response to the P-CSCF's protected
/// client port, and a request arriving on either UE port matches it.
fn assert_in_service(manager: &IpsecManager, sa: &SecurityAssociationPair) {
    let held = manager
        .get_sa(&sa.ue_addr, sa.ue_port_c)
        .expect("the pair in use is still held");
    assert_eq!((held.spi_pc, held.spi_ps), (sa.spi_pc, sa.spi_ps));
    let ue = sa.ue_addr.to_string();
    assert!(
        manager.test_kernel_accepts_inbound(
            socket(&ue, sa.ue_port_c),
            socket(PCSCF, sa.pcscf_port_s),
            sa.spi_ps
        ),
        "a request over the pair in use is decrypted"
    );
    assert!(
        manager.test_kernel_accepts_inbound(
            socket(&ue, sa.ue_port_s),
            socket(PCSCF, sa.pcscf_port_c),
            sa.spi_pc
        ),
        "a response over the pair in use is decrypted"
    );
    for port in [sa.ue_port_c, sa.ue_port_s] {
        let matched = manager
            .find_sa_by_ue(&sa.ue_addr, port)
            .expect("a protected request matches the pair in use");
        assert_eq!(matched.spi_ps, sa.spi_ps);
    }
}

/// The field sequence: the 401 for the first challenge is lost, the UE
/// retransmits (new Call-ID), a second pair on the same client port replaces
/// the first, is answered and taken into use. The first one's stash entry then
/// expires. The pair in use must stay installed, with all eight kernel
/// objects, and no port of it may be recorded as deleted.
#[tokio::test(start_paused = true)]
async fn stash_expiry_of_a_replaced_challenge_leaves_the_pair_in_use() {
    pyo3::Python::initialize();
    let manager = Arc::new(IpsecManager::with_test_kernel());
    let ipsec = namespace(&manager, Duration::from_secs(30));

    let first = challenge_pair(UE, 60_010);
    let pending_first = challenge(&manager, &first).await;
    ipsec.stash("call-first".into(), pending_first);
    settle().await;

    tokio::time::advance(Duration::from_secs(3)).await;
    let second = challenge_pair(UE, 60_036);
    let pending_second = challenge(&manager, &second).await;
    ipsec.stash("call-second".into(), pending_second);
    settle().await;

    tokio::time::advance(Duration::from_secs(1)).await;
    let taken = ipsec.unstash("call-second").expect("stashed");
    activate(&taken, Some(600));
    settle().await;
    assert_in_service(&manager, &second);

    // The first challenge's stash entry expires.
    tokio::time::advance(Duration::from_secs(27)).await;
    settle().await;

    assert_eq!(ipsec.stash_size(), 0);
    assert_in_service(&manager, &second);
    assert_eq!(
        manager.test_kernel_live_count(),
        8,
        "the pair in use's eight"
    );
    assert_eq!(
        manager.deleted_flow_count(),
        0,
        "no port of the pair in use is recorded as deleted"
    );
    assert_eq!(manager.test_spi_owner_count(), 2, "the pair in use's SPIs");
}

/// The same retransmission under the same Call-ID: stashing the second
/// `PendingSA` displaces the first, whose cleanup runs at once. It must not
/// take the second pair, which replaced it on the same client port.
#[tokio::test(start_paused = true)]
async fn a_displaced_stash_entry_leaves_the_pair_that_replaced_it() {
    pyo3::Python::initialize();
    let manager = Arc::new(IpsecManager::with_test_kernel());
    let ipsec = namespace(&manager, Duration::from_secs(30));

    let first = challenge_pair(UE, 60_110);
    ipsec.stash("call".into(), challenge(&manager, &first).await);
    let second = challenge_pair(UE, 60_136);
    ipsec.stash("call".into(), challenge(&manager, &second).await);
    settle().await;

    assert_eq!(ipsec.stash_size(), 1);
    let taken = ipsec.unstash("call").expect("the second is stashed");
    activate(&taken, None);
    settle().await;
    assert_in_service(&manager, &second);
    assert_eq!(manager.test_kernel_live_count(), 8);
    assert_eq!(manager.deleted_flow_count(), 0);
}

/// Activating the first, replaced, `PendingSA` (a 2xx the script matched to
/// it) must not act on the pair that replaced it: no re-pin of its kernel
/// objects, and it stays installed.
#[tokio::test(start_paused = true)]
async fn activating_a_replaced_pending_sa_leaves_the_newer_pair_alone() {
    pyo3::Python::initialize();
    let manager = Arc::new(IpsecManager::with_test_kernel());

    let first = challenge_pair(UE, 60_210);
    let pending_first = challenge(&manager, &first).await;
    let second = challenge_pair(UE, 60_236);
    let _pending_second = challenge(&manager, &second).await;
    let ops_before = manager.test_kernel_ops().len();

    activate(&pending_first, Some(120));
    settle().await;

    let later = &manager.test_kernel_ops()[ops_before..];
    assert!(
        later.is_empty(),
        "the replaced challenge touches no kernel object: {later:?}"
    );
    assert_in_service(&manager, &second);
}

/// Leak gate: many UEs, each with a retransmitted challenge whose first pair
/// is abandoned in the stash. Once the entries expire, every store is back to
/// what the pairs in use account for: nothing stashed, nothing pending, no
/// deleted flows, two SPIs and eight kernel objects per UE. Deleting the
/// pairs in use then drains the SPIs and the kernel to zero.
#[tokio::test(start_paused = true)]
async fn abandoned_challenges_drain_every_store() {
    pyo3::Python::initialize();
    let manager = Arc::new(IpsecManager::with_test_kernel());
    let ipsec = namespace(&manager, Duration::from_secs(30));
    const UES: u32 = 40;

    let mut in_use = Vec::new();
    for index in 0..UES {
        let ue = format!("192.0.2.{}", index + 10);
        let first = challenge_pair(&ue, 61_000 + index * 4);
        ipsec.stash(format!("first-{index}"), challenge(&manager, &first).await);
        settle().await;
        let second = challenge_pair(&ue, 61_002 + index * 4);
        ipsec.stash(
            format!("second-{index}"),
            challenge(&manager, &second).await,
        );
        let taken = ipsec.unstash(&format!("second-{index}")).expect("stashed");
        activate(&taken, None);
        in_use.push(second);
    }
    tokio::time::advance(Duration::from_secs(31)).await;
    settle().await;

    assert_eq!(ipsec.stash_size(), 0);
    assert_eq!(manager.active_count(), UES as usize);
    assert_eq!(manager.deleted_flow_count(), 0);
    assert_eq!(manager.test_pending_count(), 0);
    assert_eq!(manager.test_spi_owner_count(), 2 * UES as usize);
    assert_eq!(manager.test_kernel_live_count(), 8 * UES as usize);
    for sa in &in_use {
        assert_in_service(&manager, sa);
    }

    for sa in &in_use {
        manager
            .retire_ue_now(sa.ue_addr, Some(sa.ue_port_c), "test teardown")
            .await;
    }
    assert_eq!(manager.active_count(), 0);
    assert_eq!(manager.test_spi_owner_count(), 0);
    assert_eq!(manager.test_kernel_live_count(), 0);
    assert_eq!(manager.test_pending_count(), 0);
}
