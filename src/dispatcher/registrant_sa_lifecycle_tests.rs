//! The IMS UE's SA lifecycle beyond a refresh: the binding a protected
//! REGISTER makes (TS 24.229 5.1.1.2.2 b, 5.1.1.4.2 b, 5.1.1.6.2 b), the
//! answer to an invalid challenge (5.1.1.5.3), the temporary set's lifetime
//! (5.1.1.5.1), the make-before-break overlap against a P-CSCF that keeps its
//! protected client port (TS 33.203 7.4), and deleting every set at shutdown
//! (TS 33.203 7.4.1a). Driven through the dispatcher's response handler
//! against the mock kernel, like `protected_tests`.

use super::protected_tests::{header, ip, wait_for, Harness, UE_ADDR};
use super::*;
use crate::registrant::test_support::{self, impu};
use crate::registrant::{RegistrantState, UeExchange};
use std::net::SocketAddr;
use std::time::Duration;

/// The P-CSCF of the fixtures, and its protected client port: siphon's own
/// P-CSCF keeps it across authentications.
const PCSCF_IP: &str = "198.51.100.10";
const PCSCF_PORT_C: u16 = 5064;

fn contact_port(message: &SipMessage) -> Option<u16> {
    let contact = message.headers.get("Contact")?;
    let uri = contact.split('>').next()?;
    uri.rsplit(':').next()?.parse().ok()
}

fn via_sent_by(message: &SipMessage) -> String {
    message
        .headers
        .get("Via")
        .and_then(|via| via.split(';').next())
        .and_then(|first| first.split(' ').nth(1))
        .unwrap_or_default()
        .to_string()
}

fn parsed(message: &crate::transport::OutboundMessage) -> SipMessage {
    crate::sip::parser::parse_sip_message_bytes(&message.data).expect("what siphon sent parses")
}

fn add_sa_count(harness: &Harness) -> usize {
    harness
        .ipsec
        .test_kernel_ops()
        .iter()
        .filter(|op| op.starts_with("add_sa"))
        .count()
}

fn pcscf_client() -> SocketAddr {
    SocketAddr::new(ip(PCSCF_IP), PCSCF_PORT_C)
}

fn ue_server() -> SocketAddr {
    SocketAddr::new(ip(UE_ADDR), 6101)
}

/// TS 24.229 5.1.1.2.2 b and 5.1.1.4.2 b: a REGISTER protected by a security
/// association names "the protected server port value in the hostport
/// parameter" of its Contact, as its Via sent-by does (c). That is the
/// binding the S-CSCF keeps, so MT requests come to the protected server
/// port over the set. The unprotected initial REGISTER keeps the plain port.
#[tokio::test]
async fn every_protected_register_binds_the_protected_server_port() {
    let mut harness = Harness::new();
    harness.add(1, UE_ADDR);

    let initial = harness.register(&impu(1));
    assert!(!initial.protected);
    assert_eq!(
        contact_port(&initial.message),
        Some(5060),
        "unprotected: plain port"
    );
    let call_id = harness.call_id(&initial);
    harness.challenge(&call_id);
    let authenticated = parsed(&harness.sent().await);
    assert_eq!(
        contact_port(&authenticated),
        Some(6101),
        "the authenticated REGISTER rides the temporary set (5.1.1.2.2 b)"
    );
    assert_eq!(via_sent_by(&authenticated), format!("{UE_ADDR}:6101"));
    harness.answer("200 OK", &call_id, "Expires: 600\r\n");

    let refresh = harness.register(&impu(1));
    assert!(refresh.protected);
    assert_eq!(contact_port(&refresh.message), Some(6101), "5.1.1.4.2 b");
    assert_eq!(via_sent_by(&refresh.message), format!("{UE_ADDR}:6101"));
    let call_id = harness.call_id(&refresh);
    harness.challenge(&call_id);
    let reauthenticated = parsed(&harness.sent().await);
    assert_eq!(contact_port(&reauthenticated), Some(6101));
    harness.answer("200 OK", &call_id, "Expires: 600\r\n");

    harness.registrant.remove(&impu(1));
    let deregistration = test_support::take_deregistrations(&harness.registrant)
        .pop()
        .expect("a de-REGISTER");
    assert!(deregistration.protected);
    assert_eq!(
        contact_port(&deregistration.message),
        Some(6101),
        "5.1.1.6.2 b"
    );
}

/// TS 24.229 5.1.1.5.3: an SQN out of range is answered with "auts", sent
/// "using an existing set of security associations, if available", with a
/// Security-Client carrying "new values for spi_uc, spi_us and port_uc", and
/// the UE does "not create a temporary set of security associations". It used
/// to install one from the CK/IK of the previous authentication.
#[tokio::test]
async fn a_resync_goes_over_the_existing_set_and_installs_no_temporary_one() {
    let mut harness = Harness::new();
    harness.add(1, UE_ADDR);
    harness.register_initially(1, UE_ADDR).await;
    let established = test_support::sa_sets(&harness.registrant, &impu(1))
        .established
        .expect("established");
    let installs = add_sa_count(&harness);

    let refresh = harness.register(&impu(1));
    let call_id = harness.call_id(&refresh);
    let offered = refresh
        .message
        .headers
        .get("Security-Client")
        .cloned()
        .expect("a Security-Client");
    // An SQN the USIM has already seen (the initial registration used 1).
    let stale = format!(
        "WWW-Authenticate: {}\r\nSecurity-Server: {}\r\n",
        test_support::aka_challenge_value("000000000001"),
        test_support::security_server(80_000, 80_001)
    );
    harness.answer("401 Unauthorized", &call_id, &stale);

    let resync = harness.sent().await;
    assert_eq!(
        resync.source_local_addr,
        Some(SocketAddr::new(ip(UE_ADDR), 6100)),
        "over the established set"
    );
    assert_eq!(
        resync.destination,
        "198.51.100.10:5066".parse().expect("addr")
    );
    let authorization = header(&resync, "Authorization").expect("an Authorization");
    assert!(authorization.contains("auts="), "{authorization}");
    assert_eq!(
        header(&resync, "Security-Verify"),
        Some(established.security_server.clone()),
        "the Security-Server of the last successful authentication"
    );
    let client = header(&resync, "Security-Client").expect("a Security-Client");
    assert_ne!(client, offered, "new spi_uc, spi_us and port_uc: {client}");
    assert!(
        client.contains("port-c=6103"),
        "not the challenged offer's port: {client}"
    );
    assert!(!client.contains(&format!("spi-c={}", established.key.spi_uc)));
    assert_eq!(contact_port(&parsed(&resync)), Some(6101));

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        add_sa_count(&harness),
        installs,
        "no temporary set installed"
    );
    assert_eq!(harness.ports(UE_ADDR), vec![6100]);
    let sets = test_support::sa_sets(&harness.registrant, &impu(1));
    assert!(sets.temporary.is_none());
    assert_eq!(sets.exchange, UeExchange::Protected);

    // The network re-challenges with a fresh SQN: that one sets up a set.
    harness.challenge(&call_id);
    harness.sent().await;
    harness.answer("200 OK", &call_id, "Expires: 600\r\n");
    assert_eq!(
        harness.registrant.state(&impu(1)),
        Some(RegistrantState::Registered)
    );
    assert_eq!(
        harness.ports(UE_ADDR).len(),
        2,
        "old retiring beside the new"
    );
}

/// Without a set yet (the initial registration), the resync goes
/// unprotected, like the initial REGISTER, and still installs nothing.
#[tokio::test]
async fn a_resync_before_any_set_goes_unprotected() {
    let mut harness = Harness::new();
    harness.add(1, UE_ADDR);
    // The USIM has seen a later SQN than the network's next challenge.
    test_support::set_sqn(&harness.registrant, &impu(1), [0, 0, 0, 0, 0, 0x30]);

    let initial = harness.register(&impu(1));
    let call_id = harness.call_id(&initial);
    harness.challenge(&call_id);
    let resync = harness.sent().await;
    assert_eq!(
        resync.source_local_addr,
        Some(SocketAddr::new(ip(UE_ADDR), 5060))
    );
    assert_eq!(
        resync.destination,
        test_support::PCSCF.parse().expect("addr")
    );
    assert!(header(&resync, "Authorization").is_some_and(|value| value.contains("auts=")));
    assert!(header(&resync, "Security-Verify").is_none());
    assert!(
        header(&resync, "Security-Client").is_some_and(|client| client.contains("port-c=6102")),
        "a port_uc other than the challenged offer's"
    );
    assert_eq!(contact_port(&parsed(&resync)), Some(5060));
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(add_sa_count(&harness), 0);
    assert_eq!(
        harness.registrant.ipsec_exchange(&impu(1)),
        Some(UeExchange::Unprotected)
    );
}

/// TS 24.229 5.1.1.5.1 step 2: the temporary set lives "the value of
/// reg-await-auth timer" (4 minutes, table 7.8.1). At its 200 it becomes the
/// established set, for "the lifetime of the just completed registration plus
/// 30 seconds" unless the old set had longer. States and policies alike: a
/// policy left on the temporary lifetime would end under a live set.
#[tokio::test]
async fn the_temporary_set_lives_reg_await_auth_then_the_registration_plus_30() {
    let mut harness = Harness::new();
    harness.add(1, UE_ADDR);
    let initial = harness.register(&impu(1));
    let call_id = harness.call_id(&initial);
    harness.challenge(&call_id);
    harness.sent().await;
    let temporary = harness
        .ipsec
        .get_sa(&ip(UE_ADDR), 6100)
        .expect("the temporary set");
    assert_eq!(temporary.hard_lifetime_secs, Some(240));

    harness.answer("200 OK", &call_id, "Expires: 600\r\n");
    wait_for(|| {
        harness
            .ipsec
            .get_sa(&ip(UE_ADDR), 6100)
            .and_then(|sa| sa.hard_lifetime_secs)
            .filter(|lifetime| *lifetime == 630)
    })
    .await;
    let updates = harness.ipsec.test_kernel_policy_updates();
    assert_eq!(updates.len(), 4, "every policy re-pinned: {updates:?}");
    assert!(
        updates.iter().all(|(_, lifetime)| *lifetime == Some(630)),
        "{updates:?}"
    );
}

/// TS 33.203 7.4.1a / TS 24.229 5.1.1.5.1: after the 200 to a re-challenged
/// refresh the UE keeps the old set until something arrives over the new one,
/// and the P-CSCF may go on sending over the old one meanwhile. Against a
/// P-CSCF that keeps its protected client port, both sets' SA #3 share one
/// inbound policy; its template must accept either set's SA, or that request
/// is dropped. It used to name the newest set's SPI only.
#[tokio::test]
async fn during_make_before_break_the_old_set_still_receives() {
    let mut harness = Harness::new();
    harness.add(1, UE_ADDR);
    harness.register_initially(1, UE_ADDR).await;
    let old = harness
        .ipsec
        .get_sa(&ip(UE_ADDR), 6100)
        .expect("the old set");
    harness.rechallenged_refresh(&impu(1)).await;
    let new = harness
        .ipsec
        .get_sa(&ip(UE_ADDR), 6102)
        .expect("the new set");
    assert_ne!(old.spi_us, new.spi_us);
    let sets = test_support::sa_sets(&harness.registrant, &impu(1));
    assert_eq!(sets.retiring.map(|key| key.ue_port_c), Some(6100));

    assert!(
        harness
            .ipsec
            .test_kernel_accepts_inbound(pcscf_client(), ue_server(), old.spi_us),
        "a request the P-CSCF sends over the old set during the overlap"
    );
    assert!(harness
        .ipsec
        .test_kernel_accepts_inbound(pcscf_client(), ue_server(), new.spi_us));
    assert!(
        !harness
            .ipsec
            .test_kernel_accepts_inbound(pcscf_client(), ue_server(), 4_242),
        "only an SA the UE holds decrypts"
    );

    // The old set goes at the answer to the next REGISTER: the shared policy
    // stays for the new one, which alone is accepted from then on.
    let next = harness.register(&impu(1));
    harness.answer("200 OK", &harness.call_id(&next), "Expires: 600\r\n");
    harness.settle(UE_ADDR, &[6102]).await;
    assert!(harness
        .ipsec
        .test_kernel_accepts_inbound(pcscf_client(), ue_server(), new.spi_us));
    assert!(!harness
        .ipsec
        .test_kernel_accepts_inbound(pcscf_client(), ue_server(), old.spi_us));
}

/// A failed authentication deletes the temporary set and leaves the old one
/// receiving, with no window in which the shared policy was missing (it is
/// never deleted, only handed back).
#[tokio::test]
async fn a_failed_authentication_leaves_the_old_set_receiving() {
    let mut harness = Harness::new();
    harness.add(1, UE_ADDR);
    harness.register_initially(1, UE_ADDR).await;
    let old = harness.ipsec.get_sa(&ip(UE_ADDR), 6100).expect("old set");
    let built = harness.register(&impu(1));
    let call_id = harness.call_id(&built);
    let ops_before = harness.ipsec.test_kernel_ops().len();
    harness.challenge(&call_id);
    harness.sent().await;
    harness.answer("403 Forbidden", &call_id, "");
    harness.settle(UE_ADDR, &[6100]).await;
    assert!(harness
        .ipsec
        .test_kernel_accepts_inbound(pcscf_client(), ue_server(), old.spi_us));
    let shared = format!("policy:{PCSCF_IP}:{PCSCF_PORT_C}->{UE_ADDR}:6101:in");
    assert!(
        !harness.ipsec.test_kernel_ops()[ops_before..]
            .iter()
            .any(|op| *op == format!("del_policy {shared}")),
        "the shared policy is never deleted under the old set"
    );
}

/// TS 33.203 7.4.1a: "The UE shall delete all SAs it holds once all the IMPUs
/// are de-registered." Shutdown de-registers every UE over its set, deletes the
/// sets of the ones answered, and after a bounded wait those of the rest.
/// They used to stay in the kernel to their hard lifetime.
#[tokio::test]
async fn shutdown_deletes_every_set_answered_or_not_within_its_bound() {
    let mut harness = Harness::new();
    harness.add(1, "192.0.2.77");
    harness.add(2, "192.0.2.78");
    harness.register_initially(1, "192.0.2.77").await;
    harness.register_initially(2, "192.0.2.78").await;
    // UE 2 also mid re-authentication: an old and a temporary set.
    let refresh = harness.register(&impu(2));
    harness.challenge(&harness.call_id(&refresh));
    harness.sent().await;
    assert_eq!(harness.ipsec.active_count(), 3);

    let sent =
        crate::registrant::deregister_all(&harness.registrant, &harness.dispatcher.state.outbound);
    assert_eq!(sent, 1, "UE 2 was mid-authentication, not registered");
    assert!(
        harness.registrant.entries_due().is_empty(),
        "the loop has nothing left to refresh"
    );
    assert_eq!(
        harness.registrant.deregistration(&impu(2)),
        crate::registrant::Deregistration::Owed,
        "UE 2 de-registers once its REGISTER in flight is answered"
    );
    let deregistration = harness.sent().await;
    assert!(header(&deregistration, "Expires").is_some_and(|value| value == "0"));
    harness.answer(
        "200 OK",
        &header(&deregistration, "Call-ID").expect("Call-ID"),
        "",
    );

    let started = tokio::time::Instant::now();
    let answers_by = started + Duration::from_millis(300);
    crate::registrant::retire_ue_security_associations(&harness.registrant, answers_by).await;
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "bounded: {:?}",
        started.elapsed()
    );
    assert_eq!(harness.ipsec.active_count(), 0);
    assert_eq!(harness.ipsec.test_kernel_live_count(), 0);
    assert_eq!(harness.ipsec.test_spi_owner_count(), 0);
    assert_eq!(harness.registrant.tracked_sa_sets(), 0);
}

/// An unanswered protected de-REGISTER holds shutdown no longer than its
/// bound, and its set still goes.
#[tokio::test]
async fn an_unanswered_de_register_at_shutdown_waits_its_bound_then_deletes() {
    let mut harness = Harness::new();
    harness.add(1, UE_ADDR);
    harness.register_initially(1, UE_ADDR).await;
    crate::registrant::deregister_all(&harness.registrant, &harness.dispatcher.state.outbound);
    assert_eq!(
        harness.registrant.tracked_sa_sets(),
        1,
        "waiting on the answer"
    );

    let started = tokio::time::Instant::now();
    let deleted = crate::registrant::retire_ue_security_associations(
        &harness.registrant,
        started + Duration::from_millis(200),
    )
    .await;
    assert!(
        started.elapsed() >= Duration::from_millis(200),
        "waited for the answer"
    );
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(deleted, 1);
    assert_eq!(harness.ipsec.test_kernel_live_count(), 0);
    assert_eq!(harness.registrant.tracked_sa_sets(), 0);
}

/// Two UEs on one address with disjoint protected ports: removing one deletes
/// its sets only; the other's still receive.
#[tokio::test]
async fn two_ues_on_one_address_never_delete_each_others_sets() {
    let mut harness = Harness::new();
    harness.add(1, UE_ADDR);
    let mut second = test_support::ue(2, Some(ip(UE_ADDR)));
    second.ue_ipsec = Some(crate::registrant::UeIpsec::new(
        6200,
        6201,
        crate::ipsec::IntegrityAlgorithm::HmacSha1,
        crate::ipsec::EncryptionAlgorithm::Null,
    ));
    harness.registrant.try_add(second).expect("added");
    harness.register_initially(1, UE_ADDR).await;
    let built = harness.register(&impu(2));
    let call_id = harness.call_id(&built);
    harness.challenge(&call_id);
    harness.sent().await;
    harness.answer("200 OK", &call_id, "Expires: 600\r\n");
    let second_set = harness
        .ipsec
        .get_sa(&ip(UE_ADDR), 6200)
        .expect("UE 2's set");

    harness.registrant.remove(&impu(1));
    let deregistration = test_support::take_deregistrations(&harness.registrant)
        .pop()
        .expect("a de-REGISTER");
    harness.answer("200 OK", &harness.call_id(&deregistration), "");
    wait_for(|| {
        harness
            .ipsec
            .get_sa(&ip(UE_ADDR), 6100)
            .is_none()
            .then_some(())
    })
    .await;
    assert!(harness.ipsec.get_sa(&ip(UE_ADDR), 6200).is_some());
    assert!(harness.ipsec.test_kernel_accepts_inbound(
        pcscf_client(),
        SocketAddr::new(ip(UE_ADDR), 6201),
        second_set.spi_us
    ));
}

/// The per-module leak gate for the whole lifecycle: through many cycles of
/// register, re-challenge, resync and removal, then shutdown, the manager's
/// sets, the IPsec manager's pairs, the mock kernel's states and policies and
/// the SPI owner map all drain to zero.
#[tokio::test]
async fn every_store_drains_to_zero_across_lifecycle_cycles() {
    let mut harness = Harness::new();
    for cycle in 0..100u32 {
        harness.add(1, UE_ADDR);
        harness.register_initially(1, UE_ADDR).await;
        harness.rechallenged_refresh(&impu(1)).await;
        let refresh = harness.register(&impu(1));
        let call_id = harness.call_id(&refresh);
        let stale = format!(
            "WWW-Authenticate: {}\r\nSecurity-Server: {}\r\n",
            test_support::aka_challenge_value("000000000001"),
            test_support::security_server(90_000, 90_001)
        );
        harness.answer("401 Unauthorized", &call_id, &stale);
        harness.sent().await;
        harness.answer("200 OK", &call_id, "Expires: 600\r\n");
        if cycle % 2 == 0 {
            harness.registrant.remove(&impu(1));
            let deregistration = test_support::take_deregistrations(&harness.registrant)
                .pop()
                .expect("a de-REGISTER");
            harness.answer("200 OK", &harness.call_id(&deregistration), "");
        } else {
            crate::registrant::deregister_all(
                &harness.registrant,
                &harness.dispatcher.state.outbound,
            );
            while harness.dispatcher.udp.try_recv().is_ok() {}
            crate::registrant::retire_ue_security_associations(
                &harness.registrant,
                tokio::time::Instant::now(),
            )
            .await;
        }
        wait_for(|| (harness.ipsec.active_count() == 0).then_some(())).await;
        assert_eq!(harness.registrant.tracked_sa_sets(), 0, "cycle {cycle}");
        assert_eq!(harness.ipsec.test_kernel_live_count(), 0, "cycle {cycle}");
        assert_eq!(harness.ipsec.test_spi_owner_count(), 0, "cycle {cycle}");
        harness.sqn = 0;
        if cycle % 2 == 1 {
            // A shut-down registrant registers nothing again, as the process it
            // belongs to is going away: the next cycle is the next process.
            harness = Harness::new();
        }
    }
}
