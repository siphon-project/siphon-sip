//! A UE de-registering itself through the P-CSCF over its security
//! associations (3GPP TS 24.229 clause 5.2.5.1): on the 200 to the
//! de-REGISTER the P-CSCF removes the binding of the UE's contact address for
//! the public user identity in To (with its implicitly registered ones), and,
//! once no identity the UE registered over the pair is left, deletes the pair
//! "after the server transaction ... pertaining to this deregistration
//! terminates". It does so whether or not the script cached or cleared the
//! binding itself.
//!
//! Before: the pair went only if the registrar held no live binding from the
//! UE's protected client port by then, and nothing but the script removed the
//! binding the de-REGISTER ended. A script that cached the binding with
//! `registrar.save_proxy` on the registration's 200 and did not clear it on the
//! de-registration's (no call, or one refused because the 200 carries the
//! expiration in the Contact, not in an `Expires` header) kept the pair until
//! the binding expired.

use std::net::SocketAddr;
use std::time::Duration;

use super::ipsec_lifecycle_tests::{install, p_cscf, registrar_answers, PAST_TIMER_J, RELAY};
use super::proxy_dialog_state_tests::Proxy;
use super::*;
use crate::ipsec::IpsecManager;

/// A REGISTER from the UE at `ue` (its protected client port) for `aor`, its
/// Contact on the UE's protected server port, with `contact_params` on it and
/// `expires` in an `Expires` header when given.
fn register(
    ue: SocketAddr,
    aor: &str,
    call_id: &str,
    cseq: u32,
    contact_params: &str,
    expires: Option<u32>,
) -> String {
    let expires = expires
        .map(|expires| format!("Expires: {expires}\r\n"))
        .unwrap_or_default();
    format!(
        concat!(
            "REGISTER sip:ims.example.invalid SIP/2.0\r\n",
            "Via: SIP/2.0/UDP {ue};branch=z9hG4bK-{call_id}-{cseq}\r\n",
            "Max-Forwards: 70\r\n",
            "From: <{aor}>;tag=ue-tag\r\n",
            "To: <{aor}>\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: {cseq} REGISTER\r\n",
            "Contact: <{contact}>{contact_params}\r\n",
            "{expires}",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        ue = ue,
        aor = aor,
        call_id = call_id,
        cseq = cseq,
        contact = contact_of(ue),
        contact_params = contact_params,
        expires = expires,
    )
}

/// The Contact a UE at `ue` registers: its protected server port.
fn contact_of(ue: SocketAddr) -> String {
    format!("sip:ue@{}:{}", ue.ip(), ue.port() + 1)
}

/// The binding a P-CSCF script caches from the 200 to the UE's registration
/// (`registrar.save_proxy`): `contact` for `aor`, from the UE's protected
/// client port.
fn cache_binding(aor: &str, contact: &str, ue: SocketAddr) {
    crate::script::api::test_registrar()
        .save_with_source(
            aor,
            crate::sip::parser::parse_uri_standalone(contact).expect("a URI"),
            600,
            1.0,
            format!("{aor}-registration"),
            1,
            Some(ue),
            Some(Transport::Udp),
        )
        .expect("the binding is cached");
}

fn bindings_from(aor: &str, ue: SocketAddr) -> Vec<String> {
    crate::script::api::test_registrar()
        .lookup(aor)
        .into_iter()
        .filter(|contact| contact.source_addr == Some(ue))
        .map(|contact| contact.uri.to_string())
        .collect()
}

/// The UE de-registers `aor` over its pair (Expires: 0) and the S-CSCF accepts
/// it with a 200 that names the Contact with `expires=0` and carries no
/// `Expires` header. Returns what reached the UE.
fn de_register(proxy: &Proxy, ue: SocketAddr, aor: &str, call_id: &str) -> Vec<u16> {
    registrar_answers(
        proxy,
        ue,
        &register(ue, aor, call_id, 3, "", Some(0)),
        200,
        "",
    )
}

async fn gone_within(manager: &IpsecManager, ue: SocketAddr, within: Duration) -> bool {
    let deadline = std::time::Instant::now() + within;
    while std::time::Instant::now() < deadline {
        if !manager.has_sa(&ue.ip(), ue.port()) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    !manager.has_sa(&ue.ip(), ue.port())
}

/// The 200 leaves over the pair; the binding the script cached and never
/// cleared goes with it; the pair goes once the server transaction is over,
/// and with it its kernel objects, its SPIs and the pair count the
/// `siphon_ipsec_sa_pairs` gauge reports.
#[tokio::test(flavor = "multi_thread")]
async fn a_de_register_deletes_the_pair_although_the_script_kept_the_binding() {
    let (proxy, manager) = p_cscf(RELAY);
    let ue: SocketAddr = "198.51.100.240:6100".parse().expect("an address");
    let aor = "sip:dereg-240@ims.example.invalid";
    install(&manager, ue).await;
    cache_binding(aor, &contact_of(ue), ue);
    assert_eq!(manager.active_count(), 1);

    let to_ue = de_register(&proxy, ue, aor, "dereg-240");
    assert_eq!(to_ue, [200], "the 200 is relayed to the UE");
    assert!(
        manager.has_sa(&ue.ip(), ue.port()),
        "the 200, and any retransmission of it, leaves over the pair"
    );
    assert!(
        bindings_from(aor, ue).is_empty(),
        "the binding of the de-registered contact address is removed (TS 24.229 5.2.5.1 1)"
    );

    tokio::time::sleep(PAST_TIMER_J).await;
    assert!(
        !manager.has_sa(&ue.ip(), ue.port()),
        "the pair goes after the server transaction (TS 24.229 5.2.5.1 2)"
    );
    assert_eq!(manager.active_count(), 0, "siphon_ipsec_sa_pairs drops");
    assert_eq!(
        manager.test_kernel_live_count(),
        0,
        "SAs and policies removed"
    );
    assert_eq!(manager.test_spi_owner_count(), 0, "its SPIs are released");
}

/// The UE registers again on the same protected client port: the
/// re-registration's challenge finds nothing there to replace, and afterwards
/// only its own pair exists.
#[tokio::test(flavor = "multi_thread")]
async fn a_re_registration_after_a_de_register_on_the_same_port_holds_only_the_new_pair() {
    let (proxy, manager) = p_cscf(RELAY);
    let ue: SocketAddr = "198.51.100.241:6100".parse().expect("an address");
    let aor = "sip:dereg-241@ims.example.invalid";
    install(&manager, ue).await;
    cache_binding(aor, &contact_of(ue), ue);

    de_register(&proxy, ue, aor, "dereg-241");
    tokio::time::sleep(PAST_TIMER_J).await;
    assert!(
        !manager.has_sa(&ue.ip(), ue.port()),
        "no pair left on the port when the UE registers again"
    );

    // The re-registration's challenge installs the new pair on the same port.
    let new = install(&manager, ue).await;
    cache_binding(aor, &contact_of(ue), ue);
    registrar_answers(
        &proxy,
        ue,
        &register(ue, aor, "rereg-241", 5, "", Some(600)),
        200,
        "Expires: 600\r\n",
    );
    tokio::time::sleep(PAST_TIMER_J).await;
    assert_eq!(manager.active_count(), 1);
    assert!(
        manager.holds_installation(&new),
        "the new pair is the one held"
    );
    assert_eq!(
        manager.test_kernel_live_count(),
        8,
        "one pair's SAs and policies"
    );
    assert_eq!(manager.test_spi_owner_count(), 2, "one pair's SPIs");
}

/// A re-registration that challenges before the de-registered pair's hold is
/// over replaces the pair on the port, and the old pair's retirement, named by
/// its own SPIs, leaves the new one alone.
#[tokio::test(flavor = "multi_thread")]
async fn a_re_registration_within_the_hold_keeps_its_new_pair() {
    let (proxy, manager) = p_cscf(RELAY);
    let ue: SocketAddr = "198.51.100.242:6100".parse().expect("an address");
    let aor = "sip:dereg-242@ims.example.invalid";
    install(&manager, ue).await;
    cache_binding(aor, &contact_of(ue), ue);

    de_register(&proxy, ue, aor, "dereg-242");
    let new = install(&manager, ue).await;
    tokio::time::sleep(PAST_TIMER_J).await;
    assert!(manager.holds_installation(&new), "the new pair is kept");
    assert_eq!(manager.active_count(), 1);
    assert_eq!(manager.test_kernel_live_count(), 8);
}

/// A de-REGISTER of one of two contact addresses the UE registered over the
/// same pair removes that binding only, and the pair stays for the other.
#[tokio::test(flavor = "multi_thread")]
async fn removing_one_of_two_contacts_on_the_same_flow_keeps_the_pair() {
    let (proxy, manager) = p_cscf(RELAY);
    let ue: SocketAddr = "198.51.100.243:6100".parse().expect("an address");
    let aor = "sip:dereg-243@ims.example.invalid";
    let other = format!("sip:other@{}:{}", ue.ip(), ue.port() + 1);
    install(&manager, ue).await;
    cache_binding(aor, &contact_of(ue), ue);
    cache_binding(aor, &other, ue);

    let to_ue = registrar_answers(
        &proxy,
        ue,
        &register(ue, aor, "dereg-243", 3, ";expires=0", None),
        200,
        "",
    );
    assert_eq!(to_ue, [200]);
    tokio::time::sleep(PAST_TIMER_J).await;
    assert_eq!(
        bindings_from(aor, ue),
        [other],
        "only the de-registered contact address is removed"
    );
    assert!(
        manager.has_sa(&ue.ip(), ue.port()),
        "the pair stays for the binding still registered over it"
    );
}

/// The UE de-registers an implicitly registered identity of its set: the set's
/// binding, stored under the primary identity, goes, and the pair with it.
#[tokio::test(flavor = "multi_thread")]
async fn a_de_register_of_an_implicitly_registered_identity_ends_the_set() {
    let (proxy, manager) = p_cscf(RELAY);
    let ue: SocketAddr = "198.51.100.244:6100".parse().expect("an address");
    let primary = "sip:dereg-244@ims.example.invalid";
    let alias = "sip:+15550100244@ims.example.invalid";
    install(&manager, ue).await;
    cache_binding(primary, &contact_of(ue), ue);
    crate::script::api::test_registrar()
        .set_associated_uris(primary, vec![primary.to_string(), alias.to_string()]);

    de_register(&proxy, ue, alias, "dereg-244");
    assert!(bindings_from(primary, ue).is_empty());
    assert!(gone_within(&manager, ue, Duration::from_secs(2)).await);
}

/// Leak gate: register / de-register cycles on one UE and port. After them
/// the pair count, SPIs, kernel objects, pending sets, per-pair lifecycle
/// stores and cached bindings are back to their baseline, and the deleted-flow
/// bar holds the UE's two protected ports, however many cycles ran.
#[tokio::test(flavor = "multi_thread")]
async fn register_and_de_register_cycles_return_every_store_to_baseline() {
    const CYCLES: u32 = 12;
    let (proxy, manager) = p_cscf(RELAY);
    let ue: SocketAddr = "198.51.100.245:6100".parse().expect("an address");
    let aor = "sip:dereg-245@ims.example.invalid";
    let baseline_spis = manager.spi_usage().0;
    let mut deleted_flows_after_first = None;

    for cycle in 0..CYCLES {
        install(&manager, ue).await;
        // The registration's 200 over the pair, and the binding cached from it.
        cache_binding(aor, &contact_of(ue), ue);
        let cseq = cycle * 2 + 1;
        registrar_answers(
            &proxy,
            ue,
            &register(ue, aor, &format!("reg-245-{cycle}"), cseq, "", Some(600)),
            200,
            "Expires: 600\r\n",
        );
        registrar_answers(
            &proxy,
            ue,
            &register(
                ue,
                aor,
                &format!("dereg-245-{cycle}"),
                cseq + 1,
                "",
                Some(0),
            ),
            200,
            "",
        );
        assert!(
            gone_within(&manager, ue, Duration::from_secs(2)).await,
            "cycle {cycle}: the de-registered pair goes"
        );
        let deleted_flows = manager.deleted_flow_count();
        assert_eq!(
            *deleted_flows_after_first.get_or_insert(deleted_flows),
            deleted_flows,
            "cycle {cycle}: the deleted-flow bar does not grow per cycle"
        );
    }

    assert_eq!(manager.active_count(), 0, "pairs");
    assert_eq!(manager.spi_usage().0, baseline_spis, "SPIs");
    assert_eq!(manager.test_spi_owner_count(), 0, "SPI owners");
    assert_eq!(
        manager.test_kernel_live_count(),
        0,
        "kernel SAs and policies"
    );
    assert_eq!(manager.test_pending_count(), 0, "pending sets");
    assert_eq!(
        manager.test_lifecycle_sizes(),
        (0, 0, 0, 0),
        "registered, predecessors, retiring, awaiting NOTIFY"
    );
    assert!(bindings_from(aor, ue).is_empty(), "cached bindings");
    assert!(
        manager.deleted_flow_count() <= 2,
        "the UE's two protected ports at most"
    );
}
