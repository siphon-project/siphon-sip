//! A P-CSCF's REGISTER traffic moving the UE's security associations: the 2xx
//! to a relayed de-REGISTER deletes the pair once the server transaction is
//! over (TS 24.229 clause 5.2.5.1), unless another identity of the UE is still
//! registered over it; a 2xx the script answered does the same; a relayed 2xx
//! to a registration notes the binding the pair now carries; and the 401 to a
//! REGISTER that came protected marks the pair it came over as the one a
//! re-registration keeps for a while (TS 33.203 clause 7.4.2a).
//!
//! The manager runs on the in-memory kernel and the transaction layer on a 2 ms
//! T1, so Timer J (64*T1) is 128 ms of real time. The registrar is the process
//! one, so each test has a UE address of its own.

use std::net::SocketAddr;
use std::time::Duration;

use super::proxy_dialog_state_tests::{response_to, Proxy};
use super::test_dispatcher::test_dispatcher_with_script;
use super::*;
use crate::ipsec::{
    EncryptionAlgorithm, IntegrityAlgorithm, IpsecManager, SaProtocol, SaRole,
    SecurityAssociationPair,
};
use crate::transaction::timer::TimerConfig;

pub(super) const REGISTRAR: &str = "198.51.100.12:5060";

pub(super) const RELAY: &str = concat!(
    "from siphon import proxy\n",
    "\n",
    "@proxy.on_request\n",
    "def route(request):\n",
    "    request.relay(\"sip:registrar@198.51.100.12:5060\")\n",
);

pub(super) const ANSWER: &str = concat!(
    "from siphon import proxy\n",
    "\n",
    "@proxy.on_request\n",
    "def route(request):\n",
    "    request.reply(200, \"OK\")\n",
);

const T1: Duration = Duration::from_millis(2);

/// Comfortably past Timer J (64*T1 = 128 ms).
pub(super) const PAST_TIMER_J: Duration = Duration::from_millis(600);

pub(super) fn p_cscf(script: &str) -> (Proxy, Arc<IpsecManager>) {
    p_cscf_with_client_ports(script, "5064")
}

/// [`p_cscf`] with `ipsec.pcscf_port_c` set to `client_ports` (YAML).
fn p_cscf_with_client_ports(script: &str, client_ports: &str) -> (Proxy, Arc<IpsecManager>) {
    let mut dispatcher = test_dispatcher_with_script(script);
    let timers = TimerConfig::new(T1, Duration::from_millis(8), Duration::from_millis(10));
    dispatcher.state.transaction_manager = Arc::new(TransactionManager::new(timers));
    let manager = Arc::new(IpsecManager::with_test_kernel());
    dispatcher.state.ipsec_manager = Some(Arc::clone(&manager));
    // The harness listens on 5060: make that the protected server port.
    dispatcher.state.ipsec_config = Some(
        crate::config::yaml::from_str(&format!("pcscf_port_s: 5060\npcscf_port_c: {client_ports}"))
            .expect("an ipsec block"),
    );
    (
        Proxy {
            state: Arc::new(dispatcher.state),
            udp: dispatcher.udp,
        },
        manager,
    )
}

/// The pair a UE at `ue` (its protected client port) set up, with its own
/// server port next to it.
pub(super) async fn install(manager: &IpsecManager, ue: SocketAddr) -> SecurityAssociationPair {
    install_with_server_port(manager, ue, ue.port() + 1).await
}

/// [`install`] with the UE's protected server port `ue_port_s`, which a UE
/// keeps across a re-authentication (TS 33.203 clause 7.4.0).
async fn install_with_server_port(
    manager: &IpsecManager,
    ue: SocketAddr,
    ue_port_s: u16,
) -> SecurityAssociationPair {
    install_with_ports(manager, ue, ue_port_s, 5064).await
}

/// [`install_with_server_port`] with the P-CSCF protected client port
/// `pcscf_port_c`.
async fn install_with_ports(
    manager: &IpsecManager,
    ue: SocketAddr,
    ue_port_s: u16,
    pcscf_port_c: u16,
) -> SecurityAssociationPair {
    let (spi_pc, spi_ps) = manager.allocate_spi_pair().expect("room in the partition");
    let sa = SecurityAssociationPair {
        ue_addr: ue.ip(),
        pcscf_addr: "192.0.2.1".parse().expect("an address"),
        ue_port_c: ue.port(),
        ue_port_s,
        pcscf_port_c,
        pcscf_port_s: 5060,
        spi_uc: 80_000 + u32::from(ue.port()),
        spi_us: 90_000 + u32::from(ue.port()),
        spi_pc,
        spi_ps,
        ealg: EncryptionAlgorithm::Null,
        aalg: IntegrityAlgorithm::HmacSha1,
        encryption_key: String::new(),
        integrity_key: "00112233445566778899aabbccddeeff".to_string(),
        hard_lifetime_secs: Some(3600),
        protocol: SaProtocol::Any,
        expires_at: std::time::Instant::now(),
        created_at: std::time::Instant::now(),
        role: SaRole::PCscf,
        impi: None,
        security_server: None,
    };
    manager.create_sa_pair(sa.clone()).await.expect("installed");
    std::thread::sleep(Duration::from_millis(2));
    sa
}

fn register(ue: SocketAddr, call_id: &str, cseq: u32, expires: u32) -> String {
    format!(
        concat!(
            "REGISTER sip:ims.example.invalid SIP/2.0\r\n",
            "Via: SIP/2.0/UDP {ue};branch=z9hG4bK-{call_id}-{cseq}\r\n",
            "Max-Forwards: 70\r\n",
            "From: <sip:001010000000001@ims.example.invalid>;tag=ue-tag\r\n",
            "To: <sip:001010000000001@ims.example.invalid>\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: {cseq} REGISTER\r\n",
            "Contact: <sip:ue@{host}:{port_s}>\r\n",
            "Expires: {expires}\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        ue = ue,
        host = ue.ip(),
        port_s = ue.port() + 1,
        call_id = call_id,
        cseq = cseq,
        expires = expires,
    )
}

/// The UE sends `raw`; the registrar answers the relayed REGISTER with
/// `status_code` and `extra` headers. Returns what the UE was sent.
pub(super) fn registrar_answers(
    proxy: &Proxy,
    ue: SocketAddr,
    raw: &str,
    status_code: u16,
    extra: &str,
) -> Vec<u16> {
    registrar_answers_on_the_wire(proxy, ue, raw, status_code, extra)
        .into_iter()
        .map(|(status_code, ..)| status_code)
        .collect()
}

/// [`registrar_answers`], with where each response to the UE went and the
/// local socket it left from.
fn registrar_answers_on_the_wire(
    proxy: &Proxy,
    ue: SocketAddr,
    raw: &str,
    status_code: u16,
    extra: &str,
) -> Vec<(u16, SocketAddr, Option<SocketAddr>)> {
    proxy.request(&ue.to_string(), raw);
    let relayed: Vec<SipMessage> = proxy
        .wire()
        .into_iter()
        .filter(|sent| sent.destination == REGISTRAR)
        .map(|sent| sent.message)
        .collect();
    assert_eq!(relayed.len(), 1, "the REGISTER is relayed");
    let reason = if status_code == 401 {
        "Unauthorized"
    } else {
        "OK"
    };
    proxy.response(
        REGISTRAR,
        response_to(
            &relayed[0],
            status_code,
            reason,
            "scscf",
            "sip:ue@198.51.100.1",
            extra,
        ),
    );
    // A 2xx over a pending pair is held until the pair is taken into use, on
    // a task of its own, so it can reach the wire a moment after this returns.
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        let to_ue: Vec<(u16, SocketAddr, Option<SocketAddr>)> = proxy
            .wire()
            .into_iter()
            // Over UDP the response goes to the UE's protected server port, not
            // the client port the request came from (TS 33.203 clause 7.1).
            .filter_map(|sent| {
                let destination = sent.destination.parse::<SocketAddr>().ok()?;
                (destination.ip() == ue.ip())
                    .then(|| {
                        sent.message
                            .status_code()
                            .map(|code| (code, destination, sent.source))
                    })
                    .flatten()
            })
            .collect();
        if !to_ue.is_empty() || std::time::Instant::now() >= deadline {
            return to_ue;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
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

/// The relayed 200 to a de-REGISTER leaves over the pair, and the pair goes
/// once the server transaction is over (Timer J).
///
/// Before: only a 200 the script answered itself deleted the pair, so a P-CSCF
/// relaying the de-REGISTER kept the UE's associations, and the connections
/// over them, until their hard lifetime.
#[tokio::test(flavor = "multi_thread")]
async fn the_relayed_2xx_to_a_de_register_deletes_the_pair_after_timer_j() {
    let (proxy, manager) = p_cscf(RELAY);
    let ue: SocketAddr = "198.51.100.90:6100".parse().expect("an address");
    install(&manager, ue).await;

    let to_ue = registrar_answers(&proxy, ue, &register(ue, "dereg-90", 3, 0), 200, "");
    assert_eq!(to_ue, [200], "the 200 is relayed to the UE");
    assert!(
        manager.has_sa(&ue.ip(), ue.port()),
        "the 200 and its retransmissions still leave over the pair"
    );

    tokio::time::sleep(PAST_TIMER_J).await;
    assert!(!manager.has_sa(&ue.ip(), ue.port()), "the pair is deleted");
    assert_eq!(manager.active_count(), 0);
}

/// Another identity the UE registered over the same pair keeps it: only once
/// every one is de-registered does it go.
#[tokio::test(flavor = "multi_thread")]
async fn a_de_register_of_one_identity_keeps_the_pair_another_still_uses() {
    let (proxy, manager) = p_cscf(RELAY);
    let ue: SocketAddr = "198.51.100.91:6100".parse().expect("an address");
    install(&manager, ue).await;
    register_binding("sip:other-identity-91@ims.example.invalid", ue);

    registrar_answers(&proxy, ue, &register(ue, "dereg-91", 3, 0), 200, "");
    tokio::time::sleep(PAST_TIMER_J).await;
    assert!(manager.has_sa(&ue.ip(), ue.port()));
}

/// A refused de-REGISTER, and a registration, delete nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_de_register_or_a_registration_keeps_the_pair() {
    let (proxy, manager) = p_cscf(RELAY);
    let ue: SocketAddr = "198.51.100.92:6100".parse().expect("an address");
    install(&manager, ue).await;

    registrar_answers(&proxy, ue, &register(ue, "dereg-92", 3, 0), 403, "");
    registrar_answers(&proxy, ue, &register(ue, "rereg-92", 4, 600), 200, "");
    tokio::time::sleep(PAST_TIMER_J).await;
    assert!(manager.has_sa(&ue.ip(), ue.port()));
}

/// The 2xx to a registration that left a binding notes it on the pair, so the
/// pair goes when the binding does: here the script removing it, as it does
/// on a reg-event NOTIFY that ended the registration (TS 24.229 clause
/// 5.2.5.2), seen by the next sweep.
#[tokio::test(flavor = "multi_thread")]
async fn a_registration_relayed_over_a_pair_ties_the_pair_to_its_binding() {
    let (proxy, manager) = p_cscf(RELAY);
    let ue: SocketAddr = "198.51.100.93:6100".parse().expect("an address");
    install(&manager, ue).await;
    let aor = "sip:impu-93@ims.example.invalid";
    // The binding the script saves from the 200 (`registrar.save_proxy`).
    register_binding(aor, ue);

    registrar_answers(&proxy, ue, &register(ue, "reg-93", 2, 600), 200, "");
    crate::script::api::test_registrar().remove_all(aor);
    assert_eq!(
        manager.reconcile_registrations(Duration::from_millis(10)),
        1,
        "the pair the binding was registered over is shortened"
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!manager.has_sa(&ue.ip(), ue.port()));
}

/// The script answering the de-REGISTER itself: the same, once its server
/// transaction is over.
#[tokio::test(flavor = "multi_thread")]
async fn a_2xx_the_script_answers_to_a_de_register_deletes_the_pair_after_timer_j() {
    let (proxy, manager) = p_cscf(ANSWER);
    let ue: SocketAddr = "198.51.100.94:6100".parse().expect("an address");
    install(&manager, ue).await;

    proxy.request(&ue.to_string(), &register(ue, "dereg-94", 3, 0));
    assert!(
        manager.has_sa(&ue.ip(), ue.port()),
        "the 200 leaves over the pair"
    );
    tokio::time::sleep(PAST_TIMER_J).await;
    assert!(!manager.has_sa(&ue.ip(), ue.port()));
}

/// The 401 to a REGISTER that came over the UE's pair marks that pair as the
/// one the re-registration keeps while its transactions finish; once the new
/// pair is taken into use the old one stays for the grace, then goes.
#[tokio::test(flavor = "multi_thread")]
async fn the_pair_a_re_register_came_over_is_kept_for_the_grace_after_activation() {
    let (proxy, manager) = p_cscf(RELAY);
    let old: SocketAddr = "198.51.100.95:6100".parse().expect("an address");
    install(&manager, old).await;
    // What `ipsec.allocate` installed for the re-registration's challenge.
    let new = install(&manager, "198.51.100.95:6200".parse().expect("an address")).await;
    let security_server = format!(
        "Security-Server: ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;spi-c={};spi-s={};port-c=5064;port-s=5060\r\n",
        new.spi_pc, new.spi_ps
    );

    let to_ue = registrar_answers(
        &proxy,
        old,
        &register(old, "rereg-95", 5, 600),
        401,
        &security_server,
    );
    assert_eq!(to_ue, [401]);

    manager
        .supersede_pairs_for_ue(&old.ip(), new.ue_port_c, Duration::from_millis(100))
        .await;
    assert!(
        manager.has_sa(&old.ip(), old.port()),
        "kept for its pending transactions"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!manager.has_sa(&old.ip(), old.port()));
    assert!(manager.has_sa(&old.ip(), new.ue_port_c));
}

/// A re-authentication through the relaying P-CSCF: the set the challenge sets
/// up is installed (what `ipsec.allocate` does) before the 401 leaves, yet the
/// 401 leaves with the kernel's outbound policy of the shared selector still
/// naming the old set, which the UE holds (TS 24.229 clause 5.2.2.2). The 200
/// to the REGISTER that came over the new set leaves with that policy naming
/// the new set (TS 33.203 clause 7.4.2a, SM12), and the old set is kept for
/// its pending transactions.
///
/// Before: the install named the new set at once, so the 401 went over an SA
/// the UE could not have yet, and the UE dropped it.
#[tokio::test(flavor = "multi_thread")]
async fn a_re_authentication_challenge_leaves_over_the_old_set_and_its_2xx_over_the_new() {
    let (proxy, manager) = p_cscf(RELAY);
    let old_ue: SocketAddr = "198.51.100.96:6100".parse().expect("an address");
    let new_ue: SocketAddr = "198.51.100.96:6102".parse().expect("an address");
    let outbound = "policy:192.0.2.1:5064->198.51.100.96:6101:out";
    let old = install_with_server_port(&manager, old_ue, 6101).await;
    let new = install_with_server_port(&manager, new_ue, 6101).await;
    assert!(manager.is_pending(&new_ue.ip(), new_ue.port()));
    let security_server = format!(
        "Security-Server: ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;spi-c={};spi-s={};port-c=5064;port-s=5060\r\n",
        new.spi_pc, new.spi_ps
    );

    let to_ue = registrar_answers(
        &proxy,
        old_ue,
        &register(old_ue, "reauth-96", 7, 600),
        401,
        &security_server,
    );
    assert_eq!(to_ue, [401]);
    assert_eq!(
        manager.test_kernel_policy_template(outbound),
        Some(old.spi_us),
        "the 401 leaves over the set the UE holds"
    );
    assert!(manager.is_pending(&new_ue.ip(), new_ue.port()));

    let to_ue = registrar_answers(
        &proxy,
        new_ue,
        &register(new_ue, "reauth-96", 8, 600),
        200,
        "Expires: 600\r\n",
    );
    assert!(to_ue.contains(&200), "{to_ue:?}");
    assert_eq!(
        manager.test_kernel_policy_template(outbound),
        Some(new.spi_us),
        "the 200 leaves over the new set"
    );
    assert!(!manager.is_pending(&new_ue.ip(), new_ue.port()));
    assert!(
        manager.has_sa(&old_ue.ip(), old_ue.port()),
        "the old set stays for its pending transactions"
    );
}

/// The 2xx to a REGISTER over a pending pair does not wait, on the thread that
/// forwards it, for the kernel to take the pair into use: it is held at the
/// egress until the policy update is over, and then leaves over the new set.
///
/// Before: the response path blocked (`block_in_place` + `block_on`) on the
/// netlink round trip. On an executor worker still attached to Python that
/// holds up every free-threaded stop-the-world, and with it each thread that
/// attaches, the blocking-pool thread the round trip runs on among them.
#[tokio::test(flavor = "multi_thread")]
async fn a_2xx_over_a_pending_pair_does_not_wait_for_the_policy_update() {
    let (proxy, manager) = p_cscf(RELAY);
    let old_ue: SocketAddr = "198.51.100.97:6100".parse().expect("an address");
    let new_ue: SocketAddr = "198.51.100.97:6102".parse().expect("an address");
    let outbound = "policy:192.0.2.1:5064->198.51.100.97:6101:out";
    let old = install_with_server_port(&manager, old_ue, 6101).await;
    let new = install_with_server_port(&manager, new_ue, 6101).await;
    assert!(manager.is_pending(&new_ue.ip(), new_ue.port()));

    proxy.request(&new_ue.to_string(), &register(new_ue, "stall-97", 8, 600));
    let relayed: Vec<SipMessage> = proxy
        .wire()
        .into_iter()
        .filter(|sent| sent.destination == REGISTRAR)
        .map(|sent| sent.message)
        .collect();
    assert_eq!(relayed.len(), 1, "the REGISTER is relayed");
    let answer = response_to(
        &relayed[0],
        200,
        "OK",
        "scscf",
        "sip:ue@198.51.100.1",
        "Expires: 600\r\n",
    );

    let gate = manager.test_stall_policy_updates();
    let state = Arc::clone(&proxy.state);
    let forwarding = tokio::task::spawn_blocking(move || {
        let raw = String::from_utf8(answer.to_bytes()).expect("UTF-8");
        handle_response(
            super::proxy_dialog_state_tests::inbound(REGISTRAR, &raw),
            answer,
            200,
            &state,
        );
    });
    let returned = tokio::time::timeout(Duration::from_secs(1), forwarding).await;
    // Let a blocked forward finish either way, so a failure does not hang.
    gate.add_permits(64);
    assert!(
        returned.is_ok(),
        "forwarding the 2xx waited for the kernel policy update"
    );

    let mut to_ue = Vec::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !to_ue.contains(&200) && std::time::Instant::now() < deadline {
        to_ue.extend(
            proxy
                .wire()
                .into_iter()
                .filter(|sent| {
                    sent.destination
                        .parse::<SocketAddr>()
                        .is_ok_and(|destination| destination.ip() == new_ue.ip())
                })
                .filter_map(|sent| sent.message.status_code()),
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(to_ue, [200], "the 2xx leaves once, after the update");
    assert_eq!(
        manager.test_kernel_policy_template(outbound),
        Some(new.spi_us),
        "the 2xx leaves over the new set"
    );
    assert_ne!(old.spi_us, new.spi_us);
    assert!(!manager.is_pending(&new_ue.ip(), new_ue.port()));
    assert!(
        !crate::ipsec::switch::is_held(new_ue.ip()),
        "the UE's messages are not held once the 2xx is out"
    );
}

/// While the policy update is held up, nothing to the UE leaves: the 2xx is
/// held until the update is over, so it never goes out over the old set.
#[tokio::test(flavor = "multi_thread")]
async fn the_2xx_is_held_until_the_policy_update_is_over() {
    let (proxy, manager) = p_cscf(ANSWER);
    let old_ue: SocketAddr = "198.51.100.98:6100".parse().expect("an address");
    let new_ue: SocketAddr = "198.51.100.98:6102".parse().expect("an address");
    let outbound = "policy:192.0.2.1:5064->198.51.100.98:6101:out";
    let old = install_with_server_port(&manager, old_ue, 6101).await;
    let new = install_with_server_port(&manager, new_ue, 6101).await;
    let gate = manager.test_stall_policy_updates();

    // The script answers the REGISTER itself (request_script.rs).
    let state = Arc::clone(&proxy.state);
    let answering = tokio::task::spawn_blocking(move || {
        let raw = register(new_ue, "held-98", 8, 600);
        let message = parse_sip_message_bytes(raw.as_bytes()).expect("the request parses");
        handle_request(
            super::proxy_dialog_state_tests::inbound(&new_ue.to_string(), &raw),
            message,
            "REGISTER".to_string(),
            &state,
        );
    });
    let returned = tokio::time::timeout(Duration::from_secs(1), answering).await;
    if returned.is_err() {
        gate.add_permits(64);
        panic!("answering the REGISTER waited for the kernel policy update");
    }
    let early: Vec<u16> = proxy
        .wire()
        .into_iter()
        .filter_map(|sent| sent.message.status_code())
        .collect();
    assert!(early.is_empty(), "sent before the update: {early:?}");
    assert_eq!(
        manager.test_kernel_policy_template(outbound),
        Some(old.spi_us)
    );
    assert!(crate::ipsec::switch::is_held(new_ue.ip()));

    gate.add_permits(64);
    let mut sent = Vec::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while sent.is_empty() && std::time::Instant::now() < deadline {
        sent.extend(
            proxy
                .wire()
                .into_iter()
                .filter_map(|sent| sent.message.status_code()),
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(sent, [200]);
    assert_eq!(
        manager.test_kernel_policy_template(outbound),
        Some(new.spi_us)
    );
    assert!(!crate::ipsec::switch::is_held(new_ue.ip()));
}

/// With `ipsec.pcscf_port_c` listing two ports, a re-authentication's set has
/// its own protected client port (TS 33.203 clause 7.4.0): the 401 to the
/// REGISTER over the old set leaves from the old set's port_pc, the 200 to the
/// REGISTER over the new set from the new one's (TS 33.203 clause 7.4.2a, SM6
/// and SM12), and no kernel policy moves for either. The new set then waits
/// for a further message over it before requests to the UE use it.
#[tokio::test(flavor = "multi_thread")]
async fn with_two_client_ports_the_challenge_and_the_2xx_leave_from_their_own_sets() {
    let (proxy, manager) = p_cscf_with_client_ports(RELAY, "[5064, 5068]");
    let old_ue: SocketAddr = "198.51.100.89:6100".parse().expect("an address");
    let new_ue: SocketAddr = "198.51.100.89:6102".parse().expect("an address");
    let port_us: SocketAddr = "198.51.100.89:6101".parse().expect("an address");
    install_with_ports(&manager, old_ue, 6101, 5064).await;
    let new = install_with_ports(&manager, new_ue, 6101, 5068).await;
    assert_eq!(
        manager.pending_how(&new_ue.ip(), new_ue.port()),
        Some(crate::ipsec::retire::Pending::Challenged)
    );
    let security_server = format!(
        "Security-Server: ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;spi-c={};spi-s={};port-c=5068;port-s=5060\r\n",
        new.spi_pc, new.spi_ps
    );
    let ops_before = manager.test_kernel_ops().len();

    let to_ue = registrar_answers_on_the_wire(
        &proxy,
        old_ue,
        &register(old_ue, "reauth-97", 7, 600),
        401,
        &security_server,
    );
    let from_old = "192.0.2.1:5064".parse().ok();
    assert_eq!(to_ue, [(401, port_us, from_old)], "SM6 over the old set");

    let to_ue = registrar_answers_on_the_wire(
        &proxy,
        new_ue,
        &register(new_ue, "reauth-97", 8, 600),
        200,
        "Expires: 600\r\n",
    );
    let from_new = "192.0.2.1:5068".parse().ok();
    assert!(
        to_ue.contains(&(200, port_us, from_new)),
        "SM12 over the new set: {to_ue:?}"
    );
    assert!(
        !manager.test_kernel_ops()[ops_before..]
            .iter()
            .any(|op| op.starts_with("update_policy")),
        "no shared policy to move"
    );
    assert_eq!(
        manager.pending_how(&new_ue.ip(), new_ue.port()),
        Some(crate::ipsec::retire::Pending::Registered)
    );
    assert_eq!(
        manager.udp_request_flow_to_ue(new_ue),
        crate::ipsec::FlowToUe::Protected {
            local: "192.0.2.1:5064".parse().expect("an address"),
            destination: port_us,
        },
        "requests stay on the old set for now"
    );
    assert!(manager.has_sa(&old_ue.ip(), old_ue.port()));
    assert!(
        !crate::ipsec::switch::is_held(new_ue.ip()),
        "nothing to hold: no policy update to wait for"
    );
}
