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
const PAST_TIMER_J: Duration = Duration::from_millis(600);

pub(super) fn p_cscf(script: &str) -> (Proxy, Arc<IpsecManager>) {
    let mut dispatcher = test_dispatcher_with_script(script);
    let timers = TimerConfig::new(T1, Duration::from_millis(8), Duration::from_millis(10));
    dispatcher.state.transaction_manager = Arc::new(TransactionManager::new(timers));
    let manager = Arc::new(IpsecManager::with_test_kernel());
    dispatcher.state.ipsec_manager = Some(Arc::clone(&manager));
    // The harness listens on 5060: make that the protected server port.
    dispatcher.state.ipsec_config = Some(
        crate::config::yaml::from_str("pcscf_port_s: 5060\npcscf_port_c: 5064")
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
    let (spi_pc, spi_ps) = manager.allocate_spi_pair().expect("room in the partition");
    let sa = SecurityAssociationPair {
        ue_addr: ue.ip(),
        pcscf_addr: "192.0.2.1".parse().expect("an address"),
        ue_port_c: ue.port(),
        ue_port_s: ue.port() + 1,
        pcscf_port_c: 5064,
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
fn registrar_answers(
    proxy: &Proxy,
    ue: SocketAddr,
    raw: &str,
    status_code: u16,
    extra: &str,
) -> Vec<u16> {
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
    proxy
        .wire()
        .into_iter()
        // Over UDP the response goes to the UE's protected server port, not
        // the client port the request came from (TS 33.203 clause 7.1).
        .filter(|sent| {
            sent.destination
                .parse::<SocketAddr>()
                .is_ok_and(|destination| destination.ip() == ue.ip())
        })
        .filter_map(|sent| sent.message.status_code())
        .collect()
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
