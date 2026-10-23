//! An IMS UE re-registering and de-registering over the SA set it holds (3GPP
//! TS 24.229 5.1.1.4, 5.1.1.5.1, 5.1.1.6; TS 33.203 7.4): the protected
//! refresh, the new set a challenge makes beside the old one, which set goes
//! when, and the fall-backs. Driven through the dispatcher's response handler
//! against the mock kernel.

use super::*;
use crate::ipsec::IpsecManager;
use crate::registrant::test_support::{self, impu, ue};
use crate::registrant::{EgressDefaults, RegistrantManager, RegistrantState, UeExchange};
use crate::transport::OutboundMessage;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

pub(super) const UE_ADDR: &str = "192.0.2.77";

pub(super) fn ip(text: &str) -> IpAddr {
    text.parse().expect("an IP literal")
}

pub(super) fn response(status: &str, call_id: &str, extra: &str) -> SipMessage {
    let raw = format!(
        concat!(
            "SIP/2.0 {status}\r\n",
            "Via: SIP/2.0/UDP 192.0.2.77:6101;branch=z9hG4bK-reg-test\r\n",
            "From: <sip:ue@example.invalid>;tag=reg-1\r\n",
            "To: <sip:ue@example.invalid>;tag=pcscf\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: 1 REGISTER\r\n",
            "{extra}",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        status = status,
        call_id = call_id,
        extra = extra,
    );
    crate::sip::parser::parse_sip_message_bytes(raw.as_bytes()).expect("a response that parses")
}

pub(super) async fn wait_for<T>(mut probe: impl FnMut() -> Option<T>) -> T {
    for _ in 0..400 {
        if let Some(value) = probe() {
            return value;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    probe().expect("the condition came true in time")
}

pub(super) fn header(message: &OutboundMessage, name: &str) -> Option<String> {
    let parsed =
        crate::sip::parser::parse_sip_message_bytes(&message.data).expect("a message that parses");
    parsed.headers.get(name).cloned()
}

/// A registrant, the dispatcher under test (192.0.2.1:5060) and its
/// mock-kernel IPsec manager, and the network SQN of the next challenge.
pub(super) struct Harness {
    pub(super) registrant: Arc<RegistrantManager>,
    pub(super) dispatcher: super::test_dispatcher::TestDispatcher,
    pub(super) ipsec: Arc<IpsecManager>,
    pub(super) listen: HashMap<Transport, SocketAddr>,
    pub(super) sqn: u64,
    pub(super) spi: u32,
}

impl Harness {
    pub(super) fn new() -> Self {
        let registrant = Arc::new(test_support::manager());
        test_support::install_egress(&registrant);
        let mut dispatcher = super::test_dispatcher::test_dispatcher();
        let ipsec = Arc::new(IpsecManager::with_test_kernel());
        dispatcher.state.ipsec_manager = Some(Arc::clone(&ipsec));
        dispatcher.state.registrant_manager = Some(Arc::clone(&registrant));
        let listen = HashMap::from([(Transport::Udp, "192.0.2.1:5060".parse().expect("addr"))]);
        dispatcher
            .state
            .listen_addrs
            .insert(Transport::Udp, "192.0.2.1:5060".parse().expect("addr"));
        registrant.install_ipsec(Arc::clone(&ipsec));
        Self {
            registrant,
            dispatcher,
            ipsec,
            listen,
            sqn: 0,
            spi: 70_000,
        }
    }

    pub(super) fn add(&self, index: u32, address: &str) {
        self.registrant
            .try_add(ue(index, Some(ip(address))))
            .expect("added");
    }

    pub(super) fn defaults(&self) -> EgressDefaults<'_> {
        EgressDefaults::new("192.0.2.1:5060".parse().expect("addr"), &self.listen)
    }

    /// Build the REGISTER the loop would send now.
    pub(super) fn register(&self, aor: &str) -> crate::registrant::BuiltRegister {
        self.registrant
            .build_register(aor, self.defaults(), 600000)
            .expect("built")
    }

    pub(super) fn call_id(&self, built: &crate::registrant::BuiltRegister) -> String {
        built
            .message
            .headers
            .get("Call-ID")
            .cloned()
            .expect("a Call-ID")
    }

    pub(super) fn answer(&self, status: &str, call_id: &str, extra: &str) {
        let code: u16 = status[..3].parse().expect("a status code");
        handle_registrant_response(
            &self.registrant,
            &response(status, call_id, extra),
            code,
            "z9hG4bK-reg-test",
            &self.dispatcher.state,
        );
    }

    /// A 401 with a fresh AKA challenge and a Security-Server with fresh
    /// P-CSCF SPIs.
    pub(super) fn challenge(&mut self, call_id: &str) {
        self.sqn += 1;
        self.spi += 2;
        let extra = format!(
            "WWW-Authenticate: {}\r\nSecurity-Server: {}\r\n",
            test_support::aka_challenge_value(&format!("{:012x}", self.sqn)),
            test_support::security_server(self.spi, self.spi + 1)
        );
        self.answer("401 Unauthorized", call_id, &extra);
    }

    pub(super) async fn sent(&self) -> OutboundMessage {
        tokio::time::timeout(Duration::from_secs(2), self.dispatcher.udp.recv_async())
            .await
            .expect("sent in time")
            .expect("channel open")
    }

    /// The pairs installed on `address`, by client port.
    pub(super) fn ports(&self, address: &str) -> Vec<u16> {
        let mut ports: Vec<u16> = [6100, 6102, 6103]
            .into_iter()
            .filter(|port| self.ipsec.get_sa(&ip(address), *port).is_some())
            .collect();
        ports.sort_unstable();
        ports
    }

    /// Wait until exactly `expected` pairs are installed on `address`.
    pub(super) async fn settle(&self, address: &str, expected: &[u16]) {
        wait_for(|| (self.ports(address) == expected).then_some(())).await;
    }

    /// Initial registration: unprotected REGISTER, 401, the authenticated
    /// REGISTER over the new set, 200.
    pub(super) async fn register_initially(&mut self, index: u32, address: &str) {
        let aor = impu(index);
        let built = self.register(&aor);
        assert!(!built.protected);
        let call_id = self.call_id(&built);
        self.challenge(&call_id);
        self.sent().await;
        self.answer("200 OK", &call_id, "Expires: 600\r\n");
        assert_eq!(
            self.registrant.state(&aor),
            Some(RegistrantState::Registered)
        );
        self.settle(address, &[6100]).await;
    }

    /// A protected refresh the S-CSCF re-challenges, through to its 200.
    /// Returns the authenticated REGISTER.
    pub(super) async fn rechallenged_refresh(&mut self, aor: &str) -> OutboundMessage {
        let built = self.register(aor);
        assert!(built.protected, "a registered UE refreshes over its SA set");
        let call_id = self.call_id(&built);
        self.challenge(&call_id);
        let authenticated = self.sent().await;
        self.answer("200 OK", &call_id, "Expires: 600\r\n");
        authenticated
    }
}

#[tokio::test]
async fn a_refresh_goes_over_the_established_set_with_the_headers_the_spec_asks() {
    let mut harness = Harness::new();
    harness.add(1, UE_ADDR);
    harness.register_initially(1, UE_ADDR).await;
    let established = test_support::sa_sets(&harness.registrant, &impu(1))
        .established
        .expect("an established set");

    let built = harness.register(&impu(1));
    assert!(built.protected);
    assert_eq!(
        built.source_local_addr,
        Some(SocketAddr::new(ip(UE_ADDR), 6100)),
        "from the established set's protected client port"
    );
    assert_eq!(
        built.destination,
        "198.51.100.10:5066".parse().expect("addr"),
        "to the P-CSCF protected server port"
    );
    let headers = &built.message.headers;
    assert_eq!(
        headers
            .get("Via")
            .map(String::as_str)
            .unwrap_or("")
            .split(';')
            .next(),
        Some(format!("SIP/2.0/UDP {UE_ADDR}:6101").as_str()),
        "the Via names the protected server port (TS 24.229 5.1.1.4.2 c)"
    );
    assert_eq!(
        headers.get("Authorization"),
        Some(&established.authorization),
        "the last nonce and response, repeated (5.1.1.4.2 a)"
    );
    assert_eq!(
        headers.get("Security-Verify"),
        Some(&established.security_server),
        "the Security-Server of the last successful authentication (5.1.1.4.2 e)"
    );
    let client = headers.get("Security-Client").expect("a Security-Client");
    assert!(
        client.contains("port-c=6102") && client.contains("port-s=6101"),
        "new parameters on a new client port, the server port kept: {client}"
    );
    assert!(
        !client.contains(&format!("spi-c={}", established.key.spi_uc)),
        "fresh SPIs: {client}"
    );
    assert_eq!(headers.get("Call-ID"), Some(&harness.call_id(&built)));
}

#[tokio::test]
async fn a_200_to_a_protected_refresh_extends_the_set_and_installs_none() {
    let mut harness = Harness::new();
    harness.add(1, UE_ADDR);
    harness.register_initially(1, UE_ADDR).await;
    let installs_before = harness
        .ipsec
        .test_kernel_ops()
        .iter()
        .filter(|op| op.starts_with("add_sa"))
        .count();

    let built = harness.register(&impu(1));
    let call_id = harness.call_id(&built);
    harness.answer("200 OK", &call_id, "Expires: 3600\r\n");
    assert_eq!(
        harness.registrant.ipsec_exchange(&impu(1)),
        Some(UeExchange::Idle)
    );
    wait_for(|| {
        harness
            .ipsec
            .get_sa(&ip(UE_ADDR), 6100)
            .and_then(|sa| sa.hard_lifetime_secs)
            .filter(|lifetime| *lifetime == 3630)
    })
    .await;
    let installs_after = harness
        .ipsec
        .test_kernel_ops()
        .iter()
        .filter(|op| op.starts_with("add_sa"))
        .count();
    assert_eq!(installs_before, installs_after, "no new SA");
    assert_eq!(harness.ipsec.active_count(), 1);
}

#[tokio::test]
async fn a_lifetime_is_never_shortened_by_a_shorter_grant() {
    let mut harness = Harness::new();
    harness.add(1, UE_ADDR);
    harness.register_initially(1, UE_ADDR).await;
    let built = harness.register(&impu(1));
    harness.answer("200 OK", &harness.call_id(&built), "Expires: 3600\r\n");
    wait_for(|| {
        harness
            .ipsec
            .get_sa(&ip(UE_ADDR), 6100)
            .and_then(|sa| sa.hard_lifetime_secs)
            .filter(|lifetime| *lifetime == 3630)
    })
    .await;
    let built = harness.register(&impu(1));
    harness.answer("200 OK", &harness.call_id(&built), "Expires: 60\r\n");
    tokio::time::sleep(Duration::from_millis(50)).await;
    let lifetime = harness
        .ipsec
        .get_sa(&ip(UE_ADDR), 6100)
        .and_then(|sa| sa.hard_lifetime_secs)
        .expect("a lifetime");
    assert!(lifetime > 3500, "kept the longer lifetime: {lifetime}");
}

#[tokio::test]
async fn a_challenged_refresh_makes_the_new_set_before_it_breaks_the_old() {
    let mut harness = Harness::new();
    harness.add(1, UE_ADDR);
    harness.register_initially(1, UE_ADDR).await;
    let old = test_support::sa_sets(&harness.registrant, &impu(1))
        .established
        .expect("established")
        .key;

    let built = harness.register(&impu(1));
    let call_id = harness.call_id(&built);
    harness.challenge(&call_id);
    let authenticated = harness.sent().await;

    // The new set was installed before the authenticated REGISTER left, beside
    // the old one, which still stands.
    assert_eq!(harness.ports(UE_ADDR), vec![6100, 6102]);
    assert_eq!(
        authenticated.source_local_addr,
        Some(SocketAddr::new(ip(UE_ADDR), 6102)),
        "over the new set"
    );
    assert_eq!(
        authenticated.destination,
        "198.51.100.10:5066".parse().expect("addr")
    );
    assert_eq!(
        header(&authenticated, "Security-Client"),
        built.message.headers.get("Security-Client").cloned(),
        "the Security-Client of the challenged REGISTER (TS 24.229 5.1.1.5.1)"
    );
    assert_eq!(
        header(&authenticated, "Security-Verify"),
        Some(test_support::security_server(harness.spi, harness.spi + 1)),
        "mirrors the new Security-Server"
    );
    assert_eq!(
        header(&authenticated, "Call-ID"),
        Some(call_id.clone()),
        "the Call-ID of the 401"
    );
    let ops_at_send = harness.ipsec.test_kernel_ops().len();

    // The 200 takes the new set into use; the old one stays for the P-CSCF,
    // which keeps sending over it until it hears over the new one.
    harness.answer("200 OK", &call_id, "Expires: 600\r\n");
    let sets = test_support::sa_sets(&harness.registrant, &impu(1));
    assert_eq!(sets.retiring, Some(old));
    assert_eq!(
        sets.established.as_ref().map(|set| set.key.ue_port_c),
        Some(6102)
    );
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(harness.ports(UE_ADDR), vec![6100, 6102]);

    // The answer to the next REGISTER, over the new set, retires the old.
    let next = harness.register(&impu(1));
    assert_eq!(
        next.source_local_addr,
        Some(SocketAddr::new(ip(UE_ADDR), 6102)),
        "the next refresh rides the new set"
    );
    assert!(
        next.message
            .headers
            .get("Security-Client")
            .is_some_and(|client| client.contains("port-c=6103")),
        "offers the one client port neither set uses"
    );
    harness.answer("200 OK", &harness.call_id(&next), "Expires: 600\r\n");
    harness.settle(UE_ADDR, &[6102]).await;
    let ops = harness.ipsec.test_kernel_ops();
    let old_deleted = ops
        .iter()
        .rposition(|op| *op == format!("del_sa sa:{UE_ADDR}:{}", old.spi_uc))
        .expect("the old set deleted");
    assert!(
        old_deleted >= ops_at_send,
        "install < send < delete old: deleted at op {old_deleted}, sent at {ops_at_send}"
    );
    assert_eq!(harness.registrant.tracked_sa_sets(), 1);
}

#[tokio::test]
async fn a_failed_challenged_refresh_drops_the_new_set_and_keeps_the_old() {
    let mut harness = Harness::new();
    harness.add(1, UE_ADDR);
    harness.register_initially(1, UE_ADDR).await;

    let built = harness.register(&impu(1));
    let call_id = harness.call_id(&built);
    harness.challenge(&call_id);
    harness.sent().await;
    assert_eq!(harness.ports(UE_ADDR), vec![6100, 6102]);

    harness.answer("403 Forbidden", &call_id, "");
    harness.settle(UE_ADDR, &[6100]).await;
    assert_eq!(
        harness.registrant.state(&impu(1)),
        Some(RegistrantState::Failed)
    );
    let sets = test_support::sa_sets(&harness.registrant, &impu(1));
    assert!(sets.temporary.is_none());
    let established = sets.established.expect("the old set kept");
    assert!(
        !established.usable,
        "a failed re-registration falls back to an initial one (TS 24.229 5.1.1.4.1)"
    );

    // The next REGISTER goes unprotected, offering a port the kept set does
    // not use; its authentication, an initial one, deletes the kept set.
    test_support::make_due(&harness.registrant, &impu(1));
    let fallback = harness.register(&impu(1));
    assert!(!fallback.protected);
    assert_eq!(
        fallback.source_local_addr,
        Some(SocketAddr::new(ip(UE_ADDR), 5060))
    );
    assert!(fallback.message.headers.get("Security-Verify").is_none());
    assert!(fallback
        .message
        .headers
        .get("Security-Client")
        .is_some_and(|client| client.contains("port-c=6102")));
    let call_id = harness.call_id(&fallback);
    harness.challenge(&call_id);
    harness.sent().await;
    harness.answer("200 OK", &call_id, "Expires: 600\r\n");
    harness.settle(UE_ADDR, &[6102]).await;
    assert_eq!(harness.registrant.tracked_sa_sets(), 1);
}

#[tokio::test]
async fn an_unanswered_protected_refresh_falls_back_to_unprotected_after_timer_f() {
    let mut harness = Harness::new();
    harness.add(1, UE_ADDR);
    harness.register_initially(1, UE_ADDR).await;

    let built = harness.register(&impu(1));
    assert!(built.protected);
    test_support::backdate_last_sent(&harness.registrant, &impu(1), Duration::from_secs(33));
    let timed_out = harness.registrant.entries_timed_out();
    assert_eq!(timed_out, vec![impu(1)]);
    harness.registrant.handle_failure(&impu(1), 0, None);

    test_support::make_due(&harness.registrant, &impu(1));
    let fallback = harness.register(&impu(1));
    assert!(
        !fallback.protected,
        "the P-CSCF is taken to have lost the set"
    );
    assert_eq!(
        fallback.destination,
        "198.51.100.10:5060".parse().expect("addr")
    );
    assert!(fallback.message.headers.get("Security-Verify").is_none());
}

#[tokio::test]
async fn a_set_the_kernel_lost_sends_the_refresh_unprotected() {
    let mut harness = Harness::new();
    harness.add(1, UE_ADDR);
    harness.register_initially(1, UE_ADDR).await;
    harness
        .ipsec
        .delete_sa_pair(&ip(UE_ADDR), 6100)
        .await
        .expect("deleted");

    let built = harness.register(&impu(1));
    assert!(!built.protected);
    assert_eq!(
        built.source_local_addr,
        Some(SocketAddr::new(ip(UE_ADDR), 5060))
    );
    assert!(test_support::sa_sets(&harness.registrant, &impu(1))
        .established
        .is_none());
}

#[tokio::test]
async fn a_removed_ue_de_registers_over_its_set_and_then_deletes_it() {
    let mut harness = Harness::new();
    harness.add(1, UE_ADDR);
    harness.register_initially(1, UE_ADDR).await;

    harness.registrant.remove(&impu(1));
    let mut queued = test_support::take_deregistrations(&harness.registrant);
    assert_eq!(queued.len(), 1);
    let deregistration = queued.remove(0);
    assert!(deregistration.protected, "TS 24.229 5.1.1.6.1");
    assert_eq!(
        deregistration.source_local_addr,
        Some(SocketAddr::new(ip(UE_ADDR), 6100))
    );
    assert_eq!(
        deregistration.destination,
        "198.51.100.10:5066".parse().expect("addr")
    );
    let headers = &deregistration.message.headers;
    assert_eq!(headers.get("Expires").map(String::as_str), Some("0"));
    assert!(headers.get("Security-Verify").is_some());
    assert!(headers.get("Security-Client").is_some(), "5.1.1.6.2 d");
    assert!(headers.get("Authorization").is_some(), "5.1.1.6.2 a");

    // The set stays until the de-REGISTER is answered.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(harness.ports(UE_ADDR), vec![6100]);
    assert_eq!(harness.registrant.tracked_sa_sets(), 1);

    harness.answer(
        "200 OK",
        &harness.call_id(&deregistration),
        "Expires: 0\r\n",
    );
    harness.settle(UE_ADDR, &[]).await;
    assert_eq!(harness.ipsec.active_count(), 0);
    assert_eq!(harness.ipsec.test_kernel_live_count(), 0);
    assert_eq!(harness.registrant.tracked_sa_sets(), 0);
}

#[tokio::test]
async fn an_unanswered_de_register_still_deletes_the_set() {
    let mut harness = Harness::new();
    harness.add(1, UE_ADDR);
    harness.register_initially(1, UE_ADDR).await;
    harness.registrant.remove(&impu(1));
    assert_eq!(harness.registrant.tracked_sa_sets(), 1);

    harness
        .registrant
        .expire_teardowns(std::time::Instant::now() + Duration::from_secs(60));
    assert_eq!(harness.registrant.tracked_sa_sets(), 1, "now queued");
    harness
        .registrant
        .spawn_sa_deletions(&harness.ipsec, ip("192.0.2.1"));
    harness.settle(UE_ADDR, &[]).await;
    assert_eq!(harness.registrant.tracked_sa_sets(), 0);
}

#[tokio::test]
async fn a_removed_ue_mid_authentication_deletes_both_sets_at_once() {
    let mut harness = Harness::new();
    harness.add(1, UE_ADDR);
    harness.register_initially(1, UE_ADDR).await;
    let built = harness.register(&impu(1));
    harness.challenge(&harness.call_id(&built));
    harness.sent().await;
    assert_eq!(harness.ports(UE_ADDR), vec![6100, 6102]);

    // Not registered right now, so no de-REGISTER: the sets go at once.
    harness.registrant.remove(&impu(1));
    assert!(test_support::take_deregistrations(&harness.registrant).is_empty());
    harness
        .registrant
        .spawn_sa_deletions(&harness.ipsec, ip("192.0.2.1"));
    harness.settle(UE_ADDR, &[]).await;
    assert_eq!(harness.ipsec.test_kernel_live_count(), 0);
}

#[tokio::test]
async fn two_ues_on_the_same_ports_each_keep_one_set_through_refreshes() {
    let mut harness = Harness::new();
    harness.add(1, "192.0.2.77");
    harness.add(2, "192.0.2.78");
    harness.register_initially(1, "192.0.2.77").await;
    harness.register_initially(2, "192.0.2.78").await;
    for _ in 0..3 {
        for index in [1, 2] {
            let built = harness.register(&impu(index));
            assert!(built.protected);
            harness.answer("200 OK", &harness.call_id(&built), "Expires: 600\r\n");
        }
    }
    // And through a re-challenge of each, plus the refresh that retires it.
    for (index, address) in [(1, "192.0.2.77"), (2, "192.0.2.78")] {
        harness.rechallenged_refresh(&impu(index)).await;
        let built = harness.register(&impu(index));
        harness.answer("200 OK", &harness.call_id(&built), "Expires: 600\r\n");
        harness.settle(address, &[6102]).await;
    }
    assert_eq!(harness.ipsec.active_count(), 2);
    assert_eq!(harness.registrant.tracked_sa_sets(), 2);
}

/// The per-module leak gate: through 500 re-challenged refreshes the UE holds
/// at most two sets, and after a plain refresh exactly one, in the manager, in
/// the IPsec manager and in the kernel; removing it drains all three to zero.
#[tokio::test]
async fn sa_sets_drain_to_one_per_entry_across_500_challenge_cycles() {
    let mut harness = Harness::new();
    harness.add(1, UE_ADDR);
    harness.register_initially(1, UE_ADDR).await;
    for cycle in 0..500 {
        harness.rechallenged_refresh(&impu(1)).await;
        assert!(
            harness.registrant.tracked_sa_sets() <= 2,
            "cycle {cycle}: {} sets tracked",
            harness.registrant.tracked_sa_sets()
        );
    }
    // Spawned deletions land before the plain refresh's answer is checked.
    wait_for(|| (harness.ipsec.active_count() <= 2).then_some(())).await;
    let built = harness.register(&impu(1));
    harness.answer("200 OK", &harness.call_id(&built), "Expires: 600\r\n");
    wait_for(|| (harness.ipsec.active_count() == 1).then_some(())).await;
    assert_eq!(harness.registrant.tracked_sa_sets(), 1);
    assert_eq!(
        harness.ipsec.test_kernel_live_count(),
        8,
        "four states and four policies"
    );

    harness.registrant.remove(&impu(1));
    let deregistration = test_support::take_deregistrations(&harness.registrant)
        .pop()
        .expect("a de-REGISTER");
    harness.answer("200 OK", &harness.call_id(&deregistration), "");
    wait_for(|| (harness.ipsec.active_count() == 0).then_some(())).await;
    assert_eq!(harness.registrant.tracked_sa_sets(), 0);
    assert_eq!(harness.ipsec.test_kernel_live_count(), 0);
}

/// A provisional answer to a protected refresh is not its outcome (RFC 3261
/// 17.1.2.2: Trying -> Proceeding, the transaction waits for the final
/// response). A P-CSCF whose server transaction emits a 100 Trying once Timer
/// E reaches T2 (RFC 4320 4.2, 3.5 s over UDP) used to fail the refresh with
/// status 100, which dropped the established set and sent the next REGISTER
/// unprotected, drawing a fresh challenge.
#[tokio::test]
async fn a_100_trying_to_a_protected_refresh_does_not_fail_it() {
    let mut harness = Harness::new();
    harness.add(1, UE_ADDR);
    harness.register_initially(1, UE_ADDR).await;

    let built = harness.register(&impu(1));
    assert!(built.protected);
    let call_id = harness.call_id(&built);
    harness.answer("100 Trying", &call_id, "");
    assert_eq!(
        harness.registrant.state(&impu(1)),
        Some(RegistrantState::Registering),
        "a provisional leaves the refresh in flight"
    );
    assert!(
        test_support::sa_sets(&harness.registrant, &impu(1))
            .established
            .is_some(),
        "the established set survives the provisional"
    );

    harness.answer("200 OK", &call_id, "Expires: 600\r\n");
    assert_eq!(
        harness.registrant.state(&impu(1)),
        Some(RegistrantState::Registered)
    );
    let next = harness.register(&impu(1));
    assert!(next.protected, "the next refresh still rides the SA set");
}
