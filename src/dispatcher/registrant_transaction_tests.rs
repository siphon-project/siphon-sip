//! The registrant's REGISTERs under the dispatcher's client transactions (RFC
//! 3261 §17.1.2): retransmitted over UDP on Timer E from T1 doubling to T2,
//! byte for byte and from the socket the first one left (a UE's own address,
//! its SA), never over TCP, ended by Timer F or by a response; and nothing
//! registers once its entry is removed or shutdown has begun.

use super::protected_tests::{Harness, UE_ADDR};
use super::*;
use crate::registrant::test_support::{self, impu, trunk, ue};
use crate::registrant::{BuiltRegister, EgressDefaults, RegistrantManager, RegistrantState};
use crate::transport::OutboundMessage;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

const TRUNK: &str = "sip:trunk@carrier.example";

const T1: Duration = Duration::from_millis(500);
const T2: Duration = Duration::from_secs(4);

fn ip(text: &str) -> IpAddr {
    text.parse().expect("an IP literal")
}

/// A registrant sending under the transaction layer of the dispatcher under
/// test (192.0.2.1:5060), as `dispatcher::run` attaches it.
struct Setup {
    registrant: Arc<RegistrantManager>,
    dispatcher: super::test_dispatcher::TestDispatcher,
    listen: HashMap<Transport, SocketAddr>,
}

impl Setup {
    fn new() -> Self {
        let registrant = Arc::new(test_support::manager());
        test_support::install_egress(&registrant);
        let mut dispatcher = super::test_dispatcher::test_dispatcher();
        dispatcher.state.registrant_manager = Some(Arc::clone(&registrant));
        let listen = HashMap::from([(Transport::Udp, "192.0.2.1:5060".parse().expect("addr"))]);
        dispatcher.state.listen_addrs = listen.clone();
        registrant.attach_transactions(Arc::new(RegisterTransactionLayer::of(&dispatcher.state)));
        Self {
            registrant,
            dispatcher,
            listen,
        }
    }

    fn defaults(&self) -> EgressDefaults<'_> {
        EgressDefaults::new("192.0.2.1:5060".parse().expect("addr"), &self.listen)
    }

    /// Build and send a REGISTER of `aor`, returning it and what went out.
    fn send(&self, aor: &str, expires: u32) -> (BuiltRegister, OutboundMessage) {
        let built = self
            .registrant
            .build_register(aor, self.defaults(), expires)
            .expect("built");
        send_registrant_request(&self.registrant, aor, &built, &self.dispatcher.state);
        let sent = self.dispatcher.udp.try_recv().expect("the REGISTER");
        (built, sent)
    }

    /// When timer `name` of the transaction `request` opened fires.
    fn timer(&self, request: &SipMessage, name: TimerName) -> Option<Instant> {
        let key = TransactionManager::key_from_message(request).expect("a key");
        self.dispatcher
            .state
            .timer_wheel
            .iter()
            .find(|entry| entry.key == key && entry.name == name)
            .map(|entry| entry.fires_at)
    }

    fn fire(&self, at: Instant) {
        fire_expired_timers_at(&self.dispatcher.state, at);
    }

    fn answer(&self, request: &SipMessage, status: &str, extra: &str) {
        let header = |name: &str| request.headers.get(name).cloned().expect(name);
        let raw = format!(
            concat!(
                "SIP/2.0 {status}\r\n",
                "Via: {via}\r\n",
                "From: {from}\r\n",
                "To: {to};tag=registrar\r\n",
                "Call-ID: {call_id}\r\n",
                "CSeq: {cseq}\r\n",
                "{extra}",
                "Content-Length: 0\r\n",
                "\r\n",
            ),
            status = status,
            via = header("Via"),
            from = header("From"),
            to = header("To"),
            call_id = header("Call-ID"),
            cseq = header("CSeq"),
            extra = extra,
        );
        let response = crate::sip::parser::parse_sip_message_bytes(raw.as_bytes())
            .expect("a response that parses");
        let code: u16 = status[..3].parse().expect("a status code");
        handle_registrant_response(
            &self.registrant,
            &response,
            code,
            "z9hG4bK-reg-test",
            &self.dispatcher.state,
        );
    }

    fn transactions(&self) -> usize {
        self.dispatcher.state.transaction_manager.count()
    }
}

fn assert_retransmission_of(first: &OutboundMessage, again: &OutboundMessage) {
    assert_eq!(
        again.data, first.data,
        "a retransmission is the same octets"
    );
    assert_eq!(again.destination, first.destination);
    assert_eq!(again.transport, first.transport);
    assert_eq!(again.source_local_addr, first.source_local_addr);
}

/// RFC 3261 §17.1.2.2: Timer E at T1, doubling, capped at T2; the same octets
/// from the UE's own address each time; Timer F at 64·T1 fails the entry.
#[tokio::test]
async fn an_unanswered_udp_register_is_retransmitted_on_timer_e_until_timer_f() {
    let setup = Setup::new();
    setup
        .registrant
        .try_add(ue(1, Some(ip(UE_ADDR))))
        .expect("added");
    let sent_at = Instant::now();
    let (built, first) = setup.send(&impu(1), 600000);
    assert_eq!(
        first.source_local_addr,
        Some(SocketAddr::new(ip(UE_ADDR), 5060))
    );

    let timer_f = setup.timer(&built.message, TimerName::F).expect("Timer F");
    let to_f = timer_f.duration_since(sent_at);
    assert!(
        to_f >= 64 * T1 && to_f < 64 * T1 + Duration::from_millis(200),
        "{to_f:?}"
    );

    let mut expected = T1;
    for _ in 0..7 {
        let timer_e = setup
            .timer(&built.message, TimerName::E)
            .expect("Timer E armed");
        let interval = timer_e.saturating_duration_since(Instant::now());
        assert!(
            interval <= expected && interval + Duration::from_millis(200) >= expected,
            "Timer E in {interval:?}, expected {expected:?}"
        );
        setup.fire(timer_e);
        let again = setup.dispatcher.udp.try_recv().expect("retransmitted");
        assert_retransmission_of(&first, &again);
        assert!(setup.dispatcher.udp.try_recv().is_err(), "one per Timer E");
        expected = (expected * 2).min(T2);
    }
    assert_eq!(
        setup.registrant.state(&impu(1)),
        Some(RegistrantState::Registering),
        "a retransmission is not a new attempt"
    );

    setup.fire(timer_f);
    assert_eq!(
        setup.registrant.state(&impu(1)),
        Some(RegistrantState::Failed)
    );
    assert_eq!(setup.transactions(), 0);
    assert!(setup.dispatcher.state.timer_wheel.is_empty());
    let _ = setup.dispatcher.udp.try_iter().count();
    setup.fire(Instant::now() + 64 * T1);
    assert!(
        setup.dispatcher.udp.try_recv().is_err(),
        "nothing after Timer F"
    );
}

/// A response ends the retransmissions; a repeat of the final response is
/// absorbed by the transaction instead of being answered twice.
#[tokio::test]
async fn an_answer_stops_the_retransmissions_and_its_repeat_is_absorbed() {
    let setup = Setup::new();
    setup.registrant.add(trunk(TRUNK));
    let (built, first) = setup.send(TRUNK, 3600);
    let timer_e = setup.timer(&built.message, TimerName::E).expect("Timer E");
    setup.fire(timer_e);
    assert_retransmission_of(&first, &setup.dispatcher.udp.try_recv().expect("one"));

    let challenge =
        "WWW-Authenticate: Digest realm=\"carrier.example\", nonce=\"abc\", qop=\"auth\"\r\n";
    setup.answer(&built.message, "401 Unauthorized", challenge);
    let authenticated = setup.dispatcher.udp.try_recv().expect("the answer");
    assert!(String::from_utf8_lossy(&authenticated.data).contains("Authorization: Digest"));
    assert!(setup.timer(&built.message, TimerName::E).is_none());
    assert!(setup.timer(&built.message, TimerName::F).is_none());

    // The 401 again, as a registrar repeats it for each retransmission it saw.
    setup.answer(&built.message, "401 Unauthorized", challenge);
    assert!(
        setup.dispatcher.udp.try_recv().is_err(),
        "a repeated 401 started a second authentication"
    );

    // Nothing of the first REGISTER is retransmitted any more.
    setup.fire(Instant::now() + 64 * T1);
    let left: Vec<OutboundMessage> = setup.dispatcher.udp.try_iter().collect();
    assert!(
        left.iter().all(|message| message.data != first.data),
        "the answered REGISTER went out again"
    );
}

/// RFC 3261 §17.1.2.2: over a reliable transport Timer E is not set; Timer F
/// still bounds the transaction.
#[tokio::test]
async fn a_tcp_register_is_never_retransmitted() {
    let setup = Setup::new();
    let mut entry = trunk(TRUNK);
    entry.transport = Transport::Tcp;
    setup.registrant.add(entry);
    let built = setup
        .registrant
        .build_register(TRUNK, setup.defaults(), 3600)
        .expect("built");
    send_registrant_request(&setup.registrant, TRUNK, &built, &setup.dispatcher.state);

    assert!(setup.timer(&built.message, TimerName::E).is_none());
    let timer_f = setup.timer(&built.message, TimerName::F).expect("Timer F");
    setup.fire(timer_f - Duration::from_millis(1));
    assert!(setup.dispatcher.udp.try_recv().is_err());
    assert_eq!(setup.transactions(), 1);

    setup.fire(timer_f);
    assert_eq!(setup.registrant.state(TRUNK), Some(RegistrantState::Failed));
    assert_eq!(setup.transactions(), 0);
}

/// A protected REGISTER is retransmitted where it first went: from the UE's
/// protected client port to the P-CSCF's protected server port, so through the
/// SA set it rides (TS 33.203 §7.1).
#[tokio::test]
async fn a_protected_register_is_retransmitted_through_its_sa() {
    let mut harness = Harness::new();
    harness
        .registrant
        .attach_transactions(Arc::new(RegisterTransactionLayer::of(
            &harness.dispatcher.state,
        )));
    harness.add(1, UE_ADDR);
    let built = harness.register(&impu(1));
    let call_id = harness.call_id(&built);
    harness.challenge(&call_id);
    let protected = harness.sent().await;
    assert_eq!(
        protected.source_local_addr,
        Some(SocketAddr::new(ip(UE_ADDR), 6100))
    );
    let request = crate::sip::parser::parse_sip_message_bytes(&protected.data).expect("a REGISTER");
    let key = TransactionManager::key_from_message(&request).expect("a key");
    let timer_e = harness
        .dispatcher
        .state
        .timer_wheel
        .iter()
        .find(|entry| entry.key == key && entry.name == TimerName::E)
        .map(|entry| entry.fires_at)
        .expect("Timer E");

    fire_expired_timers_at(&harness.dispatcher.state, timer_e);

    let again = harness.sent().await;
    assert_retransmission_of(&protected, &again);
    assert_eq!(
        again.destination,
        "198.51.100.10:5066".parse::<SocketAddr>().expect("addr")
    );
}

/// The challenge of a REGISTER is answered from a spawned task once the UE's SA
/// set is installed. An entry removed meanwhile is not registered by it.
#[tokio::test]
async fn a_removed_entry_is_not_registered_by_a_challenge_answered_after_it() {
    let mut harness = Harness::new();
    harness.add(1, UE_ADDR);
    let built = harness.register(&impu(1));
    let call_id = harness.call_id(&built);
    harness.challenge(&call_id);

    harness.registrant.remove(&impu(1));

    tokio::time::sleep(Duration::from_millis(100)).await;
    let registers: Vec<OutboundMessage> = harness.dispatcher.udp.try_iter().collect();
    assert!(
        registers.is_empty(),
        "a removed entry sent {} REGISTER(s)",
        registers.len()
    );
    assert!(harness.ports(UE_ADDR).is_empty(), "an SA set was installed");
}

/// The same with shutdown beginning while the challenge is being answered.
#[tokio::test]
async fn shutdown_stops_a_challenge_answered_during_it() {
    let mut harness = Harness::new();
    harness.add(1, UE_ADDR);
    let built = harness.register(&impu(1));
    let call_id = harness.call_id(&built);
    harness.challenge(&call_id);

    crate::registrant::deregister_all(&harness.registrant, &harness.dispatcher.state.outbound);

    tokio::time::sleep(Duration::from_millis(100)).await;
    let registers: Vec<OutboundMessage> = harness.dispatcher.udp.try_iter().collect();
    assert!(
        registers.is_empty(),
        "sent {} REGISTER(s) after shutdown began",
        registers.len()
    );
}

/// Project leak gate: after register and de-register cycles, answered and
/// unanswered, the transaction store and the timer wheel are back where they
/// started, and so is the registrant.
#[tokio::test]
async fn register_cycles_leave_no_transaction_or_timer_behind() {
    let setup = Setup::new();
    let baseline_transactions = setup.transactions();
    let baseline_timers = setup.dispatcher.state.timer_wheel.len();

    for cycle in 0..50 {
        setup.registrant.add(trunk(TRUNK));
        let (register, _) = setup.send(TRUNK, 3600);
        setup.answer(&register.message, "200 OK", "Expires: 3600\r\n");
        let (deregister, _) = setup.send(TRUNK, 0);
        setup.answer(&deregister.message, "200 OK", "Expires: 0\r\n");
        // Every fifth REGISTER goes unanswered and times out.
        if cycle % 5 == 0 {
            test_support::make_due(&setup.registrant, TRUNK);
            let (unanswered, _) = setup.send(TRUNK, 3600);
            let timer_f = setup.timer(&unanswered.message, TimerName::F).expect("F");
            setup.fire(timer_f);
        }
        setup.registrant.remove(TRUNK);
        // The loop's to send; this test sends none.
        test_support::take_deregistrations(&setup.registrant);
        let _ = setup.dispatcher.udp.try_iter().count();
    }
    // Timer K (T4 over UDP) ends the answered ones.
    setup.fire(Instant::now() + 64 * T1);

    assert_eq!(setup.transactions(), baseline_transactions);
    assert_eq!(setup.dispatcher.state.timer_wheel.len(), baseline_timers);
    assert!(setup.registrant.is_empty());
}

// --- shutdown, end to end ------------------------------------------------------

/// What a mock registrar saw and holds.
#[derive(Default)]
struct RegistrarLog {
    /// Every request on the wire after the signal: (method, To AoR, Expires,
    /// whether it carried credentials).
    requests: Vec<(String, String, u32, bool)>,
    /// The AoRs it holds a binding for.
    bound: std::collections::HashSet<String>,
}

fn to_aor(request: &SipMessage) -> String {
    request
        .headers
        .get("To")
        .map(|to| to.trim_matches(|c| c == '<' || c == '>').to_string())
        .expect("a To")
}

/// A registrar that challenges the first de-REGISTER of `challenged`, accepts
/// everything else, answers `held` (a REGISTER in flight when the signal came)
/// once the first de-REGISTER arrives, and records what it saw. What a script
/// does meanwhile is tried at that point too: putting an entry back and
/// forcing a refresh.
async fn mock_registrar(
    setup: &Setup,
    log: &std::sync::Mutex<RegistrarLog>,
    challenged: &str,
    held: &SipMessage,
) {
    let mut held = Some(held);
    while let Ok(sent) = setup.dispatcher.udp.recv_async().await {
        let request = crate::sip::parser::parse_sip_message_bytes(&sent.data).expect("a request");
        let method = request
            .method()
            .map(|method| method.as_str().to_string())
            .unwrap_or_default();
        let aor = to_aor(&request);
        let expires: u32 = request
            .headers
            .get("Expires")
            .and_then(|value| value.trim().parse().ok())
            .unwrap_or(0);
        let credentials = request.headers.get("Authorization").is_some();
        log.lock().expect("the log").requests.push((
            method.clone(),
            aor.clone(),
            expires,
            credentials,
        ));
        if method != "REGISTER" {
            continue;
        }
        if expires == 0 {
            if let Some(in_flight) = held.take() {
                log.lock().expect("the log").bound.insert(to_aor(in_flight));
                setup.answer(in_flight, "200 OK", "Expires: 3600\r\n");
                assert!(setup
                    .registrant
                    .try_add(trunk("sip:readded@carrier.example"))
                    .is_err());
                assert!(!setup.registrant.refresh(challenged));
                assert!(setup.registrant.entries_due().is_empty());
            }
            if aor == challenged && !credentials {
                setup.answer(
                    &request,
                    "401 Unauthorized",
                    "WWW-Authenticate: Digest realm=\"carrier.example\", nonce=\"dereg\", qop=\"auth\"\r\n",
                );
                continue;
            }
            log.lock().expect("the log").bound.remove(&aor);
            setup.answer(&request, "200 OK", "Expires: 0\r\n");
        } else {
            log.lock().expect("the log").bound.insert(aor);
            setup.answer(&request, "200 OK", &format!("Expires: {expires}\r\n"));
        }
    }
}

/// TS 24.229 5.1.1.6 / RFC 3261 §10.2.2 through the server's own shutdown
/// sequence: every registered entry sends one de-REGISTER, a challenged one
/// answers its challenge with `Expires: 0`, a REGISTER in flight at the
/// signal is followed by its de-REGISTER once answered, and from the signal
/// on nothing registers, nothing announces a registration (the event a script
/// subscribes to reg on) and nothing is subscribed. The registrar ends up
/// holding no binding.
#[tokio::test]
async fn shutdown_de_registers_every_binding_and_registers_nothing() {
    const ENTRIES: usize = 5;
    const IN_FLIGHT: &str = "sip:in-flight@carrier.example";
    let setup = Setup::new();
    let aors: Vec<String> = (0..ENTRIES)
        .map(|index| format!("sip:trunk{index}@carrier.example"))
        .collect();
    for aor in &aors {
        setup.registrant.add(trunk(aor));
        let (register, _) = setup.send(aor, 3600);
        setup.answer(&register.message, "200 OK", "Expires: 3600\r\n");
    }
    setup.registrant.add(trunk(IN_FLIGHT));
    let (in_flight, _) = setup.send(IN_FLIGHT, 3600);
    let mut events = setup.registrant.subscribe_events();
    let log = std::sync::Mutex::new(RegistrarLog {
        bound: aors.iter().cloned().collect(),
        ..RegistrarLog::default()
    });

    let config = crate::config::Config::from_str(concat!(
        "listen:\n  udp: [\"192.0.2.1:5060\"]\n",
        "domain:\n  local: [\"example.com\"]\n",
        "server:\n  drain_secs: 1\n",
    ))
    .expect("a config");
    let drain = Arc::new(crate::dispatcher::DrainState::new());
    let started = Instant::now();
    tokio::select! {
        () = crate::server::shutdown_sequence::shut_down(
            &config,
            &drain,
            Some(&setup.registrant),
            &setup.dispatcher.state.outbound,
        ) => {}
        () = mock_registrar(&setup, &log, &aors[0], &in_flight.message) => {
            panic!("the registrar's channel closed");
        }
    }
    assert!(
        started.elapsed() < crate::registrant::SHUTDOWN_ANSWER_WAIT,
        "it waited out its bound: {:?}",
        started.elapsed()
    );

    let log = log.into_inner().expect("the log");
    for aor in aors.iter().chain([IN_FLIGHT.to_string()].iter()) {
        let unauthenticated = log
            .requests
            .iter()
            .filter(|(method, to, expires, credentials)| {
                method == "REGISTER" && to == aor && *expires == 0 && !credentials
            })
            .count();
        assert_eq!(unauthenticated, 1, "{aor}: {:?}", log.requests);
    }
    assert!(
        log.requests
            .iter()
            .any(|(_, to, expires, credentials)| *to == aors[0] && *expires == 0 && *credentials),
        "the challenged de-REGISTER was not answered: {:?}",
        log.requests
    );
    assert!(
        log.requests
            .iter()
            .all(|(method, _, expires, _)| method == "REGISTER" && *expires == 0),
        "something other than a de-REGISTER went out: {:?}",
        log.requests
    );
    assert!(log.bound.is_empty(), "still bound: {:?}", log.bound);
    assert!(!setup.registrant.deregistrations_pending());
    while let Ok(event) = events.try_recv() {
        assert!(
            matches!(
                event,
                crate::registrant::RegistrantEvent::Deregistered { .. }
            ),
            "announced during shutdown: {event:?}"
        );
    }
}

// --- the de-REGISTER of a removed entry, challenged ----------------------------

const DIGEST_CHALLENGE: &str =
    "Digest realm=\"carrier.example\", nonce=\"n1\", algorithm=MD5, qop=\"auth\"";

fn parse_sent(sent: &OutboundMessage) -> SipMessage {
    crate::sip::parser::parse_sip_message_bytes(&sent.data).expect("a request that parses")
}

fn header(message: &SipMessage, name: &str) -> String {
    message.headers.get(name).cloned().unwrap_or_default()
}

impl Setup {
    /// A registered trunk, removed: the de-REGISTER the loop would send, sent.
    fn removed_trunk_deregistration(&self) -> SipMessage {
        self.registrant.add(trunk(TRUNK));
        let (register, _) = self.send(TRUNK, 3600);
        self.answer(&register.message, "200 OK", "Expires: 3600\r\n");
        self.registrant.remove(TRUNK);
        self.send_queued_deregistration()
    }

    fn send_queued_deregistration(&self) -> SipMessage {
        let built = test_support::take_deregistrations(&self.registrant)
            .pop()
            .expect("a queued de-REGISTER");
        send_registrant_request(&self.registrant, TRUNK, &built, &self.dispatcher.state);
        parse_sent(&self.dispatcher.udp.try_recv().expect("the de-REGISTER"))
    }

    fn challenge(&self, request: &SipMessage, status: &str, header_name: &str) {
        self.answer(
            request,
            status,
            &format!("{header_name}: {DIGEST_CHALLENGE}\r\n"),
        );
    }
}

fn cseq(message: &SipMessage) -> u32 {
    crate::registrant::cseq_number(message).expect("a CSeq")
}

#[tokio::test]
async fn a_challenged_de_register_is_answered_once_and_ended_by_the_200() {
    let setup = Setup::new();
    let deregister = setup.removed_trunk_deregistration();
    assert_eq!(header(&deregister, "Expires"), "0");
    assert!(header(&deregister, "Authorization").is_empty());

    setup.challenge(&deregister, "401 Unauthorized", "WWW-Authenticate");

    let answer = parse_sent(&setup.dispatcher.udp.try_recv().expect("the answer"));
    assert_eq!(header(&answer, "Expires"), "0");
    assert!(header(&answer, "Authorization").contains("username=\"trunk\""));
    assert_eq!(header(&answer, "Call-ID"), header(&deregister, "Call-ID"));
    assert_eq!(cseq(&answer), cseq(&deregister) + 1);
    assert!(setup.registrant.is_empty(), "a removed trunk reads as live");
    assert_eq!(setup.registrant.removed_deregistrations_pending(), 1);

    setup.answer(&answer, "200 OK", "Expires: 0\r\n");

    assert_eq!(setup.registrant.removed_deregistrations_pending(), 0);
    assert!(
        setup.dispatcher.udp.try_recv().is_err(),
        "nothing else sent"
    );
}

#[tokio::test]
async fn a_proxy_challenge_to_a_de_register_is_answered_with_proxy_authorization() {
    let setup = Setup::new();
    let deregister = setup.removed_trunk_deregistration();

    setup.challenge(
        &deregister,
        "407 Proxy Authentication Required",
        "Proxy-Authenticate",
    );

    let answer = parse_sent(&setup.dispatcher.udp.try_recv().expect("the answer"));
    assert_eq!(header(&answer, "Expires"), "0");
    assert!(header(&answer, "Proxy-Authorization").contains("username=\"trunk\""));
}

#[tokio::test]
async fn a_second_challenge_gives_up() {
    let setup = Setup::new();
    let deregister = setup.removed_trunk_deregistration();
    setup.challenge(&deregister, "401 Unauthorized", "WWW-Authenticate");
    let answer = parse_sent(&setup.dispatcher.udp.try_recv().expect("the answer"));

    setup.challenge(&answer, "401 Unauthorized", "WWW-Authenticate");

    assert!(setup.dispatcher.udp.try_recv().is_err(), "answered twice");
    assert_eq!(setup.registrant.removed_deregistrations_pending(), 0);
}

#[tokio::test]
async fn a_refused_de_register_is_given_up_on() {
    let setup = Setup::new();
    let deregister = setup.removed_trunk_deregistration();

    setup.answer(&deregister, "503 Service Unavailable", "");

    assert!(setup.dispatcher.udp.try_recv().is_err());
    assert_eq!(setup.registrant.removed_deregistrations_pending(), 0);
}

#[tokio::test]
async fn an_unanswered_de_register_times_out_and_is_forgotten() {
    let setup = Setup::new();
    let deregister = setup.removed_trunk_deregistration();
    let timer_f = setup.timer(&deregister, TimerName::F).expect("Timer F");

    setup.fire(timer_f);
    // The failure is posted off the sweep.
    wait_until_pending_is(&setup.registrant, 0).await;
}

async fn wait_until_pending_is(registrant: &RegistrantManager, expected: usize) {
    for _ in 0..100 {
        if registrant.removed_deregistrations_pending() == expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!(
        "{} removed de-REGISTER(s) still tracked, expected {expected}",
        registrant.removed_deregistrations_pending()
    );
}

#[tokio::test]
async fn a_late_answer_to_the_first_register_does_not_end_the_de_register() {
    let setup = Setup::new();
    setup.registrant.add(trunk(TRUNK));
    let (first, _) = setup.send(TRUNK, 3600);
    setup.registrant.remove(TRUNK);
    let deregister = setup.send_queued_deregistration();
    assert!(cseq(&deregister) > cseq(&first.message));

    // The first REGISTER's own 200 arrives late: no entry, no new binding, and
    // the de-REGISTER, still in flight, is not taken as answered.
    setup.answer(&first.message, "200 OK", "Expires: 3600\r\n");
    assert!(setup.registrant.is_empty());
    assert_eq!(setup.registrant.removed_deregistrations_pending(), 1);

    setup.answer(&deregister, "200 OK", "Expires: 0\r\n");
    assert_eq!(setup.registrant.removed_deregistrations_pending(), 0);
}

/// Project leak gate: whichever way a removed trunk's de-REGISTER ends, the
/// store, the transactions and the timers are back where they started.
#[tokio::test]
async fn removed_de_registers_leave_nothing_behind_whichever_way_they_end() {
    let setup = Setup::new();
    let baseline_transactions = setup.transactions();
    let baseline_timers = setup.dispatcher.state.timer_wheel.len();

    for cycle in 0..60 {
        let deregister = setup.removed_trunk_deregistration();
        match cycle % 6 {
            0 => setup.answer(&deregister, "200 OK", "Expires: 0\r\n"),
            1 | 2 => {
                setup.challenge(&deregister, "401 Unauthorized", "WWW-Authenticate");
                let answer = parse_sent(&setup.dispatcher.udp.try_recv().expect("answer"));
                if cycle % 6 == 1 {
                    setup.answer(&answer, "200 OK", "Expires: 0\r\n");
                } else {
                    setup.challenge(&answer, "401 Unauthorized", "WWW-Authenticate");
                }
            }
            3 => setup.answer(&deregister, "500 Server Error", ""),
            4 => {
                let timer_f = setup.timer(&deregister, TimerName::F).expect("Timer F");
                setup.fire(timer_f);
            }
            _ => {
                // Never answered, never timed out: the sweep bound ends it.
                setup
                    .registrant
                    .expire_removed_deregistrations(Instant::now() + Duration::from_secs(120));
            }
        }
        let _ = setup.dispatcher.udp.try_iter().count();
    }
    setup.fire(Instant::now() + 64 * T1);
    wait_until_pending_is(&setup.registrant, 0).await;

    assert_eq!(setup.transactions(), baseline_transactions);
    assert_eq!(setup.dispatcher.state.timer_wheel.len(), baseline_timers);
    assert!(setup.registrant.is_empty());
}
use crate::registrant::persist::{BindingRecord, BindingStore};
use crate::registrant::source::{CredentialLookup, RegistrantRow};
use std::sync::atomic::{AtomicUsize, Ordering};

const ORPHAN_CALL_ID: &str = "reg-before-the-kill";

/// A source that knows (or does not know, or cannot answer for) one trunk.
struct StubLookup {
    answer: Result<Option<RegistrantRow>, String>,
    asked: AtomicUsize,
    /// How long the source takes to answer.
    delay: Duration,
}

impl StubLookup {
    fn knowing(username: &str, password: &str) -> Arc<Self> {
        let row: RegistrantRow = serde_json::from_value(serde_json::json!({
            "aor": TRUNK,
            "registrar": "sip:198.51.100.10:5060",
            "username": username,
            "password": password,
            "enabled": false,
        }))
        .expect("a row");
        Self::answering(Ok(Some(row)))
    }

    fn answering(answer: Result<Option<RegistrantRow>, String>) -> Arc<Self> {
        Arc::new(Self {
            answer,
            asked: AtomicUsize::new(0),
            delay: Duration::ZERO,
        })
    }

    fn slow(username: &str, password: &str, delay: Duration) -> Arc<Self> {
        let knowing = Self::knowing(username, password);
        Arc::new(Self {
            answer: knowing.answer.clone(),
            asked: AtomicUsize::new(0),
            delay,
        })
    }
}

impl CredentialLookup for StubLookup {
    fn is_configured(&self) -> bool {
        true
    }

    fn lookup<'a>(
        &'a self,
        aor: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Option<RegistrantRow>, String>> + Send + 'a>,
    > {
        assert_eq!(aor, TRUNK, "asked for another AoR");
        self.asked.fetch_add(1, Ordering::SeqCst);
        let answer = self.answer.clone();
        let delay = self.delay;
        Box::pin(async move {
            tokio::time::sleep(delay).await;
            answer
        })
    }
}

fn orphan_record() -> BindingRecord {
    BindingRecord {
        instance: "node-a".to_string(),
        aor: TRUNK.to_string(),
        registrar_uri: format!("sip:{}", test_support::PCSCF),
        destination: test_support::PCSCF.parse().expect("addr"),
        address_str: None,
        transport: Transport::Udp,
        contact: "sip:trunk@192.0.2.1:5060".to_string(),
        call_id: ORPHAN_CALL_ID.to_string(),
        next_cseq: 9,
        local_addr: None,
        interval_secs: 600,
        binding_until_unix: crate::registrant::persist::unix_now() + 600,
        origin: crate::registrant::EntryOrigin::Source,
        attempts: 0,
    }
}

impl Setup {
    /// A restart that finds one orphaned binding: its de-REGISTER, sent.
    async fn startup_orphan(
        &self,
        lookup: Option<Arc<StubLookup>>,
    ) -> (Arc<BindingStore>, SipMessage) {
        let store = BindingStore::in_memory("node-a", 30);
        store.save(orphan_record());
        self.registrant.attach_binding_store(Arc::clone(&store));
        if let Some(lookup) = lookup {
            self.registrant.set_credential_lookup(lookup);
        }
        let report = self
            .registrant
            .startup_cleanup(vec![orphan_record()], self.defaults());
        assert_eq!(report.deregistered, 1);
        self.registrant.release_startup_deregistrations().await;
        (store, self.send_queued_deregistration())
    }

    /// The authenticated de-REGISTER the lookup task queued, once it has run.
    async fn queued_after_lookup(&self) -> Option<SipMessage> {
        for _ in 0..100 {
            self.registrant.release_startup_deregistrations().await;
            if let Some(built) = test_support::take_deregistrations(&self.registrant).pop() {
                send_registrant_request(&self.registrant, TRUNK, &built, &self.dispatcher.state);
                return Some(parse_sent(&self.dispatcher.udp.try_recv().expect("sent")));
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        None
    }
}

#[tokio::test]
async fn a_restarts_de_register_is_sent_on_the_old_call_id_and_the_next_cseq() {
    let setup = Setup::new();
    let (_store, deregister) = setup.startup_orphan(None).await;

    assert_eq!(header(&deregister, "Expires"), "0");
    assert_eq!(header(&deregister, "Call-ID"), ORPHAN_CALL_ID);
    assert!(cseq(&deregister) > orphan_record().next_cseq);
    assert!(header(&deregister, "Contact").contains("sip:trunk@192.0.2.1:5060"));
    assert!(header(&deregister, "Authorization").is_empty());
}

#[tokio::test]
async fn a_challenge_to_a_restarts_de_register_is_answered_from_the_lookup() {
    let setup = Setup::new();
    let lookup = StubLookup::knowing("looked-up-user", "looked-up-password");
    let (store, deregister) = setup.startup_orphan(Some(Arc::clone(&lookup))).await;
    setup.challenge(&deregister, "401 Unauthorized", "WWW-Authenticate");

    let answer = setup.queued_after_lookup().await.expect("the answer");

    // Asked for the claim before each de-REGISTER leaves, and for the credentials.
    assert!(lookup.asked.load(Ordering::SeqCst) >= 1);
    assert_eq!(header(&answer, "Expires"), "0");
    assert_eq!(header(&answer, "Call-ID"), ORPHAN_CALL_ID);
    assert_eq!(cseq(&answer), cseq(&deregister) + 1);
    assert!(header(&answer, "Authorization").contains("username=\"looked-up-user\""));
    assert_eq!(setup.registrant.removed_deregistrations_pending(), 1);

    setup.answer(&answer, "200 OK", "Expires: 0\r\n");

    assert_eq!(setup.registrant.removed_deregistrations_pending(), 0);
    assert!(store.load().await.expect("loaded").is_empty());
    assert!(setup.registrant.is_empty());
}

#[tokio::test]
async fn a_proxy_challenge_to_a_restarts_de_register_is_answered_with_proxy_authorization() {
    let setup = Setup::new();
    let (_store, deregister) = setup
        .startup_orphan(Some(StubLookup::knowing("user-a", "pw")))
        .await;
    setup.challenge(
        &deregister,
        "407 Proxy Authentication Required",
        "Proxy-Authenticate",
    );
    let answer = setup.queued_after_lookup().await.expect("the answer");
    assert!(header(&answer, "Proxy-Authorization").contains("username=\"user-a\""));
}

/// No lookup configured, an unknown AoR, a failing source: the challenge is
/// not answered, nothing is sent, and the record is dropped rather than tried
/// at every restart.
#[tokio::test]
async fn a_challenge_nothing_can_answer_leaves_the_binding_to_expire_and_drops_the_record() {
    let cases: [(&str, Option<Arc<StubLookup>>); 2] = [
        ("no lookup configured", None),
        ("an unknown AoR", Some(StubLookup::answering(Ok(None)))),
    ];
    for (name, lookup) in cases {
        let setup = Setup::new();
        let (store, deregister) = setup.startup_orphan(lookup).await;
        setup.challenge(&deregister, "401 Unauthorized", "WWW-Authenticate");
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert!(
            test_support::take_deregistrations(&setup.registrant).is_empty(),
            "{name}: answered"
        );
        assert!(setup.dispatcher.udp.try_recv().is_err(), "{name}: sent");
        wait_until_pending_is(&setup.registrant, 0).await;
        assert!(
            store.load().await.expect("loaded").is_empty(),
            "{name}: the record stayed"
        );
    }
}

#[tokio::test]
async fn a_second_challenge_after_the_lookup_gives_up_and_drops_the_record() {
    let setup = Setup::new();
    let (store, deregister) = setup
        .startup_orphan(Some(StubLookup::knowing("user-a", "pw")))
        .await;
    setup.challenge(&deregister, "401 Unauthorized", "WWW-Authenticate");
    let answer = setup.queued_after_lookup().await.expect("the answer");

    setup.challenge(&answer, "401 Unauthorized", "WWW-Authenticate");

    assert!(setup.dispatcher.udp.try_recv().is_err(), "answered twice");
    assert_eq!(setup.registrant.removed_deregistrations_pending(), 0);
    assert!(store.load().await.expect("loaded").is_empty());
}

#[tokio::test]
async fn timer_f_of_a_restarts_de_register_drops_the_record() {
    let setup = Setup::new();
    let (store, deregister) = setup.startup_orphan(None).await;
    let timer_f = setup.timer(&deregister, TimerName::F).expect("Timer F");

    setup.fire(timer_f);
    wait_until_pending_is(&setup.registrant, 0).await;

    assert!(store.load().await.expect("loaded").is_empty());
}

/// Project leak gate for the restart path: the tracked de-REGISTERs, the
/// transactions, the timers and the stored records are back where they began.
#[tokio::test]
async fn restart_de_registers_leave_nothing_behind_whichever_way_they_end() {
    let setup = Setup::new();
    let baseline_transactions = setup.transactions();
    let baseline_timers = setup.dispatcher.state.timer_wheel.len();
    let store = BindingStore::in_memory("node-a", 30);
    setup.registrant.attach_binding_store(Arc::clone(&store));
    setup
        .registrant
        .set_credential_lookup(StubLookup::knowing("user-a", "pw"));

    for cycle in 0..30 {
        store.save(orphan_record());
        setup
            .registrant
            .startup_cleanup(vec![orphan_record()], setup.defaults());
        setup.registrant.release_startup_deregistrations().await;
        let deregister = setup.send_queued_deregistration();
        match cycle % 3 {
            0 => setup.answer(&deregister, "200 OK", "Expires: 0\r\n"),
            1 => {
                setup.challenge(&deregister, "401 Unauthorized", "WWW-Authenticate");
                let answer = setup.queued_after_lookup().await.expect("the answer");
                setup.answer(&answer, "200 OK", "Expires: 0\r\n");
            }
            _ => {
                let timer_f = setup.timer(&deregister, TimerName::F).expect("Timer F");
                setup.fire(timer_f);
                wait_until_pending_is(&setup.registrant, 0).await;
            }
        }
        let _ = setup.dispatcher.udp.try_iter().count();
    }
    setup.fire(Instant::now() + 64 * T1);
    wait_until_pending_is(&setup.registrant, 0).await;

    assert_eq!(setup.transactions(), baseline_transactions);
    assert_eq!(setup.dispatcher.state.timer_wheel.len(), baseline_timers);
    assert!(store.load().await.expect("loaded").is_empty());
    assert_eq!(store.pending_writes(), 0);
    assert!(test_support::take_deregistrations(&setup.registrant).is_empty());
}

/// Re-checked before the authorised retry too: the lookup was slow, the trunk
/// was added and registered on that Contact meanwhile, and an `Expires: 0` now
/// would delete its binding.
#[tokio::test]
async fn a_slow_lookup_does_not_send_the_retry_once_the_trunk_registered_meanwhile() {
    let setup = Setup::new();
    let lookup = StubLookup::slow("user-a", "pw", Duration::from_millis(300));
    let (store, deregister) = setup.startup_orphan(Some(Arc::clone(&lookup))).await;
    setup.challenge(&deregister, "401 Unauthorized", "WWW-Authenticate");

    // While the source thinks: the trunk is live here, on the same Contact.
    setup.registrant.add(trunk(TRUNK));
    let (register, _) = setup.send(TRUNK, 3600);
    setup.answer(&register.message, "200 OK", "Expires: 3600\r\n");
    tokio::time::sleep(Duration::from_millis(600)).await;

    // Asked for the claim before each de-REGISTER leaves, and for the credentials.
    assert!(lookup.asked.load(Ordering::SeqCst) >= 1);
    assert!(
        test_support::take_deregistrations(&setup.registrant).is_empty(),
        "an authorised de-REGISTER was queued over a live registration"
    );
    assert_eq!(setup.registrant.removed_deregistrations_pending(), 0);
    // The record is the live registration's now.
    let left = store.load().await.expect("loaded");
    assert_eq!(left.len(), 1);
    assert_ne!(left[0].call_id, ORPHAN_CALL_ID);
}

/// Re-checked before the authorised retry as well: another node's record of the
/// same Contact appeared while the source was thinking.
#[tokio::test]
async fn another_nodes_record_appearing_during_a_slow_lookup_stops_the_retry() {
    let setup = Setup::new();
    let lookup = StubLookup::slow("user-a", "pw", Duration::from_millis(300));
    let (store, deregister) = setup.startup_orphan(Some(Arc::clone(&lookup))).await;
    setup.challenge(&deregister, "401 Unauthorized", "WWW-Authenticate");

    let mut other = orphan_record();
    other.instance = "node-b".to_string();
    other.call_id = "reg-on-the-other-node".to_string();
    store.save_as_instance(other);
    tokio::time::sleep(Duration::from_millis(600)).await;
    setup.registrant.release_startup_deregistrations().await;

    // Asked for the claim before each de-REGISTER leaves, and for the credentials.
    assert!(lookup.asked.load(Ordering::SeqCst) >= 1);
    assert!(
        test_support::take_deregistrations(&setup.registrant).is_empty(),
        "an authorised de-REGISTER left over another node's binding"
    );
    assert_eq!(setup.registrant.removed_deregistrations_pending(), 0);
    assert!(store.load().await.expect("loaded").is_empty());
}

/// A challenged REGISTER carries the Contact the first one did, even when the
/// dispatcher's own view of the addressing differs from the registration
/// loop's: only a wildcard UDP listener and a global advertised host name, so
/// the dispatcher's resolved local address is a concrete IP.
#[tokio::test]
async fn a_challenged_register_keeps_the_contact_of_the_first_one() {
    let registrant = Arc::new(test_support::manager().with_instance_id("node-a".to_string()));
    test_support::install_egress_with(
        &registrant,
        "0.0.0.0:5060",
        HashMap::new(),
        HashMap::new(),
        Some("sbc.example.org"),
    );
    let mut dispatcher = super::test_dispatcher::test_dispatcher();
    dispatcher.state.registrant_manager = Some(Arc::clone(&registrant));
    registrant.attach_transactions(Arc::new(RegisterTransactionLayer::of(&dispatcher.state)));
    let setup = Setup {
        registrant: Arc::clone(&registrant),
        dispatcher,
        listen: HashMap::new(),
    };
    registrant.add(trunk(TRUNK));

    let first = registrant
        .build_register(TRUNK, registrant.egress_defaults().expect("an egress"), 600)
        .expect("first");
    send_registrant_request(&registrant, TRUNK, &first, &setup.dispatcher.state);
    let first_sent = setup.dispatcher.udp.try_recv().expect("the REGISTER");
    let first_message = parse_sent(&first_sent);

    setup.answer(
        &first_message,
        "401 Unauthorized",
        "WWW-Authenticate: Digest realm=\"registrar.example\", nonce=\"abc123\", algorithm=MD5, qop=\"auth\"\r\n",
    );
    let retry = parse_sent(&setup.dispatcher.udp.try_recv().expect("the retry"));

    let expected = format!(
        "<sip:trunk@sbc.example.org:5060;rnode={}>",
        crate::registrant::contact_token_for_tests("node-a", TRUNK)
    );
    assert_eq!(header(&first_message, "Contact"), expected);
    assert_eq!(header(&retry, "Contact"), expected);
}
