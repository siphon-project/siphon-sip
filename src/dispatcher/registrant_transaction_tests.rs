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
