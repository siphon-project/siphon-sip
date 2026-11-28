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
        Self::with_timers(None)
    }

    /// With the transaction layer's timers as given (`transaction.timeout_secs`).
    fn with_timers(timers: Option<crate::transaction::timer::TimerConfig>) -> Self {
        let registrant = Arc::new(test_support::manager());
        test_support::install_egress(&registrant);
        let mut dispatcher = super::test_dispatcher::test_dispatcher();
        if let Some(timers) = timers {
            dispatcher.state.transaction_manager = Arc::new(TransactionManager::new(timers));
        }
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

/// The `expires` a mock registrar logs for a fetch (RFC 3261 §10.2.3).
const FETCH: u32 = u32::MAX;

/// What a mock registrar saw and holds.
#[derive(Default)]
struct RegistrarLog {
    /// Every request on the wire after the signal: (method, To AoR, Expires,
    /// whether it carried credentials).
    requests: Vec<(String, String, u32, bool)>,
    /// The AoRs it holds a binding for.
    bound: std::collections::HashSet<String>,
    /// The Contact each of them registered, which a fetch lists back.
    contacts: HashMap<String, String>,
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
    if let Some(contact) = held.and_then(|held| held.headers.get("Contact")) {
        log.lock()
            .expect("the log")
            .contacts
            .insert(to_aor(held.expect("held")), contact.clone());
    }
    while let Ok(sent) = setup.dispatcher.udp.recv_async().await {
        let request = crate::sip::parser::parse_sip_message_bytes(&sent.data).expect("a request");
        let method = request
            .method()
            .map(|method| method.as_str().to_string())
            .unwrap_or_default();
        let aor = to_aor(&request);
        let fetch = method == "REGISTER"
            && request.headers.get("Expires").is_none()
            && request.headers.get("Contact").is_none();
        let expires: u32 = if fetch {
            FETCH
        } else {
            request
                .headers
                .get("Expires")
                .and_then(|value| value.trim().parse().ok())
                .unwrap_or(0)
        };
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
        if fetch || expires == 0 {
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
            if fetch {
                // The bindings it holds for the AoR (RFC 3261 §10.2.3).
                let log = log.lock().expect("the log");
                let listing = match log.contacts.get(&aor) {
                    Some(contact) if log.bound.contains(&aor) => {
                        format!("Contact: {contact}\r\nExpires: 3600\r\n")
                    }
                    _ => String::new(),
                };
                drop(log);
                setup.answer(&request, "200 OK", &listing);
                continue;
            }
            log.lock().expect("the log").bound.remove(&aor);
            setup.answer(&request, "200 OK", "Expires: 0\r\n");
        } else {
            if let Some(contact) = request.headers.get("Contact") {
                log.lock()
                    .expect("the log")
                    .contacts
                    .insert(aor.clone(), contact.clone());
            }
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
    let mut registered = Vec::new();
    for aor in &aors {
        setup.registrant.add(trunk(aor));
        let (register, _) = setup.send(aor, 3600);
        registered.push(header(&register.message, "Contact"));
        setup.answer(&register.message, "200 OK", "Expires: 3600\r\n");
    }
    setup.registrant.add(trunk(IN_FLIGHT));
    let (in_flight, _) = setup.send(IN_FLIGHT, 3600);
    let mut events = setup.registrant.subscribe_events();
    let log = std::sync::Mutex::new(RegistrarLog {
        bound: aors.iter().cloned().collect(),
        ..RegistrarLog::default()
    });
    for (index, aor) in aors.iter().enumerate() {
        log.lock()
            .expect("the log")
            .contacts
            .insert(aor.clone(), registered[index].clone());
    }

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
        let unauthenticated = |wanted: u32| {
            log.requests
                .iter()
                .filter(|(method, to, expires, credentials)| {
                    method == "REGISTER" && to == aor && *expires == wanted && !credentials
                })
                .count()
        };
        // The fetch first, then the one de-REGISTER its answer allowed.
        assert_eq!(unauthenticated(FETCH), 1, "{aor}: {:?}", log.requests);
        assert_eq!(unauthenticated(0), 1, "{aor}: {:?}", log.requests);
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
            .all(|(method, _, expires, _)| method == "REGISTER"
                && (*expires == 0 || *expires == FETCH)),
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
    // The fetch (RFC 3261 §10.2.3) that goes before any `Expires: 0`.
    assert!(header(&deregister, "Expires").is_empty());
    assert!(header(&deregister, "Contact").is_empty());
    assert!(header(&deregister, "Authorization").is_empty());

    setup.challenge(&deregister, "401 Unauthorized", "WWW-Authenticate");

    let answer = parse_sent(&setup.dispatcher.udp.try_recv().expect("the answer"));
    assert!(header(&answer, "Expires").is_empty(), "the fetch, answered");
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
    assert!(header(&answer, "Expires").is_empty(), "the fetch, answered");
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

/// A registrar's 2xx to a fetch that lists the orphan's Contact.
const OUR_CONTACT_LISTED: &str = "Contact: <sip:trunk@192.0.2.1:5060>;expires=120\r\n";

/// A registrar's 2xx to a fetch that lists only another node's Contact.
const OTHER_CONTACT_LISTED: &str = "Contact: <sip:trunk@198.51.100.77:5060>;expires=120\r\n";

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
    /// A restart that finds one orphaned binding: its fetch (RFC 3261
    /// §10.2.3), sent.
    async fn startup_fetch(
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

    /// A restart that finds one orphaned binding whose fetch lists this node's
    /// Contact: the de-REGISTER that follows, sent.
    async fn startup_orphan(
        &self,
        lookup: Option<Arc<StubLookup>>,
    ) -> (Arc<BindingStore>, SipMessage) {
        let (store, fetch) = self.startup_fetch(lookup).await;
        self.answer(&fetch, "200 OK", OUR_CONTACT_LISTED);
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

// --- the fetch before a restart's de-REGISTER (RFC 3261 §10.2.3) ---------------

/// The restart's first request queries the registrar and changes nothing: no
/// Contact, no Expires, the stored Call-ID, a CSeq past the stored one.
#[tokio::test]
async fn a_restarts_first_request_is_a_fetch_with_no_contact_and_no_expires() {
    let setup = Setup::new();
    let (_store, fetch) = setup.startup_fetch(None).await;

    assert_eq!(fetch.method(), Some(&crate::sip::message::Method::Register));
    assert!(fetch.headers.get("Contact").is_none());
    assert!(fetch.headers.get("Expires").is_none());
    assert!(header(&fetch, "Authorization").is_empty());
    assert_eq!(header(&fetch, "Call-ID"), ORPHAN_CALL_ID);
    assert!(cseq(&fetch) > orphan_record().next_cseq);
}

#[tokio::test]
async fn a_fetch_listing_our_contact_is_followed_by_the_de_register_on_the_next_cseq() {
    let setup = Setup::new();
    let (store, fetch) = setup.startup_fetch(None).await;
    setup.answer(&fetch, "200 OK", OUR_CONTACT_LISTED);
    setup.registrant.release_startup_deregistrations().await;
    let deregister = setup.send_queued_deregistration();

    assert_eq!(header(&deregister, "Expires"), "0");
    assert_eq!(header(&deregister, "Call-ID"), ORPHAN_CALL_ID);
    assert_eq!(cseq(&deregister), cseq(&fetch) + 1);
    assert!(header(&deregister, "Contact").contains("sip:trunk@192.0.2.1:5060"));
    assert_eq!(setup.registrant.removed_deregistrations_pending(), 1);

    setup.answer(&deregister, "200 OK", "Expires: 0\r\n");
    assert_eq!(setup.registrant.removed_deregistrations_pending(), 0);
    assert!(store.load().await.expect("loaded").is_empty());
}

/// A listed Contact that is the same URI spelled another way (case, parameter
/// order, a bare form with header parameters) still counts as ours.
#[tokio::test]
async fn an_equivalent_listed_contact_still_counts_as_ours() {
    for listed in [
        "Contact: <SIP:trunk@192.0.2.1:5060>;expires=120\r\n",
        "Contact: sip:trunk@192.0.2.1:5060;expires=120\r\n",
        "Contact: <sip:trunk@198.51.100.77:5060>, <sip:trunk@192.0.2.1:5060>\r\n",
    ] {
        let setup = Setup::new();
        let (_store, fetch) = setup.startup_fetch(None).await;
        setup.answer(&fetch, "200 OK", listed);
        setup.registrant.release_startup_deregistrations().await;
        let deregister = setup.send_queued_deregistration();
        assert_eq!(header(&deregister, "Expires"), "0", "{listed}");
    }
}

/// The registrar keeps one binding per AoR and another node holds it: nothing
/// is sent, the record is dropped, nothing stays tracked.
#[tokio::test]
async fn a_fetch_listing_only_another_contact_sends_no_de_register_and_drops_the_record() {
    for listed in [OTHER_CONTACT_LISTED, ""] {
        let setup = Setup::new();
        let (store, fetch) = setup.startup_fetch(None).await;
        setup.answer(&fetch, "200 OK", listed);
        setup.registrant.release_startup_deregistrations().await;

        assert!(
            test_support::take_deregistrations(&setup.registrant).is_empty(),
            "a de-REGISTER was queued over {listed:?}"
        );
        assert!(setup.dispatcher.udp.try_recv().is_err());
        assert_eq!(setup.registrant.removed_deregistrations_pending(), 0);
        assert!(store.load().await.expect("loaded").is_empty());
    }
}

#[tokio::test]
async fn a_refused_or_unanswered_fetch_sends_no_de_register_and_drops_the_record() {
    let setup = Setup::new();
    let (store, fetch) = setup.startup_fetch(None).await;
    setup.answer(&fetch, "503 Service Unavailable", "");
    setup.registrant.release_startup_deregistrations().await;
    assert!(test_support::take_deregistrations(&setup.registrant).is_empty());
    assert_eq!(setup.registrant.removed_deregistrations_pending(), 0);
    assert!(store.load().await.expect("loaded").is_empty());

    let setup = Setup::new();
    let (store, fetch) = setup.startup_fetch(None).await;
    let timer_f = setup.timer(&fetch, TimerName::F).expect("Timer F");
    setup.fire(timer_f);
    wait_until_pending_is(&setup.registrant, 0).await;
    setup.registrant.release_startup_deregistrations().await;
    assert!(test_support::take_deregistrations(&setup.registrant).is_empty());
    assert!(store.load().await.expect("loaded").is_empty());
}

/// A challenged fetch is answered from the lookup, still without Contact or
/// Expires; its 2xx listing ours leads to a de-REGISTER that is challenged and
/// answered the same way.
#[tokio::test]
async fn a_challenged_fetch_is_answered_from_the_lookup_and_the_de_register_too() {
    let setup = Setup::new();
    let (store, fetch) = setup
        .startup_fetch(Some(StubLookup::knowing(
            "looked-up-user",
            "looked-up-password",
        )))
        .await;
    setup.challenge(&fetch, "401 Unauthorized", "WWW-Authenticate");

    let authenticated_fetch = setup.queued_after_lookup().await.expect("the answer");
    assert!(header(&authenticated_fetch, "Authorization").contains("username=\"looked-up-user\""));
    assert!(authenticated_fetch.headers.get("Contact").is_none());
    assert!(authenticated_fetch.headers.get("Expires").is_none());
    assert_eq!(header(&authenticated_fetch, "Call-ID"), ORPHAN_CALL_ID);
    assert_eq!(cseq(&authenticated_fetch), cseq(&fetch) + 1);

    setup.answer(&authenticated_fetch, "200 OK", OUR_CONTACT_LISTED);
    let deregister = setup.queued_after_lookup().await.expect("the de-REGISTER");
    assert_eq!(header(&deregister, "Expires"), "0");
    assert_eq!(cseq(&deregister), cseq(&authenticated_fetch) + 1);

    setup.challenge(&deregister, "401 Unauthorized", "WWW-Authenticate");
    let authenticated = setup.queued_after_lookup().await.expect("the answer");
    assert_eq!(header(&authenticated, "Expires"), "0");
    assert!(header(&authenticated, "Authorization").contains("username=\"looked-up-user\""));
    assert_eq!(cseq(&authenticated), cseq(&deregister) + 1);

    setup.answer(&authenticated, "200 OK", "Expires: 0\r\n");
    assert_eq!(setup.registrant.removed_deregistrations_pending(), 0);
    assert!(store.load().await.expect("loaded").is_empty());
}

/// A fetch and the de-REGISTER after it are one attempt toward the bound.
#[tokio::test]
async fn a_fetch_and_its_de_register_count_as_one_attempt() {
    let setup = Setup::new();
    let (store, fetch) = setup.startup_fetch(None).await;
    assert_eq!(store.load().await.expect("loaded")[0].attempts, 1);
    setup.answer(&fetch, "200 OK", OUR_CONTACT_LISTED);
    setup.registrant.release_startup_deregistrations().await;
    let _ = setup.send_queued_deregistration();
    assert_eq!(store.load().await.expect("loaded")[0].attempts, 1);
}

/// Project leak gate: the tracked requests, the staged queue, the transactions,
/// the timers and the stored records are back where they began whichever way
/// the fetch and the de-REGISTER end.
#[tokio::test]
async fn fetches_leave_nothing_behind_whichever_way_they_end() {
    let setup = Setup::new();
    let baseline_transactions = setup.transactions();
    let baseline_timers = setup.dispatcher.state.timer_wheel.len();
    let store = BindingStore::in_memory("node-a", 30);
    setup.registrant.attach_binding_store(Arc::clone(&store));
    setup
        .registrant
        .set_credential_lookup(StubLookup::knowing("user-a", "pw"));

    for cycle in 0..40 {
        store.save(orphan_record());
        setup
            .registrant
            .startup_cleanup(vec![orphan_record()], setup.defaults());
        setup.registrant.release_startup_deregistrations().await;
        let fetch = setup.send_queued_deregistration();
        match cycle % 5 {
            0 => setup.answer(&fetch, "200 OK", OTHER_CONTACT_LISTED),
            1 => setup.answer(&fetch, "200 OK", ""),
            2 => setup.answer(&fetch, "500 Server Error", ""),
            3 => {
                setup.answer(&fetch, "200 OK", OUR_CONTACT_LISTED);
                setup.registrant.release_startup_deregistrations().await;
                let deregister = setup.send_queued_deregistration();
                setup.answer(&deregister, "200 OK", "Expires: 0\r\n");
            }
            _ => {
                let timer_f = setup.timer(&fetch, TimerName::F).expect("Timer F");
                setup.fire(timer_f);
                wait_until_pending_is(&setup.registrant, 0).await;
            }
        }
        let _ = setup.dispatcher.udp.try_iter().count();
    }
    setup.fire(Instant::now() + 64 * T1);
    wait_until_pending_is(&setup.registrant, 0).await;
    setup.registrant.release_startup_deregistrations().await;

    assert_eq!(setup.transactions(), baseline_transactions);
    assert_eq!(setup.dispatcher.state.timer_wheel.len(), baseline_timers);
    assert!(store.load().await.expect("loaded").is_empty());
    assert_eq!(store.pending_writes(), 0);
    assert!(test_support::take_deregistrations(&setup.registrant).is_empty());
    assert!(setup.registrant.is_empty());
}

/// RFC 3261 §10.3 step 8: our Contact listed with an expiry of zero (its own
/// parameter, or the answer's `Expires`) is not bound, whatever else is listed.
#[tokio::test]
async fn our_contact_listed_with_a_zero_expiry_does_not_authorize_the_de_register() {
    for listed in [
        "Contact: <sip:trunk@192.0.2.1:5060>;expires=0\r\nContact: <sip:trunk@198.51.100.77:5060>;expires=120\r\n",
        "Expires: 0\r\nContact: <sip:trunk@192.0.2.1:5060>\r\n",
    ] {
        let setup = Setup::new();
        let (store, fetch) = setup.startup_fetch(None).await;
        setup.answer(&fetch, "200 OK", listed);
        setup.registrant.release_startup_deregistrations().await;
        assert!(
            test_support::take_deregistrations(&setup.registrant).is_empty(),
            "a de-REGISTER was queued over {listed:?}"
        );
        assert_eq!(setup.registrant.removed_deregistrations_pending(), 0);
        assert!(store.load().await.expect("loaded").is_empty());
    }
}

/// Our Contact quoted inside a peer's display name, or behind a quoted-pair, is
/// not a listing of ours.
#[tokio::test]
async fn a_contact_inside_a_display_name_is_not_ours() {
    for listed in [
        "Contact: \"Old <sip:trunk@192.0.2.1:5060>\" <sip:trunk@198.51.100.77:5060>\r\n",
        "Contact: \"A \\\", <sip:trunk@192.0.2.1:5060>\" <sip:trunk@198.51.100.77:5060>\r\n",
    ] {
        let setup = Setup::new();
        let (_store, fetch) = setup.startup_fetch(None).await;
        setup.answer(&fetch, "200 OK", listed);
        setup.registrant.release_startup_deregistrations().await;
        assert!(
            test_support::take_deregistrations(&setup.registrant).is_empty(),
            "a de-REGISTER was queued over {listed:?}"
        );
    }
}

/// A listed URI the parser does not consume to its end, and a bare Contact in
/// an upper-case scheme with `expires=0`, are not a listing of ours.
#[tokio::test]
async fn a_partial_uri_or_an_expired_bare_contact_in_any_case_does_not_authorize_the_de_register() {
    for listed in [
        "Contact: <sip:trunk@192.0.2.1:5060/other>\r\n",
        "Contact: SIP:trunk@192.0.2.1:5060;expires=0\r\nContact: <sip:trunk@198.51.100.77:5060>\r\n",
    ] {
        let setup = Setup::new();
        let (_store, fetch) = setup.startup_fetch(None).await;
        setup.answer(&fetch, "200 OK", listed);
        setup.registrant.release_startup_deregistrations().await;
        assert!(
            test_support::take_deregistrations(&setup.registrant).is_empty(),
            "a de-REGISTER was queued over {listed:?}"
        );
    }
}

#[path = "registrant_fetch_deregistration_tests.rs"]
mod fetch_deregistration;

/// An unanswered UDP REGISTER sent just before the hold ran out is not
/// retransmitted after the entry stood down, and its transaction is gone: a
/// retransmission could still be answered, refreshing a binding another node
/// holds now.
#[tokio::test(start_paused = true)]
async fn a_stood_down_entry_leaves_no_transaction_to_retransmit() {
    let setup = Setup::new();
    let mut entry = trunk(TRUNK).from_source(1);
    entry.hold_secs = Some(30);
    setup.registrant.add(entry);
    setup.registrant.record_source_read();
    setup.registrant.record_source_unreadable();
    let sent_at = Instant::now();
    let (built, first) = setup.send(TRUNK, 3600);
    assert_eq!(setup.transactions(), 1);

    tokio::time::advance(Duration::from_secs(31)).await;
    assert_eq!(setup.registrant.record_source_unreadable(), 1);

    assert_eq!(setup.transactions(), 0, "the transaction is gone");
    assert!(setup.timer(&built.message, TimerName::E).is_none());
    assert!(setup.timer(&built.message, TimerName::F).is_none());
    for after in [T1, T1 * 3, T1 * 7, T2 * 2, T2 * 20] {
        setup.fire(sent_at + after);
    }
    assert!(
        setup.dispatcher.udp.try_recv().is_err(),
        "no retransmission of {:?}",
        first.destination
    );
}

/// A REGISTER built before the hold ran out, sent after: refused where the
/// transaction would be opened, so nothing leaves and nothing is left open.
#[tokio::test(start_paused = true)]
async fn a_register_sent_after_its_hold_ran_out_opens_no_transaction() {
    let setup = Setup::new();
    let mut entry = trunk(TRUNK).from_source(1);
    entry.hold_secs = Some(30);
    setup.registrant.add(entry);
    setup.registrant.record_source_read();
    setup.registrant.record_source_unreadable();
    let built = setup
        .registrant
        .build_register(TRUNK, setup.defaults(), 3600)
        .expect("built");

    setup
        .registrant
        .source_unreadable_since(Duration::from_secs(60));
    send_registrant_request(&setup.registrant, TRUNK, &built, &setup.dispatcher.state);

    assert!(setup.dispatcher.udp.try_recv().is_err(), "nothing sent");
    assert_eq!(setup.transactions(), 0);
    assert!(setup.registrant.is_empty());
}

/// Timer E asks the registrant before it re-sends: a Call-ID a stand-down
/// retired is refused even when the abandon has not run (or lost a race), and
/// the transaction and its timers end.
#[tokio::test]
async fn a_retransmission_on_a_stood_down_call_id_is_refused_and_ends_the_transaction() {
    let setup = Setup::new();
    setup.registrant.add(trunk(TRUNK));
    let (built, _first) = setup.send(TRUNK, 3600);
    assert_eq!(setup.transactions(), 1);

    let call_id = test_support::call_id(&setup.registrant, TRUNK).expect("a call id");
    setup.registrant.retire_call_id(&call_id);
    let fires = setup.timer(&built.message, TimerName::E).expect("Timer E");
    setup.fire(fires);

    assert!(setup.dispatcher.udp.try_recv().is_err(), "nothing re-sent");
    assert_eq!(setup.transactions(), 0);
    assert!(setup.timer(&built.message, TimerName::E).is_none());
    assert!(setup.timer(&built.message, TimerName::F).is_none());
}

/// A transaction opened for a Call-ID that was retired between the caller's
/// check and the timers being armed is ended at once.
#[tokio::test]
async fn a_transaction_opened_for_a_stood_down_call_id_is_ended_at_once() {
    use crate::registrant::RegisterTransactions;
    let setup = Setup::new();
    setup.registrant.add(trunk(TRUNK));
    let built = setup
        .registrant
        .build_register(TRUNK, setup.defaults(), 3600)
        .expect("built");
    let call_id = test_support::call_id(&setup.registrant, TRUNK).expect("a call id");
    setup.registrant.retire_call_id(&call_id);
    let layer = RegisterTransactionLayer::of(&setup.dispatcher.state);
    let wire = OutboundMessage {
        relayed: false,
        followups: None,
        connection_id: Default::default(),
        transport: built.transport,
        destination: built.destination,
        data: bytes::Bytes::from(built.message.to_bytes()),
        source_local_addr: built.source_local_addr,
        server_name: None,
        verify_server: None,
    };

    assert!(layer.open(&built.message, &wire).is_err());

    assert_eq!(setup.transactions(), 0);
    assert!(setup.timer(&built.message, TimerName::E).is_none());
}

/// Shutdown began, then a script removed the IMS entry: the de-REGISTER already
/// built still goes, and Timer E still retransmits it. No hold is involved.
#[tokio::test]
async fn an_ims_shutdown_de_register_survives_a_script_removing_the_entry() {
    let setup = Setup::new();
    setup
        .registrant
        .try_add(ue(1, Some(ip(UE_ADDR))))
        .expect("added");
    setup.registrant.handle_success(&impu(1), 600000);
    assert_eq!(
        crate::registrant::deregister_all(&setup.registrant, &setup.dispatcher.state.outbound),
        1
    );
    let first = setup
        .dispatcher
        .udp
        .try_recv()
        .expect("the de-REGISTER goes");
    let sent = parse_sent(&first);

    setup.registrant.remove(&impu(1));
    let fires = setup.timer(&sent, TimerName::E).expect("Timer E");
    setup.fire(fires);

    let again = setup
        .dispatcher
        .udp
        .try_recv()
        .expect("and is retransmitted");
    assert_retransmission_of(&first, &again);
}

/// A removed entry's fetch keeps retransmitting once the manager has dropped
/// its drain (70 s), when `transaction.timeout_secs` is longer.
#[tokio::test]
async fn a_removed_entrys_fetch_keeps_retransmitting_after_its_drain_is_dropped_under_a_long_timer_f(
) {
    let timers = crate::transaction::timer::TimerConfig {
        timer_f_secs: std::num::NonZeroU16::new(120),
        ..Default::default()
    };
    let setup = Setup::with_timers(Some(timers));
    setup.registrant.add(trunk(TRUNK));
    setup.registrant.handle_success(TRUNK, 3600);
    setup.registrant.remove(TRUNK);
    let mut queued = test_support::take_deregistrations(&setup.registrant);
    assert_eq!(queued.len(), 1);
    let fetch = queued.remove(0);
    send_registrant_request(&setup.registrant, TRUNK, &fetch, &setup.dispatcher.state);
    let first = setup.dispatcher.udp.try_recv().expect("the fetch goes");

    // The loop's tick has dropped the drain by now (70 s), and Timer F, set to
    // 120 s, has not fired: the fetch is still being retransmitted. (The
    // harness re-arms each timer from the real clock, so the 70 s is the
    // drain's deadline, passed to the expiry, not time that elapsed.)
    setup
        .registrant
        .expire_removed_deregistrations(Instant::now() + Duration::from_secs(75));
    assert!(!setup
        .registrant
        .is_deregistering(&test_support::call_id_of_message(&fetch.message)));
    let next = setup
        .timer(&fetch.message, TimerName::E)
        .expect("Timer E still armed");
    setup.fire(next);

    let again = setup.dispatcher.udp.try_recv().expect("retransmitted");
    assert_retransmission_of(&first, &again);
    assert!(setup.timer(&fetch.message, TimerName::F).is_some());
}

/// An action produced before the transaction was abandoned and executed after
/// it neither sends nor leaves a timer behind.
#[tokio::test(start_paused = true)]
async fn an_action_produced_before_the_abandon_sends_nothing_and_leaves_no_timer() {
    let setup = Setup::new();
    let mut entry = trunk(TRUNK).from_source(1);
    entry.hold_secs = Some(30);
    setup.registrant.add(entry);
    setup.registrant.record_source_read();
    setup.registrant.record_source_unreadable();
    let (built, first) = setup.send(TRUNK, 3600);
    let key = TransactionManager::key_from_message(&built.message).expect("a key");
    let produced = vec![
        Action::SendFrame(first.data.clone()),
        Action::StartTimer(TimerName::E, T2),
    ];

    tokio::time::advance(Duration::from_secs(31)).await;
    assert_eq!(setup.registrant.record_source_unreadable(), 1);
    process_timer_actions(
        &produced,
        &key,
        Some(first.destination),
        Some(first.transport),
        None,
        first.source_local_addr,
        &setup.dispatcher.state,
    );

    assert!(setup.dispatcher.udp.try_recv().is_err());
    assert!(setup.timer(&built.message, TimerName::E).is_none());
    assert_eq!(setup.transactions(), 0);
}

/// A timer started for a transaction the registrant ended meanwhile is not
/// kept, even when what it was produced with is still allowed.
#[tokio::test]
async fn a_timer_started_for_an_ended_transaction_is_not_kept() {
    let setup = Setup::new();
    setup.registrant.add(trunk(TRUNK));
    let (built, first) = setup.send(TRUNK, 3600);
    let key = TransactionManager::key_from_message(&built.message).expect("a key");
    setup.dispatcher.state.transaction_manager.remove(&key);
    setup.dispatcher.state.timer_wheel.clear();

    process_timer_actions(
        &[Action::StartTimer(TimerName::E, T2)],
        &key,
        Some(first.destination),
        Some(first.transport),
        None,
        first.source_local_addr,
        &setup.dispatcher.state,
    );

    assert!(setup.timer(&built.message, TimerName::E).is_none());
}
