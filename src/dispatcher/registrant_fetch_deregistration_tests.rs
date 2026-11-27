//! The fetch (RFC 3261 §10.2.3) before every digest de-REGISTER: a live removal,
//! a source update that moves the binding, and shutdown. A registrar that keeps
//! one binding per AoR drops this node's binding when another node registers,
//! and an `Expires: 0` then clears the other node's. So the `Expires: 0` goes
//! only when the fetch's 2xx lists this node's own Contact; otherwise nothing is
//! sent, the binding expires on its own, and the record is dropped.

use super::*;
use crate::registrant::persist::BindingStore;

/// Another node's Contact on the same registrar.
const OTHER_CONTACT: &str = "Contact: <sip:trunk@198.51.100.77:5060>;expires=120\r\n";

fn lists(contact: &str) -> String {
    format!("Contact: {contact};expires=120\r\n")
}

impl Setup {
    /// A registered digest trunk `aor`, with a store holding its record.
    /// Returns the Contact it registered and the REGISTER that did.
    fn bound(&self, aor: &str) -> (String, SipMessage) {
        self.registrant.add(trunk(aor));
        let (register, _) = self.send(aor, 3600);
        self.answer(&register.message, "200 OK", "Expires: 3600\r\n");
        (header(&register.message, "Contact"), register.message)
    }

    fn next_sent(&self) -> Option<SipMessage> {
        self.dispatcher
            .udp
            .try_recv()
            .ok()
            .map(|sent| parse_sent(&sent))
    }

    /// A trunk registered and removed: the fetch the loop would send, sent.
    fn removed_fetch(&self) -> (String, SipMessage, SipMessage) {
        let (contact, register) = self.bound(TRUNK);
        self.registrant.remove(TRUNK);
        let fetch = self.send_queued_deregistration();
        assert_fetch(&fetch);
        (contact, register, fetch)
    }

    fn with_store(&self) -> Arc<BindingStore> {
        let store = BindingStore::in_memory("node-a", 30);
        self.registrant.attach_binding_store(Arc::clone(&store));
        store
    }

    /// Shutdown as `serve()` starts it: every registered entry's first request.
    fn begin_shutdown(&self) {
        crate::registrant::deregister_all(&self.registrant, &self.dispatcher.state.outbound);
    }
}

/// Nothing on the wire carries `Expires: 0`: only what Timer E retransmits of
/// the fetch is left.
fn assert_no_de_register(setup: &Setup) {
    for sent in setup.dispatcher.udp.try_iter() {
        let request = parse_sent(&sent);
        assert!(header(&request, "Expires").is_empty(), "Expires: 0 sent");
    }
}

fn assert_fetch(request: &SipMessage) {
    assert!(request.headers.get("Contact").is_none(), "a Contact");
    assert!(request.headers.get("Expires").is_none(), "an Expires");
}

fn assert_clearing(request: &SipMessage, contact: &str, fetch: &SipMessage) {
    assert_eq!(header(request, "Expires"), "0");
    assert_eq!(header(request, "Contact"), contact);
    assert_eq!(header(request, "Call-ID"), header(fetch, "Call-ID"));
    assert_eq!(cseq(request), cseq(fetch) + 1, "the CSeq after the fetch's");
}

// --- a live removal -----------------------------------------------------------

#[tokio::test]
async fn a_removed_trunks_first_request_is_a_fetch_on_its_call_id() {
    let setup = Setup::new();
    let (_contact, register, fetch) = setup.removed_fetch();

    assert_fetch(&fetch);
    assert_eq!(header(&fetch, "Call-ID"), header(&register, "Call-ID"));
    assert!(cseq(&fetch) > cseq(&register));
    assert!(setup.next_sent().is_none(), "an Expires: 0 went with it");
}

#[tokio::test]
async fn a_removal_fetch_listing_ours_is_followed_by_the_de_register_at_once() {
    let setup = Setup::new();
    let store = setup.with_store();
    let (contact, _register, fetch) = setup.removed_fetch();

    setup.answer(&fetch, "200 OK", &lists(&contact));

    let deregister = setup.next_sent().expect("the de-REGISTER");
    assert_clearing(&deregister, &contact, &fetch);
    assert_eq!(setup.registrant.removed_deregistrations_pending(), 1);
    setup.answer(&deregister, "200 OK", "Expires: 0\r\n");
    assert_eq!(setup.registrant.removed_deregistrations_pending(), 0);
    assert!(store.load().await.expect("loaded").is_empty());
}

#[tokio::test]
async fn a_removal_fetch_listing_only_another_contact_or_none_sends_no_de_register() {
    for (name, listing) in [("another", OTHER_CONTACT), ("none", "")] {
        let setup = Setup::new();
        let store = setup.with_store();
        let (_contact, _register, fetch) = setup.removed_fetch();

        setup.answer(&fetch, "200 OK", listing);

        assert!(setup.next_sent().is_none(), "{name}: Expires: 0 sent");
        assert_eq!(setup.registrant.removed_deregistrations_pending(), 0);
        assert!(
            store.load().await.expect("loaded").is_empty(),
            "{name}: the record stayed"
        );
    }
}

#[tokio::test]
async fn a_challenged_removal_fetch_is_answered_with_the_entrys_credentials_then_the_de_register_follows(
) {
    let setup = Setup::new();
    let (contact, _register, fetch) = setup.removed_fetch();

    setup.challenge(&fetch, "401 Unauthorized", "WWW-Authenticate");

    let answer = setup.next_sent().expect("the answered fetch");
    assert_fetch(&answer);
    assert!(header(&answer, "Authorization").contains("username=\"trunk\""));
    assert_eq!(cseq(&answer), cseq(&fetch) + 1);
    setup.answer(&answer, "200 OK", &lists(&contact));

    let deregister = setup.next_sent().expect("the de-REGISTER");
    assert_clearing(&deregister, &contact, &answer);
}

#[tokio::test]
async fn a_refused_or_unanswered_removal_fetch_sends_no_de_register() {
    let setup = Setup::new();
    let store = setup.with_store();
    let (_contact, _register, fetch) = setup.removed_fetch();
    setup.answer(&fetch, "503 Service Unavailable", "");
    assert!(setup.next_sent().is_none());
    assert_eq!(setup.registrant.removed_deregistrations_pending(), 0);
    assert!(store.load().await.expect("loaded").is_empty());

    let (_contact, _register, fetch) = setup.removed_fetch();
    let timer_f = setup.timer(&fetch, TimerName::F).expect("Timer F");
    setup.fire(timer_f);
    wait_until_pending_is(&setup.registrant, 0).await;
    assert_no_de_register(&setup);
    assert!(store.load().await.expect("loaded").is_empty());
}

#[tokio::test]
async fn a_trunk_added_again_meanwhile_keeps_its_binding() {
    let setup = Setup::new();
    let (contact, _register, fetch) = setup.removed_fetch();
    // The same trunk is back, and registered on the same Contact, before the
    // fetch is answered: an Expires: 0 on that Contact would clear its binding.
    let (_contact, _register) = setup.bound(TRUNK);

    setup.answer(&fetch, "200 OK", &lists(&contact));

    assert!(setup.next_sent().is_none(), "the live binding was cleared");
    assert_eq!(setup.registrant.removed_deregistrations_pending(), 0);
}

// --- a source update that moves the binding ------------------------------------

fn moved_trunk() -> crate::registrant::RegistrantEntry {
    let mut moved = trunk(TRUNK).from_source(2);
    moved.registrar_uri = "sip:198.51.100.20:5060".to_string();
    moved.destination = "198.51.100.20:5060".parse().expect("addr");
    moved
}

impl Setup {
    /// A source-owned trunk, registered, then moved to another registrar: the
    /// fetch to the old one, sent (and where it went).
    fn moved_fetch(&self) -> (String, SipMessage, SocketAddr) {
        self.registrant.add(trunk(TRUNK).from_source(1));
        let (register, _) = self.send(TRUNK, 3600);
        self.answer(&register.message, "200 OK", "Expires: 3600\r\n");
        let contact = header(&register.message, "Contact");
        assert!(self.registrant.update_from_source(moved_trunk()));
        let built = test_support::take_deregistrations(&self.registrant)
            .pop()
            .expect("a queued fetch");
        send_registrant_request(&self.registrant, TRUNK, &built, &self.dispatcher.state);
        let sent = self.dispatcher.udp.try_recv().expect("the fetch");
        assert_fetch(&parse_sent(&sent));
        (contact, parse_sent(&sent), sent.destination)
    }
}

#[tokio::test]
async fn a_binding_moved_to_another_registrar_is_fetched_from_the_old_one_first() {
    let setup = Setup::new();
    let (contact, fetch, destination) = setup.moved_fetch();

    assert_fetch(&fetch);
    assert_eq!(destination, test_support::PCSCF.parse().expect("addr"));
    assert_eq!(setup.registrant.removed_deregistrations_pending(), 1);
    setup.answer(&fetch, "200 OK", &lists(&contact));

    let deregister = setup.dispatcher.udp.try_recv().expect("the de-REGISTER");
    // The old registrar, not the new one.
    assert_eq!(deregister.destination, destination);
    assert_clearing(&parse_sent(&deregister), &contact, &fetch);
}

#[tokio::test]
async fn a_moved_binding_another_node_replaced_is_left() {
    let setup = Setup::new();
    let (_contact, fetch, _destination) = setup.moved_fetch();

    setup.answer(&fetch, "200 OK", OTHER_CONTACT);

    assert!(setup.next_sent().is_none(), "Expires: 0 sent");
    assert_eq!(setup.registrant.removed_deregistrations_pending(), 0);
}

// --- shutdown -----------------------------------------------------------------

#[tokio::test]
async fn shutdown_fetches_first_and_clears_only_a_binding_the_registrar_still_lists() {
    let setup = Setup::new();
    let store = setup.with_store();
    let (contact, register) = setup.bound(TRUNK);

    setup.begin_shutdown();

    let fetch = setup.next_sent().expect("the fetch");
    assert_fetch(&fetch);
    assert_eq!(header(&fetch, "Call-ID"), header(&register, "Call-ID"));
    assert!(cseq(&fetch) > cseq(&register));
    assert!(setup.next_sent().is_none(), "an Expires: 0 went with it");
    assert!(setup.registrant.deregistrations_pending());

    setup.answer(&fetch, "200 OK", &lists(&contact));

    let deregister = setup.next_sent().expect("the de-REGISTER");
    assert_clearing(&deregister, &contact, &fetch);
    assert!(setup.registrant.deregistrations_pending());
    setup.answer(&deregister, "200 OK", "Expires: 0\r\n");
    assert!(!setup.registrant.deregistrations_pending());
    assert_eq!(setup.registrant.removed_deregistrations_pending(), 0);
    assert!(store.load().await.expect("loaded").is_empty());
    assert_eq!(
        setup.registrant.state(TRUNK),
        Some(RegistrantState::Unregistered)
    );
}

#[tokio::test]
async fn shutdown_leaves_a_binding_another_node_replaced() {
    for (name, listing) in [("another", OTHER_CONTACT), ("none", "")] {
        let setup = Setup::new();
        let store = setup.with_store();
        setup.bound(TRUNK);
        setup.begin_shutdown();
        let fetch = setup.next_sent().expect("the fetch");
        assert_fetch(&fetch);

        setup.answer(&fetch, "200 OK", listing);

        assert!(setup.next_sent().is_none(), "{name}: Expires: 0 sent");
        assert!(!setup.registrant.deregistrations_pending(), "{name}");
        assert_eq!(setup.registrant.removed_deregistrations_pending(), 0);
        assert!(store.load().await.expect("loaded").is_empty(), "{name}");
    }
}

#[tokio::test]
async fn shutdown_answers_a_challenged_fetch_and_then_a_challenged_de_register() {
    let setup = Setup::new();
    let (contact, _register) = setup.bound(TRUNK);
    setup.begin_shutdown();
    let fetch = setup.next_sent().expect("the fetch");

    setup.challenge(&fetch, "401 Unauthorized", "WWW-Authenticate");
    let answered_fetch = setup.next_sent().expect("the answered fetch");
    assert_fetch(&answered_fetch);
    assert!(header(&answered_fetch, "Authorization").contains("username=\"trunk\""));
    assert_eq!(cseq(&answered_fetch), cseq(&fetch) + 1);
    setup.answer(&answered_fetch, "200 OK", &lists(&contact));

    let deregister = setup.next_sent().expect("the de-REGISTER");
    assert_clearing(&deregister, &contact, &answered_fetch);
    setup.challenge(&deregister, "401 Unauthorized", "WWW-Authenticate");
    let answered = setup.next_sent().expect("the answered de-REGISTER");
    assert_eq!(header(&answered, "Expires"), "0");
    assert!(header(&answered, "Authorization").contains("username=\"trunk\""));
    assert_eq!(cseq(&answered), cseq(&deregister) + 1);
    setup.answer(&answered, "200 OK", "Expires: 0\r\n");
    assert!(!setup.registrant.deregistrations_pending());
}

#[tokio::test]
async fn a_refused_or_timed_out_shutdown_fetch_sends_no_de_register() {
    let setup = Setup::new();
    let store = setup.with_store();
    setup.bound(TRUNK);
    setup.begin_shutdown();
    let fetch = setup.next_sent().expect("the fetch");
    assert_fetch(&fetch);
    setup.answer(&fetch, "503 Service Unavailable", "");
    assert!(setup.next_sent().is_none());
    assert!(!setup.registrant.deregistrations_pending());
    assert!(store.load().await.expect("loaded").is_empty());

    let setup = Setup::new();
    setup.bound(TRUNK);
    setup.begin_shutdown();
    let fetch = setup.next_sent().expect("the fetch");
    let timer_f = setup.timer(&fetch, TimerName::F).expect("Timer F");
    setup.fire(timer_f);
    for _ in 0..100 {
        if !setup.registrant.deregistrations_pending() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(!setup.registrant.deregistrations_pending());
    assert_no_de_register(&setup);
}

/// Shutdown stays inside its bound when the registrar never answers the fetch,
/// and sends no `Expires: 0`: the binding then expires on its own.
#[tokio::test(start_paused = true)]
async fn shutdown_with_an_unanswered_fetch_ends_within_its_bound_and_sends_no_de_register() {
    let setup = Setup::new();
    setup.bound(TRUNK);
    let config = crate::config::Config::from_str(concat!(
        "listen:\n  udp: [\"192.0.2.1:5060\"]\n",
        "domain:\n  local: [\"example.com\"]\n",
        "server:\n  drain_secs: 1\n",
    ))
    .expect("a config");
    let drain = Arc::new(crate::dispatcher::DrainState::new());
    let started = tokio::time::Instant::now();

    crate::server::shutdown_sequence::shut_down(
        &config,
        &drain,
        Some(&setup.registrant),
        &setup.dispatcher.state.outbound,
    )
    .await;

    assert!(
        started.elapsed() <= crate::registrant::SHUTDOWN_ANSWER_WAIT + Duration::from_secs(1),
        "{:?}",
        started.elapsed()
    );
    let fetch = setup.next_sent().expect("the fetch");
    assert_fetch(&fetch);
    assert!(setup.next_sent().is_none(), "an Expires: 0 went");
}

/// An IMS entry keeps its protected de-REGISTER: no fetch, `Expires: 0` first.
/// Its S-CSCF keeps every contact of the IMPU rather than replacing them, and
/// the de-REGISTER rides the SA set the registration did.
#[tokio::test]
async fn an_ims_entry_is_not_fetched_before_its_de_register() {
    let setup = Setup::new();
    setup.registrant.add(ue(1, None));
    setup.registrant.handle_success(&impu(1), 600000);

    setup.registrant.remove(&impu(1));

    let built = test_support::take_deregistrations(&setup.registrant)
        .pop()
        .expect("a de-REGISTER");
    assert_eq!(header(&built.message, "Expires"), "0");
    assert_eq!(setup.registrant.removed_deregistrations_pending(), 0);
}

/// Project leak gate: whichever way the fetches and de-REGISTERs of a shutdown
/// and of removals end, the draining entries, transactions, timers and records
/// are back where they started.
#[tokio::test]
async fn fetches_and_de_registers_leave_nothing_behind_whichever_way_they_end() {
    let setup = Setup::new();
    let store = setup.with_store();
    let baseline_transactions = setup.transactions();
    let baseline_timers = setup.dispatcher.state.timer_wheel.len();

    for cycle in 0..60 {
        let (contact, _register, fetch) = setup.removed_fetch();
        match cycle % 6 {
            0 => {
                setup.answer(&fetch, "200 OK", &lists(&contact));
                let deregister = setup.next_sent().expect("the de-REGISTER");
                setup.answer(&deregister, "200 OK", "Expires: 0\r\n");
            }
            1 => {
                setup.challenge(&fetch, "401 Unauthorized", "WWW-Authenticate");
                let answered = setup.next_sent().expect("the answered fetch");
                setup.answer(&answered, "200 OK", &lists(&contact));
                let deregister = setup.next_sent().expect("the de-REGISTER");
                setup.challenge(&deregister, "401 Unauthorized", "WWW-Authenticate");
            }
            2 => setup.answer(&fetch, "200 OK", OTHER_CONTACT),
            3 => setup.answer(&fetch, "500 Server Error", ""),
            4 => {
                let timer_f = setup.timer(&fetch, TimerName::F).expect("Timer F");
                setup.fire(timer_f);
            }
            _ => setup
                .registrant
                .expire_removed_deregistrations(Instant::now() + Duration::from_secs(120)),
        }
        let _ = setup.dispatcher.udp.try_iter().count();
    }
    setup.fire(Instant::now() + 64 * T1);
    wait_until_pending_is(&setup.registrant, 0).await;
    let _ = setup.dispatcher.udp.try_iter().count();

    // Shutdown, one entry per way it can end.
    let aors: Vec<String> = (0..4)
        .map(|index| format!("sip:trunk{index}@carrier.example"))
        .collect();
    let contacts: Vec<String> = aors.iter().map(|aor| setup.bound(aor).0).collect();
    setup.begin_shutdown();
    let fetches: Vec<SipMessage> = setup
        .dispatcher
        .udp
        .try_iter()
        .map(|s| parse_sent(&s))
        .collect();
    assert_eq!(fetches.len(), aors.len());
    for fetch in &fetches {
        let aor = header(fetch, "To")
            .trim_matches(|c| c == '<' || c == '>')
            .to_string();
        let index = aors
            .iter()
            .position(|candidate| *candidate == aor)
            .expect("an AoR");
        match index {
            0 => {
                setup.answer(fetch, "200 OK", &lists(&contacts[index]));
                let deregister = setup.next_sent().expect("the de-REGISTER");
                setup.answer(&deregister, "200 OK", "Expires: 0\r\n");
            }
            1 => setup.answer(fetch, "200 OK", OTHER_CONTACT),
            2 => setup.answer(fetch, "403 Forbidden", ""),
            _ => {
                let timer_f = setup.timer(fetch, TimerName::F).expect("Timer F");
                setup.fire(timer_f);
            }
        }
    }
    for _ in 0..100 {
        if !setup.registrant.deregistrations_pending() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let _ = setup.dispatcher.udp.try_iter().count();
    setup.fire(Instant::now() + 64 * T1);

    assert!(!setup.registrant.deregistrations_pending());
    assert_eq!(setup.registrant.removed_deregistrations_pending(), 0);
    assert_eq!(setup.transactions(), baseline_transactions);
    assert_eq!(setup.dispatcher.state.timer_wheel.len(), baseline_timers);
    assert!(store.load().await.expect("loaded").is_empty());
}
