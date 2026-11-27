//! Clearing the bindings a killed process left: what is stored, what a restart
//! makes of it, and that nothing it tracks outlives it.

// The deprecated `answer_removed_deregistration` is still what these drive.
#![allow(deprecated)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::*;
use crate::registrant::persist::{BindingRecord, BindingStore, MAX_STARTUP_ATTEMPTS};
use crate::registrant::test_support::{self, trunk, ue};
use crate::registrant::{cseq_number, EgressDefaults, EntryOrigin, RegistrantState};
use crate::transport::Transport;

const AOR: &str = "sip:trunk@carrier.example";
/// What a `trunk` fixture's Contact is on the process's address.
const CONTACT: &str = "sip:trunk@192.0.2.1:5060";

fn listen() -> HashMap<Transport, std::net::SocketAddr> {
    HashMap::from([(Transport::Udp, "192.0.2.1:5060".parse().expect("addr"))])
}

fn defaults(listen: &HashMap<Transport, std::net::SocketAddr>) -> EgressDefaults<'_> {
    EgressDefaults::new("192.0.2.1:5060".parse().expect("addr"), listen)
}

fn record(aor: &str) -> BindingRecord {
    BindingRecord {
        instance: "node-a".to_string(),
        aor: aor.to_string(),
        registrar_uri: format!("sip:{}", test_support::PCSCF),
        destination: test_support::PCSCF.parse().expect("addr"),
        address_str: None,
        transport: Transport::Udp,
        contact: CONTACT.to_string(),
        call_id: "reg-before-the-kill".to_string(),
        next_cseq: 9,
        local_addr: None,
        interval_secs: 600,
        binding_until_unix: unix_now() + 600,
        origin: EntryOrigin::Source,
        attempts: 0,
    }
}

/// A manager whose loop would have started: egress in place, the transaction
/// layer attached, and a store.
fn manager_with_store() -> (Arc<RegistrantManager>, Arc<BindingStore>) {
    let manager = Arc::new(test_support::manager());
    test_support::install_egress(&manager);
    test_support::attach_untracked_transactions(&manager);
    let store = BindingStore::in_memory("node-a", 30);
    manager.attach_binding_store(Arc::clone(&store));
    (manager, store)
}

/// What the clean-up queued, after the checks made just before it would leave.
async fn released(manager: &RegistrantManager) -> Vec<crate::registrant::BuiltRegister> {
    manager.release_startup_deregistrations().await;
    test_support::take_deregistrations(manager)
}

fn header(message: &crate::sip::message::SipMessage, name: &str) -> String {
    message.headers.get(name).cloned().unwrap_or_default()
}

#[tokio::test]
async fn a_granted_binding_is_stored_with_what_clears_it() {
    let (manager, store) = manager_with_store();
    let mut entry = trunk(AOR);
    entry.contact_uri = Some(CONTACT.to_string());
    let call_id = entry.call_id.clone();
    manager.add(entry);
    let listen = listen();
    let built = manager
        .build_register(AOR, defaults(&listen), 600)
        .expect("a REGISTER");
    let sent_cseq = cseq_number(&built.message).expect("a CSeq");
    manager.handle_success(AOR, 600);

    let stored = store.load().await.expect("loaded");
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].aor, AOR);
    assert_eq!(stored[0].call_id, call_id);
    assert_eq!(stored[0].contact, CONTACT);
    assert_eq!(stored[0].next_cseq, sent_cseq + 1);
    assert_eq!(stored[0].instance, "node-a");
    assert_eq!(stored[0].attempts, 0);
}

#[tokio::test]
async fn an_ims_ue_binding_is_never_stored() {
    let (manager, store) = manager_with_store();
    let impu = test_support::impu(1);
    manager.add(ue(1, None));
    manager.handle_success(&impu, 600);
    assert!(store.load().await.expect("loaded").is_empty());
}

#[tokio::test]
async fn bindings_registered_before_the_store_attached_are_written_when_it_does() {
    let manager = Arc::new(test_support::manager());
    test_support::install_egress(&manager);
    let mut entry = trunk(AOR);
    entry.contact_uri = Some(CONTACT.to_string());
    manager.add(entry);
    let listen = listen();
    manager.build_register(AOR, defaults(&listen), 600);
    manager.handle_success(AOR, 600);

    let store = BindingStore::in_memory("node-a", 30);
    manager.attach_binding_store(Arc::clone(&store));

    assert_eq!(store.load().await.expect("loaded").len(), 1);
}

/// RFC 3261 §10.2.3 / §10.2.4: the first request is a fetch (no Contact, no
/// Expires) on the stored Call-ID with a CSeq above every one the process
/// before used; the de-REGISTER follows it only on a 2xx listing our Contact.
#[tokio::test]
async fn an_orphan_is_fetched_then_de_registered_on_its_call_id_contact_and_next_cseq() {
    let (manager, store) = manager_with_store();
    let listen = listen();
    let stored = record(AOR);
    store.save(stored.clone());

    let report = manager.startup_cleanup(vec![stored.clone()], defaults(&listen));

    assert_eq!(
        report,
        CleanupReport {
            deregistered: 1,
            ..CleanupReport::default()
        }
    );
    let fetch = released(&manager).await.pop().expect("a queued fetch");
    assert!(fetch.message.headers.get("Expires").is_none());
    assert!(fetch.message.headers.get("Contact").is_none());
    assert_eq!(header(&fetch.message, "Call-ID"), stored.call_id);
    assert!(cseq_number(&fetch.message).expect("CSeq") > stored.next_cseq);
    assert!(header(&fetch.message, "Authorization").is_empty());
    assert_eq!(manager.removed_deregistrations_pending(), 1);
    assert!(manager.is_empty(), "an orphan is not a live entry");

    // The attempt is counted where a later restart reads it.
    let after = store.load().await.expect("loaded");
    assert_eq!(after[0].attempts, 1);

    let answer = manager.answer_removed_registration(
        &stored.call_id,
        cseq_number(&fetch.message),
        200,
        None,
        &[format!("<{CONTACT}>;expires=120")],
        None,
        defaults(&listen),
    );
    assert!(matches!(
        answer,
        crate::registrant::RemovedAnswer::Continued
    ));
    let deregister = released(&manager).await.pop().expect("a de-REGISTER");
    assert_eq!(header(&deregister.message, "Expires"), "0");
    assert_eq!(header(&deregister.message, "Call-ID"), stored.call_id);
    assert!(header(&deregister.message, "Contact").contains(CONTACT));
    assert_eq!(
        cseq_number(&deregister.message),
        cseq_number(&fetch.message).map(|cseq| cseq + 1)
    );
}

#[tokio::test]
async fn an_entry_that_has_not_registered_takes_over_the_stored_binding() {
    let (manager, store) = manager_with_store();
    let listen = listen();
    manager.add(trunk(AOR));
    let stored = record(AOR);
    store.save(stored.clone());

    let report = manager.startup_cleanup(vec![stored.clone()], defaults(&listen));

    assert_eq!(report.carried, 1);
    assert!(released(&manager).await.is_empty());
    assert_eq!(manager.removed_deregistrations_pending(), 0);
    // Its next REGISTER refreshes that binding (RFC 3261 §10.2.4).
    let refresh = manager
        .build_register(AOR, defaults(&listen), 600)
        .expect("a REGISTER");
    assert_eq!(header(&refresh.message, "Call-ID"), stored.call_id);
    assert!(cseq_number(&refresh.message).expect("CSeq") > stored.next_cseq);
    assert!(header(&refresh.message, "Contact").contains(CONTACT));
}

/// A live entry that registered since has replaced the binding on the same
/// contact (§10.3), so there is nothing to clear and nothing to take over.
#[tokio::test]
async fn an_entry_that_registered_since_on_the_same_contact_is_left_alone() {
    let (manager, store) = manager_with_store();
    let listen = listen();
    manager.add(trunk(AOR));
    let own_call_id = manager
        .build_register(AOR, defaults(&listen), 600)
        .map(|built| header(&built.message, "Call-ID"))
        .expect("a REGISTER");
    let stored = record(AOR);
    store.save(stored.clone());

    let report = manager.startup_cleanup(vec![stored], defaults(&listen));

    assert_eq!(report.left, 1);
    assert!(released(&manager).await.is_empty());
    let after = manager
        .build_register(AOR, defaults(&listen), 600)
        .map(|built| header(&built.message, "Call-ID"))
        .expect("a REGISTER");
    assert_eq!(after, own_call_id, "its Call-ID was not touched");
}

/// The trunk is listed again but registers from somewhere else now: the old
/// contact is an orphan.
#[tokio::test]
async fn a_live_entry_on_another_contact_leaves_the_stored_one_to_be_cleared() {
    let (manager, store) = manager_with_store();
    let listen = listen();
    let mut entry = trunk(AOR);
    entry.contact_uri = Some("sip:trunk@192.0.2.99:5060".to_string());
    manager.add(entry);
    let stored = record(AOR);
    store.save(stored.clone());

    let report = manager.startup_cleanup(vec![stored.clone()], defaults(&listen));

    assert_eq!(report.deregistered, 1);
    let fetch = released(&manager).await.pop().expect("a fetch");
    manager.answer_removed_registration(
        &stored.call_id,
        cseq_number(&fetch.message),
        200,
        None,
        &[format!("<{CONTACT}>")],
        None,
        defaults(&listen),
    );
    let built = released(&manager).await.pop().expect("a de-REGISTER");
    assert!(header(&built.message, "Contact").contains(CONTACT));
    assert_eq!(manager.len(), 1);
    assert_eq!(manager.state(AOR), Some(RegistrantState::Unregistered));
}

#[tokio::test]
async fn an_ims_ue_entry_is_neither_taken_over_nor_cleared() {
    let (manager, store) = manager_with_store();
    let listen = listen();
    let impu = test_support::impu(1);
    manager.add(ue(1, None));
    let stored = record(&impu);
    store.save(stored.clone());

    let report = manager.startup_cleanup(vec![stored], defaults(&listen));

    assert_eq!(report.dropped, 1);
    assert!(released(&manager).await.is_empty());
    assert!(store.load().await.expect("loaded").is_empty());
}

#[tokio::test]
async fn a_binding_that_used_up_its_attempts_is_dropped_not_tried_again() {
    let (manager, store) = manager_with_store();
    let listen = listen();
    let mut stored = record(AOR);
    stored.attempts = MAX_STARTUP_ATTEMPTS;
    store.save(stored.clone());

    let report = manager.startup_cleanup(vec![stored], defaults(&listen));

    assert_eq!(report.dropped, 1);
    assert!(released(&manager).await.is_empty());
    assert!(store.load().await.expect("loaded").is_empty());
}

/// Each start-up that tries counts: three starts of an unanswerable binding,
/// and the fourth does not try.
#[tokio::test]
async fn the_attempt_bound_holds_across_restarts() {
    let store = BindingStore::in_memory("node-a", 30);
    store.save(record(AOR));
    let listen = listen();
    for restart in 1..=MAX_STARTUP_ATTEMPTS {
        let manager = Arc::new(test_support::manager());
        test_support::install_egress(&manager);
        manager.attach_binding_store(Arc::clone(&store));
        let records = store.load().await.expect("loaded");
        let report = manager.startup_cleanup(records, defaults(&listen));
        assert_eq!(report.deregistered, 1, "restart {restart} tries");
    }
    let manager = Arc::new(test_support::manager());
    test_support::install_egress(&manager);
    manager.attach_binding_store(Arc::clone(&store));
    let records = store.load().await.expect("loaded");
    let report = manager.startup_cleanup(records, defaults(&listen));
    assert_eq!(report.deregistered, 0);
    assert_eq!(report.dropped, 1);
    assert!(store.load().await.expect("loaded").is_empty());
}

/// A row the source returned and siphon rejected still counts as listed.
#[tokio::test]
async fn a_binding_of_a_row_the_source_rejected_is_left_alone() {
    let (manager, store) = manager_with_store();
    let listen = listen();
    manager.set_source_unusable(std::iter::once(AOR.to_string()).collect());
    let stored = record(AOR);
    store.save(stored.clone());

    let report = manager.startup_cleanup(vec![stored], defaults(&listen));

    assert_eq!(report.left, 1);
    assert!(released(&manager).await.is_empty());
    assert_eq!(store.load().await.expect("loaded").len(), 1);
}

#[tokio::test]
async fn nothing_is_cleared_once_shutdown_has_begun() {
    let (manager, store) = manager_with_store();
    let listen = listen();
    manager.begin_shutdown();
    let stored = record(AOR);
    store.save(stored.clone());
    let report = manager.startup_cleanup(vec![stored], defaults(&listen));
    assert_eq!(report, CleanupReport::default());
}

/// The three conditions and the store, in every order: ready only when the
/// last has happened. A store that attaches late is one of the orders.
#[test]
fn start_up_is_ready_only_once_all_four_have_happened_in_any_order() {
    fn step(manager: &Arc<RegistrantManager>, which: usize) {
        match which {
            0 => manager.mark_source_loaded(),
            1 => test_support::install_egress(manager),
            2 => test_support::attach_untracked_transactions(manager),
            _ => manager.attach_binding_store(BindingStore::in_memory("node-a", 30)),
        }
    }
    let mut orders = Vec::new();
    for first in 0..4 {
        for second in (0..4).filter(|n| *n != first) {
            for third in (0..4).filter(|n| *n != first && *n != second) {
                let fourth = 6 - first - second - third;
                orders.push([first, second, third, fourth]);
            }
        }
    }
    assert_eq!(orders.len(), 24);
    for order in orders {
        let manager = Arc::new(test_support::manager());
        for (index, which) in order.iter().enumerate() {
            assert!(
                !manager.startup_ready(),
                "ready before {order:?} step {index}"
            );
            step(&manager, *which);
        }
        assert!(manager.startup_ready(), "not ready after {order:?}");
    }
}

#[tokio::test]
async fn the_start_up_task_waits_for_a_late_store_then_clears_the_orphans() {
    let manager = Arc::new(test_support::manager());
    test_support::install_egress(&manager);
    test_support::attach_untracked_transactions(&manager);
    manager.mark_source_loaded();
    let late: Arc<std::sync::Mutex<Option<Arc<BindingStore>>>> = Arc::default();
    let published = Arc::clone(&late);
    let task = tokio::spawn(super::run_startup_cleanup_from(
        Arc::clone(&manager),
        move || published.lock().ok().and_then(|store| store.clone()),
    ));

    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!task.is_finished(), "ran without a store");
    assert!(released(&manager).await.is_empty());

    // Redis came up after boot.
    let store = BindingStore::in_memory("node-a", 30);
    store.save(record(AOR));
    *late.lock().expect("lock") = Some(Arc::clone(&store));
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("the task ends once it has run")
        .expect("no panic");

    assert_eq!(released(&manager).await.len(), 1);
}

// --- every way the de-REGISTER ends drops the record ---------------------------

async fn queued_orphan(
    manager: &RegistrantManager,
    store: &BindingStore,
) -> crate::registrant::BuiltRegister {
    let listen = listen();
    let stored = record(AOR);
    store.save(stored.clone());
    manager.startup_cleanup(vec![stored], defaults(&listen));
    released(manager).await.pop().expect("a de-REGISTER")
}

async fn stored_count(store: &BindingStore) -> usize {
    store.load().await.expect("loaded").len()
}

#[tokio::test]
async fn a_final_answer_to_an_orphans_de_register_drops_its_record() {
    let (manager, store) = manager_with_store();
    let built = queued_orphan(&manager, &store).await;
    let listen = listen();
    assert_eq!(stored_count(&store).await, 1);

    let answer = manager.answer_removed_deregistration(
        &header(&built.message, "Call-ID"),
        cseq_number(&built.message),
        200,
        None,
        defaults(&listen),
    );

    assert!(matches!(answer, crate::registrant::RemovedAnswer::Finished));
    assert_eq!(stored_count(&store).await, 0);
    assert_eq!(manager.removed_deregistrations_pending(), 0);
}

#[tokio::test]
async fn timer_f_of_an_orphans_de_register_drops_its_record() {
    let (manager, store) = manager_with_store();
    let built = queued_orphan(&manager, &store).await;
    assert!(manager.removed_deregistration_ended(&built.branch, "unanswered"));
    assert_eq!(stored_count(&store).await, 0);
    assert_eq!(manager.removed_deregistrations_pending(), 0);
}

#[tokio::test]
async fn the_sweep_of_an_orphans_de_register_drops_its_record() {
    let (manager, store) = manager_with_store();
    let _built = queued_orphan(&manager, &store).await;
    manager.expire_removed_deregistrations(Instant::now() + Duration::from_secs(120));
    assert_eq!(stored_count(&store).await, 0);
    assert_eq!(manager.removed_deregistrations_pending(), 0);
}

/// A trunk removed while registered clears its record with its de-REGISTER; a
/// trunk that never held a binding has none to clear.
#[tokio::test]
async fn removing_an_entry_drops_its_record_when_its_de_register_ends() {
    let (manager, store) = manager_with_store();
    let listen = listen();
    manager.add(trunk(AOR));
    manager.build_register(AOR, defaults(&listen), 600);
    manager.handle_success(AOR, 600);
    assert_eq!(stored_count(&store).await, 1);

    manager.remove(AOR);
    assert_eq!(stored_count(&store).await, 1, "kept until it is cleared");
    let built = released(&manager).await.pop().expect("a de-REGISTER");
    manager.answer_removed_deregistration(
        &header(&built.message, "Call-ID"),
        cseq_number(&built.message),
        200,
        None,
        defaults(&listen),
    );
    assert_eq!(stored_count(&store).await, 0);
}

#[tokio::test]
async fn a_shutdown_de_registration_drops_the_record() {
    let (manager, store) = manager_with_store();
    let listen = listen();
    manager.add(trunk(AOR));
    manager.build_register(AOR, defaults(&listen), 600);
    manager.handle_success(AOR, 600);
    assert_eq!(stored_count(&store).await, 1);

    let built = manager.begin_deregistration(defaults(&listen));
    assert_eq!(built.len(), 1);
    manager.finish_deregistration(AOR, 200);

    assert_eq!(stored_count(&store).await, 0);
}

/// A removal answered after the AoR was added again must not take the new
/// registration's record with it.
#[tokio::test]
async fn an_old_de_register_ending_leaves_the_record_of_a_new_registration() {
    let (manager, store) = manager_with_store();
    let listen = listen();
    manager.add(trunk(AOR));
    manager.build_register(AOR, defaults(&listen), 600);
    manager.handle_success(AOR, 600);
    manager.remove(AOR);
    let old = released(&manager).await.pop().expect("a de-REGISTER");

    manager.add(trunk(AOR));
    manager.build_register(AOR, defaults(&listen), 600);
    manager.handle_success(AOR, 600);
    manager.answer_removed_deregistration(
        &header(&old.message, "Call-ID"),
        cseq_number(&old.message),
        200,
        None,
        defaults(&listen),
    );

    assert_eq!(stored_count(&store).await, 1);
}

/// Project leak gate: the draining map, the queue and the records are back at
/// zero whichever way each orphan's de-REGISTER ended.
#[tokio::test]
async fn orphans_leave_no_tracked_de_register_and_no_record_whichever_way_they_end() {
    let (manager, store) = manager_with_store();
    let listen = listen();
    for cycle in 0..60u32 {
        let built = queued_orphan(&manager, &store).await;
        let call_id = header(&built.message, "Call-ID");
        match cycle % 4 {
            0 => {
                manager.answer_removed_deregistration(
                    &call_id,
                    cseq_number(&built.message),
                    200,
                    None,
                    defaults(&listen),
                );
            }
            1 => {
                manager.answer_removed_deregistration(
                    &call_id,
                    cseq_number(&built.message),
                    503,
                    None,
                    defaults(&listen),
                );
            }
            2 => {
                manager.removed_deregistration_ended(&built.branch, "unanswered");
            }
            _ => manager.expire_removed_deregistrations(Instant::now() + Duration::from_secs(120)),
        }
    }
    assert_eq!(manager.removed_deregistrations_pending(), 0);
    assert_eq!(stored_count(&store).await, 0);
    assert_eq!(store.pending_writes(), 0);
    assert!(released(&manager).await.is_empty());
    assert!(manager.is_empty());
}

// --- review findings ---------------------------------------------------------

/// A registrar keys a binding by its Contact (RFC 3261 §10.3): an `Expires: 0`
/// on a Contact that does not name this node could delete the binding another
/// node registered on it.
#[tokio::test]
async fn a_binding_on_a_contact_that_is_not_this_nodes_is_not_de_registered() {
    for contact in [
        // Another host.
        "sip:edge@203.0.113.9:5060",
        // This host, a port nothing here listens on.
        "sip:trunk@192.0.2.1:5099",
    ] {
        let (manager, store) = manager_with_store();
        let listen = listen();
        let mut stored = record(AOR);
        stored.contact = contact.to_string();
        store.save(stored.clone());

        let report = manager.startup_cleanup(vec![stored], defaults(&listen));

        assert_eq!(report.dropped, 1, "{contact}");
        assert_eq!(report.deregistered, 0, "{contact}");
        assert!(
            released(&manager).await.is_empty(),
            "{contact}: a de-REGISTER went out"
        );
        assert!(
            store.load().await.expect("loaded").is_empty(),
            "{contact}: the record stayed"
        );
    }
}

/// A per-entry address moves to another node with the trunk, which then
/// registers the same Contact: an address this node no longer holds is not its
/// own, whatever the old record says.
#[tokio::test]
async fn a_per_entry_address_that_moved_away_is_not_cleared() {
    let (manager, store) = manager_with_store();
    let listen = listen();
    let mut stored = record(AOR);
    stored.local_addr = Some("192.0.2.77".parse().expect("addr"));
    stored.contact = "sip:trunk@192.0.2.77:5060".to_string();
    store.save(stored.clone());

    let report = manager.startup_cleanup(vec![stored], defaults(&listen));

    assert_eq!(report.dropped, 1);
    assert!(released(&manager).await.is_empty());
    assert!(store.load().await.expect("loaded").is_empty());
}

/// Stricter: the Contact must carry an explicit IP and port equal to a
/// specific listener or the egress socket, exactly. A bindable address, a
/// wildcard, a hostname or a missing port never qualifies (the binding just
/// expires, as before).
#[tokio::test]
async fn a_contact_that_is_not_exactly_a_listener_or_egress_socket_never_qualifies() {
    for contact in [
        // Bindable here, but not a socket this node registers from.
        "sip:trunk@127.0.0.1:5060",
        // Wildcards.
        "sip:trunk@0.0.0.0:5060",
        "sip:trunk@[::]:5060",
        // No port.
        "sip:trunk@192.0.2.1",
        // A name.
        "sip:trunk@sbc.example:5060",
    ] {
        let (manager, store) = manager_with_store();
        let listen = listen();
        let mut stored = record(AOR);
        stored.contact = contact.to_string();
        store.save(stored.clone());

        let report = manager.startup_cleanup(vec![stored], defaults(&listen));

        assert_eq!(report.dropped, 1, "{contact}");
        assert!(
            released(&manager).await.is_empty(),
            "{contact}: a de-REGISTER went out"
        );
    }
}

/// A wildcard listener is no address to name in a Contact.
#[tokio::test]
async fn a_wildcard_listener_does_not_make_a_wildcard_contact_this_nodes() {
    let manager = Arc::new(test_support::manager());
    test_support::attach_untracked_transactions(&manager);
    let wildcard: HashMap<Transport, std::net::SocketAddr> =
        HashMap::from([(Transport::Udp, "0.0.0.0:5060".parse().expect("addr"))]);
    manager.set_egress(crate::registrant::RegistrantEgress {
        local_addr: "0.0.0.0:5060".parse().expect("addr"),
        listen_addrs: wildcard.clone(),
        advertised_addrs: HashMap::new(),
        advertised_address: None,
        hep_sender: None,
    });
    let store = BindingStore::in_memory("node-a", 30);
    manager.attach_binding_store(Arc::clone(&store));
    let mut stored = record(AOR);
    stored.contact = "sip:trunk@0.0.0.0:5060".to_string();
    store.save(stored.clone());

    let report = manager.startup_cleanup(
        vec![stored],
        EgressDefaults::new("0.0.0.0:5060".parse().expect("addr"), &wildcard),
    );

    assert_eq!(report.dropped, 1);
}

/// The default generated Contact is built from the listener's address and port,
/// which is what qualifies it.
#[tokio::test]
async fn the_default_generated_contact_is_the_listeners_socket_and_qualifies() {
    let (manager, _store) = manager_with_store();
    let listen = listen();
    manager.add(trunk(AOR));
    manager.build_register(AOR, defaults(&listen), 600);
    manager.handle_success(AOR, 600);
    let stored = manager
        .restart
        .bindings
        .get()
        .expect("a store")
        .load()
        .await
        .expect("loaded")
        .pop()
        .expect("a record");
    assert_eq!(stored.contact, "sip:trunk@192.0.2.1:5060");

    manager.remove(AOR);
    let mut again = stored;
    again.call_id = "reg-from-the-last-process".to_string();
    let report = manager.startup_cleanup(vec![again], defaults(&listen));
    assert_eq!(report.deregistered, 1);
}

/// A name advertised by every node proves nothing about whose Contact it is.
#[tokio::test]
async fn an_advertised_shared_host_does_not_make_a_contact_this_nodes() {
    let manager = Arc::new(test_support::manager());
    let listen = listen();
    manager.set_egress(crate::registrant::RegistrantEgress {
        local_addr: "192.0.2.1:5060".parse().expect("addr"),
        listen_addrs: listen.clone(),
        advertised_addrs: HashMap::from([(Transport::Udp, "sbc.example".to_string())]),
        advertised_address: Some("sbc.example".to_string()),
        hep_sender: None,
    });
    test_support::attach_untracked_transactions(&manager);
    let store = BindingStore::in_memory("node-a", 30);
    manager.attach_binding_store(Arc::clone(&store));
    let mut stored = record(AOR);
    stored.contact = "sip:trunk@sbc.example:5060".to_string();
    store.save(stored.clone());

    let report = manager.startup_cleanup(vec![stored], defaults(&listen));

    assert_eq!(report.dropped, 1);
    assert!(released(&manager).await.is_empty());
}

fn other_instance_record(contact: &str) -> BindingRecord {
    let mut other = record(AOR);
    other.instance = "node-b".to_string();
    other.call_id = "reg-on-the-other-node".to_string();
    other.contact = contact.to_string();
    other
}

/// Another node's record of the same AoR on the same Contact: its REGISTER
/// already replaced ours (RFC 3261 §10.3), and ours would delete it. Checked
/// again when the de-REGISTER is about to leave, so one that appears after the
/// clean-up queued it stops it too.
#[tokio::test]
async fn another_instance_holding_the_same_contact_stops_the_de_register() {
    let (manager, store) = manager_with_store();
    let listen = listen();
    let stored = record(AOR);
    store.save(stored.clone());
    manager.startup_cleanup(vec![stored], defaults(&listen));
    // It registered after ours was queued.
    store.save_as_instance(other_instance_record(CONTACT));

    assert!(
        released(&manager).await.is_empty(),
        "the de-REGISTER left over another node's binding"
    );
    assert_eq!(manager.removed_deregistrations_pending(), 0);
    assert!(store.load().await.expect("loaded").is_empty());
}

/// ...but another node on another Contact does not.
#[tokio::test]
async fn another_instance_on_another_contact_does_not_stop_it() {
    let (manager, store) = manager_with_store();
    let listen = listen();
    let stored = record(AOR);
    store.save(stored.clone());
    store.save_as_instance(other_instance_record("sip:trunk@192.0.2.9:5060"));
    manager.startup_cleanup(vec![stored], defaults(&listen));

    assert_eq!(released(&manager).await.len(), 1);
}

/// Fail closed: a store that cannot be read at send time abandons the
/// de-REGISTER (the binding expires, as before) and drops our record.
#[tokio::test]
async fn a_store_that_cannot_be_read_abandons_the_de_register() {
    let manager = Arc::new(test_support::manager());
    test_support::install_egress(&manager);
    test_support::attach_untracked_transactions(&manager);
    let store = BindingStore::inert("node-a");
    manager.attach_binding_store(Arc::clone(&store));
    let listen = listen();
    manager.startup_cleanup(vec![record(AOR)], defaults(&listen));

    assert!(released(&manager).await.is_empty());
    assert_eq!(manager.removed_deregistrations_pending(), 0);
}

/// A newer record (another Call-ID) written meanwhile is neither overwritten by
/// the attempt counter nor deleted by the clean-up's completion.
#[tokio::test]
async fn a_newer_record_survives_the_attempt_update_and_the_completion() {
    let (manager, store) = manager_with_store();
    let listen = listen();
    let mut newer = record(AOR);
    newer.call_id = "reg-newer".to_string();
    store.save(newer.clone());

    manager.startup_cleanup(vec![record(AOR)], defaults(&listen));
    let built = released(&manager).await.pop().expect("a de-REGISTER");
    manager.answer_removed_deregistration(
        &header(&built.message, "Call-ID"),
        cseq_number(&built.message),
        200,
        None,
        defaults(&listen),
    );

    assert_eq!(store.load().await.expect("loaded"), vec![newer]);
}

/// The registrar target is part of what a live entry replaces: a trunk moved
/// from one registrar to another on the same Contact leaves the old
/// registrar's binding to be cleared.
#[tokio::test]
async fn a_trunk_moved_to_another_registrar_does_not_cancel_the_old_ones_clean_up() {
    let (manager, store) = manager_with_store();
    let listen = listen();
    let stored = record(AOR);
    store.save(stored.clone());
    manager.startup_cleanup(vec![stored], defaults(&listen));
    let mut entry = trunk(AOR);
    entry.registrar_uri = "sip:198.51.100.99:5060".to_string();
    entry.contact_uri = Some(CONTACT.to_string());
    manager.add(entry);

    assert_eq!(
        released(&manager).await.len(),
        1,
        "the old registrar's binding was abandoned"
    );
}

/// A replacement record saved at late attach is not the clean-up's to delete,
/// by whichever path the clean-up drops a record.
#[tokio::test]
async fn a_replacement_record_saved_at_late_attach_survives_the_clean_up() {
    for attempts in [0, MAX_STARTUP_ATTEMPTS] {
        let manager = Arc::new(test_support::manager());
        test_support::install_egress(&manager);
        let listen = listen();
        let mut entry = trunk(AOR);
        entry.contact_uri = Some("sip:trunk@192.0.2.1:5090".to_string());
        let live_call_id = entry.call_id.clone();
        manager.add(entry);
        manager.build_register(AOR, defaults(&listen), 600);
        manager.handle_success(AOR, 600);
        let store = BindingStore::in_memory("node-a", 30);
        let mut stored = record(AOR);
        stored.attempts = attempts;
        store.save(stored);

        let snapshot = super::snapshot_then_attach(&manager, Arc::clone(&store))
            .await
            .expect("read");
        manager.startup_cleanup(snapshot, defaults(&listen));
        if let Some(built) = released(&manager).await.pop() {
            manager.answer_removed_deregistration(
                &header(&built.message, "Call-ID"),
                cseq_number(&built.message),
                200,
                None,
                defaults(&listen),
            );
        }

        let left = store.load().await.expect("loaded");
        assert_eq!(left.len(), 1, "attempts {attempts}");
        assert_eq!(left[0].call_id, live_call_id, "attempts {attempts}");
    }
}
/// DNS can hand back another frontend after a restart: the configured registrar
/// names the target, not the address it resolved to.
#[tokio::test]
async fn a_registrar_that_resolves_elsewhere_after_the_restart_is_the_same_target() {
    let (manager, store) = manager_with_store();
    let listen = listen();
    let mut entry = trunk(AOR);
    entry.destination = "198.51.100.77:5060".parse().expect("addr");
    manager.add(entry);
    let stored = record(AOR);
    store.save(stored.clone());

    let report = manager.startup_cleanup(vec![stored], defaults(&listen));

    assert_eq!(report.carried, 1);
    assert!(released(&manager).await.is_empty());
}

/// Checked again when the de-REGISTER is about to leave: a live entry took the
/// Contact since it was queued, so it would delete that entry's binding.
#[tokio::test]
async fn a_queued_restart_de_register_is_dropped_once_a_live_entry_holds_the_contact() {
    let (manager, store) = manager_with_store();
    let listen = listen();
    let stored = record(AOR);
    store.save(stored.clone());
    manager.startup_cleanup(vec![stored], defaults(&listen));
    assert_eq!(manager.removed_deregistrations_pending(), 1);
    manager.add(trunk(AOR));

    assert!(
        released(&manager).await.is_empty(),
        "the de-REGISTER left although the trunk is live on that Contact"
    );
    assert_eq!(manager.removed_deregistrations_pending(), 0);
}

/// A live entry that holds the AoR on another Contact does not stop the
/// de-REGISTER of the old one.
#[tokio::test]
async fn a_live_entry_on_another_contact_does_not_stop_the_de_register() {
    let (manager, store) = manager_with_store();
    let listen = listen();
    let mut entry = trunk(AOR);
    entry.contact_uri = Some("sip:trunk@192.0.2.1:5090".to_string());
    manager.add(entry);
    let stored = record(AOR);
    store.save(stored.clone());
    manager.startup_cleanup(vec![stored], defaults(&listen));

    assert_eq!(released(&manager).await.len(), 1);
}

/// The record of a cleaned-up binding goes with its de-REGISTER unless a live
/// entry has actually written one of its own; a live entry that merely exists
/// (here on another Contact, never registered) wrote nothing.
#[tokio::test]
async fn a_cleaned_up_record_is_dropped_although_a_live_entry_holds_the_aor() {
    let (manager, store) = manager_with_store();
    let listen = listen();
    let mut entry = trunk(AOR);
    entry.contact_uri = Some("sip:trunk@192.0.2.1:5090".to_string());
    manager.add(entry);
    let stored = record(AOR);
    store.save(stored.clone());
    manager.startup_cleanup(vec![stored.clone()], defaults(&listen));
    let built = released(&manager).await.pop().expect("a de-REGISTER");

    manager.answer_removed_deregistration(
        &header(&built.message, "Call-ID"),
        cseq_number(&built.message),
        200,
        None,
        defaults(&listen),
    );

    assert!(store.load().await.expect("loaded").is_empty());
}

/// ...and one a live entry did write stays.
#[tokio::test]
async fn a_record_a_live_entry_wrote_survives_the_clean_up_of_the_old_one() {
    let (manager, store) = manager_with_store();
    let listen = listen();
    let mut entry = trunk(AOR);
    entry.contact_uri = Some("sip:trunk@192.0.2.1:5090".to_string());
    let live_call_id = entry.call_id.clone();
    manager.add(entry);
    let stored = record(AOR);
    store.save(stored.clone());
    manager.startup_cleanup(vec![stored], defaults(&listen));
    let built = released(&manager).await.pop().expect("a de-REGISTER");
    manager.build_register(AOR, defaults(&listen), 600);
    manager.handle_success(AOR, 600);

    manager.answer_removed_deregistration(
        &header(&built.message, "Call-ID"),
        cseq_number(&built.message),
        200,
        None,
        defaults(&listen),
    );

    let left = store.load().await.expect("loaded");
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].call_id, live_call_id);
}

/// The previous process's records are read before any live binding is written
/// over them, a store that attaches late or not.
#[tokio::test]
async fn the_stored_records_are_read_before_a_live_binding_overwrites_them() {
    let manager = Arc::new(test_support::manager());
    test_support::install_egress(&manager);
    let listen = listen();
    let mut entry = trunk(AOR);
    entry.contact_uri = Some("sip:trunk@192.0.2.1:5090".to_string());
    manager.add(entry);
    manager.build_register(AOR, defaults(&listen), 600);
    manager.handle_success(AOR, 600);
    let store = BindingStore::in_memory("node-a", 30);
    store.save(record(AOR));

    let snapshot = super::snapshot_then_attach(&manager, Arc::clone(&store))
        .await
        .expect("read");

    assert_eq!(snapshot.len(), 1);
    assert_eq!(
        snapshot[0].contact, CONTACT,
        "the previous process's record"
    );
    // And the live binding is written afterwards.
    let now = store.load().await.expect("loaded");
    assert_eq!(now[0].contact, "sip:trunk@192.0.2.1:5090");
}

// ---------------------------------------------------------------------------
// Ownership by the per-node Contact token
// ---------------------------------------------------------------------------

fn token_manager(instance: &str) -> (Arc<RegistrantManager>, Arc<BindingStore>) {
    let manager = Arc::new(test_support::manager().with_instance_id(instance.to_string()));
    test_support::install_egress_with(
        &manager,
        "0.0.0.0:5060",
        HashMap::from([(Transport::Udp, "0.0.0.0:5060".parse().expect("addr"))]),
        HashMap::new(),
        Some("203.0.113.10"),
    );
    test_support::attach_untracked_transactions(&manager);
    let store = BindingStore::in_memory(instance, 30);
    manager.attach_binding_store(Arc::clone(&store));
    (manager, store)
}

fn tokened(instance: &str, host: &str) -> String {
    format!(
        "sip:trunk@{host};rnode={}",
        crate::registrant::contact::instance_token(instance, AOR)
    )
}

fn cleanup_of(
    manager: &RegistrantManager,
    contact: &str,
) -> crate::registrant::startup::CleanupReport {
    let mut stored = record(AOR);
    stored.contact = contact.to_string();
    let defaults = manager.egress_defaults().expect("an egress");
    manager.startup_cleanup(vec![stored], defaults)
}

/// A Contact carrying this instance's token is its own whatever its address:
/// the advertised IP, a host name, an address every node shares.
#[tokio::test]
async fn a_contact_with_this_instances_token_is_cleared_whatever_its_host() {
    for host in [
        "203.0.113.10:5060",
        "sbc.example.org:5060",
        "198.51.100.7:5099",
    ] {
        let (manager, _store) = token_manager("node-a");
        let report = cleanup_of(&manager, &tokened("node-a", host));
        assert_eq!(report.deregistered, 1, "{host}");
        assert_eq!(released(&manager).await.len(), 1, "{host}");
    }
}

/// Another instance's token on the shared address is never de-registered, with
/// or without a record of that node's binding: the registrar holds a different
/// binding for it.
#[tokio::test]
async fn another_instances_token_on_a_shared_address_is_never_cleared() {
    let (manager, store) = token_manager("node-a");
    let report = cleanup_of(&manager, &tokened("node-b", "203.0.113.10:5060"));
    assert_eq!(report.deregistered, 0);
    assert_eq!(report.dropped, 1);
    assert!(released(&manager).await.is_empty());
    assert!(store.load().await.expect("loaded").is_empty());
}

/// A token that is not this node's is not its own even on one of its sockets.
#[tokio::test]
async fn another_instances_token_on_this_nodes_own_socket_is_not_cleared() {
    let manager = Arc::new(test_support::manager().with_instance_id("node-a".to_string()));
    test_support::install_egress(&manager);
    test_support::attach_untracked_transactions(&manager);
    manager.attach_binding_store(BindingStore::in_memory("node-a", 30));
    let report = cleanup_of(&manager, &tokened("node-b", "192.0.2.1:5060"));
    assert_eq!(report.deregistered, 0);
}

/// No token (a source row's explicit contact, or one an older version stored):
/// only a concrete listener socket counts, as before.
#[tokio::test]
async fn a_contact_without_a_token_falls_back_to_the_concrete_socket_rule() {
    let manager = Arc::new(test_support::manager().with_instance_id("node-a".to_string()));
    test_support::install_egress(&manager);
    test_support::attach_untracked_transactions(&manager);
    manager.attach_binding_store(BindingStore::in_memory("node-a", 30));
    assert_eq!(
        cleanup_of(&manager, "sip:trunk@192.0.2.1:5060").deregistered,
        1
    );

    let (wildcard, _store) = token_manager("node-a");
    // The advertised address with no token proves nothing.
    assert_eq!(
        cleanup_of(&wildcard, "sip:trunk@203.0.113.10:5060").deregistered,
        0
    );
    assert_eq!(
        cleanup_of(&wildcard, "sip:trunk@sbc.example.org:5060").deregistered,
        0
    );
}

/// The second guard still stops a de-REGISTER over a binding another node
/// recorded on the very same Contact.
#[tokio::test]
async fn another_node_recording_the_same_tokened_contact_stops_the_de_register() {
    let (manager, store) = token_manager("node-a");
    let contact = tokened("node-a", "203.0.113.10:5060");
    assert_eq!(cleanup_of(&manager, &contact).deregistered, 1);
    store.save_as_instance(other_instance_record(&contact));
    assert!(released(&manager).await.is_empty());
}

/// A binding this node's live entry registers on the same Contact is taken
/// over, not de-registered: the live entry predicts the tokened Contact.
#[tokio::test]
async fn a_live_entry_takes_over_a_binding_on_its_own_tokened_contact() {
    let (manager, _store) = token_manager("node-a");
    manager.add(trunk(AOR));
    let contact = tokened("node-a", "203.0.113.10:5060");
    let report = cleanup_of(&manager, &contact);
    assert_eq!(report.carried, 1);
    assert_eq!(report.deregistered, 0);
}

// ---------------------------------------------------------------------------
// Contacts compared as SIP URIs (RFC 3261 §19.1.4), token case
// ---------------------------------------------------------------------------

/// Another node registered the same AoR with a tokenless Contact on the same
/// address: a parameter on one URI only is ignored, so it is the same binding
/// at the registrar, and this node's de-REGISTER would delete it.
#[tokio::test]
async fn a_tokenless_contact_equivalent_to_ours_stops_the_de_register() {
    let (manager, store) = token_manager("node-a");
    assert_eq!(
        cleanup_of(&manager, &tokened("node-a", "203.0.113.10:5060")).deregistered,
        1
    );
    store.save_as_instance(other_instance_record("sip:trunk@203.0.113.10:5060"));
    assert!(released(&manager).await.is_empty());
}

/// And a Contact of another instance's token, in another spelling, does not.
#[tokio::test]
async fn a_contact_with_another_token_does_not_stop_the_de_register() {
    let (manager, store) = token_manager("node-a");
    assert_eq!(
        cleanup_of(&manager, &tokened("node-a", "203.0.113.10:5060")).deregistered,
        1
    );
    store.save_as_instance(other_instance_record(&tokened(
        "node-b",
        "203.0.113.10:5060",
    )));
    assert_eq!(released(&manager).await.len(), 1);
}

/// A live entry registered the same binding in another spelling (parameter
/// order, case): the stored record is that entry's, taken over, not an orphan.
#[tokio::test]
async fn a_live_entry_takes_over_a_binding_spelled_another_way() {
    let (manager, _store) = manager_with_store();
    let listen = listen();
    let mut entry = trunk(AOR);
    entry.contact_uri = Some("sip:trunk@192.0.2.1:5060;rnode=ab12;transport=udp".to_string());
    manager.add(entry);
    let mut stored = record(AOR);
    stored.contact = "sip:trunk@192.0.2.1:5060;Transport=UDP;RNode=AB12".to_string();

    let report = manager.startup_cleanup(vec![stored], defaults(&listen));

    assert_eq!(report.carried, 1);
    assert_eq!(report.deregistered, 0);
}

/// The final guard: a live entry that took the Contact, spelled another way,
/// stops a queued de-REGISTER.
#[tokio::test]
async fn a_queued_de_register_is_dropped_once_a_live_entry_holds_an_equivalent_contact() {
    let (manager, store) = manager_with_store();
    let listen = listen();
    let mut stored = record(AOR);
    stored.contact = "sip:trunk@192.0.2.1:5060;transport=UDP".to_string();
    store.save(stored.clone());
    manager.startup_cleanup(vec![stored], defaults(&listen));
    assert_eq!(manager.removed_deregistrations_pending(), 1);
    let mut entry = trunk(AOR);
    entry.contact_uri = Some("sip:trunk@192.0.2.1:5060;transport=udp".to_string());
    manager.add(entry);
    // It registers on it, so its sent Contact is the equivalent spelling.
    manager.build_register(AOR, defaults(&listen), 600);

    assert!(released(&manager).await.is_empty());
}

/// A token in another spelling of the parameter name, foreign, on this node's
/// own socket: never accepted through the concrete-socket fallback.
#[tokio::test]
async fn a_foreign_token_in_any_case_is_never_cleared_on_a_concrete_socket() {
    let manager = Arc::new(test_support::manager().with_instance_id("node-a".to_string()));
    test_support::install_egress(&manager);
    test_support::attach_untracked_transactions(&manager);
    manager.attach_binding_store(BindingStore::in_memory("node-a", 30));
    let foreign = crate::registrant::contact::instance_token("node-b", AOR);
    for contact in [
        format!("sip:trunk@192.0.2.1:5060;RNode={foreign}"),
        format!("sip:trunk@192.0.2.1:5060;rnode={}", foreign.to_uppercase()),
    ] {
        assert_eq!(cleanup_of(&manager, &contact).deregistered, 0, "{contact}");
    }
}

/// This node's own token, upper-cased, is still its own.
#[tokio::test]
async fn this_nodes_token_in_upper_case_is_still_its_own() {
    let (manager, _store) = token_manager("node-a");
    let own = crate::registrant::contact::instance_token("node-a", AOR).to_uppercase();
    let contact = format!("sip:trunk@203.0.113.10:5060;RNODE={own}");
    assert_eq!(cleanup_of(&manager, &contact).deregistered, 1);
}

// ---------------------------------------------------------------------------
// A tokened claim and the trunk source: another node's tokenless Contact
// ---------------------------------------------------------------------------

/// A source that answers the lookup of every AoR the same way.
struct SourceStub {
    answer: Result<Option<crate::registrant::source::RegistrantRow>, String>,
    configured: bool,
}

impl crate::registrant::source::CredentialLookup for SourceStub {
    fn is_configured(&self) -> bool {
        self.configured
    }

    fn lookup<'a>(
        &'a self,
        _aor: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<Option<crate::registrant::source::RegistrantRow>, String>,
                > + Send
                + 'a,
        >,
    > {
        let answer = self.answer.clone();
        Box::pin(async move { answer })
    }
}

fn row(contact: Option<&str>) -> crate::registrant::source::RegistrantRow {
    serde_json::from_value(serde_json::json!({
        "aor": AOR,
        "registrar": "sip:198.51.100.10:5060",
        "username": "u",
        "password": "p",
        "contact": contact,
    }))
    .expect("a row")
}

/// The clean-up of a tokened binding of this node's on a shared address, with
/// the source answering `answer`: whether its de-REGISTER may leave.
async fn tokened_claim_with(
    answer: Option<Result<Option<crate::registrant::source::RegistrantRow>, String>>,
    configured: bool,
) -> bool {
    let (manager, _store) = token_manager("node-a");
    if let Some(answer) = answer {
        manager.set_credential_lookup(Arc::new(SourceStub { answer, configured }));
    }
    let report = cleanup_of(&manager, &tokened("node-a", "203.0.113.10:5060"));
    assert_eq!(report.deregistered, 1);
    !released(&manager).await.is_empty()
}

/// Another node registers a tokenless Contact only from a source row with an
/// explicit contact (or on an older version): the trunk source says so, not
/// Redis timing.
#[tokio::test]
async fn a_source_row_with_an_explicit_contact_blocks_the_tokened_claim() {
    // The AoR is not listed here, the lookup knows it with an explicit contact.
    assert!(!tokened_claim_with(Some(Ok(Some(row(Some("sip:u@203.0.113.10:5060"))))), true).await);
}

#[tokio::test]
async fn a_generated_source_row_or_an_unknown_aor_allows_the_tokened_claim() {
    assert!(tokened_claim_with(Some(Ok(Some(row(None)))), true).await);
    assert!(tokened_claim_with(Some(Ok(Some(row(Some(" "))))), true).await);
    assert!(tokened_claim_with(Some(Ok(None)), true).await);
    // No source at all: what is configured is all there is.
    assert!(tokened_claim_with(None, true).await);
}

#[tokio::test]
async fn a_failed_or_missing_lookup_blocks_the_tokened_claim() {
    assert!(!tokened_claim_with(Some(Err("down".to_string())), true).await);
    // A source with no lookup cannot say whether the AoR has an explicit one.
    assert!(!tokened_claim_with(Some(Ok(None)), false).await);
}

/// An AoR in this node's own list answers from the list: an explicit contact
/// blocks, a generated one allows, without asking the lookup.
#[tokio::test]
async fn a_listed_aor_answers_from_its_live_entry() {
    for (explicit, allowed) in [(Some("sip:u@198.51.100.7:5099"), false), (None, true)] {
        let (manager, _store) = token_manager("node-a");
        manager.set_credential_lookup(Arc::new(SourceStub {
            answer: Err("must not be asked".to_string()),
            configured: true,
        }));
        let mut entry = trunk(AOR);
        entry.contact_uri = explicit.map(str::to_string);
        manager.add(entry);
        // On another host than the live entry's: an orphan, not an adoption.
        let report = cleanup_of(&manager, &tokened("node-a", "198.51.100.99:5060"));
        assert_eq!(report.deregistered, 1, "{explicit:?}");
        assert_eq!(
            !released(&manager).await.is_empty(),
            allowed,
            "{explicit:?}"
        );
    }
}

/// A tokenless Contact on one of this node's own sockets, with the trunk source
/// answering `answer` (none: no source): whether its de-REGISTER may leave.
async fn tokenless_claim_with(
    answer: Option<Result<Option<crate::registrant::source::RegistrantRow>, String>>,
    configured: bool,
) -> bool {
    let manager = Arc::new(test_support::manager().with_instance_id("node-a".to_string()));
    test_support::install_egress(&manager);
    test_support::attach_untracked_transactions(&manager);
    manager.attach_binding_store(BindingStore::in_memory("node-a", 30));
    if let Some(answer) = answer {
        manager.set_credential_lookup(Arc::new(SourceStub { answer, configured }));
    }
    let report = cleanup_of(&manager, "sip:trunk@192.0.2.1:5060");
    assert_eq!(report.deregistered, 1);
    !released(&manager).await.is_empty()
}

/// Another node may hold the same explicit Contact (the socket may be a shared
/// address): when the source's row for the AoR names an equivalent one, no claim.
#[tokio::test]
async fn a_tokenless_claim_is_blocked_by_an_equivalent_explicit_contact_in_the_source() {
    assert!(
        !tokenless_claim_with(
            Some(Ok(Some(row(Some("SIP:trunk@192.0.2.1:5060;x=1"))))),
            true
        )
        .await,
        "equivalent but not identical spelling"
    );
    assert!(!tokenless_claim_with(Some(Err("down".to_string())), true).await);
    assert!(!tokenless_claim_with(Some(Ok(None)), false).await);
}

#[tokio::test]
async fn a_tokenless_claim_goes_when_the_source_shows_no_equivalent_contact() {
    assert!(tokenless_claim_with(Some(Ok(Some(row(None)))), true).await);
    assert!(
        tokenless_claim_with(Some(Ok(Some(row(Some("sip:trunk@192.0.2.1:5090"))))), true).await
    );
    assert!(tokenless_claim_with(Some(Ok(None)), true).await);
    assert!(tokenless_claim_with(None, true).await);
}

/// An escaped spelling of the token parameter's name is the token parameter.
#[tokio::test]
async fn a_foreign_token_behind_an_escaped_parameter_name_is_never_cleared() {
    let manager = Arc::new(test_support::manager().with_instance_id("node-a".to_string()));
    test_support::install_egress(&manager);
    test_support::attach_untracked_transactions(&manager);
    manager.attach_binding_store(BindingStore::in_memory("node-a", 30));
    let foreign = crate::registrant::contact::instance_token("node-b", AOR);
    let contact = format!("sip:trunk@192.0.2.1:5060;%72node={foreign}");
    assert_eq!(cleanup_of(&manager, &contact).deregistered, 0);
}

/// The deprecated answer function is given no Contacts, so it cannot read a
/// fetch's 2xx: it ends the exchange without `Expires: 0` and says so once.
#[test]
fn the_deprecated_answer_ends_a_fetch_without_a_de_register_and_warns() {
    let manager = test_support::manager();
    test_support::install_egress(&manager);
    manager.add(trunk("sip:trunk@carrier.example"));
    manager.handle_success("sip:trunk@carrier.example", 3600);
    manager.remove("sip:trunk@carrier.example");
    let fetch = manager
        .take_pending_deregistrations()
        .pop()
        .expect("the fetch");
    let call_id = fetch.message.headers.get("Call-ID").cloned().expect("id");
    let listen = HashMap::new();

    let answer = manager.answer_removed_deregistration(
        &call_id,
        cseq_number(&fetch.message),
        200,
        None,
        EgressDefaults::new("192.0.2.1:5060".parse().expect("addr"), &listen),
    );

    assert!(
        matches!(answer, crate::registrant::RemovedAnswer::Finished),
        "{answer:?}"
    );
    assert!(manager.take_pending_deregistrations().is_empty());
    assert_eq!(manager.removed_deregistrations_pending(), 0);
    assert!(crate::registrant::removed::deprecated_answer_noticed());
}
