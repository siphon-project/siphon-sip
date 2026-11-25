//! Clearing the bindings a killed process left: what is stored, what a restart
//! makes of it, and that nothing it tracks outlives it.

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

/// RFC 3261 §10.2.2 / §10.2.4: Expires 0 on the stored Contact, the stored
/// Call-ID, a CSeq above every one the process before used.
#[tokio::test]
async fn an_orphan_is_de_registered_on_its_call_id_contact_and_next_cseq() {
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
    let built = released(&manager)
        .await
        .pop()
        .expect("a queued de-REGISTER");
    assert_eq!(header(&built.message, "Expires"), "0");
    assert_eq!(header(&built.message, "Call-ID"), stored.call_id);
    assert!(header(&built.message, "Contact").contains(CONTACT));
    assert!(cseq_number(&built.message).expect("CSeq") > stored.next_cseq);
    assert!(header(&built.message, "Authorization").is_empty());
    assert_eq!(manager.removed_deregistrations_pending(), 1);
    assert!(manager.is_empty(), "an orphan is not a live entry");

    // The attempt is counted where a later restart reads it.
    let after = store.load().await.expect("loaded");
    assert_eq!(after[0].attempts, 1);
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
