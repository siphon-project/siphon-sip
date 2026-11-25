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
    let built = test_support::take_deregistrations(&manager)
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
    assert!(test_support::take_deregistrations(&manager).is_empty());
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
    assert!(test_support::take_deregistrations(&manager).is_empty());
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
    let built = test_support::take_deregistrations(&manager)
        .pop()
        .expect("a de-REGISTER");
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
    assert!(test_support::take_deregistrations(&manager).is_empty());
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
    assert!(test_support::take_deregistrations(&manager).is_empty());
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
    assert!(test_support::take_deregistrations(&manager).is_empty());
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
    let task = tokio::spawn(super::run_startup_cleanup(Arc::clone(&manager)));

    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!task.is_finished(), "ran without a store");
    assert!(test_support::take_deregistrations(&manager).is_empty());

    // Redis came up after boot.
    let store = BindingStore::in_memory("node-a", 30);
    store.save(record(AOR));
    manager.attach_binding_store(Arc::clone(&store));
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("the task ends once it has run")
        .expect("no panic");

    assert_eq!(test_support::take_deregistrations(&manager).len(), 1);
}

// --- every way the de-REGISTER ends drops the record ---------------------------

fn queued_orphan(
    manager: &RegistrantManager,
    store: &BindingStore,
) -> crate::registrant::BuiltRegister {
    let listen = listen();
    let stored = record(AOR);
    store.save(stored.clone());
    manager.startup_cleanup(vec![stored], defaults(&listen));
    test_support::take_deregistrations(manager)
        .pop()
        .expect("a de-REGISTER")
}

async fn stored_count(store: &BindingStore) -> usize {
    store.load().await.expect("loaded").len()
}

#[tokio::test]
async fn a_final_answer_to_an_orphans_de_register_drops_its_record() {
    let (manager, store) = manager_with_store();
    let built = queued_orphan(&manager, &store);
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
    let built = queued_orphan(&manager, &store);
    assert!(manager.removed_deregistration_ended(&built.branch, "unanswered"));
    assert_eq!(stored_count(&store).await, 0);
    assert_eq!(manager.removed_deregistrations_pending(), 0);
}

#[tokio::test]
async fn the_sweep_of_an_orphans_de_register_drops_its_record() {
    let (manager, store) = manager_with_store();
    let _built = queued_orphan(&manager, &store);
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
    let built = test_support::take_deregistrations(&manager)
        .pop()
        .expect("a de-REGISTER");
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
    let old = test_support::take_deregistrations(&manager)
        .pop()
        .expect("a de-REGISTER");

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
        let built = queued_orphan(&manager, &store);
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
    assert!(test_support::take_deregistrations(&manager).is_empty());
    assert!(manager.is_empty());
}
