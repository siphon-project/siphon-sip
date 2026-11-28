//! A trunk served with `hold_secs` stops registering once its source has been
//! unreadable for that long, and does so without sending a REGISTER.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::*;
use crate::registrant::persist::{BindingRecord, BindingStore};
use crate::registrant::refresh::{run_tick, RegistrationLoopContext};
use crate::registrant::source::{
    reconcile_once, HttpSource, ReconcileReport, RegistrantRow, RegistrantSource,
};
use crate::registrant::test_support::{self, trunk};
use crate::registrant::{
    EgressDefaults, EntryOrigin, RegistrantEntry, RegistrantEvent, RegistrantManager,
    RegistrantState,
};
use crate::transport::pool::ConnectionPool;
use crate::transport::{OutboundMessage, OutboundRouter, Transport};

const AOR: &str = "sip:trunk@carrier.example";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A source entry that holds for `hold_secs`.
fn held(aor: &str, hold_secs: Option<u32>) -> RegistrantEntry {
    let mut entry = trunk(aor).from_source(1);
    entry.hold_secs = hold_secs;
    entry
}

fn context() -> (RegistrationLoopContext, flume::Receiver<OutboundMessage>) {
    let (udp_sender, udp_receiver) = flume::unbounded();
    let (tcp, _) = flume::unbounded();
    let (tls, _) = flume::unbounded();
    let (ws, _) = flume::unbounded();
    let (wss, _) = flume::unbounded();
    let outbound = Arc::new(OutboundRouter {
        udp: udp_sender.into(),
        udp_by_local: HashMap::new(),
        udp_dynamic: None,
        tcp,
        tls,
        ws,
        wss,
        sctp: None,
    });
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    let pool = Arc::new(ConnectionPool::new(
        Arc::new(dashmap::DashMap::new()),
        flume::unbounded().0,
        "127.0.0.1:5060".parse().expect("addr"),
        None,
        None,
        None,
        crate::transport::pool::build_outbound_tls_config(
            None,
            crate::config::TlsMethod::default(),
        )
        .expect("a TLS config"),
    ));
    (
        RegistrationLoopContext {
            outbound,
            local_addr: "192.0.2.1:5060".parse().expect("addr"),
            listen_addrs: HashMap::from([(
                Transport::Udp,
                "192.0.2.1:5060".parse().expect("addr"),
            )]),
            advertised_addrs: HashMap::new(),
            advertised_address: None,
            hep_sender: None,
            connection_pool: pool,
            ue_sockets: None,
            ipsec_manager: None,
            mtu: None,
        },
        udp_receiver,
    )
}

/// A manager as the loop leaves it once running, with its context and the
/// receiver everything it sends arrives on.
fn running() -> (
    Arc<RegistrantManager>,
    RegistrationLoopContext,
    flume::Receiver<OutboundMessage>,
) {
    let manager = Arc::new(test_support::manager());
    test_support::install_egress(&manager);
    test_support::attach_untracked_transactions(&manager);
    let (context, receiver) = context();
    (manager, context, receiver)
}

fn tick(manager: &Arc<RegistrantManager>, context: &RegistrationLoopContext) {
    let Some(egress) = manager.egress.get() else {
        panic!("egress is installed by `running`");
    };
    run_tick(manager, context, egress, None);
}

fn defaults(manager: &RegistrantManager) -> EgressDefaults<'_> {
    manager.egress_defaults().expect("egress is installed")
}

fn sent(receiver: &flume::Receiver<OutboundMessage>) -> usize {
    receiver.try_iter().count()
}

fn nothing_is_left_behind(manager: &RegistrantManager) {
    assert!(manager.is_empty(), "the entry is gone");
    assert!(
        test_support::take_deregistrations(manager).is_empty(),
        "no de-REGISTER or fetch is queued"
    );
    assert_eq!(manager.removed_deregistrations_pending(), 0);
}

/// The source went unreadable at once after a good read, `elapsed` ago.
async fn unreadable_for(manager: &RegistrantManager, elapsed: Duration) {
    manager.record_source_read();
    manager.record_source_unreadable();
    tokio::time::advance(elapsed).await;
}

// ---------------------------------------------------------------------------
// The stand-down itself
// ---------------------------------------------------------------------------

/// Before the hold has run out the node still refreshes: the lease is not yet
/// known to have lapsed.
#[tokio::test(start_paused = true)]
async fn a_refresh_still_goes_before_the_hold_has_elapsed() {
    let (manager, context, receiver) = running();
    manager.add(held(AOR, Some(30)));
    unreadable_for(&manager, Duration::from_secs(29)).await;
    assert_eq!(manager.record_source_unreadable(), 0);

    test_support::make_due(&manager, AOR);
    tick(&manager, &context);

    assert_eq!(sent(&receiver), 1, "the REGISTER goes");
    assert_eq!(manager.len(), 1);
}

#[tokio::test(start_paused = true)]
async fn once_the_hold_has_elapsed_the_entry_stands_down_without_a_register() {
    let (manager, context, receiver) = running();
    let store = BindingStore::in_memory("node-a", 30);
    manager.attach_binding_store(Arc::clone(&store));
    let _ = crate::metrics::init();
    let before = crate::metrics::try_metrics()
        .expect("metrics")
        .registrant_source_standdowns_total
        .get();
    let mut events = manager.subscribe_events();
    manager.add(held(AOR, Some(30)));
    store.save(BindingRecord {
        instance: "node-a".to_string(),
        aor: AOR.to_string(),
        registrar_uri: format!("sip:{}", test_support::PCSCF),
        destination: test_support::PCSCF.parse().expect("addr"),
        address_str: None,
        transport: Transport::Udp,
        contact: "sip:trunk@192.0.2.1:5060".to_string(),
        call_id: test_support::call_id(&manager, AOR).expect("a call id"),
        next_cseq: 3,
        local_addr: None,
        interval_secs: 600,
        binding_until_unix: crate::registrant::persist::unix_now() + 600,
        origin: EntryOrigin::Source,
        attempts: 0,
    });

    unreadable_for(&manager, Duration::from_secs(31)).await;
    assert_eq!(manager.record_source_unreadable(), 1);

    nothing_is_left_behind(&manager);
    test_support::make_due(&manager, AOR);
    tick(&manager, &context);
    assert_eq!(sent(&receiver), 0, "nothing of any kind is sent");

    // The binding record stays: a restart's clean-up may still need it.
    assert_eq!(store.load().await.expect("loaded").len(), 1);

    let after = crate::metrics::try_metrics()
        .expect("metrics")
        .registrant_source_standdowns_total
        .get();
    assert!(after > before, "the counter moved: {before} -> {after}");

    let event = events.try_recv().expect("an event");
    assert!(
        matches!(event, RegistrantEvent::StoodDown { ref aor } if aor == AOR),
        "{event:?}"
    );
    assert!(events.try_recv().is_err(), "no Deregistered follows");
}

/// The poll interval can be longer than the hold: a refresh falling due in
/// between must be refused where it is built, whichever REGISTER it is.
#[tokio::test(start_paused = true)]
async fn a_refresh_due_between_polls_is_refused_where_it_is_built() {
    let (manager, context, receiver) = running();
    manager.add(held(AOR, Some(30)));
    manager.record_source_read();
    // One failed poll at t=0, the hold not yet run out, and no poll after it.
    assert_eq!(manager.record_source_unreadable(), 0);
    tokio::time::advance(Duration::from_secs(45)).await;

    assert!(manager
        .build_register(AOR, defaults(&manager), 3600)
        .is_none());
    nothing_is_left_behind(&manager);

    // The challenge answer of a REGISTER that was already out.
    manager.add(held(AOR, Some(30)));
    let challenge = crate::auth::parse_challenge(
        "Digest realm=\"carrier.example\", nonce=\"abc123\", algorithm=MD5",
    )
    .expect("a challenge");
    assert!(manager
        .build_register_with_auth(AOR, defaults(&manager), &challenge, false, 3600)
        .is_none());
    // The dispatcher then reports the failure; there is nothing to retry.
    manager.handle_failure(AOR, 401, None);
    nothing_is_left_behind(&manager);
    assert!(manager.entries_due_at(std::time::Instant::now()).is_empty());

    // The loop never picks it either.
    manager.add(held(AOR, Some(30)));
    test_support::make_due(&manager, AOR);
    tick(&manager, &context);
    assert_eq!(sent(&receiver), 0);
    nothing_is_left_behind(&manager);
}

/// A de-REGISTER is not a registration and is never held back by this.
#[tokio::test(start_paused = true)]
async fn a_de_register_is_not_refused() {
    let (manager, _context, _receiver) = running();
    manager.add(held(AOR, Some(30)));
    unreadable_for(&manager, Duration::from_secs(31)).await;
    assert!(!manager.refuses_registration(AOR, 0));
    assert!(manager.refuses_registration(AOR, 3600));
}

#[tokio::test(start_paused = true)]
async fn an_entry_without_a_hold_keeps_refreshing_while_the_source_is_down() {
    let (manager, context, receiver) = running();
    manager.add(held(AOR, None));
    unreadable_for(&manager, Duration::from_secs(10 * 3600)).await;
    assert_eq!(manager.record_source_unreadable(), 0);

    test_support::make_due(&manager, AOR);
    tick(&manager, &context);

    assert_eq!(sent(&receiver), 1);
    assert_eq!(manager.len(), 1);
}

/// Entries from `siphon.yaml` or a script have no hold, and a hold on one is
/// not honoured: the source never owned it.
#[tokio::test(start_paused = true)]
async fn yaml_and_script_entries_are_never_stood_down() {
    let (manager, context, receiver) = running();
    let mut yaml = trunk("sip:yaml@carrier.example").from_yaml();
    yaml.hold_secs = Some(0);
    let mut script = trunk("sip:script@carrier.example");
    script.hold_secs = Some(0);
    manager.add(yaml);
    manager.add(script);
    unreadable_for(&manager, Duration::from_secs(3600)).await;
    assert_eq!(manager.record_source_unreadable(), 0);

    test_support::make_due(&manager, "sip:yaml@carrier.example");
    test_support::make_due(&manager, "sip:script@carrier.example");
    tick(&manager, &context);

    assert_eq!(sent(&receiver), 2);
    assert_eq!(manager.len(), 2);
}

/// Only a failure since the last good read counts: a source that reads fine
/// holds nothing back however old the last read is.
#[tokio::test(start_paused = true)]
async fn a_readable_source_never_stands_an_entry_down() {
    let (manager, context, receiver) = running();
    manager.add(held(AOR, Some(0)));
    manager.record_source_read();
    tokio::time::advance(Duration::from_secs(3600)).await;

    test_support::make_due(&manager, AOR);
    tick(&manager, &context);

    assert_eq!(sent(&receiver), 1);
    assert_eq!(manager.len(), 1);
}

#[tokio::test(start_paused = true)]
async fn a_good_read_ends_the_outage() {
    let (manager, context, receiver) = running();
    manager.add(held(AOR, Some(30)));
    unreadable_for(&manager, Duration::from_secs(20)).await;
    manager.record_source_read();
    tokio::time::advance(Duration::from_secs(300)).await;

    test_support::make_due(&manager, AOR);
    tick(&manager, &context);
    assert_eq!(sent(&receiver), 1);
    assert_eq!(manager.len(), 1);
}

/// The answer to a REGISTER that was in flight when the entry stood down finds
/// nothing to update, and brings nothing back.
#[tokio::test(start_paused = true)]
async fn a_late_answer_does_not_bring_the_entry_back() {
    let (manager, _context, _receiver) = running();
    manager.add(held(AOR, Some(30)));
    let call_id = test_support::call_id(&manager, AOR).expect("a call id");
    unreadable_for(&manager, Duration::from_secs(31)).await;
    assert_eq!(manager.record_source_unreadable(), 1);
    let mut events = manager.subscribe_events();

    manager.handle_success(AOR, 3600);

    assert!(manager.is_empty());
    assert!(manager.find_by_call_id(&call_id).is_none());
    assert!(!manager.is_deregistering(&call_id));
    assert!(
        events.try_recv().is_err(),
        "no event for an entry that is gone"
    );
}

#[tokio::test(start_paused = true)]
async fn standing_down_twice_counts_once() {
    let (manager, _context, _receiver) = running();
    manager.add(held(AOR, Some(30)));
    unreadable_for(&manager, Duration::from_secs(31)).await;
    assert_eq!(manager.record_source_unreadable(), 1);
    assert_eq!(manager.record_source_unreadable(), 0);
}

// ---------------------------------------------------------------------------
// A hold that runs out between a check and what the check guards
// ---------------------------------------------------------------------------

const ELAPSED: Duration = Duration::from_secs(60);

fn outbound_of(built: &crate::registrant::BuiltRegister) -> OutboundMessage {
    OutboundMessage {
        relayed: false,
        followups: None,
        connection_id: crate::transport::ConnectionId::default(),
        transport: built.transport,
        destination: built.destination,
        data: bytes::Bytes::from(built.message.to_bytes()),
        source_local_addr: built.source_local_addr,
        server_name: None,
        verify_server: None,
    }
}

/// A REGISTER built while the hold had not run out is not put on the wire once
/// it has: the transaction is not opened, which is what every send site does
/// last (the loop's tick, the over-MTU task, a challenge answered, the AKA
/// task after its SA install).
#[tokio::test(start_paused = true)]
async fn a_register_built_before_the_hold_ran_out_is_not_sent_after() {
    let (manager, _context, _receiver) = running();
    manager.add(held(AOR, Some(30)));
    manager.record_source_read();
    manager.record_source_unreadable();
    let built = manager
        .build_register(AOR, defaults(&manager), 3600)
        .expect("built while the hold had time left");

    manager.source_unreadable_since(ELAPSED);
    let error = manager
        .open_transaction(&built.message, &outbound_of(&built))
        .expect_err("refused");

    assert!(error.contains("not sent"), "{error}");
    nothing_is_left_behind(&manager);
}

/// What the AKA task asks again after its kernel round trip, and the over-MTU
/// task after its connect.
#[tokio::test(start_paused = true)]
async fn a_registration_is_not_live_once_its_hold_ran_out() {
    let (manager, _context, _receiver) = running();
    manager.add(held(AOR, Some(30)));
    let call_id = test_support::call_id(&manager, AOR).expect("a call id");
    manager.record_source_read();
    manager.record_source_unreadable();
    assert!(manager.registration_live(AOR, &call_id));

    manager.source_unreadable_since(ELAPSED);

    assert!(!manager.registration_live(AOR, &call_id));
    nothing_is_left_behind(&manager);
}

/// A binding held, and the hold run out before any sweep: removing the entry
/// must not fetch (digest) or send `Expires: 0` (IMS).
#[tokio::test(start_paused = true)]
async fn removing_an_entry_past_its_hold_sends_no_fetch_and_no_de_register() {
    for ims in [false, true] {
        let (manager, _context, _receiver) = running();
        let mut entry = if ims {
            test_support::ue(1, None)
        } else {
            trunk(AOR)
        };
        let aor = entry.aor.clone();
        entry.origin = EntryOrigin::Source;
        entry.hold_secs = Some(30);
        manager.add(entry);
        manager.handle_success(&aor, 3600);
        manager.record_source_read();
        manager.record_source_unreadable();
        manager.source_unreadable_since(ELAPSED);

        manager.remove(&aor);

        assert!(manager.is_empty(), "ims {ims}");
        assert!(
            test_support::take_deregistrations(&manager).is_empty(),
            "ims {ims}: nothing queued"
        );
        assert_eq!(manager.removed_deregistrations_pending(), 0, "ims {ims}");
    }
}

#[tokio::test(start_paused = true)]
async fn shutdown_past_the_hold_sends_nothing_for_that_entry() {
    for ims in [false, true] {
        let (manager, _context, _receiver) = running();
        let mut entry = if ims {
            test_support::ue(1, None)
        } else {
            trunk(AOR)
        };
        let aor = entry.aor.clone();
        entry.origin = EntryOrigin::Source;
        entry.hold_secs = Some(30);
        manager.add(entry);
        // One that holds no hold, to show shutdown still de-registers it.
        manager.add(trunk("sip:other@carrier.example"));
        manager.handle_success(&aor, 3600);
        manager.handle_success("sip:other@carrier.example", 3600);
        manager.record_source_read();
        manager.record_source_unreadable();
        manager.source_unreadable_since(ELAPSED);

        let built = manager.begin_deregistration(defaults(&manager));

        assert_eq!(built.len(), 1, "ims {ims}: only the entry without a hold");
        assert!(manager.entries.get(&aor).is_none(), "ims {ims}");
        assert_eq!(manager.len(), 1, "ims {ims}");
    }
}

#[tokio::test(start_paused = true)]
async fn a_source_update_that_moves_a_binding_past_the_hold_sends_no_fetch() {
    let (manager, _context, _receiver) = running();
    manager.add(held(AOR, Some(30)));
    manager.handle_success(AOR, 3600);
    manager.record_source_read();
    manager.record_source_unreadable();
    manager.source_unreadable_since(ELAPSED);

    let mut moved = held(AOR, Some(30));
    moved.registrar_uri = "sip:other-registrar.example".to_string();
    moved.destination = "198.51.100.77:5060".parse().expect("addr");
    assert!(!manager.update_from_source(moved), "nothing to update");

    nothing_is_left_behind(&manager);
}

/// A failed read standing the entry down between an update's look-up and its
/// replacement must not be undone by the replacement.
#[tokio::test(start_paused = true)]
async fn an_update_does_not_bring_back_an_entry_stood_down_meanwhile() {
    const RACING: &str = "sip:racing@carrier.example";
    let (manager, _context, _receiver) = running();
    manager.add(held(RACING, Some(0)));
    manager.record_source_read();
    let racing = Arc::clone(&manager);
    *UPDATE_HOOK.lock().expect("lock") = Some((
        RACING.to_string(),
        Arc::new(move || {
            assert_eq!(
                racing.record_source_unreadable(),
                1,
                "stood down mid-update"
            );
        }),
    ));

    let updated = manager.update_from_source(held(RACING, Some(0)));

    *UPDATE_HOOK.lock().expect("lock") = None;
    assert!(!updated);
    nothing_is_left_behind(&manager);
}

// ---------------------------------------------------------------------------
// One authority: may a REGISTER on this Call-ID leave
// ---------------------------------------------------------------------------

/// A transaction layer that records what is abandoned.
#[derive(Default)]
struct Recorder {
    abandoned: Mutex<Vec<String>>,
}

impl crate::registrant::RegisterTransactions for Recorder {
    fn open(
        &self,
        _request: &crate::sip::message::SipMessage,
        _message: &OutboundMessage,
    ) -> Result<(), String> {
        Ok(())
    }

    fn transaction_lifetime(&self) -> Duration {
        Duration::from_secs(37)
    }

    fn abandon(&self, branch: &str) {
        self.abandoned
            .lock()
            .expect("lock")
            .push(branch.to_string());
    }
}

fn recording() -> (Arc<RegistrantManager>, Arc<Recorder>) {
    let manager = Arc::new(test_support::manager());
    test_support::install_egress(&manager);
    let recorder = Arc::new(Recorder::default());
    manager.attach_transactions(
        Arc::clone(&recorder) as Arc<dyn crate::registrant::RegisterTransactions>
    );
    (manager, recorder)
}

/// An entry the sweep already removed has no Call-ID to send on: the check
/// that used to pass for want of an entry now refuses.
#[tokio::test(start_paused = true)]
async fn an_entry_a_sweep_already_removed_is_refused_at_open_transaction() {
    let (manager, _context, _receiver) = running();
    manager.add(held(AOR, Some(30)));
    manager.record_source_read();
    manager.record_source_unreadable();
    let built = manager
        .build_register(AOR, defaults(&manager), 3600)
        .expect("built while the hold had time left");
    tokio::time::advance(Duration::from_secs(31)).await;
    assert_eq!(
        manager.record_source_unreadable(),
        1,
        "the sweep got there first"
    );

    assert!(manager
        .open_transaction(&built.message, &outbound_of(&built))
        .is_err());
    nothing_is_left_behind(&manager);
}

/// Without a stand-down nothing is refused, whoever owns the Call-ID: the
/// check is a deny-list, so a deployment without holds is never affected.
#[tokio::test(start_paused = true)]
async fn a_register_nobody_stood_down_is_allowed_whoever_owns_it() {
    let (manager, _context, _receiver) = running();
    manager.add(trunk(AOR));
    let built = manager
        .build_register(AOR, defaults(&manager), 3600)
        .expect("built");
    manager.entries.remove(AOR);

    assert!(manager
        .open_transaction(&built.message, &outbound_of(&built))
        .is_ok());
    assert!(!manager.send_refused("a-call-id-nobody-holds"));
}

/// The de-REGISTER of a removed entry keeps its authority however long it
/// lives, an IMS one included: nothing here depends on how long a drain is
/// tracked, or on whether one is.
#[tokio::test(start_paused = true)]
async fn a_removed_entrys_de_registration_is_never_refused_without_a_stand_down() {
    let (manager, _context, _receiver) = running();
    for (aor, ims) in [(AOR.to_string(), false), (test_support::impu(1), true)] {
        let entry = if ims {
            test_support::ue(1, None)
        } else {
            trunk(&aor)
        };
        manager.add(entry);
        let call_id = test_support::call_id(&manager, &aor).expect("a call id");
        manager.handle_success(&aor, 3600);

        manager.remove(&aor);
        let queued = test_support::take_deregistrations(&manager);
        assert_eq!(queued.len(), 1, "ims {ims}");
        manager
            .expire_removed_deregistrations(std::time::Instant::now() + Duration::from_secs(3600));
        tokio::time::advance(Duration::from_secs(300)).await;

        assert!(!manager.send_refused(&call_id), "ims {ims}");
        assert!(
            manager
                .open_transaction(&queued[0].message, &outbound_of(&queued[0]))
                .is_ok(),
            "ims {ims}: the first send"
        );
    }
}

/// Shutdown began and built an IMS entry's de-REGISTER, then a script removed
/// the entry before it went: the first send still goes (no hold is involved).
#[tokio::test(start_paused = true)]
async fn an_ims_shutdown_de_register_goes_after_a_script_removed_its_entry() {
    let (manager, _context, _receiver) = running();
    manager.add(test_support::ue(1, None));
    manager.handle_success(&test_support::impu(1), 600000);
    let mut built = manager.begin_deregistration(defaults(&manager));
    assert_eq!(built.len(), 1);
    let deregistration = built.remove(0);

    manager.remove(&test_support::impu(1));

    assert!(manager
        .open_transaction(&deregistration.message, &outbound_of(&deregistration))
        .is_ok());
}

/// A restart's clean-up queued with a delay still sends: no timer of ours
/// decides whether it has authority.
#[tokio::test(start_paused = true)]
async fn a_delayed_startup_clean_up_still_sends() {
    let (manager, _context, _receiver) = running();
    manager.add(trunk(AOR));
    manager.handle_success(AOR, 3600);
    manager.remove(AOR);
    let queued = test_support::take_deregistrations(&manager);
    assert_eq!(queued.len(), 1);
    tokio::time::advance(Duration::from_secs(600)).await;
    manager.expire_removed_deregistrations(std::time::Instant::now() + Duration::from_secs(600));

    assert!(manager
        .open_transaction(&queued[0].message, &outbound_of(&queued[0]))
        .is_ok());
}

/// Standing down remembers the Call-ID, and only for as long as a transaction
/// can live: then the set drains back to nothing.
#[tokio::test(start_paused = true)]
async fn stood_down_call_ids_are_remembered_for_a_transaction_lifetime_and_then_forgotten() {
    let (manager, _context, _receiver) = running();
    let mut call_ids = Vec::new();
    for index in 0..50 {
        let aor = format!("sip:trunk{index}@carrier.example");
        manager.add(held(&aor, Some(30)));
        call_ids.push(test_support::call_id(&manager, &aor).expect("a call id"));
    }
    unreadable_for(&manager, Duration::from_secs(31)).await;
    assert_eq!(manager.record_source_unreadable(), 50);

    assert_eq!(manager.tombstones(), 50);
    assert!(call_ids.iter().all(|call_id| manager.send_refused(call_id)));
    // A transaction layer's lifetime (37 s here) and a margin.
    manager.sweep_tombstones(std::time::Instant::now() + Duration::from_secs(10));
    assert_eq!(
        manager.tombstones(),
        50,
        "still within a transaction's life"
    );
    manager.sweep_tombstones(std::time::Instant::now() + Duration::from_secs(60));
    assert_eq!(manager.tombstones(), 0, "drained");
    assert!(manager.is_empty());
    assert_eq!(manager.removed_deregistrations_pending(), 0);
}

/// An entry handed back with the Call-ID that was stood down, and a recovery
/// with a persisted record still on file, both register on a Call-ID of their
/// own, which no tombstone can block.
#[tokio::test(start_paused = true)]
async fn a_recovered_entry_registers_on_a_fresh_call_id_with_its_record_still_stored() {
    let (manager, _context, _receiver) = running();
    let store = BindingStore::in_memory("node-a", 30);
    manager.attach_binding_store(Arc::clone(&store));
    manager.add(held(AOR, Some(30)));
    let old_call_id = test_support::call_id(&manager, AOR).expect("a call id");
    store.save(BindingRecord {
        instance: "node-a".to_string(),
        aor: AOR.to_string(),
        registrar_uri: format!("sip:{}", test_support::PCSCF),
        destination: test_support::PCSCF.parse().expect("addr"),
        address_str: None,
        transport: Transport::Udp,
        contact: "sip:trunk@192.0.2.1:5060".to_string(),
        call_id: old_call_id.clone(),
        next_cseq: 3,
        local_addr: None,
        interval_secs: 600,
        binding_until_unix: crate::registrant::persist::unix_now() + 600,
        origin: EntryOrigin::Source,
        attempts: 0,
    });
    unreadable_for(&manager, Duration::from_secs(31)).await;
    assert_eq!(manager.record_source_unreadable(), 1);
    assert!(manager.send_refused(&old_call_id));
    manager.record_source_read();

    // The source serves it again; a script hands the old entry back as well.
    let mut back = held(AOR, Some(30));
    back.call_id = old_call_id.clone();
    manager.add(back);

    let fresh = test_support::call_id(&manager, AOR).expect("added afresh");
    assert_ne!(fresh, old_call_id);
    assert!(!manager.send_refused(&fresh));
    let built = manager
        .build_register(AOR, defaults(&manager), 3600)
        .expect("built");
    assert!(manager
        .open_transaction(&built.message, &outbound_of(&built))
        .is_ok());
    assert_eq!(store.load().await.expect("loaded").len(), 1, "record kept");
}

/// The follow-up of a de-registration whose Call-ID was stood down is not
/// built, even when its drain is still there.
#[tokio::test(start_paused = true)]
async fn a_follow_up_on_a_stood_down_call_id_is_not_built() {
    use crate::registrant::RemovedAnswer;
    let (manager, _context, _receiver) = running();
    manager.add(trunk(AOR));
    manager
        .build_register(AOR, defaults(&manager), 3600)
        .expect("registered once");
    manager.handle_success(AOR, 3600);
    let contact = manager
        .entries
        .get(AOR)
        .and_then(|entry| entry.sent_contact.clone())
        .expect("the contact it registered");
    let fetch = manager.begin_deregistration(defaults(&manager));
    let call_id = test_support::call_id(&manager, AOR).expect("call id");
    manager.retire_call_id(&call_id);

    let answer = manager.answer_removed_registration(
        &call_id,
        crate::registrant::cseq_number(&fetch[0].message),
        200,
        None,
        &[contact],
        None,
        defaults(&manager),
    );

    assert!(matches!(answer, RemovedAnswer::NotTracked), "{answer:?}");
}

/// A deployment that never set a hold does no sweep work at all, and creates
/// no tombstone.
#[tokio::test(start_paused = true)]
async fn without_a_hold_nothing_is_scanned_or_remembered() {
    let (manager, _context, _receiver) = running();
    manager.add(trunk(AOR));
    let built = manager
        .build_register(AOR, defaults(&manager), 3600)
        .expect("built");
    manager.record_source_read();
    manager.record_source_unreadable();
    tokio::time::advance(Duration::from_secs(3600)).await;
    manager.record_source_unreadable();

    assert!(manager
        .open_transaction(&built.message, &outbound_of(&built))
        .is_ok());
    assert!(!manager.send_refused(
        &built
            .message
            .headers
            .get("Call-ID")
            .cloned()
            .unwrap_or_default()
    ));
    manager.entries_due();
    let _ = manager.begin_deregistration(defaults(&manager));

    assert_eq!(manager.expiry_scans(), 0);
    assert_eq!(manager.tombstones(), 0);
}

/// With holds in use but the source readable, the sweep is a flag check.
#[tokio::test(start_paused = true)]
async fn a_readable_source_costs_no_scan_even_with_holds() {
    let (manager, _context, _receiver) = running();
    manager.add(held(AOR, Some(30)));
    manager.record_source_read();
    tokio::time::advance(Duration::from_secs(3600)).await;
    for _ in 0..100 {
        manager.entries_due();
        manager.send_refused("any");
    }
    assert_eq!(manager.expiry_scans(), 0);
}

/// A replacement keeps the REGISTER that is in flight, so a stand-down before
/// the next one is built still abandons its transaction.
#[tokio::test(start_paused = true)]
async fn a_replaced_entry_keeps_its_in_flight_branch_for_a_later_stand_down() {
    let (manager, recorder) = recording();
    manager.add(held(AOR, Some(30)));
    manager.record_source_read();
    manager.record_source_unreadable();
    let built = manager
        .build_register(AOR, defaults(&manager), 3600)
        .expect("built");

    assert!(manager.update_from_source(held(AOR, Some(30))));
    assert_eq!(
        manager
            .entries
            .get(AOR)
            .expect("replaced")
            .in_flight_branch
            .as_deref(),
        Some(built.branch.as_str())
    );

    tokio::time::advance(Duration::from_secs(31)).await;
    assert_eq!(manager.record_source_unreadable(), 1);

    assert_eq!(
        *recorder.abandoned.lock().expect("lock"),
        std::slice::from_ref(&built.branch)
    );
}

/// Shutdown began before the hold ran out; the answer to its fetch comes after.
/// The answers that would send the authenticated retry or the `Expires: 0` are
/// no longer acted on, and the entry is gone.
#[tokio::test(start_paused = true)]
async fn de_registration_follow_ups_are_not_sent_after_the_hold() {
    use crate::registrant::RemovedAnswer;
    for (status, held_down) in [(200u16, true), (401, true), (200, false), (401, false)] {
        let (manager, _context, _receiver) = running();
        let mut entry = trunk(AOR).from_source(1);
        entry.hold_secs = held_down.then_some(30);
        manager.add(entry);
        manager
            .build_register(AOR, defaults(&manager), 3600)
            .expect("registered once");
        manager.handle_success(AOR, 3600);
        let contact = manager
            .entries
            .get(AOR)
            .and_then(|entry| entry.sent_contact.clone())
            .expect("the contact it registered");
        manager.record_source_read();
        manager.record_source_unreadable();

        let fetch = manager.begin_deregistration(defaults(&manager));
        assert_eq!(fetch.len(), 1);
        let call_id = test_support::call_id(&manager, AOR).expect("call id");
        let cseq = crate::registrant::cseq_number(&fetch[0].message);
        tokio::time::advance(Duration::from_secs(31)).await;
        manager.record_source_unreadable();
        let challenge = crate::auth::parse_challenge(
            "Digest realm=\"carrier.example\", nonce=\"abc123\", algorithm=MD5",
        )
        .expect("a challenge");

        let answer = manager.answer_removed_registration(
            &call_id,
            cseq,
            status,
            (status == 401).then_some((&challenge, false)),
            &[contact],
            None,
            defaults(&manager),
        );

        assert_eq!(
            matches!(answer, RemovedAnswer::Retry(_)),
            !held_down,
            "status {status}, hold {held_down}: {answer:?}"
        );
        if held_down {
            assert!(manager.is_empty());
            assert_eq!(manager.removed_deregistrations_pending(), 0);
            assert!(manager.send_refused(&call_id));
        }
    }
}

/// An answer to an earlier registration is not credited to the one that came
/// back after a stand-down.
#[tokio::test(start_paused = true)]
async fn an_answer_to_an_earlier_registration_is_not_applied_to_the_returned_entry() {
    let (manager, _context, _receiver) = running();
    manager.add(held(AOR, Some(30)));
    let old_call_id = test_support::call_id(&manager, AOR).expect("a call id");
    unreadable_for(&manager, Duration::from_secs(31)).await;
    assert_eq!(manager.record_source_unreadable(), 1);
    manager.record_source_read();
    manager.add(held(AOR, Some(30)));
    let new_call_id = test_support::call_id(&manager, AOR).expect("a call id");
    assert_ne!(old_call_id, new_call_id);

    manager.handle_success_for(AOR, &old_call_id, 3600);
    assert_eq!(manager.state(AOR), Some(RegistrantState::Unregistered));
    manager.handle_failure_for(AOR, &old_call_id, 503, None);
    assert_eq!(manager.state(AOR), Some(RegistrantState::Unregistered));

    manager.handle_success_for(AOR, &new_call_id, 3600);
    assert_eq!(manager.state(AOR), Some(RegistrantState::Registered));
}

// ---------------------------------------------------------------------------
// Publication, queues and the hold count
// ---------------------------------------------------------------------------

/// The Call-ID is remembered before the entry stops being found: a sender that
/// no longer finds the entry already finds the tombstone.
#[tokio::test(start_paused = true)]
async fn the_tombstone_is_there_before_the_entry_is_gone() {
    let (manager, _context, _receiver) = running();
    manager.add(held(AOR, Some(30)));
    let call_id = test_support::call_id(&manager, AOR).expect("a call id");
    manager.record_source_read();
    manager.record_source_unreadable();
    tokio::time::advance(Duration::from_secs(31)).await;
    let observed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let seen = Arc::clone(&observed);
    let watching = Arc::clone(&manager);
    let watched = call_id.clone();
    *STAND_DOWN_HOOK.lock().expect("lock") = Some((
        call_id,
        Arc::new(move || {
            // The entry is still in the map here, and already refused.
            seen.store(
                watching.stood_down_call_ids.contains_key(&watched),
                std::sync::atomic::Ordering::SeqCst,
            );
        }),
    ));

    assert_eq!(manager.record_source_unreadable(), 1);

    *STAND_DOWN_HOOK.lock().expect("lock") = None;
    assert!(observed.load(std::sync::atomic::Ordering::SeqCst));
}

/// A de-registration built and queued, not yet sent, does not outlive the
/// stand-down of its AoR: nothing is sent when the tombstone has expired and
/// the loop's tick runs.
#[tokio::test(start_paused = true)]
async fn a_queued_request_does_not_outlive_the_stand_down_and_its_tombstone() {
    for staged in [false, true] {
        let (manager, _context, receiver) = running();
        manager.add(held(AOR, Some(30)));
        manager.handle_success(AOR, 3600);
        manager.record_source_read();
        manager.record_source_unreadable();
        manager.remove(AOR);
        if staged {
            // The restart clean-up's queue instead of the removal's.
            for built in test_support::take_deregistrations(&manager) {
                manager.stage_startup_deregistration(built);
            }
        }
        tokio::time::advance(Duration::from_secs(31)).await;
        // No entry is left to stand down; the drain of the removed one carries
        // the hold and is dropped, with what it had queued.
        assert_eq!(manager.record_source_unreadable(), 0);
        manager.sweep_tombstones(std::time::Instant::now() + Duration::from_secs(3600));
        assert_eq!(manager.tombstones(), 0, "staged {staged}: forgotten");

        let queued = test_support::take_deregistrations(&manager);
        manager.release_startup_deregistrations().await;
        let released = test_support::take_deregistrations(&manager);
        assert!(queued.is_empty(), "staged {staged}: nothing queued");
        assert!(released.is_empty(), "staged {staged}: nothing staged");
        assert_eq!(sent(&receiver), 0);
    }
}

/// The hold count follows the entries: once the last one with a hold is gone,
/// an outage over many entries scans nothing.
#[tokio::test(start_paused = true)]
async fn the_fast_path_returns_once_the_last_held_entry_is_gone() {
    for scenario in ["stood down", "hold dropped", "replaced", "removed"] {
        let (manager, _context, _receiver) = running();
        for index in 0..100 {
            manager.add(trunk(&format!("sip:plain{index}@carrier.example")));
        }
        manager.add(held(AOR, Some(30)));
        match scenario {
            "stood down" => {
                unreadable_for(&manager, Duration::from_secs(31)).await;
                assert_eq!(manager.record_source_unreadable(), 1);
                manager.record_source_read();
            }
            "hold dropped" => manager.set_source_hold(AOR, None),
            "replaced" => {
                assert!(manager.update_from_source(held(AOR, None)));
            }
            _ => {
                manager.remove(AOR);
                manager.expire_removed_deregistrations(
                    std::time::Instant::now() + Duration::from_secs(3600),
                );
                manager.sweep_tombstones(std::time::Instant::now());
            }
        }
        let before = manager.expiry_scans();

        manager.record_source_read();
        for _ in 0..20 {
            manager.record_source_unreadable();
            manager.entries_due();
            manager.send_refused("any");
        }

        assert_eq!(manager.expiry_scans(), before, "{scenario}: no scan");
    }
}

// ---------------------------------------------------------------------------
// Through the source: what the reconcile feeds it
// ---------------------------------------------------------------------------

/// An HTTP endpoint whose answer a test switches: a body, or a dropped
/// connection.
struct Switchable {
    base: String,
    body: Arc<Mutex<Option<String>>>,
}

async fn switchable(initial: Option<&str>) -> Switchable {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    let body = Arc::new(Mutex::new(initial.map(str::to_string)));
    let shared = Arc::clone(&body);
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let mut buffer = vec![0u8; 8192];
            let _ = stream.read(&mut buffer).await;
            let answer = shared.lock().ok().and_then(|body| body.clone());
            if let Some(body) = answer {
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            }
            let _ = stream.shutdown().await;
        }
    });
    Switchable { base, body }
}

impl Switchable {
    fn serve(&self, body: Option<&str>) {
        *self.body.lock().expect("lock") = body.map(str::to_string);
    }

    fn source(&self) -> RegistrantSource {
        RegistrantSource::Http(
            HttpSource::new(crate::config::RegistrantHttpConfig {
                url: format!("{}/trunks", self.base),
                refresh_secs: 30,
                timeout_ms: 1000,
                auth_header: None,
                lookup_url: None,
            })
            .expect("the HTTP client builds"),
        )
    }
}

fn list(hold: &str) -> String {
    format!(
        r#"{{"registrants":[{{"aor":"{AOR}","registrar":"sip:198.51.100.10:5060","username":"u","password":"p"{hold}}}]}}"#
    )
}

#[tokio::test]
async fn a_row_with_hold_secs_gives_its_entry_the_hold() {
    let endpoint = switchable(Some(&list(r#","hold_secs":45"#))).await;
    let manager = Arc::new(test_support::manager());

    let report = reconcile_once(&manager, &endpoint.source())
        .await
        .expect("a pass");

    assert_eq!(report.added, 1);
    assert_eq!(manager.entries.get(AOR).expect("added").hold_secs, Some(45));
}

/// The row's `hold_secs` is not part of what is registered, so changing it
/// alone must not re-REGISTER: same Call-ID, same state, same schedule.
#[tokio::test]
async fn a_change_of_hold_secs_alone_forces_no_refresh() {
    let endpoint = switchable(Some(&list(r#","hold_secs":45"#))).await;
    let manager = Arc::new(test_support::manager());
    let source = endpoint.source();
    reconcile_once(&manager, &source).await.expect("a pass");
    manager.handle_success(AOR, 3600);
    let (call_id, next_attempt) = {
        let entry = manager.entries.get(AOR).expect("added");
        (entry.call_id.clone(), entry.next_attempt)
    };

    endpoint.serve(Some(&list(r#","hold_secs":120"#)));
    let report = reconcile_once(&manager, &source).await.expect("a pass");
    assert_eq!(report, ReconcileReport::default(), "no update, no removal");
    {
        let entry = manager.entries.get(AOR).expect("kept");
        assert_eq!(entry.hold_secs, Some(120), "the hold follows the row");
        assert_eq!(entry.call_id, call_id);
        assert_eq!(entry.state, RegistrantState::Registered);
        assert_eq!(entry.next_attempt, next_attempt, "not made due");
    }

    // Dropping it altogether is a change of hold too.
    endpoint.serve(Some(&list("")));
    let report = reconcile_once(&manager, &source).await.expect("a pass");
    assert_eq!(report, ReconcileReport::default());
    assert_eq!(manager.entries.get(AOR).expect("kept").hold_secs, None);
}

/// A failed read reaches the stand-down through `reconcile_once`, which both
/// the loop and `POST /admin/registrants/refresh` run.
#[tokio::test]
async fn a_failed_read_stands_a_zero_hold_entry_down_and_a_good_one_brings_it_back() {
    let endpoint = switchable(Some(&list(r#","hold_secs":0"#))).await;
    let manager = Arc::new(test_support::manager());
    let source = endpoint.source();

    reconcile_once(&manager, &source).await.expect("a pass");
    assert_eq!(manager.len(), 1, "a readable source holds nothing back");
    let first_call_id = test_support::call_id(&manager, AOR).expect("added");

    endpoint.serve(None);
    reconcile_once(&manager, &source)
        .await
        .expect_err("the source is unreadable");
    nothing_is_left_behind(&manager);

    // The controller is back and serves the row again: a fresh registration.
    endpoint.serve(Some(&list(r#","hold_secs":0"#)));
    let report = reconcile_once(&manager, &source).await.expect("a pass");
    assert_eq!(report.added, 1);
    let entry = manager.entries.get(AOR).expect("added afresh");
    assert_ne!(entry.call_id, first_call_id, "a new registration");
    assert_eq!(entry.state, RegistrantState::Unregistered);
}

/// A row without `hold_secs` is held to nothing, however long the outage.
#[tokio::test]
async fn a_failed_read_leaves_an_entry_without_a_hold_alone() {
    let endpoint = switchable(Some(&list(""))).await;
    let manager = Arc::new(test_support::manager());
    let source = endpoint.source();
    reconcile_once(&manager, &source).await.expect("a pass");

    endpoint.serve(None);
    reconcile_once(&manager, &source)
        .await
        .expect_err("the source is unreadable");

    assert_eq!(manager.len(), 1);
}

#[test]
fn the_row_parses_hold_secs_present_absent_and_zero() {
    let parse = |extra: &str| -> RegistrantRow {
        serde_json::from_str(&format!(
            r#"{{"aor":"{AOR}","registrar":"sip:r.example","username":"u","password":"p"{extra}}}"#
        ))
        .expect("parses")
    };
    assert_eq!(parse("").hold_secs, None);
    assert_eq!(parse(r#","hold_secs":null"#).hold_secs, None);
    assert_eq!(parse(r#","hold_secs":90"#).hold_secs, Some(90));
    assert_eq!(parse(r#","hold_secs":0"#).hold_secs, Some(0));
}
