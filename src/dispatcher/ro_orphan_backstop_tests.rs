use super::*;

fn store_with_call() -> (CallActorStore, String) {
    let store = CallActorStore::new();
    let call_id = store.create_call(Leg::new_a_leg(
        "call-1@192.0.2.1".to_string(),
        "tag-a".to_string(),
        "z9hG4bK-a".to_string(),
        LegTransport {
            remote_addr: "192.0.2.1:5060".parse().unwrap(),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: None,
        },
    ));
    (store, call_id)
}

/// A reservation whose call is still up must never be reaped.
///
/// This is the dangerous direction: the backstop terminates credit control,
/// so a mis-recovered key would cut charging on calls that are still
/// connected — a far worse failure than the leak it exists to close.
#[test]
fn a_live_calls_reservation_is_never_an_orphan() {
    let (call_actors, call_id) = store_with_call();
    let ro_sessions: DashMap<String, ()> = DashMap::new();
    ro_sessions.insert(ro_b2bua_key(&call_id), ());

    assert!(
        orphaned_ro_session_keys(&ro_sessions, &call_actors).is_empty(),
        "the call is still in the store — its reservation is live, not orphaned"
    );
}

/// The leak this closes: a terminal path removed the call and left the
/// reservation behind. Nothing else can release it, so the backstop must
/// find it, and removing what it finds must drain the store to empty.
#[test]
fn a_reservation_left_behind_by_a_teardown_is_found_and_drains_the_store() {
    let (call_actors, call_id) = store_with_call();
    let ro_sessions: DashMap<String, ()> = DashMap::new();
    ro_sessions.insert(ro_b2bua_key(&call_id), ());

    call_actors.remove_call(&call_id);

    let orphans = orphaned_ro_session_keys(&ro_sessions, &call_actors);
    assert_eq!(orphans, vec![ro_b2bua_key(&call_id)]);

    for key in orphans {
        ro_sessions.remove(&key);
    }
    assert!(
        ro_sessions.is_empty(),
        "ro_sessions must be empty once the call it was reserved for is gone"
    );
}

/// Live and gone must be separated within a single pass, not all-or-nothing.
#[test]
fn only_the_gone_calls_reservation_is_reaped() {
    let (call_actors, live_call) = store_with_call();
    let gone_call = call_actors.create_call(Leg::new_a_leg(
        "call-2@192.0.2.2".to_string(),
        "tag-b".to_string(),
        "z9hG4bK-b".to_string(),
        LegTransport {
            remote_addr: "192.0.2.2:5060".parse().unwrap(),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: None,
        },
    ));
    let ro_sessions: DashMap<String, ()> = DashMap::new();
    ro_sessions.insert(ro_b2bua_key(&live_call), ());
    ro_sessions.insert(ro_b2bua_key(&gone_call), ());

    call_actors.remove_call(&gone_call);

    assert_eq!(
        orphaned_ro_session_keys(&ro_sessions, &call_actors),
        vec![ro_b2bua_key(&gone_call)]
    );
}

/// A session filed under any other prefix is not a B2BUA call's, so the
/// call store has no opinion on it and the backstop must not reap it
/// against one. Guards a future non-B2BUA Ro user of the same map.
#[test]
fn a_session_that_is_not_a_b2bua_calls_is_left_alone() {
    let (call_actors, call_id) = store_with_call();
    call_actors.remove_call(&call_id);

    let ro_sessions: DashMap<String, ()> = DashMap::new();
    ro_sessions.insert(format!("ro-sms:{call_id}"), ());
    ro_sessions.insert(call_id.clone(), ());

    assert!(
        orphaned_ro_session_keys(&ro_sessions, &call_actors).is_empty(),
        "neither key carries the B2BUA prefix, so neither names a call actor"
    );
}

/// The prefix is written by one function and read back by another; a change
/// to either that does not change the other silently turns every live
/// reservation into an orphan.
#[test]
fn the_key_written_is_the_key_read_back() {
    let key = ro_b2bua_key("abc-123");
    assert_eq!(key.strip_prefix(RO_B2BUA_KEY_PREFIX), Some("abc-123"));
}
