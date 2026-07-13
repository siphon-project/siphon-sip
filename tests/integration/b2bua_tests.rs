//! Integration tests for B2BUA functionality.
//!
//! Tests cross-module interactions: dialog store management during B2BUA call flows,
//! registrar lookups for routing B2BUA calls, and transaction key handling.

use siphon::b2bua::actor::{
    CallActor, CallActorStore, CallEvent, CallState, Leg, LegActor, TransportInfo,
    SessionTimerState, generate_call_id, generate_tag,
};
use siphon::b2bua::header_policy::{
    apply_to_request, apply_to_response, builtin_presets, validate_preset,
    DirectionPolicy, HeaderPattern, PolicyContext, Preset, PresetError,
    ResolvedPolicy, RewriteOp, Verb,
};
use siphon::sip::message::SipMessage;
use siphon::sip::parser::parse_sip_message;
use siphon::dialog::{Dialog, DialogId, DialogStore, DialogState};
use siphon::registrar::Registrar;
use siphon::sip::builder::SipMessageBuilder;
use siphon::sip::uri::SipUri;
use siphon::sip::message::Method;
use siphon::transaction::key::TransactionKey;
use siphon::transport::{ConnectionId, Transport};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------------------
// B2BUA two-leg dialog management
// ---------------------------------------------------------------------------

#[test]
fn b2bua_two_leg_dialog_correlation() {
    let store = DialogStore::new();

    // Leg A: caller → B2BUA (UAS perspective)
    let leg_a = Dialog::new_uas(
        "b2bua-call-001".to_string(),
        "b2bua-tag-a".to_string(),
        "caller-tag".to_string(),
        1,
        vec![],
        Some(SipUri::new("caller.example.com".to_string()).with_user("alice".to_string())),
        Some(SipUri::new("b2bua.example.com".to_string())),
        Some(SipUri::new("caller.example.com".to_string()).with_user("alice".to_string())),
    );
    let leg_a_id = leg_a.id.clone();
    store.insert(leg_a);

    // Leg B: B2BUA → callee (UAC perspective)
    let leg_b = Dialog::new_uac(
        "b2bua-call-001-leg-b".to_string(),
        "b2bua-tag-b".to_string(),
        "callee-tag".to_string(),
        1,
        vec![],
        Some(SipUri::new("10.0.0.50".to_string()).with_user("bob".to_string()).with_port(5060)),
        Some(SipUri::new("b2bua.example.com".to_string())),
        Some(SipUri::new("biloxi.com".to_string()).with_user("bob".to_string())),
    );
    let leg_b_id = leg_b.id.clone();
    store.insert(leg_b);

    assert_eq!(store.count(), 2);
    assert_eq!(store.confirmed_count(), 0);

    // Callee answers (200 OK on leg B) → confirm both legs
    assert!(store.confirm(&leg_b_id));
    assert!(store.confirm(&leg_a_id));
    assert_eq!(store.confirmed_count(), 2);

    // BYE on leg A → terminate both legs
    store.terminate(&leg_a_id);
    store.terminate(&leg_b_id);
    assert_eq!(store.count(), 0);
}

// ---------------------------------------------------------------------------
// B2BUA routing: registrar lookup drives leg-B destination
// ---------------------------------------------------------------------------

#[test]
fn b2bua_routes_to_registered_contact() {
    let registrar = Registrar::default();

    // Bob registers from his device
    registrar
        .save(
            "sip:bob@example.com",
            SipUri::new("10.0.0.50".to_string())
                .with_user("bob".to_string())
                .with_port(5060),
            3600,
            1.0,
            "bob-reg-001".into(),
            1,
        )
        .unwrap();

    // B2BUA receives INVITE for bob@example.com — look up where to send leg B
    let contacts = registrar.lookup("sip:bob@example.com");
    assert_eq!(contacts.len(), 1);

    // Use the contact URI as the leg-B target
    let target = &contacts[0].uri;
    assert_eq!(target.user.as_deref(), Some("bob"));
    assert_eq!(target.host, "10.0.0.50");
    assert_eq!(target.port, Some(5060));

    // Create the leg-B dialog toward the registered contact
    let store = DialogStore::new();
    let leg_b = Dialog::new_uac(
        "b2bua-route-001".to_string(),
        "b2bua-tag".to_string(),
        String::new(), // remote tag not yet known (will come in response)
        1,
        vec![],
        Some(target.clone()),
        None,
        None,
    );
    store.insert(leg_b);
    assert_eq!(store.count(), 1);
}

// ---------------------------------------------------------------------------
// B2BUA generates separate transaction keys per leg
// ---------------------------------------------------------------------------

#[test]
fn b2bua_legs_have_independent_transaction_keys() {
    // Leg A: incoming INVITE
    let leg_a_branch = TransactionKey::generate_branch();
    let leg_a_key = TransactionKey::new(leg_a_branch.clone(), Method::Invite, "10.0.0.1:5060".to_string());

    // Leg B: outgoing INVITE (B2BUA generates a new branch)
    let leg_b_branch = TransactionKey::generate_branch();
    let leg_b_key = TransactionKey::new(leg_b_branch.clone(), Method::Invite, "10.0.0.2:5060".to_string());

    // The two legs must have different transaction keys
    assert_ne!(leg_a_key, leg_b_key);
    assert_ne!(leg_a_branch, leg_b_branch);

    // Both branches are valid RFC 3261 branches
    assert!(TransactionKey::is_rfc3261_branch(&leg_a_branch));
    assert!(TransactionKey::is_rfc3261_branch(&leg_b_branch));
}

// ---------------------------------------------------------------------------
// B2BUA deregistration during active call
// ---------------------------------------------------------------------------

#[test]
fn deregister_during_active_b2bua_call() {
    let registrar = Registrar::default();
    let dialog_store = DialogStore::new();

    // Register bob
    registrar
        .save(
            "sip:bob@example.com",
            SipUri::new("10.0.0.50".to_string()).with_user("bob".to_string()),
            3600,
            1.0,
            "bob-reg".into(),
            1,
        )
        .unwrap();

    // Establish a B2BUA call to bob
    let dialog = Dialog::new_uac(
        "active-call-001".to_string(),
        "b2bua".to_string(),
        "bob-resp".to_string(),
        1,
        vec![],
        Some(SipUri::new("10.0.0.50".to_string()).with_user("bob".to_string())),
        None,
        None,
    );
    let dialog_id = dialog.id.clone();
    dialog_store.insert(dialog);
    dialog_store.confirm(&dialog_id);

    // Bob deregisters (Expires=0) while call is active
    registrar
        .save(
            "sip:bob@example.com",
            SipUri::new("10.0.0.50".to_string()).with_user("bob".to_string()),
            0,
            1.0,
            "bob-reg".into(),
            2,
        )
        .unwrap();

    // Bob is no longer registered
    assert!(!registrar.is_registered("sip:bob@example.com"));

    // But the active dialog is still intact (registration and dialogs are independent)
    assert_eq!(dialog_store.count(), 1);
    assert_eq!(dialog_store.confirmed_count(), 1);
    let active = dialog_store.get(&dialog_id).unwrap();
    assert_eq!(active.state, DialogState::Confirmed);
}

// ---------------------------------------------------------------------------
// Dialog ID reversal for B2BUA perspective switching
// ---------------------------------------------------------------------------

#[test]
fn dialog_id_reversal_for_perspective_switch() {
    let caller_perspective = DialogId::new(
        "call-perspective-001".to_string(),
        "caller-tag".to_string(),
        "b2bua-tag".to_string(),
    );

    let b2bua_perspective = caller_perspective.reversed();
    assert_eq!(b2bua_perspective.local_tag, "b2bua-tag");
    assert_eq!(b2bua_perspective.remote_tag, "caller-tag");
    assert_eq!(b2bua_perspective.call_id, "call-perspective-001");

    // Double reversal returns to original
    let back = b2bua_perspective.reversed();
    assert_eq!(back, caller_perspective);
}

// ---------------------------------------------------------------------------
// B2BUA full call flow: INVITE → 180 → 200 → BYE
// ---------------------------------------------------------------------------

fn make_a_leg(call_id: &str) -> Leg {
    Leg::new_a_leg(
        call_id.to_string(),
        "alice-tag".to_string(),
        "z9hG4bK-aleg".to_string(),
        TransportInfo {
            remote_addr: "10.0.0.1:5060".parse().unwrap(),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: None,
        },
    )
}

fn make_b_leg(target: &str) -> Leg {
    let addr: SocketAddr = target.parse().unwrap_or("10.0.0.2:5060".parse().unwrap());
    Leg::new_b_leg(
        generate_call_id(),
        generate_tag(),
        format!("sip:bob@{}", target),
        TransactionKey::generate_branch(),
        TransportInfo {
            remote_addr: addr,
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: None,
        },
    )
}

#[test]
fn b2bua_full_call_lifecycle() {
    let store = CallActorStore::new();

    // 1. INVITE arrives → create call
    let a_leg = make_a_leg("call-lifecycle@test");
    let call_id = store.create_call(a_leg);
    assert_eq!(store.count(), 1);
    {
        let call = store.get_call(&call_id).unwrap();
        assert_eq!(call.state, CallState::Calling);
    }

    // 2. Script dials → add B-leg
    let b_leg = make_b_leg("10.0.0.2:5060");
    let b_branch = b_leg.branch.clone();
    store.add_b_leg(&call_id, b_leg);
    assert_eq!(store.call_id_for_branch(&b_branch), Some(call_id.clone()));

    // 3. B-leg sends 180 Ringing → state changes to Ringing
    store.set_state(&call_id, CallState::Ringing);
    {
        let call = store.get_call(&call_id).unwrap();
        assert_eq!(call.state, CallState::Ringing);
    }

    // 4. B-leg sends 200 OK → call answered, winner set
    store.set_winner(&call_id, 0);
    {
        let call = store.get_call(&call_id).unwrap();
        assert_eq!(call.state, CallState::Answered);
        assert_eq!(call.winner, Some(0));
    }

    // 5. BYE received → terminate and cleanup
    store.set_state(&call_id, CallState::Terminated);
    store.remove_call(&call_id);
    assert_eq!(store.count(), 0);
    assert!(store.call_id_for_branch(&b_branch).is_none());
}

// ---------------------------------------------------------------------------
// B2BUA auth/422 retry supersede: the retry INVITE must replace the failed
// B-leg in place, not append a second leg. Otherwise a caller CANCEL during
// alerting fans out to the dead pre-auth transaction too (→ a spurious 481,
// RFC 3261 §9.1) on top of the live one.
// ---------------------------------------------------------------------------

#[test]
fn b2bua_auth_retry_supersedes_failed_leg_for_single_cancel() {
    let store = CallActorStore::new();
    let call_id = store.create_call(make_a_leg("b2b-supersede@test"));

    // CSeq-1 INVITE (no creds) went out and drew a 401. Its leg carries the
    // pre-auth INVITE, stashed so a CANCEL can be rebuilt from it.
    let cseq1 = concat!(
        "INVITE sip:bob@10.0.0.2:5060 SIP/2.0\r\n",
        "Via: SIP/2.0/UDP 10.0.0.9:5060;branch=z9hG4bK-cseq1-687e\r\n",
        "Max-Forwards: 70\r\n",
        "From: <sip:alice@10.0.0.1>;tag=alice-tag\r\n",
        "To: <sip:bob@10.0.0.2>\r\n",
        "Call-ID: b2b-supersede@test\r\n",
        "CSeq: 1 INVITE\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    );
    let cseq1_invite = parse_sip_message(cseq1).expect("cseq1 fixture parses").1;
    let mut leg1 = Leg::new_b_leg(
        generate_call_id(),
        generate_tag(),
        "sip:bob@10.0.0.2:5060".to_string(),
        "z9hG4bK-cseq1-687e".to_string(),
        TransportInfo {
            remote_addr: "10.0.0.2:5060".parse().unwrap(),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: None,
        },
    );
    leg1.b_leg_invite = Some(Arc::new(Mutex::new(cseq1_invite)));
    store.add_b_leg(&call_id, leg1);
    assert_eq!(
        store.call_id_for_branch("z9hG4bK-cseq1-687e"),
        Some(call_id.clone())
    );

    // The 401 retry: same dialog, new branch + CSeq, Authorization added. It
    // supersedes the failed leg in place at index 0 (what the dispatcher does
    // via replace_b_leg + spawn_b_leg_actor_at).
    let cseq2 = concat!(
        "INVITE sip:bob@10.0.0.2:5060 SIP/2.0\r\n",
        "Via: SIP/2.0/UDP 10.0.0.9:5060;branch=z9hG4bK-cseq2-4a39\r\n",
        "Max-Forwards: 70\r\n",
        "From: <sip:alice@10.0.0.1>;tag=alice-tag\r\n",
        "To: <sip:bob@10.0.0.2>\r\n",
        "Call-ID: b2b-supersede@test\r\n",
        "CSeq: 2 INVITE\r\n",
        "Authorization: Digest username=\"alice\", realm=\"trunk\", nonce=\"abc\"\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    );
    let cseq2_invite = parse_sip_message(cseq2).expect("cseq2 fixture parses").1;
    let mut leg2 = Leg::new_b_leg(
        generate_call_id(),
        generate_tag(),
        "sip:bob@10.0.0.2:5060".to_string(),
        "z9hG4bK-cseq2-4a39".to_string(),
        TransportInfo {
            remote_addr: "10.0.0.2:5060".parse().unwrap(),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: None,
        },
    );
    leg2.b_leg_invite = Some(Arc::new(Mutex::new(cseq2_invite)));
    assert!(store.replace_b_leg(&call_id, 0, leg2));

    // The dead pre-auth branch no longer routes; the retry branch does.
    assert!(store.call_id_for_branch("z9hG4bK-cseq1-687e").is_none());
    assert_eq!(
        store.call_id_for_branch("z9hG4bK-cseq2-4a39"),
        Some(call_id.clone())
    );

    // Single-CANCEL invariant: handle_b2bua_cancel builds one CANCEL per leg
    // that carries a stashed b_leg_invite. Exactly one such leg must remain,
    // on the live CSeq-2 branch — never the dead CSeq-1 one.
    let call = store.get_call(&call_id).expect("call exists");
    let cancelable_vias: Vec<String> = call
        .b_legs
        .iter()
        .filter_map(|leg| leg.b_leg_invite.as_ref())
        .map(|invite| {
            invite
                .lock()
                .unwrap()
                .headers
                .get("Via")
                .cloned()
                .unwrap_or_default()
        })
        .collect();
    assert_eq!(call.b_legs.len(), 1, "retry must supersede, not append");
    assert_eq!(
        cancelable_vias.len(),
        1,
        "exactly one CANCEL would be sent"
    );
    assert!(
        cancelable_vias[0].contains("z9hG4bK-cseq2-4a39"),
        "the single CANCEL must target the live CSeq-2 branch, got: {}",
        cancelable_vias[0]
    );
    assert!(
        !cancelable_vias[0].contains("z9hG4bK-cseq1-687e"),
        "no CANCEL must target the dead CSeq-1 branch"
    );
}

// ---------------------------------------------------------------------------
// B2BUA error propagation: B-leg failure → call cleanup
// ---------------------------------------------------------------------------

#[test]
fn b2bua_error_propagation() {
    let store = CallActorStore::new();

    let call_id = store.create_call(make_a_leg("call-error@test"));
    let b_leg = make_b_leg("10.0.0.2:5060");
    let b_branch = b_leg.branch.clone();
    store.add_b_leg(&call_id, b_leg);

    // B-leg returns 486 Busy Here → remove call
    {
        let call = store.get_call(&call_id).unwrap();
        assert_eq!(call.state, CallState::Calling);
    }
    store.remove_call(&call_id);
    assert_eq!(store.count(), 0);
    assert!(store.call_id_for_branch(&b_branch).is_none());
}

// ---------------------------------------------------------------------------
// B2BUA BYE bridging: A→B and B→A
// ---------------------------------------------------------------------------

#[test]
fn b2bua_bye_from_a_leg_bridges_to_b_leg() {
    let store = CallActorStore::new();

    let a_leg = make_a_leg("call-bye-a@test");
    let call_id = store.create_call(a_leg);
    let b_leg = make_b_leg("10.0.0.2:5060");
    let b_destination = b_leg.transport.remote_addr;
    store.add_b_leg(&call_id, b_leg);
    store.set_winner(&call_id, 0);

    // BYE from A-leg (source matches a_leg transport addr)
    let call = store.get_call(&call_id).unwrap();
    let from_a = call.a_leg.transport.remote_addr == "10.0.0.1:5060".parse::<SocketAddr>().unwrap();
    assert!(from_a);

    // Verify we can find the B-leg winner to forward BYE to
    assert_eq!(call.winner, Some(0));
    assert_eq!(call.b_legs[0].transport.remote_addr, b_destination);
    drop(call);

    store.set_state(&call_id, CallState::Terminated);
    store.remove_call(&call_id);
    assert_eq!(store.count(), 0);
}

#[test]
fn b2bua_bye_from_b_leg_bridges_to_a_leg() {
    let store = CallActorStore::new();

    let a_leg = make_a_leg("call-bye-b@test");
    let a_source = a_leg.transport.remote_addr;
    let call_id = store.create_call(a_leg);
    store.add_b_leg(&call_id, make_b_leg("10.0.0.2:5060"));
    store.set_winner(&call_id, 0);

    // BYE from B-leg (source is NOT a_leg transport addr)
    let b_leg_source: SocketAddr = "10.0.0.2:5060".parse().unwrap();
    let call = store.get_call(&call_id).unwrap();
    let from_a = b_leg_source == call.a_leg.transport.remote_addr;
    assert!(!from_a); // This is from B-leg

    // Forward to A-leg
    assert_eq!(call.a_leg.transport.remote_addr, a_source);
    drop(call);

    store.set_state(&call_id, CallState::Terminated);
    store.remove_call(&call_id);
    assert_eq!(store.count(), 0);
}

// ---------------------------------------------------------------------------
// B2BUA imperative terminate (b2bua.terminate) — UAS single-leg precondition
// ---------------------------------------------------------------------------

#[test]
fn uas_single_leg_call_is_resolvable_by_sip_call_id_for_terminate() {
    // A UAS-mode IVR/echo call (call.answer, no dial) has only an A-leg — no
    // B-leg, no winner. b2bua.terminate(call_id) resolves the SIP Call-ID
    // (which is what @rtpengine.on_dtmf carries) to the internal call, then
    // BYEs every present leg; "both legs" degrades to just the A-leg here.
    let store = CallActorStore::new();
    let sip_call_id = "ivr-echo@test";
    let call_id = store.create_call(make_a_leg(sip_call_id));

    // The SIP Call-ID resolves to the internal call id.
    assert_eq!(store.find_by_sip_call_id(sip_call_id), Some(call_id.clone()));

    let call = store.get_call(&call_id).unwrap();
    // Single-leg UAS call: no B-leg / winner.
    assert!(call.winner.is_none());
    assert!(call.b_legs.is_empty());
    // The A-leg dialog carries the local_tag that the UAS 200 OK put in its To
    // header (Change A), so a siphon-originated BYE's From-tag matches the
    // caller's dialog. build_b2bua_bye reads exactly this local_tag +
    // remote_tag, so both must be present for the BYE to be accepted (not 481).
    assert!(!call.a_leg.dialog.local_tag.is_empty());
    assert_eq!(call.a_leg.dialog.remote_tag.as_deref(), Some("alice-tag"));
    drop(call);

    // An unknown SIP Call-ID does not resolve — the imperative terminate returns
    // false (clean no-op) for it.
    assert!(store.find_by_sip_call_id("not-a-call@test").is_none());
}

#[test]
fn uas_imperative_answer_marks_answered_and_keeps_actor_alive() {
    // call.answer() sends the 2xx imperatively then marks the call Answered via
    // CallAction::Answered so the dispatcher keeps the actor alive (instead of
    // removing it as a no-action silent drop). Model that at the store level:
    // set_state(Answered) leaves the actor resolvable, and the A-leg dialog
    // carries the local_tag the 2xx To header is stamped with.
    let store = CallActorStore::new();
    let sip_call_id = "ivr-answer@test";
    let call_id = store.create_call(make_a_leg(sip_call_id));

    let local_tag = {
        let call = store.get_call(&call_id).unwrap();
        assert_eq!(call.state, CallState::Calling);
        assert!(!call.a_leg.dialog.local_tag.is_empty());
        call.a_leg.dialog.local_tag.clone()
    };

    store.set_state(&call_id, CallState::Answered);

    let call = store.get_call(&call_id).unwrap();
    assert_eq!(call.state, CallState::Answered);
    // Still a single-leg UAS call; the actor persists so @b2bua.on_bye /
    // b2bua.terminate can reach it, and the dialog tag is stable.
    assert!(call.winner.is_none());
    assert_eq!(call.a_leg.dialog.local_tag, local_tag);
    drop(call);
    assert_eq!(store.count(), 1);
}

// ---------------------------------------------------------------------------
// B2BUA CANCEL: A-leg CANCEL → cancel B-legs
// ---------------------------------------------------------------------------

#[test]
fn b2bua_cancel_removes_call() {
    let store = CallActorStore::new();

    let call_id = store.create_call(make_a_leg("call-cancel@test"));
    let b_leg = make_b_leg("10.0.0.2:5060");
    store.add_b_leg(&call_id, b_leg);

    // Call is in Calling state — CANCEL should terminate it
    {
        let call = store.get_call(&call_id).unwrap();
        assert_eq!(call.state, CallState::Calling);
    }

    // CANCEL → set terminated, remove
    store.set_state(&call_id, CallState::Terminated);
    store.remove_call(&call_id);
    assert_eq!(store.count(), 0);
}

#[test]
fn b2bua_cancel_ignored_after_answer() {
    let store = CallActorStore::new();

    let call_id = store.create_call(make_a_leg("call-cancel-late@test"));
    store.add_b_leg(&call_id, make_b_leg("10.0.0.2:5060"));
    store.set_winner(&call_id, 0);

    // Call is Answered — CANCEL should not change state
    {
        let call = store.get_call(&call_id).unwrap();
        assert_eq!(call.state, CallState::Answered);
    }

    // In B2BUA, CANCEL after answer: we return 200 OK to CANCEL but don't terminate
    // (the actual call termination comes via BYE)
}

// ---------------------------------------------------------------------------
// B2BUA multi-leg forking
// ---------------------------------------------------------------------------

#[test]
fn b2bua_multi_leg_forking() {
    let store = CallActorStore::new();
    let call_id = store.create_call(make_a_leg("call-fork@test"));

    // Fork to 3 B-legs
    for i in 0..3 {
        let b_leg = Leg::new_b_leg(
            generate_call_id(),
            generate_tag(),
            format!("sip:bob@10.0.0.{}", i + 2),
            TransactionKey::generate_branch(),
            TransportInfo {
                remote_addr: format!("10.0.0.{}:5060", i + 2).parse().unwrap(),
                connection_id: ConnectionId::default(),
                transport: Transport::Udp,
                local_addr: None,
            },
        );
        store.add_b_leg(&call_id, b_leg);
    }

    {
        let call = store.get_call(&call_id).unwrap();
        assert_eq!(call.b_legs.len(), 3);
    }

    // Second B-leg answers first
    store.set_winner(&call_id, 1);
    {
        let call = store.get_call(&call_id).unwrap();
        assert_eq!(call.winner, Some(1));
        assert_eq!(call.state, CallState::Answered);
    }

    // Cleanup
    store.remove_call(&call_id);
    assert_eq!(store.count(), 0);
}

// ---------------------------------------------------------------------------
// Transaction key for CANCEL has same branch, different method
// ---------------------------------------------------------------------------

#[test]
fn cancel_transaction_key_differs_from_invite() {
    let branch = TransactionKey::generate_branch();
    let invite_key = TransactionKey::new(branch.clone(), Method::Invite, "10.0.0.1:5060".to_string());
    let cancel_key = TransactionKey::new(branch.clone(), Method::Cancel, "10.0.0.1:5060".to_string());

    // CANCEL creates its own transaction (same branch but different method)
    assert_ne!(invite_key, cancel_key);
    assert_eq!(invite_key.branch, cancel_key.branch);
}

// ---------------------------------------------------------------------------
// Transaction layer: client transaction lifecycle
// ---------------------------------------------------------------------------

#[test]
fn client_transaction_lifecycle_options() {
    use siphon::transaction::TransactionManager;
    use siphon::transaction::state::{Transport as TxnTransport, Action, TimerName};
    use siphon::transaction::{ClientEvent};
    use siphon::transaction::state::NictEvent;

    let manager = TransactionManager::default();

    let request = SipMessageBuilder::new()
        .request(Method::Options, SipUri::new("example.com".to_string()))
        .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-opts-txn".to_string())
        .to("<sip:example.com>".to_string())
        .from("<sip:user@example.com>;tag=abc".to_string())
        .call_id("txn-test-1".to_string())
        .cseq("1 OPTIONS".to_string())
        .content_length(0)
        .build()
        .unwrap();

    // Create client transaction
    let (key, actions) = manager.new_client_transaction(request, TxnTransport::Udp).unwrap();
    assert_eq!(manager.count(), 1);
    assert!(actions.iter().any(|a| matches!(a, Action::SendMessage(_))));
    assert!(actions.iter().any(|a| matches!(a, Action::StartTimer(TimerName::F, _))));
    assert!(actions.iter().any(|a| matches!(a, Action::StartTimer(TimerName::E, _))));

    // Receive 200 OK
    let response = SipMessageBuilder::new()
        .response(200, "OK".to_string())
        .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-opts-txn".to_string())
        .to("<sip:example.com>".to_string())
        .from("<sip:user@example.com>;tag=abc".to_string())
        .call_id("txn-test-1".to_string())
        .cseq("1 OPTIONS".to_string())
        .content_length(0)
        .build()
        .unwrap();

    let actions = manager.process_client_event(
        &key,
        ClientEvent::Nict(NictEvent::FinalResponse(response)),
    ).unwrap();
    assert!(actions.iter().any(|a| matches!(a, Action::PassToTu(_))));
    // UDP: enters Completed with Timer K, then terminates
}

#[test]
fn server_transaction_lifecycle_options() {
    use siphon::transaction::TransactionManager;
    use siphon::transaction::state::{Transport as TxnTransport, Action};
    use siphon::transaction::ServerEvent;
    use siphon::transaction::state::NistEvent;

    let manager = TransactionManager::default();

    let request = SipMessageBuilder::new()
        .request(Method::Options, SipUri::new("example.com".to_string()))
        .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-srv-opts".to_string())
        .to("<sip:example.com>".to_string())
        .from("<sip:user@example.com>;tag=abc".to_string())
        .call_id("srv-test-1".to_string())
        .cseq("1 OPTIONS".to_string())
        .content_length(0)
        .build()
        .unwrap();

    // Create server transaction
    let (key, actions) = manager.new_server_transaction(&request, TxnTransport::Udp).unwrap();
    assert_eq!(manager.count(), 1);
    assert!(actions.iter().any(|a| matches!(a, Action::PassToTu(_))));

    // TU sends 200 OK
    let response = SipMessageBuilder::new()
        .response(200, "OK".to_string())
        .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-srv-opts".to_string())
        .to("<sip:example.com>".to_string())
        .from("<sip:user@example.com>;tag=abc".to_string())
        .call_id("srv-test-1".to_string())
        .cseq("1 OPTIONS".to_string())
        .content_length(0)
        .build()
        .unwrap();

    let actions = manager.process_server_event(
        &key,
        ServerEvent::Nist(NistEvent::TuFinal(response)),
    ).unwrap();
    assert!(actions.iter().any(|a| matches!(a, Action::SendMessage(_))));
    // UDP NIST: enters Completed with Timer J (not immediately terminated)
}

// ---------------------------------------------------------------------------
// B2BUA A-leg INVITE storage for handler reconstruction
// ---------------------------------------------------------------------------

#[test]
fn b2bua_a_leg_invite_stored_and_available_through_lifecycle() {
    let store = CallActorStore::new();

    // Create call
    let a_leg = make_a_leg("call-invite-store@test");
    let call_id = store.create_call(a_leg);

    // Build and store an INVITE with SDP body
    let invite = SipMessageBuilder::new()
        .request(
            Method::Invite,
            SipUri::new("example.com".to_string()).with_user("bob".to_string()),
        )
        .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-store-test".to_string())
        .from("<sip:alice@atlanta.com>;tag=store-tag".to_string())
        .to("<sip:bob@example.com>".to_string())
        .call_id("call-invite-store@test".to_string())
        .cseq("1 INVITE".to_string())
        .content_length(0)
        .build()
        .unwrap();
    let invite_arc = Arc::new(Mutex::new(invite));
    store.set_a_leg_invite(&call_id, Arc::clone(&invite_arc));

    // Add B-leg, answer the call
    store.add_b_leg(&call_id, make_b_leg("10.0.0.2:5060"));
    store.set_winner(&call_id, 0);

    // A-leg INVITE should still be available after answer (for on_answer handler)
    {
        let call = store.get_call(&call_id).unwrap();
        assert_eq!(call.state, CallState::Answered);
        let stored_invite = call.a_leg_invite.as_ref().expect("a_leg_invite should be stored");
        let msg = stored_invite.lock().unwrap();
        assert_eq!(msg.headers.get("From").map(|s| s.contains("store-tag")), Some(true));
    }

    // A-leg INVITE should still be available at BYE time (for on_bye handler)
    store.set_state(&call_id, CallState::Terminated);
    {
        let call = store.get_call(&call_id).unwrap();
        assert!(call.a_leg_invite.is_some());
    }

    // After removal, everything is cleaned up
    store.remove_call(&call_id);
    assert_eq!(store.count(), 0);
}

// ---------------------------------------------------------------------------
// B2BUA media session store tracks call lifecycle
// ---------------------------------------------------------------------------

#[test]
fn media_session_store_lifecycle() {
    use siphon::rtpengine::session::{MediaSession, MediaSessionStore};
    let store = MediaSessionStore::new();

    // Offer: create session (from_tag known, to_tag not yet)
    let session = MediaSession {
        call_id: "media-lifecycle@test".to_string(),
        from_tag: "alice-tag".to_string(),
        to_tag: None,
        profile: "srtp_to_rtp".to_string(),
        created_at: std::time::Instant::now(),
    };
    store.insert(session);
    assert_eq!(store.len(), 1);

    // Answer: set to_tag
    store.set_to_tag("media-lifecycle@test", "bob-tag".to_string());
    {
        let session = store.get("media-lifecycle@test").unwrap();
        assert_eq!(session.to_tag.as_deref(), Some("bob-tag"));
    }

    // BYE: remove session
    let removed = store.remove("media-lifecycle@test");
    assert!(removed.is_some());
    assert_eq!(store.len(), 0);
}

// ---------------------------------------------------------------------------
// RFC 4028 Session timer tests
// ---------------------------------------------------------------------------

#[test]
fn session_timer_config_parsing() {
    use siphon::config::{Config, SessionRefresher};

    let yaml = r#"
listen:
  udp:
    - "0.0.0.0:5060"
domain:
  local:
    - "example.com"
script:
  path: "scripts/proxy_default.py"
session_timer:
  session_expires: 1800
  min_se: 90
  refresher: uac
  enabled: true
"#;
    let config = Config::from_str(yaml).unwrap();
    let timer = config.session_timer.unwrap();
    assert_eq!(timer.session_expires, 1800);
    assert_eq!(timer.min_se, 90);
    assert_eq!(timer.refresher, SessionRefresher::Uac);
    assert!(timer.enabled);
}

#[test]
fn session_timer_state_lifecycle() {
    let store = CallActorStore::new();
    let a_leg = make_a_leg("timer-lifecycle@test");
    let call_id = store.create_call(a_leg);

    // No timer initially
    {
        let call = store.get_call(&call_id).unwrap();
        assert!(call.session_timer.is_none());
    }

    // Add B-leg and set to Answered
    let b_leg = make_b_leg("10.0.0.2:5060");
    store.add_b_leg(&call_id, b_leg);
    store.set_winner(&call_id, 0);

    // Activate session timer (simulating 200 OK processing)
    let timer = SessionTimerState {
        session_expires: 1800,
        refresher: "b2bua".to_string(),
        last_refresh: std::time::Instant::now(),
    };
    store.set_session_timer(&call_id, timer);

    // Verify timer is active
    {
        let call = store.get_call(&call_id).unwrap();
        assert_eq!(call.state, CallState::Answered);
        let timer = call.session_timer.as_ref().unwrap();
        assert_eq!(timer.session_expires, 1800);
        assert_eq!(timer.refresher, "b2bua");
    }

    // Reset timer (simulating successful refresh)
    let before = {
        let call = store.get_call(&call_id).unwrap();
        call.session_timer.as_ref().unwrap().last_refresh
    };
    std::thread::sleep(std::time::Duration::from_millis(10));
    store.reset_session_timer(&call_id);
    let after = {
        let call = store.get_call(&call_id).unwrap();
        call.session_timer.as_ref().unwrap().last_refresh
    };
    assert!(after > before);

    // Remove call cleans up timer
    store.remove_call(&call_id);
    assert!(store.get_call(&call_id).is_none());
}


#[test]
fn session_timer_per_call_override_on_call_actor_store() {
    use siphon::script::api::call::SessionTimerOverride;

    let store = CallActorStore::new();
    let a_leg = make_a_leg("override-mgr@test");
    let call_id = store.create_call(a_leg);

    // Store override on the call
    if let Some(mut call_ref) = store.get_call_mut(&call_id) {
        call_ref.session_timer_override = Some(SessionTimerOverride {
            session_expires: 3600,
            min_se: 120,
            refresher: "uas".to_string(),
        });
    }

    // Verify override persists
    let call_ref = store.get_call(&call_id).unwrap();
    let stored = call_ref.session_timer_override.as_ref().unwrap();
    assert_eq!(stored.session_expires, 3600);
    assert_eq!(stored.min_se, 120);
    assert_eq!(stored.refresher, "uas");
}

// ---------------------------------------------------------------------------
// LegActor integration: remove_call terminates spawned actor tasks
// ---------------------------------------------------------------------------

#[tokio::test]
async fn remove_call_terminates_actor_tasks() {
    let store = CallActorStore::new();
    let a_leg = make_a_leg("actor-terminate@test");
    let call_id = store.create_call(a_leg);

    let (event_tx, _event_rx) = tokio::sync::mpsc::channel::<CallEvent>(64);
    if let Some(mut call) = store.get_call_mut(&call_id) {
        call.event_tx = Some(event_tx.clone());
    }

    // Spawn two B-leg actors
    let mut joins = Vec::new();
    for addr in &["10.0.0.2:5060", "10.0.0.3:5060"] {
        let b_leg = make_b_leg(addr);
        let b_leg_clone = b_leg.clone();
        store.add_b_leg(&call_id, b_leg);

        let (actor, handle) = LegActor::new(b_leg_clone, event_tx.clone());
        joins.push(tokio::spawn(actor.run()));

        let index = store.get_call(&call_id).unwrap().b_legs.len() - 1;
        if let Some(mut call) = store.get_call_mut(&call_id) {
            call.set_b_leg_handle(index, handle);
        }
    }

    // Actors should be running
    for join in &joins {
        assert!(!join.is_finished());
    }

    // remove_call sends Shutdown to all actor handles
    store.remove_call(&call_id);
    assert_eq!(store.count(), 0);

    // All actor tasks should terminate
    for join in joins {
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            join,
        ).await.expect("actor task did not terminate").unwrap();
    }
}

// ---------------------------------------------------------------------------
// B2BUA re-INVITE B-leg lifecycle (target_uri marking + cleanup)
// ---------------------------------------------------------------------------

#[test]
fn reinvite_b_leg_non2xx_removed() {
    // When a re-INVITE gets a non-2xx response (e.g. 491 Request Pending),
    // the re-INVITE B-leg entry should be removed after ACKing.
    let store = CallActorStore::new();

    let call_id = store.create_call(make_a_leg("reinvite-non2xx@test"));
    let b_leg = make_b_leg("10.0.0.2:5060");
    store.add_b_leg(&call_id, b_leg);
    store.set_winner(&call_id, 0);

    // Simulate a re-INVITE by adding a tracking B-leg entry
    let reinvite_branch = TransactionKey::generate_branch();
    let reinvite_leg = Leg::new_b_leg(
        generate_call_id(),
        generate_tag(),
        "reinvite:a2b".to_string(),
        reinvite_branch.clone(),
        TransportInfo {
            remote_addr: "10.0.0.2:5060".parse().unwrap(),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: None,
        },
    );
    store.add_b_leg(&call_id, reinvite_leg);

    // Verify re-INVITE entry exists at index 1
    {
        let call = store.get_call(&call_id).unwrap();
        assert_eq!(call.b_legs.len(), 2);
        assert_eq!(call.b_legs[1].dialog.target_uri.as_deref(), Some("reinvite:a2b"));
    }

    // Simulate non-2xx response → remove re-INVITE entry
    store.remove_b_leg(&call_id, 1);

    // Verify only the winning B-leg remains
    {
        let call = store.get_call(&call_id).unwrap();
        assert_eq!(call.b_legs.len(), 1);
        assert_eq!(call.winner, Some(0));
    }
}

#[test]
fn reinvite_b_leg_2xx_marked_done() {
    // When a re-INVITE gets a 2xx response, the B-leg entry should be
    // marked as "reinvite_done:" instead of removed, so retransmitted
    // 200 OKs can still be matched and re-ACKed.
    let store = CallActorStore::new();

    let call_id = store.create_call(make_a_leg("reinvite-2xx@test"));
    let b_leg = make_b_leg("10.0.0.2:5060");
    let b_branch = b_leg.branch.clone();
    store.add_b_leg(&call_id, b_leg);
    store.set_winner(&call_id, 0);

    // Simulate a re-INVITE tracking entry
    let reinvite_branch = TransactionKey::generate_branch();
    let reinvite_leg = Leg::new_b_leg(
        generate_call_id(),
        generate_tag(),
        "reinvite:b2a".to_string(),
        reinvite_branch.clone(),
        TransportInfo {
            remote_addr: "10.0.0.1:5060".parse().unwrap(),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: None,
        },
    );
    store.add_b_leg(&call_id, reinvite_leg);

    // Simulate 2xx response → mark as done (not removed)
    store.set_b_leg_target_uri(&call_id, 1, "reinvite_done:b2a".to_string());

    // Verify the entry still exists for retransmission matching
    {
        let call = store.get_call(&call_id).unwrap();
        assert_eq!(call.b_legs.len(), 2);
        assert_eq!(call.b_legs[1].dialog.target_uri.as_deref(), Some("reinvite_done:b2a"));
        assert_eq!(call.b_legs[1].branch, reinvite_branch);
    }

    // The branch should still be resolvable to the call
    assert_eq!(store.call_id_for_branch(&reinvite_branch), Some(call_id.clone()));

    // Winner index unaffected
    {
        let call = store.get_call(&call_id).unwrap();
        assert_eq!(call.winner, Some(0));
        assert_eq!(call.b_legs[0].branch, b_branch);
    }
}

#[test]
fn reinvite_done_entry_cleaned_on_call_removal() {
    // Marked "reinvite_done:" entries should be cleaned up when the call ends.
    let store = CallActorStore::new();

    let call_id = store.create_call(make_a_leg("reinvite-cleanup@test"));
    store.add_b_leg(&call_id, make_b_leg("10.0.0.2:5060"));
    store.set_winner(&call_id, 0);

    // Add and mark a re-INVITE entry as done
    let reinvite_branch = TransactionKey::generate_branch();
    let reinvite_leg = Leg::new_b_leg(
        generate_call_id(),
        generate_tag(),
        "reinvite:a2b".to_string(),
        reinvite_branch.clone(),
        TransportInfo {
            remote_addr: "10.0.0.2:5060".parse().unwrap(),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: None,
        },
    );
    store.add_b_leg(&call_id, reinvite_leg);
    store.set_b_leg_target_uri(&call_id, 1, "reinvite_done:a2b".to_string());

    // remove_call should clean up the call and move re-INVITE entries to zombie map
    let reinvite_sip_cid = {
        let call = store.get_call(&call_id).unwrap();
        call.b_legs[1].dialog.call_id.clone()
    };
    store.remove_call(&call_id);
    assert_eq!(store.count(), 0);
    assert!(store.call_id_for_branch(&reinvite_branch).is_none());
    // Zombie entry should exist for the re-INVITE B-leg
    let zombie = store.get_zombie_reinvite(&reinvite_sip_cid);
    assert!(zombie.is_some(), "reinvite_done entry should become a zombie");
    let zombie = zombie.unwrap();
    assert_eq!(zombie.destination, "10.0.0.2:5060".parse::<std::net::SocketAddr>().unwrap());
    assert_eq!(zombie.transport, Transport::Udp);
}

#[test]
fn zombie_reinvite_not_created_for_normal_bleg() {
    // Normal B-legs (no reinvite: prefix) should NOT create zombie entries.
    let store = CallActorStore::new();

    let call_id = store.create_call(make_a_leg("zombie-normal@test"));
    let normal_leg = make_b_leg("10.0.0.3:5060");
    let normal_cid = normal_leg.dialog.call_id.clone();
    store.add_b_leg(&call_id, normal_leg);

    store.remove_call(&call_id);
    assert!(store.get_zombie_reinvite(&normal_cid).is_none(),
        "normal B-leg should not create a zombie entry");
    assert!(store.zombie_reinvites.is_empty());
}

#[test]
fn zombie_reinvite_created_for_pending_reinvite() {
    // B-legs with "reinvite:" (not yet ACKed) should also become zombies.
    let store = CallActorStore::new();

    let call_id = store.create_call(make_a_leg("zombie-pending@test"));
    store.add_b_leg(&call_id, make_b_leg("10.0.0.2:5060"));
    store.set_winner(&call_id, 0);

    let reinvite_leg = Leg::new_b_leg(
        generate_call_id(),
        generate_tag(),
        "reinvite:b2a".to_string(),
        TransactionKey::generate_branch(),
        TransportInfo {
            remote_addr: "10.0.0.5:5060".parse().unwrap(),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: None,
        },
    );
    let reinvite_cid = reinvite_leg.dialog.call_id.clone();
    store.add_b_leg(&call_id, reinvite_leg);

    store.remove_call(&call_id);
    let zombie = store.get_zombie_reinvite(&reinvite_cid);
    assert!(zombie.is_some(), "pending reinvite entry should become a zombie");
    assert_eq!(zombie.unwrap().destination, "10.0.0.5:5060".parse::<std::net::SocketAddr>().unwrap());
}

#[test]
fn zombie_reinvite_manual_removal() {
    // Test manual removal of zombie entries.
    let store = CallActorStore::new();

    let call_id = store.create_call(make_a_leg("zombie-remove@test"));
    store.add_b_leg(&call_id, make_b_leg("10.0.0.2:5060"));
    store.set_winner(&call_id, 0);

    let reinvite_leg = Leg::new_b_leg(
        generate_call_id(),
        generate_tag(),
        "reinvite_done:a2b".to_string(),
        TransactionKey::generate_branch(),
        TransportInfo {
            remote_addr: "10.0.0.2:5060".parse().unwrap(),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: None,
        },
    );
    let reinvite_cid = reinvite_leg.dialog.call_id.clone();
    store.add_b_leg(&call_id, reinvite_leg);

    store.remove_call(&call_id);
    assert!(store.get_zombie_reinvite(&reinvite_cid).is_some());

    store.remove_zombie_reinvite(&reinvite_cid);
    assert!(store.get_zombie_reinvite(&reinvite_cid).is_none());
    assert!(store.zombie_reinvites.is_empty());
}

// ---------------------------------------------------------------------------
// B2BUA UPDATE B-leg lifecycle (RFC 3311 — bug fix: UPDATE was being silently
// dropped, leading to T1-backoff retransmits and 408 → BYE call drop)
// ---------------------------------------------------------------------------

#[test]
fn update_b_leg_non2xx_removed() {
    // Non-2xx UPDATE response → no ACK (RFC 3311 §5.4 — UPDATE is non-INVITE),
    // entry removed.
    let store = CallActorStore::new();

    let call_id = store.create_call(make_a_leg("update-non2xx@test"));
    store.add_b_leg(&call_id, make_b_leg("10.0.0.2:5060"));
    store.set_winner(&call_id, 0);

    let update_branch = TransactionKey::generate_branch();
    let update_leg = Leg::new_b_leg(
        generate_call_id(),
        generate_tag(),
        "update:a2b".to_string(),
        update_branch.clone(),
        TransportInfo {
            remote_addr: "10.0.0.2:5060".parse().unwrap(),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: None,
        },
    );
    store.add_b_leg(&call_id, update_leg);

    {
        let call = store.get_call(&call_id).unwrap();
        assert_eq!(call.b_legs.len(), 2);
        assert_eq!(call.b_legs[1].dialog.target_uri.as_deref(), Some("update:a2b"));
    }

    store.remove_b_leg(&call_id, 1);

    {
        let call = store.get_call(&call_id).unwrap();
        assert_eq!(call.b_legs.len(), 1);
        assert_eq!(call.winner, Some(0));
    }
    assert!(store.call_id_for_branch(&update_branch).is_none());
}

#[test]
fn update_b_leg_2xx_marked_done() {
    // 2xx UPDATE response → entry is marked "update_done:" so retransmitted
    // 2xx are absorbed (no ACK is ever sent for UPDATE).
    let store = CallActorStore::new();

    let call_id = store.create_call(make_a_leg("update-2xx@test"));
    store.add_b_leg(&call_id, make_b_leg("10.0.0.2:5060"));
    store.set_winner(&call_id, 0);

    let update_branch = TransactionKey::generate_branch();
    let update_leg = Leg::new_b_leg(
        generate_call_id(),
        generate_tag(),
        "update:b2a".to_string(),
        update_branch.clone(),
        TransportInfo {
            remote_addr: "10.0.0.1:5060".parse().unwrap(),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: None,
        },
    );
    store.add_b_leg(&call_id, update_leg);

    store.set_b_leg_target_uri(&call_id, 1, "update_done:b2a".to_string());

    {
        let call = store.get_call(&call_id).unwrap();
        assert_eq!(call.b_legs.len(), 2);
        assert_eq!(call.b_legs[1].dialog.target_uri.as_deref(), Some("update_done:b2a"));
        assert_eq!(call.b_legs[1].branch, update_branch);
    }
    assert_eq!(store.call_id_for_branch(&update_branch), Some(call_id.clone()));
}

#[test]
fn update_concurrent_with_reinvite_distinct_slots() {
    // RFC 3311 allows UPDATE concurrent with a re-INVITE on the same dialog.
    // The "update:" / "reinvite:" prefixes occupy distinct b_legs slots so
    // their branches resolve independently.
    let store = CallActorStore::new();

    let call_id = store.create_call(make_a_leg("update-concurrent@test"));
    store.add_b_leg(&call_id, make_b_leg("10.0.0.2:5060"));
    store.set_winner(&call_id, 0);

    let reinvite_branch = TransactionKey::generate_branch();
    let reinvite_leg = Leg::new_b_leg(
        generate_call_id(),
        generate_tag(),
        "reinvite:a2b".to_string(),
        reinvite_branch.clone(),
        TransportInfo {
            remote_addr: "10.0.0.2:5060".parse().unwrap(),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: None,
        },
    );
    store.add_b_leg(&call_id, reinvite_leg);

    let update_branch = TransactionKey::generate_branch();
    let update_leg = Leg::new_b_leg(
        generate_call_id(),
        generate_tag(),
        "update:b2a".to_string(),
        update_branch.clone(),
        TransportInfo {
            remote_addr: "10.0.0.1:5060".parse().unwrap(),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: None,
        },
    );
    store.add_b_leg(&call_id, update_leg);

    // Branches resolve independently
    assert_eq!(store.call_id_for_branch(&reinvite_branch), Some(call_id.clone()));
    assert_eq!(store.call_id_for_branch(&update_branch), Some(call_id.clone()));

    {
        let call = store.get_call(&call_id).unwrap();
        assert_eq!(call.b_legs.len(), 3);
        assert_eq!(call.b_legs[1].dialog.target_uri.as_deref(), Some("reinvite:a2b"));
        assert_eq!(call.b_legs[2].dialog.target_uri.as_deref(), Some("update:b2a"));
    }
}

#[test]
fn update_done_entry_cleaned_on_call_removal() {
    // "update_done:" entries must not linger in the registry when the call
    // ends. UPDATE has no ACK to retransmit, so unlike re-INVITE the leg
    // doesn't need a zombie placeholder — late dups are simply dropped.
    let store = CallActorStore::new();

    let call_id = store.create_call(make_a_leg("update-cleanup@test"));
    store.add_b_leg(&call_id, make_b_leg("10.0.0.2:5060"));
    store.set_winner(&call_id, 0);

    let update_branch = TransactionKey::generate_branch();
    let update_leg = Leg::new_b_leg(
        generate_call_id(),
        generate_tag(),
        "update:a2b".to_string(),
        update_branch.clone(),
        TransportInfo {
            remote_addr: "10.0.0.2:5060".parse().unwrap(),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: None,
        },
    );
    store.add_b_leg(&call_id, update_leg);
    store.set_b_leg_target_uri(&call_id, 1, "update_done:a2b".to_string());

    store.remove_call(&call_id);
    assert_eq!(store.count(), 0);
    assert!(store.call_id_for_branch(&update_branch).is_none());
}

#[test]
fn set_b_leg_target_uri_no_panic_on_invalid_index() {
    // Setting target_uri on a non-existent index should be a no-op.
    let store = CallActorStore::new();
    let call_id = store.create_call(make_a_leg("target-uri-invalid@test"));
    store.add_b_leg(&call_id, make_b_leg("10.0.0.2:5060"));

    // Index 5 doesn't exist — should not panic
    store.set_b_leg_target_uri(&call_id, 5, "reinvite_done:a2b".to_string());

    // Original B-leg unaffected
    {
        let call = store.get_call(&call_id).unwrap();
        assert_eq!(call.b_legs.len(), 1);
        assert!(call.b_legs[0].dialog.target_uri.as_deref().unwrap().starts_with("sip:"));
    }
}

// ---------------------------------------------------------------------------
// B2BUA topology hiding — rewrite_uri_host
// ---------------------------------------------------------------------------

#[test]
fn rewrite_uri_host_hides_private_ip_in_from() {
    use siphon::b2bua::actor::rewrite_uri_host;

    // Simulates BYE forwarding: A-leg From has private IP, must be rewritten
    let from = "<sip:alice@10.0.0.5>;tag=sb-17291b99bc2d";
    let rewritten = rewrite_uri_host(from, "203.0.113.5");
    assert_eq!(rewritten, "<sip:alice@203.0.113.5>;tag=sb-17291b99bc2d");
    assert!(!rewritten.contains("10.0.0.5"), "private IP must not leak");
}

#[test]
fn rewrite_uri_host_hides_private_ip_in_pai() {
    use siphon::b2bua::actor::rewrite_uri_host;

    // Simulates PAI from A-leg: has a private IP that must not leak downstream
    let pai = "<sip:alice@10.0.0.6>";
    let rewritten = rewrite_uri_host(pai, "203.0.113.5");
    assert_eq!(rewritten, "<sip:alice@203.0.113.5>");
    assert!(!rewritten.contains("10.0.0.6"), "private IP must not leak");
}

#[test]
fn rewrite_uri_authority_no_double_port_when_topology_hiding_to() {
    use siphon::b2bua::actor::rewrite_uri_authority;

    // Regression: an inbound INVITE carried the callee's To against siphon's
    // own inbound port (`pcscf.example.com:5061`).  When the B2BUA dials a
    // trunk that itself advertises a port (`trunk.example.com:5060`), the
    // To must be topology-hidden to the *whole* target authority.  Replacing
    // host-only left the old port and emitted `trunk.example.com:5060:5061`
    // (two ports on one URI, RFC 3261 §19.1.1 violation) which the trunk
    // rejected with `400 Wrong URI`.
    let to = "<sip:bob@pcscf.example.com:5061;user=phone>";
    let rewritten = rewrite_uri_authority(to, "trunk.example.com:5060");
    assert_eq!(
        rewritten,
        "<sip:bob@trunk.example.com:5060;user=phone>"
    );
    assert!(
        !rewritten.contains("5060:5061"),
        "double port must not appear: {rewritten}"
    );
    assert!(
        !rewritten.contains("pcscf.example.com"),
        "siphon's inbound host must not leak to the B-leg: {rewritten}"
    );
}

// ---------------------------------------------------------------------------
// ensure_tag — From/To tag-stitching for in-dialog request bridges
// ---------------------------------------------------------------------------

#[test]
fn ensure_tag_combines_dialog_uri_and_tag_for_bridged_update() {
    // Models the state captured at outbound INVITE-send time: remote_to_uri
    // has no tag yet (the trunk hasn't answered), but local_tag is the
    // B2BUA's own tag toward the trunk. The 2xx splice fills in remote_tag.
    // ensure_tag is what the UPDATE/re-INVITE/BYE bridges then call to
    // assemble the From/To headers.
    use siphon::b2bua::actor::ensure_tag;

    let untagged_to_uri = "<sip:bob@trunk.example.com:5061>";
    let remote_tag = "trunk-side-tag-abc123";
    assert_eq!(
        ensure_tag(untagged_to_uri, Some(remote_tag)),
        "<sip:bob@trunk.example.com:5061>;tag=trunk-side-tag-abc123",
        "untagged To URI must have the trunk's remote tag appended"
    );

    // Idempotent — if the splice path already ran, the URI carries the tag.
    let already_tagged = "<sip:bob@trunk.example.com:5061>;tag=trunk-side-tag-abc123";
    assert_eq!(
        ensure_tag(already_tagged, Some("different-tag")),
        already_tagged,
        "ensure_tag must not double-append a tag"
    );

    // Early-dialog UPDATE before 2xx: remote_tag is None — no tag added.
    // RFC 3311 §5.2 explicitly permits this (precondition negotiation).
    let bare = "<sip:bob@trunk.example.com:5061>";
    assert_eq!(ensure_tag(bare, None), bare);
}

#[test]
fn b2bua_cseq_independent_per_leg() {
    // Verify that Dialog tracks independent CSeq counters
    use siphon::b2bua::actor::Dialog;

    let mut a_dialog = Dialog::from_inbound("call-a@host".into(), "remote-tag".into());
    let mut b_dialog = Dialog::new_outbound("b2b-call@host".into(), "local-tag".into(), "sip:bob@10.0.0.2".into());

    // A-leg and B-leg start with independent CSeq = 1
    assert_eq!(a_dialog.local_cseq, 1);
    assert_eq!(b_dialog.local_cseq, 1);

    // Incrementing B-leg CSeq does not affect A-leg
    b_dialog.local_cseq += 1;
    b_dialog.local_cseq += 1;
    assert_eq!(b_dialog.local_cseq, 3);
    assert_eq!(a_dialog.local_cseq, 1);

    // Incrementing A-leg CSeq does not affect B-leg
    a_dialog.local_cseq += 1;
    assert_eq!(a_dialog.local_cseq, 2);
    assert_eq!(b_dialog.local_cseq, 3);
}

// ---------------------------------------------------------------------------
// B2BUA per-leg Contact storage
// ---------------------------------------------------------------------------

#[test]
fn dialog_local_and_remote_contact_storage() {
    use siphon::b2bua::actor::{Dialog, extract_contact_uri};

    let mut a_dialog = Dialog::from_inbound("call-a@host".into(), "remote-tag".into());
    let mut b_dialog = Dialog::new_outbound(
        "b2b-call@host".into(),
        "local-tag".into(),
        "sip:bob@10.0.0.2:5060;transport=tcp".into(),
    );

    // Initially both contacts are None
    assert!(a_dialog.local_contact.is_none());
    assert!(a_dialog.remote_contact.is_none());
    assert!(b_dialog.local_contact.is_none());
    assert!(b_dialog.remote_contact.is_none());

    // Set A-leg contacts (siphon's Contact to caller + caller's Contact)
    a_dialog.local_contact = Some("<sip:203.0.113.1:5060;transport=udp>".to_string());
    a_dialog.remote_contact = Some(
        extract_contact_uri("<sip:alice@10.0.0.1:5060;transport=udp>;expires=3600"),
    );

    // Set B-leg contacts (siphon's Contact to callee + callee's Contact from 200 OK)
    b_dialog.local_contact = Some("<sip:203.0.113.1:5060;transport=tcp>".to_string());
    b_dialog.remote_contact = Some(
        extract_contact_uri("<sip:bob@192.168.1.100:5060;transport=tcp>"),
    );

    // Verify extract_contact_uri strips angle brackets and header params
    assert_eq!(a_dialog.remote_contact.as_deref().unwrap(), "sip:alice@10.0.0.1:5060;transport=udp");
    assert_eq!(b_dialog.remote_contact.as_deref().unwrap(), "sip:bob@192.168.1.100:5060;transport=tcp");

    // Each leg is independent — contacts don't leak between legs
    assert_ne!(a_dialog.local_contact, b_dialog.local_contact);
    assert_ne!(a_dialog.remote_contact, b_dialog.remote_contact);
}

#[test]
fn extract_contact_uri_formats() {
    use siphon::b2bua::actor::extract_contact_uri;

    // Angle brackets with header params
    assert_eq!(
        extract_contact_uri("<sip:alice@10.0.0.1:5060;transport=tcp>;expires=3600"),
        "sip:alice@10.0.0.1:5060;transport=tcp"
    );

    // Angle brackets without header params
    assert_eq!(
        extract_contact_uri("<sip:bob@192.168.1.1>"),
        "sip:bob@192.168.1.1"
    );

    // Bare URI (no angle brackets)
    assert_eq!(
        extract_contact_uri("sip:carol@example.com:5060"),
        "sip:carol@example.com:5060"
    );

    // With display name
    assert_eq!(
        extract_contact_uri("\"Alice\" <sip:alice@10.0.0.1:5060>"),
        "sip:alice@10.0.0.1:5060"
    );

    // Whitespace trimming
    assert_eq!(
        extract_contact_uri("  <sip:alice@10.0.0.1>  "),
        "sip:alice@10.0.0.1"
    );
}

#[test]
fn per_leg_contact_on_call_actor_store() {
    let store = CallActorStore::new();

    // Create A-leg with contacts populated
    let mut a_leg = make_a_leg("contact-test@host");
    a_leg.dialog.local_contact = Some("<sip:203.0.113.1:5060;transport=udp>".to_string());
    a_leg.dialog.remote_contact = Some("sip:alice@10.0.0.1:5060".to_string());
    let call_id = store.create_call(a_leg);

    // Create B-leg with local_contact
    let mut b_leg = make_b_leg("10.0.0.2:5060");
    b_leg.dialog.local_contact = Some("<sip:203.0.113.1:5060;transport=tcp>".to_string());
    store.add_b_leg(&call_id, b_leg);

    // Simulate 200 OK: set B-leg remote_contact
    {
        let mut call = store.get_call_mut(&call_id).unwrap();
        if let Some(b) = call.b_legs.get_mut(0) {
            b.dialog.remote_contact = Some("sip:bob@192.168.1.100:5060;transport=tcp".to_string());
            b.dialog.remote_tag = Some("bob-tag".to_string());
        }
    }

    // Verify contacts are stored and retrievable
    let call = store.get_call(&call_id).unwrap();

    // A-leg contacts
    assert_eq!(call.a_leg.dialog.local_contact.as_deref(), Some("<sip:203.0.113.1:5060;transport=udp>"));
    assert_eq!(call.a_leg.dialog.remote_contact.as_deref(), Some("sip:alice@10.0.0.1:5060"));

    // B-leg contacts
    let b = &call.b_legs[0];
    assert_eq!(b.dialog.local_contact.as_deref(), Some("<sip:203.0.113.1:5060;transport=tcp>"));
    assert_eq!(b.dialog.remote_contact.as_deref(), Some("sip:bob@192.168.1.100:5060;transport=tcp"));

    // For in-dialog re-INVITE A→B:
    //   RURI = B-leg remote_contact = "sip:bob@192.168.1.100:5060;transport=tcp"
    //   Contact = B-leg local_contact = "<sip:203.0.113.1:5060;transport=tcp>"
    // For in-dialog BYE B→A:
    //   RURI = A-leg remote_contact = "sip:alice@10.0.0.1:5060"
    //   Contact = A-leg local_contact = "<sip:203.0.113.1:5060;transport=udp>"
}

// ---------------------------------------------------------------------------
// Header policy — integration with CallActor + preset library
// ---------------------------------------------------------------------------

fn make_invite(extras: &[(&str, &str)]) -> SipMessage {
    let mut raw = String::from("INVITE sip:bob@biloxi.com SIP/2.0\r\n");
    raw.push_str("Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1\r\n");
    raw.push_str("From: <sip:alice@atlanta.com>;tag=a\r\n");
    raw.push_str("To: <sip:bob@biloxi.com>\r\n");
    raw.push_str("Call-ID: hp-int-test@example.com\r\n");
    raw.push_str("CSeq: 1 INVITE\r\n");
    raw.push_str("Max-Forwards: 70\r\n");
    for (n, v) in extras {
        raw.push_str(&format!("{}: {}\r\n", n, v));
    }
    raw.push_str("Content-Length: 0\r\n\r\n");
    parse_sip_message(&raw).expect("test fixture must parse").1
}

fn make_response_200(extras: &[(&str, &str)]) -> SipMessage {
    let mut raw = String::from("SIP/2.0 200 OK\r\n");
    raw.push_str("Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK1\r\n");
    raw.push_str("From: <sip:alice@atlanta.com>;tag=a\r\n");
    raw.push_str("To: <sip:bob@biloxi.com>;tag=b\r\n");
    raw.push_str("Call-ID: hp-int-test@example.com\r\n");
    raw.push_str("CSeq: 1 INVITE\r\n");
    for (n, v) in extras {
        raw.push_str(&format!("{}: {}\r\n", n, v));
    }
    raw.push_str("Content-Length: 0\r\n\r\n");
    parse_sip_message(&raw).expect("test fixture must parse").1
}

fn test_ctx() -> PolicyContext<'static> {
    PolicyContext {
        b2bua_host: "192.0.2.1",
        b2bua_port: 5060,
        user_agent_header: Some("siphon-test/1.0"),
        server_header: Some("siphon-test/1.0"),
    }
}

#[test]
fn preset_library_contains_four_built_in_presets() {
    let presets = builtin_presets();
    for name in &[
        "transparent-b2bua@2026",
        "ims-intra-trust-domain@2026",
        "ims-trust-domain-boundary@2026",
        "sip-trunk-edge@2026",
    ] {
        assert!(presets.contains_key(*name), "missing preset: {name}");
    }
    assert_eq!(presets.len(), 4);
}

#[test]
fn call_actor_can_carry_resolved_header_policy() {
    let leg = make_a_leg("policy-attach@test");
    let mut call = CallActor::new(leg);
    assert!(call.resolved_header_policy.is_none());

    let preset = builtin_presets()
        .get("ims-trust-domain-boundary@2026")
        .unwrap()
        .clone();
    let resolved = ResolvedPolicy::from_preset(preset);
    call.resolved_header_policy = Some(Arc::new(resolved));

    assert!(call.resolved_header_policy.is_some());
    let attached = call.resolved_header_policy.as_ref().unwrap();
    assert_eq!(attached.preset.qualified_name(), "ims-trust-domain-boundary@2026");
}

#[test]
fn bgcf_mtc_trace_headers_stripped_by_trust_boundary_preset() {
    // The exact headers that leaked through to the Samsung S21 MT INVITE in
    // the BGCF/FreeSWITCH trace that motivated the opt-in policy work.
    let mut invite = make_invite(&[
        ("Alert-Info", "<urn:alert:service:call-waiting>"),
        ("Diversion", "<sip:+3197010267609@sip.didww.com>;reason=unconditional"),
        ("P-Hint", "inbound"),
        ("X-FS-Support", "update_display,send_info"),
    ]);

    let preset = builtin_presets()
        .get("ims-trust-domain-boundary@2026")
        .unwrap()
        .clone();
    let policy = ResolvedPolicy::from_preset(preset);
    apply_to_request(&mut invite, &policy, &test_ctx());

    // Alert-Info, P-Hint, X-FS-Support: stripped (not on safe-set)
    assert!(!invite.headers.has("Alert-Info"));
    assert!(!invite.headers.has("P-Hint"));
    assert!(!invite.headers.has("X-FS-Support"));
    // Diversion: translated to History-Info (RFC 7044)
    assert!(!invite.headers.has("Diversion"));
    let hi = invite
        .headers
        .get("History-Info")
        .expect("Diversion should have been translated to History-Info");
    assert!(hi.contains("+3197010267609@sip.didww.com"));
    assert!(hi.contains("cause%3D302")); // unconditional → SIP 302
}

#[test]
fn intra_trust_preset_preserves_end_to_end_prack_headers() {
    // RFC 3262 §6 / RFC 3312 / RFC 4032 — PRACK + IMS preconditions require
    // Require/RSeq/Supported to flow end-to-end across intra-trust hops.
    // Pre-policy siphon stripped them unconditionally on every B2BUA hop,
    // which silently broke IMS preconditions across S-CSCF ↔ AS bridges.
    let mut response = make_response_200(&[
        ("Require", "100rel"),
        ("RSeq", "1"),
        ("Supported", "100rel, precondition"),
    ]);

    let preset = builtin_presets()
        .get("ims-intra-trust-domain@2026")
        .unwrap()
        .clone();
    let policy = ResolvedPolicy::from_preset(preset);
    apply_to_response(&mut response, &policy, &test_ctx());

    assert!(response.headers.has("Require"));
    assert!(response.headers.has("RSeq"));
    assert!(response.headers.has("Supported"));
}

#[test]
fn intentional_proxy_authenticate_strip_works_for_every_preset() {
    // RFC 3261 §22.3 — Proxy-Authenticate is hop-by-hop.  Pre-policy siphon
    // passed it through B2BUA hops, which was broken (A's resulting
    // Proxy-Authorization would target the wrong realm).  Every shipped
    // preset must strip it on B→A responses.  Lives in the preset rather
    // than as framework-auto so transparent-proxy B2BUAs can opt back in
    // via `call.dial(copy=["Proxy-Authenticate"])` for the rare case.
    for preset_name in &[
        "transparent-b2bua@2026",
        "ims-intra-trust-domain@2026",
        "ims-trust-domain-boundary@2026",
        "sip-trunk-edge@2026",
    ] {
        let mut response = make_response_200(&[(
            "Proxy-Authenticate",
            "Digest realm=\"b-leg.example.com\"",
        )]);

        let preset = builtin_presets().get(*preset_name).unwrap().clone();
        let policy = ResolvedPolicy::from_preset(preset);
        apply_to_response(&mut response, &policy, &test_ctx());

        assert!(
            !response.headers.has("Proxy-Authenticate"),
            "preset {preset_name} must strip Proxy-Authenticate on B→A responses"
        );
    }
}

#[test]
fn framework_auto_100rel_strip_is_preset_independent() {
    // RFC 3262 — a B2BUA that PRACKs a B-leg's reliable provisional locally
    // must not leak the `100rel` contract to an A-leg that never advertised it
    // (a plain trunk would CANCEL the call rather than PRACK).  The strip is a
    // correctness invariant applied framework-auto in sanitize_b2bua_response,
    // NOT a preset override — so it must hold even under presets (like
    // sip-trunk-edge@2026) whose response policy is `default → Copy` and would
    // otherwise pass `Require`/`RSeq` straight through.
    let preset = builtin_presets()
        .get("sip-trunk-edge@2026")
        .unwrap()
        .clone();
    let policy = ResolvedPolicy::from_preset(preset);

    // First confirm the preset itself leaves the markers (this is the bug the
    // framework-auto strip exists to backstop).
    let mut passed_through = make_response_200(&[
        ("Require", "100rel"),
        ("RSeq", "1"),
        ("Supported", "timer, 100rel"),
    ]);
    apply_to_response(&mut passed_through, &policy, &test_ctx());
    assert!(
        passed_through.headers.has("Require") && passed_through.headers.has("RSeq"),
        "sip-trunk-edge@2026 Copy policy is expected to leave Require/RSeq — \
         the framework-auto strip is what removes them"
    );

    // Non-100rel A-leg: framework-auto strip removes the contract on top of any
    // preset's output.
    let removed = siphon::sip::headers::rseq::strip_100rel_for_unsupported_peer(
        &mut passed_through.headers,
        false,
    );
    assert!(removed);
    assert!(!passed_through.headers.has("Require"));
    assert!(!passed_through.headers.has("RSeq"));

    // 100rel-capable A-leg: the reliable provisional still flows end-to-end.
    let mut for_capable_peer = make_response_200(&[
        ("Require", "100rel"),
        ("RSeq", "1"),
    ]);
    apply_to_response(&mut for_capable_peer, &policy, &test_ctx());
    let removed = siphon::sip::headers::rseq::strip_100rel_for_unsupported_peer(
        &mut for_capable_peer.headers,
        true,
    );
    assert!(!removed);
    assert!(for_capable_peer.headers.has("Require"));
    assert!(for_capable_peer.headers.has("RSeq"));
}

#[test]
fn a_leg_100rel_capability_is_snapshotted_not_re_derived_from_mutable_invite() {
    // Regression: the A-leg's reliable-provisional capability MUST be captured
    // from the on-wire INVITE before the @b2bua.on_invite script runs and stored
    // immutably on the call — NOT re-derived from `a_leg_invite`, which the script
    // can mutate via `call.set_header("Supported", "…100rel")` to advertise
    // reliable provisionals toward the B-leg (IR.92).  Re-deriving from the
    // mutated message falsely reports the A-leg trunk as 100rel-capable, defeats
    // the reliable-1xx strip, and the trunk CANCELs the call.
    let raw = concat!(
        "INVITE sip:bob@biloxi.com SIP/2.0\r\n",
        "Via: SIP/2.0/UDP trunk.example.com;branch=z9hG4bK-onwire\r\n",
        "From: <sip:alice@trunk.example.com>;tag=a\r\n",
        "To: <sip:bob@biloxi.com>\r\n",
        "Call-ID: gate-poison@test\r\n",
        "CSeq: 1 INVITE\r\n",
        "Supported: timer, path, replaces\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    );
    let invite = parse_sip_message(raw).expect("fixture parses").1;

    // siphon snapshots the on-wire capability before the script runs.
    let snapshot = siphon::sip::headers::rseq::supports_100rel(&invite.headers);
    assert!(!snapshot, "on-wire trunk INVITE must not advertise 100rel");

    let store = CallActorStore::new();
    let call_id = store.create_call(make_a_leg("gate-poison@test"));
    {
        let mut call = store.get_call_mut(&call_id).unwrap();
        call.a_leg_supports_100rel = snapshot;
    }

    // Script mutates the SHARED INVITE to advertise 100rel toward the B-leg.
    let invite_arc = Arc::new(Mutex::new(invite));
    store.set_a_leg_invite(&call_id, Arc::clone(&invite_arc));
    invite_arc
        .lock()
        .unwrap()
        .headers
        .set("Supported", "timer, 100rel".to_string());

    let call = store.get_call(&call_id).unwrap();
    // The mutated INVITE now *reads* as 100rel-capable — exactly what poisoned
    // the old gate that re-derived from `a_leg_invite`.
    assert!(
        siphon::sip::headers::rseq::supports_100rel(
            &call.a_leg_invite.as_ref().unwrap().lock().unwrap().headers
        ),
        "the script-mutated INVITE reads as 100rel-capable"
    );
    // The snapshot stays false — the gate is immune to script header shaping.
    assert!(
        !call.a_leg_supports_100rel,
        "snapshotted capability must reflect the on-wire INVITE, not the mutated one"
    );
}

#[test]
fn transparent_proxy_b2bua_can_opt_in_to_proxy_authenticate_passthrough() {
    // Rare transparent-proxy B2BUA case: A and C share auth domain and
    // the B2BUA wants A to handle the 401 itself.  Per-call delta restores
    // the header that every preset strips by default.
    let mut response = make_response_200(&[(
        "Proxy-Authenticate",
        "Digest realm=\"trusted.example.com\"",
    )]);

    let preset = builtin_presets().get("transparent-b2bua@2026").unwrap().clone();
    let mut policy = ResolvedPolicy::from_preset(preset);
    policy.deltas_copy.push("Proxy-Authenticate".to_string());

    apply_to_response(&mut response, &policy, &test_ctx());

    assert!(
        response.headers.has("Proxy-Authenticate"),
        "delta copy must override preset strip for transparent-proxy use case"
    );
}

#[test]
fn per_call_delta_overrides_preset_strip_for_emergency_call() {
    // Emergency-call use case: the sip-trunk-edge preset strips P-*
    // headers defensively, but an emergency call needs P-Asserted-Identity
    // and Geolocation to reach the PSAP.  Per-call copy delta restores them.
    let mut invite = make_invite(&[
        ("P-Asserted-Identity", "<sip:+15551234@example.com>"),
        ("Geolocation", "<cid:geo1@example.com>"),
        ("X-Internal-Tag", "should-still-be-stripped"),
    ]);

    let preset = builtin_presets().get("sip-trunk-edge@2026").unwrap().clone();
    let mut policy = ResolvedPolicy::from_preset(preset);
    policy.deltas_copy.push("P-Asserted-Identity".to_string());
    policy.deltas_copy.push("Geolocation".to_string());

    apply_to_request(&mut invite, &policy, &test_ctx());

    assert!(invite.headers.has("P-Asserted-Identity"), "delta copy should restore PAI");
    assert!(invite.headers.has("Geolocation"), "delta copy should restore Geolocation");
    assert!(!invite.headers.has("X-Internal-Tag"), "X-* still stripped by preset");
}

#[test]
fn validator_rejects_authorization_copy_combined_with_pai_rewrite() {
    // Digest auth (RFC 7616) signs the R-URI / To URI / etc.  Any preset
    // that copies Authorization through (transparent-auth case-c) AND
    // rewrites a Digest-protected field would silently break the hash.
    // The validator must reject this at preset construction time.
    let bad_preset = Preset {
        name: "bad".to_string(),
        version: "test".to_string(),
        request: DirectionPolicy {
            default: Verb::Copy,
            overrides: vec![
                (HeaderPattern::Exact("Authorization".to_string()), Verb::Copy),
                (
                    HeaderPattern::Exact("P-Asserted-Identity".to_string()),
                    Verb::Rewrite(RewriteOp::HostToAdvertised),
                ),
            ],
        },
        response: DirectionPolicy {
            default: Verb::Copy,
            overrides: vec![],
        },
    };

    let err = validate_preset(&bad_preset).expect_err("should reject");
    match err {
        PresetError::AuthorizationCopyWithDigestProtectedRewrite(name) => {
            assert!(name.contains("bad"), "error should name the bad preset: {name}");
        }
        other => panic!("wrong error variant: {other:?}"),
    }
}

#[test]
fn validator_accepts_intra_trust_with_per_call_authorization_copy() {
    // The supported transparent-auth case-c pattern: use a preset without
    // R-URI / PAI rewrites (ims-intra-trust-domain), then add Authorization
    // to deltas_copy at dial time.  Validator is preset-level so the
    // delta is fine; preset must still validate cleanly.
    let preset = (**builtin_presets().get("ims-intra-trust-domain@2026").unwrap()).clone();
    validate_preset(&preset).expect("intra-trust preset must validate clean");

    // And a ResolvedPolicy carrying the Authorization delta still works.
    let mut policy = ResolvedPolicy::from_preset(Arc::new(preset));
    policy.deltas_copy.push("Authorization".to_string());

    let mut invite = make_invite(&[("Authorization", "Digest username=\"alice\", realm=\"c.example.com\"")]);
    apply_to_request(&mut invite, &policy, &test_ctx());
    // Authorization copied through (case-c transparent auth)
    assert!(invite.headers.has("Authorization"));
}
