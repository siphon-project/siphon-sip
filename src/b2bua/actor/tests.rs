//! Unit tests for the actor module.
//!
//! They exercise private items across every submodule, so they live at the
//! module root with `use super::*` rather than beside each file.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dashmap::DashMap;

use super::store::{TERMINATED_CALL_CAPACITY, TERMINATED_CALL_TTL};
use crate::transport::{ConnectionId, Transport};

use super::*;

#[cfg(test)]
mod call_actor_footprint {
    use super::*;

    /// The call store holds a *pointer* to the actor, not the actor.
    ///
    /// `CallActor` is ~2.2 KB — an inline `a_leg: Leg`, the `b_legs` vectors,
    /// session-timer and transfer state — and `hashbrown` sizes its bucket
    /// array for the peak number of live calls and never shrinks it. Stored
    /// inline that was the largest retained bucket in siphon, held at the
    /// busiest moment the process ever saw for the rest of its life, with
    /// `call_count()` reading 0 the whole time.
    #[test]
    fn the_call_store_holds_a_pointer_not_the_actor() {
        let bucket = std::mem::size_of::<(String, Box<CallActor>)>();
        let key_only = std::mem::size_of::<String>();
        assert!(
            bucket <= key_only + 16,
            "call bucket is {bucket} B against a {key_only} B key — the actor is \
             being stored inline again, and the table will retain it at peak \
             concurrency forever"
        );
        // Guard the premise: boxing only pays while the payload is big.
        let payload = std::mem::size_of::<CallActor>();
        assert!(
            payload >= 512,
            "CallActor is down to {payload} B — re-check whether boxing still earns \
             its indirection"
        );
    }
}
// ---------------------------------------------------------------------------

#[cfg(test)]
use crate::b2bua::transfer::{ReplacementOrigin, TransferState};
use std::net::{IpAddr, Ipv4Addr};

fn test_transport() -> TransportInfo {
    TransportInfo {
        remote_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 5060),
        connection_id: ConnectionId::default(),
        transport: Transport::Udp,
        local_addr: None,
    }
}

fn make_a_leg() -> Leg {
    Leg::new_a_leg(
        "call-1@10.0.0.1".to_string(),
        "tag-alice".to_string(),
        "z9hG4bK-aleg1".to_string(),
        test_transport(),
    )
}

fn make_b_leg(index: usize) -> Leg {
    Leg::new_b_leg(
        format!("b2b-bleg{}", index),
        format!("sb-bleg{}", index),
        format!("sip:bob{}@10.0.0.2", index),
        format!("z9hG4bK-bleg{}", index),
        TransportInfo {
            remote_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 5060),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: None,
        },
    )
}

fn lcr_route(carrier: &str) -> crate::lcr::Route {
    crate::lcr::Route {
        carrier_id: carrier.to_string(),
        next_hop: Some(format!("sip:{carrier}.example:5060")),
        ..Default::default()
    }
}

// --- LCR sequential-failover state tests ---

#[test]
fn route_sequence_pops_in_order_and_drains() {
    let mut actor = CallActor::new(make_a_leg());
    actor.route_sequence = Some(RouteSequenceState {
        pending: [lcr_route("a"), lcr_route("b"), lcr_route("c")]
            .into_iter()
            .collect(),
        ..Default::default()
    });
    assert_eq!(actor.pending_route_len(), 3);
    assert!(actor.has_pending_routes());
    assert!(actor.is_route_sequence());

    let first = actor.take_next_route().expect("first carrier");
    assert_eq!(first.carrier_id, "a");
    // The popped carrier becomes the active (in-flight) route.
    assert_eq!(
        actor.active_route().map(|route| route.carrier_id.as_str()),
        Some("a")
    );
    assert_eq!(actor.pending_route_len(), 2);

    assert_eq!(actor.take_next_route().unwrap().carrier_id, "b");
    assert_eq!(actor.take_next_route().unwrap().carrier_id, "c");
    assert!(!actor.has_pending_routes());
    assert!(actor.take_next_route().is_none());
    // Active stays at the last carrier tried (the winner after a 2xx).
    assert_eq!(
        actor.active_route().map(|route| route.carrier_id.as_str()),
        Some("c")
    );
}

#[test]
fn release_control_owner_clears_park_state() {
    // A call parked under external control (deferred handover) → the
    // controller hands control back with a routing decision. Releasing must
    // clear the owner + control-loss policy AND disarm the handoff-pending
    // path so a later B-leg ring-timeout takes the normal 408 route, not the
    // parked-503 default.
    let store = CallActorStore::new();
    let call_id = store.create_call(make_a_leg());
    store.set_control_owner(&call_id, "ivr-app", Some("hangup"));
    assert_eq!(store.control_app(&call_id).as_deref(), Some("ivr-app"));
    assert!(store
        .get_call(&call_id)
        .is_some_and(|call| call.is_handoff_pending()));

    store.release_control_owner(&call_id);

    assert!(store.control_app(&call_id).is_none());
    let call = store.get_call(&call_id).expect("call still present");
    assert!(
        !call.is_handoff_pending(),
        "handoff must be disarmed after release"
    );
    assert!(call.on_control_loss.is_none());
    // The call lives on — release does not remove it.
    assert!(matches!(call.state, CallState::Calling));
}

#[test]
fn parked_call_unparks_into_route_sequence() {
    // Models the store-level transition b2bua_route_call performs: a parked
    // (deferred-handover) call, on a routing decision, is released from
    // control AND a sequential route sequence is started — so the shipped LCR
    // engine (b2bua_advance_route) then dials the B-leg. (The dispatcher
    // wiring around this is the same shipped rail the imperative fns use.)
    let store = CallActorStore::new();
    let call_id = store.create_call(make_a_leg());
    // Park under control (deferred handover): Ringing + control owner.
    store.set_state(&call_id, CallState::Ringing);
    store.set_control_owner(&call_id, "ivr-app", Some("hangup"));
    assert!(!store.is_route_sequence(&call_id));

    // Route: release control, then start the sequential-failover queue.
    store.release_control_owner(&call_id);
    store.start_route_sequence(
        &call_id,
        RouteSequenceState {
            pending: [lcr_route("a"), lcr_route("b")].into_iter().collect(),
            ..Default::default()
        },
    );

    // The call is now an autonomous LCR sequence, no longer under control.
    assert!(store.is_route_sequence(&call_id));
    assert!(store.control_app(&call_id).is_none());
    assert!(store.has_pending_routes(&call_id));
    assert!(!store
        .get_call(&call_id)
        .is_some_and(|call| call.is_handoff_pending()));
    // The first carrier is dialable.
    assert_eq!(store.take_next_route(&call_id).unwrap().carrier_id, "a");
}

#[test]
fn record_route_failure_keeps_highest_priority() {
    let mut actor = CallActor::new(make_a_leg());
    actor.route_sequence = Some(RouteSequenceState::default());
    actor.record_route_failure(486);
    assert_eq!(actor.best_route_error(), Some(486));
    // 5xx outranks 4xx.
    actor.record_route_failure(503);
    assert_eq!(actor.best_route_error(), Some(503));
    // A later lower-priority 404 does not displace the 503.
    actor.record_route_failure(404);
    assert_eq!(actor.best_route_error(), Some(503));
    // 6xx outranks everything.
    actor.record_route_failure(603);
    assert_eq!(actor.best_route_error(), Some(603));
}

/// Each failure is recorded against the carrier that was actually in
/// flight, in the order tried — the record that used to be collapsed into a
/// single best-error code, so a call that burned a carrier on its way to
/// answering said nothing about which one.
#[test]
fn every_attempt_is_recorded_against_the_carrier_that_was_tried() {
    let mut actor = CallActor::new(make_a_leg());
    actor.route_sequence = Some(RouteSequenceState {
        pending: [lcr_route("a"), lcr_route("b"), lcr_route("c")]
            .into_iter()
            .collect(),
        ..Default::default()
    });

    actor.take_next_route().expect("carrier a");
    let first = actor.record_route_failure(503).expect("attempt recorded");
    assert_eq!(first.carrier_id, "a");
    assert_eq!(first.status, 503);

    actor.take_next_route().expect("carrier b");
    // A ring timeout is recorded like any other failure, as 408.
    let second = actor.record_route_failure(408).expect("attempt recorded");
    assert_eq!(second.carrier_id, "b");
    assert_eq!(second.status, 408);

    // Carrier c is dialled and answers, so it is never recorded as an
    // attempt — it is the winner, and reaches a script as `active_route`.
    actor.take_next_route().expect("carrier c");

    let carriers: Vec<&str> = actor
        .route_attempts()
        .iter()
        .map(|attempt| attempt.carrier_id.as_str())
        .collect();
    assert_eq!(carriers, ["a", "b"]);
    assert_eq!(
        actor.active_route().map(|route| route.carrier_id.as_str()),
        Some("c"),
        "the answering carrier is the winner, not an attempt"
    );
    // Derived from the attempts, so the code the A-leg would get and the
    // per-attempt record cannot disagree.
    assert_eq!(actor.best_route_error(), Some(503));
}

/// A carrier siphon never reached is still an attempt — the sequence
/// consumed it and the caller took the consequence — but it must not read
/// as the carrier's own answer. Without the distinction a local DNS or
/// gateway problem is indistinguishable from a carrier rejecting the call,
/// in `route_attempts`, in the CDR's `lcr_attempts` and in
/// `@b2bua.on_route_failure` alike: the figures an operator trends a
/// carrier on, and takes to that carrier.
#[test]
fn a_carrier_that_was_never_dialled_is_recorded_but_not_blamed() {
    let mut actor = CallActor::new(make_a_leg());
    actor.route_sequence = Some(RouteSequenceState {
        pending: [lcr_route("a"), lcr_route("b")].into_iter().collect(),
        ..Default::default()
    });

    actor.take_next_route().expect("carrier a");
    let undialed = actor.record_route_undialed(503).expect("attempt recorded");
    assert_eq!(undialed.carrier_id, "a");
    assert_eq!(undialed.status, 503);
    assert!(
        !undialed.dialed,
        "no INVITE reached the transport for this carrier"
    );

    actor.take_next_route().expect("carrier b");
    let answered_badly = actor.record_route_failure(486).expect("attempt recorded");
    assert!(
        answered_badly.dialed,
        "the carrier was dialled and answered 486 itself"
    );

    // Both are on the list — the sequence burned both — and the list is
    // still what best_route_error derives from, so an exhausted sequence of
    // unroutable carriers still hands the caller a code.
    assert_eq!(actor.route_attempts().len(), 2);
    assert_eq!(actor.best_route_error(), Some(503));
}

/// A call with no failover sequence has nothing to report, and asking must
/// not be an error — every `Call` handed to a script reads this property,
/// LCR or not.
#[test]
fn a_non_lcr_call_reports_no_attempts() {
    let mut actor = CallActor::new(make_a_leg());
    assert!(actor.route_attempts().is_empty());
    assert!(actor.record_route_failure(503).is_none());
    assert!(actor.record_route_undialed(503).is_none());
}

#[test]
fn non_sequential_call_has_no_route_state() {
    let mut actor = CallActor::new(make_a_leg());
    assert!(!actor.is_route_sequence());
    assert!(!actor.has_pending_routes());
    assert!(actor.take_next_route().is_none());
    assert_eq!(actor.best_route_error(), None);
    assert!(actor.active_route().is_none());
    assert_eq!(actor.pending_route_len(), 0);
}

// --- Leg tests ---

#[test]
fn leg_id_is_unique() {
    let id1 = LegId::new();
    let id2 = LegId::new();
    assert_ne!(id1, id2);
}

#[test]
fn dialog_has_stable_sdp_session_id_and_zero_version() {
    // Each dialog is born with a stable siphon-owned SDP session-id and a
    // version starting at 0 (RFC 4566 §5.2 / RFC 3264 §8).
    let a = Dialog::from_inbound("c@h".to_string(), "rt".to_string());
    assert_eq!(a.sdp_version, 0);
    let b = Dialog::new_outbound("c@h".to_string(), "lt".to_string(), "sip:x@h".to_string());
    assert_eq!(b.sdp_version, 0);
    // Distinct dialogs get distinct session-ids (overwhelmingly — u64 from a
    // v4 UUID).
    assert_ne!(a.sdp_session_id, b.sdp_session_id);
}

#[test]
fn generated_sdp_session_id_fits_a_signed_64_bit_integer() {
    // RFC 3264 §5: the o= session-id MUST be representable in a signed
    // 64-bit integer.  The generator drew from the whole unsigned range, so
    // roughly every second dialog emitted one a peer parsing it as i64
    // overflows on.  Sample enough that the old behaviour cannot pass by
    // luck (2^-4096), and keep the range assertion rather than a bit-mask
    // one so it still holds if the generator is ever re-implemented.
    for _ in 0..4096 {
        let id = generate_sdp_session_id();
        assert!(
            id <= i64::MAX as u64,
            "session-id {id} exceeds i64::MAX and overflows a peer parsing o= as a signed 64-bit integer"
        );
    }
}

#[test]
fn generated_sdp_session_ids_are_distinct() {
    // Masking the top bit must not have collapsed the space: the id has to
    // stay unique across the sessions one peer holds at once (RFC 4566
    // §5.2).
    let ids: std::collections::HashSet<u64> =
        (0..1024).map(|_| generate_sdp_session_id()).collect();
    assert_eq!(ids.len(), 1024);
}

#[test]
fn reserve_leg_sdp_version_is_monotonic_and_session_stable() {
    let store = CallActorStore::new();
    let call_id = store.create_call(make_a_leg());
    store.add_b_leg(&call_id, make_b_leg(0));
    store.set_winner(&call_id, 0);

    // A-leg: same session-id across reservations, version steps 0,1,2.
    let (a_sess0, v0) = store.reserve_leg_sdp_version(&call_id, true).unwrap();
    let (a_sess1, v1) = store.reserve_leg_sdp_version(&call_id, true).unwrap();
    let (a_sess2, v2) = store.reserve_leg_sdp_version(&call_id, true).unwrap();
    assert_eq!((v0, v1, v2), (0, 1, 2));
    assert_eq!(a_sess0, a_sess1);
    assert_eq!(a_sess1, a_sess2);

    // Winning B-leg counts independently under its own session-id.
    let (b_sess, bv0) = store.reserve_leg_sdp_version(&call_id, false).unwrap();
    let (_, bv1) = store.reserve_leg_sdp_version(&call_id, false).unwrap();
    assert_eq!((bv0, bv1), (0, 1));
    assert_ne!(a_sess0, b_sess, "each leg owns a distinct SDP session-id");

    // By-index variant advances the same B-leg counter.
    let (b_sess_idx, bv2) = store
        .reserve_b_leg_sdp_version_by_index(&call_id, 0)
        .unwrap();
    assert_eq!(bv2, 2);
    assert_eq!(b_sess_idx, b_sess);

    // Unknown call / index → None.
    assert!(store.reserve_leg_sdp_version("nope", true).is_none());
    assert!(store
        .reserve_b_leg_sdp_version_by_index(&call_id, 99)
        .is_none());
}

#[test]
fn set_leg_last_sdp_records_per_leg_raw_body() {
    let store = CallActorStore::new();
    let call_id = store.create_call(make_a_leg());
    store.add_b_leg(&call_id, make_b_leg(0));
    store.set_winner(&call_id, 0);

    // Default: no SDP captured.
    assert!(store.get_call(&call_id).unwrap().a_leg.last_sdp.is_none());

    store.set_leg_last_sdp(&call_id, true, b"v=0\r\no=alice 1 1 IN IP4 192.0.2.1\r\n");
    store.set_leg_last_sdp(&call_id, false, b"v=0\r\no=bob 2 2 IN IP4 192.0.2.2\r\n");
    let call = store.get_call(&call_id).unwrap();
    assert_eq!(
        call.a_leg.last_sdp.as_deref(),
        Some(&b"v=0\r\no=alice 1 1 IN IP4 192.0.2.1\r\n"[..])
    );
    assert_eq!(
        call.b_legs[0].last_sdp.as_deref(),
        Some(&b"v=0\r\no=bob 2 2 IN IP4 192.0.2.2\r\n"[..])
    );

    // Empty SDP is a no-op (does not clobber a stored body).
    store.set_leg_last_sdp(&call_id, true, b"");
    assert!(store.get_call(&call_id).unwrap().a_leg.last_sdp.is_some());
}

#[test]
fn leg_stored_request_from_to_default_none_and_round_trip() {
    // Both constructors leave the verbatim request From/To capture empty —
    // only the transparent REFER/NOTIFY pseudo-legs populate it (RFC 3261
    // §8.2.6.2 verbatim echo). A leg that never captures them keeps the
    // dialog-reconstruction fallback.
    let mut a_leg = make_a_leg();
    assert_eq!(a_leg.stored_from, None);
    assert_eq!(a_leg.stored_to, None);
    let mut b_leg = make_b_leg(1);
    assert_eq!(b_leg.stored_from, None);
    assert_eq!(b_leg.stored_to, None);

    a_leg.stored_from = Some("<sip:bob@192.0.2.52>;tag=abc".to_string());
    a_leg.stored_to = Some("<sip:alice@192.0.2.50>;tag=xyz".to_string());
    assert_eq!(
        a_leg.stored_from.as_deref(),
        Some("<sip:bob@192.0.2.52>;tag=abc")
    );
    assert_eq!(
        a_leg.stored_to.as_deref(),
        Some("<sip:alice@192.0.2.50>;tag=xyz")
    );
    // A clone preserves the capture (the dispatcher clones legs when
    // snapshotting the call actor before relaying a response).
    b_leg.stored_from = a_leg.stored_from.clone();
    assert_eq!(b_leg.clone().stored_from, a_leg.stored_from);
}

#[test]
fn generate_tag_format() {
    let tag = generate_tag();
    assert!(tag.starts_with("sb-"));
    assert_eq!(tag.len(), 15);
}

#[test]
fn generate_call_id_format() {
    let cid = generate_call_id();
    assert!(cid.starts_with("b2b-"));
}

#[test]
fn a_leg_has_inbound_dialog() {
    let leg = make_a_leg();
    assert_eq!(leg.side, LegSide::A);
    assert_eq!(leg.dialog.call_id, "call-1@10.0.0.1");
    assert_eq!(leg.dialog.remote_tag, Some("tag-alice".to_string()));
    assert!(leg.dialog.local_tag.starts_with("sb-"));
    assert_eq!(leg.branch, "z9hG4bK-aleg1");
}

#[test]
fn b_leg_has_outbound_dialog() {
    let leg = make_b_leg(0);
    assert_eq!(leg.side, LegSide::B);
    assert_eq!(leg.dialog.call_id, "b2b-bleg0");
    assert_eq!(leg.dialog.local_tag, "sb-bleg0");
    assert!(leg.dialog.remote_tag.is_none());
    assert_eq!(leg.dialog.target_uri.as_deref(), Some("sip:bob0@10.0.0.2"));
}

// --- Dialog rewrite tests ---

#[test]
fn dialog_rewrite_swaps_call_id_and_tags() {
    let mut msg = crate::sip::builder::SipMessageBuilder::new()
        .response(200, "OK".to_string())
        .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-test".to_string())
        .from("<sip:alice@example.com>;tag=old-tag".to_string())
        .to("<sip:bob@example.com>;tag=bob-tag".to_string())
        .call_id("old-call-id".to_string())
        .cseq("1 INVITE".to_string())
        .content_length(0)
        .build()
        .unwrap();

    Dialog::rewrite_headers(&mut msg, "new-call-id", "old-tag", "new-tag", None);

    assert_eq!(msg.headers.get("Call-ID").unwrap(), "new-call-id");
    assert!(msg.headers.get("From").unwrap().contains("tag=new-tag"));
    assert!(!msg.headers.get("From").unwrap().contains("tag=old-tag"));
    assert!(msg.headers.get("To").unwrap().contains("tag=bob-tag"));
}

#[test]
fn dialog_rewrite_overwrites_to_tag_when_new_to_tag_given() {
    // Reproduces the B2BUA 200 OK forwarding scenario:
    //   B-leg 200 OK has From=siphon-b-tag and To=gateway-tag.
    //   Forwarding to A-leg must rewrite both — From → A-leg's stored
    //   remote tag, AND To → A-leg's local tag (the one the receiving UA
    //   stores as its dialog's remote tag and matches in-dialog requests
    //   against). Without the To rewrite, the BYE we later build with
    //   a_leg.dialog.local_tag in From is rejected with 481.
    let mut msg = crate::sip::builder::SipMessageBuilder::new()
        .response(200, "OK".to_string())
        .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-test".to_string())
        .from("<sip:alice@example.com>;tag=b-leg-from-tag".to_string())
        .to("<sip:bob@example.com>;tag=gateway-far-end-tag".to_string())
        .call_id("b-leg-call-id".to_string())
        .cseq("1 INVITE".to_string())
        .content_length(0)
        .build()
        .unwrap();

    Dialog::rewrite_headers(
        &mut msg,
        "a-leg-call-id",
        "b-leg-from-tag",
        "a-leg-remote-tag",
        Some("a-leg-local-tag"),
    );

    assert_eq!(msg.headers.get("Call-ID").unwrap(), "a-leg-call-id");
    let from = msg.headers.get("From").unwrap();
    assert!(
        from.contains("tag=a-leg-remote-tag"),
        "From should have A-leg remote tag, got: {from}"
    );
    assert!(!from.contains("tag=b-leg-from-tag"));
    let to = msg.headers.get("To").unwrap();
    assert!(
        to.contains("tag=a-leg-local-tag"),
        "To should have A-leg local tag, got: {to}"
    );
    assert!(!to.contains("tag=gateway-far-end-tag"));
}

#[test]
fn dialog_rewrite_skips_to_when_no_existing_tag() {
    // 100 Trying / out-of-dialog responses without an early dialog must
    // not get a synthetic To-tag spliced in: passing Some(...) is a no-op
    // when the inbound message has no To-tag.
    let mut msg = crate::sip::builder::SipMessageBuilder::new()
        .response(100, "Trying".to_string())
        .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-test".to_string())
        .from("<sip:alice@example.com>;tag=from-tag".to_string())
        .to("<sip:bob@example.com>".to_string())
        .call_id("call-id".to_string())
        .cseq("1 INVITE".to_string())
        .content_length(0)
        .build()
        .unwrap();

    Dialog::rewrite_headers(
        &mut msg,
        "call-id",
        "from-tag",
        "from-tag",
        Some("would-be-synthetic-tag"),
    );

    let to = msg.headers.get("To").unwrap();
    assert!(
        !to.contains(";tag="),
        "tagless To must remain tagless, got: {to}"
    );
}

#[test]
fn dialog_rewrite_to_tag_none_leaves_to_alone() {
    // Original out-of-dialog INVITE retry path: caller passes None,
    // To header (whether tagged or not) is left untouched.
    let mut msg = crate::sip::builder::SipMessageBuilder::new()
        .response(200, "OK".to_string())
        .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-test".to_string())
        .from("<sip:alice@example.com>;tag=from-tag".to_string())
        .to("<sip:bob@example.com>;tag=to-tag-original".to_string())
        .call_id("call-id".to_string())
        .cseq("1 INVITE".to_string())
        .content_length(0)
        .build()
        .unwrap();

    Dialog::rewrite_headers(&mut msg, "call-id", "from-tag", "from-tag-new", None);

    let to = msg.headers.get("To").unwrap();
    assert!(
        to.contains("tag=to-tag-original"),
        "To should be untouched, got: {to}"
    );
}

// --- CallActor tests ---

#[test]
fn call_actor_create_and_add_b_legs() {
    let mut call = CallActor::new(make_a_leg());
    assert_eq!(call.state, CallState::Calling);
    assert!(call.b_legs.is_empty());

    let idx = call.add_b_leg(make_b_leg(0));
    assert_eq!(idx, 0);
    assert_eq!(call.b_legs.len(), 1);
    assert_eq!(call.b_leg_status[0], BLegStatus::Trying);
}

#[test]
fn call_actor_set_winner() {
    let mut call = CallActor::new(make_a_leg());
    call.add_b_leg(make_b_leg(0));
    call.add_b_leg(make_b_leg(1));

    call.set_winner(1);
    assert_eq!(call.state, CallState::Answered);
    assert_eq!(call.winner, Some(1));
    assert_eq!(call.b_leg_status[1], BLegStatus::Answered);
}

#[test]
fn call_actor_replace_b_leg_supersedes_in_place() {
    // 401/407/422 retry: the retry INVITE supersedes the failed leg at the
    // same index rather than appending a second leg. The parallel vectors
    // stay aligned, the slot's status resets to Trying, its actor handle is
    // cleared, and the old branch is returned for registry re-pointing.
    let mut call = CallActor::new(make_a_leg());
    call.add_b_leg(make_b_leg(0)); // CSeq-1 leg, branch z9hG4bK-bleg0
    call.add_b_leg(make_b_leg(1)); // an unrelated fork branch

    // The failed CSeq-1 leg got a final response, and we parked a handle on it.
    call.b_leg_status[0] = BLegStatus::Failed(401);
    let (tx, _rx) = tokio::sync::mpsc::channel::<LegMessage>(1);
    call.b_leg_handles[0] = Some(LegHandle {
        id: call.b_legs[0].id.clone(),
        side: LegSide::B,
        tx,
    });

    // Build the retry leg on a fresh branch and supersede index 0.
    let retry = Leg::new_b_leg(
        "b2b-bleg0".to_string(),
        "sb-bleg0".to_string(),
        "sip:bob0@10.0.0.2".to_string(),
        "z9hG4bK-bleg0-retry".to_string(),
        test_transport(),
    );
    let old_branch = call.replace_b_leg(0, retry);

    assert_eq!(old_branch.as_deref(), Some("z9hG4bK-bleg0"));
    assert_eq!(call.b_legs.len(), 2); // superseded, not appended
    assert_eq!(call.b_legs[0].branch, "z9hG4bK-bleg0-retry"); // live branch
    assert_eq!(call.b_leg_status[0], BLegStatus::Trying); // status reset
    assert!(call.b_leg_handles[0].is_none()); // old actor handle cleared
                                              // The unrelated fork branch at index 1 is untouched.
    assert_eq!(call.b_legs[1].branch, "z9hG4bK-bleg1");

    // Out-of-range supersede is a no-op returning None.
    assert_eq!(call.replace_b_leg(99, make_b_leg(7)), None);
    assert_eq!(call.b_legs.len(), 2);
}

#[test]
fn call_actor_losers() {
    let mut call = CallActor::new(make_a_leg());
    call.add_b_leg(make_b_leg(0));
    call.add_b_leg(make_b_leg(1));
    call.add_b_leg(make_b_leg(2));

    // Leg 1 answers
    call.set_winner(1);

    let losers = call.losers(1);
    assert_eq!(losers, vec![0, 2]);
}

#[test]
fn call_actor_should_teardown_on_winner_bye() {
    let mut call = CallActor::new(make_a_leg());
    call.add_b_leg(make_b_leg(0));
    call.add_b_leg(make_b_leg(1));
    call.set_winner(0);

    // BYE from winner should teardown
    assert!(call.should_teardown_on_b_bye(0));
    // BYE from non-winner should NOT teardown
    assert!(!call.should_teardown_on_b_bye(1));
}

#[test]
fn call_actor_all_failed() {
    let mut call = CallActor::new(make_a_leg());
    call.add_b_leg(make_b_leg(0));
    call.add_b_leg(make_b_leg(1));

    assert!(!call.all_b_legs_settled());

    call.mark_b_leg_failed(0, 486);
    assert!(!call.all_b_legs_settled());

    call.mark_b_leg_failed(1, 503);
    assert!(call.all_b_legs_settled());

    assert_eq!(call.best_error_code(), 503); // 5xx > 4xx
}

#[test]
fn call_actor_remove_b_leg_adjusts_winner() {
    let mut call = CallActor::new(make_a_leg());
    call.add_b_leg(make_b_leg(0));
    call.add_b_leg(make_b_leg(1));
    call.add_b_leg(make_b_leg(2));
    call.set_winner(2);

    // Remove leg 0 — winner should shift from 2 to 1
    call.remove_b_leg(0);
    assert_eq!(call.winner, Some(1));
    assert_eq!(call.b_legs.len(), 2);
}

// --- CallActorStore tests ---

#[test]
fn store_create_and_lookup() {
    let store = CallActorStore::new();
    let call_id = store.create_call(make_a_leg());

    assert_eq!(store.count(), 1);
    assert!(store.get_call(&call_id).is_some());
    assert_eq!(
        store.find_by_sip_call_id("call-1@10.0.0.1"),
        Some(call_id.clone())
    );
}

#[test]
fn store_add_b_leg_and_route() {
    let store = CallActorStore::new();
    let call_id = store.create_call(make_a_leg());
    let b_leg = make_b_leg(0);
    let branch = b_leg.branch.clone();

    assert!(store.add_b_leg(&call_id, b_leg));
    assert_eq!(store.call_id_for_branch(&branch), Some(call_id));
}

/// RFC 3261 §14.1 glare detection: take-and-set of the pending_reinvite
/// flag on the target leg. A second `set_pending_reinvite(_, _, true)`
/// against the same leg must return the previous `true` so the caller
/// knows another re-INVITE is already in flight and can reject with 491.
#[test]
fn pending_reinvite_flag_tracks_concurrent_reinvites() {
    let store = CallActorStore::new();
    let call_id = store.create_call(make_a_leg());
    store.add_b_leg(&call_id, make_b_leg(0));
    store.set_winner(&call_id, 0);

    // First re-INVITE toward B-leg: flag was false, is now true.
    assert!(!store.set_pending_reinvite(&call_id, /*on_a_leg=*/ false, true));
    // Second (glare): flag was already true.
    assert!(store.set_pending_reinvite(&call_id, /*on_a_leg=*/ false, true));
    // Clear on completion.
    assert!(store.set_pending_reinvite(&call_id, /*on_a_leg=*/ false, false));
    // Now a new re-INVITE can start.
    assert!(!store.set_pending_reinvite(&call_id, /*on_a_leg=*/ false, true));
}

/// The 2xx answer must be claimed atomically: the first `try_win` wins
/// (sets the winner + `Answered`), and every subsequent 2xx (retransmit or
/// losing fork branch) reports `AlreadyAnswered`. This is what stops two
/// concurrent B-leg 200s from both forwarding to the A-leg and delivering a
/// duplicate 200 to a caller that already ACKed.
#[test]
fn try_win_claims_the_answer_exactly_once() {
    let store = CallActorStore::new();
    let call_id = store.create_call(make_a_leg());
    store.add_b_leg(&call_id, make_b_leg(0));
    store.add_b_leg(&call_id, make_b_leg(1));

    // First 200 (B-leg 0) wins, setting winner + state atomically.
    assert_eq!(store.try_win(&call_id, 0), WinOutcome::FirstWin);
    {
        let call = store.get_call(&call_id).unwrap();
        assert_eq!(call.winner, Some(0));
        assert_eq!(call.state, CallState::Answered);
    }

    // A retransmit of the winner's 200 before the B-leg ACK went out:
    // already answered, absorb silently.
    assert_eq!(
        store.try_win(&call_id, 0),
        WinOutcome::AlreadyAnswered { b_leg_acked: false }
    );
    // A losing fork branch's 200 (B-leg 1): also already answered, not a win.
    assert_eq!(
        store.try_win(&call_id, 1),
        WinOutcome::AlreadyAnswered { b_leg_acked: false }
    );
    // The winner is unchanged (still B-leg 0).
    assert_eq!(store.get_call(&call_id).unwrap().winner, Some(0));

    // Once the winner's ACK has gone out, a further retransmit reports
    // acked=true so the caller re-ACKs to stop the UAS retransmitting.
    store.get_call_mut(&call_id).unwrap().b_legs[0].initial_acked = true;
    assert_eq!(
        store.try_win(&call_id, 0),
        WinOutcome::AlreadyAnswered { b_leg_acked: true }
    );
}

/// A 1xx provisional is forwarded (and moves Calling -> Ringing) until the
/// call is answered; a late provisional reordered behind its 200 is then
/// dropped and must NOT downgrade the confirmed dialog back to Ringing.
/// This is the atomic guard that stops a late 180 processed on another
/// worker from being forwarded to the A-leg after the final response.
#[test]
fn try_mark_ringing_drops_provisional_after_answer() {
    let store = CallActorStore::new();
    let call_id = store.create_call(make_a_leg());
    store.add_b_leg(&call_id, make_b_leg(0));

    // First 180: Calling -> Ringing, forward it.
    assert!(store.try_mark_ringing(&call_id));
    assert_eq!(store.get_call(&call_id).unwrap().state, CallState::Ringing);
    // A second 180 while Ringing: still forwarded, stays Ringing.
    assert!(store.try_mark_ringing(&call_id));
    assert_eq!(store.get_call(&call_id).unwrap().state, CallState::Ringing);

    // Answer the call.
    store.set_winner(&call_id, 0);
    assert_eq!(store.get_call(&call_id).unwrap().state, CallState::Answered);

    // A late 180 reordered behind the 200: dropped, dialog NOT downgraded.
    assert!(!store.try_mark_ringing(&call_id));
    assert_eq!(store.get_call(&call_id).unwrap().state, CallState::Answered);

    // A provisional for a call that no longer exists is dropped.
    assert!(!store.try_mark_ringing("nonexistent"));
}

/// The transferor may equally be the party siphon *called* — a callee
/// transferring a call it answered is the everyday case. Then the named
/// dialog is a B-leg, and the survivor is the A-leg.
#[test]
fn find_call_by_replaces_reports_a_b_leg_match() {
    let store = CallActorStore::new();
    let call_id = store.create_call(make_a_leg());
    let mut b_leg = make_b_leg(0);
    b_leg.dialog.remote_tag = Some("tag-callee".to_string());
    let b_call_id = b_leg.dialog.call_id.clone();
    let b_local_tag = b_leg.dialog.local_tag.clone();
    store.add_b_leg(&call_id, b_leg);
    store.set_winner(&call_id, 0);

    let matched = store.find_call_by_replaces_dialog(&b_call_id, "tag-callee", &b_local_tag);
    assert_eq!(
        matched,
        Some(ReplacesMatch {
            call_id,
            on_a_leg: false
        })
    );
}

#[test]
fn pending_replaces_round_trips_and_is_taken_once() {
    let store = CallActorStore::new();
    let call_id = store.create_call(make_a_leg());
    let pending = PendingReplaces {
        replaced_call_id: "other-call".to_string(),
        replaced_on_a_leg: true,
        early_only: false,
    };
    store.set_pending_replaces(&call_id, pending.clone());
    assert_eq!(store.take_pending_replaces(&call_id), Some(pending));
    // Taken once — a second admission pass must not re-run the takeover.
    assert_eq!(store.take_pending_replaces(&call_id), None);
}

/// The leg is moving to another call, not ending. If the detach retired its
/// Call-ID the ACK for the 200 it is about to receive would resolve to
/// nothing and be answered 481, and the new party would retransmit its way
/// to Timer B.
#[test]
fn detaching_a_leg_for_adoption_keeps_its_call_id_live() {
    let store = CallActorStore::new();
    let a_leg = make_a_leg();
    let sip_call_id = a_leg.dialog.call_id.clone();
    let call_id = store.create_call(a_leg);

    let detached = store.detach_a_leg_for_adoption(&call_id);
    assert!(detached.is_some());
    assert!(
        store.get_call(&call_id).is_none(),
        "the emptied call is dropped"
    );
    assert!(
        !store.is_recently_terminated(&sip_call_id),
        "the moving dialog must NOT be remembered as terminated"
    );
}

/// The transferor is the caller (its dialog is the A-leg): the new party
/// takes the A-leg slot and the callee carries on as the sole B-leg.
#[test]
fn adopting_a_replaced_a_leg_rebuilds_the_call_around_the_new_party() {
    let store = CallActorStore::new();
    let a_leg = make_a_leg();
    let replaced_sip_call_id = a_leg.dialog.call_id.clone();
    let call_id = store.create_call(a_leg);
    let mut b_leg = make_b_leg(0);
    b_leg.dialog.remote_tag = Some("tag-callee".to_string());
    let survivor_sip_call_id = b_leg.dialog.call_id.clone();
    store.add_b_leg(&call_id, b_leg);
    store.set_winner(&call_id, 0);

    let mut new_leg = make_a_leg();
    new_leg.dialog.call_id = "takeover@10.0.0.9".to_string();
    new_leg.branch = "z9hG4bK-takeover".to_string();

    let (replaced, survivor) = store
        .adopt_replaced_dialog(&call_id, true, new_leg)
        .expect("the swap must succeed on an answered call");

    assert_eq!(replaced.dialog.call_id, replaced_sip_call_id);
    assert_eq!(survivor.dialog.call_id, survivor_sip_call_id);

    let call = store.get_call(&call_id).unwrap();
    assert_eq!(call.a_leg.dialog.call_id, "takeover@10.0.0.9");
    assert_eq!(call.b_legs.len(), 1);
    assert_eq!(call.b_legs[0].dialog.call_id, survivor_sip_call_id);
    assert_eq!(call.winner, Some(0));
    assert_eq!(call.state, CallState::Answered);
    drop(call);

    // The new party's dialog resolves here — its ACK/BYE arrive on it.
    assert_eq!(
        store.find_by_sip_call_id("takeover@10.0.0.9").as_deref(),
        Some(call_id.as_str())
    );
    // The replaced dialog is retired: gone from the registry and remembered
    // terminated, so a late in-dialog request on it answers 481.
    assert!(store.find_by_sip_call_id(&replaced_sip_call_id).is_none());
    assert!(store.is_recently_terminated(&replaced_sip_call_id));
}

/// The transferor is the callee (its dialog is the winning B-leg): the new
/// party still lands in the A-leg slot — the inbound-ACK path only ever
/// marks `a_leg` — and the original caller moves across to be the B-leg.
#[test]
fn adopting_a_replaced_b_leg_moves_the_caller_to_the_b_slot() {
    let store = CallActorStore::new();
    let a_leg = make_a_leg();
    let caller_sip_call_id = a_leg.dialog.call_id.clone();
    let call_id = store.create_call(a_leg);
    let mut b_leg = make_b_leg(0);
    b_leg.dialog.remote_tag = Some("tag-callee".to_string());
    let replaced_sip_call_id = b_leg.dialog.call_id.clone();
    store.add_b_leg(&call_id, b_leg);
    store.set_winner(&call_id, 0);

    let mut new_leg = make_a_leg();
    new_leg.dialog.call_id = "takeover-b@10.0.0.9".to_string();
    new_leg.branch = "z9hG4bK-takeover-b".to_string();

    let (replaced, survivor) = store
        .adopt_replaced_dialog(&call_id, false, new_leg)
        .expect("the swap must succeed on an answered call");

    assert_eq!(replaced.dialog.call_id, replaced_sip_call_id);
    assert_eq!(survivor.dialog.call_id, caller_sip_call_id);

    let call = store.get_call(&call_id).unwrap();
    assert_eq!(call.a_leg.dialog.call_id, "takeover-b@10.0.0.9");
    assert_eq!(call.b_legs.len(), 1);
    assert_eq!(
        call.b_legs[0].dialog.call_id, caller_sip_call_id,
        "the original caller survives as the B-leg"
    );
    assert_eq!(call.winner, Some(0));
    drop(call);

    assert!(store.is_recently_terminated(&replaced_sip_call_id));
    assert!(
        !store.is_recently_terminated(&caller_sip_call_id),
        "the survivor's dialog is untouched"
    );
}

/// A call that never answered has no negotiated media and no answered party
/// to keep, so there is nothing to hand over.
#[test]
fn adopting_refuses_a_call_with_no_winner() {
    let store = CallActorStore::new();
    let call_id = store.create_call(make_a_leg());
    store.add_b_leg(&call_id, make_b_leg(0));

    let mut new_leg = make_a_leg();
    new_leg.dialog.call_id = "takeover-early@10.0.0.9".to_string();
    assert!(store
        .adopt_replaced_dialog(&call_id, true, new_leg)
        .is_none());
}

/// RFC 3891 §3 dialog lookup: find a call where one of its legs has
/// the dialog identifiers (call_id, local_tag, remote_tag) referenced
/// by a `Replaces` header.
#[test]
fn find_call_by_replaces_matches_a_leg() {
    let store = CallActorStore::new();
    let a_leg = make_a_leg();
    let dialog_call_id = a_leg.dialog.call_id.clone();
    let our_tag = a_leg.dialog.local_tag.clone();
    let their_tag = a_leg.dialog.remote_tag.clone().unwrap();
    let call_id = store.create_call(a_leg);

    // Replaces says: "the dialog you (siphon) have where YOU are tagged
    // `our_tag` and the OTHER end is tagged `their_tag`".
    let matched = store.find_call_by_replaces_dialog(&dialog_call_id, &their_tag, &our_tag);
    assert_eq!(
        matched,
        Some(ReplacesMatch {
            call_id,
            on_a_leg: true
        })
    );
}

#[test]
fn find_call_by_replaces_no_match_returns_none() {
    let store = CallActorStore::new();
    let _ = store.create_call(make_a_leg());

    let matched = store.find_call_by_replaces_dialog("bogus-call", "x", "y");
    assert_eq!(matched, None);
}

#[test]
fn find_call_by_replaces_wrong_tag_combo() {
    // Right call_id, wrong tag pair → no match (avoid false positives).
    let store = CallActorStore::new();
    let a_leg = make_a_leg();
    let dialog_call_id = a_leg.dialog.call_id.clone();
    let _ = store.create_call(a_leg);

    let matched = store.find_call_by_replaces_dialog(&dialog_call_id, "wrong-from", "wrong-to");
    assert_eq!(matched, None);
}

/// RFC 3262 auto-PRACK dedup: each new RSeq returns true once,
/// retransmits return false so we don't PRACK the same provisional twice.
#[test]
fn try_mark_prack_acked_dedupes() {
    let store = CallActorStore::new();
    let call_id = store.create_call(make_a_leg());
    store.add_b_leg(&call_id, make_b_leg(0));

    let tag = "uas-early-tag";
    assert!(store.try_mark_prack_acked(&call_id, 0, tag, 42));
    // Same RSeq again — already PRACKed, returns false.
    assert!(!store.try_mark_prack_acked(&call_id, 0, tag, 42));
    // Earlier RSeq (out-of-order retransmit) — also no PRACK.
    assert!(!store.try_mark_prack_acked(&call_id, 0, tag, 1));
    // Higher RSeq (next reliable 1xx, e.g. 180 after 183) — PRACK it.
    assert!(store.try_mark_prack_acked(&call_id, 0, tag, 43));
}

/// Forked early dialogs on ONE INVITE branch have independent RSeq spaces
/// (RFC 3262 §3) that commonly both start at 1. The dedup is keyed per
/// remote To-tag, so each dialog's RSeq 1 gets its own PRACK — the second
/// is NOT swallowed as a retransmit of the first.
#[test]
fn try_mark_prack_acked_per_early_dialog() {
    let store = CallActorStore::new();
    let call_id = store.create_call(make_a_leg());
    store.add_b_leg(&call_id, make_b_leg(0));

    // Two distinct early dialogs (two To-tags), each RSeq 1 → both PRACKed.
    assert!(store.try_mark_prack_acked(&call_id, 0, "tag-alpha", 1));
    assert!(store.try_mark_prack_acked(&call_id, 0, "tag-beta", 1));
    // Retransmit of each is still deduped independently.
    assert!(!store.try_mark_prack_acked(&call_id, 0, "tag-alpha", 1));
    assert!(!store.try_mark_prack_acked(&call_id, 0, "tag-beta", 1));
    // Each dialog advances its own RSeq independently.
    assert!(store.try_mark_prack_acked(&call_id, 0, "tag-alpha", 2));
    assert!(!store.try_mark_prack_acked(&call_id, 0, "tag-beta", 1));
}

/// 401/407 auth-retry dedup: the first challenge on a B-leg returns true
/// (drive the retry); every retransmit of that challenge on the same
/// branch returns false (absorb — ACK only, no second authenticated
/// INVITE → no 482 merged request). A chained re-challenge arrives on the
/// retry leg's own branch, which is a distinct B-leg that has not yet been
/// challenged, so it returns true once on its own.
#[test]
fn try_mark_auth_challenged_dedupes_per_leg() {
    let store = CallActorStore::new();
    let call_id = store.create_call(make_a_leg());
    store.add_b_leg(&call_id, make_b_leg(0));

    // First 401 on the original B-leg → retry.
    assert!(store.try_mark_auth_challenged(&call_id, 0));
    // Retransmitted 401 on the same branch → absorbed.
    assert!(!store.try_mark_auth_challenged(&call_id, 0));
    assert!(!store.try_mark_auth_challenged(&call_id, 0));

    // The auth retry adds a new B-leg with a fresh branch. A chained
    // re-challenge (stale nonce) on that leg is a legitimate new challenge.
    store.add_b_leg(&call_id, make_b_leg(1));
    assert!(store.try_mark_auth_challenged(&call_id, 1));
    assert!(!store.try_mark_auth_challenged(&call_id, 1));

    // Out-of-range index returns false (no leg to mark).
    assert!(!store.try_mark_auth_challenged(&call_id, 99));
}

/// The per-call credentialed-retry counter backs the dispatcher's auth
/// retry cap: it starts at 0, increments once per committed retry, and is
/// readable without mutation. Unknown calls read 0 and increment to 0.
#[test]
fn auth_retry_count_increments_and_caps() {
    let store = CallActorStore::new();
    let call_id = store.create_call(make_a_leg());

    assert_eq!(store.auth_retry_count(&call_id), 0);
    assert_eq!(store.incr_auth_retry_count(&call_id), 1);
    assert_eq!(store.incr_auth_retry_count(&call_id), 2);
    // Reading does not mutate.
    assert_eq!(store.auth_retry_count(&call_id), 2);
    assert_eq!(store.incr_auth_retry_count(&call_id), 3);

    // Unknown call: read 0, increment is a no-op returning 0.
    assert_eq!(store.auth_retry_count("nope"), 0);
    assert_eq!(store.incr_auth_retry_count("nope"), 0);
}

#[test]
fn next_b_leg_local_cseq_increments_per_call() {
    let store = CallActorStore::new();
    let call_id = store.create_call(make_a_leg());
    store.add_b_leg(&call_id, make_b_leg(0));

    // B-leg starts at local_cseq = 1 (the INVITE).
    assert_eq!(store.next_b_leg_local_cseq(&call_id, 0), Some(2));
    assert_eq!(store.next_b_leg_local_cseq(&call_id, 0), Some(3));
    assert_eq!(store.next_b_leg_local_cseq(&call_id, 0), Some(4));
    // Out-of-range index returns None.
    assert_eq!(store.next_b_leg_local_cseq(&call_id, 99), None);
}

#[test]
fn pending_reinvite_is_per_leg() {
    // A-leg and B-leg pending flags are independent — a re-INVITE in
    // flight toward the B-leg does NOT block a re-INVITE toward the
    // A-leg.
    let store = CallActorStore::new();
    let call_id = store.create_call(make_a_leg());
    store.add_b_leg(&call_id, make_b_leg(0));
    store.set_winner(&call_id, 0);

    assert!(!store.set_pending_reinvite(&call_id, false, true));
    // The A-leg flag should still be false.
    assert!(!store.set_pending_reinvite(&call_id, true, true));
}

#[test]
fn store_remove_cleans_registry() {
    let store = CallActorStore::new();
    let call_id = store.create_call(make_a_leg());
    let b_leg = make_b_leg(0);
    let b_branch = b_leg.branch.clone();
    let b_cid = b_leg.dialog.call_id.clone();
    store.add_b_leg(&call_id, b_leg);

    store.remove_call(&call_id);

    assert_eq!(store.count(), 0);
    assert!(store.call_id_for_branch(&b_branch).is_none());
    assert!(store.find_by_sip_call_id(&b_cid).is_none());
    assert!(store.find_by_sip_call_id("call-1@10.0.0.1").is_none());
}

#[test]
fn store_replace_b_leg_repoints_registry() {
    // Superseding a B-leg must move the routing registry from the old
    // branch to the retry branch: responses to the retry INVITE route to
    // this call, and the dead pre-auth branch no longer resolves (so a
    // stray retransmit on it can't re-enter the call with a stale leg).
    let store = CallActorStore::new();
    let call_id = store.create_call(make_a_leg());
    let original = make_b_leg(0);
    let old_branch = original.branch.clone();
    store.add_b_leg(&call_id, original);
    assert_eq!(store.call_id_for_branch(&old_branch), Some(call_id.clone()));

    let retry = Leg::new_b_leg(
        "b2b-bleg0".to_string(),
        "sb-bleg0".to_string(),
        "sip:bob0@10.0.0.2".to_string(),
        "z9hG4bK-bleg0-retry".to_string(),
        test_transport(),
    );
    assert!(store.replace_b_leg(&call_id, 0, retry));

    // Exactly one leg survives, on the retry branch.
    let call = store.get_call(&call_id).expect("call exists");
    assert_eq!(call.b_legs.len(), 1);
    assert_eq!(call.b_legs[0].branch, "z9hG4bK-bleg0-retry");
    drop(call);

    // Registry now resolves the retry branch, not the dead one.
    assert_eq!(
        store.call_id_for_branch("z9hG4bK-bleg0-retry"),
        Some(call_id.clone())
    );
    assert!(store.call_id_for_branch(&old_branch).is_none());

    // Superseding an unknown call or out-of-range index is a no-op.
    assert!(!store.replace_b_leg("nope", 0, make_b_leg(9)));
    assert!(!store.replace_b_leg(&call_id, 99, make_b_leg(9)));
}

#[test]
fn store_remove_call_after_cancel_zombifies_pending_legs() {
    // A CANCELled call's still-pending B-leg (INVITE on the wire, status
    // Trying) must survive teardown as a zombie-cancelled entry so a 2xx
    // that raced the CANCEL can be ACKed + BYEd. A leg whose INVITE never
    // went out (no stash) must not.
    let store = CallActorStore::new();
    let call_id = store.create_call(make_a_leg());

    let mut sent_leg = make_b_leg(0);
    let sent_cid = sent_leg.dialog.call_id.clone();
    let invite = crate::sip::builder::SipMessageBuilder::new()
        .request(
            crate::sip::message::Method::Invite,
            crate::sip::uri::SipUri::new("10.0.0.2".to_string()),
        )
        .via("SIP/2.0/UDP 10.0.0.9:5060;branch=z9hG4bK-b0".to_string())
        .from("<sip:alice@10.0.0.1>;tag=a".to_string())
        .to("<sip:bob@10.0.0.2>".to_string())
        .call_id(sent_cid.clone())
        .cseq("1 INVITE".to_string())
        .content_length(0)
        .build()
        .unwrap();
    sent_leg.b_leg_invite = Some(Arc::new(Mutex::new(invite)));
    store.add_b_leg(&call_id, sent_leg);

    // A second B-leg whose INVITE never went on the wire (no stash).
    let unsent_leg = make_b_leg(1);
    let unsent_cid = unsent_leg.dialog.call_id.clone();
    store.add_b_leg(&call_id, unsent_leg);

    let captured = store.remove_call_after_cancel(&call_id);
    assert!(captured, "the sent, still-pending leg should be zombified");
    assert_eq!(store.count(), 0, "the call itself is removed");

    // The sent leg resolves as a zombie; the unsent one does not.
    let (leg, first) = store
        .zombie_cancelled_for_2xx(&sent_cid)
        .expect("zombie present for the sent leg");
    assert!(first, "the first racing 2xx triggers ACK + BYE");
    assert_eq!(leg.dialog.call_id, sent_cid);
    assert!(store.zombie_cancelled_for_2xx(&unsent_cid).is_none());

    // A retransmitted 2xx for the same Call-ID re-ACKs only (no second BYE).
    let (_leg, second) = store
        .zombie_cancelled_for_2xx(&sent_cid)
        .expect("entry stays until the 32s cleanup");
    assert!(!second, "a retransmit must not trigger a second BYE");
}

/// The ORDINARY outcome of a CANCEL, not the glare one: the peer answers
/// the CANCELled INVITE `487 Request Terminated` (RFC 3261 §9.1), and
/// §17.1.1.3 requires an ACK for it. The call is gone by then, so the ACK
/// can only be built from the zombie entry — which therefore has to carry
/// the CANCELled INVITE's Request-URI (§17.1.1.3: the ACK's Request-URI
/// equals the INVITE's).
#[test]
fn store_zombie_captures_the_invite_ruri_so_the_487_can_be_acked() {
    let store = CallActorStore::new();
    let call_id = store.create_call(make_a_leg());

    let mut sent_leg = make_b_leg(0);
    let sent_cid = sent_leg.dialog.call_id.clone();
    let invite = crate::sip::builder::SipMessageBuilder::new()
        .request(
            crate::sip::message::Method::Invite,
            crate::sip::uri::SipUri::new("198.51.100.20".to_string())
                .with_user("bob".to_string())
                .with_port(5060),
        )
        .via("SIP/2.0/UDP 198.51.100.10:5060;branch=z9hG4bK-bleg0".to_string())
        .from("<sip:alice@198.51.100.10>;tag=a".to_string())
        .to("<sip:bob@198.51.100.20>".to_string())
        .call_id(sent_cid.clone())
        .cseq("1 INVITE".to_string())
        .content_length(0)
        .build()
        .unwrap();
    sent_leg.b_leg_invite = Some(Arc::new(Mutex::new(invite)));
    store.add_b_leg(&call_id, sent_leg);

    // A leg whose INVITE never went on the wire draws no final response, so
    // it is not captured and nothing is owed an ACK.
    let unsent_leg = make_b_leg(1);
    let unsent_cid = unsent_leg.dialog.call_id.clone();
    store.add_b_leg(&call_id, unsent_leg);

    assert!(store.remove_call_after_cancel(&call_id));

    let (leg, ruri) = store
        .zombie_cancelled_for_non2xx(&sent_cid)
        .expect("the CANCELled leg must still resolve for its 487");
    assert_eq!(leg.dialog.call_id, sent_cid);
    // The ACK goes out on the INVITE's own branch (§17.1.1.3), which is the
    // leg's branch — not a fresh one.
    assert_eq!(leg.branch, "z9hG4bK-bleg0");
    assert_eq!(ruri.as_deref(), Some("sip:bob@198.51.100.20:5060"));
    assert!(store.zombie_cancelled_for_non2xx(&unsent_cid).is_none());

    // §17.1.1.3 has the client transaction re-pass the ACK to the transport
    // on EVERY retransmission of the final response while it sits in
    // Completed — so the lookup must keep resolving, not consume the entry.
    assert!(
        store.zombie_cancelled_for_non2xx(&sent_cid).is_some(),
        "a retransmitted 487 must still be ACKable"
    );

    // ...and it must not have consumed the glare path's first-2xx flag: a
    // 487 followed by a raced 2xx (both are possible on a forked downstream)
    // must still produce ACK + BYE for the 2xx.
    let (_leg, first_2xx) = store
        .zombie_cancelled_for_2xx(&sent_cid)
        .expect("the glare entry survives a 487 lookup");
    assert!(
        first_2xx,
        "ACKing a 487 must not consume the BYE the glare 2xx path owes"
    );
}

#[test]
fn store_sweep_stale() {
    let store = CallActorStore::new();
    store.create_call(make_a_leg());
    assert_eq!(store.sweep_stale(std::time::Duration::from_secs(60)), 0);
    assert_eq!(store.sweep_stale(std::time::Duration::ZERO), 1);
    assert_eq!(store.count(), 0);
}

/// The dispatcher parks its B-leg event receivers in a map keyed by call id
/// and reaps them by asking whether the call is still live. Two things ride
/// on that: a receiver for a reaped call holds a whole 64-slot channel of
/// `CallEvent`s forever, and — because the leg actors send on that channel
/// with an unbounded await — a full channel parks the actor until something
/// drops the receiver.
///
/// So this asserts both halves: the reaped call is gone from the store, and
/// an actor already parked on a full channel is released once the receiver
/// the sweep would drop is dropped.
#[tokio::test]
async fn a_reaped_call_releases_an_actor_parked_on_its_event_channel() {
    let store = CallActorStore::new();
    let call_id = store.create_call(make_a_leg());
    assert!(
        store.contains_call(&call_id),
        "a fresh call is live, so its receiver must be kept"
    );

    // One slot, already full: the next send parks, exactly as a leg actor
    // does when the dispatcher has not drained the channel.
    let (event_tx, event_rx) = tokio::sync::mpsc::channel::<u8>(1);
    event_tx.send(1).await.expect("first send fits");
    let parked = tokio::spawn(async move { event_tx.send(2).await });
    tokio::task::yield_now().await;
    assert!(!parked.is_finished(), "the second send must be parked");

    // The sweep's rule: no call, no receiver.
    store.sweep_stale(std::time::Duration::ZERO);
    assert!(!store.contains_call(&call_id), "the call was reaped");
    let receivers = dashmap::DashMap::new();
    receivers.insert(call_id.clone(), event_rx);
    receivers.retain(|id: &String, _| store.contains_call(id));
    assert!(
        receivers.is_empty(),
        "a receiver whose call is gone must be reaped — it holds a whole \
         channel of events, and the actor parked on it, for the life of the \
         process"
    );

    let outcome = tokio::time::timeout(std::time::Duration::from_secs(5), parked)
        .await
        .expect("dropping the receiver must release the parked actor")
        .expect("the sending task did not panic");
    assert!(
        outcome.is_err(),
        "the parked send must complete as Closed once the receiver is gone"
    );
}

#[test]
fn take_timed_out_calls_only_unanswered_past_deadline() {
    // The answer-timeout sweep must select only calls that are still
    // un-answered AND past their deadline — never an answered call, a call
    // whose deadline is in the future, or one with no deadline. And it must
    // not remove anything (the dispatcher runs the teardown).
    let store = CallActorStore::new();
    let now = std::time::Instant::now();
    let past = now - std::time::Duration::from_secs(1);
    let future = now + std::time::Duration::from_secs(60);

    // Un-answered (Calling), deadline already passed → timed out.
    let stuck = store.create_call(make_a_leg());
    store.set_answer_deadline(&stuck, past);

    // Un-answered, deadline still in the future → not yet.
    let waiting = store.create_call(make_a_leg());
    store.set_answer_deadline(&waiting, future);

    // Answered, deadline passed → never (it answered; lives until BYE).
    let answered = store.create_call(make_a_leg());
    store.set_answer_deadline(&answered, past);
    store.add_b_leg(&answered, make_b_leg(0));
    store.set_winner(&answered, 0);

    // No deadline → only the 24h orphan backstop applies.
    let no_deadline = store.create_call(make_a_leg());

    let timed_out = store.take_timed_out_calls(now);
    assert_eq!(timed_out, vec![stuck.clone()]);
    // Nothing was removed.
    assert_eq!(store.count(), 4);
    let _ = (waiting, answered, no_deadline);
}

/// Answer a call the way the winning-B-leg 2xx does (`try_win` →
/// `set_winner`), which is the path that has to stamp `answered_at`.
fn answer_call(store: &CallActorStore, call_id: &str) {
    store.add_b_leg(call_id, make_b_leg(0));
    store.set_winner(call_id, 0);
}

/// Backdate a call's answer so the maximum-duration sweep sees it as having
/// been up for `elapsed`, without sleeping in a unit test.
fn backdate_answer(store: &CallActorStore, call_id: &str, elapsed: std::time::Duration) {
    let mut call = store.get_call_mut(call_id).expect("call exists");
    let answered_at = call.answered_at.expect("call was answered");
    call.answered_at = Some(answered_at - elapsed);
}

#[test]
fn answering_stamps_answered_at_once_and_never_moves_it() {
    // The stamp is the anchor the maximum-duration cap measures from, so a
    // call that re-enters Answered — a re-INVITE, a promoted leg
    // replacement — must not get a fresh clock, or a call kept busy with
    // re-INVITEs would never hit its cap.
    let store = CallActorStore::new();

    let call_id = store.create_call(make_a_leg());
    assert!(
        store
            .get_call(&call_id)
            .and_then(|c| c.answered_at)
            .is_none(),
        "an un-answered call has no answer stamp"
    );

    answer_call(&store, &call_id);
    let first = store
        .get_call(&call_id)
        .and_then(|c| c.answered_at)
        .expect("answering stamps answered_at");

    // Re-entering Answered from either direction leaves the stamp alone.
    store.set_state(&call_id, CallState::Answered);
    store.set_winner(&call_id, 0);
    assert_eq!(
        store.get_call(&call_id).and_then(|c| c.answered_at),
        Some(first),
        "the answer stamp must not move once set"
    );
}

#[test]
fn uas_mode_answer_also_stamps_answered_at() {
    // A call answered by the script itself (`call.answer()`) or by an
    // originate's 2xx never goes through set_winner — it flips state
    // through the store. It must be capped like any other answered call.
    let store = CallActorStore::new();
    let call_id = store.create_call(make_a_leg());

    store.set_state(&call_id, CallState::Answered);

    assert!(
        store
            .get_call(&call_id)
            .and_then(|c| c.answered_at)
            .is_some(),
        "a UAS-mode answer must stamp answered_at too"
    );
}

#[test]
fn take_calls_over_max_duration_only_answered_calls_past_their_cap() {
    // The answered-call counterpart of the answer-timeout sweep: it must
    // select only calls that ANSWERED and have been up longer than their
    // own cap, and must not remove anything (the dispatcher runs the real
    // teardown: BYE both legs, charging stop, CDR, media release).
    let store = CallActorStore::new();
    let now = std::time::Instant::now();

    // Answered 61s ago with a 60s cap → over.
    let over = store.create_call(make_a_leg());
    answer_call(&store, &over);
    backdate_answer(&store, &over, std::time::Duration::from_secs(61));
    store
        .get_call_mut(&over)
        .expect("call exists")
        .max_duration_secs = Some(60);

    // Answered 61s ago with a 3600s cap → still inside it.
    let inside = store.create_call(make_a_leg());
    answer_call(&store, &inside);
    backdate_answer(&store, &inside, std::time::Duration::from_secs(61));
    store
        .get_call_mut(&inside)
        .expect("call exists")
        .max_duration_secs = Some(3600);

    // Never answered → the answer-timeout sweep's business, not this one.
    // A ringing call has no answered_at at all, so a cap on it is inert.
    let ringing = store.create_call(make_a_leg());
    store.set_state(&ringing, CallState::Ringing);
    store
        .get_call_mut(&ringing)
        .expect("call exists")
        .max_duration_secs = Some(1);

    // Answered, no cap and no configured default → uncapped.
    let uncapped = store.create_call(make_a_leg());
    answer_call(&store, &uncapped);
    backdate_answer(&store, &uncapped, std::time::Duration::from_secs(86_400));

    assert_eq!(store.take_calls_over_max_duration(now, None), vec![over]);
    assert_eq!(store.count(), 4, "the sweep must not remove anything");
    let _ = (inside, ringing, uncapped);
}

#[test]
fn max_duration_falls_back_to_the_configured_default() {
    // `b2bua.max_call_duration_secs` is the operator's backstop for every
    // call that didn't ask for its own — including one answered in UAS mode
    // that never dialled anything.
    let store = CallActorStore::new();
    let now = std::time::Instant::now();

    let call_id = store.create_call(make_a_leg());
    answer_call(&store, &call_id);
    backdate_answer(&store, &call_id, std::time::Duration::from_secs(120));

    assert!(
        store.take_calls_over_max_duration(now, None).is_empty(),
        "no per-call cap and no default means uncapped"
    );
    assert!(
        store
            .take_calls_over_max_duration(now, Some(300))
            .is_empty(),
        "a default the call has not reached yet leaves it alone"
    );
    assert_eq!(
        store.take_calls_over_max_duration(now, Some(60)),
        vec![call_id],
        "a call past the configured default is cut"
    );
}

#[test]
fn per_call_max_duration_overrides_the_default_in_both_directions() {
    // Both directions matter: a script tightening the ceiling for one call,
    // and `max_duration=0` opting a call out of a configured ceiling
    // entirely (a supervised conference, a long-running trunk session).
    let store = CallActorStore::new();
    let now = std::time::Instant::now();

    // Tighter than the default → cut by its own cap.
    let tighter = store.create_call(make_a_leg());
    answer_call(&store, &tighter);
    backdate_answer(&store, &tighter, std::time::Duration::from_secs(120));
    store
        .get_call_mut(&tighter)
        .expect("call exists")
        .max_duration_secs = Some(60);

    // Explicitly uncapped → survives a default it is far past.
    let opted_out = store.create_call(make_a_leg());
    answer_call(&store, &opted_out);
    backdate_answer(&store, &opted_out, std::time::Duration::from_secs(86_400));
    store
        .get_call_mut(&opted_out)
        .expect("call exists")
        .max_duration_secs = Some(0);

    assert_eq!(
        store.take_calls_over_max_duration(now, Some(3600)),
        vec![tighter],
        "max_duration=0 must beat a configured ceiling"
    );
    let _ = opted_out;
}

fn replacement(
    target_leg_call_id: Option<&str>,
    deadline: Option<std::time::Instant>,
    siphon_notifies: bool,
) -> ReferSubscription {
    ReferSubscription {
        on_a_leg: true,
        siphon_notifies,
        origin: ReplacementOrigin::SiphonInitiated,
        event_id: 0,
        notify_cseq: 0,
        state: TransferState::Trying,
        target_leg_call_id: target_leg_call_id.map(str::to_string),
        referrer_gone: false,
        deadline,
        media_profile: None,
    }
}

#[test]
fn take_timed_out_replacements_selects_only_a_live_target_past_its_deadline() {
    // A replacement runs on an ANSWERED call, which take_timed_out_calls
    // filters out by design — so without this sweep a target that never
    // sends a final response leaves the replacement armed for the life of
    // the call and the survivor bridged to nobody. It must be as narrow as
    // its sibling: only a notifier-role replacement, that actually dialed
    // something, whose deadline has passed.
    let store = CallActorStore::new();
    let now = std::time::Instant::now();
    let past = now - std::time::Duration::from_secs(1);
    let future = now + std::time::Duration::from_secs(60);

    // Dialed a target, deadline passed → swept, even though the call is
    // Answered (which is the whole point).
    let stuck = store.create_call(make_a_leg());
    store.set_state(&stuck, CallState::Answered);
    store.push_refer_subscription(&stuck, replacement(Some("target-1@host"), Some(past), true));

    // Deadline still in the future → not yet.
    let ringing = store.create_call(make_a_leg());
    store.push_refer_subscription(
        &ringing,
        replacement(Some("target-2@host"), Some(future), true),
    );

    // No deadline → waits indefinitely, as before this existed.
    let unbounded = store.create_call(make_a_leg());
    store.push_refer_subscription(&unbounded, replacement(Some("target-3@host"), None, true));

    // Subscriber role (`call.refer()`): siphon dialed nothing and is
    // waiting on the far end's NOTIFYs, so there is no leg to cancel.
    let subscriber = store.create_call(make_a_leg());
    store.push_refer_subscription(
        &subscriber,
        replacement(Some("target-4@host"), Some(past), false),
    );

    // Notifier whose dial never left the box: no target leg to cancel, and
    // the subscription is already inert.
    let undialed = store.create_call(make_a_leg());
    store.push_refer_subscription(&undialed, replacement(None, Some(past), true));

    let swept = store.take_timed_out_replacements(now);
    assert_eq!(swept, vec![(stuck.clone(), "target-1@host".to_string())]);
    // Nothing was removed — the dispatcher owns the teardown.
    assert_eq!(store.count(), 5);
    let _ = (ringing, unbounded, subscriber, undialed);
}

// --- LegRegistry tests ---

fn originated_refer(call_id: &str) -> OriginatedRefer {
    OriginatedRefer {
        call_id: call_id.to_string(),
        on_a_leg: true,
        target_uri: "sip:caller@198.51.100.10:5060".to_string(),
        refer_to: crate::sip::headers::refer::ReferTo {
            uri: "sip:agent@pbx.example.com".to_string(),
            replaces: None,
        },
        auth_retries: 0,
    }
}

#[test]
fn originated_refer_is_matched_by_branch_and_taken_once() {
    // A REFER siphon originates carries a branch belonging to no leg, so it
    // is tracked separately; its final response ends the transaction and
    // must consume the entry (a non-INVITE transaction has exactly one).
    let store = CallActorStore::new();
    let call_id = store.create_call(make_a_leg());
    store.register_originated_refer("z9hG4bK-refer-1", originated_refer(&call_id));

    assert!(store.lookup_originated_refer("z9hG4bK-refer-1").is_some());
    let taken = store.take_originated_refer("z9hG4bK-refer-1").unwrap();
    assert_eq!(taken.call_id, call_id);
    assert!(taken.on_a_leg);
    assert_eq!(taken.refer_to.uri, "sip:agent@pbx.example.com");
    // Gone: a retransmitted final must not drive a second retry.
    assert!(store.take_originated_refer("z9hG4bK-refer-1").is_none());
}

#[test]
fn originated_refer_does_not_leak_into_the_leg_branch_index() {
    // Registering it in `by_branch` would send the REFER's 401 down the
    // INVITE/B-leg response path, which ACKs a non-2xx — wrong for a
    // non-INVITE transaction (RFC 3261 §17.1.2).
    let store = CallActorStore::new();
    let call_id = store.create_call(make_a_leg());
    store.register_originated_refer("z9hG4bK-refer-2", originated_refer(&call_id));
    assert!(store.call_id_for_branch("z9hG4bK-refer-2").is_none());
}

#[test]
fn originated_refer_is_dropped_when_its_call_goes_away() {
    // A call that is gone cannot be transferred; leaving the entry would
    // leak one per abandoned transfer.
    let store = CallActorStore::new();
    let call_id = store.create_call(make_a_leg());
    store.register_originated_refer("z9hG4bK-refer-3", originated_refer(&call_id));
    store.remove_call(&call_id);
    assert!(store.lookup_originated_refer("z9hG4bK-refer-3").is_none());
}

#[test]
fn registry_basic() {
    let reg = LegRegistry::new();
    reg.register_call_id("call-1@host", "internal-1");
    reg.register_branch("z9hG4bK-test", "internal-1");

    assert_eq!(
        reg.lookup_call_id("call-1@host"),
        Some("internal-1".to_string())
    );
    assert_eq!(
        reg.lookup_branch("z9hG4bK-test"),
        Some("internal-1".to_string())
    );
    assert!(reg.lookup_call_id("nonexistent").is_none());

    reg.remove_call_id("call-1@host");
    assert!(reg.lookup_call_id("call-1@host").is_none());
}

// --- Extract tag test ---

#[test]
fn extract_to_tag_from_response() {
    let msg = crate::sip::builder::SipMessageBuilder::new()
        .response(200, "OK".to_string())
        .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-test".to_string())
        .from("<sip:alice@atlanta.com>;tag=abc".to_string())
        .to("<sip:bob@biloxi.com>;tag=xyz".to_string())
        .call_id("test@host".to_string())
        .cseq("1 INVITE".to_string())
        .content_length(0)
        .build()
        .unwrap();

    assert_eq!(extract_to_tag(&msg), Some("xyz".to_string()));
}

// --- B-leg handle tracking ---

#[test]
fn call_actor_b_leg_handles_parallel_with_b_legs() {
    let mut call = CallActor::new(make_a_leg());
    assert!(call.b_leg_handles.is_empty());

    call.add_b_leg(make_b_leg(0));
    call.add_b_leg(make_b_leg(1));
    assert_eq!(call.b_leg_handles.len(), 2);
    assert!(call.b_leg_handles[0].is_none());
    assert!(call.b_leg_handles[1].is_none());

    // Set a handle for leg 1
    let (call_tx, _call_rx) = tokio::sync::mpsc::channel(16);
    let (_, handle) = LegActor::new(make_b_leg(1), call_tx);
    call.set_b_leg_handle(1, handle);
    assert!(call.b_leg_handles[0].is_none());
    assert!(call.b_leg_handles[1].is_some());

    // Remove leg 0 — handle vector stays in sync
    call.remove_b_leg(0);
    assert_eq!(call.b_leg_handles.len(), 1);
    assert!(call.b_leg_handles[0].is_some());
}

// --- LegActor async tests ---

#[tokio::test]
async fn leg_actor_lifecycle() {
    let (call_tx, mut call_rx) = tokio::sync::mpsc::channel(16);
    let leg = make_b_leg(0);
    let leg_id = leg.id.clone();

    let (actor, handle) = LegActor::new(leg, call_tx);
    let join = tokio::spawn(actor.run());

    handle.tx.send(LegMessage::Shutdown).await.unwrap();
    join.await.unwrap();

    let event = call_rx.recv().await.unwrap();
    match event {
        CallEvent::Terminated { leg_id: id } => assert_eq!(id, leg_id),
        _ => panic!("expected Terminated event"),
    }
}

#[tokio::test]
async fn leg_actor_classifies_200_ok_as_answered() {
    let (call_tx, mut call_rx) = tokio::sync::mpsc::channel(16);
    let leg = make_b_leg(0);
    let leg_id = leg.id.clone();

    let (actor, handle) = LegActor::new(leg, call_tx);
    let join = tokio::spawn(actor.run());

    // Send a 200 OK response to the actor
    let response = crate::sip::builder::SipMessageBuilder::new()
        .response(200, "OK".to_string())
        .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-test".to_string())
        .from("<sip:alice@atlanta.com>;tag=abc".to_string())
        .to("<sip:bob@biloxi.com>;tag=xyz".to_string())
        .call_id("b2b-bleg0".to_string())
        .cseq("1 INVITE".to_string())
        .content_length(0)
        .build()
        .unwrap();
    handle
        .tx
        .send(LegMessage::SipInbound {
            message: response,
            source: test_transport(),
        })
        .await
        .unwrap();

    let event = call_rx.recv().await.unwrap();
    match event {
        CallEvent::Answered { leg_id: id, .. } => assert_eq!(id, leg_id),
        other => panic!("expected Answered, got {:?}", other),
    }

    // Shut down
    handle.tx.send(LegMessage::Shutdown).await.unwrap();
    join.await.unwrap();
}

#[tokio::test]
async fn leg_actor_classifies_486_as_failed() {
    let (call_tx, mut call_rx) = tokio::sync::mpsc::channel(16);
    let leg = make_b_leg(0);
    let leg_id = leg.id.clone();

    let (actor, handle) = LegActor::new(leg, call_tx);
    let join = tokio::spawn(actor.run());

    let response = crate::sip::builder::SipMessageBuilder::new()
        .response(486, "Busy Here".to_string())
        .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-test".to_string())
        .from("<sip:alice@atlanta.com>;tag=abc".to_string())
        .to("<sip:bob@biloxi.com>;tag=xyz".to_string())
        .call_id("b2b-bleg0".to_string())
        .cseq("1 INVITE".to_string())
        .content_length(0)
        .build()
        .unwrap();
    handle
        .tx
        .send(LegMessage::SipInbound {
            message: response,
            source: test_transport(),
        })
        .await
        .unwrap();

    let event = call_rx.recv().await.unwrap();
    match event {
        CallEvent::Failed {
            leg_id: id,
            status_code,
            ..
        } => {
            assert_eq!(id, leg_id);
            assert_eq!(status_code, 486);
        }
        other => panic!("expected Failed, got {:?}", other),
    }

    handle.tx.send(LegMessage::Shutdown).await.unwrap();
    join.await.unwrap();
}

#[tokio::test]
async fn leg_actor_classifies_180_as_provisional() {
    let (call_tx, mut call_rx) = tokio::sync::mpsc::channel(16);
    let leg = make_b_leg(0);
    let leg_id = leg.id.clone();

    let (actor, handle) = LegActor::new(leg, call_tx);
    let join = tokio::spawn(actor.run());

    let response = crate::sip::builder::SipMessageBuilder::new()
        .response(180, "Ringing".to_string())
        .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-test".to_string())
        .from("<sip:alice@atlanta.com>;tag=abc".to_string())
        .to("<sip:bob@biloxi.com>;tag=xyz".to_string())
        .call_id("b2b-bleg0".to_string())
        .cseq("1 INVITE".to_string())
        .content_length(0)
        .build()
        .unwrap();
    handle
        .tx
        .send(LegMessage::SipInbound {
            message: response,
            source: test_transport(),
        })
        .await
        .unwrap();

    let event = call_rx.recv().await.unwrap();
    match event {
        CallEvent::Provisional {
            leg_id: id,
            status_code,
            ..
        } => {
            assert_eq!(id, leg_id);
            assert_eq!(status_code, 180);
        }
        other => panic!("expected Provisional, got {:?}", other),
    }

    handle.tx.send(LegMessage::Shutdown).await.unwrap();
    join.await.unwrap();
}

#[tokio::test]
async fn leg_actor_cancel_stops_loop() {
    let (call_tx, mut call_rx) = tokio::sync::mpsc::channel(16);
    let leg = make_b_leg(0);
    let leg_id = leg.id.clone();

    let (actor, handle) = LegActor::new(leg, call_tx);
    let join = tokio::spawn(actor.run());

    handle.tx.send(LegMessage::Cancel).await.unwrap();
    join.await.unwrap();

    let event = call_rx.recv().await.unwrap();
    match event {
        CallEvent::Terminated { leg_id: id } => assert_eq!(id, leg_id),
        other => panic!("expected Terminated, got {:?}", other),
    }
}

#[tokio::test]
async fn leg_actor_classifies_bye_request() {
    use crate::sip::message::Method;

    let (call_tx, mut call_rx) = tokio::sync::mpsc::channel(16);
    let leg = make_b_leg(0);
    let leg_id = leg.id.clone();

    let (actor, handle) = LegActor::new(leg, call_tx);
    let join = tokio::spawn(actor.run());

    let bye = crate::sip::builder::SipMessageBuilder::new()
        .request(
            Method::Bye,
            crate::sip::uri::SipUri::new("10.0.0.2".to_string()).with_port(5060),
        )
        .via("SIP/2.0/UDP 10.0.0.2:5060;branch=z9hG4bK-bye".to_string())
        .from("<sip:bob@biloxi.com>;tag=xyz".to_string())
        .to("<sip:alice@atlanta.com>;tag=abc".to_string())
        .call_id("b2b-bleg0".to_string())
        .cseq("2 BYE".to_string())
        .content_length(0)
        .build()
        .unwrap();
    handle
        .tx
        .send(LegMessage::SipInbound {
            message: bye,
            source: test_transport(),
        })
        .await
        .unwrap();

    let event = tokio::time::timeout(std::time::Duration::from_secs(2), call_rx.recv())
        .await
        .unwrap()
        .unwrap();
    match event {
        CallEvent::Bye {
            leg_id: id,
            from_side,
            ..
        } => {
            assert_eq!(id, leg_id);
            assert_eq!(from_side, LegSide::B);
        }
        other => panic!("expected Bye, got {:?}", other),
    }

    handle.tx.send(LegMessage::Shutdown).await.unwrap();
    join.await.unwrap();
}

#[tokio::test]
async fn leg_actor_classifies_reinvite_request() {
    use crate::sip::message::Method;

    let (call_tx, mut call_rx) = tokio::sync::mpsc::channel(16);
    let leg = make_b_leg(0);
    let leg_id = leg.id.clone();

    let (actor, handle) = LegActor::new(leg, call_tx);
    let join = tokio::spawn(actor.run());

    let reinvite = crate::sip::builder::SipMessageBuilder::new()
        .request(
            Method::Invite,
            crate::sip::uri::SipUri::new("10.0.0.2".to_string()).with_port(5060),
        )
        .via("SIP/2.0/UDP 10.0.0.2:5060;branch=z9hG4bK-reinv".to_string())
        .from("<sip:bob@biloxi.com>;tag=xyz".to_string())
        .to("<sip:alice@atlanta.com>;tag=abc".to_string())
        .call_id("b2b-bleg0".to_string())
        .cseq("2 INVITE".to_string())
        .content_length(0)
        .build()
        .unwrap();
    handle
        .tx
        .send(LegMessage::SipInbound {
            message: reinvite,
            source: test_transport(),
        })
        .await
        .unwrap();

    let event = tokio::time::timeout(std::time::Duration::from_secs(2), call_rx.recv())
        .await
        .unwrap()
        .unwrap();
    match event {
        CallEvent::ReInvite { leg_id: id, .. } => assert_eq!(id, leg_id),
        other => panic!("expected ReInvite, got {:?}", other),
    }

    handle.tx.send(LegMessage::Shutdown).await.unwrap();
    join.await.unwrap();
}

// --- rewrite_uri_host tests ---

#[test]
fn rewrite_uri_host_standard_from() {
    let from = "<sip:alice@10.0.0.1:5060>;tag=abc123";
    let result = rewrite_uri_host(from, "203.0.113.1");
    assert_eq!(result, "<sip:alice@203.0.113.1:5060>;tag=abc123");
}

#[test]
fn rewrite_uri_host_no_port() {
    let from = "<sip:alice@10.0.0.1>;tag=abc123";
    let result = rewrite_uri_host(from, "sbc.example.com");
    assert_eq!(result, "<sip:alice@sbc.example.com>;tag=abc123");
}

#[test]
fn rewrite_uri_host_with_params() {
    let from = "<sip:alice@10.0.0.1;transport=udp>;tag=abc123";
    let result = rewrite_uri_host(from, "203.0.113.1");
    assert_eq!(result, "<sip:alice@203.0.113.1;transport=udp>;tag=abc123");
}

#[test]
fn rewrite_uri_host_display_name() {
    let from = "\"Alice\" <sip:alice@192.168.1.1:5060>;tag=xyz";
    let result = rewrite_uri_host(from, "pub.example.com");
    assert_eq!(result, "\"Alice\" <sip:alice@pub.example.com:5060>;tag=xyz");
}

#[test]
fn rewrite_uri_host_no_at_sign() {
    let from = "<sip:192.168.1.1:5060>;tag=abc";
    let result = rewrite_uri_host(from, "203.0.113.1");
    // No @ sign — should return unchanged
    assert_eq!(result, from);
}

#[test]
fn rewrite_uri_host_pai_with_display() {
    let pai = "\"Outbound Call\" <sip:alice@10.0.0.5>";
    let result = rewrite_uri_host(pai, "203.0.113.5");
    assert_eq!(result, "\"Outbound Call\" <sip:alice@203.0.113.5>");
}

// --- rewrite_uri_authority tests ---

#[test]
fn rewrite_uri_authority_replaces_host_and_port() {
    // Regression: the original To carried siphon's inbound port (:5061)
    // leaked from the A-leg.  Topology-hiding the To to a dial target that
    // itself carries a port must replace host AND port — replacing host
    // only left the old port and produced `host:5060:5061` (double port),
    // which the SBC rejected as 400 Wrong URI.
    let to = "<sip:bob@pcscf.example.com:5061;user=phone>";
    let result = rewrite_uri_authority(to, "trunk.example.com:5060");
    assert_eq!(result, "<sip:bob@trunk.example.com:5060;user=phone>");
    // No double port anywhere in the result.
    assert!(!result.contains(":5060:"));
    assert!(!result.contains("5060:5061"));
}

#[test]
fn rewrite_uri_authority_drops_old_port_when_target_has_none() {
    let to = "<sip:bob@10.0.0.1:5061;user=phone>";
    let result = rewrite_uri_authority(to, "trunk.example.com");
    assert_eq!(result, "<sip:bob@trunk.example.com;user=phone>");
}

#[test]
fn rewrite_uri_authority_no_original_port() {
    let to = "<sip:bob@old.example.com;user=phone>";
    let result = rewrite_uri_authority(to, "trunk.example.com:5060");
    assert_eq!(result, "<sip:bob@trunk.example.com:5060;user=phone>");
}

#[test]
fn rewrite_uri_authority_no_params_no_port() {
    let to = "<sip:bob@old.example.com>";
    let result = rewrite_uri_authority(to, "trunk.example.com:5060");
    assert_eq!(result, "<sip:bob@trunk.example.com:5060>");
}

#[test]
fn rewrite_uri_authority_display_name() {
    let to = "\"Alice\" <sip:alice@old.example.net:5061;user=phone>";
    let result = rewrite_uri_authority(to, "gw.example.net:5060");
    assert_eq!(
        result,
        "\"Alice\" <sip:alice@gw.example.net:5060;user=phone>"
    );
}

#[test]
fn rewrite_uri_authority_no_at_sign() {
    let to = "<sip:host.a:5060>";
    let result = rewrite_uri_authority(to, "gw.b:5060");
    // No @ sign — returned unchanged.
    assert_eq!(result, to);
}

// --- ensure_tag tests ---

#[test]
fn ensure_tag_appends_when_missing() {
    let to = "<sip:bob@example.com:5060>";
    assert_eq!(
        ensure_tag(to, Some("xyz123")),
        "<sip:bob@example.com:5060>;tag=xyz123"
    );
}

#[test]
fn ensure_tag_idempotent_when_already_tagged() {
    let to = "<sip:bob@example.com>;tag=existing";
    assert_eq!(ensure_tag(to, Some("xyz123")), to);
}

#[test]
fn ensure_tag_no_op_on_none() {
    let to = "<sip:bob@example.com>";
    assert_eq!(ensure_tag(to, None), to);
}

#[test]
fn ensure_tag_no_op_on_empty() {
    let to = "<sip:bob@example.com>";
    assert_eq!(ensure_tag(to, Some("")), to);
}

#[test]
fn ensure_tag_trims_trailing_whitespace_before_appending() {
    let to = "<sip:bob@example.com>  ";
    assert_eq!(ensure_tag(to, Some("abc")), "<sip:bob@example.com>;tag=abc");
}

#[test]
fn ensure_tag_with_display_name() {
    let to = "\"Bob\" <sip:bob@example.com>";
    assert_eq!(
        ensure_tag(to, Some("xyz")),
        "\"Bob\" <sip:bob@example.com>;tag=xyz"
    );
}

#[tokio::test]
async fn leg_actor_classifies_refer_request() {
    use crate::sip::message::Method;

    let (call_tx, mut call_rx) = tokio::sync::mpsc::channel(16);
    let leg = make_b_leg(0);
    let leg_id = leg.id.clone();

    let (actor, handle) = LegActor::new(leg, call_tx);
    let join = tokio::spawn(actor.run());

    let refer = crate::sip::builder::SipMessageBuilder::new()
        .request(
            Method::Refer,
            crate::sip::uri::SipUri::new("10.0.0.2".to_string()).with_port(5060),
        )
        .via("SIP/2.0/UDP 10.0.0.2:5060;branch=z9hG4bK-refer".to_string())
        .from("<sip:bob@biloxi.com>;tag=xyz".to_string())
        .to("<sip:alice@atlanta.com>;tag=abc".to_string())
        .call_id("b2b-bleg0".to_string())
        .cseq("3 REFER".to_string())
        .header("Refer-To", "<sip:carol@chicago.com>".to_string())
        .content_length(0)
        .build()
        .unwrap();
    handle
        .tx
        .send(LegMessage::SipInbound {
            message: refer,
            source: test_transport(),
        })
        .await
        .unwrap();

    let event = tokio::time::timeout(std::time::Duration::from_secs(2), call_rx.recv())
        .await
        .unwrap()
        .unwrap();
    match event {
        CallEvent::Refer { leg_id: id, .. } => assert_eq!(id, leg_id),
        other => panic!("expected Refer, got {:?}", other),
    }

    handle.tx.send(LegMessage::Shutdown).await.unwrap();
    join.await.unwrap();
}

#[tokio::test]
async fn leg_actor_ignores_unknown_request() {
    use crate::sip::message::Method;

    let (call_tx, mut call_rx) = tokio::sync::mpsc::channel(16);
    let leg = make_b_leg(0);

    let (actor, handle) = LegActor::new(leg, call_tx);
    let join = tokio::spawn(actor.run());

    // OPTIONS is not classified by the actor — no event emitted
    let options = crate::sip::builder::SipMessageBuilder::new()
        .request(
            Method::Options,
            crate::sip::uri::SipUri::new("10.0.0.2".to_string()).with_port(5060),
        )
        .via("SIP/2.0/UDP 10.0.0.2:5060;branch=z9hG4bK-opts".to_string())
        .from("<sip:bob@biloxi.com>;tag=xyz".to_string())
        .to("<sip:alice@atlanta.com>;tag=abc".to_string())
        .call_id("b2b-bleg0".to_string())
        .cseq("4 OPTIONS".to_string())
        .content_length(0)
        .build()
        .unwrap();
    handle
        .tx
        .send(LegMessage::SipInbound {
            message: options,
            source: test_transport(),
        })
        .await
        .unwrap();

    // Should timeout — no event expected
    let result = tokio::time::timeout(std::time::Duration::from_millis(100), call_rx.recv()).await;
    assert!(result.is_err(), "expected timeout, got event");

    handle.tx.send(LegMessage::Shutdown).await.unwrap();
    join.await.unwrap();
}

#[tokio::test]
async fn forking_multiple_actors_share_event_channel() {
    let (call_tx, mut call_rx) = tokio::sync::mpsc::channel(16);

    // Spawn 3 B-leg actors sharing the same event_tx
    let mut handles = Vec::new();
    let mut leg_ids = Vec::new();
    let mut joins = Vec::new();
    for i in 0..3 {
        let leg = make_b_leg(i);
        leg_ids.push(leg.id.clone());
        let (actor, handle) = LegActor::new(leg, call_tx.clone());
        joins.push(tokio::spawn(actor.run()));
        handles.push(handle);
    }

    // Send different responses to each actor
    // Leg 0: 180 Ringing
    let ringing = crate::sip::builder::SipMessageBuilder::new()
        .response(180, "Ringing".to_string())
        .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-f0".to_string())
        .from("<sip:alice@atlanta.com>;tag=abc".to_string())
        .to("<sip:bob@biloxi.com>;tag=b0".to_string())
        .call_id("b2b-bleg0".to_string())
        .cseq("1 INVITE".to_string())
        .content_length(0)
        .build()
        .unwrap();
    handles[0]
        .tx
        .send(LegMessage::SipInbound {
            message: ringing,
            source: test_transport(),
        })
        .await
        .unwrap();

    // Leg 1: 486 Busy
    let busy = crate::sip::builder::SipMessageBuilder::new()
        .response(486, "Busy Here".to_string())
        .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-f1".to_string())
        .from("<sip:alice@atlanta.com>;tag=abc".to_string())
        .to("<sip:bob@biloxi.com>;tag=b1".to_string())
        .call_id("b2b-bleg1".to_string())
        .cseq("1 INVITE".to_string())
        .content_length(0)
        .build()
        .unwrap();
    handles[1]
        .tx
        .send(LegMessage::SipInbound {
            message: busy,
            source: test_transport(),
        })
        .await
        .unwrap();

    // Leg 2: 200 OK
    let ok = crate::sip::builder::SipMessageBuilder::new()
        .response(200, "OK".to_string())
        .via("SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-f2".to_string())
        .from("<sip:alice@atlanta.com>;tag=abc".to_string())
        .to("<sip:bob@biloxi.com>;tag=b2".to_string())
        .call_id("b2b-bleg2".to_string())
        .cseq("1 INVITE".to_string())
        .content_length(0)
        .build()
        .unwrap();
    handles[2]
        .tx
        .send(LegMessage::SipInbound {
            message: ok,
            source: test_transport(),
        })
        .await
        .unwrap();

    // Collect all 3 events — order may vary
    let mut events = Vec::new();
    for _ in 0..3 {
        let event = tokio::time::timeout(std::time::Duration::from_secs(2), call_rx.recv())
            .await
            .unwrap()
            .unwrap();
        events.push(event);
    }

    // Verify all 3 leg_ids are present
    let event_leg_ids: std::collections::HashSet<String> = events
        .iter()
        .map(|e| match e {
            CallEvent::Provisional { leg_id, .. } => leg_id.0.clone(),
            CallEvent::Answered { leg_id, .. } => leg_id.0.clone(),
            CallEvent::Failed { leg_id, .. } => leg_id.0.clone(),
            CallEvent::Terminated { leg_id, .. } => leg_id.0.clone(),
            CallEvent::Bye { leg_id, .. } => leg_id.0.clone(),
            CallEvent::ReInvite { leg_id, .. } => leg_id.0.clone(),
            CallEvent::Refer { leg_id, .. } => leg_id.0.clone(),
        })
        .collect();

    for id in &leg_ids {
        assert!(
            event_leg_ids.contains(&id.0),
            "missing event for leg {}",
            id
        );
    }

    // Verify event types
    assert!(events.iter().any(|e| matches!(
        e,
        CallEvent::Provisional {
            status_code: 180,
            ..
        }
    )));
    assert!(events.iter().any(|e| matches!(
        e,
        CallEvent::Failed {
            status_code: 486,
            ..
        }
    )));
    assert!(events
        .iter()
        .any(|e| matches!(e, CallEvent::Answered { .. })));

    // Shutdown all
    for handle in &handles {
        let _ = handle.tx.send(LegMessage::Shutdown).await;
    }
    for join in joins {
        let _ = join.await;
    }
}

#[tokio::test]
async fn shutdown_actors_terminates_running_tasks() {
    let (call_tx, _call_rx) = tokio::sync::mpsc::channel(16);

    let mut call = CallActor::new(make_a_leg());
    call.add_b_leg(make_b_leg(0));
    call.add_b_leg(make_b_leg(1));

    let mut joins = Vec::new();
    for i in 0..2 {
        let leg = make_b_leg(i);
        let (actor, handle) = LegActor::new(leg, call_tx.clone());
        joins.push(tokio::spawn(actor.run()));
        call.set_b_leg_handle(i, handle);
    }

    // All actors should be running
    for join in &joins {
        assert!(!join.is_finished());
    }

    // shutdown_actors sends Shutdown to all
    call.shutdown_actors();

    // All tasks should complete within timeout
    for join in joins {
        tokio::time::timeout(std::time::Duration::from_secs(2), join)
            .await
            .expect("actor did not terminate")
            .unwrap();
    }
}

// --- Recently-terminated Call-IDs (post-teardown 481) ---

#[test]
fn teardown_remembers_every_leg_call_id() {
    // Hang-up glare: whichever peer's BYE loses the race must still be
    // answerable, and on a B2BUA that peer may be on either side, so both
    // the A-leg and every B-leg Call-ID has to be remembered.
    let store = CallActorStore::new();
    let call_id = store.create_call(make_a_leg());
    store.add_b_leg(&call_id, make_b_leg(0));
    store.add_b_leg(&call_id, make_b_leg(1));

    assert!(!store.is_recently_terminated("call-1@10.0.0.1"));

    store.remove_call(&call_id);

    assert!(store.is_recently_terminated("call-1@10.0.0.1"));
    assert!(store.is_recently_terminated("b2b-bleg0"));
    assert!(store.is_recently_terminated("b2b-bleg1"));
    // A Call-ID this node never saw stays unknown — the dispatcher leaves
    // those to the script (a proxy loose-routes dialogs it doesn't track).
    assert!(!store.is_recently_terminated("stranger@10.0.0.9"));
    assert!(!store.is_recently_terminated(""));
}

#[test]
fn live_call_is_never_remembered_as_terminated() {
    // Guards the dispatcher's ordering: a call that is up must not be able
    // to answer 481 to its own in-dialog requests.
    let store = CallActorStore::new();
    let call_id = store.create_call(make_a_leg());
    store.add_b_leg(&call_id, make_b_leg(0));

    assert!(!store.is_recently_terminated("call-1@10.0.0.1"));
    assert!(!store.is_recently_terminated("b2b-bleg0"));
}

#[test]
fn legs_sharing_a_call_id_are_remembered_once() {
    // With preserve_call_id — and for the dispatcher's `reinvite:` tracking
    // pseudo-legs — a B-leg carries the A-leg's Call-ID. One membership entry
    // covers both.
    let store = CallActorStore::new();
    let call_id = store.create_call(make_a_leg());
    let mut b_leg = make_b_leg(0);
    b_leg.dialog.call_id = "call-1@10.0.0.1".to_string();
    store.add_b_leg(&call_id, b_leg);

    store.remove_call(&call_id);

    assert!(store.is_recently_terminated("call-1@10.0.0.1"));
    assert_eq!(store.terminated.len(), 1);
}

#[test]
fn re_terminating_a_reused_call_id_keeps_it_remembered() {
    // Regression: a peer that reuses one Call-ID across calls used to LOSE its
    // 481. The second teardown found the Call-ID already present and pushed no
    // fresh entry, so eviction aged out the first call's entry and removed the
    // Call-ID that had just been remembered again. The stamp is a generation:
    // an expiring entry may only remove the Call-ID if it is still current.
    let terminated = DashMap::new();
    let mut order = VecDeque::new();
    let base = Instant::now();
    let refreshed = base + Duration::from_secs(60);
    // Remembered at `base`, then again at `refreshed`.
    terminated.insert("reused@10.0.0.1".to_string(), refreshed);
    order.push_back(("reused@10.0.0.1".to_string(), base));
    order.push_back(("reused@10.0.0.1".to_string(), refreshed));

    // The first entry is well past the TTL; the second is not.
    CallActorStore::evict_terminated(
        &terminated,
        &mut order,
        base + Duration::from_secs(40),
        TERMINATED_CALL_TTL,
        TERMINATED_CALL_CAPACITY,
    );

    assert!(terminated.contains_key("reused@10.0.0.1"));
    assert_eq!(order.len(), 1);
}

#[test]
fn second_teardown_of_the_same_call_id_still_remembered() {
    // The store-level shape of the regression above: tear down, reuse the
    // Call-ID for another call, tear that down too. Still answerable.
    let store = CallActorStore::new();
    let first = store.create_call(make_a_leg());
    store.remove_call(&first);
    let second = store.create_call(make_a_leg());
    store.remove_call(&second);

    assert!(store.is_recently_terminated("call-1@10.0.0.1"));
    assert_eq!(store.terminated.len(), 1);
}

#[test]
fn terminated_evicts_by_age() {
    // Past the TTL the peer's own transaction has timed out, so the entry
    // has nothing left to answer. `now` is moved forward rather than slept.
    let store = CallActorStore::new();
    let call_id = store.create_call(make_a_leg());
    store.remove_call(&call_id);
    assert!(store.is_recently_terminated("call-1@10.0.0.1"));

    let mut order = store.terminated_order.lock().unwrap();
    CallActorStore::evict_terminated(
        &store.terminated,
        &mut order,
        Instant::now() + Duration::from_secs(40),
        TERMINATED_CALL_TTL,
        TERMINATED_CALL_CAPACITY,
    );
    drop(order);

    assert!(!store.is_recently_terminated("call-1@10.0.0.1"));
    assert_eq!(store.terminated_order.lock().unwrap().len(), 0);
}

#[test]
fn terminated_evicts_by_capacity_oldest_first() {
    // The cap is what keeps a 40k-cps run from holding 32 s of Call-IDs.
    let terminated = DashMap::new();
    let mut order = VecDeque::new();
    let base = Instant::now();
    for index in 0..5 {
        let stamp = base + Duration::from_millis(index);
        terminated.insert(format!("cid-{index}"), stamp);
        order.push_back((format!("cid-{index}"), stamp));
    }

    CallActorStore::evict_terminated(&terminated, &mut order, base, TERMINATED_CALL_TTL, 2);

    // Newest two survive, in order.
    assert_eq!(order.len(), 2);
    assert!(!terminated.contains_key("cid-0"));
    assert!(!terminated.contains_key("cid-1"));
    assert!(!terminated.contains_key("cid-2"));
    assert!(terminated.contains_key("cid-3"));
    assert!(terminated.contains_key("cid-4"));
}
#[cfg(test)]
mod originate_tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn transport() -> TransportInfo {
        TransportInfo {
            remote_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 5060),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: None,
        }
    }

    fn originating_leg() -> Leg {
        Leg::new_originating_leg(
            "orig-call@siphon.invalid".to_string(),
            "sip-from-tag".to_string(),
            "sip:+14035551212@carrier.example".to_string(),
            "z9hG4bK-orig1".to_string(),
            transport(),
        )
    }

    #[test]
    fn originating_leg_is_an_a_leg_with_an_outbound_dialog() {
        let leg = originating_leg();
        assert_eq!(leg.side, LegSide::A);
        // Outbound dialog: our tag is the local (From) tag, the remote tag is
        // still unknown, and the target URI is the R-URI we INVITE.
        assert_eq!(leg.dialog.local_tag, "sip-from-tag");
        assert!(leg.dialog.remote_tag.is_none());
        assert_eq!(
            leg.dialog.target_uri.as_deref(),
            Some("sip:+14035551212@carrier.example")
        );
        assert_eq!(leg.dialog.local_cseq, 1);
        assert!(!leg.is_tracking_leg());
    }

    #[test]
    fn a_fresh_call_is_not_originated() {
        let store = CallActorStore::new();
        let call_id = store.create_call(originating_leg());
        assert!(!store.is_originated(&call_id));
    }

    /// A call siphon placed itself carries its pending INVITE on the A-leg, so
    /// the B-leg capture loop finds nothing — without the A-leg arm the `487
    /// Request Terminated` its CANCEL draws (RFC 3261 §9.1) is dropped as an
    /// unknown branch, unACKed, and the peer retransmits to Timer H (§17.2.1).
    #[test]
    fn cancelled_originate_is_zombified_with_its_invite_ruri_for_the_487_ack() {
        let store = CallActorStore::new();
        let call_id = store.create_call(originating_leg());
        store.mark_originated(&call_id, "z9hG4bK-orig1");

        let sip_call_id = "orig-call@siphon.invalid".to_string();
        let invite = crate::sip::builder::SipMessageBuilder::new()
            .request(
                crate::sip::message::Method::Invite,
                crate::sip::uri::SipUri::new("carrier.example".to_string())
                    .with_user("+14035551212".to_string()),
            )
            .via("SIP/2.0/UDP 198.51.100.10:5060;branch=z9hG4bK-orig1".to_string())
            .from("<sip:siphon@198.51.100.10>;tag=sip-from-tag".to_string())
            .to("<sip:+14035551212@carrier.example>".to_string())
            .call_id(sip_call_id.clone())
            .cseq("1 INVITE".to_string())
            .content_length(0)
            .build()
            .unwrap();
        store.set_a_leg_invite(&call_id, Arc::new(Mutex::new(invite)));

        assert!(
            store.remove_call_after_cancel(&call_id),
            "an originated call's pending A-leg must be captured"
        );

        let (leg, ruri) = store
            .zombie_cancelled_for_non2xx(&sip_call_id)
            .expect("the CANCELled originate must still resolve for its 487");
        // RFC 3261 §17.1.1.3 — the ACK rides the INVITE's own branch and
        // Request-URI.
        assert_eq!(leg.branch, "z9hG4bK-orig1");
        assert_eq!(ruri.as_deref(), Some("sip:+14035551212@carrier.example"));
    }

    #[test]
    fn mark_originated_flags_the_call_and_indexes_the_branch() {
        let store = CallActorStore::new();
        let call_id = store.create_call(originating_leg());
        store.mark_originated(&call_id, "z9hG4bK-orig1");

        assert!(store.is_originated(&call_id));
        assert_eq!(
            store.lookup_originated_call("z9hG4bK-orig1").as_deref(),
            Some(call_id.as_str())
        );
        assert!(store
            .lookup_originated_call("z9hG4bK-someone-else")
            .is_none());
    }

    #[test]
    fn removing_the_call_drains_the_originate_branch_index() {
        let store = CallActorStore::new();
        let call_id = store.create_call(originating_leg());
        store.mark_originated(&call_id, "z9hG4bK-orig1");
        assert_eq!(store.registry.originated_call_count(), 1);

        store.remove_call(&call_id);
        assert_eq!(store.registry.originated_call_count(), 0);
        assert!(store.lookup_originated_call("z9hG4bK-orig1").is_none());
    }

    /// Steady-state leak guard for the originate branch index: a batch of
    /// complete place-then-tear-down cycles must return every store to the
    /// length it started at.
    #[test]
    fn originate_cycles_drain_every_store_to_baseline() {
        let store = CallActorStore::new();
        let baseline = (store.count(), store.registry.originated_call_count());

        for index in 0..200 {
            let leg = Leg::new_originating_leg(
                format!("orig-{index}@siphon.invalid"),
                format!("tag-{index}"),
                "sip:+14035551212@carrier.example".to_string(),
                format!("z9hG4bK-orig-{index}"),
                transport(),
            );
            let call_id = store.create_call(leg);
            store.mark_originated(&call_id, &format!("z9hG4bK-orig-{index}"));
            store.remove_call(&call_id);
        }

        assert_eq!(
            (store.count(), store.registry.originated_call_count()),
            baseline,
            "originate must not retain per-call state after teardown"
        );
    }

    #[test]
    fn an_originated_call_routes_its_own_in_dialog_requests_to_the_a_leg() {
        // RFC 3261 §12: the far end's BYE carries our dialog Call-ID, and its
        // From-tag is the tag it assigned (our `remote_tag`). A single-leg
        // originated call must resolve that to the A-leg, never to "no dialog".
        let mut actor = CallActor::new(originating_leg());
        actor.a_leg.dialog.remote_tag = Some("peer-tag".to_string());
        assert_eq!(
            actor.request_direction("orig-call@siphon.invalid", Some("peer-tag")),
            Some(LegSide::A)
        );
        assert_eq!(
            actor.request_direction("some-other-call@elsewhere", Some("peer-tag")),
            None
        );
    }
}
