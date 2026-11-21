//! Content delivery for the shapes of a call that are not two parties and a
//! relay: a party seated in a conference room, a call's leg moved into one,
//! and a call the engine answered itself.
//!
//! Driven the way [`super::li_session_tests`] drives a plain call: the
//! messages through [`intercept_message`], the media verbs through the backend
//! a script's `rtpengine` namespace calls, against the in-process native
//! engine modelling siphon-rtp 0.25.2. The engine reports no events of its
//! own, so each test sends the `x3_ended` the real one would.
//!
//! The seats this process holds are kept per SIP Call-ID for the whole
//! process, so every test here runs on a Call-ID of its own.

use super::li_session_tests::{
    arrives, attach_outcomes, backend_of, callee_request, callee_response, caller_calls,
    capture_log, dial, drain_iri, engine_events, engine_reports, faults_reported,
    intercepting_on_the_engine, proxied_response, CALLEE, CALLEE_CALL_ID, CALLER, CALLER_ACK,
    CALLER_BYE_OK, CALLER_INVITE, SECOND_CALLEE_CALL_ID,
};
use super::*;
use crate::li::pdu::PayloadDirection;
use crate::li::{correlation_from_call_id, IriEvent};
use crate::rtpengine::backend::{AdoptedSeat, ConferenceDtmf, ConferenceRole, ConferenceSeat};
use crate::rtpengine::test_native_engine::{
    NativeTestEngine, NATIVE_ENGINE_CLOSING_ROOM, NATIVE_ENGINE_ECHO_REFUSED,
};
use crate::rtpengine::NgFlags;

const BASE_CALL_ID: &str = "caller-call@192.0.2.10";

/// `raw`, a message of the shared caller dialog, on the dialog `call_id`.
fn on_call(raw: &str, call_id: &str) -> String {
    raw.replace(BASE_CALL_ID, call_id)
}

fn seat(conference_id: &str, tag: &str) -> ConferenceSeat {
    ConferenceSeat {
        conference_id: conference_id.to_string(),
        from_tag: tag.to_string(),
    }
}

/// The engine's report that the delivery named `call_id` / `from_tag` ended.
fn ended(call_id: &str, from_tag: &str, reason: &str) -> crate::rtpengine::events::RtpEngineEvent {
    crate::rtpengine::events::RtpEngineEvent::X3Ended(crate::rtpengine::events::X3EndedEvent {
        call_id: call_id.to_string(),
        from_tag: from_tag.to_string(),
        reason: reason.to_string(),
        orderly: reason == "Detached",
        delivered: 320,
        dropped: 0,
        delivery: None,
    })
}

/// What a script's `rtpengine.conference_join(call, ...)` does on the factory
/// INVITE: the caller is seated in the room under its own tag.
async fn script_joins(state: &Arc<DispatcherState>, call_id: &str, room: &str) {
    backend_of(state)
        .conference_join(
            call_id,
            seat(room, "caller-tag"),
            "v=0\r\n",
            ConferenceRole::Talker,
            &NgFlags::default(),
        )
        .await
        .expect("the engine seats the caller");
}

/// A caller under warrant that dials a conference factory URI is seated in a
/// room and has no engine call. Its content is asked for on the seat, named
/// by the room and the seat's tag, as soon as it is seated, and never under
/// the SIP Call-ID, which the engine does not hold. siphon taking the seat
/// out (the script's `rtpengine.delete()` at the end) is why its delivery
/// ends, so the engine's `call_ended` for it is clean.
#[tokio::test]
async fn a_factory_invite_seat_is_attached_on_the_seat_and_its_leave_is_clean() {
    const CALL: &str = "factory-seat@192.0.2.10";
    const ROOM: &str = "room-factory-seat";
    let (log, _guard) = capture_log();
    let (state, engine, li, _iri, mut audit) =
        intercepting_on_the_engine(NativeTestEngine::start_with_x3().await).await;
    let events = engine_events(&state);

    arrives(&state, CALLER, &on_call(CALLER_INVITE, CALL));
    script_joins(&state, CALL, ROOM).await;
    assert_eq!(
        attach_outcomes(&mut audit).await,
        (1, 0),
        "attached when the caller is seated"
    );
    let attached = engine.commands("attach_x3");
    assert_eq!(attached.len(), 1);
    assert_eq!(attached[0].call_id, ROOM, "the room stands for the call");
    assert_eq!(attached[0].from_tag, "caller-tag", "and the seat's tag");
    assert_eq!(attached[0].scope, None, "a room verb carries no scope");
    assert!(!attached[0].refused);

    // siphon's own 200 is not inbound; the caller's ACK of it is, and finds
    // the seat attached.
    arrives(&state, CALLER, &on_call(CALLER_ACK, CALL));
    assert_eq!(attach_outcomes(&mut audit).await, (0, 0));
    assert_eq!(
        engine.commands("attach_x3").len(),
        1,
        "the ACK asks neither for the seat again nor for a call the engine does not hold"
    );

    // The conference ends for this caller: siphon takes the seat out, which
    // stops the room with its last seat, and the engine ends the delivery.
    backend_of(&state)
        .delete(CALL, "caller-tag")
        .await
        .expect("the seat is freed");
    assert_eq!(engine.commands("conference_leave").len(), 1);
    engine_reports(&events, ended(ROOM, "caller-tag", "CallEnded")).await;

    assert_eq!(faults_reported(&log), 0, "{}", log.rendered());
    assert_eq!(li.x3_attachment_count(), 0, "the seat's record drains");
    assert!(engine.commands("detach_x3").is_empty());
}

/// The caller hanging up detaches the seat's delivery on the seat.
#[tokio::test]
async fn a_bye_detaches_a_seats_delivery_on_the_seat() {
    const CALL: &str = "factory-seat-bye@192.0.2.10";
    const ROOM: &str = "room-factory-seat-bye";
    let (state, engine, li, _iri, mut audit) =
        intercepting_on_the_engine(NativeTestEngine::start_with_x3().await).await;
    arrives(&state, CALLER, &on_call(CALLER_INVITE, CALL));
    script_joins(&state, CALL, ROOM).await;
    arrives(&state, CALLER, &on_call(CALLER_ACK, CALL));
    assert_eq!(attach_outcomes(&mut audit).await, (1, 0));

    let bye = on_call(CALLER_ACK, CALL)
        .replace("ACK sip:", "BYE sip:")
        .replace("CSeq: 1 ACK", "CSeq: 2 BYE")
        .replace("z9hG4bK-caller-ack", "z9hG4bK-caller-bye");
    arrives(&state, CALLER, &bye);
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    let detached = engine.commands("detach_x3");
    assert_eq!(detached.len(), 1);
    assert_eq!(
        (detached[0].call_id.as_str(), detached[0].from_tag.as_str()),
        (ROOM, "caller-tag")
    );
    assert!(!detached[0].refused);
    assert!(
        li.x3_attachments_for(&crate::li::seat_record(ROOM, "caller-tag"))
            .is_empty(),
        "no longer live; on record until the engine reports it ended"
    );
    backend_of(&state)
        .delete(CALL, "caller-tag")
        .await
        .expect("the seat is freed");
}

/// A detach that the engine reports as having dropped content, or that a
/// transport failure beat, is content the agency did not get. The delivery is
/// kept on record from the detach to that report, so the fault is raised, and
/// against the warrant it was delivering for.
#[tokio::test]
async fn a_detach_that_dropped_content_is_a_fault_against_its_warrant() {
    for (call, reason) in [
        ("detach-dropped@192.0.2.10", "Detached"),
        ("detach-lost-the-race@192.0.2.10", "TransportError"),
    ] {
        let (log, _guard) = capture_log();
        let (state, engine, li, _iri, mut audit) =
            intercepting_on_the_engine(NativeTestEngine::start_with_x3().await).await;
        let events = engine_events(&state);
        arrives(&state, CALLER, &on_call(CALLER_INVITE, call));
        backend_of(&state)
            .offer(call, "caller-tag", b"v=0\r\n", &NgFlags::default())
            .await
            .expect("offered");
        assert_eq!(attach_outcomes(&mut audit).await, (1, 0));
        let warrant = li.tasks().list()[0].details.x_id.to_string();

        let bye = on_call(CALLER_ACK, call)
            .replace("ACK sip:", "BYE sip:")
            .replace("CSeq: 1 ACK", "CSeq: 2 BYE")
            .replace("z9hG4bK-caller-ack", "z9hG4bK-caller-bye");
        arrives(&state, CALLER, &bye);
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert_eq!(engine.commands("detach_x3").len(), 1, "{reason}");
        assert!(li.x3_attachments_for(call).is_empty(), "no longer live");

        let mut report = ended(call, "caller-tag", reason);
        if let crate::rtpengine::events::RtpEngineEvent::X3Ended(ended) = &mut report {
            ended.dropped = 3;
        }
        engine_reports(&events, report).await;
        assert_eq!(faults_reported(&log), 1, "{reason}:\n{}", log.rendered());
        assert!(
            log.rendered()
                .contains(&format!("X3 delivery ended for task {warrant}")),
            "{reason}: reported against the warrant:\n{}",
            log.rendered()
        );
        assert_eq!(li.x3_attachment_count(), 0, "{reason}: the record drains");
        backend_of(&state)
            .delete(call, "caller-tag")
            .await
            .expect("deleted");
    }
}

/// The engine ending a seat's delivery while siphon took no seat out (the
/// engine reaped the seat, or its room stopped under it) is a fault: the
/// target is in the conference as far as its signalling says.
#[tokio::test]
async fn a_seats_delivery_ending_while_siphon_left_it_seated_is_a_fault() {
    const CALL: &str = "factory-seat-reaped@192.0.2.10";
    const ROOM: &str = "room-factory-seat-reaped";
    let (log, _guard) = capture_log();
    let (state, _engine, li, _iri, mut audit) =
        intercepting_on_the_engine(NativeTestEngine::start_with_x3().await).await;
    let events = engine_events(&state);
    arrives(&state, CALLER, &on_call(CALLER_INVITE, CALL));
    script_joins(&state, CALL, ROOM).await;
    assert_eq!(attach_outcomes(&mut audit).await, (1, 0));

    engine_reports(&events, ended(ROOM, "caller-tag", "CallEnded")).await;
    assert_eq!(faults_reported(&log), 1, "{}", log.rendered());
    assert_eq!(li.x3_attachment_count(), 0);
    backend_of(&state)
        .delete(CALL, "caller-tag")
        .await
        .expect("the seat is freed");
}

/// A `delete` the engine refuses ended nothing: the call is still there and
/// still delivering. siphon had counted it as its own end the moment it asked,
/// so when the engine later ended the call on its own (it timed it out) the
/// delivery's end read as clean. The refusal puts the delivery back on watch,
/// and that end is a fault.
#[tokio::test]
async fn a_delete_the_engine_refused_does_not_make_a_later_end_clean() {
    const CALL: &str = "delete-refused@192.0.2.10";
    let (log, _guard) = capture_log();
    let (state, engine, li, _iri, mut audit) =
        intercepting_on_the_engine(NativeTestEngine::start_with_x3().await).await;
    let events = engine_events(&state);
    arrives(&state, CALLER, &on_call(CALLER_INVITE, CALL));
    backend_of(&state)
        .offer(CALL, "caller-tag", b"v=0\r\n", &NgFlags::default())
        .await
        .expect("offered");
    assert_eq!(attach_outcomes(&mut audit).await, (1, 0));

    engine.refuse_next("delete");
    assert!(
        backend_of(&state).delete(CALL, "caller-tag").await.is_err(),
        "the engine refuses the delete"
    );
    assert_eq!(
        li.x3_attachments_for(CALL).len(),
        1,
        "the delivery is live again"
    );
    engine_reports(&events, ended(CALL, "caller-tag", "CallEnded")).await;
    assert_eq!(faults_reported(&log), 1, "{}", log.rendered());
    assert_eq!(li.x3_attachment_count(), 0);
    backend_of(&state)
        .delete(CALL, "caller-tag")
        .await
        .expect("deleted");
}

/// The same for a seat: a `conference_leave` the engine refuses leaves the
/// target seated and delivering, and still the session's. The engine reaping
/// that seat later is a fault.
#[tokio::test]
async fn a_leave_the_engine_refused_does_not_make_a_later_reap_clean() {
    const CALL: &str = "leave-refused@192.0.2.10";
    const ROOM: &str = "room-leave-refused";
    let (log, _guard) = capture_log();
    let (state, engine, li, _iri, mut audit) =
        intercepting_on_the_engine(NativeTestEngine::start_with_x3().await).await;
    let events = engine_events(&state);
    arrives(&state, CALLER, &on_call(CALLER_INVITE, CALL));
    script_joins(&state, CALL, ROOM).await;
    assert_eq!(attach_outcomes(&mut audit).await, (1, 0));

    engine.refuse_next("conference_leave");
    assert!(
        backend_of(&state)
            .conference_leave(CALL, &seat(ROOM, "caller-tag"))
            .await
            .is_err(),
        "the engine refuses the leave"
    );
    assert_eq!(
        li.session_of_leg(CALL).expect("the session").seats.len(),
        1,
        "the seat is still the session's"
    );
    engine_reports(&events, ended(ROOM, "caller-tag", "CallEnded")).await;
    assert_eq!(faults_reported(&log), 1, "{}", log.rendered());
    assert_eq!(li.x3_attachment_count(), 0);
    backend_of(&state)
        .delete(CALL, "caller-tag")
        .await
        .expect("the seat is freed");
}

/// On an engine that does not list `x3_conference_seat` nothing changes:
/// nothing is asked when the caller is seated, the ACK asks for the call as
/// it always did, the engine holds no such call, and that refusal is a loud
/// fault toward the ADMF. The seat form is never sent to an engine that would
/// not understand it.
#[tokio::test]
async fn without_the_feature_a_seated_caller_is_still_a_refused_attach_and_a_fault() {
    const CALL: &str = "factory-seat-old-engine@192.0.2.10";
    const ROOM: &str = "room-factory-seat-old-engine";
    let (log, _guard) = capture_log();
    let (state, engine, li, _iri, mut audit) =
        intercepting_on_the_engine(NativeTestEngine::start_with_x3_at_offer().await).await;
    arrives(&state, CALLER, &on_call(CALLER_INVITE, CALL));
    script_joins(&state, CALL, ROOM).await;
    assert_eq!(
        attach_outcomes(&mut audit).await,
        (0, 0),
        "nothing asked at the seat"
    );

    arrives(&state, CALLER, &on_call(CALLER_ACK, CALL));
    assert_eq!(attach_outcomes(&mut audit).await, (1, 1));
    let attached = engine.commands("attach_x3");
    assert_eq!(attached.len(), 1);
    assert_eq!(attached[0].call_id, CALL, "asked as a call, as before");
    assert!(attached[0].refused, "which the engine does not hold");
    assert!(
        log.rendered().contains("NOT being delivered"),
        "{}",
        log.rendered()
    );
    assert_eq!(faults_reported(&log), 1, "{}", log.rendered());
    assert_eq!(li.x3_attachment_count(), 0);
    backend_of(&state)
        .delete(CALL, "caller-tag")
        .await
        .expect("the seat is freed");
}

/// An intercepted B2BUA call on `call_id`, offered, answered and attached at
/// its offer, with the far party's tag known to the engine.
async fn answered_b2bua_call(
    state: &Arc<DispatcherState>,
    call_id: &str,
    callee_call_id: &str,
) -> String {
    arrives(state, CALLER, &on_call(CALLER_INVITE, call_id));
    let a_leg = Leg::new_a_leg(
        call_id.to_string(),
        "caller-tag".to_string(),
        "z9hG4bK-caller-invite".to_string(),
        LegTransport {
            remote_addr: CALLER.parse().expect("a literal address"),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: None,
        },
    );
    let internal_id = create_b2bua_call(state, a_leg);
    let flags = NgFlags::default();
    backend_of(state)
        .offer(call_id, "caller-tag", b"v=0\r\n", &flags)
        .await
        .expect("the engine takes the offer");
    dial(state, &internal_id, callee_call_id);
    arrives(state, CALLEE, &callee_response(callee_call_id, "200 OK"));
    backend_of(state)
        .answer(call_id, "caller-tag", "callee-tag", b"v=0\r\n", &flags)
        .await
        .expect("the engine takes the answer");
    arrives(state, CALLER, &on_call(CALLER_ACK, call_id));
    internal_id
}

fn adopted(call_id: &str, internal_id: &str) -> AdoptedSeat {
    AdoptedSeat {
        sip_call_id: call_id.to_string(),
        party_uri: None,
        internal_call_id: internal_id.to_string(),
        owner_call_id: "conference-dialog@192.0.2.10".to_string(),
        end_owner_on_last: false,
        dtmf: ConferenceDtmf::Events,
    }
}

/// `b2bua.adopt_replaced` moves the far party of an intercepted call into a
/// room in place and ends the caller's dialog. The engine carries the call's
/// interception into the room, out of it and into another on the one delivery
/// connection, so siphon detaches nothing and asks for nothing again, and the
/// call's X2 and X3 stay under its Correlation ID for as long as the call
/// lives: the 200 to the BYE that ended the merged dialog does not end the
/// session. The call's `delete` is what ends the delivery, cleanly.
#[tokio::test]
async fn a_seated_call_keeps_its_one_interception_across_seat_leave_and_reseat() {
    const CALL: &str = "seated-call@192.0.2.10";
    const FAR: &str = "seated-call-far@192.0.2.1";
    let (log, _guard) = capture_log();
    let (state, engine, li, mut iri, mut audit) =
        intercepting_on_the_engine(NativeTestEngine::start_with_x3().await).await;
    let events = engine_events(&state);
    let internal_id = answered_b2bua_call(&state, CALL, FAR).await;
    assert_eq!(attach_outcomes(&mut audit).await, (1, 0), "at the offer");
    let correlation = correlation_from_call_id(&internal_id);
    let backend = backend_of(&state);

    // The merge: the far party is seated, the caller's dialog is sent its
    // BYE and answers it.
    backend
        .conference_seat_call(
            CALL,
            "callee-tag",
            "room-seated-a",
            ConferenceRole::Talker,
            adopted(FAR, &internal_id),
        )
        .await
        .expect("the engine seats an intercepted call's leg");
    arrives(&state, CALLER, &on_call(CALLER_BYE_OK, CALL));

    // The call lives on in the room well past the grace of a session that
    // ended: its session, and the record of its delivery, stay.
    li.sweep_sessions(
        std::time::Instant::now() + crate::li::SESSION_GRACE * 4,
        |session_id| state.call_actors.contains_call(session_id),
    );
    li.sweep_sessions(
        std::time::Instant::now() + crate::li::SESSION_GRACE * 8,
        |session_id| state.call_actors.contains_call(session_id),
    );
    assert_eq!(
        li.x3_attachments_for(CALL).len(),
        1,
        "the seated call's delivery is still on record"
    );

    // Out of the room and into another.
    backend
        .conference_leave(FAR, &seat("room-seated-a", "callee-tag"))
        .await
        .expect("the leg leaves the room");
    backend
        .conference_seat_call(
            CALL,
            "callee-tag",
            "room-seated-b",
            ConferenceRole::Talker,
            adopted(FAR, &internal_id),
        )
        .await
        .expect("the leg is seated again");
    assert_eq!(attach_outcomes(&mut audit).await, (0, 0));
    assert_eq!(engine.commands("conference_seat").len(), 2);
    assert_eq!(
        engine.commands("attach_x3").len(),
        1,
        "one interception for the life of the call"
    );
    assert!(
        engine.commands("detach_x3").is_empty(),
        "nothing is detached"
    );
    assert_eq!(li.x3_attachments_for(CALL).len(), 1);

    // The far party's signalling still belongs to the session.
    drain_iri(&mut iri);
    arrives(
        &state,
        CALLEE,
        &callee_request("INFO", 2, "z9hG4bK-far-info").replace(CALLEE_CALL_ID, FAR),
    );
    let late = drain_iri(&mut iri);
    assert_eq!(late.len(), 1, "X2 goes on");
    assert_eq!(late[0].correlation_id, correlation, "under the one CID");

    // The call ends: siphon deletes it, and the engine ends the delivery.
    backend
        .delete(CALL, "caller-tag")
        .await
        .expect("the engine deletes the call");
    engine_reports(&events, ended(CALL, "caller-tag", "CallEnded")).await;
    assert_eq!(faults_reported(&log), 0, "{}", log.rendered());
    assert_eq!(li.x3_attachment_count(), 0);
}

/// After the merge the handset may hang up the merged-away dialog itself,
/// crossing the BYE siphon sends it. That BYE ends a dialog, not the call: the
/// far party is in the room and the engine is delivering from there. Nothing
/// is detached (a detach ends the delivery cleanly, so content would stop
/// with nobody told), and the same holds for the far party's own BYE: the
/// interception ends with the engine call, at siphon's `delete`.
#[tokio::test]
async fn a_bye_on_a_dialog_of_a_seated_call_does_not_detach_its_interception() {
    const CALL: &str = "seated-call-handset-bye@192.0.2.10";
    const FAR: &str = "seated-call-handset-bye-far@192.0.2.1";
    let (log, _guard) = capture_log();
    let (state, engine, li, _iri, mut audit) =
        intercepting_on_the_engine(NativeTestEngine::start_with_x3().await).await;
    let events = engine_events(&state);
    let internal_id = answered_b2bua_call(&state, CALL, FAR).await;
    assert_eq!(attach_outcomes(&mut audit).await, (1, 0));
    backend_of(&state)
        .conference_seat_call(
            CALL,
            "callee-tag",
            "room-handset-bye",
            ConferenceRole::Talker,
            adopted(FAR, &internal_id),
        )
        .await
        .expect("the engine seats the far party");

    // The handset's own BYE on the dialog that was merged away.
    let bye = on_call(CALLER_ACK, CALL)
        .replace("ACK sip:", "BYE sip:")
        .replace("CSeq: 1 ACK", "CSeq: 2 BYE")
        .replace("z9hG4bK-caller-ack", "z9hG4bK-caller-bye");
    arrives(&state, CALLER, &bye);
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(
        engine.commands("detach_x3").is_empty(),
        "the seated call's delivery is not detached"
    );
    assert_eq!(
        li.x3_attachments_for(CALL).len(),
        1,
        "and is still on record, so its end is still judged"
    );

    // The engine losing the call now would be a fault, as on any live call...
    // and the far party hanging up later detaches nothing either.
    arrives(
        &state,
        CALLEE,
        &callee_request("BYE", 2, "z9hG4bK-far-bye").replace(CALLEE_CALL_ID, FAR),
    );
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(engine.commands("detach_x3").is_empty());

    // siphon's teardown deletes the call, and that is the clean end.
    backend_of(&state)
        .delete(CALL, "caller-tag")
        .await
        .expect("the engine deletes the call");
    engine_reports(&events, ended(CALL, "caller-tag", "CallEnded")).await;
    assert_eq!(faults_reported(&log), 0, "{}", log.rendered());
    assert_eq!(li.x3_attachment_count(), 0);
}

/// A transfer re-anchors the call's media: siphon offers the survivor's SDP
/// under an engine call-id of its own minting, answers it with the transfer
/// target's, and deletes the engine call the caller's Call-ID named. Content
/// delivery follows the media. The new engine call is attached, at its offer
/// on an engine that takes it there and at its answer on one that does not
/// (siphon sends the ACKs of a transfer itself, so none arrives to ask at),
/// and the old delivery ends with the engine call siphon deleted: one live
/// interception, on the engine call that holds the media.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_transfer_re_anchoring_the_media_is_followed_by_its_interception() {
    for at_offer in [true, false] {
        let call = format!("transfer-re-anchor-{at_offer}@192.0.2.10");
        let minted = format!("minted-engine-call-{at_offer}");
        let engine = match at_offer {
            true => NativeTestEngine::start_with_x3().await,
            false => NativeTestEngine::start().await,
        };
        let (state, engine, li, _iri, mut audit) = intercepting_on_the_engine(engine).await;
        let events = engine_events(&state);
        let backend = backend_of(&state);
        let flags = NgFlags::default();
        arrives(&state, CALLER, &on_call(CALLER_INVITE, &call));
        backend
            .offer(&call, "caller-tag", b"v=0\r\n", &flags)
            .await
            .expect("offered");
        arrives(&state, CALLEE, &on_call(&proxied_response("200 OK"), &call));
        backend
            .answer(&call, "caller-tag", "callee-tag", b"v=0\r\n", &flags)
            .await
            .expect("answered");
        arrives(&state, CALLER, &on_call(CALLER_ACK, &call));
        assert_eq!(attach_outcomes(&mut audit).await, (1, 0), "{at_offer}");

        // The transfer: the caller survives, and its media is offered afresh.
        tokio::task::block_in_place(|| {
            assert!(super::b2bua::b2bua_transfer_rtpengine_offer(
                &state,
                &minted,
                "caller-tag",
                b"v=0\r\n",
                &call,
                "rtp_passthrough",
                None,
            )
            .is_some());
            assert!(super::b2bua::b2bua_transfer_rtpengine_answer(
                &state,
                &minted,
                "caller-tag",
                "target-tag",
                b"v=0\r\n",
                "transfer-target@192.0.2.1",
                &crate::rtpengine::session::SideFlags {
                    profile: "rtp_passthrough".to_string(),
                    half: crate::rtpengine::session::ProfileHalf::Answer,
                },
                None,
            )
            .is_some());
        });
        backend
            .delete(&call, "caller-tag")
            .await
            .expect("the old anchor is deleted");
        engine_reports(&events, ended(&call, "caller-tag", "CallEnded")).await;

        assert_eq!(
            attach_outcomes(&mut audit).await,
            (1, 0),
            "{at_offer}: the new engine call is attached"
        );
        let attached: Vec<String> = engine
            .commands("attach_x3")
            .into_iter()
            .map(|command| command.call_id)
            .collect();
        assert_eq!(attached, vec![call.clone(), minted.clone()], "{at_offer}");
        assert!(engine.commands("detach_x3").is_empty(), "{at_offer}");
        assert_eq!(
            li.x3_attachments_for(&minted).len(),
            1,
            "{at_offer}: live on the engine call that holds the media"
        );
        assert!(li.x3_attachments_for(&call).is_empty(), "{at_offer}");
        assert_eq!(li.x3_attachment_count(), 1, "{at_offer}: exactly one");

        // A later ACK on the caller's dialog asks for nothing more, and not
        // for the engine call that is gone.
        let ack = on_call(CALLER_ACK, &call)
            .replace("CSeq: 1 ACK", "CSeq: 2 ACK")
            .replace("z9hG4bK-caller-ack", "z9hG4bK-caller-reack");
        arrives(&state, CALLER, &ack);
        assert_eq!(attach_outcomes(&mut audit).await, (0, 0), "{at_offer}");
        assert_eq!(engine.commands("attach_x3").len(), 2, "{at_offer}");

        // The call ends: the BYE detaches the live engine call's delivery.
        let bye = on_call(CALLER_ACK, &call)
            .replace("ACK sip:", "BYE sip:")
            .replace("CSeq: 1 ACK", "CSeq: 3 BYE")
            .replace("z9hG4bK-caller-ack", "z9hG4bK-caller-bye");
        arrives(&state, CALLER, &bye);
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let detached = engine.commands("detach_x3");
        assert_eq!(detached.len(), 1, "{at_offer}");
        assert_eq!(detached[0].call_id, minted, "{at_offer}");
        backend
            .delete(&minted, "caller-tag")
            .await
            .expect("the engine call is deleted");
    }
}

// ── Engine calls siphon mints ───────────────────────────────────────────────
//
// The control plane's verbs put a call's media on an engine call under an id
// of siphon's own: `dial` (the caller's offer, on an allocation of its own),
// `bridge`, `replace_peer` and `accept_refer` (the pair's fresh engine call,
// one step of the bridge plan), an originate's early offer, and a transfer or
// take-over (the survivor's media, offered afresh). None of those ids is a
// Call-ID. Each allocation says which dialog's SDP it carries, and that is
// what binds it to the dialog's lawful-intercept session, in the one place
// every offer is sent from.

/// The SDP a control verb offers for the caller.
const CALLER_SDP: &str = concat!(
    "v=0\r\n",
    "o=- 1 1 IN IP4 192.0.2.10\r\n",
    "s=-\r\n",
    "c=IN IP4 192.0.2.10\r\n",
    "t=0 0\r\n",
    "m=audio 40000 RTP/AVP 0\r\n",
);

/// The caller's INVITE on `call_id`, with an offer in it.
fn caller_invite_with_sdp(call_id: &str) -> String {
    on_call(CALLER_INVITE, call_id).replace(
        "Content-Length: 0\r\n\r\n",
        &format!(
            "Content-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{CALLER_SDP}",
            CALLER_SDP.len()
        ),
    )
}

fn caller_side() -> crate::rtpengine::session::SideFlags {
    crate::rtpengine::session::SideFlags {
        profile: "rtp_passthrough".to_string(),
        half: crate::rtpengine::session::ProfileHalf::Offer,
    }
}

/// Run the media step `verb` takes for the caller on `call`, as the control
/// verb of that name does.
fn mint_engine_call(verb: &str, state: &Arc<DispatcherState>, call: &str) {
    let source: std::net::IpAddr = "192.0.2.10".parse().expect("a literal address");
    tokio::task::block_in_place(|| match verb {
        "dial" => {
            let invite = parse_sip_message_bytes(caller_invite_with_sdp(call).as_bytes())
                .expect("the INVITE parses");
            super::b2bua::control_dial_media_offer(&invite, source, "rtp_passthrough", state)
                .expect("the dial's media is offered");
        }
        "bridge" => {
            let step = crate::b2bua::bridge::MediaStep::Offer {
                media_call_id: crate::b2bua::actor::generate_call_id(),
                from_tag: "caller-tag".to_string(),
                profile: "rtp_passthrough".to_string(),
                sdp: CALLER_SDP.as_bytes().to_vec(),
                received_from: Some(source),
                ingress: caller_side(),
                sip_call_id: call.to_string(),
            };
            let backend = backend_of(state);
            let offered =
                tokio::runtime::Handle::current().block_on(super::b2bua::bridge_run_media_step(
                    &backend,
                    state.rtpengine_profiles.as_ref(),
                    &step,
                ));
            assert!(matches!(offered, Ok(Some(_))), "the pair's offer");
        }
        "originate" => {
            let caller = super::b2bua::LegOfferCaller {
                sip_call_id: call.to_string(),
                from_tag: "caller-tag".to_string(),
                sdp: CALLER_SDP.as_bytes().to_vec(),
                source,
                ingress: caller_side(),
                relaying: false,
            };
            assert!(
                super::b2bua::allocate_leg_offer(&caller, "rtp_passthrough", state).is_ok(),
                "the leg's early offer"
            );
        }
        "transfer" => {
            assert!(super::b2bua::b2bua_transfer_rtpengine_offer(
                state,
                &crate::b2bua::actor::generate_call_id(),
                "caller-tag",
                CALLER_SDP.as_bytes(),
                call,
                "rtp_passthrough",
                None,
            )
            .is_some());
        }
        other => panic!("no such verb: {other}"),
    });
}

/// Each control verb that mints an engine call for an intercepted call has
/// that engine call attached, at its offer on an engine that takes an
/// interception there and at its answer on one that does not, and never under
/// the SIP Call-ID, which the engine holds no call for. With the caller's old
/// engine call released there is exactly one live interception, on the engine
/// call that holds the media.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_engine_call_a_control_verb_mints_is_attached() {
    for verb in ["dial", "bridge", "originate", "transfer"] {
        for at_offer in [true, false] {
            let case = format!("{verb} at_offer={at_offer}");
            let call = format!("minted-by-{verb}-{at_offer}@192.0.2.10");
            let engine = match at_offer {
                true => NativeTestEngine::start_with_x3().await,
                false => NativeTestEngine::start().await,
            };
            let (state, engine, li, _iri, mut audit) = intercepting_on_the_engine(engine).await;
            let events = engine_events(&state);
            let backend = backend_of(&state);
            let flags = NgFlags::default();
            arrives(&state, CALLER, &caller_invite_with_sdp(&call));
            // A dial is the caller's first allocation. Every other verb moves
            // media the caller's Call-ID already anchors.
            let anchored = verb != "dial";
            if anchored {
                backend
                    .offer(&call, "caller-tag", CALLER_SDP.as_bytes(), &flags)
                    .await
                    .expect("offered");
                backend
                    .answer(&call, "caller-tag", "callee-tag", b"v=0\r\n", &flags)
                    .await
                    .expect("answered");
                arrives(&state, CALLER, &on_call(CALLER_ACK, &call));
                assert_eq!(attach_outcomes(&mut audit).await, (1, 0), "{case}");
            }

            mint_engine_call(verb, &state, &call);
            let minted = engine
                .commands("offer")
                .last()
                .expect("the verb offered")
                .call_id
                .clone();
            assert_ne!(minted, call, "{case}: an id of siphon's own");
            // The other party answers on the minted engine call.
            let mut answer_flags = NgFlags::default();
            answer_flags.stamp_sip_call_id("other-party@192.0.2.1");
            backend
                .answer(
                    &minted,
                    "caller-tag",
                    "other-tag",
                    b"v=0\r\n",
                    &answer_flags,
                )
                .await
                .expect("answered");
            if anchored {
                backend
                    .delete(&call, "caller-tag")
                    .await
                    .expect("the old anchor is released");
                engine_reports(&events, ended(&call, "caller-tag", "CallEnded")).await;
            }

            assert_eq!(attach_outcomes(&mut audit).await, (1, 0), "{case}");
            let attached: Vec<String> = engine
                .commands("attach_x3")
                .into_iter()
                .map(|command| command.call_id)
                .collect();
            let expected = match anchored {
                true => vec![call.clone(), minted.clone()],
                false => vec![minted.clone()],
            };
            assert_eq!(attached, expected, "{case}");
            assert!(
                engine
                    .commands("attach_x3")
                    .iter()
                    .all(|command| !command.refused),
                "{case}: nothing asked of a call the engine does not hold"
            );
            assert_eq!(li.x3_attachments_for(&minted).len(), 1, "{case}");
            assert_eq!(li.x3_attachment_count(), 1, "{case}: exactly one live");

            // A later ACK asks for nothing more.
            let ack = on_call(CALLER_ACK, &call)
                .replace("CSeq: 1 ACK", "CSeq: 2 ACK")
                .replace("z9hG4bK-caller-ack", "z9hG4bK-caller-reack");
            arrives(&state, CALLER, &ack);
            assert_eq!(attach_outcomes(&mut audit).await, (0, 0), "{case}");
            backend
                .delete(&minted, "caller-tag")
                .await
                .expect("released");
        }
    }
}

/// A warrant activated after the call's media was moved onto an engine call
/// siphon minted, on a node that had nothing provisioned until then and so
/// remembers nothing of the call: what the media path holds says where the
/// media is, and the next ACK attaches there, not under the Call-ID.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_mid_call_warrant_attaches_on_the_engine_call_the_media_moved_to() {
    const CALL: &str = "mid-call-on-minted@192.0.2.10";
    let (state, engine, li, _iri, mut audit) =
        intercepting_on_the_engine(NativeTestEngine::start_with_x3().await).await;
    let warrant = li.tasks().list()[0].details.clone();
    li.tasks().deactivate(warrant.x_id).expect("no warrant yet");
    let backend = backend_of(&state);
    let flags = NgFlags::default();
    arrives(&state, CALLER, &caller_invite_with_sdp(CALL));
    backend
        .offer(CALL, "caller-tag", CALLER_SDP.as_bytes(), &flags)
        .await
        .expect("offered");
    mint_engine_call("transfer", &state, CALL);
    let minted = engine
        .commands("offer")
        .last()
        .expect("offered")
        .call_id
        .clone();
    backend
        .answer(&minted, "caller-tag", "target-tag", b"v=0\r\n", &flags)
        .await
        .expect("answered");
    backend
        .delete(CALL, "caller-tag")
        .await
        .expect("the old anchor is released");
    // What the transfer leaves in siphon's media store for the caller.
    let sessions = state.rtpengine_sessions.as_ref().expect("a store");
    sessions.insert(crate::rtpengine::MediaSession {
        rtpengine_call_id: minted.clone(),
        ..super::li_session_tests::leg_session(CALL)
    });
    sessions.record_parties(CALL, &minted, &[(CALL, Some("caller-tag"))]);
    assert_eq!(
        attach_outcomes(&mut audit).await,
        (0, 0),
        "nobody is warranted"
    );

    li.tasks()
        .activate(warrant)
        .expect("the warrant arrives mid-call");
    arrives(&state, CALLER, &on_call(CALLER_ACK, CALL));
    assert_eq!(attach_outcomes(&mut audit).await, (1, 0));
    let attached = engine.commands("attach_x3");
    assert_eq!(attached.len(), 1);
    assert_eq!(attached[0].call_id, minted, "on the live allocation");
    assert!(!attached[0].refused);
    assert_eq!(attached[0].detail.as_deref(), Some("caller"));
    assert_eq!(li.x3_attachments_for(&minted).len(), 1);
    backend
        .delete(&minted, "caller-tag")
        .await
        .expect("released");
}

/// A transfer forked to two targets offers the caller's media on two minted
/// engine calls. The one whose target answers has the media, whichever was
/// offered last and whether the loser's engine call is gone yet. On an engine
/// that takes no interception before the answer it is attached at that
/// answer, once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_winner_of_a_forked_transfer_is_attached_before_the_loser_is_released() {
    let call = "forked-transfer@192.0.2.10";
    let (state, engine, li, _iri, mut audit) =
        intercepting_on_the_engine(NativeTestEngine::start().await).await;
    let backend = backend_of(&state);
    let flags = NgFlags::default();
    arrives(&state, CALLER, &caller_invite_with_sdp(call));
    backend
        .offer(call, "caller-tag", CALLER_SDP.as_bytes(), &flags)
        .await
        .expect("offered");
    backend
        .answer(call, "caller-tag", "callee-tag", b"v=0\r\n", &flags)
        .await
        .expect("answered");
    arrives(&state, CALLER, &on_call(CALLER_ACK, call));
    assert_eq!(attach_outcomes(&mut audit).await, (1, 0));

    // Two targets, each on an engine call of its own. The first is the winner.
    mint_engine_call("transfer", &state, call);
    let winner = engine
        .commands("offer")
        .last()
        .expect("offered")
        .call_id
        .clone();
    mint_engine_call("transfer", &state, call);
    let loser = engine
        .commands("offer")
        .last()
        .expect("offered")
        .call_id
        .clone();
    assert_ne!(winner, loser);
    backend
        .answer(&winner, "caller-tag", "winner-tag", b"v=0\r\n", &flags)
        .await
        .expect("the winner answers");
    assert_eq!(
        attach_outcomes(&mut audit).await,
        (1, 0),
        "attached at its answer, with the loser still offered"
    );
    // Only now is the loser released, and the caller's old engine call.
    backend
        .delete(&loser, "caller-tag")
        .await
        .expect("the loser is released");
    backend
        .delete(call, "caller-tag")
        .await
        .expect("the old anchor is released");
    assert_eq!(attach_outcomes(&mut audit).await, (0, 0));
    let attached: Vec<String> = engine
        .commands("attach_x3")
        .into_iter()
        .map(|command| command.call_id)
        .collect();
    assert_eq!(attached, vec![call.to_string(), winner.clone()]);
    assert_eq!(li.x3_attachments_for(&winner).len(), 1);
    assert!(li.x3_attachments_for(&loser).is_empty());
    assert_eq!(
        &*li.session_of_leg(call).expect("the session").engine_call_id,
        winner.as_str(),
        "and it is where the session's media is"
    );
    backend
        .delete(&winner, "caller-tag")
        .await
        .expect("released");
}

/// The engine ends a delivery while a `delete` siphon sent is still
/// unanswered. Whether that end is the one siphon asked for is what the
/// delete's answer says, so it is not judged until then: the engine refusing
/// the delete means it ended the delivery on its own, which is a fault, and
/// the engine taking it means the end was siphon's, which is clean.
#[tokio::test]
async fn an_end_reported_while_a_delete_is_out_is_judged_by_the_deletes_answer() {
    for refused in [true, false] {
        let call = format!("end-during-delete-{refused}@192.0.2.10");
        let (log, _guard) = capture_log();
        let (state, engine, li, _iri, mut audit) =
            intercepting_on_the_engine(NativeTestEngine::start_with_x3().await).await;
        let events = engine_events(&state);
        arrives(&state, CALLER, &on_call(CALLER_INVITE, &call));
        backend_of(&state)
            .offer(&call, "caller-tag", b"v=0\r\n", &NgFlags::default())
            .await
            .expect("offered");
        assert_eq!(attach_outcomes(&mut audit).await, (1, 0));

        if refused {
            engine.refuse_next("delete");
        }
        engine.hold_deletes();
        let deleting = {
            let (backend, call) = (backend_of(&state), call.clone());
            tokio::spawn(async move { backend.delete(&call, "caller-tag").await })
        };
        while engine.commands("delete").is_empty() {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        engine_reports(&events, ended(&call, "caller-tag", "CallEnded")).await;
        assert_eq!(
            faults_reported(&log),
            0,
            "refused={refused}: not judged while the delete is out"
        );
        assert_eq!(li.x3_attachment_count(), 1, "refused={refused}: on record");

        engine.release_deletes();
        let deleted = deleting.await.expect("the delete ran");
        assert_eq!(deleted.is_err(), refused);
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert_eq!(
            faults_reported(&log),
            usize::from(refused),
            "refused={refused}:\n{}",
            log.rendered()
        );
        assert_eq!(li.x3_attachment_count(), 0, "refused={refused}: drained");
        if refused {
            backend_of(&state)
                .delete(&call, "caller-tag")
                .await
                .expect("deleted");
        }
    }
}

/// An intercepted, offered proxy call whose `delete` is out, unanswered, with
/// the engine's `CallEnded` for its delivery already in: held, not judged.
async fn end_reported_while_a_delete_is_unanswered(
    call: &str,
) -> (
    Arc<DispatcherState>,
    NativeTestEngine,
    crate::li::LiManager,
    tokio::task::JoinHandle<Result<(), crate::rtpengine::RtpEngineError>>,
) {
    let (state, engine, li, _iri, mut audit) =
        intercepting_on_the_engine(NativeTestEngine::start_with_x3().await).await;
    let events = engine_events(&state);
    arrives(&state, CALLER, &on_call(CALLER_INVITE, call));
    backend_of(&state)
        .offer(call, "caller-tag", b"v=0\r\n", &NgFlags::default())
        .await
        .expect("offered");
    assert_eq!(attach_outcomes(&mut audit).await, (1, 0));
    engine.hold_deletes();
    let deleting = {
        let (backend, call) = (backend_of(&state), call.to_string());
        tokio::spawn(async move { backend.delete(&call, "caller-tag").await })
    };
    while engine.commands("delete").is_empty() {
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    engine_reports(&events, ended(call, "caller-tag", "CallEnded")).await;
    assert_eq!(li.x3_attachment_count(), 1, "held with its delivery");
    (state, engine, li, deleting)
}

/// The handler that asked for the delete is cancelled, and its future is
/// dropped with the command still out: no answer will ever be read. Nothing
/// then shows the engine took the delete, so the end that was waiting for
/// its answer is not siphon's: a fault, raised when the future goes.
#[tokio::test]
async fn an_end_held_for_a_delete_that_is_dropped_is_a_fault() {
    const CALL: &str = "delete-dropped@192.0.2.10";
    let (log, _guard) = capture_log();
    let (state, engine, li, deleting) = end_reported_while_a_delete_is_unanswered(CALL).await;
    assert_eq!(faults_reported(&log), 0);

    deleting.abort();
    assert!(deleting.await.is_err(), "the delete was cancelled");
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(faults_reported(&log), 1, "{}", log.rendered());
    assert_eq!(li.x3_attachment_count(), 0, "judged, and off the record");
    engine.release_deletes();
    drop(state);
}

/// The session is released with an end report still waiting on it. The
/// report is not dropped with the record: it is reported as an end nothing
/// shows siphon brought about.
#[tokio::test]
async fn an_end_still_held_when_its_session_is_released_is_a_fault() {
    const CALL: &str = "released-under-a-held-end@192.0.2.10";
    let (log, _guard) = capture_log();
    let (state, engine, li, deleting) = end_reported_while_a_delete_is_unanswered(CALL).await;
    let session_id = li.session_of_leg(CALL).expect("the session").session_id;

    li.forget_session(&session_id);
    assert_eq!(faults_reported(&log), 0, "not yet reported");
    sweep_stale_entries(&state).await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(faults_reported(&log), 1, "{}", log.rendered());
    assert_eq!(li.x3_call_count(), 0);

    // The delete's answer, when it comes, finds nothing left to judge.
    engine.release_deletes();
    deleting.await.expect("ran").expect("deleted");
    sweep_stale_entries(&state).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(faults_reported(&log), 1, "once");
}

/// The ADMF changes the task's Correlation ID while a call of the target is
/// up. The session's records keep the one they started with, X2 and X3
/// alike, and the session asking for its own delivery again is not a second
/// session: no attach, no fault.
#[tokio::test]
async fn a_task_modified_mid_call_leaves_the_sessions_correlation_as_it_was() {
    const CALL: &str = "task-modified@192.0.2.10";
    let (log, _guard) = capture_log();
    let (state, engine, li, mut iri, mut audit) =
        intercepting_on_the_engine(NativeTestEngine::start_with_x3().await).await;
    arrives(&state, CALLER, &on_call(CALLER_INVITE, CALL));
    backend_of(&state)
        .offer(CALL, "caller-tag", b"v=0\r\n", &NgFlags::default())
        .await
        .expect("offered");
    assert_eq!(attach_outcomes(&mut audit).await, (1, 0));
    let before = drain_iri(&mut iri)[0].correlation_id;
    assert_eq!(li.x3_attachments_for(CALL)[0].correlation_id, before);

    let mut modified = li.tasks().list()[0].details.clone();
    modified.correlation_id = Some(before.wrapping_add(4242));
    li.tasks().modify(modified).expect("the task is modified");

    arrives(&state, CALLEE, &on_call(&proxied_response("200 OK"), CALL));
    arrives(&state, CALLER, &on_call(CALLER_ACK, CALL));
    assert_eq!(
        attach_outcomes(&mut audit).await,
        (0, 0),
        "nothing asked again"
    );
    assert_eq!(engine.commands("attach_x3").len(), 1);
    assert_eq!(faults_reported(&log), 0, "{}", log.rendered());
    assert_eq!(
        li.x3_attachments_for(CALL)[0].correlation_id,
        before,
        "the delivery keeps its Correlation ID"
    );
    let after = drain_iri(&mut iri);
    assert_eq!(after.len(), 2);
    assert!(
        after.iter().all(|event| event.correlation_id == before),
        "and so do the session's X2 records"
    );

    // A call that starts after the change carries the new one.
    arrives(
        &state,
        CALLER,
        &on_call(CALLER_INVITE, "after-the-change@192.0.2.10"),
    );
    assert_eq!(
        drain_iri(&mut iri)[0].correlation_id,
        before.wrapping_add(4242)
    );
    backend_of(&state)
        .delete(CALL, "caller-tag")
        .await
        .expect("deleted");
}

/// The session cache is cleared when it reaches its cap, and every decision
/// with it, while the engine goes on delivering. The call's next message
/// rebuilds its session, and the session's Correlation ID is the one its
/// content is already going out under: the live delivery kept it. So the X2
/// records after the clear carry what the X3 does, also when the task's own
/// Correlation ID was changed meanwhile, and nothing is asked for again.
#[tokio::test]
async fn a_session_rebuilt_after_the_cache_is_cleared_keeps_its_correlation() {
    const CALL: &str = "cache-cleared@192.0.2.10";
    let (log, _guard) = capture_log();
    let (state, engine, li, mut iri, mut audit) =
        intercepting_on_the_engine(NativeTestEngine::start_with_x3().await).await;
    arrives(&state, CALLER, &on_call(CALLER_INVITE, CALL));
    backend_of(&state)
        .offer(CALL, "caller-tag", b"v=0\r\n", &NgFlags::default())
        .await
        .expect("offered");
    assert_eq!(attach_outcomes(&mut audit).await, (1, 0));
    let before = drain_iri(&mut iri)[0].correlation_id;

    let mut modified = li.tasks().list()[0].details.clone();
    modified.correlation_id = Some(before.wrapping_add(4242));
    li.tasks().modify(modified).expect("the task is modified");
    li.clear_session_cache();
    assert_eq!(li.remembered_session_count(), 0);

    arrives(&state, CALLEE, &on_call(&proxied_response("200 OK"), CALL));
    arrives(&state, CALLER, &on_call(CALLER_ACK, CALL));
    let after = drain_iri(&mut iri);
    assert_eq!(after.len(), 2);
    assert!(
        after.iter().all(|event| event.correlation_id == before),
        "X2 carries the Correlation ID the content is delivered under"
    );
    assert_eq!(
        attach_outcomes(&mut audit).await,
        (0, 0),
        "nothing asked again"
    );
    assert_eq!(engine.commands("attach_x3").len(), 1);
    assert_eq!(li.x3_attachments_for(CALL)[0].correlation_id, before);
    assert_eq!(faults_reported(&log), 0, "{}", log.rendered());
    backend_of(&state)
        .delete(CALL, "caller-tag")
        .await
        .expect("deleted");
}

/// Nine re-INVITEs are cancelled, and the far end's late 481 to the first
/// CANCEL arrives after all of them: it ends nothing and detaches nothing.
#[tokio::test]
async fn a_late_481_to_one_of_many_cancelled_re_invites_detaches_nothing() {
    const CALL: &str = "many-cancels@192.0.2.10";
    let (state, engine, li, mut iri, mut audit) =
        intercepting_on_the_engine(NativeTestEngine::start_with_x3().await).await;
    arrives(&state, CALLER, &on_call(CALLER_INVITE, CALL));
    backend_of(&state)
        .offer(CALL, "caller-tag", b"v=0\r\n", &NgFlags::default())
        .await
        .expect("offered");
    arrives(&state, CALLEE, &on_call(&proxied_response("200 OK"), CALL));
    arrives(&state, CALLER, &on_call(CALLER_ACK, CALL));
    assert_eq!(attach_outcomes(&mut audit).await, (1, 0));
    drain_iri(&mut iri);

    for cseq in 2..11 {
        let re_invite = on_call(CALLER_ACK, CALL)
            .replace("ACK sip:", "INVITE sip:")
            .replace("CSeq: 1 ACK", &format!("CSeq: {cseq} INVITE"))
            .replace("z9hG4bK-caller-ack", &format!("z9hG4bK-reinvite-{cseq}"));
        arrives(&state, CALLER, &re_invite);
        let cancel = re_invite.replace("INVITE sip:", "CANCEL sip:").replace(
            &format!("CSeq: {cseq} INVITE"),
            &format!("CSeq: {cseq} CANCEL"),
        );
        arrives(&state, CALLER, &cancel);
    }
    let late = on_call(
        &proxied_response("481 Call/Transaction Does Not Exist"),
        CALL,
    )
    .replace("CSeq: 1 INVITE", "CSeq: 2 CANCEL");
    arrives(&state, CALLEE, &late);
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    assert!(engine.commands("detach_x3").is_empty());
    assert_eq!(li.x3_attachments_for(CALL).len(), 1);
    assert!(drain_iri(&mut iri)
        .iter()
        .all(|event| event.event_type != crate::li::IriEventType::End));
    backend_of(&state)
        .delete(CALL, "caller-tag")
        .await
        .expect("deleted");
}

/// What the engine refused for good on an engine call stays refused when a
/// `delete` of that engine call fails: it is the same engine call, and a
/// later ACK does not ask again or report again.
#[tokio::test]
async fn a_failed_delete_does_not_ask_again_for_what_the_engine_refused() {
    const CALL: &str = "refused-then-delete-failed@192.0.2.10";
    let (log, _guard) = capture_log();
    let (state, engine, _li, _iri, mut audit) =
        intercepting_on_the_engine(NativeTestEngine::start_with_x3_at_offer().await).await;
    backend_of(&state)
        .answer_local(CALL, "caller-tag", "v=0\r\n", &NgFlags::default())
        .await
        .expect("answered by the engine");
    arrives(&state, CALLER, &on_call(CALLER_INVITE, CALL));
    arrives(&state, CALLER, &on_call(CALLER_ACK, CALL));
    assert_eq!(attach_outcomes(&mut audit).await, (1, 1));

    engine.refuse_next("delete");
    assert!(backend_of(&state).delete(CALL, "caller-tag").await.is_err());
    let ack = on_call(CALLER_ACK, CALL)
        .replace("CSeq: 1 ACK", "CSeq: 2 ACK")
        .replace("z9hG4bK-caller-ack", "z9hG4bK-caller-reack");
    arrives(&state, CALLER, &ack);
    assert_eq!(attach_outcomes(&mut audit).await, (0, 0), "not asked again");
    assert_eq!(engine.commands("attach_x3").len(), 1);
    assert_eq!(faults_reported(&log), 1, "{}", log.rendered());
    backend_of(&state)
        .delete(CALL, "caller-tag")
        .await
        .expect("deleted");
}

/// Two calls of one target are bridged onto one engine call. Each is a
/// session with a Correlation ID of its own, and the warrant owes each its
/// content under it. The engine holds one delivery of a warrant per engine
/// call, so the second cannot be delivered under its own: that is reported to
/// the ADMF, once, naming both Correlation IDs, and never dropped in silence.
#[tokio::test]
async fn a_second_session_on_one_engine_call_is_a_fault_naming_both_correlations() {
    const FIRST: &str = "bridged-first@192.0.2.10";
    const SECOND: &str = "bridged-second@192.0.2.10";
    const MINTED: &str = "bridged-pair-engine-call";
    let (log, _guard) = capture_log();
    let (state, engine, li, _iri, mut audit) =
        intercepting_on_the_engine(NativeTestEngine::start_with_x3().await).await;
    let backend = backend_of(&state);
    arrives(&state, CALLER, &on_call(CALLER_INVITE, FIRST));
    arrives(&state, CALLER, &on_call(CALLER_INVITE, SECOND));
    let correlation = |call: &str| {
        let session = li.session_of_leg(call).expect("the session");
        li.correlation_for(&session.matches[0].task, &session.session_id)
    };
    let (first, second) = (correlation(FIRST), correlation(SECOND));
    assert_ne!(first, second, "two sessions");

    // The pair's engine call: the first call's media offered, the second's
    // answering.
    let mut offer = NgFlags::default();
    offer.stamp_sip_call_id(FIRST);
    backend
        .offer(MINTED, "caller-tag", b"v=0\r\n", &offer)
        .await
        .expect("offered");
    assert_eq!(attach_outcomes(&mut audit).await, (1, 0));
    let mut answer = NgFlags::default();
    answer.stamp_sip_call_id(SECOND);
    backend
        .answer(MINTED, "caller-tag", "peer-tag", b"v=0\r\n", &answer)
        .await
        .expect("answered");

    assert_eq!(
        attach_outcomes(&mut audit).await,
        (1, 1),
        "the second session's is audited as not delivered"
    );
    assert_eq!(
        engine.commands("attach_x3").len(),
        1,
        "a second attach would replace the first session's delivery"
    );
    let rendered = log.rendered();
    assert_eq!(faults_reported(&log), 1, "{rendered}");
    assert!(
        rendered.contains(&format!("cannot be delivered under correlation {second}"))
            && rendered.contains(&format!("the session of correlation {first}")),
        "both Correlation IDs are named:\n{rendered}"
    );

    // Reported once: a later ACK of either call says nothing more.
    arrives(&state, CALLER, &on_call(CALLER_ACK, SECOND));
    assert_eq!(attach_outcomes(&mut audit).await, (0, 0));
    assert_eq!(faults_reported(&log), 1);

    // The second call ending detaches nothing: the delivery on the engine
    // call is the first session's, and the first call is still up.
    let bye = on_call(CALLER_ACK, SECOND)
        .replace("ACK sip:", "BYE sip:")
        .replace("CSeq: 1 ACK", "CSeq: 2 BYE")
        .replace("z9hG4bK-caller-ack", "z9hG4bK-caller-bye");
    arrives(&state, CALLER, &bye);
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(
        engine.commands("detach_x3").is_empty(),
        "the first session's delivery is not the second's to end"
    );
    assert_eq!(li.x3_attachments_for(MINTED).len(), 1);
    backend
        .delete(MINTED, "caller-tag")
        .await
        .expect("released");
}

/// A room that closes while the leg is being moved into it leaves the call's
/// media stopped. The engine refuses the seat and ends the interception with
/// `transport_error`, which is a fault toward the ADMF like any end siphon did
/// not ask for.
#[tokio::test]
async fn a_room_that_cannot_take_the_seat_ends_the_delivery_as_a_fault() {
    const CALL: &str = "seated-call-broken-room@192.0.2.10";
    const FAR: &str = "seated-call-broken-room-far@192.0.2.1";
    let (log, _guard) = capture_log();
    let (state, _engine, li, _iri, mut audit) =
        intercepting_on_the_engine(NativeTestEngine::start_with_x3().await).await;
    let events = engine_events(&state);
    let internal_id = answered_b2bua_call(&state, CALL, FAR).await;
    assert_eq!(attach_outcomes(&mut audit).await, (1, 0));

    let room = format!("{NATIVE_ENGINE_CLOSING_ROOM}room");
    let refused = backend_of(&state)
        .conference_seat_call(
            CALL,
            "callee-tag",
            &room,
            ConferenceRole::Talker,
            adopted(FAR, &internal_id),
        )
        .await;
    assert!(refused.is_err(), "the engine refuses the seat");
    engine_reports(&events, ended(CALL, "caller-tag", "TransportError")).await;

    assert_eq!(faults_reported(&log), 1, "{}", log.rendered());
    assert_eq!(li.x3_attachment_count(), 0);
    backend_of(&state)
        .delete(CALL, "caller-tag")
        .await
        .expect("the engine deletes the call");
}

/// A call siphon answers itself (an announcement, an IVR) is attached when the
/// engine has answered it, on an engine that lists `x3_single_leg`. A
/// re-answer of the same dialog keeps the interception and asks for nothing,
/// and so does the ACK. The call's `delete` ends it cleanly.
#[tokio::test]
async fn a_locally_answered_call_is_attached_at_its_answer() {
    const CALL: &str = "local-answer@192.0.2.10";
    let (log, _guard) = capture_log();
    let (state, engine, li, _iri, mut audit) =
        intercepting_on_the_engine(NativeTestEngine::start_with_x3().await).await;
    let events = engine_events(&state);
    let backend = backend_of(&state);
    let flags = NgFlags::default();
    arrives(&state, CALLER, &on_call(CALLER_INVITE, CALL));

    backend
        .answer_local(CALL, "caller-tag", "v=0\r\n", &flags)
        .await
        .expect("the engine answers the call itself");
    assert_eq!(
        attach_outcomes(&mut audit).await,
        (1, 0),
        "attached at the local answer"
    );
    let attached = engine.commands("attach_x3");
    assert_eq!(attached.len(), 1);
    assert_eq!(
        (attached[0].call_id.as_str(), attached[0].from_tag.as_str()),
        (CALL, "caller-tag")
    );
    assert!(!attached[0].refused);

    arrives(&state, CALLER, &on_call(CALLER_ACK, CALL));
    backend
        .answer_local(CALL, "caller-tag", "v=0\r\n", &flags)
        .await
        .expect("the same dialog is answered again");
    backend
        .offer_far(CALL, "caller-tag", &flags)
        .await
        .expect("a far leg is offered behind it");
    assert_eq!(attach_outcomes(&mut audit).await, (0, 0));
    assert_eq!(engine.commands("attach_x3").len(), 1, "one interception");
    assert!(engine.commands("detach_x3").is_empty());
    assert_eq!(li.x3_attachments_for(CALL).len(), 1);

    backend
        .delete(CALL, "caller-tag")
        .await
        .expect("the engine deletes the call");
    engine_reports(&events, ended(CALL, "caller-tag", "CallEnded")).await;
    assert_eq!(faults_reported(&log), 0, "{}", log.rendered());
    assert_eq!(li.x3_attachment_count(), 0);
}

/// Echo and an interception do not go together, either way round, and neither
/// refusal is swallowed. `echo` on an intercepted call is refused by the
/// engine: the script's verb fails with the engine's reason and the call
/// stays intercepted. An attach on a call already echoing is refused, and
/// that is warranted content not being delivered: a fault toward the ADMF.
#[tokio::test]
async fn echo_is_refused_on_an_intercepted_call_and_an_echoing_call_is_a_fault() {
    const INTERCEPTED: &str = "echo-on-intercepted@192.0.2.10";
    const ECHOING: &str = "attach-on-echoing@192.0.2.10";
    let (log, _guard) = capture_log();
    let (state, engine, li, _iri, mut audit) =
        intercepting_on_the_engine(NativeTestEngine::start_with_x3().await).await;
    let backend = backend_of(&state);
    let flags = NgFlags::default();

    arrives(&state, CALLER, &on_call(CALLER_INVITE, INTERCEPTED));
    backend
        .offer(INTERCEPTED, "caller-tag", b"v=0\r\n", &flags)
        .await
        .expect("offered");
    assert_eq!(attach_outcomes(&mut audit).await, (1, 0));
    let refused = backend
        .echo(INTERCEPTED, "caller-tag", true)
        .await
        .expect_err("the engine refuses echo on an intercepted call");
    assert!(
        refused.to_string().contains(NATIVE_ENGINE_ECHO_REFUSED),
        "the script is told why: {refused}"
    );
    assert_eq!(
        li.x3_attachments_for(INTERCEPTED).len(),
        1,
        "the call is intercepted as it was"
    );
    assert!(engine.commands("detach_x3").is_empty());
    assert_eq!(faults_reported(&log), 0, "content is still delivered");

    // The other way round: the call echoes before anything is attached.
    backend
        .answer_local(ECHOING, "caller-tag", "v=0\r\n", &flags)
        .await
        .expect("answered before the warrant's INVITE is seen");
    backend
        .echo(ECHOING, "caller-tag", true)
        .await
        .expect("an echo test on a call nothing intercepts");
    arrives(&state, CALLER, &on_call(CALLER_INVITE, ECHOING));
    arrives(&state, CALLER, &on_call(CALLER_ACK, ECHOING));
    assert_eq!(attach_outcomes(&mut audit).await, (1, 1));
    assert!(
        log.rendered().contains("NOT being delivered") && log.rendered().contains("echo mode"),
        "{}",
        log.rendered()
    );
    assert_eq!(faults_reported(&log), 1, "{}", log.rendered());

    for call in [INTERCEPTED, ECHOING] {
        backend
            .delete(call, "caller-tag")
            .await
            .expect("the engine deletes the call");
    }
}

// ── An attach the engine says to ask again ──────────────────────────────────

/// An offered, intercepted proxy call on `call_id` whose first attach the
/// engine refuses `refusals` times as a call that is being re-answered.
async fn attach_refused_for_now(
    call_id: &str,
    refusals: u32,
) -> (
    Arc<DispatcherState>,
    NativeTestEngine,
    crate::li::LiManager,
    tokio::sync::mpsc::Receiver<crate::li::AuditEntry>,
) {
    let (state, engine, li, _iri, audit) =
        intercepting_on_the_engine(NativeTestEngine::start_with_x3().await).await;
    // The engine has said what it lists, so the attach is asked at the offer.
    backend_of(&state)
        .learn_x3_feature(
            crate::rtpengine::siphon_rtp::X3Feature::AttachAtOffer,
            call_id,
            None,
        )
        .await
        .expect("the engine answers node_info");
    engine.refuse_attaches_for_now(refusals);
    arrives(&state, CALLER, &on_call(CALLER_INVITE, call_id));
    backend_of(&state)
        .offer(call_id, "caller-tag", b"v=0\r\n", &NgFlags::default())
        .await
        .expect("offered");
    (state, engine, li, audit)
}

/// The retries of one attach are over within about a second.
async fn retries_are_over() {
    tokio::time::sleep(std::time::Duration::from_millis(1_300)).await;
}

/// The engine refuses an attach while the call is being re-answered and says
/// to ask again. siphon does, and the third try is taken: one delivery, one
/// audit record, no failed attempt and no fault.
#[tokio::test]
async fn an_attach_refused_for_now_is_asked_again_until_it_is_taken() {
    const CALL: &str = "attach-retried@192.0.2.10";
    let (log, _guard) = capture_log();
    let (state, engine, li, mut audit) = attach_refused_for_now(CALL, 2).await;
    retries_are_over().await;

    assert_eq!(attach_outcomes(&mut audit).await, (1, 0));
    assert_eq!(engine.commands("attach_x3").len(), 3, "taken at the third");
    assert_eq!(li.x3_attachments_for(CALL).len(), 1);
    assert_eq!(faults_reported(&log), 0, "{}", log.rendered());
    backend_of(&state)
        .delete(CALL, "caller-tag")
        .await
        .expect("deleted");
}

/// An engine that keeps refusing is asked four times within about a second,
/// and then warranted content is not being delivered: a fault, once.
#[tokio::test]
async fn an_attach_refused_every_time_is_a_fault_when_the_retries_run_out() {
    const CALL: &str = "attach-retries-exhausted@192.0.2.10";
    let (log, _guard) = capture_log();
    let (state, engine, li, mut audit) = attach_refused_for_now(CALL, 100).await;
    retries_are_over().await;

    assert_eq!(
        attach_outcomes(&mut audit).await,
        (1, 1),
        "one failed attempt"
    );
    assert_eq!(
        engine.commands("attach_x3").len(),
        4,
        "the first and three more"
    );
    assert!(li.x3_attachments_for(CALL).is_empty());
    assert_eq!(faults_reported(&log), 1, "{}", log.rendered());
    backend_of(&state)
        .delete(CALL, "caller-tag")
        .await
        .expect("deleted");
}

/// A refusal that says nothing of asking again is a fault at once.
#[tokio::test]
async fn an_attach_refused_for_good_is_not_asked_again() {
    const CALL: &str = "attach-refused-for-good@192.0.2.10";
    let (log, _guard) = capture_log();
    let (state, engine, _li, _iri, mut audit) =
        intercepting_on_the_engine(NativeTestEngine::start_with_x3_at_offer().await).await;
    backend_of(&state)
        .answer_local(CALL, "caller-tag", "v=0\r\n", &NgFlags::default())
        .await
        .expect("answered by the engine");
    arrives(&state, CALLER, &on_call(CALLER_INVITE, CALL));
    arrives(&state, CALLER, &on_call(CALLER_ACK, CALL));
    assert_eq!(attach_outcomes(&mut audit).await, (1, 1));
    assert_eq!(engine.commands("attach_x3").len(), 1);
    assert_eq!(faults_reported(&log), 1, "{}", log.rendered());
    backend_of(&state)
        .delete(CALL, "caller-tag")
        .await
        .expect("deleted");
}

/// siphon releases the call's media while the attach is being retried (the
/// caller gave up): the retry stops, nothing more is asked of an engine call
/// that is gone, and nothing is a fault.
#[tokio::test]
async fn an_attach_being_retried_is_given_up_when_siphon_ends_the_call() {
    const CALL: &str = "attach-retry-abandoned@192.0.2.10";
    let (log, _guard) = capture_log();
    let (state, engine, li, mut audit) = attach_refused_for_now(CALL, 100).await;
    // The first try is refused; the call is released before the second.
    tokio::time::sleep(std::time::Duration::from_millis(40)).await;
    assert_eq!(engine.commands("attach_x3").len(), 1);
    backend_of(&state)
        .delete(CALL, "caller-tag")
        .await
        .expect("deleted");
    retries_are_over().await;

    assert_eq!(
        attach_outcomes(&mut audit).await,
        (0, 0),
        "no failed attempt"
    );
    assert_eq!(engine.commands("attach_x3").len(), 1, "not asked again");
    assert_eq!(li.x3_attachment_count(), 0, "nothing left on record");
    assert_eq!(faults_reported(&log), 0, "{}", log.rendered());
}

/// A refusal for good is the engine's answer for that engine call: asking
/// again at every later ACK would get it again and report it again. One
/// attach and one fault, until siphon ends the engine call.
#[tokio::test]
async fn an_attach_refused_for_good_is_asked_and_reported_once_per_engine_call() {
    const CALL: &str = "attach-refused-once@192.0.2.10";
    let (log, _guard) = capture_log();
    let (state, engine, _li, _iri, mut audit) =
        intercepting_on_the_engine(NativeTestEngine::start_with_x3_at_offer().await).await;
    backend_of(&state)
        .answer_local(CALL, "caller-tag", "v=0\r\n", &NgFlags::default())
        .await
        .expect("answered by the engine");
    arrives(&state, CALLER, &on_call(CALLER_INVITE, CALL));
    arrives(&state, CALLER, &on_call(CALLER_ACK, CALL));
    assert_eq!(attach_outcomes(&mut audit).await, (1, 1));

    // A re-INVITE on the same engine call, and its ACK.
    let re_invite = on_call(CALLER_ACK, CALL)
        .replace("ACK sip:", "INVITE sip:")
        .replace("CSeq: 1 ACK", "CSeq: 2 INVITE")
        .replace("z9hG4bK-caller-ack", "z9hG4bK-caller-reinvite");
    arrives(&state, CALLER, &re_invite);
    let ack = on_call(CALLER_ACK, CALL)
        .replace("CSeq: 1 ACK", "CSeq: 2 ACK")
        .replace("z9hG4bK-caller-ack", "z9hG4bK-caller-reack");
    arrives(&state, CALLER, &ack);
    assert_eq!(attach_outcomes(&mut audit).await, (0, 0), "not asked again");
    assert_eq!(engine.commands("attach_x3").len(), 1);
    assert_eq!(faults_reported(&log), 1, "{}", log.rendered());
    backend_of(&state)
        .delete(CALL, "caller-tag")
        .await
        .expect("deleted");
}

/// An attach that is refused after siphon has ended its engine call takes
/// only its own record with it. The engine call before it, whose delivery
/// siphon ended as well and the engine has not reported yet, keeps its own:
/// when that delivery turns out to have failed, the fault names its warrant.
#[tokio::test]
async fn a_late_refusal_does_not_erase_an_earlier_engine_calls_delivery() {
    const CALL: &str = "late-refusal@192.0.2.10";
    let (log, _guard) = capture_log();
    let (state, engine, li, mut audit) = attach_refused_for_now(CALL, 0).await;
    let events = engine_events(&state);
    let backend = backend_of(&state);
    let flags = NgFlags::default();
    assert_eq!(
        attach_outcomes(&mut audit).await,
        (1, 0),
        "the first is live"
    );

    // Offered again, which replaces the engine call; the new one's attach is
    // refused for now, and the call is released while it is being retried.
    engine.refuse_attaches_for_now(100);
    backend
        .offer(CALL, "caller-tag", b"v=0\r\n", &flags)
        .await
        .expect("offered again");
    tokio::time::sleep(std::time::Duration::from_millis(40)).await;
    backend.delete(CALL, "caller-tag").await.expect("deleted");
    retries_are_over().await;
    assert_eq!(faults_reported(&log), 0, "the given-up retry is no fault");
    assert_eq!(
        li.x3_attachment_count(),
        1,
        "the first engine call's delivery is still owed its end"
    );

    // The first delivery's end: its connection had failed.
    engine_reports(&events, ended(CALL, "caller-tag", "TransportError")).await;
    assert_eq!(faults_reported(&log), 1, "{}", log.rendered());
    assert!(
        log.rendered().contains("X3 delivery ended for task"),
        "reported against the warrant: {}",
        log.rendered()
    );
    assert_eq!(li.x3_attachment_count(), 0);
}

/// The caller re-INVITEs an established, intercepted call and then CANCELs
/// that re-INVITE (RFC 3261 §9.1: the CANCEL carries the re-INVITE's branch).
/// The call goes on as it was, and so does its interception: nothing is
/// detached.
#[tokio::test]
async fn a_cancelled_re_invite_keeps_the_calls_interception() {
    const CALL: &str = "re-invite-cancelled@192.0.2.10";
    let (state, engine, li, mut iri, mut audit) =
        intercepting_on_the_engine(NativeTestEngine::start_with_x3().await).await;
    arrives(&state, CALLER, &on_call(CALLER_INVITE, CALL));
    backend_of(&state)
        .offer(CALL, "caller-tag", b"v=0\r\n", &NgFlags::default())
        .await
        .expect("offered");
    arrives(&state, CALLEE, &on_call(&proxied_response("200 OK"), CALL));
    arrives(&state, CALLER, &on_call(CALLER_ACK, CALL));
    assert_eq!(attach_outcomes(&mut audit).await, (1, 0));
    drain_iri(&mut iri);

    let re_invite = on_call(CALLER_ACK, CALL)
        .replace("ACK sip:", "INVITE sip:")
        .replace("CSeq: 1 ACK", "CSeq: 2 INVITE")
        .replace("z9hG4bK-caller-ack", "z9hG4bK-caller-reinvite");
    arrives(&state, CALLER, &re_invite);
    let cancel = re_invite
        .replace("INVITE sip:", "CANCEL sip:")
        .replace("CSeq: 2 INVITE", "CSeq: 2 CANCEL");
    arrives(&state, CALLER, &cancel);
    // The far end had answered the re-INVITE already: nothing to cancel.
    let no_transaction = on_call(
        &proxied_response("481 Call/Transaction Does Not Exist"),
        CALL,
    )
    .replace("CSeq: 1 INVITE", "CSeq: 2 CANCEL");
    arrives(&state, CALLEE, &no_transaction);
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    assert!(
        engine.commands("detach_x3").is_empty(),
        "the call's content is still being delivered"
    );
    assert_eq!(li.x3_attachments_for(CALL).len(), 1);
    assert!(
        drain_iri(&mut iri)
            .iter()
            .all(|event| event.event_type != crate::li::IriEventType::End),
        "and the session has not ended"
    );
    backend_of(&state)
        .delete(CALL, "caller-tag")
        .await
        .expect("deleted");
}

/// The local tag siphon holds on the caller's dialog of `internal_id`.
fn siphon_tag(state: &Arc<DispatcherState>, internal_id: &str) -> String {
    state
        .call_actors
        .get_call(internal_id)
        .expect("the call")
        .a_leg
        .dialog
        .local_tag
        .clone()
}

/// An INVITE on a dialog of its own that asks to replace the caller's dialog
/// of the call (RFC 3891), from `from`.
fn replacing_invite(call_id: &str, from: &str, replaces: &str) -> String {
    format!(
        concat!(
            "INVITE sip:15550100042@siphon.example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 192.0.2.30:5060;branch=z9hG4bK-{call_id}\r\n",
            "Max-Forwards: 70\r\n",
            "From: <{from}>;tag=replacing-tag\r\n",
            "To: <sip:15550100042@siphon.example.com>\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: 1 INVITE\r\n",
            "Contact: <sip:192.0.2.30:5060>\r\n",
            "Replaces: {replaces}\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        call_id = call_id,
        from = from,
        replaces = replaces,
    )
}

/// An INVITE with `Replaces` arrives on a dialog of its own, before the
/// take-over moves it onto the call it names. It is signalling of that call,
/// so it is recorded in that call's session under its Correlation ID, whoever
/// sent it. One whose `Replaces` names no dialog here is a call of its own.
#[tokio::test]
async fn an_invite_with_replaces_joins_the_session_of_the_call_it_replaces() {
    let (state, _engine, _li, mut iri, _audit) =
        intercepting_on_the_engine(NativeTestEngine::start().await).await;
    let internal_id = caller_calls(&state);
    dial(&state, &internal_id, CALLEE_CALL_ID);
    arrives(&state, CALLEE, &callee_response(CALLEE_CALL_ID, "200 OK"));
    arrives(&state, CALLER, CALLER_ACK);
    let correlation = correlation_from_call_id(&internal_id);
    drain_iri(&mut iri);
    let replaces = format!(
        "{BASE_CALL_ID};to-tag={};from-tag=caller-tag",
        siphon_tag(&state, &internal_id)
    );

    // From the target's own second device, and from a party no warrant names.
    for (call_id, from) in [
        ("replacing-own@192.0.2.30", "sip:alice@example.com"),
        ("replacing-other@192.0.2.30", "sip:carol@example.com"),
    ] {
        arrives(
            &state,
            "192.0.2.30:5060",
            &replacing_invite(call_id, from, &replaces),
        );
        let events = drain_iri(&mut iri);
        assert_eq!(events.len(), 1, "{from}: recorded");
        assert_eq!(events[0].call_id, call_id, "under its own Call-ID");
        assert_eq!(
            events[0].correlation_id, correlation,
            "{from}: and the Correlation ID of the call it replaces a dialog of"
        );
    }

    // A Replaces that names no dialog here joins nothing.
    arrives(
        &state,
        "192.0.2.30:5060",
        &replacing_invite(
            "replacing-nothing@192.0.2.30",
            "sip:alice@example.com",
            &format!("{BASE_CALL_ID};to-tag=not-siphons;from-tag=caller-tag"),
        ),
    );
    let events = drain_iri(&mut iri);
    assert_eq!(events.len(), 1, "the target's own call is still recorded");
    assert_ne!(
        events[0].correlation_id, correlation,
        "as a call of its own"
    );
}

fn directions(events: &[IriEvent]) -> Vec<(String, Option<u16>, PayloadDirection)> {
    events
        .iter()
        .map(|event| (event.sip_method.clone(), event.status_code, event.direction))
        .collect()
}

/// TS 103 221-2 §5.2.6: each X2 record's direction is its message's, relative
/// to the target. With the caller under warrant, what the caller sends is
/// from the target on whichever dialog it sends it, and what the callee and a
/// transfer's third leg send is to the target.
#[tokio::test]
async fn x2_direction_follows_who_sent_each_message_on_every_leg() {
    use PayloadDirection::{SentFromTarget, SentToTarget};
    let (state, _engine, _li, mut iri, _audit) =
        intercepting_on_the_engine(NativeTestEngine::start().await).await;
    let internal_id = caller_calls(&state);
    dial(&state, &internal_id, CALLEE_CALL_ID);
    arrives(&state, CALLEE, &callee_response(CALLEE_CALL_ID, "200 OK"));
    arrives(&state, CALLER, CALLER_ACK);
    // The caller transfers: a REFER on its dialog, and the transfer target
    // answers on a third leg.
    let refer = CALLER_ACK
        .replace("ACK sip:", "REFER sip:")
        .replace("CSeq: 1 ACK", "CSeq: 2 REFER")
        .replace("z9hG4bK-caller-ack", "z9hG4bK-caller-refer");
    arrives(&state, CALLER, &refer);
    dial(&state, &internal_id, SECOND_CALLEE_CALL_ID);
    arrives(
        &state,
        CALLEE,
        &callee_response(SECOND_CALLEE_CALL_ID, "180 Ringing"),
    );
    arrives(
        &state,
        CALLEE,
        &callee_response(SECOND_CALLEE_CALL_ID, "200 OK"),
    );
    arrives(
        &state,
        CALLEE,
        &callee_request("BYE", 2, "z9hG4bK-third-bye")
            .replace(CALLEE_CALL_ID, SECOND_CALLEE_CALL_ID),
    );
    // The caller's answer to the BYE siphon relays to it.
    arrives(&state, CALLER, CALLER_BYE_OK);
    // And its own second dialog, replacing the first.
    let replaces = format!(
        "{BASE_CALL_ID};to-tag={};from-tag=caller-tag",
        siphon_tag(&state, &internal_id)
    );
    arrives(
        &state,
        "192.0.2.30:5060",
        &replacing_invite(
            "direction-own@192.0.2.30",
            "sip:alice@example.com",
            &replaces,
        ),
    );

    assert_eq!(
        directions(&drain_iri(&mut iri)),
        vec![
            ("INVITE".to_string(), None, SentFromTarget),
            ("INVITE".to_string(), Some(200), SentToTarget),
            ("ACK".to_string(), None, SentFromTarget),
            ("REFER".to_string(), None, SentFromTarget),
            ("INVITE".to_string(), Some(180), SentToTarget),
            ("INVITE".to_string(), Some(200), SentToTarget),
            ("BYE".to_string(), None, SentToTarget),
            ("BYE".to_string(), Some(200), SentFromTarget),
            ("INVITE".to_string(), None, SentFromTarget),
        ]
    );
}

/// The same with the callee under warrant, on a proxy, where both ends send
/// on the one dialog: the direction turns with the sender.
#[tokio::test]
async fn x2_direction_turns_with_the_sender_on_a_proxied_dialog() {
    use PayloadDirection::{SentFromTarget, SentToTarget};
    let (state, _engine, li, mut iri, _audit) =
        intercepting_on_the_engine(NativeTestEngine::start().await).await;
    // The warrant names the callee.
    let mut callee = li.tasks().list()[0].details.clone();
    li.tasks()
        .deactivate(callee.x_id)
        .expect("the caller's warrant is withdrawn");
    callee.target_identifiers = vec![crate::li::x1::types::TargetIdentifier::SipUri(
        "sip:15550100042@siphon.example.com".to_string(),
    )];
    li.tasks().activate(callee).expect("task must provision");

    arrives(&state, CALLER, CALLER_INVITE);
    arrives(&state, CALLEE, &proxied_response("200 OK"));
    arrives(&state, CALLER, CALLER_ACK);
    arrives(&state, CALLEE, &far_end_request("BYE", 1));
    assert_eq!(
        directions(&drain_iri(&mut iri)),
        vec![
            ("INVITE".to_string(), None, SentToTarget),
            ("INVITE".to_string(), Some(200), SentFromTarget),
            ("ACK".to_string(), None, SentToTarget),
            ("BYE".to_string(), None, SentFromTarget),
        ]
    );
}

/// The called party is under warrant on a B2BUA call, and the caller transfers
/// it: siphon dials the transfer target on a third leg. The called party's
/// own leg is from the target. The third party is somebody else, and nothing
/// it sends is delivered as sent by the target: to the target where that is
/// known, and not known (1) otherwise.
#[tokio::test]
async fn a_transfers_third_leg_is_never_from_a_called_target() {
    use crate::b2bua::actor::{ReferSubscription, ReplacementTarget};
    use crate::b2bua::transfer::TransferState;
    use PayloadDirection::{SentFromTarget, SentToTarget, Unknown};
    let (state, _engine, li, mut iri, _audit) =
        intercepting_on_the_engine(NativeTestEngine::start().await).await;
    let mut callee = li.tasks().list()[0].details.clone();
    li.tasks()
        .deactivate(callee.x_id)
        .expect("the caller's warrant is withdrawn");
    callee.target_identifiers = vec![crate::li::x1::types::TargetIdentifier::SipUri(
        "sip:15550100042@siphon.example.com".to_string(),
    )];
    li.tasks().activate(callee).expect("task must provision");

    let internal_id = caller_calls(&state);
    dial(&state, &internal_id, CALLEE_CALL_ID);
    arrives(&state, CALLEE, &callee_response(CALLEE_CALL_ID, "200 OK"));
    arrives(&state, CALLER, CALLER_ACK);
    // The transfer: a replacement of the caller's leg dials its target.
    state.call_actors.push_refer_subscription(
        &internal_id,
        ReferSubscription {
            on_a_leg: true,
            siphon_notifies: true,
            origin: crate::b2bua::transfer::ReplacementOrigin::SiphonInitiated,
            event_id: 0,
            notify_cseq: 0,
            state: TransferState::Trying,
            targets: Vec::new(),
            referrer_gone: false,
            deadline: None,
            media_profile: None,
        },
    );
    dial(&state, &internal_id, SECOND_CALLEE_CALL_ID);
    let target = ReplacementTarget::ringing(
        format!("z9hG4bK-{SECOND_CALLEE_CALL_ID}"),
        SECOND_CALLEE_CALL_ID.to_string(),
        None,
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    assert!(state
        .call_actors
        .add_replacement_target(&internal_id, true, target, deadline)
        .is_none());
    arrives(
        &state,
        CALLEE,
        &callee_response(SECOND_CALLEE_CALL_ID, "180 Ringing"),
    );
    arrives(
        &state,
        CALLEE,
        &callee_response(SECOND_CALLEE_CALL_ID, "200 OK"),
    );
    arrives(
        &state,
        CALLEE,
        &callee_request("INFO", 2, "z9hG4bK-callee-info"),
    );

    let seen = directions(&drain_iri(&mut iri));
    assert_eq!(
        seen[..3],
        [
            ("INVITE".to_string(), None, SentToTarget),
            ("INVITE".to_string(), Some(200), SentFromTarget),
            ("ACK".to_string(), None, SentToTarget),
        ],
        "the caller's and the called party's own"
    );
    for third in &seen[3..5] {
        assert!(
            matches!(third.2, SentToTarget | Unknown),
            "the third party's {third:?} is not the target's"
        );
    }
    assert_eq!(
        seen[5],
        ("INFO".to_string(), None, SentFromTarget),
        "and the called party is still told from it"
    );
}

/// A request from the far end of the caller's proxied dialog: `From` is the
/// callee, `To` the caller.
fn far_end_request(method: &str, cseq: u32) -> String {
    format!(
        concat!(
            "{method} sip:alice@192.0.2.10:5060 SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 198.51.100.77:5060;branch=z9hG4bK-far-{method}-{cseq}\r\n",
            "Max-Forwards: 70\r\n",
            "From: <sip:15550100042@siphon.example.com>;tag=callee-tag\r\n",
            "To: <sip:alice@example.com>;tag=caller-tag\r\n",
            "Call-ID: caller-call@192.0.2.10\r\n",
            "CSeq: {cseq} {method}\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        method = method,
        cseq = cseq,
    )
}

/// A warrant activated while the target's call is up is decided on whatever
/// message comes next. When that is a request from the far end, the caller is
/// in `To`: the warrant still names the caller, and the engine is told the
/// caller is the target, or every delivered packet's direction is inverted.
/// The same call seen from its start gives the same answer.
#[tokio::test]
async fn a_warrant_activated_mid_call_names_the_end_the_target_is_on() {
    for mid_call in [true, false] {
        let (state, engine, li, _iri, mut audit) =
            intercepting_on_the_engine(NativeTestEngine::start().await).await;
        let warrant = li.tasks().list()[0].details.clone();
        if mid_call {
            li.tasks().deactivate(warrant.x_id).expect("no warrant yet");
        }
        // The call is set up: alice calls, the script anchors the media.
        arrives(&state, CALLER, CALLER_INVITE);
        backend_of(&state)
            .offer(BASE_CALL_ID, "caller-tag", b"v=0\r\n", &NgFlags::default())
            .await
            .expect("offered");
        arrives(&state, CALLEE, &proxied_response("200 OK"));
        if mid_call {
            li.tasks()
                .activate(warrant)
                .expect("the warrant arrives mid-call");
        }

        // The far end re-INVITEs and ACKs the answer.
        arrives(&state, CALLEE, &far_end_request("INVITE", 1));
        arrives(&state, CALLEE, &far_end_request("ACK", 1));
        assert_eq!(
            attach_outcomes(&mut audit).await,
            (1, 0),
            "mid_call={mid_call}"
        );
        let attached = engine.commands("attach_x3");
        assert_eq!(attached.len(), 1, "mid_call={mid_call}");
        assert_eq!(
            attached[0].detail.as_deref(),
            Some("caller"),
            "mid_call={mid_call}: alice opened the dialog, so the target is the caller's leg"
        );
        backend_of(&state)
            .delete(BASE_CALL_ID, "caller-tag")
            .await
            .expect("deleted");
    }
}
