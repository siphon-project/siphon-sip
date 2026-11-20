//! Several content deliveries on one engine call.
//!
//! A siphon-rtp that lists `x3_multi_delivery` (0.26.0 and later) keys a
//! delivery by its warrant, its delivery address and its Correlation ID, takes
//! one `attach_x3` for each, ends each on its own and names the one on every
//! end and loss it reports. An engine before that holds one delivery per call
//! and ends it, in silence, for the next one asked for.
//!
//! Driven the way [`super::li_conference_tests`] drives a call, against the
//! in-process native engine as either of the two. The engine sends no events;
//! it keeps the `x3_ended` the real one would have sent, and each test passes
//! them on.

use super::li_session_tests::{
    arrives, attach_outcomes, backend_of, capture_log, engine_events, engine_reports,
    faults_reported, intercepting_on_the_engine, proxied_response, CALLEE, CALLER, CALLER_ACK,
    CALLER_INVITE,
};
use super::*;
use crate::li::x1::message::DestinationDetails;
use crate::li::x1::types::{DId, DeliveryAddress, DeliveryType, IpAddressPort, Port, XId};
use crate::li::LiManager;
use crate::rtpengine::events::{RtpEngineEvent, X3Delivery, X3EndedEvent, X3LossEvent};
use crate::rtpengine::test_native_engine::{NativeCommand, NativeTestEngine};
use crate::rtpengine::NgFlags;
use tokio::sync::mpsc;

const BASE_CALL_ID: &str = "caller-call@192.0.2.10";

/// `raw`, a message of the shared caller dialog, on the dialog `call_id`.
fn on_call(raw: &str, call_id: &str) -> String {
    raw.replace(BASE_CALL_ID, call_id)
}

/// The caller's BYE on the dialog `call_id`.
fn bye(call_id: &str) -> String {
    on_call(CALLER_ACK, call_id)
        .replace("ACK sip:", "BYE sip:")
        .replace("CSeq: 1 ACK", "CSeq: 2 BYE")
        .replace("z9hG4bK-caller-ack", "z9hG4bK-caller-bye")
}

/// A second content warrant on the caller, to the first one's destination.
fn second_warrant(li: &LiManager) -> XId {
    let mut second = li.tasks().list()[0].details.clone();
    second.x_id = XId::generate();
    let x_id = second.x_id;
    li.tasks().activate(second).expect("task must provision");
    x_id
}

/// A second destination for the one warrant there is.
fn second_destination(li: &LiManager) -> DId {
    let d_id = DId::generate();
    li.destinations()
        .create(DestinationDetails {
            d_id,
            friendly_name: None,
            delivery_type: DeliveryType::X2AndX3,
            delivery_address: DeliveryAddress::IpAddressAndPort(IpAddressPort {
                address: "192.0.2.51".parse().expect("a literal address"),
                port: Port::Tcp(42069),
            }),
        })
        .expect("destination must provision");
    let mut task = li.tasks().list()[0].details.clone();
    task.list_of_dids.push(d_id);
    li.tasks().modify(task).expect("task must take it");
    d_id
}

/// What a script's `rtpengine.offer()` does: the caller's offer reaches the
/// engine under the caller's Call-ID and tag.
async fn offers(state: &Arc<DispatcherState>, call_id: &str) {
    backend_of(state)
        .offer(call_id, "caller-tag", b"v=0\r\n", &NgFlags::default())
        .await
        .expect("the engine takes the offer");
}

/// The callee answers and the caller acknowledges, on a proxied call.
fn answered(state: &Arc<DispatcherState>, call_id: &str) {
    arrives(
        state,
        CALLEE,
        &on_call(&proxied_response("200 OK"), call_id),
    );
    arrives(state, CALLER, &on_call(CALLER_ACK, call_id));
}

/// The delivery an X3 command named.
fn named(command: &NativeCommand) -> X3Delivery {
    command
        .x3_delivery
        .clone()
        .expect("the command names a delivery")
}

/// The delivery of the warrant `x_id` among the attaches the engine was sent.
fn delivery_of(engine: &NativeTestEngine, x_id: XId) -> X3Delivery {
    engine
        .commands("attach_x3")
        .iter()
        .map(named)
        .find(|delivery| delivery.xid == x_id.as_bytes())
        .expect("the warrant was attached")
}

/// The engine's report that `delivery` on `call_id` ended.
fn ended(call_id: &str, reason: &str, delivery: Option<X3Delivery>) -> RtpEngineEvent {
    RtpEngineEvent::X3Ended(X3EndedEvent {
        call_id: call_id.to_string(),
        from_tag: "caller-tag".to_string(),
        delivery,
        reason: reason.to_string(),
        orderly: reason == "Detached",
        delivered: 320,
        dropped: 0,
    })
}

/// The engine's report that `delivery` on `call_id` dropped content.
fn loss(call_id: &str, delivery: Option<X3Delivery>) -> RtpEngineEvent {
    RtpEngineEvent::X3Loss(X3LossEvent {
        call_id: call_id.to_string(),
        from_tag: "caller-tag".to_string(),
        delivery,
        dropped: 5,
        delivered: 100,
        dropped_since_ms: 2_000,
    })
}

/// Pass on every `x3_ended` the engine would have sent for what it was asked
/// since the last time, and say how many there were.
async fn engine_reports_its_ends(
    events: &mpsc::Sender<RtpEngineEvent>,
    engine: &NativeTestEngine,
) -> usize {
    let ends = engine.take_x3_ends();
    let count = ends.len();
    for end in ends {
        engine_reports(events, end).await;
    }
    count
}

/// Two warrants cover one call. On an engine that carries several deliveries
/// each is attached, with its own warrant. A loss the engine reports for one
/// and a delivery connection failing for the other are each reported against
/// that warrant alone, and each leaves the other's record where it is.
#[tokio::test]
async fn two_warrants_on_one_call_are_two_deliveries_with_a_fault_each() {
    const CALL: &str = "multi-two-warrants@192.0.2.10";
    let (log, _guard) = capture_log();
    let (state, engine, li, _iri, mut audit) =
        intercepting_on_the_engine(NativeTestEngine::start_with_x3_026().await).await;
    let events = engine_events(&state);
    let first = li.tasks().list()[0].details.x_id;
    let second = second_warrant(&li);

    arrives(&state, CALLER, &on_call(CALLER_INVITE, CALL));
    offers(&state, CALL).await;
    assert_eq!(
        attach_outcomes(&mut audit).await,
        (2, 0),
        "one attach for each warrant"
    );
    assert_eq!(engine.commands("attach_x3").len(), 2);
    assert_eq!(engine.x3_delivery_count(), 2, "and the engine holds both");
    let (of_first, of_second) = (delivery_of(&engine, first), delivery_of(&engine, second));
    answered(&state, CALL);
    assert_eq!(
        attach_outcomes(&mut audit).await,
        (0, 0),
        "the ACK asks nothing"
    );
    assert_eq!(faults_reported(&log), 0, "{}", log.rendered());

    // The second warrant's delivery drops content.
    engine_reports(&events, loss(CALL, Some(of_second.clone()))).await;
    let rendered = log.rendered();
    assert_eq!(faults_reported(&log), 1, "one fault, not one per warrant");
    assert!(
        rendered.contains(&format!("X3 delivery loss on task {second}"))
            && !rendered.contains(&format!("X3 delivery loss on task {first}")),
        "against the warrant that lost it:\n{rendered}"
    );

    // The first warrant's delivery connection fails.
    engine_reports(&events, ended(CALL, "TransportError", Some(of_first))).await;
    let rendered = log.rendered();
    assert_eq!(faults_reported(&log), 2);
    assert!(
        rendered.contains(&format!("X3 delivery ended for task {first}"))
            && !rendered.contains(&format!("X3 delivery ended for task {second}")),
        "against the warrant that ended:\n{rendered}"
    );
    let left = li.x3_attachments_for(CALL);
    assert_eq!(left.len(), 1, "the other delivery is still on record");
    assert_eq!(left[0].x_id, second);

    // siphon releases the call: the delivery that is left ends with it.
    backend_of(&state)
        .delete(CALL, "caller-tag")
        .await
        .expect("deleted");
    engine_reports(&events, ended(CALL, "CallEnded", Some(of_second))).await;
    assert_eq!(faults_reported(&log), 2, "a clean end");
    assert_eq!(li.x3_attachment_count(), 0);
    assert!(
        engine.commands("detach_x3").is_empty(),
        "a delete is enough"
    );
}

/// Two calls of one target are bridged onto one engine call. Each is a
/// session with a Correlation ID of its own. On an engine that carries
/// several deliveries each is attached under its own, to the same warrant and
/// destination. One of the two ending detaches its own delivery, by name, and
/// the other's goes on.
#[tokio::test]
async fn two_bridged_sessions_are_two_deliveries_and_one_ending_detaches_its_own() {
    const FIRST: &str = "multi-bridged-first@192.0.2.10";
    const SECOND: &str = "multi-bridged-second@192.0.2.10";
    const MINTED: &str = "multi-bridged-engine-call";
    let (log, _guard) = capture_log();
    let (state, engine, li, _iri, mut audit) =
        intercepting_on_the_engine(NativeTestEngine::start_with_x3_026().await).await;
    let events = engine_events(&state);
    let backend = backend_of(&state);
    arrives(&state, CALLER, &on_call(CALLER_INVITE, FIRST));
    arrives(&state, CALLER, &on_call(CALLER_INVITE, SECOND));
    let correlation = |call: &str| {
        let session = li.session_of_leg(call).expect("the session");
        li.correlation_for(&session.matches[0].task, &session.session_id)
    };
    let (first, second) = (correlation(FIRST), correlation(SECOND));
    assert_ne!(first, second, "two sessions");

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
        (1, 0),
        "the second session's delivery is asked for, and taken"
    );
    let attached: Vec<X3Delivery> = engine.commands("attach_x3").iter().map(named).collect();
    assert_eq!(attached.len(), 2);
    assert_eq!(
        (attached[0].correlation_id, attached[1].correlation_id),
        (first, second),
        "each under its own Correlation ID"
    );
    assert_eq!(
        (attached[0].xid, &attached[0].address),
        (attached[1].xid, &attached[1].address),
        "of the one warrant, to the one destination"
    );
    assert_eq!(faults_reported(&log), 0, "{}", log.rendered());

    // The second call ends. The engine call lives on with the first's media.
    arrives(&state, CALLER, &bye(SECOND));
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let detached = engine.commands("detach_x3");
    assert_eq!(detached.len(), 1);
    assert_eq!(
        detached[0].x3_delivery.as_ref(),
        Some(&attached[1]),
        "its own delivery, by warrant, address and Correlation ID"
    );
    assert_eq!(engine.x3_delivery_count(), 1, "the first's is untouched");
    assert_eq!(engine_reports_its_ends(&events, &engine).await, 1);
    let left = li.x3_attachments_for(MINTED);
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].correlation_id, first, "and still on record");
    assert_eq!(faults_reported(&log), 0, "{}", log.rendered());

    // A fault on the first's delivery is still reported against it.
    engine_reports(&events, loss(MINTED, Some(attached[0].clone()))).await;
    assert_eq!(faults_reported(&log), 1);

    backend
        .delete(MINTED, "caller-tag")
        .await
        .expect("released");
    assert_eq!(engine_reports_its_ends(&events, &engine).await, 1);
    assert_eq!(faults_reported(&log), 1, "the call's end is clean");
    assert_eq!(li.x3_attachment_count(), 0);
}

/// An intercepting dispatcher on an engine that holds one delivery per call
/// (siphon-rtp 0.25.2), with the offered call `call_id` owed two deliveries:
/// what `second` provisions on top of the one warrant and destination.
async fn two_deliveries_owed_on_an_engine_that_holds_one(
    call_id: &str,
    second: impl FnOnce(&LiManager),
) -> (
    crate::log_capture::LogBuffer,
    tracing::subscriber::DefaultGuard,
    Arc<DispatcherState>,
    NativeTestEngine,
) {
    let (log, guard) = capture_log();
    let (state, engine, li, _iri, mut audit) =
        intercepting_on_the_engine(NativeTestEngine::start_with_x3().await).await;
    second(&li);
    arrives(&state, CALLER, &on_call(CALLER_INVITE, call_id));
    offers(&state, call_id).await;
    assert_eq!(
        attach_outcomes(&mut audit).await,
        (2, 1),
        "the second is audited as not delivered"
    );
    assert_eq!(
        engine.commands("attach_x3").len(),
        1,
        "and never asked for: it would end the first"
    );
    assert!(
        engine.take_x3_ends().is_empty(),
        "nothing was replaced at the engine"
    );
    assert_eq!(li.x3_attachments_for(call_id).len(), 1);
    assert_eq!(faults_reported(&log), 1, "{}", log.rendered());

    // Reported once: the ACK asks for nothing and says nothing more.
    answered(&state, call_id);
    assert_eq!(attach_outcomes(&mut audit).await, (0, 0));
    assert_eq!(engine.commands("attach_x3").len(), 1);
    assert_eq!(faults_reported(&log), 1);
    (log, guard, state, engine)
}

/// A second warrant on a call whose engine holds one delivery per call would
/// replace the first warrant's delivery without a word. It is not asked for:
/// the ADMF is told, naming the delivery that is there.
#[tokio::test]
async fn a_second_warrant_on_an_engine_that_holds_one_delivery_is_a_fault() {
    const CALL: &str = "single-two-warrants@192.0.2.10";
    let (log, _guard, state, _engine) =
        two_deliveries_owed_on_an_engine_that_holds_one(CALL, |li| {
            second_warrant(li);
        })
        .await;
    let rendered = log.rendered();
    assert!(
        rendered.contains("the media engine holds one delivery per call, and this call's is task"),
        "{rendered}"
    );
    backend_of(&state)
        .delete(CALL, "caller-tag")
        .await
        .expect("released");
}

/// The same for one warrant that names two destinations.
#[tokio::test]
async fn a_second_destination_on_an_engine_that_holds_one_delivery_is_a_fault() {
    const CALL: &str = "single-two-destinations@192.0.2.10";
    let (log, _guard, state, _engine) =
        two_deliveries_owed_on_an_engine_that_holds_one(CALL, |li| {
            second_destination(li);
        })
        .await;
    let rendered = log.rendered();
    assert!(
        rendered.contains("cannot be delivered to destination"),
        "{rendered}"
    );
    backend_of(&state)
        .delete(CALL, "caller-tag")
        .await
        .expect("released");
}

/// One warrant to two destinations is two deliveries on an engine that
/// carries several.
#[tokio::test]
async fn two_destinations_are_two_deliveries_on_an_engine_that_carries_several() {
    const CALL: &str = "multi-two-destinations@192.0.2.10";
    let (log, _guard) = capture_log();
    let (state, engine, li, _iri, mut audit) =
        intercepting_on_the_engine(NativeTestEngine::start_with_x3_026().await).await;
    second_destination(&li);
    arrives(&state, CALLER, &on_call(CALLER_INVITE, CALL));
    offers(&state, CALL).await;
    assert_eq!(attach_outcomes(&mut audit).await, (2, 0));
    let attached: Vec<X3Delivery> = engine.commands("attach_x3").iter().map(named).collect();
    assert_ne!(attached[0].address, attached[1].address);
    assert_eq!(attached[0].xid, attached[1].xid);
    assert_eq!(faults_reported(&log), 0, "{}", log.rendered());
    backend_of(&state)
        .delete(CALL, "caller-tag")
        .await
        .expect("released");
}

/// The caller's ACK of the answer on `call_id`, arriving late.
fn late_ack(call_id: &str) -> String {
    on_call(CALLER_ACK, call_id)
        .replace("CSeq: 1 ACK", "CSeq: 3 ACK")
        .replace("z9hG4bK-caller-ack", "z9hG4bK-caller-late-ack")
}

/// An ACK that crosses the BYE of its call arrives on a session that has
/// ended, whose delivery siphon has detached. It asks for nothing: the call
/// has had its one attach, the engine is left with no delivery, and the
/// detached one's end is clean.
#[tokio::test]
async fn an_ack_that_crosses_the_bye_asks_for_no_second_delivery() {
    const CALL: &str = "ended-ack-crosses-bye@192.0.2.10";
    let (log, _guard) = capture_log();
    let (state, engine, li, _iri, mut audit) =
        intercepting_on_the_engine(NativeTestEngine::start_with_x3_026().await).await;
    let events = engine_events(&state);
    arrives(&state, CALLER, &on_call(CALLER_INVITE, CALL));
    offers(&state, CALL).await;
    assert_eq!(attach_outcomes(&mut audit).await, (1, 0));
    arrives(&state, CALLEE, &on_call(&proxied_response("200 OK"), CALL));

    arrives(&state, CALLER, &bye(CALL));
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(engine.commands("detach_x3").len(), 1);
    arrives(&state, CALLER, &on_call(CALLER_ACK, CALL));
    arrives(&state, CALLER, &late_ack(CALL));
    assert_eq!(
        attach_outcomes(&mut audit).await,
        (0, 0),
        "a session that has ended is owed no delivery"
    );
    assert_eq!(engine.commands("attach_x3").len(), 1, "exactly one attach");
    assert_eq!(engine.x3_delivery_count(), 0, "nothing stale at the engine");
    assert!(li.x3_attachments_for(CALL).is_empty());

    assert_eq!(engine_reports_its_ends(&events, &engine).await, 1);
    assert_eq!(li.x3_attachment_count(), 0);
    backend_of(&state)
        .delete(CALL, "caller-tag")
        .await
        .expect("released");
    // And an ACK after the media is gone asks an engine that holds no call
    // for nothing either.
    arrives(
        &state,
        CALLER,
        &late_ack(CALL).replace("CSeq: 3 ACK", "CSeq: 4 ACK"),
    );
    assert_eq!(attach_outcomes(&mut audit).await, (0, 0));
    assert_eq!(engine_reports_its_ends(&events, &engine).await, 0);
    assert_eq!(faults_reported(&log), 0, "{}", log.rendered());
    assert_eq!(li.x3_attachment_count(), 0);
}

/// On an engine that is asked at the ACK, a call hung up before its ACK
/// arrives is never asked for: the first attach is not made on a session that
/// has ended any more than a second is. A call whose ACK came first has its
/// one attach and its one detach.
#[tokio::test]
async fn a_late_ack_after_the_bye_attaches_nothing_and_raises_no_fault() {
    const HUNG_UP: &str = "ended-bye-then-ack@192.0.2.10";
    const ANSWERED: &str = "ended-ack-then-bye@192.0.2.10";
    let (log, _guard) = capture_log();
    let engine = NativeTestEngine::start_with_features(&[
        "relay",
        "scope",
        crate::rtpengine::test_native_engine::NATIVE_ENGINE_X3_MULTI_DELIVERY,
    ])
    .await;
    let (state, engine, li, _iri, mut audit) = intercepting_on_the_engine(engine).await;
    let events = engine_events(&state);
    for call in [HUNG_UP, ANSWERED] {
        arrives(&state, CALLER, &on_call(CALLER_INVITE, call));
        offers(&state, call).await;
        arrives(&state, CALLEE, &on_call(&proxied_response("200 OK"), call));
    }
    assert_eq!(
        attach_outcomes(&mut audit).await,
        (0, 0),
        "asked at the ACK"
    );

    arrives(&state, CALLER, &bye(HUNG_UP));
    arrives(&state, CALLER, &on_call(CALLER_ACK, HUNG_UP));
    assert_eq!(attach_outcomes(&mut audit).await, (0, 0), "no attach");
    assert!(engine.commands("attach_x3").is_empty());
    assert!(engine.commands("detach_x3").is_empty());

    arrives(&state, CALLER, &on_call(CALLER_ACK, ANSWERED));
    assert_eq!(attach_outcomes(&mut audit).await, (1, 0));
    arrives(&state, CALLER, &bye(ANSWERED));
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(engine.commands("attach_x3").len(), 1, "exactly one attach");
    assert_eq!(engine.commands("detach_x3").len(), 1);
    assert_eq!(engine_reports_its_ends(&events, &engine).await, 1);

    for call in [HUNG_UP, ANSWERED] {
        backend_of(&state)
            .delete(call, "caller-tag")
            .await
            .expect("released");
    }
    assert_eq!(engine_reports_its_ends(&events, &engine).await, 0);
    assert_eq!(faults_reported(&log), 0, "{}", log.rendered());
    assert_eq!(engine.x3_delivery_count(), 0);
    assert_eq!(li.x3_attachment_count(), 0);
}

/// A CANCEL of the opening INVITE is taken for the end of its session, and
/// its delivery is detached. The answer that beat the CANCEL shows the call
/// up after all: the session is live again and owed its content, so its ACK
/// asks for the delivery again, and the detached one's end leaves that one
/// on record.
#[tokio::test]
async fn a_call_answered_despite_its_cancel_is_attached_again() {
    const CALL: &str = "ended-cancel-lost@192.0.2.10";
    let (log, _guard) = capture_log();
    let (state, engine, li, _iri, mut audit) =
        intercepting_on_the_engine(NativeTestEngine::start_with_x3_026().await).await;
    let events = engine_events(&state);
    arrives(&state, CALLER, &on_call(CALLER_INVITE, CALL));
    offers(&state, CALL).await;
    assert_eq!(attach_outcomes(&mut audit).await, (1, 0));

    let cancel = on_call(CALLER_INVITE, CALL)
        .replace("INVITE sip:", "CANCEL sip:")
        .replace("CSeq: 1 INVITE", "CSeq: 1 CANCEL");
    arrives(&state, CALLER, &cancel);
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(engine.commands("detach_x3").len(), 1);

    answered(&state, CALL);
    assert_eq!(
        attach_outcomes(&mut audit).await,
        (1, 0),
        "the call is up: asked for again"
    );
    assert_eq!(engine.x3_delivery_count(), 1);
    assert_eq!(engine_reports_its_ends(&events, &engine).await, 1);
    assert_eq!(li.x3_attachments_for(CALL).len(), 1, "and still on record");

    backend_of(&state)
        .delete(CALL, "caller-tag")
        .await
        .expect("released");
    assert_eq!(engine_reports_its_ends(&events, &engine).await, 1);
    assert_eq!(faults_reported(&log), 0, "{}", log.rendered());
    assert_eq!(li.x3_attachment_count(), 0);
}

/// An attach of a delivery the call already carries replaces it at the
/// engine, which reports the one it replaced ended, `detached`. siphon asked
/// for no detach, so that end is the replaced one's and the registration is
/// the live one's: it stays, and a fault on the delivery afterwards is still
/// reported against its warrant.
#[tokio::test]
async fn the_end_of_a_delivery_the_engine_replaced_does_not_consume_its_registration() {
    const CALL: &str = "multi-same-triple-replaced@192.0.2.10";
    let (log, _guard) = capture_log();
    let (state, engine, li, _iri, mut audit) =
        intercepting_on_the_engine(NativeTestEngine::start_with_x3_026().await).await;
    let events = engine_events(&state);
    arrives(&state, CALLER, &on_call(CALLER_INVITE, CALL));
    offers(&state, CALL).await;
    assert_eq!(attach_outcomes(&mut audit).await, (1, 0));
    let delivery = named(&engine.commands("attach_x3")[0]);

    // The same delivery reaches the engine a second time.
    backend_of(&state)
        .attach_x3(
            CALL,
            "caller-tag",
            &delivery.address,
            delivery.xid,
            delivery.correlation_id,
            crate::rtpengine::backend::X3TargetLeg::Caller,
        )
        .await
        .expect("the engine replaces the delivery by itself");
    assert_eq!(engine.x3_delivery_count(), 1, "replaced, not added");
    assert_eq!(
        engine_reports_its_ends(&events, &engine).await,
        1,
        "the replaced one is reported ended"
    );
    assert_eq!(
        li.x3_attachments_for(CALL).len(),
        1,
        "the registration is the live delivery's"
    );
    assert_eq!(faults_reported(&log), 0, "{}", log.rendered());

    engine_reports(&events, ended(CALL, "TransportError", Some(delivery))).await;
    assert_eq!(
        faults_reported(&log),
        1,
        "the live delivery failing is still a fault against its warrant:\n{}",
        log.rendered()
    );
    assert!(li.x3_attachments_for(CALL).is_empty());
    backend_of(&state)
        .delete(CALL, "caller-tag")
        .await
        .expect("released");
}

/// An engine before 0.26.0 names no delivery on what it reports. Its loss and
/// its end are the leg's, as they always were: reported against the leg's
/// warrant, and the end takes the leg's record.
#[tokio::test]
async fn a_report_that_names_no_delivery_is_still_the_legs() {
    const CALL: &str = "single-old-shape@192.0.2.10";
    let (log, _guard) = capture_log();
    let (state, engine, li, _iri, mut audit) =
        intercepting_on_the_engine(NativeTestEngine::start_with_x3().await).await;
    let events = engine_events(&state);
    let warrant = li.tasks().list()[0].details.x_id;
    arrives(&state, CALLER, &on_call(CALLER_INVITE, CALL));
    offers(&state, CALL).await;
    assert_eq!(attach_outcomes(&mut audit).await, (1, 0));

    engine_reports(&events, loss(CALL, None)).await;
    assert_eq!(faults_reported(&log), 1);
    assert!(log
        .rendered()
        .contains(&format!("X3 delivery loss on task {warrant}")));
    assert_eq!(li.x3_attachments_for(CALL).len(), 1);

    // siphon releases the call, and the engine's own end of it names nothing.
    backend_of(&state)
        .delete(CALL, "caller-tag")
        .await
        .expect("released");
    let ends = engine.take_x3_ends();
    assert_eq!(ends.len(), 1);
    assert!(
        matches!(&ends[0], RtpEngineEvent::X3Ended(ended) if ended.delivery.is_none()),
        "an engine that holds one delivery names none"
    );
    for end in ends {
        engine_reports(&events, end).await;
    }
    assert_eq!(faults_reported(&log), 1, "a clean end");
    assert_eq!(li.x3_attachment_count(), 0);

    // And an end siphon did not bring about is the leg's fault.
    offers(&state, CALL).await;
    assert_eq!(attach_outcomes(&mut audit).await, (1, 0));
    engine_reports(&events, ended(CALL, "TransportError", None)).await;
    assert_eq!(faults_reported(&log), 2);
    assert!(li.x3_attachments_for(CALL).is_empty());
    backend_of(&state)
        .delete(CALL, "caller-tag")
        .await
        .expect("released");
}

/// The leak gate for several deliveries on a call: calls under two warrants
/// that complete, that are routed again, and pairs of calls bridged onto one
/// engine call leave every lawful-intercept map, the media backend's and the
/// engine's deliveries at baseline.
#[tokio::test]
async fn calls_with_several_deliveries_drain_every_map_to_baseline() {
    const EACH: usize = 20;
    const KINDS: [&str; 4] = ["completed", "rerouted", "bridged", "late-ack"];
    let (state, engine, li, _iri, _audit) =
        intercepting_on_the_engine(NativeTestEngine::start_with_x3_026().await).await;
    second_warrant(&li);
    let backend = backend_of(&state);
    let events = engine_events(&state);
    let settle = || tokio::time::sleep(std::time::Duration::from_millis(10));
    let pass_on = || async {
        for end in engine.take_x3_ends() {
            events.send(end).await.expect("the event loop runs");
        }
    };
    let mut sessions = 0;

    for kind in KINDS {
        for index in 0..EACH {
            let call_id = format!("leak-multi-{kind}-{index}@192.0.2.10");
            arrives(&state, CALLER, &on_call(CALLER_INVITE, &call_id));
            sessions += 1;
            if kind == "bridged" {
                // A second call of the target, bridged with the first onto an
                // engine call of siphon's own.
                let peer = format!("leak-multi-peer-{index}@192.0.2.10");
                let minted = format!("leak-multi-minted-{index}");
                arrives(&state, CALLER, &on_call(CALLER_INVITE, &peer));
                sessions += 1;
                let mut offer = NgFlags::default();
                offer.stamp_sip_call_id(&call_id);
                backend
                    .offer(&minted, "caller-tag", b"v=0\r\n", &offer)
                    .await
                    .expect("offered");
                let mut answer = NgFlags::default();
                answer.stamp_sip_call_id(&peer);
                backend
                    .answer(&minted, "caller-tag", "peer-tag", b"v=0\r\n", &answer)
                    .await
                    .expect("answered");
                settle().await;
                // One hangs up, then the other, then the media is released.
                arrives(&state, CALLER, &bye(&peer));
                settle().await;
                pass_on().await;
                arrives(&state, CALLER, &bye(&call_id));
                settle().await;
                backend
                    .delete(&minted, "caller-tag")
                    .await
                    .expect("released");
                pass_on().await;
                continue;
            }
            offers(&state, &call_id).await;
            settle().await;
            if kind == "rerouted" {
                backend
                    .delete(&call_id, "caller-tag")
                    .await
                    .expect("released");
                offers(&state, &call_id).await;
                settle().await;
                pass_on().await;
            }
            answered(&state, &call_id);
            arrives(&state, CALLER, &bye(&call_id));
            settle().await;
            if kind == "late-ack" {
                // An ACK that crossed the BYE, before the media is released.
                arrives(&state, CALLER, &late_ack(&call_id));
                settle().await;
            }
            backend
                .delete(&call_id, "caller-tag")
                .await
                .expect("released");
            pass_on().await;
            if kind == "late-ack" {
                // And one more after it.
                let later = late_ack(&call_id).replace("CSeq: 3 ACK", "CSeq: 4 ACK");
                arrives(&state, CALLER, &later);
                settle().await;
            }
        }
    }
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    assert_eq!(
        engine.x3_delivery_count(),
        0,
        "the engine holds no delivery"
    );
    assert_eq!(
        engine.commands("attach_x3").len(),
        // Two warrants: two for a completed call and for one with a late
        // ACK, four for one routed again, four for a bridged pair.
        EACH * (2 + 4 + 4 + 2),
        "one attach for each delivery of each engine call, and none after a call ended"
    );
    assert!(
        engine.take_x3_ends().is_empty(),
        "and every end was passed on"
    );
    assert_eq!(li.x3_attachment_count(), 0, "no delivery left on record");
    assert_eq!(
        li.remembered_session_count(),
        sessions,
        "kept for the grace"
    );
    li.sweep_sessions(
        std::time::Instant::now() + crate::li::SESSION_GRACE + std::time::Duration::from_secs(1),
        |_| false,
    );
    assert_eq!(li.remembered_session_count(), 0, "decisions drain");
    assert_eq!(li.session_alias_count(), 0, "aliases drain");
    assert_eq!(
        li.minted_engine_call_count(),
        0,
        "minted engine calls drain"
    );
    assert_eq!(li.x3_call_count(), 0, "engine-call records drain");
    assert!(li.take_unanswered_x3_ends(usize::MAX).is_empty());
    assert_eq!(backend.active_sessions(), 0, "the backend holds no call");
    assert_eq!(engine.held_count(), 0, "and neither does the engine");
}
