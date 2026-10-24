//! A warranted B2BUA call is one lawful-intercept session across its legs.
//!
//! Each leg of a B2BUA call is its own dialog with its own Call-ID. TS 103 221-2
//! clause 6 wants one Correlation ID across all of a session's X2 and X3
//! records, so interception resolves every leg to one session: the call's
//! internal id, which it mints on the caller's INVITE and the call adopts.
//!
//! Driven through [`intercept_message`], the chokepoint every inbound message
//! passes, against a real call store: the caller's INVITE, the callee's answer,
//! the caller's ACK, a re-INVITE from the far end with its ACK, the far end's
//! BYE and the caller's 200 to the BYE siphon relays.

use super::b_leg_2xx_ack_tests::{caller_leg, CALLER_CALL_ID};
use super::test_dispatcher::test_dispatcher;
use super::*;
use crate::config::LawfulInterceptConfig;
use crate::li::x1::message::{DestinationDetails, TaskDetails};
use crate::li::x1::store::ContentCapability;
use crate::li::x1::types::{
    DId, DeliveryAddress, DeliveryType, IpAddressPort, Port, TargetIdentifier, XId,
};
use crate::li::{correlation_from_call_id, AuditEntry, AuditOperation, IriEvent, LiManager};
use crate::rtpengine::test_engine::TestEngine;
use std::net::{IpAddr, Ipv4Addr};
use tokio::sync::mpsc;

const CALLER: &str = "192.0.2.10:5060";
const CALLEE: &str = "198.51.100.77:5060";
const CALLEE_CALL_ID: &str = "b2b-callee@192.0.2.1";
const SECOND_CALLEE_CALL_ID: &str = "b2b-callee-2@192.0.2.1";

/// The caller's INVITE. The warrant names the caller, in From.
const CALLER_INVITE: &str = concat!(
    "INVITE sip:15550100042@siphon.example.com SIP/2.0\r\n",
    "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-caller-invite\r\n",
    "Max-Forwards: 70\r\n",
    "From: <sip:alice@example.com>;tag=caller-tag\r\n",
    "To: <sip:15550100042@siphon.example.com>\r\n",
    "Call-ID: caller-call@192.0.2.10\r\n",
    "CSeq: 1 INVITE\r\n",
    "Contact: <sip:alice@192.0.2.10:5060>\r\n",
    "Content-Length: 0\r\n",
    "\r\n",
);

const CALLER_ACK: &str = concat!(
    "ACK sip:192.0.2.1:5060 SIP/2.0\r\n",
    "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-caller-ack\r\n",
    "Max-Forwards: 70\r\n",
    "From: <sip:alice@example.com>;tag=caller-tag\r\n",
    "To: <sip:15550100042@siphon.example.com>;tag=siphon-tag\r\n",
    "Call-ID: caller-call@192.0.2.10\r\n",
    "CSeq: 1 ACK\r\n",
    "Content-Length: 0\r\n",
    "\r\n",
);

/// The caller's 200 to the BYE siphon sends it when the far end hangs up.
const CALLER_BYE_OK: &str = concat!(
    "SIP/2.0 200 OK\r\n",
    "Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-siphon-bye\r\n",
    "From: <sip:15550100042@siphon.example.com>;tag=siphon-tag\r\n",
    "To: <sip:alice@example.com>;tag=caller-tag\r\n",
    "Call-ID: caller-call@192.0.2.10\r\n",
    "CSeq: 1 BYE\r\n",
    "Content-Length: 0\r\n",
    "\r\n",
);

/// A response from the callee to the INVITE siphon sent it on `call_id`. The
/// callee leg carries none of the caller's identities: the B2BUA rewrote From
/// to a number and To to the carrier's host.
fn callee_response(call_id: &str, status_line: &str) -> String {
    format!(
        concat!(
            "SIP/2.0 {status_line}\r\n",
            "Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-{call_id}\r\n",
            "From: <sip:15550100001@192.0.2.1>;tag=siphon-leg\r\n",
            "To: <sip:15550100042@198.51.100.77>;tag=callee-tag\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: 1 INVITE\r\n",
            "Contact: <sip:15550100042@198.51.100.77:5060>\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        status_line = status_line,
        call_id = call_id,
    )
}

/// A request from the callee on its dialog with siphon.
fn callee_request(method: &str, cseq: u32, branch: &str) -> String {
    format!(
        concat!(
            "{method} sip:192.0.2.1:5060 SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 198.51.100.77:5060;branch={branch}\r\n",
            "Max-Forwards: 70\r\n",
            "From: <sip:15550100042@198.51.100.77>;tag=callee-tag\r\n",
            "To: <sip:15550100001@192.0.2.1>;tag=siphon-leg\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: {cseq} {method}\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        method = method,
        branch = branch,
        call_id = CALLEE_CALL_ID,
        cseq = cseq,
    )
}

fn arrives(state: &Arc<DispatcherState>, source: &str, raw: &str) {
    let message = parse_sip_message_bytes(raw.as_bytes()).expect("the message parses");
    let inbound = InboundMessage {
        client_transport: None,
        connection_id: ConnectionId::default(),
        transport: Transport::Udp,
        local_addr: "192.0.2.1:5060".parse().expect("a literal address"),
        remote_addr: source.parse().expect("a literal address"),
        data: Bytes::from(raw.to_string()),
    };
    intercept_message(&message, &inbound, state);
}

/// A dispatcher with interception on and one content warrant on the caller.
fn intercepting() -> (
    Arc<DispatcherState>,
    LiManager,
    mpsc::Receiver<IriEvent>,
    mpsc::Receiver<AuditEntry>,
) {
    intercepting_on(test_dispatcher())
}

/// [`intercepting`] on a dispatcher the test prepared (a media engine, say).
fn intercepting_on(
    mut dispatcher: super::test_dispatcher::TestDispatcher,
) -> (
    Arc<DispatcherState>,
    LiManager,
    mpsc::Receiver<IriEvent>,
    mpsc::Receiver<AuditEntry>,
) {
    let (li, iri, audit) = LiManager::new(
        LawfulInterceptConfig {
            enabled: true,
            audit_log: None,
            x1: None,
            x2: None,
            x3: None,
            siprec: None,
        },
        100,
        ContentCapability::Available,
    );
    let d_id = DId::generate();
    li.destinations()
        .create(DestinationDetails {
            d_id,
            friendly_name: None,
            delivery_type: DeliveryType::X2AndX3,
            delivery_address: DeliveryAddress::IpAddressAndPort(IpAddressPort {
                address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50)),
                port: Port::Tcp(42069),
            }),
        })
        .expect("destination must provision");
    li.tasks()
        .activate(TaskDetails {
            x_id: XId::generate(),
            target_identifiers: vec![TargetIdentifier::SipUri(
                "sip:alice@example.com".to_string(),
            )],
            delivery_type: DeliveryType::X2AndX3,
            list_of_dids: vec![d_id],
            list_of_dsids: Vec::new(),
            list_of_mediation_details: Vec::new(),
            correlation_id: None,
            implicit_deactivation_allowed: None,
            product_id: None,
            list_of_service_types: Vec::new(),
        })
        .expect("task must provision");

    dispatcher.state.li_manager = Some(li.clone());
    (Arc::new(dispatcher.state), li, iri, audit)
}

/// The caller's INVITE arrives, and the call is created the way
/// `handle_b2bua_invite` creates it. Returns the call's internal id.
fn caller_calls(state: &Arc<DispatcherState>) -> String {
    arrives(state, CALLER, CALLER_INVITE);
    create_b2bua_call(state, caller_leg())
}

/// A callee leg on `call_id`, as `b2bua_send_b_leg_invite` registers one.
fn dial(state: &Arc<DispatcherState>, internal_id: &str, call_id: &str) {
    let leg = Leg::new_b_leg(
        call_id.to_string(),
        "siphon-leg".to_string(),
        "sip:15550100042@198.51.100.77:5060".to_string(),
        format!("z9hG4bK-{call_id}"),
        LegTransport {
            remote_addr: CALLEE.parse().expect("a literal address"),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: None,
        },
    );
    assert!(state.call_actors.add_b_leg(internal_id, leg));
}

fn drain_iri(iri: &mut mpsc::Receiver<IriEvent>) -> Vec<IriEvent> {
    let mut events = Vec::new();
    while let Ok(event) = iri.try_recv() {
        events.push(event);
    }
    events
}

/// How many X3 attachments were attempted, waiting long enough for the
/// spawned attach tasks to report.
async fn attach_attempts(audit: &mut mpsc::Receiver<AuditEntry>) -> usize {
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let mut attempts = 0;
    while let Ok(entry) = audit.try_recv() {
        if entry.operation == AuditOperation::MediaCaptureStarted {
            attempts += 1;
        }
    }
    attempts
}

#[tokio::test]
async fn every_leg_of_a_warranted_b2bua_call_carries_one_correlation() {
    let (state, li, mut iri, _audit) = intercepting();
    let internal_id = caller_calls(&state);
    dial(&state, &internal_id, CALLEE_CALL_ID);

    arrives(
        &state,
        CALLEE,
        &callee_response(CALLEE_CALL_ID, "180 Ringing"),
    );
    arrives(&state, CALLEE, &callee_response(CALLEE_CALL_ID, "200 OK"));
    arrives(&state, CALLER, CALLER_ACK);
    arrives(
        &state,
        CALLEE,
        &callee_request("INVITE", 1, "z9hG4bK-far-reinvite"),
    );
    arrives(
        &state,
        CALLEE,
        &callee_request("ACK", 1, "z9hG4bK-far-reack"),
    );
    arrives(&state, CALLEE, &callee_request("BYE", 2, "z9hG4bK-far-bye"));
    arrives(&state, CALLER, CALLER_BYE_OK);

    let events = drain_iri(&mut iri);
    assert_eq!(
        events.len(),
        8,
        "every message on both legs is intercepted, the callee leg included \
         although none of its identities name the target"
    );
    let expected = correlation_from_call_id(&internal_id);
    for event in &events {
        assert_eq!(
            event.correlation_id, expected,
            "{} {:?} on {} must carry the call's correlation",
            event.sip_method, event.status_code, event.call_id
        );
    }
    assert!(
        events.iter().any(|event| event.call_id == CALLEE_CALL_ID)
            && events.iter().any(|event| event.call_id == CALLER_CALL_ID),
        "each record still carries its own leg's Call-ID"
    );
    assert_eq!(
        li.correlation_for(&li.tasks().list()[0], &internal_id),
        expected,
        "the correlation derives from the call's internal id, the CDR's key"
    );
    assert_eq!(
        events.last().map(|event| event.event_type),
        Some(crate::li::IriEventType::Continue),
        "the 200 to the BYE closes the session it belongs to"
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| event.event_type == crate::li::IriEventType::End)
            .count(),
        1,
        "the far end's BYE is the one end"
    );
}

#[tokio::test]
async fn a_re_invite_from_the_far_end_does_not_attach_content_twice() {
    let (state, _li, _iri, mut audit) = intercepting();
    let engine = TestEngine::start(false).await;
    // The real backend here refuses X3 (only one engine delivers it), and an
    // attempt is audited either way, which makes each attempt countable.
    let state = {
        let mut state = Arc::try_unwrap(state).unwrap_or_else(|_| panic!("one owner"));
        state.rtpengine_set = Some(engine.backend().await);
        Arc::new(state)
    };
    let internal_id = caller_calls(&state);
    dial(&state, &internal_id, CALLEE_CALL_ID);
    arrives(&state, CALLEE, &callee_response(CALLEE_CALL_ID, "200 OK"));

    arrives(&state, CALLER, CALLER_ACK);
    assert_eq!(
        attach_attempts(&mut audit).await,
        1,
        "the caller's ACK attaches"
    );

    arrives(
        &state,
        CALLEE,
        &callee_request("INVITE", 1, "z9hG4bK-far-reinvite"),
    );
    arrives(
        &state,
        CALLEE,
        &callee_request("ACK", 1, "z9hG4bK-far-reack"),
    );
    assert_eq!(
        attach_attempts(&mut audit).await,
        0,
        "the callee leg's ACK must not open a second content stream"
    );
}

#[tokio::test]
async fn the_far_end_hanging_up_stops_content_capture() {
    let (state, li, _iri, _audit) = intercepting();
    let internal_id = caller_calls(&state);
    dial(&state, &internal_id, CALLEE_CALL_ID);
    arrives(&state, CALLEE, &callee_response(CALLEE_CALL_ID, "200 OK"));
    arrives(&state, CALLER, CALLER_ACK);
    // What a successful attach records: on the call-id the engine knows the
    // call by, the caller leg's.
    li.record_x3_attachment(
        CALLER_CALL_ID,
        crate::li::ActiveIntercept {
            x_id: li.tasks().list()[0].details.x_id,
            d_id: li.tasks().list()[0].details.list_of_dids[0],
            from_tag: "caller-tag".to_string(),
            correlation_id: correlation_from_call_id(&internal_id),
            scope: None,
        },
    );

    arrives(&state, CALLEE, &callee_request("BYE", 2, "z9hG4bK-far-bye"));
    assert_eq!(
        li.x3_attachment_count(),
        0,
        "a BYE on the callee leg ends the call, so its content capture"
    );
}

#[tokio::test]
async fn a_failed_carrier_does_not_end_the_session() {
    let (state, li, mut iri, _audit) = intercepting();
    let internal_id = caller_calls(&state);

    // The first carrier refuses; the call fails over to a second.
    dial(&state, &internal_id, CALLEE_CALL_ID);
    arrives(
        &state,
        CALLEE,
        &callee_response(CALLEE_CALL_ID, "503 Service Unavailable"),
    );
    dial(&state, &internal_id, SECOND_CALLEE_CALL_ID);
    arrives(
        &state,
        CALLEE,
        &callee_response(SECOND_CALLEE_CALL_ID, "200 OK"),
    );

    let events = drain_iri(&mut iri);
    assert!(
        events
            .iter()
            .all(|event| event.event_type != crate::li::IriEventType::End),
        "a carrier refusing is not the end of the call: {:?}",
        events
            .iter()
            .map(|event| event.event_type)
            .collect::<Vec<_>>()
    );
    let expected = correlation_from_call_id(&internal_id);
    assert!(events.iter().all(|event| event.correlation_id == expected));
    assert_eq!(li.remembered_session_count(), 1);
}

#[tokio::test]
async fn a_finished_call_releases_its_session() {
    let (state, li, _iri, _audit) = intercepting();
    for index in 0..50 {
        let internal_id = caller_calls(&state);
        dial(&state, &internal_id, CALLEE_CALL_ID);
        arrives(&state, CALLEE, &callee_response(CALLEE_CALL_ID, "200 OK"));
        arrives(&state, CALLER, CALLER_ACK);
        arrives(
            &state,
            CALLEE,
            &callee_request("BYE", 2, &format!("z9hG4bK-far-bye-{index}")),
        );
        state.call_actors.remove_call(&internal_id);
        // The periodic sweep notices the call is gone...
        sweep_stale_entries(&state).await;
    }
    assert!(li.remembered_session_count() > 0, "kept for the grace");

    // ...and releases it once the grace is over.
    li.sweep_sessions(
        std::time::Instant::now() + crate::li::SESSION_GRACE,
        |session_id| state.call_actors.contains_call(session_id),
    );
    assert_eq!(li.remembered_session_count(), 0, "decisions drain");
    assert_eq!(li.session_alias_count(), 0, "aliases drain");
}

#[tokio::test]
async fn a_call_that_fails_unanswered_releases_its_session() {
    // Nothing inbound follows the failure siphon sends the caller, so only the
    // call ending can end the session.
    let (state, li, _iri, _audit) = intercepting();
    let internal_id = caller_calls(&state);
    dial(&state, &internal_id, CALLEE_CALL_ID);
    arrives(
        &state,
        CALLEE,
        &callee_response(CALLEE_CALL_ID, "486 Busy Here"),
    );
    state.call_actors.remove_call(&internal_id);

    sweep_stale_entries(&state).await;
    li.sweep_sessions(
        std::time::Instant::now() + crate::li::SESSION_GRACE,
        |session_id| state.call_actors.contains_call(session_id),
    );
    assert_eq!(li.remembered_session_count(), 0);
    assert_eq!(li.session_alias_count(), 0);
}

/// A proxy call whose two legs a script anchored under per-call scopes, on a
/// media engine that delivers X3.
const PROXY_CALL_ID: &str = "proxy-scoped@192.0.2.10";

fn proxy_scoped_message(raw: &str) -> String {
    raw.replace("caller-call@192.0.2.10", PROXY_CALL_ID)
}

fn leg_scope(name: &str) -> crate::rtpengine::CallScope {
    crate::rtpengine::CallScope::per_call(name).expect("a valid scope")
}

fn leg_session(call_id: &str) -> crate::rtpengine::MediaSession {
    crate::rtpengine::MediaSession {
        rtpengine_call_id: call_id.to_string(),
        call_id: call_id.to_string(),
        from_tag: "caller-tag".to_string(),
        to_tag: None,
        profile: "rtp_passthrough".to_string(),
        ws_uri: None,
        ws_tee: None,
        ws_bridge_attached: false,
        bridge_sides: None,
        created_at: std::time::Instant::now(),
    }
}

/// The scoped legs of an intercepted proxy call are each tapped, each with
/// the session's one Correlation ID, recorded under its own scope, and each
/// is detached on its own leg when the call ends.
#[tokio::test]
async fn every_scoped_leg_of_an_intercepted_proxy_call_is_tapped() {
    let engine = crate::rtpengine::test_native_engine::NativeTestEngine::start().await;
    let backend = engine.backend();
    let sessions = Arc::new(crate::rtpengine::MediaSessionStore::new());
    for name in ["orig", "term"] {
        let scope = leg_scope(name);
        backend
            .offer_in(
                Some(&scope),
                PROXY_CALL_ID,
                "caller-tag",
                b"v=0\r\n",
                &crate::rtpengine::NgFlags::default(),
            )
            .await
            .expect("the leg is anchored");
        sessions
            .scoped(&scope)
            .expect("a scope store")
            .insert(leg_session(PROXY_CALL_ID));
    }
    let mut dispatcher = test_dispatcher();
    dispatcher.state.rtpengine_set = Some(Arc::clone(&backend));
    dispatcher.state.rtpengine_sessions = Some(Arc::clone(&sessions));
    let (state, li, _iri, mut audit) = intercepting_on(dispatcher);
    assert_eq!(
        super::intercept::intercepted_legs(&state, PROXY_CALL_ID),
        vec![Some(leg_scope("orig")), Some(leg_scope("term"))]
    );

    arrives(&state, CALLER, &proxy_scoped_message(CALLER_INVITE));
    arrives(&state, CALLER, &proxy_scoped_message(CALLER_ACK));
    assert_eq!(attach_attempts(&mut audit).await, 2, "one per leg");

    let attached = engine.commands("attach_x3");
    let mut scopes: Vec<(Option<String>, bool)> = attached
        .iter()
        .map(|command| (command.scope.clone(), command.refused))
        .collect();
    scopes.sort();
    assert_eq!(
        scopes,
        vec![
            (Some("orig".to_string()), false),
            (Some("term".to_string()), false)
        ]
    );
    let records = li.x3_attachments_for(PROXY_CALL_ID);
    assert_eq!(records.len(), 2);
    assert!(
        records
            .iter()
            .all(|record| record.correlation_id == records[0].correlation_id),
        "one Correlation ID across the session's legs"
    );

    // A second ACK finds every leg attached and attaches nothing more.
    arrives(&state, CALLER, &proxy_scoped_message(CALLER_ACK));
    assert_eq!(attach_attempts(&mut audit).await, 0);

    let bye = proxy_scoped_message(CALLER_ACK)
        .replace("ACK sip:", "BYE sip:")
        .replace("CSeq: 1 ACK", "CSeq: 2 BYE")
        .replace("z9hG4bK-caller-ack", "z9hG4bK-caller-bye");
    arrives(&state, CALLER, &bye);
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let mut detached: Vec<Option<String>> = engine
        .commands("detach_x3")
        .into_iter()
        .map(|command| command.scope)
        .collect();
    detached.sort();
    assert_eq!(
        detached,
        vec![Some("orig".to_string()), Some("term".to_string())]
    );
    assert_eq!(li.x3_attachment_count(), 0, "the call's records drain");
}

/// Without per-call scopes the call's own media is the one tapped, as before.
#[test]
fn an_unscoped_call_taps_its_own_media() {
    let mut dispatcher = test_dispatcher();
    let sessions = Arc::new(crate::rtpengine::MediaSessionStore::new());
    dispatcher.state.rtpengine_sessions = Some(Arc::clone(&sessions));
    let state = dispatcher.state;
    assert_eq!(
        super::intercept::intercepted_legs(&state, "c-1"),
        vec![None]
    );
    sessions.insert(leg_session("c-1"));
    sessions
        .scoped(&leg_scope("term"))
        .expect("a scope store")
        .insert(leg_session("c-1"));
    assert_eq!(
        super::intercept::intercepted_legs(&state, "c-1"),
        vec![None, Some(leg_scope("term"))],
        "a call with its own media and a scoped leg taps both"
    );
}

/// One leg's delivery ending drops that leg's record only; the other leg is
/// still delivering, and its loss reports still find their warrant.
#[tokio::test]
async fn one_legs_x3_end_leaves_the_other_legs_record() {
    let (state, li, _iri, _audit) = intercepting();
    let task = li.tasks().list()[0].details.clone();
    for name in ["orig", "term"] {
        li.record_x3_attachment(
            PROXY_CALL_ID,
            crate::li::ActiveIntercept {
                x_id: task.x_id,
                d_id: task.list_of_dids[0],
                from_tag: "caller-tag".to_string(),
                correlation_id: 7,
                scope: Some(leg_scope(name)),
            },
        );
    }
    let (events, receiver) = mpsc::channel(4);
    spawn_rtpengine_events(&state, receiver);
    let ended = |leg: &str| {
        crate::rtpengine::events::RtpEngineEvent::X3Ended(crate::rtpengine::events::X3EndedEvent {
            call_id: format!("{PROXY_CALL_ID};{leg}"),
            from_tag: "caller-tag".to_string(),
            reason: "detached".to_string(),
            orderly: true,
            delivered: 10,
            dropped: 0,
        })
    };
    events
        .send(ended("orig"))
        .await
        .expect("the event loop runs");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let left = li.x3_attachments_for(PROXY_CALL_ID);
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].scope, Some(leg_scope("term")));

    events
        .send(ended("term"))
        .await
        .expect("the event loop runs");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(li.x3_attachment_count(), 0, "drains to baseline");
}
