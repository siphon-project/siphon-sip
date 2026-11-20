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

pub(super) const CALLER: &str = "192.0.2.10:5060";
pub(super) const CALLEE: &str = "198.51.100.77:5060";
pub(super) const CALLEE_CALL_ID: &str = "b2b-callee@192.0.2.1";
pub(super) const SECOND_CALLEE_CALL_ID: &str = "b2b-callee-2@192.0.2.1";

/// The caller's INVITE. The warrant names the caller, in From.
pub(super) const CALLER_INVITE: &str = concat!(
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

pub(super) const CALLER_ACK: &str = concat!(
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
pub(super) const CALLER_BYE_OK: &str = concat!(
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
pub(super) fn callee_response(call_id: &str, status_line: &str) -> String {
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
pub(super) fn callee_request(method: &str, cseq: u32, branch: &str) -> String {
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

pub(super) fn arrives(state: &Arc<DispatcherState>, source: &str, raw: &str) {
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
pub(super) fn intercepting_on(
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
pub(super) fn caller_calls(state: &Arc<DispatcherState>) -> String {
    arrives(state, CALLER, CALLER_INVITE);
    create_b2bua_call(state, caller_leg())
}

/// A callee leg on `call_id`, as `b2bua_send_b_leg_invite` registers one.
pub(super) fn dial(state: &Arc<DispatcherState>, internal_id: &str, call_id: &str) {
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

pub(super) fn drain_iri(iri: &mut mpsc::Receiver<IriEvent>) -> Vec<IriEvent> {
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

/// TS 103 221-2 clause 5.2.6 is asked of each message: the caller is the
/// target here, so what the callee leg carries travels to the target, the far
/// end's re-INVITE and BYE included, and only what the caller sends is from it.
#[tokio::test]
async fn each_record_of_a_b2bua_call_carries_its_own_direction() {
    use crate::li::pdu::PayloadDirection::{SentFromTarget, SentToTarget};

    let (state, _li, mut iri, _audit) = intercepting();
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
    arrives(&state, CALLEE, &callee_request("BYE", 2, "z9hG4bK-far-bye"));
    arrives(&state, CALLER, CALLER_BYE_OK);

    let events = drain_iri(&mut iri);
    let directions: Vec<_> = events
        .iter()
        .map(|event| {
            (
                event.sip_method.as_str(),
                event.status_code,
                event.direction,
            )
        })
        .collect();
    assert_eq!(
        directions,
        [
            ("INVITE", None, SentFromTarget),
            ("INVITE", Some(180), SentToTarget),
            ("INVITE", Some(200), SentToTarget),
            ("ACK", None, SentFromTarget),
            ("INVITE", None, SentToTarget),
            ("BYE", None, SentToTarget),
            ("BYE", Some(200), SentFromTarget),
        ]
    );
    for event in &events {
        assert_eq!(
            event.matched_identifier,
            TargetIdentifier::SipUri("sip:alice@example.com".to_string()),
            "every record names the identifier the call was intercepted on, \
             the callee leg's too though it carries none of the caller's"
        );
    }
}

/// One message of a proxied call to the target, from `carol` (tag `c`) to
/// `alice` (tag `t`).
fn proxied_to_target(start_line: &str, cseq: &str, to_tag: &str, branch: &str) -> String {
    format!(
        concat!(
            "{start_line}\r\n",
            "Via: SIP/2.0/UDP 198.51.100.77:5060;branch=z9hG4bK-{branch}\r\n",
            "Max-Forwards: 70\r\n",
            "From: <sip:carol@example.net>;tag=c\r\n",
            "To: <sip:alice@example.com>{to_tag}\r\n",
            "Call-ID: proxied-to-target@198.51.100.77\r\n",
            "CSeq: {cseq}\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        start_line = start_line,
        cseq = cseq,
        to_tag = to_tag,
        branch = branch,
    )
}

/// The proxy path: a call to the target that it declines. The caller's INVITE
/// and ACK travel to the target; the 180 and 486 are the target's own.
#[tokio::test]
async fn each_record_of_a_proxied_call_to_the_target_carries_its_own_direction() {
    use crate::li::pdu::PayloadDirection::{SentFromTarget, SentToTarget};

    let (state, _li, mut iri, _audit) = intercepting();
    let invite = "INVITE sip:alice@example.com SIP/2.0";
    arrives(
        &state,
        CALLEE,
        &proxied_to_target(invite, "1 INVITE", "", "invite"),
    );
    arrives(
        &state,
        CALLER,
        &proxied_to_target("SIP/2.0 180 Ringing", "1 INVITE", ";tag=t", "invite"),
    );
    arrives(
        &state,
        CALLER,
        &proxied_to_target("SIP/2.0 486 Busy Here", "1 INVITE", ";tag=t", "invite"),
    );
    arrives(
        &state,
        CALLEE,
        &proxied_to_target(
            "ACK sip:alice@example.com SIP/2.0",
            "1 ACK",
            ";tag=t",
            "invite",
        ),
    );

    let directions: Vec<_> = drain_iri(&mut iri)
        .iter()
        .map(|event| (event.sip_method.clone(), event.status_code, event.direction))
        .collect();
    assert_eq!(
        directions,
        [
            ("INVITE".to_string(), None, SentToTarget),
            ("INVITE".to_string(), Some(180), SentFromTarget),
            ("INVITE".to_string(), Some(486), SentFromTarget),
            ("ACK".to_string(), None, SentToTarget),
        ]
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
            delivery: "192.0.2.50:42069".to_string(),
            from_tag: "caller-tag".to_string(),
            correlation_id: correlation_from_call_id(&internal_id),
            session_id: Arc::from(internal_id.as_str()),
            scope: None,
        },
    );

    arrives(&state, CALLEE, &callee_request("BYE", 2, "z9hG4bK-far-bye"));
    assert!(
        li.x3_attachments_for(CALLER_CALL_ID).is_empty(),
        "a BYE on the callee leg ends the call, so its content capture"
    );
    assert_eq!(
        li.x3_attachment_count(),
        1,
        "on record until the engine reports the delivery ended"
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

pub(super) fn leg_session(call_id: &str) -> crate::rtpengine::MediaSession {
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
    assert!(
        li.x3_attachments_for(PROXY_CALL_ID).is_empty(),
        "no leg is live; each stays on record until the engine reports it ended"
    );
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
                delivery: "192.0.2.50:42069".to_string(),
                from_tag: "caller-tag".to_string(),
                correlation_id: 7,
                session_id: Arc::from(PROXY_CALL_ID),
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
            delivery: None,
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

/// The caller's ACK of a failure response. RFC 3261 §17.1.1.3: it belongs to
/// the INVITE's transaction, so it carries the INVITE's branch.
const CALLER_FAILURE_ACK: &str = concat!(
    "ACK sip:15550100042@siphon.example.com SIP/2.0\r\n",
    "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-caller-invite\r\n",
    "Max-Forwards: 70\r\n",
    "From: <sip:alice@example.com>;tag=caller-tag\r\n",
    "To: <sip:15550100042@siphon.example.com>;tag=siphon-tag\r\n",
    "Call-ID: caller-call@192.0.2.10\r\n",
    "CSeq: 1 ACK\r\n",
    "Content-Length: 0\r\n",
    "\r\n",
);

/// A response to the caller's INVITE as a proxy receives it from the callee:
/// same dialog, same Call-ID, the Via siphon added on top.
pub(super) fn proxied_response(status_line: &str) -> String {
    format!(
        concat!(
            "SIP/2.0 {status_line}\r\n",
            "Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-siphon-relay\r\n",
            "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-caller-invite\r\n",
            "From: <sip:alice@example.com>;tag=caller-tag\r\n",
            "To: <sip:15550100042@siphon.example.com>;tag=callee-tag\r\n",
            "Call-ID: caller-call@192.0.2.10\r\n",
            "CSeq: 1 INVITE\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        status_line = status_line,
    )
}

/// An intercepting dispatcher on a media engine that delivers X3 and counts
/// the commands it is sent. `anchored` says whether the call has media there:
/// a refused call's media session is gone by the time its ACK arrives.
async fn intercepting_on_a_counting_engine(
    anchored: bool,
) -> (
    Arc<DispatcherState>,
    crate::rtpengine::test_native_engine::NativeTestEngine,
    mpsc::Receiver<IriEvent>,
    mpsc::Receiver<AuditEntry>,
) {
    let engine = crate::rtpengine::test_native_engine::NativeTestEngine::start().await;
    let backend = engine.backend();
    if anchored {
        backend
            .offer_in(
                None,
                CALLER_CALL_ID,
                "caller-tag",
                b"v=0\r\n",
                &crate::rtpengine::NgFlags::default(),
            )
            .await
            .expect("the call is anchored");
    }
    let mut dispatcher = test_dispatcher();
    dispatcher.state.rtpengine_set = Some(backend);
    let (state, _li, iri, audit) = intercepting_on(dispatcher);
    (state, engine, iri, audit)
}

/// The ACK was still delivered on X2, as a `Continue` of the session.
fn assert_ack_reported(iri: &mut mpsc::Receiver<IriEvent>) {
    let events = drain_iri(iri);
    assert!(
        events.iter().any(|event| event.sip_method == "ACK"
            && event.event_type == crate::li::IriEventType::Continue),
        "the ACK is signalling of a warranted session and stays on X2: {:?}",
        events
            .iter()
            .map(|event| (event.sip_method.clone(), event.status_code))
            .collect::<Vec<_>>()
    );
}

/// A B2BUA call the callee refuses has no media to deliver. The caller's ACK
/// of the 486 siphon relayed must not ask the engine for content: the engine
/// no longer knows the call, and its refusal would be reported to the ADMF as
/// warranted content going undelivered.
#[tokio::test]
async fn the_ack_of_a_refused_b2bua_call_attaches_no_content() {
    let (state, engine, mut iri, mut audit) = intercepting_on_a_counting_engine(false).await;
    let internal_id = caller_calls(&state);
    dial(&state, &internal_id, CALLEE_CALL_ID);
    arrives(
        &state,
        CALLEE,
        &callee_response(CALLEE_CALL_ID, "486 Busy Here"),
    );
    arrives(&state, CALLER, CALLER_FAILURE_ACK);

    assert_eq!(
        attach_attempts(&mut audit).await,
        0,
        "no attempt, so no failed attempt audited and no fault reported to the ADMF"
    );
    assert!(
        engine.commands("attach_x3").is_empty(),
        "the engine is not asked to deliver a call that was never answered"
    );
    assert_ack_reported(&mut iri);
}

/// The same on a proxy, where the 486 arrives on the caller's own dialog.
#[tokio::test]
async fn the_ack_of_a_refused_proxied_call_attaches_no_content() {
    let (state, engine, mut iri, mut audit) = intercepting_on_a_counting_engine(false).await;
    arrives(&state, CALLER, CALLER_INVITE);
    arrives(&state, CALLEE, &proxied_response("180 Ringing"));
    arrives(&state, CALLEE, &proxied_response("486 Busy Here"));
    arrives(&state, CALLER, CALLER_FAILURE_ACK);

    assert_eq!(attach_attempts(&mut audit).await, 0);
    assert!(engine.commands("attach_x3").is_empty());
    assert_ack_reported(&mut iri);
}

/// An answered call still attaches once, on the ACK of the 2xx, which is a
/// transaction of its own with its own branch (RFC 3261 §13.2.2.4).
#[tokio::test]
async fn the_ack_of_an_answered_call_attaches_content_once() {
    for proxied in [false, true] {
        let (state, engine, mut iri, mut audit) = intercepting_on_a_counting_engine(true).await;
        if proxied {
            arrives(&state, CALLER, CALLER_INVITE);
            arrives(&state, CALLEE, &proxied_response("200 OK"));
        } else {
            let internal_id = caller_calls(&state);
            dial(&state, &internal_id, CALLEE_CALL_ID);
            arrives(&state, CALLEE, &callee_response(CALLEE_CALL_ID, "200 OK"));
        }
        arrives(&state, CALLER, CALLER_ACK);

        assert_eq!(attach_attempts(&mut audit).await, 1, "proxied={proxied}");
        let attached = engine.commands("attach_x3");
        assert_eq!(attached.len(), 1, "proxied={proxied}");
        assert!(!attached[0].refused, "the engine knows an answered call");
        assert_ack_reported(&mut iri);
    }
}

/// An ACK of a 2xx that reuses the INVITE's branch is wrong (RFC 3261
/// §13.2.2.4) but it still acknowledges an answered call, whose content is
/// owed. A missed attachment is the failure that cannot be recovered.
#[tokio::test]
async fn an_answered_call_attaches_even_when_its_ack_reuses_the_invite_branch() {
    let (state, engine, _iri, mut audit) = intercepting_on_a_counting_engine(true).await;
    arrives(&state, CALLER, CALLER_INVITE);
    arrives(&state, CALLEE, &proxied_response("200 OK"));
    arrives(&state, CALLER, CALLER_FAILURE_ACK);

    assert_eq!(attach_attempts(&mut audit).await, 1);
    assert_eq!(engine.commands("attach_x3").len(), 1);
}

// ── Content delivery follows the engine call ────────────────────────────────
//
// An engine that lists `x3_attach_at_offer` accepts an interception on a call
// that is offered but not answered yet, so siphon asks when the script's offer
// has reached the engine and the ACK finds nothing left to do. An engine that
// does not list it keeps the ACK.
//
// What is attached is recorded per engine call, before the engine is asked.
// siphon ending an engine call (a `delete`, or an `offer` replacing it) ends
// that attempt at once, and is the one way a delivery ends with its call
// that is not a fault.

use crate::rtpengine::test_native_engine::NativeTestEngine;

/// An intercepting dispatcher that follows its engine's calls, on an engine
/// that lists `x3_attach_at_offer` in `node_info` or, with `at_offer` false,
/// one that does not (an older engine, or one not provisioned for X3). The
/// call's media session is in siphon's store, as a script's offer leaves it,
/// so siphon's own teardowns release it.
async fn intercepting_on_an_engine(
    at_offer: bool,
) -> (
    Arc<DispatcherState>,
    NativeTestEngine,
    LiManager,
    mpsc::Receiver<AuditEntry>,
) {
    let engine = match at_offer {
        true => NativeTestEngine::start_with_x3_at_offer().await,
        false => NativeTestEngine::start().await,
    };
    let (state, engine, li, _iri, audit) = intercepting_on_the_engine(engine).await;
    (state, engine, li, audit)
}

/// An intercepting dispatcher that follows the calls of `engine`, with the
/// caller's media session in siphon's store, and the X2 records it emits.
pub(super) async fn intercepting_on_the_engine(
    engine: NativeTestEngine,
) -> (
    Arc<DispatcherState>,
    NativeTestEngine,
    LiManager,
    mpsc::Receiver<IriEvent>,
    mpsc::Receiver<AuditEntry>,
) {
    let mut dispatcher = test_dispatcher();
    dispatcher.state.rtpengine_set = Some(engine.backend());
    dispatcher.state.rtpengine_profiles = Some(Arc::new(crate::rtpengine::ProfileRegistry::new()));
    let sessions = Arc::new(crate::rtpengine::MediaSessionStore::new());
    sessions.insert(leg_session(CALLER_CALL_ID));
    dispatcher.state.rtpengine_sessions = Some(sessions);
    let (state, li, iri, audit) = intercepting_on(dispatcher);
    super::intercept::watch_engine_calls(&state);
    (state, engine, li, iri, audit)
}

pub(super) fn backend_of(state: &Arc<DispatcherState>) -> Arc<crate::rtpengine::MediaBackend> {
    Arc::clone(state.rtpengine_set.as_ref().expect("a media backend"))
}

/// What a script's `rtpengine.offer()` does in the INVITE's handler: the
/// caller's offer reaches the engine, under the caller's Call-ID and tag.
async fn script_offers(state: &Arc<DispatcherState>) {
    backend_of(state)
        .offer_in(
            None,
            CALLER_CALL_ID,
            "caller-tag",
            b"v=0\r\n",
            &crate::rtpengine::NgFlags::default(),
        )
        .await
        .expect("the engine takes the offer");
}

/// What a script's `rtpengine.delete()` does: siphon releases the call's
/// media at the engine.
async fn script_deletes(state: &Arc<DispatcherState>) {
    backend_of(state)
        .delete(CALLER_CALL_ID, "caller-tag")
        .await
        .expect("the engine deletes the call");
}

/// The attach attempts audited so far, and how many of them failed.
pub(super) async fn attach_outcomes(audit: &mut mpsc::Receiver<AuditEntry>) -> (usize, usize) {
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let (mut attempts, mut failed) = (0, 0);
    while let Ok(entry) = audit.try_recv() {
        if entry.operation == AuditOperation::MediaCaptureStarted {
            attempts += 1;
            if entry.detail.contains("FAILED") {
                failed += 1;
            }
        }
    }
    (attempts, failed)
}

/// Capture what is logged on this thread, which on a current-thread test
/// runtime is every task of the test.
pub(super) fn capture_log() -> (
    crate::log_capture::LogBuffer,
    tracing::subscriber::DefaultGuard,
) {
    let log = crate::log_capture::LogBuffer::default();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(log.clone())
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);
    (log, guard)
}

/// How many delivery faults went down the path to the ADMF, which this node,
/// with no `admf:` block, can only log.
pub(super) fn faults_reported(log: &crate::log_capture::LogBuffer) -> usize {
    log.rendered()
        .matches("could not be reported to the ADMF")
        .count()
}

/// The call is set up to the caller's INVITE, in either mode.
fn invite_arrives(state: &Arc<DispatcherState>, proxied: bool) -> Option<String> {
    if proxied {
        arrives(state, CALLER, CALLER_INVITE);
        None
    } else {
        Some(caller_calls(state))
    }
}

/// A response of the callee's, in either mode. A B2BUA callee leg is dialled
/// the first time.
fn callee_answers(state: &Arc<DispatcherState>, internal_id: Option<&str>, status_line: &str) {
    match internal_id {
        None => arrives(state, CALLEE, &proxied_response(status_line)),
        Some(internal_id) => {
            if state
                .call_actors
                .find_by_sip_call_id(CALLEE_CALL_ID)
                .is_none()
            {
                dial(state, internal_id, CALLEE_CALL_ID);
            }
            arrives(state, CALLEE, &callee_response(CALLEE_CALL_ID, status_line));
        }
    }
}

/// The engine's report that the delivery on the caller's engine call ended.
fn delivery_ended(reason: &str, delivered: u64) -> crate::rtpengine::events::RtpEngineEvent {
    crate::rtpengine::events::RtpEngineEvent::X3Ended(crate::rtpengine::events::X3EndedEvent {
        call_id: CALLER_CALL_ID.to_string(),
        from_tag: "caller-tag".to_string(),
        reason: reason.to_string(),
        orderly: reason == "Detached",
        delivered,
        dropped: 0,
        delivery: None,
    })
}

/// The engine's event stream into the dispatcher.
pub(super) fn engine_events(
    state: &Arc<DispatcherState>,
) -> mpsc::Sender<crate::rtpengine::events::RtpEngineEvent> {
    let (events, receiver) = mpsc::channel(16);
    spawn_rtpengine_events(state, receiver);
    events
}

/// The engine reports `event`, and the dispatcher has acted on it.
pub(super) async fn engine_reports(
    events: &mpsc::Sender<crate::rtpengine::events::RtpEngineEvent>,
    event: crate::rtpengine::events::RtpEngineEvent,
) {
    events.send(event).await.expect("the event loop runs");
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
}

/// On an engine that takes an interception before the answer, content
/// delivery is asked for as soon as the script's offer has reached the engine,
/// so the first packet after the answer and all early media are delivered. The
/// ACK then asks for nothing: exactly one attach for the call.
#[tokio::test]
async fn an_engine_that_accepts_it_is_asked_at_the_offer_and_not_at_the_ack() {
    for proxied in [false, true] {
        let (state, engine, li, mut audit) = intercepting_on_an_engine(true).await;
        let internal_id = invite_arrives(&state, proxied);
        assert_eq!(attach_outcomes(&mut audit).await, (0, 0), "nothing offered");

        script_offers(&state).await;
        assert_eq!(
            attach_outcomes(&mut audit).await,
            (1, 0),
            "proxied={proxied}: attached at the offer, before any answer"
        );
        let attached = engine.commands("attach_x3");
        assert_eq!(attached.len(), 1, "proxied={proxied}");
        assert_eq!(attached[0].call_id, CALLER_CALL_ID);
        assert_eq!(attached[0].from_tag, "caller-tag");
        assert!(!attached[0].refused);
        assert_eq!(li.x3_attachments_for(CALLER_CALL_ID).len(), 1);

        callee_answers(&state, internal_id.as_deref(), "200 OK");
        arrives(&state, CALLER, CALLER_ACK);
        assert_eq!(
            attach_outcomes(&mut audit).await,
            (0, 0),
            "proxied={proxied}: the ACK has nothing left to attach"
        );
        assert_eq!(
            engine.commands("attach_x3").len(),
            1,
            "proxied={proxied}: one attach for the call"
        );
    }
}

/// An engine that does not list the feature (one before 0.25.1, which refuses
/// an interception on an unanswered call, or one not provisioned for X3) is
/// asked nothing at the offer, and the ACK of the answer attaches, as it
/// always has.
#[tokio::test]
async fn an_older_engine_is_still_asked_at_the_ack() {
    for proxied in [false, true] {
        let (state, engine, _li, mut audit) = intercepting_on_an_engine(false).await;
        let internal_id = invite_arrives(&state, proxied);
        script_offers(&state).await;
        assert_eq!(
            attach_outcomes(&mut audit).await,
            (0, 0),
            "proxied={proxied}: without the feature nothing is asked at the offer"
        );
        assert!(engine.commands("attach_x3").is_empty());

        callee_answers(&state, internal_id.as_deref(), "200 OK");
        arrives(&state, CALLER, CALLER_ACK);
        assert_eq!(
            attach_outcomes(&mut audit).await,
            (1, 0),
            "proxied={proxied}: the ACK attaches"
        );
        assert_eq!(engine.commands("attach_x3").len(), 1);
    }
}

/// rtpengine cannot deliver X3 and tells nobody of its calls: nothing is
/// asked at the offer, and the ACK asks as it always has.
#[tokio::test]
async fn the_ng_backend_is_still_asked_at_the_ack() {
    let engine = TestEngine::start(false).await;
    let mut dispatcher = test_dispatcher();
    let backend = engine.backend().await;
    dispatcher.state.rtpengine_set = Some(Arc::clone(&backend));
    let (state, _li, _iri, mut audit) = intercepting_on(dispatcher);
    super::intercept::watch_engine_calls(&state);
    assert_eq!(
        backend.x3_attach_at_offer(CALLER_CALL_ID, None),
        Some(false)
    );

    invite_arrives(&state, true);
    backend
        .offer(
            CALLER_CALL_ID,
            "caller-tag",
            b"v=0\r\n",
            &crate::rtpengine::NgFlags::default(),
        )
        .await
        .expect("the engine takes the offer");
    assert_eq!(attach_outcomes(&mut audit).await.0, 0, "not at the offer");

    callee_answers(&state, None, "200 OK");
    arrives(&state, CALLER, CALLER_ACK);
    assert_eq!(attach_outcomes(&mut audit).await.0, 1, "at the ACK");
}

/// The first intercepted offer on an engine connection has to ask the engine
/// what it lists, off the offer's path. An ACK that arrives before that answer
/// asks for the attachment itself and the offer's side then finds it
/// recorded: one attach whichever of them runs first, and the answer is known
/// from then on.
#[tokio::test]
async fn an_ack_that_crosses_the_engines_feature_answer_attaches_once() {
    let (state, engine, _li, mut audit) = intercepting_on_an_engine(true).await;
    let backend = backend_of(&state);
    assert_eq!(
        backend.x3_attach_at_offer(CALLER_CALL_ID, None),
        None,
        "the engine has not been asked yet"
    );

    invite_arrives(&state, true);
    script_offers(&state).await;
    // No await between the offer and the ACK: the question is still out.
    callee_answers(&state, None, "200 OK");
    arrives(&state, CALLER, CALLER_ACK);

    assert_eq!(attach_outcomes(&mut audit).await, (1, 0));
    assert_eq!(engine.commands("attach_x3").len(), 1);
    assert_eq!(
        backend.x3_attach_at_offer(CALLER_CALL_ID, None),
        Some(true),
        "read off node_info once, for every later call on the connection"
    );
}

/// An intercepted call that is refused attaches once, at the offer, and
/// nothing about its failing is a delivery fault: not the ACK of the 486, and
/// not the engine ending the delivery with the call siphon deleted, whether
/// it carried nothing or the early media of a 183.
#[tokio::test]
async fn an_unanswered_call_attaches_at_the_offer_and_raises_no_fault() {
    for (proxied, early_media) in [(false, false), (true, false), (false, true), (true, true)] {
        let case = format!("proxied={proxied} early_media={early_media}");
        let (log, _guard) = capture_log();
        let (state, engine, li, mut audit) = intercepting_on_an_engine(true).await;
        let events = engine_events(&state);
        let internal_id = invite_arrives(&state, proxied);
        script_offers(&state).await;
        if early_media {
            callee_answers(&state, internal_id.as_deref(), "183 Session Progress");
        }
        callee_answers(&state, internal_id.as_deref(), "486 Busy Here");
        arrives(&state, CALLER, CALLER_FAILURE_ACK);

        assert_eq!(
            attach_outcomes(&mut audit).await,
            (1, 0),
            "{case}: one attach, at the offer, and it did not fail"
        );
        assert_eq!(engine.commands("attach_x3").len(), 1, "{case}");

        // The media of the call that failed is released, and the engine ends
        // the delivery with it.
        script_deletes(&state).await;
        engine_reports(
            &events,
            delivery_ended("CallEnded", if early_media { 240 } else { 0 }),
        )
        .await;

        assert_eq!(li.x3_attachment_count(), 0, "{case}: the record drains");
        assert_eq!(faults_reported(&log), 0, "{case}:\n{}", log.rendered());
    }
}

/// The engine ending the delivery of a call siphon did not delete is a fault:
/// the engine timed the call out or lost it, and the call is up as far as its
/// signalling says.
#[tokio::test]
async fn a_delivery_ending_with_a_call_siphon_did_not_delete_is_a_fault() {
    for proxied in [false, true] {
        let (log, _guard) = capture_log();
        let (state, _engine, li, mut audit) = intercepting_on_an_engine(true).await;
        let events = engine_events(&state);
        let internal_id = invite_arrives(&state, proxied);
        script_offers(&state).await;
        callee_answers(&state, internal_id.as_deref(), "200 OK");
        arrives(&state, CALLER, CALLER_ACK);
        assert_eq!(attach_outcomes(&mut audit).await, (1, 0));

        engine_reports(&events, delivery_ended("CallEnded", 1_200)).await;

        assert_eq!(li.x3_attachment_count(), 0);
        assert_eq!(
            faults_reported(&log),
            1,
            "proxied={proxied}:\n{}",
            log.rendered()
        );
    }
}

/// A call siphon answers itself has no offer and no second leg: the engine is
/// its far side. Nothing is asked at an offer that never happens, the ACK
/// asks as before, the engine refuses, and that refusal stays what it was: a
/// loud error and a fault toward the ADMF. Such a call carries the target's
/// media (an announcement, an IVR), so a refused attach is content that is
/// not being delivered.
#[tokio::test]
async fn a_refused_attach_on_a_locally_answered_call_is_still_a_fault() {
    let (log, _guard) = capture_log();
    let (state, engine, li, mut audit) = intercepting_on_an_engine(true).await;
    caller_calls(&state);
    backend_of(&state)
        .answer_local(
            CALLER_CALL_ID,
            "caller-tag",
            "v=0\r\n",
            &crate::rtpengine::NgFlags::default(),
        )
        .await
        .expect("the engine answers the call itself");
    assert_eq!(
        attach_outcomes(&mut audit).await,
        (0, 0),
        "a local answer is not an offer"
    );

    // siphon's own 200 is not inbound; the caller's ACK of it is.
    arrives(&state, CALLER, CALLER_ACK);
    assert_eq!(
        attach_outcomes(&mut audit).await,
        (1, 1),
        "the ACK asks, and the engine's refusal is audited as a failure"
    );
    assert_eq!(engine.commands("attach_x3").len(), 1);
    assert_eq!(li.x3_attachment_count(), 0, "nothing is left recorded");
    let rendered = log.rendered();
    assert!(
        rendered.contains("NOT being delivered")
            && rendered.contains("the call has no second leg to intercept"),
        "the refusal is a loud error carrying the engine's reason:\n{rendered}"
    );
    assert_eq!(faults_reported(&log), 1, "{rendered}");
}

/// A failed attempt whose media is released and the call routed again: the
/// offer for the new attempt attaches at once, although the engine has not yet
/// reported the old delivery ended, and so does not wait on anything. The old
/// delivery's end, when it comes, is the old engine call's and no fault.
#[tokio::test]
async fn a_call_routed_again_attaches_before_the_old_delivery_is_reported_ended() {
    let (log, _guard) = capture_log();
    let (state, engine, li, mut audit) = intercepting_on_an_engine(true).await;
    let events = engine_events(&state);
    let internal_id = caller_calls(&state);
    script_offers(&state).await;
    assert_eq!(attach_outcomes(&mut audit).await, (1, 0));

    // The first carrier refuses; the failure handler releases the media and
    // routes the call to a second, which answers, and the caller ACKs.
    callee_answers(&state, Some(&internal_id), "503 Service Unavailable");
    script_deletes(&state).await;
    script_offers(&state).await;
    dial(&state, &internal_id, SECOND_CALLEE_CALL_ID);
    arrives(
        &state,
        CALLEE,
        &callee_response(SECOND_CALLEE_CALL_ID, "200 OK"),
    );
    arrives(&state, CALLER, CALLER_ACK);
    assert_eq!(
        attach_outcomes(&mut audit).await,
        (1, 0),
        "the new engine call is attached, once"
    );
    assert_eq!(engine.commands("attach_x3").len(), 2);
    assert!(engine
        .commands("attach_x3")
        .iter()
        .all(|command| !command.refused));

    // Only now does the engine's report of the first delivery arrive.
    engine_reports(&events, delivery_ended("CallEnded", 0)).await;
    assert_eq!(faults_reported(&log), 0, "{}", log.rendered());
    assert_eq!(
        li.x3_attachments_for(CALLER_CALL_ID).len(),
        1,
        "the answered call's own attachment is untouched"
    );
}

/// After a reroute the new attempt's delivery is watched like any other: the
/// engine ending it on its own, moments after the reroute and before or after
/// the answer, is a fault. Nothing about the earlier refusal excuses it.
#[tokio::test]
async fn a_delivery_failing_right_after_a_reroute_is_a_fault() {
    for answered in [false, true] {
        let (log, _guard) = capture_log();
        let (state, _engine, li, mut audit) = intercepting_on_an_engine(true).await;
        let events = engine_events(&state);
        let internal_id = caller_calls(&state);
        script_offers(&state).await;
        assert_eq!(attach_outcomes(&mut audit).await, (1, 0));
        callee_answers(&state, Some(&internal_id), "503 Service Unavailable");
        script_deletes(&state).await;
        script_offers(&state).await;
        engine_reports(&events, delivery_ended("CallEnded", 0)).await;
        if answered {
            dial(&state, &internal_id, SECOND_CALLEE_CALL_ID);
            arrives(
                &state,
                CALLEE,
                &callee_response(SECOND_CALLEE_CALL_ID, "200 OK"),
            );
            arrives(&state, CALLER, CALLER_ACK);
        }
        assert_eq!(attach_outcomes(&mut audit).await, (1, 0));
        assert_eq!(faults_reported(&log), 0, "the released attempt is clean");

        // The engine ends the new call's delivery; siphon deleted nothing.
        engine_reports(&events, delivery_ended("CallEnded", 40)).await;
        assert_eq!(
            faults_reported(&log),
            1,
            "answered={answered}:\n{}",
            log.rendered()
        );
        assert_eq!(li.x3_attachment_count(), 0);
    }
}

/// An `offer` on an engine call that is already there replaces it, and the
/// interception with it: the new engine call is attached again, and the old
/// delivery ending with its call is no fault.
#[tokio::test]
async fn an_offer_that_replaces_the_engine_call_attaches_again() {
    let (log, _guard) = capture_log();
    let (state, engine, li, mut audit) = intercepting_on_an_engine(true).await;
    let events = engine_events(&state);
    invite_arrives(&state, true);
    script_offers(&state).await;
    assert_eq!(attach_outcomes(&mut audit).await, (1, 0));
    script_offers(&state).await;
    assert_eq!(attach_outcomes(&mut audit).await, (1, 0));
    assert_eq!(engine.commands("attach_x3").len(), 2);

    engine_reports(&events, delivery_ended("CallEnded", 0)).await;
    assert_eq!(faults_reported(&log), 0, "{}", log.rendered());
    assert_eq!(li.x3_attachments_for(CALLER_CALL_ID).len(), 1);
}

/// A re-INVITE on an intercepted call, whose script calls `rtpengine.offer()`
/// again: on a call already anchored that reaches the engine as `reoffer`
/// (`script::api::rtpengine::scope::tests` pins that), which keeps the engine
/// call and carries its interception across. So nothing is ended and nothing
/// is asked for again: the call has its one interception, and that delivery
/// ending later with a call siphon did not delete is still a fault.
#[tokio::test]
async fn a_re_offer_on_an_intercepted_call_keeps_its_one_interception() {
    let (log, _guard) = capture_log();
    let (state, engine, li, mut audit) = intercepting_on_an_engine(true).await;
    let events = engine_events(&state);
    invite_arrives(&state, true);
    script_offers(&state).await;
    callee_answers(&state, None, "200 OK");
    arrives(&state, CALLER, CALLER_ACK);
    assert_eq!(attach_outcomes(&mut audit).await, (1, 0));

    let re_invite = CALLER_ACK
        .replace("ACK sip:", "INVITE sip:")
        .replace("CSeq: 1 ACK", "CSeq: 2 INVITE")
        .replace("z9hG4bK-caller-ack", "z9hG4bK-caller-reinvite");
    arrives(&state, CALLER, &re_invite);
    backend_of(&state)
        .reoffer_in(
            None,
            CALLER_CALL_ID,
            "caller-tag",
            b"v=0\r\n",
            &crate::rtpengine::NgFlags::default(),
        )
        .await
        .expect("the engine renegotiates the call it holds");
    arrives(&state, CALLEE, &proxied_response("200 OK"));
    let ack = CALLER_ACK
        .replace("CSeq: 1 ACK", "CSeq: 2 ACK")
        .replace("z9hG4bK-caller-ack", "z9hG4bK-caller-reack");
    arrives(&state, CALLER, &ack);

    assert_eq!(
        attach_outcomes(&mut audit).await,
        (0, 0),
        "neither the re-offer nor its ACK asks again"
    );
    assert_eq!(engine.commands("reoffer").len(), 1);
    assert_eq!(engine.commands("attach_x3").len(), 1);
    assert_eq!(
        li.x3_attachments_for(CALLER_CALL_ID).len(),
        1,
        "exactly one live interception"
    );

    // The re-offer ended nothing, so this is not the end of a call siphon
    // released.
    engine_reports(&events, delivery_ended("CallEnded", 900)).await;
    assert_eq!(faults_reported(&log), 1, "{}", log.rendered());
}

/// A delivery that ends before the engine's answer to its attach has been
/// acted on (the delivery connection failed at once): the attachment is on
/// record from before the attach was sent, so the end is reported against it,
/// and the answer arriving afterwards records nothing.
#[tokio::test]
async fn a_delivery_end_that_beats_the_attach_answer_is_reported_and_leaves_no_record() {
    let (log, _guard) = capture_log();
    let (state, engine, li, mut audit) = intercepting_on_an_engine(false).await;
    let events = engine_events(&state);
    invite_arrives(&state, true);
    script_offers(&state).await;
    callee_answers(&state, None, "200 OK");

    arrives(&state, CALLER, CALLER_ACK);
    // The attach is on its way; the engine's report is already here.
    events
        .send(delivery_ended("TransportError", 0))
        .await
        .expect("the event loop runs");

    assert_eq!(attach_outcomes(&mut audit).await, (1, 0));
    assert_eq!(engine.commands("attach_x3").len(), 1);
    assert_eq!(faults_reported(&log), 1, "{}", log.rendered());
    assert!(
        li.x3_attachments_for(CALLER_CALL_ID).is_empty(),
        "the attach answer, arriving after the end, must not record a delivery"
    );

    // And so the next ACK (a re-INVITE's) asks again instead of finding a
    // record of a delivery that is not there.
    arrives(
        &state,
        CALLER,
        &CALLER_ACK.replace("z9hG4bK-caller-ack", "z9hG4bK-caller-ack-2"),
    );
    assert_eq!(attach_outcomes(&mut audit).await, (1, 0));
}

/// A proxy call whose two legs land on two engines, one that takes an
/// interception at the offer and one that does not: the first leg is attached
/// at its offer, and the ACK attaches the other, which has no record.
#[tokio::test]
async fn a_leg_on_an_engine_without_the_feature_is_attached_at_the_ack() {
    let at_offer = NativeTestEngine::start_with_x3_at_offer().await;
    let at_ack = NativeTestEngine::start().await;
    let (event_sender, _event_receiver) = mpsc::channel(16);
    let backend = Arc::new(crate::rtpengine::MediaBackend::SiphonRtp(
        crate::rtpengine::SiphonRtpClientSet::new(
            vec![(at_offer.address(), 2000, 1), (at_ack.address(), 2000, 1)],
            None,
            5_000,
            event_sender,
        )
        .expect("an engine set"),
    ));
    let sessions = Arc::new(crate::rtpengine::MediaSessionStore::new());
    let mut dispatcher = test_dispatcher();
    dispatcher.state.rtpengine_set = Some(Arc::clone(&backend));
    dispatcher.state.rtpengine_sessions = Some(Arc::clone(&sessions));
    let (state, li, _iri, mut audit) = intercepting_on(dispatcher);
    super::intercept::watch_engine_calls(&state);

    arrives(&state, CALLER, CALLER_INVITE);
    for name in ["orig", "term"] {
        let scope = leg_scope(name);
        backend
            .offer_in(
                Some(&scope),
                CALLER_CALL_ID,
                "caller-tag",
                b"v=0\r\n",
                &crate::rtpengine::NgFlags::default(),
            )
            .await
            .expect("the leg is anchored");
        sessions
            .scoped(&scope)
            .expect("a scope store")
            .insert(leg_session(CALLER_CALL_ID));
    }
    assert_eq!(
        attach_outcomes(&mut audit).await,
        (1, 0),
        "one at its offer"
    );

    arrives(&state, CALLEE, &proxied_response("200 OK"));
    arrives(&state, CALLER, CALLER_ACK);
    assert_eq!(
        attach_outcomes(&mut audit).await,
        (1, 0),
        "the ACK attaches the leg no offer attached"
    );
    let on = |engine: &NativeTestEngine| {
        engine
            .commands("attach_x3")
            .into_iter()
            .map(|command| command.scope)
            .collect::<Vec<_>>()
    };
    let mut attached = [on(&at_offer), on(&at_ack)].concat();
    attached.sort();
    assert_eq!(
        attached,
        vec![Some("orig".to_string()), Some("term".to_string())]
    );
    assert_eq!(on(&at_offer).len(), 1, "one leg on each engine");
    assert_eq!(li.x3_attachments_for(CALLER_CALL_ID).len(), 2);
}

/// A warrant activated after the call's offer was attached is served from the
/// next ACK: it has no record on the engine call, so it is asked for, while
/// the first warrant's is left alone.
#[tokio::test]
async fn a_warrant_activated_after_the_offer_is_attached_at_the_ack() {
    // On an engine that carries several deliveries on a call. One that holds
    // a single delivery cannot take a second warrant's beside the first
    // (`li_multi_delivery_tests`).
    let (state, engine, li, _iri, mut audit) =
        intercepting_on_the_engine(NativeTestEngine::start_with_x3_026().await).await;
    invite_arrives(&state, true);
    script_offers(&state).await;
    assert_eq!(attach_outcomes(&mut audit).await, (1, 0));

    let mut second = li.tasks().list()[0].details.clone();
    second.x_id = XId::generate();
    li.tasks().activate(second).expect("task must provision");

    callee_answers(&state, None, "200 OK");
    arrives(&state, CALLER, CALLER_ACK);
    assert_eq!(
        attach_outcomes(&mut audit).await,
        (1, 0),
        "the new warrant, and only it"
    );
    assert_eq!(engine.commands("attach_x3").len(), 2);
    assert_eq!(li.x3_attachments_for(CALLER_CALL_ID).len(), 2);
}

/// A caller that CANCELs while the first offer's attach is still being
/// decided (the engine has not yet said what it lists): the media is released
/// first, and the attach decided for the engine call that is gone is not
/// sent. No refusal, no fault.
#[tokio::test]
async fn an_attach_decided_for_a_call_cancelled_meanwhile_is_not_made() {
    let (log, _guard) = capture_log();
    let (state, engine, li, mut audit) = intercepting_on_an_engine(true).await;
    invite_arrives(&state, true);
    script_offers(&state).await;
    // The engine has not answered `node_info` yet. The caller gives up.
    let cancel = CALLER_INVITE
        .replace("INVITE sip:", "CANCEL sip:")
        .replace("CSeq: 1 INVITE", "CSeq: 1 CANCEL");
    arrives(&state, CALLER, &cancel);
    script_deletes(&state).await;

    assert_eq!(
        attach_outcomes(&mut audit).await,
        (0, 0),
        "nothing asked of an engine call that is gone"
    );
    assert!(engine.commands("attach_x3").is_empty());
    assert_eq!(faults_reported(&log), 0, "{}", log.rendered());
    assert_eq!(li.x3_attachment_count(), 0);
}

/// The ACK of a rejected re-INVITE acknowledges no new media, on an answered
/// call as much as on an unanswered one: it attaches nothing, even when the
/// call has no attachment left to find.
#[tokio::test]
async fn the_ack_of_a_rejected_re_invite_attaches_nothing() {
    let (state, engine, li, mut audit) = intercepting_on_an_engine(false).await;
    let events = engine_events(&state);
    invite_arrives(&state, true);
    script_offers(&state).await;
    callee_answers(&state, None, "200 OK");
    arrives(&state, CALLER, CALLER_ACK);
    assert_eq!(attach_outcomes(&mut audit).await, (1, 0));
    // The delivery is lost, so nothing on record would stop a second attach.
    engine_reports(&events, delivery_ended("TransportError", 10)).await;
    assert!(li.x3_attachments_for(CALLER_CALL_ID).is_empty());

    let re_invite = CALLER_ACK
        .replace("ACK sip:", "INVITE sip:")
        .replace("CSeq: 1 ACK", "CSeq: 2 INVITE")
        .replace("z9hG4bK-caller-ack", "z9hG4bK-caller-reinvite");
    arrives(&state, CALLER, &re_invite);
    arrives(&state, CALLEE, &proxied_response("488 Not Acceptable Here"));
    // RFC 3261 §17.1.1.3: the ACK of the 488 carries the re-INVITE's branch.
    let ack = CALLER_ACK
        .replace("CSeq: 1 ACK", "CSeq: 2 ACK")
        .replace("z9hG4bK-caller-ack", "z9hG4bK-caller-reinvite");
    arrives(&state, CALLER, &ack);

    assert_eq!(attach_outcomes(&mut audit).await, (0, 0));
    assert_eq!(engine.commands("attach_x3").len(), 1);
}

// ── An unanswered B2BUA call siphon ends itself ─────────────────────────────
//
// No inbound message ends such a call: siphon gives up on it (a ring timeout,
// a script or an application ending it before the answer) and the failure the
// caller gets is siphon's own response. siphon releases the call's media, the
// engine ends the delivery with the call, and that is no fault.

/// An intercepted B2BUA call on an engine that attaches at the offer, offered
/// and ringing with early media: a 183 from the callee, nothing final.
async fn ringing_b2bua_call_with_early_media() -> (
    Arc<DispatcherState>,
    LiManager,
    String,
    mpsc::Sender<crate::rtpengine::events::RtpEngineEvent>,
) {
    let (state, _engine, li, mut audit) = intercepting_on_an_engine(true).await;
    let events = engine_events(&state);
    let internal_id = caller_calls(&state);
    let invite = parse_sip_message_bytes(CALLER_INVITE.as_bytes()).expect("the INVITE parses");
    state
        .call_actors
        .set_a_leg_invite(&internal_id, Arc::new(Mutex::new(invite)));
    script_offers(&state).await;
    callee_answers(&state, Some(&internal_id), "183 Session Progress");
    state
        .call_actors
        .set_state(&internal_id, CallState::Ringing);
    assert_eq!(attach_outcomes(&mut audit).await, (1, 0));
    (state, li, internal_id, events)
}

/// The ring timeout: nobody answered, siphon CANCELs the callee, fails the
/// caller 408 and releases the media. The callee's 487 is not waited for.
#[tokio::test]
async fn a_ring_timeout_after_early_media_ends_the_delivery_without_a_fault() {
    let (log, _guard) = capture_log();
    let (state, li, internal_id, events) = ringing_b2bua_call_with_early_media().await;

    fail_b2bua_call_on_timeout(&internal_id, &state);
    assert!(
        !state.call_actors.contains_call(&internal_id),
        "the ring timeout ended the call"
    );

    engine_reports(&events, delivery_ended("CallEnded", 240)).await;
    assert_eq!(li.x3_attachment_count(), 0, "the record drains");
    assert_eq!(faults_reported(&log), 0, "{}", log.rendered());
}

/// A script ending the call before the answer (`b2bua.terminate`).
#[tokio::test]
async fn a_script_terminate_before_the_answer_ends_the_delivery_without_a_fault() {
    let (log, _guard) = capture_log();
    let (state, li, internal_id, events) = ringing_b2bua_call_with_early_media().await;

    assert!(super::b2bua::terminate_call(
        &state,
        CALLER_CALL_ID,
        Some("done")
    ));
    assert!(!state.call_actors.contains_call(&internal_id));

    engine_reports(&events, delivery_ended("CallEnded", 240)).await;
    assert_eq!(li.x3_attachment_count(), 0);
    assert_eq!(faults_reported(&log), 0, "{}", log.rendered());
}

/// A script or an application rejecting the call before the answer, having
/// released its media.
#[tokio::test]
async fn a_reject_before_the_answer_ends_the_delivery_without_a_fault() {
    let (log, _guard) = capture_log();
    let (state, li, internal_id, events) = ringing_b2bua_call_with_early_media().await;

    script_deletes(&state).await;
    assert!(super::b2bua::b2bua_reject_call_in(
        &state,
        &internal_id,
        603,
        "Decline",
        &[]
    ));

    engine_reports(&events, delivery_ended("CallEnded", 240)).await;
    assert_eq!(li.x3_attachment_count(), 0);
    assert_eq!(faults_reported(&log), 0, "{}", log.rendered());
}

/// An unanswered call whose delivery the engine ends while siphon has deleted
/// nothing: the engine lost the call, and that is a fault although the call
/// was never answered.
#[tokio::test]
async fn an_unanswered_calls_delivery_ending_on_its_own_is_a_fault() {
    let (log, _guard) = capture_log();
    let (_state, li, _internal_id, events) = ringing_b2bua_call_with_early_media().await;

    engine_reports(&events, delivery_ended("CallEnded", 240)).await;
    assert_eq!(li.x3_attachment_count(), 0);
    assert_eq!(faults_reported(&log), 1, "{}", log.rendered());
}

/// The rule itself: an orderly detach, or the engine ending the delivery with
/// a call siphon ended, and nothing dropped. Everything else is reported.
#[test]
fn only_a_detach_or_a_call_siphon_ended_ends_a_delivery_cleanly() {
    use super::rtpengine_events::{x3_end_is_clean, X3_ENDED_WITH_THE_CALL};
    let ended =
        |reason: &str, orderly, delivered, dropped| crate::rtpengine::events::X3EndedEvent {
            call_id: CALLER_CALL_ID.to_string(),
            from_tag: "caller-tag".to_string(),
            reason: reason.to_string(),
            orderly,
            delivered,
            dropped,
            delivery: None,
        };
    let with_the_call = X3_ENDED_WITH_THE_CALL;

    assert!(x3_end_is_clean(&ended("Detached", true, 10, 0), false));
    assert!(x3_end_is_clean(&ended(with_the_call, false, 0, 0), true));
    assert!(
        x3_end_is_clean(&ended(with_the_call, false, 240, 0), true),
        "what a released call delivered before it ended does not matter"
    );

    for (case, event, ended_by_siphon) in [
        (
            "a call siphon did not end",
            ended(with_the_call, false, 0, 0),
            false,
        ),
        (
            "content was dropped",
            ended(with_the_call, false, 0, 3),
            true,
        ),
        (
            "the mediation function closed",
            ended("MediationClosed", false, 0, 0),
            true,
        ),
        (
            "the delivery connection failed",
            ended("TransportError", false, 12, 0),
            true,
        ),
        (
            "a detach that dropped",
            ended("Detached", true, 10, 1),
            false,
        ),
    ] {
        assert!(
            !x3_end_is_clean(&event, ended_by_siphon),
            "{case} is reported"
        );
    }

    // The reason is the engine's enum as the event conversion renders it.
    assert_eq!(
        format!("{:?}", siphon_rtp_proto::X3EndReason::CallEnded),
        with_the_call
    );
}

/// The leak gate for content delivery: calls that complete, calls routed
/// again after a failed attempt, calls that fail unanswered, callers seated in
/// a conference room (hanging up, or taken out of a room siphon stops), calls
/// whose leg is moved into a room and calls the engine answers itself leave
/// every lawful-intercept map and the media backend's at baseline.
#[tokio::test]
async fn completed_rerouted_and_failed_calls_drain_every_map_to_baseline() {
    use crate::rtpengine::backend::{AdoptedSeat, ConferenceDtmf, ConferenceRole, ConferenceSeat};
    const EACH: usize = 20;
    const KINDS: [&str; 7] = [
        "completed",
        "rerouted",
        "failed",
        "seat",
        "room-stop",
        "seated",
        "local",
    ];
    let (state, engine, li, _iri, _audit) =
        intercepting_on_the_engine(NativeTestEngine::start_with_x3().await).await;
    let backend = backend_of(&state);
    let events = engine_events(&state);
    let flags = crate::rtpengine::NgFlags::default();
    let settle = || tokio::time::sleep(std::time::Duration::from_millis(5));

    for kind in KINDS {
        for index in 0..EACH {
            let call_id = format!("leak-{kind}-{index}@192.0.2.10");
            let room = format!("leak-room-{kind}-{index}");
            let seated = ["seat", "room-stop"].contains(&kind);
            let named = |raw: &str| raw.replace(CALLER_CALL_ID, &call_id);
            // A joined seat's delivery is named by its room.
            let delivery = if seated { &room } else { &call_id };
            let ended = |reason: &str| {
                crate::rtpengine::events::RtpEngineEvent::X3Ended(
                    crate::rtpengine::events::X3EndedEvent {
                        call_id: delivery.clone(),
                        from_tag: "caller-tag".to_string(),
                        reason: reason.to_string(),
                        orderly: reason == "Detached",
                        delivered: 10,
                        dropped: 0,
                        delivery: None,
                    },
                )
            };
            arrives(&state, CALLER, &named(CALLER_INVITE));
            if seated {
                let seat = ConferenceSeat {
                    conference_id: room.clone(),
                    from_tag: "caller-tag".to_string(),
                };
                backend
                    .conference_join(&call_id, seat, "v=0\r\n", ConferenceRole::Talker, &flags)
                    .await
                    .expect("seated");
                settle().await;
                arrives(&state, CALLER, &named(CALLER_ACK));
                if kind == "seat" {
                    // The caller hangs up: detached on the seat.
                    let bye = named(CALLER_ACK)
                        .replace("ACK sip:", "BYE sip:")
                        .replace("CSeq: 1 ACK", "CSeq: 2 BYE")
                        .replace("z9hG4bK-caller-ack", "z9hG4bK-caller-bye");
                    arrives(&state, CALLER, &bye);
                }
                settle().await;
                // siphon takes the seat out, which stops the room.
                backend
                    .delete(&call_id, "caller-tag")
                    .await
                    .expect("the seat is freed");
                let reason = if kind == "seat" {
                    "Detached"
                } else {
                    "CallEnded"
                };
                events
                    .send(ended(reason))
                    .await
                    .expect("the event loop runs");
                // The caller's answer to the BYE siphon sent it.
                arrives(&state, CALLER, &named(CALLER_BYE_OK));
                assert!(crate::rtpengine::MediaBackend::conference_seat(&call_id).is_none());
                continue;
            }
            if kind == "local" {
                backend
                    .answer_local(&call_id, "caller-tag", "v=0\r\n", &flags)
                    .await
                    .expect("answered by the engine");
                settle().await;
                arrives(&state, CALLER, &named(CALLER_ACK));
                backend
                    .delete(&call_id, "caller-tag")
                    .await
                    .expect("deleted");
                events
                    .send(ended("CallEnded"))
                    .await
                    .expect("the event loop runs");
                arrives(&state, CALLER, &named(CALLER_BYE_OK));
                continue;
            }
            backend
                .offer(&call_id, "caller-tag", b"v=0\r\n", &flags)
                .await
                .expect("offered");
            settle().await;
            if kind == "rerouted" {
                arrives(
                    &state,
                    CALLEE,
                    &named(&proxied_response("183 Session Progress")),
                );
                backend
                    .delete(&call_id, "caller-tag")
                    .await
                    .expect("deleted");
                backend
                    .offer(&call_id, "caller-tag", b"v=0\r\n", &flags)
                    .await
                    .expect("offered again");
                events
                    .send(ended("CallEnded"))
                    .await
                    .expect("the event loop runs");
                settle().await;
            }
            if kind == "failed" {
                arrives(&state, CALLEE, &named(&proxied_response("486 Busy Here")));
                arrives(&state, CALLER, &named(CALLER_FAILURE_ACK));
            } else {
                arrives(&state, CALLEE, &named(&proxied_response("200 OK")));
                arrives(&state, CALLER, &named(CALLER_ACK));
                if kind == "seated" {
                    // The far party is moved into a room, out, and back in.
                    backend
                        .answer(&call_id, "caller-tag", "callee-tag", b"v=0\r\n", &flags)
                        .await
                        .expect("answered");
                    for _ in 0..2 {
                        let adopted = AdoptedSeat {
                            sip_call_id: call_id.clone(),
                            party_uri: None,
                            internal_call_id: call_id.clone(),
                            owner_call_id: format!("owner-{call_id}"),
                            end_owner_on_last: false,
                            dtmf: ConferenceDtmf::Events,
                        };
                        backend
                            .conference_seat_call(
                                &call_id,
                                "callee-tag",
                                &room,
                                ConferenceRole::Talker,
                                adopted,
                            )
                            .await
                            .expect("seated in place");
                        let seat = ConferenceSeat {
                            conference_id: room.clone(),
                            from_tag: "callee-tag".to_string(),
                        };
                        backend
                            .conference_leave(&call_id, &seat)
                            .await
                            .expect("out of the room");
                    }
                }
                let bye = named(CALLER_ACK)
                    .replace("ACK sip:", "BYE sip:")
                    .replace("CSeq: 1 ACK", "CSeq: 2 BYE")
                    .replace("z9hG4bK-caller-ack", "z9hG4bK-caller-bye");
                arrives(&state, CALLER, &bye);
            }
            settle().await;
            backend
                .delete(&call_id, "caller-tag")
                .await
                .expect("deleted");
            events
                .send(ended("Detached"))
                .await
                .expect("the event loop runs");
        }
    }
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    assert_eq!(li.x3_attachment_count(), 0, "no delivery left on record");
    assert_eq!(
        li.remembered_session_count(),
        KINDS.len() * EACH,
        "kept for the grace"
    );
    li.sweep_sessions(
        std::time::Instant::now() + crate::li::SESSION_GRACE + std::time::Duration::from_secs(1),
        |_| false,
    );
    assert_eq!(li.remembered_session_count(), 0, "decisions drain");
    assert_eq!(li.session_alias_count(), 0, "aliases drain");
    assert_eq!(li.x3_call_count(), 0, "engine-call and seat records drain");
    assert_eq!(backend.active_sessions(), 0, "the backend holds no call");
    assert_eq!(engine.held_count(), 0, "and neither does the engine");
}
