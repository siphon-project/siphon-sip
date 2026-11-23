//! X2 carries what siphon sends to the target, not only what it receives.
//!
//! The tap sits where every frame leaves ([`OutboundRouter::deliver`]), so
//! these tests send through `state.outbound` as the dispatcher does and read
//! the X2 records the lawful-intercept subsystem emits. Each record is for a
//! frame addressed to the target's user agent (direction 2) under the call's
//! Correlation ID; frames to the other party are not recorded, a resend is the
//! same record, and a proxy's relayed copy is the record its arrival already
//! made.

use super::li_session_tests::{
    arrives, caller_calls, dial, drain_iri, intercepting_for, CALLEE, CALLEE_CALL_ID, CALLER,
    CALLER_ACK, CALLER_INVITE,
};
use super::test_dispatcher::test_dispatcher;
use super::x2_outbound::{li_tap_outbound, li_tap_wanted, tests_support};
use super::*;
use crate::li::pdu::PayloadDirection::SentToTarget;
use crate::li::{correlation_from_call_id, IriEvent, IriEventType};
use tokio::sync::mpsc;

const CALLER_CALL_ID: &str = "caller-call@192.0.2.10";
const CALLED: &str = "sip:15550100042@siphon.example.com";

/// Siphon's answer to the caller's INVITE, on the caller's leg.
fn answer(status_line: &str) -> String {
    format!(
        concat!(
            "SIP/2.0 {status_line}\r\n",
            "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-caller-invite\r\n",
            "From: <sip:alice@example.com>;tag=caller-tag\r\n",
            "To: <sip:15550100042@siphon.example.com>;tag=siphon-tag\r\n",
            "Call-ID: caller-call@192.0.2.10\r\n",
            "CSeq: 1 INVITE\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        status_line = status_line,
    )
}

/// Siphon's 200 to the caller's BYE.
const BYE_OK: &str = concat!(
    "SIP/2.0 200 OK\r\n",
    "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-caller-bye\r\n",
    "From: <sip:alice@example.com>;tag=caller-tag\r\n",
    "To: <sip:15550100042@siphon.example.com>;tag=siphon-tag\r\n",
    "Call-ID: caller-call@192.0.2.10\r\n",
    "CSeq: 2 BYE\r\n",
    "Content-Length: 0\r\n",
    "\r\n",
);

/// A request siphon sends on the leg it dialled for the called party.
fn on_the_dialled_leg(method: &str, cseq: u32, to_tag: &str, branch: &str) -> String {
    format!(
        concat!(
            "{method} sip:15550100042@198.51.100.77:5060 SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-{branch}\r\n",
            "Max-Forwards: 70\r\n",
            "From: <sip:15550100001@192.0.2.1>;tag=siphon-leg\r\n",
            "To: <sip:15550100042@198.51.100.77>{to_tag}\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: {cseq} {method}\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        method = method,
        cseq = cseq,
        to_tag = to_tag,
        branch = branch,
        call_id = CALLEE_CALL_ID,
    )
}

/// What `state.outbound` is handed, as the dispatcher hands it.
fn leaves(state: &Arc<DispatcherState>, destination: &str, raw: &str) {
    let message = OutboundMessage {
        relayed: false,
        followups: None,
        connection_id: ConnectionId::default(),
        transport: Transport::Udp,
        destination: destination.parse().expect("a literal address"),
        data: Bytes::from(raw.to_string()),
        source_local_addr: Some("192.0.2.1:5060".parse().expect("a literal address")),
        server_name: None,
        verify_server: None,
    };
    // The channel's far end is not read here: the tap runs before it.
    let _ = state.outbound.send(message);
}

fn summary(events: &[IriEvent]) -> Vec<(String, Option<u16>)> {
    events
        .iter()
        .map(|event| (event.sip_method.clone(), event.status_code))
        .collect()
}

/// A rig for a warrant on `identifier`: the caller's INVITE has arrived and
/// the call exists.
fn rig(
    identifier: &str,
) -> (
    Arc<DispatcherState>,
    crate::li::LiManager,
    mpsc::Receiver<IriEvent>,
    String,
    tests_support::TapGuard,
) {
    rig_on(test_dispatcher(), identifier)
}

/// [`rig`] on a dispatcher the test prepared.
fn rig_on(
    dispatcher: super::test_dispatcher::TestDispatcher,
    identifier: &str,
) -> (
    Arc<DispatcherState>,
    crate::li::LiManager,
    mpsc::Receiver<IriEvent>,
    String,
    tests_support::TapGuard,
) {
    let (state, li, mut iri, _audit) = intercepting_for(dispatcher, identifier);
    let internal_id = caller_calls(&state);
    drain_iri(&mut iri);
    let guard = tests_support::install(&li, Some(Arc::clone(&state.call_actors)));
    (state, li, iri, internal_id, guard)
}

#[tokio::test]
async fn what_siphon_answers_a_calling_target_is_recorded_to_the_target() {
    let (state, _li, mut iri, internal_id, _tap) = rig("sip:alice@example.com");

    leaves(&state, CALLER, &answer("100 Trying"));
    leaves(&state, CALLER, &answer("200 OK"));
    leaves(&state, CALLER, BYE_OK);

    let events = drain_iri(&mut iri);
    assert_eq!(
        summary(&events),
        [
            ("INVITE".to_string(), Some(100)),
            ("INVITE".to_string(), Some(200)),
            ("BYE".to_string(), Some(200)),
        ]
    );
    let correlation = correlation_from_call_id(&internal_id);
    for event in &events {
        assert_eq!(event.direction, SentToTarget);
        assert_eq!(event.correlation_id, correlation, "the call's own CID");
        assert_eq!(event.call_id, CALLER_CALL_ID);
        assert_eq!(
            event.destination_ip,
            Some(CALLER.parse::<SocketAddr>().expect("an address").ip())
        );
        assert_eq!(
            event.source_ip,
            Some("192.0.2.1".parse().expect("an address")),
            "siphon's egress address"
        );
        assert!(
            event
                .raw_message
                .as_deref()
                .is_some_and(|raw| raw.starts_with(b"SIP/2.0")),
            "the frame as it left"
        );
    }
}

#[tokio::test]
async fn a_resent_frame_is_one_record() {
    let (state, _li, mut iri, _internal_id, _tap) = rig("sip:alice@example.com");

    leaves(&state, CALLER, &answer("200 OK"));
    leaves(&state, CALLER, &answer("200 OK"));
    leaves(&state, CALLER, &answer("200 OK"));

    assert_eq!(drain_iri(&mut iri).len(), 1, "a 2xx resent until its ACK");
}

#[tokio::test]
async fn what_siphon_sends_does_not_end_the_session() {
    let (state, li, mut iri, internal_id, _tap) = rig("sip:alice@example.com");

    let bye = concat!(
        "BYE sip:alice@192.0.2.10:5060 SIP/2.0\r\n",
        "Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-siphon-bye\r\n",
        "From: <sip:15550100042@siphon.example.com>;tag=siphon-tag\r\n",
        "To: <sip:alice@example.com>;tag=caller-tag\r\n",
        "Call-ID: caller-call@192.0.2.10\r\n",
        "CSeq: 9 BYE\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    );
    leaves(&state, CALLER, bye);

    let events = drain_iri(&mut iri);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type, IriEventType::End);
    // Only what arrives ends a session: it is still resolvable and live.
    li.sweep_sessions(std::time::Instant::now(), |session_id| {
        session_id == internal_id
    });
    assert!(li.session_of_leg(CALLER_CALL_ID).is_some());
    assert!(li.any_warranted_session());
}

#[tokio::test]
async fn a_teardown_siphon_starts_reaches_the_target_on_its_own_leg_only() {
    let (state, _li, mut iri, internal_id, _tap) = rig("sip:alice@example.com");
    dial(&state, &internal_id, CALLEE_CALL_ID);
    arrives(
        &state,
        CALLEE,
        &super::li_session_tests::callee_response(CALLEE_CALL_ID, "200 OK"),
    );
    arrives(&state, CALLER, CALLER_ACK);
    drain_iri(&mut iri);

    b2bua_max_duration_terminate(&internal_id, &state);

    let events = drain_iri(&mut iri);
    assert!(
        events
            .iter()
            .all(|event| event.direction == SentToTarget && event.call_id == CALLER_CALL_ID),
        "only the BYE on the target's leg: {:?}",
        summary(&events)
    );
    assert!(
        events.iter().any(|event| event.sip_method == "BYE"),
        "the target is sent its BYE: {:?}",
        summary(&events)
    );
}

#[tokio::test]
async fn the_session_timer_teardown_is_recorded_too() {
    let (state, _li, mut iri, internal_id, _tap) = rig("sip:alice@example.com");
    dial(&state, &internal_id, CALLEE_CALL_ID);
    arrives(
        &state,
        CALLEE,
        &super::li_session_tests::callee_response(CALLEE_CALL_ID, "200 OK"),
    );
    arrives(&state, CALLER, CALLER_ACK);
    drain_iri(&mut iri);

    b2bua_session_timer_terminate(&internal_id, &state);

    let events = drain_iri(&mut iri);
    assert!(
        events
            .iter()
            .any(|event| event.sip_method == "BYE" && event.direction == SentToTarget),
        "{:?}",
        summary(&events)
    );
}

#[tokio::test]
async fn what_siphon_sends_the_far_leg_is_not_recorded_for_a_calling_target() {
    let (state, _li, mut iri, internal_id, _tap) = rig("sip:alice@example.com");
    dial(&state, &internal_id, CALLEE_CALL_ID);

    leaves(
        &state,
        CALLEE,
        &on_the_dialled_leg("INVITE", 1, "", "far-invite"),
    );

    assert!(
        drain_iri(&mut iri).is_empty(),
        "the far leg is not to or from the target"
    );
}

#[tokio::test]
async fn what_siphon_sends_a_called_target_is_recorded_whatever_the_request() {
    let (state, _li, mut iri, internal_id, _tap) = rig(CALLED);
    dial(&state, &internal_id, CALLEE_CALL_ID);

    leaves(
        &state,
        CALLEE,
        &on_the_dialled_leg("INVITE", 1, "", "dialled-invite"),
    );
    leaves(
        &state,
        CALLEE,
        &on_the_dialled_leg("PRACK", 2, ";tag=callee-tag", "dialled-prack"),
    );
    leaves(
        &state,
        CALLEE,
        &on_the_dialled_leg("ACK", 1, ";tag=callee-tag", "dialled-ack"),
    );
    leaves(
        &state,
        CALLEE,
        &on_the_dialled_leg("CANCEL", 1, "", "dialled-invite"),
    );
    // And what it sends the caller, who is not the target, is not.
    leaves(&state, CALLER, &answer("180 Ringing"));

    let events = drain_iri(&mut iri);
    assert_eq!(
        summary(&events),
        [
            ("INVITE".to_string(), None),
            ("PRACK".to_string(), None),
            ("ACK".to_string(), None),
            ("CANCEL".to_string(), None),
        ]
    );
    assert_eq!(events[0].event_type, IriEventType::Begin);
    for event in &events {
        assert_eq!(event.direction, SentToTarget);
        assert_eq!(event.call_id, CALLEE_CALL_ID, "the leg's own Call-ID");
        assert_eq!(
            event.correlation_id,
            correlation_from_call_id(&internal_id),
            "the call's one CID"
        );
    }
}

#[tokio::test]
async fn a_relayed_copy_is_not_recorded_twice_and_its_resend_is_not_new() {
    let (_state, _li, mut iri, _internal_id, _tap) = rig("sip:alice@example.com");
    let frame = Bytes::from(answer("183 Session Progress"));
    let destination: SocketAddr = CALLER.parse().expect("a literal address");

    // The proxy passes on a response it received: the arrival made the record.
    li_tap_outbound(&frame, destination, None, true);
    // A transaction resend of the same bytes carries no flag.
    li_tap_outbound(&frame, destination, None, false);

    assert!(drain_iri(&mut iri).is_empty());
}

#[tokio::test]
async fn a_proxys_own_replies_to_a_calling_target_are_recorded() {
    // A proxied call: no B2BUA call, one dialog.
    let (state, li, mut iri, _audit) = intercepting_for(test_dispatcher(), "sip:alice@example.com");
    arrives(&state, CALLER, CALLER_INVITE);
    drain_iri(&mut iri);
    let _tap = tests_support::install(&li, Some(Arc::clone(&state.call_actors)));

    leaves(&state, CALLER, &answer("100 Trying"));
    leaves(&state, CALLER, &answer("487 Request Terminated"));
    let not_found = BYE_OK.replace("200 OK", "481 Call/Transaction Does Not Exist");
    leaves(&state, CALLER, &not_found);

    let events = drain_iri(&mut iri);
    assert_eq!(
        summary(&events),
        [
            ("INVITE".to_string(), Some(100)),
            ("INVITE".to_string(), Some(487)),
            ("BYE".to_string(), Some(481)),
        ]
    );
    assert!(events.iter().all(|event| event.direction == SentToTarget));
}

#[tokio::test]
async fn a_proxys_own_replies_to_the_caller_are_not_the_called_targets() {
    let (state, li, mut iri, _audit) = intercepting_for(test_dispatcher(), CALLED);
    arrives(&state, CALLER, CALLER_INVITE);
    drain_iri(&mut iri);
    let _tap = tests_support::install(&li, Some(Arc::clone(&state.call_actors)));

    leaves(&state, CALLER, &answer("100 Trying"));

    assert!(drain_iri(&mut iri).is_empty());
}

#[tokio::test]
async fn nothing_is_tapped_while_no_session_is_warranted() {
    let (state, li, mut iri, _audit) = intercepting_for(test_dispatcher(), "sip:alice@example.com");
    let _tap = tests_support::install(&li, Some(Arc::clone(&state.call_actors)));
    assert!(!li.any_warranted_session());
    assert!(
        li_tap_wanted(),
        "a warrant exists, so an originated INVITE may open a session"
    );

    // A frame of a call nobody intercepted, though a warrant is provisioned.
    leaves(&state, CALLER, &answer("200 OK"));

    assert!(drain_iri(&mut iri).is_empty());
    assert!(
        li.session_of_leg(CALLER_CALL_ID).is_none(),
        "nothing decided"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_connection_the_pool_opens_is_tapped() {
    // A pool that can bind here: the fixture's is bound to a documentation
    // address no host holds.
    let mut dispatcher = test_dispatcher();
    dispatcher.state.connection_pool = Arc::new(ConnectionPool::new(
        Arc::new(DashMap::new()),
        flume::unbounded().0,
        "127.0.0.1:5060".parse().expect("a literal address"),
        None,
        Some(dispatcher.state.stream_connections.clone()),
        None,
        crate::transport::pool::build_outbound_tls_config(
            None,
            crate::config::TlsMethod::default(),
        )
        .expect("an outbound TLS config"),
    ));
    let (state, _li, mut iri, _internal_id, _tap) = rig_on(dispatcher, "sip:alice@example.com");
    // A listener for the pool to connect to.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a listening socket");
    let destination = listener.local_addr().expect("its address");
    let frame = Bytes::from(answer("200 OK"));
    let target = RelayTarget {
        address: destination,
        transport: Some(Transport::Tcp),
        server_name: None,
        verify_server: None,
    };

    let outcome = tokio::task::block_in_place(|| {
        send_to_target(
            frame,
            &target,
            Transport::Tcp,
            ConnectionId::default(),
            None,
            &state,
        )
    });

    assert!(!outcome.delivery_failed);
    let events = drain_iri(&mut iri);
    assert_eq!(events.len(), 1, "the pool branch skips deliver, and taps");
    assert_eq!(events[0].direction, SentToTarget);
    assert_eq!(events[0].destination_ip, Some(destination.ip()));
}
/// A script that puts every initial INVITE into B2BUA mode.
const B2BUA_SCRIPT: &str = concat!(
    "from siphon import b2bua\n",
    "\n",
    "@b2bua.on_invite\n",
    "def on_invite(call):\n",
    "    call.dial(\"sip:15550100042@198.51.100.77:5060\")\n",
);

/// A response siphon sends on the dialled leg, to the called party's request.
const BYE_OK_TO_CALLED: &str = concat!(
    "SIP/2.0 200 OK\r\n",
    "Via: SIP/2.0/UDP 198.51.100.77:5060;branch=z9hG4bK-far-bye\r\n",
    "From: <sip:15550100042@198.51.100.77>;tag=callee-tag\r\n",
    "To: <sip:15550100001@192.0.2.1>;tag=siphon-leg\r\n",
    "Call-ID: b2b-callee@192.0.2.1\r\n",
    "CSeq: 2 BYE\r\n",
    "Content-Length: 0\r\n",
    "\r\n",
);

/// The X2 stream of a called target on a B2BUA call is the wire to and from
/// that target and nothing else: not the caller's INVITE (which is not sent to
/// the target; siphon's own is), not the caller's ACK, not what siphon sends
/// the caller.
#[tokio::test]
async fn a_called_target_of_a_b2bua_call_gets_exactly_the_wire_to_and_from_it() {
    use crate::li::pdu::PayloadDirection::SentFromTarget;
    let (state, li, mut iri, _audit) = intercepting_for(
        super::test_dispatcher::test_dispatcher_with_script(B2BUA_SCRIPT),
        CALLED,
    );
    let _tap = tests_support::install(&li, Some(Arc::clone(&state.call_actors)));
    let internal_id = caller_calls(&state);
    dial(&state, &internal_id, CALLEE_CALL_ID);

    leaves(&state, CALLER, &answer("100 Trying"));
    leaves(
        &state,
        CALLEE,
        &on_the_dialled_leg("INVITE", 1, "", "dialled-invite"),
    );
    arrives(
        &state,
        CALLEE,
        &super::li_session_tests::callee_response(CALLEE_CALL_ID, "180 Ringing"),
    );
    arrives(
        &state,
        CALLEE,
        &super::li_session_tests::callee_response(CALLEE_CALL_ID, "200 OK"),
    );
    leaves(&state, CALLER, &answer("200 OK"));
    leaves(
        &state,
        CALLEE,
        &on_the_dialled_leg("ACK", 1, ";tag=callee-tag", "dialled-ack"),
    );
    arrives(&state, CALLER, CALLER_ACK);
    arrives(
        &state,
        CALLEE,
        &super::li_session_tests::callee_request("BYE", 2, "z9hG4bK-far-bye"),
    );
    leaves(&state, CALLEE, BYE_OK_TO_CALLED);
    let bye_to_caller = concat!(
        "BYE sip:alice@192.0.2.10:5060 SIP/2.0\r\n",
        "Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-siphon-bye\r\n",
        "From: <sip:15550100042@siphon.example.com>;tag=siphon-tag\r\n",
        "To: <sip:alice@example.com>;tag=caller-tag\r\n",
        "Call-ID: caller-call@192.0.2.10\r\n",
        "CSeq: 9 BYE\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    );
    leaves(&state, CALLER, bye_to_caller);

    let events = drain_iri(&mut iri);
    let stream: Vec<_> = events
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
        stream,
        [
            ("INVITE", None, SentToTarget),
            ("INVITE", Some(180), SentFromTarget),
            ("INVITE", Some(200), SentFromTarget),
            ("ACK", None, SentToTarget),
            ("BYE", None, SentFromTarget),
            ("BYE", Some(200), SentToTarget),
        ],
        "exactly the wire to and from the target"
    );
    assert_eq!(events[0].event_type, IriEventType::Begin);
    assert_eq!(events[0].call_id, CALLEE_CALL_ID, "siphon's dialled INVITE");
    let correlation = correlation_from_call_id(&internal_id);
    assert!(events
        .iter()
        .all(|event| event.correlation_id == correlation));
}

/// In proxy mode the INVITE is relayed to the target, so the arrival is the
/// record of it.
#[tokio::test]
async fn a_called_targets_opening_invite_is_kept_in_proxy_mode() {
    let (state, _li, mut iri, _audit) = intercepting_for(test_dispatcher(), CALLED);
    arrives(&state, CALLER, CALLER_INVITE);
    let events = drain_iri(&mut iri);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].sip_method, "INVITE");
}

/// A call siphon originates to a target has no inbound INVITE: the outbound
/// one decides the session, and it, a CANCEL and everything after are recorded.
#[tokio::test]
async fn a_call_siphon_originates_to_a_target_is_decided_on_its_invite() {
    let (state, li, mut iri, _audit) = intercepting_for(test_dispatcher(), ORIGINATED_TARGET);
    let _tap = tests_support::install(&li, Some(Arc::clone(&state.call_actors)));
    assert!(!li.any_warranted_session());

    leaves(
        &state,
        CALLEE,
        &on_the_dialled_leg("INVITE", 1, "", "originated"),
    );
    leaves(
        &state,
        CALLEE,
        &on_the_dialled_leg("CANCEL", 1, "", "originated"),
    );
    arrives(
        &state,
        CALLEE,
        &super::li_session_tests::callee_response(CALLEE_CALL_ID, "487 Request Terminated"),
    );
    leaves(
        &state,
        CALLEE,
        &on_the_dialled_leg("ACK", 1, ";tag=callee-tag", "originated"),
    );

    let events = drain_iri(&mut iri);
    assert_eq!(
        summary(&events),
        [
            ("INVITE".to_string(), None),
            ("CANCEL".to_string(), None),
            ("INVITE".to_string(), Some(487)),
            ("ACK".to_string(), None),
        ]
    );
    assert_eq!(events[0].event_type, IriEventType::Begin);
    assert!(events
        .iter()
        .all(|event| event.correlation_id == events[0].correlation_id));
}

/// The target of a call siphon originates, as the dialled leg names it.
const ORIGINATED_TARGET: &str = "sip:15550100042@198.51.100.77";

/// With no warrant provisioned the tap decides nothing and clones nothing.
#[tokio::test]
async fn an_originated_invite_decides_nothing_while_no_warrant_is_provisioned() {
    let (state, li, mut iri, _audit) = intercepting_for(test_dispatcher(), ORIGINATED_TARGET);
    li.tasks().deactivate_all();
    let _tap = tests_support::install(&li, Some(Arc::clone(&state.call_actors)));
    assert!(!li.any_active_task());
    assert!(!li_tap_wanted());

    leaves(
        &state,
        CALLEE,
        &on_the_dialled_leg("INVITE", 1, "", "originated"),
    );

    assert!(drain_iri(&mut iri).is_empty());
    assert_eq!(li.remembered_session_count(), 0);
}

/// An originated INVITE that no warrant names decides and remembers nothing.
#[tokio::test]
async fn an_originated_invite_no_warrant_names_is_not_remembered() {
    let (state, li, mut iri, _audit) =
        intercepting_for(test_dispatcher(), "sip:someone-else@example.com");
    let _tap = tests_support::install(&li, Some(Arc::clone(&state.call_actors)));

    leaves(
        &state,
        CALLEE,
        &on_the_dialled_leg("INVITE", 1, "", "originated"),
    );

    assert!(drain_iri(&mut iri).is_empty());
    assert_eq!(li.remembered_session_count(), 0);
}
