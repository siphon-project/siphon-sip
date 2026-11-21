//! A warrant activated while a B2BUA call is up, and the call's hold re-INVITE
//! then relayed by the real B2BUA path: the caller's re-INVITE through
//! [`handle_b2bua_reinvite`] (a `reoffer` to the engine), the callee's 200
//! through [`handle_b2bua_response`] (an `answer`), and the caller's ACK.
//!
//! The call is anchored and answered before any warrant exists, so interception
//! has seen nothing of its engine call.

use super::dial_bridge_test_harness::in_dialog_response;
use super::dialog_state_events_tests::{header, inbound, Sent};
use super::lcr_ring_timeout_tests::top_via_branch;
use super::li_session_tests::attach_outcomes;
use super::reoffer_ingress_tests::{acks, callee_of, caller_of, relayed_to, request_from, Party};
use super::test_dispatcher::TestDispatcher;
use super::transfer_ingress_tests::{anchored, sdp_naming, OPEN, SIGNALLED};
use super::*;
use crate::config::LawfulInterceptConfig;
use crate::li::x1::message::{DestinationDetails, TaskDetails};
use crate::li::x1::store::ContentCapability;
use crate::li::x1::types::{
    DId, DeliveryAddress, DeliveryType, IpAddressPort, Port, TargetIdentifier, XId,
};
use crate::li::LiManager;
use crate::rtpengine::test_native_engine::NativeTestEngine;
use std::net::{IpAddr, Ipv4Addr};

fn wire_of(udp: &flume::Receiver<OutboundMessage>) -> Vec<Sent> {
    let mut sent = Vec::new();
    while let Ok(outbound) = udp.try_recv() {
        for frame in outbound.frames() {
            sent.push(Sent {
                destination: outbound.destination.to_string(),
                message: parse_sip_message_bytes(frame).expect("siphon sent a message that parses"),
            });
        }
    }
    sent
}

/// A warrant activated mid-call attaches the call once, and the call's hold
/// re-INVITE, relayed as the B2BUA relays it, asks for nothing more: not at
/// the re-offer, not at the answer, not at the ACK. Nothing is detached and
/// the delivery is live.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hold_relayed_by_the_b2bua_after_a_mid_call_warrant_attaches_nothing_more() {
    hold_after_a_mid_call_warrant(false).await;
}

/// The same on a node that was intercepting for another warrant all along: the
/// call's setup passed through interception, which remembered it as
/// unwarranted, and the engine told it of the call's media.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_hold_after_a_mid_call_warrant_on_a_call_interception_saw_set_up_attaches_nothing_more() {
    hold_after_a_mid_call_warrant(true).await;
}

async fn hold_after_a_mid_call_warrant(setup_was_seen: bool) {
    let engine = NativeTestEngine::start_with_x3_026().await;
    let prefix = if setup_was_seen { 63000 } else { 62000 };
    let call = anchored(prefix, &engine, OPEN).await;
    let (caller, callee) = (caller_of(&call), callee_of(&call));
    acks(&call.dispatcher.state, &caller);
    let internal_id = call.call_id();
    let a_call_id = call.a_call_id.clone();
    let (caller_uri, callee_uri) = (call.a.0, call.b.0);
    let caller_ip: IpAddr = call
        .a
        .1
        .parse::<std::net::SocketAddr>()
        .expect("an address")
        .ip();
    let invite_to = header(&call.answer_to_a, "To")
        .split(';')
        .next()
        .map(str::to_string)
        .expect("a To header");
    let to_b = call.to_b.clone();
    let TestDispatcher { mut state, udp } = call.dispatcher;

    // Interception arrives after the call: nothing provisioned, and the
    // INVITE seen opening is all it holds of the call.
    let (li, _iri, mut audit) = LiManager::new(
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
        .expect("destination");
    state.li_manager = Some(li.clone());
    let state = Arc::new(state);
    super::intercept::watch_engine_calls(&state);
    if setup_was_seen {
        // Another warrant keeps interception on, so every message is decided,
        // the call's as unwarranted.
        let mut bystander = TaskDetails {
            x_id: XId::generate(),
            target_identifiers: vec![TargetIdentifier::SipUri("sip:carol@example.com".into())],
            delivery_type: DeliveryType::X2AndX3,
            list_of_dids: vec![d_id],
            list_of_dsids: Vec::new(),
            list_of_mediation_details: Vec::new(),
            correlation_id: None,
            implicit_deactivation_allowed: None,
            product_id: None,
            list_of_service_types: Vec::new(),
        };
        bystander.x_id = XId::generate();
        li.tasks().activate(bystander).expect("a bystander warrant");
        let untagged = Party {
            to: invite_to.clone(),
            ..caller_of_parts(&caller)
        };
        let (raw_invite, invite) =
            request_from(&untagged, "INVITE", 1, Some(&sdp_naming(SIGNALLED)));
        super::intercept::intercept_message(
            &invite,
            &inbound(&caller.address, &raw_invite),
            &state,
        );
        let b_leg_id = callee.call_id.clone();
        let answered = in_dialog_response(
            &to_b,
            200,
            "OK",
            &format!("sip:phone@{}", callee.address),
            Some(&sdp_naming(SIGNALLED)),
        );
        let raw_answered = String::from_utf8(answered.to_bytes()).expect("text");
        super::intercept::intercept_message(
            &answered,
            &inbound(&callee.address, &raw_answered),
            &state,
        );
        // What the engine told interception when the call was set up.
        li.adopt_engine_call(&a_call_id, &a_call_id, crate::li::EngineCallSide::Offerer);
        li.adopt_engine_call(&b_leg_id, &a_call_id, crate::li::EngineCallSide::Answerer);
        let (raw_ack, ack) = request_from(&caller, "ACK", 1, None);
        super::intercept::intercept_message(&ack, &inbound(&caller.address, &raw_ack), &state);
    }
    li.live_dialog_opened(
        &a_call_id,
        &callee_uri,
        &caller.from,
        &invite_to,
        Some(caller_ip),
    );

    let mut known = super::intercept::known_targets(&li);
    li.tasks()
        .activate(TaskDetails {
            x_id: XId::generate(),
            target_identifiers: vec![TargetIdentifier::SipUri(caller_uri.to_string())],
            delivery_type: DeliveryType::X2AndX3,
            list_of_dids: vec![d_id],
            list_of_dsids: Vec::new(),
            list_of_mediation_details: Vec::new(),
            correlation_id: None,
            implicit_deactivation_allowed: None,
            product_id: None,
            list_of_service_types: Vec::new(),
        })
        .expect("the warrant arrives mid-call");
    super::intercept::warrants_changed(&state, &mut known).await;
    assert_eq!(
        attach_outcomes(&mut audit).await,
        (1, 0),
        "the scan attaches"
    );
    assert_eq!(engine.commands("attach_x3").len(), 1);

    // Another warrant is provisioned before the call's next message, which
    // finds the generation moved.
    let mut elsewhere = TaskDetails {
        x_id: XId::generate(),
        target_identifiers: vec![TargetIdentifier::SipUri("sip:dave@example.com".into())],
        delivery_type: DeliveryType::X2AndX3,
        list_of_dids: vec![d_id],
        list_of_dsids: Vec::new(),
        list_of_mediation_details: Vec::new(),
        correlation_id: None,
        implicit_deactivation_allowed: None,
        product_id: None,
        list_of_service_types: Vec::new(),
    };
    elsewhere.x_id = XId::generate();
    li.tasks().activate(elsewhere).expect("another warrant");
    super::intercept::warrants_changed(&state, &mut known).await;
    assert_eq!(attach_outcomes(&mut audit).await, (0, 0));

    // The caller's hold. Interception sees each message first, as the
    // dispatch loop has it.
    let hold = sdp_naming(SIGNALLED);
    let (raw, reinvite) = request_from(&caller, "INVITE", 2, Some(&hold));
    super::intercept::intercept_message(&reinvite, &inbound(&caller.address, &raw), &state);
    tokio::task::block_in_place(|| {
        handle_b2bua_reinvite(inbound(&caller.address, &raw), reinvite, &state)
    });
    let relayed = relayed_to(&wire_of(&udp), &callee.address, "INVITE");
    let mut accepted = in_dialog_response(
        &relayed,
        200,
        "OK",
        &format!("sip:phone@{}", callee.address),
        Some(&sdp_naming(SIGNALLED)),
    );
    let raw_accepted = String::from_utf8(accepted.to_bytes()).expect("text");
    super::intercept::intercept_message(
        &accepted,
        &inbound(&callee.address, &raw_accepted),
        &state,
    );
    assert!(tokio::task::block_in_place(|| handle_b2bua_response(
        &internal_id,
        &top_via_branch(&relayed),
        &mut accepted,
        200,
        callee.address.parse().expect("an address"),
        &state,
    )));
    assert_eq!(engine.commands("reoffer").len(), 1, "the relay re-offered");
    assert_eq!(engine.commands("answer").len(), 2, "and answered");

    let (raw_ack, ack) = request_from(&caller, "ACK", 2, None);
    super::intercept::intercept_message(&ack, &inbound(&caller.address, &raw_ack), &state);
    let _ = tokio::task::block_in_place(|| absorb_b2bua_ack(&caller.call_id, &ack, &state));

    assert_eq!(
        attach_outcomes(&mut audit).await,
        (0, 0),
        "nothing more asked"
    );
    assert_eq!(
        engine.commands("attach_x3").len(),
        1,
        "one attach_x3 across the hold"
    );
    assert!(engine.commands("detach_x3").is_empty());
    assert_eq!(
        li.x3_attachments_for(&a_call_id).len(),
        1,
        "the delivery is live"
    );
    assert_eq!(engine.x3_delivery_count(), 1);
}

fn caller_of_parts(party: &Party) -> Party {
    Party {
        address: party.address.clone(),
        from: party.from.clone(),
        to: party.to.clone(),
        call_id: party.call_id.clone(),
    }
}
