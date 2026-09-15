//! A transfer that releases a party whose 2xx is still unACKed holds that BYE
//! for the ACK, the same way a hangup does (RFC 3261 §15).
//!
//! Every BYE a transfer sends goes to a dialog siphon may still be the UAS of,
//! with its 2xx not yet ACKed: the referrer released by a siphon-terminated
//! REFER, straight away or once the terminating NOTIFY is answered; the surviving
//! party of a transfer that failed after the referrer left; and the party an
//! INVITE with `Replaces` takes over. Which leg of the call a dialog sits on says
//! nothing about it: a takeover of the callee's side moves the caller into the
//! B-leg slot, and a teardown after that still has to hold the caller's BYE.
//!
//! Driven through the dispatcher with the harness `b_leg_2xx_ack_tests` shares:
//! the caller's call is bridged to a callee that answers, the caller has not
//! ACKed, and the transfer functions run as the response and INVITE paths run
//! them.

use super::b_leg_2xx_ack_tests::{callee, caller, Call, Sent};
use super::*;
use crate::b2bua::transfer::ReplacementOrigin;

const TARGET_CALL_ID: &str = "b2b-target@192.0.2.1";
const NEW_PARTY_CALL_ID: &str = "new-party@192.0.2.30";
const NORMAL_CLEARING: &str = "Q.850;cause=16;text=\"Normal Clearing\"";

fn target() -> SocketAddr {
    "198.51.100.88:5060".parse().expect("a literal address")
}

fn new_party() -> SocketAddr {
    "192.0.2.30:5060".parse().expect("a literal address")
}

fn byes_to(sent: &[Sent], destination: SocketAddr) -> Vec<&Sent> {
    sent.iter()
        .filter(|sent| {
            sent.destination == destination && sent.message.method() == Some(&Method::Bye)
        })
        .collect()
}

fn relayed_answer(call: &Call) -> SipMessage {
    call.wire()
        .into_iter()
        .find(|sent| sent.destination == caller() && sent.message.status_code() == Some(200))
        .expect("the answer was relayed to the caller")
        .message
}

/// Both stores drained: no answer waiting for an ACK and no BYE held for one.
fn nothing_held(call: &Call) -> bool {
    call.state.held_byes.is_empty() && call.state.uas_2xx_retransmits.is_empty()
}

/// The caller ACKs, and exactly one BYE follows it, to the caller.
fn assert_the_ack_releases_one_bye(call: &Call, relayed: &SipMessage) {
    call.caller_acks(relayed);
    let sent = call.wire();
    assert_eq!(
        byes_to(&sent, caller()).len(),
        1,
        "the caller's ACK releases its BYE"
    );
    assert!(nothing_held(call), "both stores drained");
}

/// A transfer target dialled on the call, the way the REFER path dials it.
fn add_transfer_target(call: &Call) -> usize {
    let mut leg = Leg::new_b_leg(
        TARGET_CALL_ID.to_string(),
        "sb-target-leg".to_string(),
        "sip:15550100077@198.51.100.88:5060".to_string(),
        "z9hG4bK-target-invite".to_string(),
        LegTransport {
            remote_addr: target(),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: None,
        },
    );
    leg.dialog.local_contact = Some("<sip:192.0.2.1:5060;transport=udp>".to_string());
    leg.dialog.local_from_uri = Some("<sip:15550100001@192.0.2.1>;tag=sb-target-leg".to_string());
    leg.dialog.remote_to_uri = Some("<sip:15550100077@198.51.100.88>".to_string());
    assert!(call.state.call_actors.add_b_leg(&call.call_id, leg));
    call.state
        .call_actors
        .get_call(&call.call_id)
        .map(|call| call.b_legs.len() - 1)
        .expect("the call exists")
}

/// The notifier subscription a siphon-terminated transfer records.
fn subscribe(call: &Call, referrer_on_a_leg: bool, origin: ReplacementOrigin, referrer_gone: bool) {
    call.state.call_actors.push_refer_subscription(
        &call.call_id,
        crate::b2bua::actor::ReferSubscription {
            on_a_leg: referrer_on_a_leg,
            siphon_notifies: true,
            origin,
            event_id: 2,
            notify_cseq: 2,
            state: crate::b2bua::transfer::TransferState::Trying,
            target_leg_call_id: Some(TARGET_CALL_ID.to_string()),
            referrer_gone,
            deadline: None,
            media_profile: None,
        },
    );
}

/// The transfer target's 2xx, with its answer.
fn target_answer() -> SipMessage {
    let sdp = concat!(
        "v=0\r\n",
        "o=- 5 5 IN IP4 198.51.100.88\r\n",
        "s=-\r\n",
        "c=IN IP4 198.51.100.88\r\n",
        "t=0 0\r\n",
        "m=audio 32000 RTP/AVP 0\r\n",
    );
    let raw = format!(
        concat!(
            "SIP/2.0 200 OK\r\n",
            "Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-target-invite\r\n",
            "From: <sip:15550100001@192.0.2.1>;tag=sb-target-leg\r\n",
            "To: <sip:15550100077@198.51.100.88>;tag=target-tag\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: 1 INVITE\r\n",
            "Contact: <sip:15550100077@198.51.100.88:5060>\r\n",
            "Content-Type: application/sdp\r\n",
            "Content-Length: {length}\r\n",
            "\r\n",
            "{sdp}",
        ),
        call_id = TARGET_CALL_ID,
        length = sdp.len(),
        sdp = sdp,
    );
    parse_sip_message_bytes(raw.as_bytes()).expect("the target's 2xx parses")
}

/// A siphon-decided replacement (no REFER, so no NOTIFY) releases the referrer at
/// once. A referrer that has not ACKed its 2xx gets that BYE after its ACK.
#[tokio::test(start_paused = true)]
async fn a_replaced_party_that_has_not_acked_is_sent_its_bye_after_its_ack() {
    let call = Call::bridged();
    call.callee_answers("");
    let relayed = relayed_answer(&call);
    let target_index = add_transfer_target(&call);
    subscribe(&call, true, ReplacementOrigin::SiphonInitiated, false);

    b2bua_complete_terminated_transfer(&call.call_id, target_index, &target_answer(), &call.state);
    let sent = call.wire();
    assert!(
        sent.iter()
            .any(|sent| sent.destination == target() && sent.message.method() == Some(&Method::Ack)),
        "the target is ACKed"
    );
    assert!(
        byes_to(&sent, caller()).is_empty(),
        "no BYE to a replaced party that has not ACKed its 2xx (RFC 3261 §15)"
    );

    assert_the_ack_releases_one_bye(&call, &relayed);
}

/// A REFER's referrer gets the terminating NOTIFY first and its BYE once that is
/// answered. When the referrer has not ACKed its 2xx either, the answered NOTIFY
/// is not enough: the BYE still waits for the ACK.
#[tokio::test(start_paused = true)]
async fn a_referrer_bye_released_by_its_notify_still_waits_for_the_ack() {
    let call = Call::bridged();
    call.callee_answers("");
    let relayed = relayed_answer(&call);
    let target_index = add_transfer_target(&call);
    subscribe(&call, true, ReplacementOrigin::Refer, false);

    b2bua_complete_terminated_transfer(&call.call_id, target_index, &target_answer(), &call.state);
    let sent = call.wire();
    let notify = sent
        .iter()
        .find(|sent| sent.destination == caller() && sent.message.method() == Some(&Method::Notify))
        .expect("the referrer is sent the terminating NOTIFY")
        .message
        .clone();
    assert!(byes_to(&sent, caller()).is_empty());

    let answered = build_response(&notify, 200, "OK", None, &[]);
    release_deferred_referrer_bye(&answered, 200, &call.state);
    assert!(
        byes_to(&call.wire(), caller()).is_empty(),
        "the NOTIFY is answered, and the BYE still waits for the ACK"
    );
    assert_eq!(call.state.deferred_referrer_bye.len(), 0);

    assert_the_ack_releases_one_bye(&call, &relayed);
}

/// A transfer whose target refuses after the referrer already left releases the
/// surviving party. A survivor that has not ACKed its 2xx gets that BYE after its
/// ACK.
#[tokio::test(start_paused = true)]
async fn the_survivor_of_a_failed_transfer_is_sent_its_bye_after_its_ack() {
    let call = Call::bridged();
    call.callee_answers("");
    let relayed = relayed_answer(&call);
    let target_index = add_transfer_target(&call);
    subscribe(&call, false, ReplacementOrigin::Refer, true);

    b2bua_fail_terminated_transfer(&call.call_id, target_index, 486, &call.state);
    let sent = call.wire();
    assert!(
        byes_to(&sent, caller()).is_empty(),
        "no BYE to a survivor that has not ACKed its 2xx (RFC 3261 §15)"
    );
    assert!(
        call.state.call_actors.get_call(&call.call_id).is_none(),
        "the call is released"
    );

    assert_the_ack_releases_one_bye(&call, &relayed);
}

/// The new party of a `Replaces` takeover, arriving as a call of its own.
fn new_party_call(call: &Call) -> (String, SipMessage, InboundMessage) {
    let mut leg = Leg::new_a_leg(
        NEW_PARTY_CALL_ID.to_string(),
        "new-party-tag".to_string(),
        "z9hG4bK-new-party".to_string(),
        LegTransport {
            remote_addr: new_party(),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: None,
        },
    );
    leg.dialog.local_contact = Some("<sip:192.0.2.1:5060;transport=udp>".to_string());
    leg.dialog.remote_contact = Some("sip:15550100030@192.0.2.30:5060".to_string());
    leg.dialog.local_from_uri = Some("<sip:15550100042@siphon.example.com>".to_string());
    leg.dialog.remote_to_uri =
        Some("<sip:15550100030@siphon.example.com>;tag=new-party-tag".to_string());
    let new_call_id = call.state.call_actors.create_call(leg);

    let sdp = concat!(
        "v=0\r\n",
        "o=- 9 9 IN IP4 192.0.2.30\r\n",
        "s=-\r\n",
        "c=IN IP4 192.0.2.30\r\n",
        "t=0 0\r\n",
        "m=audio 36000 RTP/AVP 0\r\n",
    );
    let raw = format!(
        concat!(
            "INVITE sip:15550100042@siphon.example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 192.0.2.30:5060;branch=z9hG4bK-new-party\r\n",
            "Max-Forwards: 70\r\n",
            "From: <sip:15550100030@siphon.example.com>;tag=new-party-tag\r\n",
            "To: <sip:15550100042@siphon.example.com>\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: 1 INVITE\r\n",
            "Contact: <sip:15550100030@192.0.2.30:5060>\r\n",
            "Content-Type: application/sdp\r\n",
            "Content-Length: {length}\r\n",
            "\r\n",
            "{sdp}",
        ),
        call_id = NEW_PARTY_CALL_ID,
        length = sdp.len(),
        sdp = sdp,
    );
    let invite = parse_sip_message_bytes(raw.as_bytes()).expect("the new party's INVITE parses");
    let inbound = InboundMessage {
        connection_id: ConnectionId::default(),
        transport: Transport::Udp,
        local_addr: "192.0.2.1:5060".parse().expect("a literal address"),
        remote_addr: new_party(),
        data: Bytes::from(raw),
    };
    (new_call_id, invite, inbound)
}

/// Each party's last SDP, which a takeover hands to the one that survives it.
fn record_last_sdp(call: &Call) {
    let mut actor = call
        .state
        .call_actors
        .get_call_mut(&call.call_id)
        .expect("the call exists");
    actor.a_leg.last_sdp = Some(b"v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\ns=-\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\nm=audio 40000 RTP/AVP 0\r\n".to_vec());
    for leg in actor.b_legs.iter_mut() {
        leg.last_sdp = Some(b"v=0\r\no=- 1 1 IN IP4 198.51.100.78\r\ns=-\r\nc=IN IP4 198.51.100.78\r\nt=0 0\r\nm=audio 30000 RTP/AVP 0\r\n".to_vec());
    }
}

/// The takeover's 200 to the new party, among `sent`.
fn answer_to_new_party(sent: &[Sent]) -> SipMessage {
    sent.iter()
        .find(|sent| sent.destination == new_party() && sent.message.status_code() == Some(200))
        .expect("siphon answered the new party")
        .message
        .clone()
}

/// The new party ACKs `answer`, the takeover's 200 (RFC 3261 §13.2.2.4), through
/// [`handle_request`].
fn new_party_acks(call: &Call, answer: &SipMessage) {
    let raw = format!(
        concat!(
            "ACK sip:192.0.2.1:5060;transport=udp SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 192.0.2.30:5060;branch=z9hG4bK-new-party-ack\r\n",
            "Max-Forwards: 70\r\n",
            "From: {from}\r\n",
            "To: {to}\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: 1 ACK\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        from = answer.headers.from().expect("the answer has a From"),
        to = answer.headers.to().expect("the answer has a To"),
        call_id = NEW_PARTY_CALL_ID,
    );
    let message = parse_sip_message_bytes(raw.as_bytes()).expect("the new party's ACK parses");
    handle_request(
        InboundMessage {
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: "192.0.2.1:5060".parse().expect("a literal address"),
            remote_addr: new_party(),
            data: Bytes::from(raw),
        },
        message,
        "ACK".to_string(),
        &call.state,
    );
}

/// An INVITE with `Replaces` naming the caller's dialog takes it over, and the
/// caller is released. A caller that has not ACKed its 2xx gets that BYE after its
/// ACK (RFC 3891 §3, RFC 3261 §15). The new party ACKs the 200 siphon answered it
/// with, so nothing of its own stays held.
#[tokio::test(start_paused = true)]
async fn a_caller_replaced_before_it_acks_is_sent_its_bye_after_its_ack() {
    let call = Call::bridged();
    call.callee_answers("");
    let relayed = relayed_answer(&call);
    record_last_sdp(&call);
    let (new_call_id, invite, inbound) = new_party_call(&call);

    b2bua_bridge_inbound_replaces(
        &inbound,
        &invite,
        &new_call_id,
        &crate::b2bua::actor::PendingReplaces {
            replaced_call_id: call.call_id.clone(),
            replaced_on_a_leg: true,
            early_only: false,
        },
        &call.state,
    );
    let sent = call.wire();
    assert!(
        byes_to(&sent, caller()).is_empty(),
        "no BYE to a replaced caller that has not ACKed its 2xx"
    );
    new_party_acks(&call, &answer_to_new_party(&sent));

    assert_the_ack_releases_one_bye(&call, &relayed);
}

/// siphon answers the new party of a takeover itself, so the new party's 2xx
/// waits for an ACK like any other: a teardown before that ACK holds its BYE, and
/// the ACK releases it (RFC 3261 §15).
#[tokio::test(start_paused = true)]
async fn a_new_party_that_has_not_acked_the_takeover_200_has_its_bye_held() {
    let call = Call::bridged();
    call.callee_answers("");
    let relayed = relayed_answer(&call);
    call.caller_acks(&relayed);
    record_last_sdp(&call);
    let (new_call_id, invite, inbound) = new_party_call(&call);

    b2bua_bridge_inbound_replaces(
        &inbound,
        &invite,
        &new_call_id,
        &crate::b2bua::actor::PendingReplaces {
            replaced_call_id: call.call_id.clone(),
            replaced_on_a_leg: true,
            early_only: false,
        },
        &call.state,
    );
    let answer = answer_to_new_party(&call.wire());

    assert!(b2bua_terminate_call_inner(
        &call.call_id,
        Some(NORMAL_CLEARING),
        "b2bua",
        &call.state,
    ));
    assert!(
        byes_to(&call.wire(), new_party()).is_empty(),
        "no BYE to a new party that has not ACKed the takeover's 200"
    );

    new_party_acks(&call, &answer);
    assert_eq!(
        byes_to(&call.wire(), new_party()).len(),
        1,
        "the new party's ACK releases its BYE"
    );
    assert!(nothing_held(&call), "both stores drained");
}

/// A takeover of the callee's dialog releases the callee, which siphon ACKed long
/// ago, and moves the caller into the B-leg slot as the surviving party. The
/// caller has still not ACKed, so a teardown after that holds the caller's BYE:
/// what decides is the dialog, not the slot it sits in.
#[tokio::test(start_paused = true)]
async fn a_caller_moved_to_the_b_leg_slot_by_a_takeover_still_has_its_bye_held() {
    let call = Call::bridged();
    call.callee_answers("");
    let relayed = relayed_answer(&call);
    record_last_sdp(&call);
    let (new_call_id, invite, inbound) = new_party_call(&call);

    b2bua_bridge_inbound_replaces(
        &inbound,
        &invite,
        &new_call_id,
        &crate::b2bua::actor::PendingReplaces {
            replaced_call_id: call.call_id.clone(),
            replaced_on_a_leg: false,
            early_only: false,
        },
        &call.state,
    );
    let sent = call.wire();
    assert_eq!(
        byes_to(&sent, callee()).len(),
        1,
        "the replaced callee is released at once"
    );
    assert!(byes_to(&sent, caller()).is_empty());
    new_party_acks(&call, &answer_to_new_party(&sent));

    assert!(b2bua_terminate_call_inner(
        &call.call_id,
        Some(NORMAL_CLEARING),
        "b2bua",
        &call.state,
    ));
    let sent = call.wire();
    assert_eq!(
        byes_to(&sent, new_party()).len(),
        1,
        "the new party, which ACKed the takeover's 200, is released at once"
    );
    assert!(
        byes_to(&sent, caller()).is_empty(),
        "the caller, now in the B-leg slot, has still not ACKed its 2xx"
    );

    assert_the_ack_releases_one_bye(&call, &relayed);
}
