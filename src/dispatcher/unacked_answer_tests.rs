//! A 2xx siphon sends the caller is retransmitted until the caller ACKs it, and
//! a caller that never does has its call ended (RFC 3261 §13.3.1.4): after 64*T1
//! with no ACK the dialog is confirmed and the session is terminated with a BYE,
//! to both legs, through the teardown every framework-ended call takes.
//!
//! Tokio's clock is paused, so the retransmit schedule and its deadline move only
//! when a test sleeps. [`sweep_unacked_uas_2xx`] is what the dispatcher's 100 ms
//! timer tick runs; a test calls it directly after stepping the clock.

use super::b_leg_2xx_ack_tests::{
    callee, caller, caller_acks, caller_invite, request_line, Call, Sent,
};
use super::*;
use std::time::Duration;

/// What a BYE for a 2xx nobody ACKed carries.
const NO_ACK_REASON: &str = "Q.850;cause=102;text=\"No ACK received\"";

fn byes(sent: &[Sent]) -> Vec<&Sent> {
    sent.iter()
        .filter(|sent| sent.message.method() == Some(&Method::Bye))
        .collect()
}

/// How many copies of a 2xx went to the caller.
fn answers_to_caller(sent: &[Sent]) -> usize {
    sent.iter()
        .filter(|sent| sent.destination == caller() && sent.message.status_code() == Some(200))
        .count()
}

fn relayed_answer(sent: Vec<Sent>) -> SipMessage {
    sent.into_iter()
        .find(|sent| sent.destination == caller() && sent.message.status_code() == Some(200))
        .expect("the answer was relayed to the caller")
        .message
}

fn call_is_up(call: &Call) -> bool {
    call.state.call_actors.get_call(&call.call_id).is_some()
}

/// The failure this exists for. The callee answers, the caller never ACKs the 2xx
/// siphon relays, and 64*T1 later both legs are sent a BYE and the call is gone.
#[tokio::test(start_paused = true)]
async fn a_caller_that_never_acks_is_sent_a_bye_after_64_t1_and_so_is_the_callee() {
    let call = Call::bridged();
    call.callee_answers("");
    let relayed = relayed_answer(call.wire());

    // Just inside 64*T1: the 2xx is still being retransmitted and nothing ended.
    tokio::time::sleep(Duration::from_millis(31_900)).await;
    sweep_unacked_uas_2xx(&call.state);
    let waiting = call.wire();
    assert!(
        answers_to_caller(&waiting) > 0,
        "the 2xx is retransmitted while it waits for its ACK (RFC 3261 §13.3.1.4)"
    );
    assert!(byes(&waiting).is_empty(), "no BYE inside 64*T1");
    assert!(call_is_up(&call));

    tokio::time::sleep(Duration::from_millis(200)).await;
    sweep_unacked_uas_2xx(&call.state);
    let sent = call.wire();
    let ended = byes(&sent);
    let mut destinations: Vec<SocketAddr> = ended.iter().map(|bye| bye.destination).collect();
    destinations.sort();
    let mut both = vec![caller(), callee()];
    both.sort();
    assert_eq!(destinations, both, "one BYE to each leg");
    for bye in &ended {
        assert_eq!(
            bye.message.headers.get("Reason").map(String::as_str),
            Some(NO_ACK_REASON)
        );
    }

    // The caller's BYE is in the dialog the unACKed 2xx created (RFC 3261
    // §12.2.1.1): its remote target, siphon's tag from that 2xx, the caller's tag.
    let to_caller = ended
        .iter()
        .find(|bye| bye.destination == caller())
        .expect("a BYE to the caller");
    assert_eq!(
        request_line(&to_caller.message),
        "BYE sip:15550100001@192.0.2.10:5060 SIP/2.0"
    );
    let siphon_tag = relayed
        .headers
        .to()
        .and_then(|to| to.split(";tag=").nth(1).map(str::to_string))
        .expect("the relayed 2xx carries siphon's tag");
    assert!(to_caller
        .message
        .headers
        .from()
        .is_some_and(|from| from.ends_with(&format!(";tag={siphon_tag}"))));
    assert!(to_caller
        .message
        .headers
        .to()
        .is_some_and(|to| to.ends_with(";tag=caller-tag")));

    assert!(!call_is_up(&call), "the call is torn down");
    assert!(
        call.state.uas_2xx_retransmits.is_empty(),
        "the retransmit entry is gone"
    );

    // Nothing after that: no second BYE, and no more copies of the 2xx.
    tokio::time::sleep(Duration::from_secs(10)).await;
    sweep_unacked_uas_2xx(&call.state);
    let after = call.wire();
    assert!(byes(&after).is_empty());
    assert_eq!(answers_to_caller(&after), 0);
}

/// An ACK that arrives inside 64*T1 stops the retransmissions and the call stays
/// up.
#[tokio::test(start_paused = true)]
async fn an_ack_just_before_64_t1_keeps_the_call_up() {
    let call = Call::bridged();
    call.callee_answers("");
    let relayed = relayed_answer(call.wire());

    tokio::time::sleep(Duration::from_millis(31_900)).await;
    call.caller_acks(&relayed);
    tokio::time::sleep(Duration::from_secs(1)).await;
    sweep_unacked_uas_2xx(&call.state);

    let sent = call.wire();
    assert!(byes(&sent).is_empty(), "an ACKed 2xx ends nothing");
    assert!(call_is_up(&call));
    assert!(call.state.uas_2xx_retransmits.is_empty());

    tokio::time::sleep(Duration::from_secs(10)).await;
    sweep_unacked_uas_2xx(&call.state);
    let after = call.wire();
    assert!(byes(&after).is_empty());
    assert_eq!(
        answers_to_caller(&after),
        0,
        "retransmission stopped on the ACK"
    );
}

/// The race. The deadline has passed but the sweep has not acted on it yet when
/// the ACK is processed: the ACK wins, and no BYE follows it.
#[tokio::test(start_paused = true)]
async fn an_ack_processed_after_the_deadline_but_before_the_sweep_wins() {
    let call = Call::bridged();
    call.callee_answers("");
    let relayed = relayed_answer(call.wire());

    tokio::time::sleep(Duration::from_secs(33)).await;
    call.caller_acks(&relayed);
    sweep_unacked_uas_2xx(&call.state);

    assert!(
        byes(&call.wire()).is_empty(),
        "no BYE once the ACK is processed"
    );
    assert!(call_is_up(&call));
    assert!(call.state.uas_2xx_retransmits.is_empty());
}

/// A call torn down some other way while its 2xx waits for an ACK is not sent a
/// second BYE at 64*T1. The teardown BYEs the callee and holds the caller's BYE for
/// the ACK (RFC 3261 §15); at 64*T1 the sweep sends that one BYE, and the 2xx stops
/// being retransmitted.
#[tokio::test(start_paused = true)]
async fn a_call_that_already_ended_gets_no_second_bye() {
    let call = Call::bridged();
    call.callee_answers("");
    call.wire();

    assert!(b2bua_terminate_call_inner(
        &call.call_id,
        Some("Q.850;cause=16;text=\"Normal Clearing\""),
        "b2bua",
        &call.state,
    ));
    let ended = call.wire();
    let destinations: Vec<SocketAddr> = byes(&ended).iter().map(|bye| bye.destination).collect();
    assert_eq!(
        destinations,
        vec![callee()],
        "the teardown BYEs the callee; the caller's BYE waits for its ACK"
    );

    tokio::time::sleep(Duration::from_secs(33)).await;
    sweep_unacked_uas_2xx(&call.state);
    let at_deadline = call.wire();
    let destinations: Vec<SocketAddr> = byes(&at_deadline)
        .iter()
        .map(|bye| bye.destination)
        .collect();
    assert_eq!(
        destinations,
        vec![caller()],
        "the held BYE, and no second one to either leg"
    );

    tokio::time::sleep(Duration::from_secs(10)).await;
    sweep_unacked_uas_2xx(&call.state);
    let after = call.wire();
    assert!(byes(&after).is_empty(), "no second BYE");
    assert_eq!(
        answers_to_caller(&after),
        0,
        "a 2xx for a call that ended is not retransmitted"
    );
    assert!(call.state.uas_2xx_retransmits.is_empty());
    assert!(call.state.held_byes.is_empty());
}

/// A 2xx siphon answered itself (`call.answer()`, the control plane's answer)
/// is armed by the same helper and bound by the same deadline. The call has one
/// leg, so the BYE goes to the caller alone.
#[tokio::test(start_paused = true)]
async fn a_2xx_siphon_answered_itself_is_bound_by_the_same_deadline() {
    let (state, udp, call_id) = Call::caller_alone();
    let local_tag = state
        .call_actors
        .get_call(&call_id)
        .map(|call| call.a_leg.dialog.local_tag.clone())
        .expect("the call exists");
    let invite = caller_invite();
    let to = invite.headers.to().cloned().expect("a To");
    let answer = build_response(
        &invite,
        200,
        "OK",
        None,
        &[(
            crate::script::api::request::ReplyHeaderOp::Replace,
            "To".to_string(),
            format!("{to};tag={local_tag}"),
        )],
    );
    arm_b2bua_2xx_retransmit(
        &call_id,
        answer,
        Transport::Udp,
        caller(),
        ConnectionId::default(),
        None,
        &state,
    );
    state.call_actors.set_state(&call_id, CallState::Answered);

    tokio::time::sleep(Duration::from_secs(33)).await;
    sweep_unacked_uas_2xx(&state);
    let sent = super::b_leg_2xx_ack_tests::drain(&udp);
    let byes = byes(&sent);
    assert_eq!(byes.len(), 1, "one BYE, to the only leg");
    assert_eq!(byes[0].destination, caller());
    assert_eq!(
        byes[0].message.headers.get("Reason").map(String::as_str),
        Some(NO_ACK_REASON)
    );
    assert!(state.call_actors.get_call(&call_id).is_none());
    assert!(state.uas_2xx_retransmits.is_empty());

    // The caller's late ACK for it finds nothing and draws nothing.
    let relayed = sent
        .into_iter()
        .find(|sent| sent.message.status_code() == Some(200))
        .expect("the 2xx was retransmitted")
        .message;
    caller_acks(&state, &relayed);
    assert!(super::b_leg_2xx_ack_tests::drain(&udp).is_empty());
}

/// A 2xx that carried the offer, because the INVITE went out without one, has its
/// ACK held for the caller's answer, and a caller that never ACKs never answers. At
/// 64*T1 the callee is still owed that ACK: it goes out with every stream rejected
/// (RFC 3261 §13.2.2.4), right before the BYE both legs get (§13.3.1.4, §15).
#[tokio::test(start_paused = true)]
async fn a_held_delayed_offer_ack_goes_out_rejecting_the_offer_before_the_64_t1_bye() {
    let call = Call::bridged_without_an_offer();
    call.callee_answers("");
    assert!(
        call.wire()
            .iter()
            .all(|sent| sent.message.method() != Some(&Method::Ack)),
        "the callee's ACK waits for an answer the caller never sends"
    );

    tokio::time::sleep(Duration::from_secs(33)).await;
    sweep_unacked_uas_2xx(&call.state);
    let sent = call.wire();
    let to_callee: Vec<&Sent> = sent
        .iter()
        .filter(|sent| sent.destination == callee())
        .collect();
    let ack_at = to_callee
        .iter()
        .position(|sent| sent.message.method() == Some(&Method::Ack))
        .expect("the callee is sent the ACK its 2xx is owed");
    let bye_at = to_callee
        .iter()
        .position(|sent| sent.message.method() == Some(&Method::Bye))
        .expect("the callee is sent a BYE");
    assert_eq!(bye_at, ack_at + 1, "the ACK goes out right before the BYE");
    let ack = &to_callee[ack_at].message;
    assert_eq!(
        ack.headers.get("Content-Type").map(String::as_str),
        Some("application/sdp")
    );
    let answer = String::from_utf8(ack.body.clone()).expect("an SDP body is UTF-8");
    assert!(
        answer.contains("m=audio 0 RTP/AVP 0\r\n"),
        "every stream rejected:\n{answer}"
    );
    assert_eq!(
        to_callee[bye_at]
            .message
            .headers
            .get("Reason")
            .map(String::as_str),
        Some(NO_ACK_REASON)
    );
    assert!(
        byes(&sent).iter().any(|bye| bye.destination == caller()),
        "the caller is sent a BYE too"
    );
    assert!(!call_is_up(&call));
    assert!(call.state.uas_2xx_retransmits.is_empty());
}
