//! A call siphon answered itself and never dialled (a bot hand-over, a
//! conference factory seat, `answer_local`, a control-plane `answer`) has no
//! B-leg: `b_legs` is empty and `winner` is unset. Its in-dialog requests are
//! answered by siphon, and a BYE from the caller is owed its 200 and nothing
//! else, so none of them may log the "no winning B-leg" warning that is meant
//! for a call whose B-legs exist but did not win.
use super::sdp_strip_tests::{
    answered_call, caller_call, in_dialog_request, inbound_from, response_to, ringing_call, CALLER,
};
use super::session_timer_tests::wire;
use super::test_dispatcher::{test_dispatcher, TestDispatcher};
use super::*;

const NO_WINNER: &str = "no winning B-leg";

/// siphon answered the caller itself: no B-leg, the A-leg answered and ACKed.
fn locally_answered_call(dispatcher: &TestDispatcher) -> String {
    let call_id = caller_call(dispatcher);
    if let Some(mut call) = dispatcher.state.call_actors.get_call_mut(&call_id) {
        call.a_leg.initial_acked = true;
        call.a_leg.dialog.remote_tag = Some("caller-tag".to_string());
    }
    dispatcher
        .state
        .call_actors
        .set_state(&call_id, CallState::Answered);
    call_id
}

fn caller_sends(dispatcher: &TestDispatcher, method: &str) {
    let message = in_dialog_request(method, true, "");
    let inbound = inbound_from(CALLER);
    tokio::task::block_in_place(|| match method {
        "BYE" => handle_b2bua_bye(inbound, message, &dispatcher.state),
        "INVITE" => handle_b2bua_reinvite(inbound, message, &dispatcher.state),
        _ => handle_b2bua_update(inbound, message, &dispatcher.state),
    });
}

/// The caller hanging up a call siphon answered itself is answered `200` and
/// is not a warning.
#[tokio::test(flavor = "multi_thread")]
async fn a_bye_on_a_call_siphon_answered_itself_is_not_a_warning() {
    let (log, _guard) = super::li_session_tests::capture_log();
    let dispatcher = test_dispatcher();
    let call_id = locally_answered_call(&dispatcher);
    {
        let call = dispatcher
            .state
            .call_actors
            .get_call(&call_id)
            .expect("call");
        assert!(call.b_legs.is_empty() && call.winner.is_none());
    }
    caller_sends(&dispatcher, "BYE");
    response_to(&wire(&dispatcher), CALLER, 200);
    assert!(!log.rendered().contains(NO_WINNER), "{}", log.rendered());
    assert!(
        log.rendered().contains("answered by siphon itself"),
        "{}",
        log.rendered()
    );
}

/// A call with B-legs, none of which won, has nobody to hang up on and is
/// inconsistent: still a warning.
#[tokio::test(flavor = "multi_thread")]
async fn a_bye_on_a_call_with_b_legs_and_no_winner_still_warns() {
    let (log, _guard) = super::li_session_tests::capture_log();
    let dispatcher = test_dispatcher();
    let call_id = ringing_call(&dispatcher);
    if let Some(mut call) = dispatcher.state.call_actors.get_call_mut(&call_id) {
        call.a_leg.dialog.remote_tag = Some("caller-tag".to_string());
    }
    caller_sends(&dispatcher, "BYE");
    response_to(&wire(&dispatcher), CALLER, 200);
    assert!(log.rendered().contains(NO_WINNER), "{}", log.rendered());
}

/// A winner index that names no B-leg is inconsistent too.
#[tokio::test(flavor = "multi_thread")]
async fn a_bye_on_a_call_whose_winner_names_no_b_leg_still_warns() {
    let (log, _guard) = super::li_session_tests::capture_log();
    let dispatcher = test_dispatcher();
    let call_id = answered_call(&dispatcher);
    if let Some(mut call) = dispatcher.state.call_actors.get_call_mut(&call_id) {
        call.winner = Some(7);
        call.a_leg.dialog.remote_tag = Some("caller-tag".to_string());
    }
    caller_sends(&dispatcher, "BYE");
    response_to(&wire(&dispatcher), CALLER, 200);
    assert!(log.rendered().contains(NO_WINNER), "{}", log.rendered());
}

/// A hold (re-INVITE) and an UPDATE from the caller of a call siphon answered
/// itself are answered `200` by siphon, with no warning: the sibling sites that
/// log the same message are unreachable from such a call.
#[tokio::test(flavor = "multi_thread")]
async fn a_refresh_on_a_call_siphon_answered_itself_is_answered_without_a_warning() {
    for method in ["INVITE", "UPDATE"] {
        let (log, _guard) = super::li_session_tests::capture_log();
        let dispatcher = test_dispatcher();
        locally_answered_call(&dispatcher);
        caller_sends(&dispatcher, method);
        response_to(&wire(&dispatcher), CALLER, 200);
        assert!(
            super::li_session_tests::own_warnings(&log).is_empty(),
            "{method}: {}",
            log.rendered()
        );
    }
}

/// The same for a call answered first and handed to a bot (`handover(app,
/// answer=True)`): the control owner is recorded, no B-leg is ever added.
#[tokio::test(flavor = "multi_thread")]
async fn a_bye_on_a_call_handed_to_a_bot_is_not_a_warning() {
    let (log, _guard) = super::li_session_tests::capture_log();
    let dispatcher = test_dispatcher();
    let call_id = locally_answered_call(&dispatcher);
    dispatcher
        .state
        .call_actors
        .set_control_owner(&call_id, "voice_ai", Some("hangup"));
    caller_sends(&dispatcher, "BYE");
    response_to(&wire(&dispatcher), CALLER, 200);
    assert!(!log.rendered().contains(NO_WINNER), "{}", log.rendered());
}
