//! RFC 3261 §15: siphon, the UAS of the caller's dialog, sends the caller no BYE
//! until the caller has ACKed the 2xx siphon sent it, or 64*T1 has passed.
//!
//! A call can end inside that window: the callee hangs up the moment it answers,
//! or a timer or a script ends the call. The callee's BYE is answered at once and
//! the rest of the call is torn down, but the caller's BYE waits. The 2xx keeps
//! being retransmitted to the caller (§13.3.1.4), the caller's ACK sends the BYE
//! right after it, and a caller that never ACKs is sent it by the 64*T1 sweep,
//! once.
//!
//! The harness is the one `b_leg_2xx_ack_tests` and `unacked_answer_tests` share.
//! Tokio's clock is paused where a test steps it.

use super::b_leg_2xx_ack_tests::{callee, caller, caller_hangs_up, request_line, Call, Sent};
use super::*;
use std::time::Duration;

const NORMAL_CLEARING: &str = "Q.850;cause=16;text=\"Normal Clearing\"";

/// A script with a B2BUA handler, so an in-dialog BYE takes the B2BUA path through
/// `handle_request`.
const B2BUA_SCRIPT: &str = concat!(
    "from siphon import b2bua\n",
    "\n",
    "@b2bua.on_invite\n",
    "def invite(call):\n",
    "    pass\n",
);

fn byes_to(sent: &[Sent], destination: SocketAddr) -> Vec<&Sent> {
    sent.iter()
        .filter(|sent| {
            sent.destination == destination && sent.message.method() == Some(&Method::Bye)
        })
        .collect()
}

/// How many 200s for a `method` request went to `destination`.
fn oks_to(sent: &[Sent], destination: SocketAddr, method: &str) -> usize {
    sent.iter()
        .filter(|sent| {
            sent.destination == destination
                && sent.message.status_code() == Some(200)
                && sent
                    .message
                    .headers
                    .cseq()
                    .is_some_and(|cseq| cseq.ends_with(method))
        })
        .count()
}

fn relayed_answer(call: &Call) -> SipMessage {
    call.wire()
        .into_iter()
        .find(|sent| sent.destination == caller() && sent.message.status_code() == Some(200))
        .expect("the answer was relayed to the caller")
        .message
}

fn reason(message: &SipMessage) -> Option<&str> {
    message.headers.get("Reason").map(String::as_str)
}

fn call_is_up(call: &Call) -> bool {
    call.state.call_actors.get_call(&call.call_id).is_some()
}

/// Both stores drained: no answer waiting for an ACK and no BYE held for one.
fn nothing_held(call: &Call) -> bool {
    call.state.held_a_leg_byes.is_empty() && call.state.uas_2xx_retransmits.is_empty()
}

/// A BYE in the dialog the 2xx created (RFC 3261 §12.2.1.1): the caller's remote
/// target, siphon's tag from that 2xx, the caller's tag.
fn assert_in_the_callers_dialog(bye: &SipMessage, relayed: &SipMessage) {
    assert_eq!(
        request_line(bye),
        "BYE sip:15550100001@192.0.2.10:5060 SIP/2.0"
    );
    let siphon_tag = relayed
        .headers
        .to()
        .and_then(|to| to.split(";tag=").nth(1).map(str::to_string))
        .expect("the relayed 2xx carries siphon's tag");
    assert!(bye
        .headers
        .from()
        .is_some_and(|from| from.ends_with(&format!(";tag={siphon_tag}"))));
    assert!(bye
        .headers
        .to()
        .is_some_and(|to| to.ends_with(";tag=caller-tag")));
}

/// The failure this exists for. The callee hangs up right after answering, before
/// the caller's ACK. Its BYE is answered and the call torn down at once; the caller
/// keeps receiving the 2xx, and its BYE follows its ACK.
#[tokio::test(start_paused = true)]
async fn a_callee_bye_before_the_caller_acks_is_answered_at_once_and_the_caller_bye_follows_its_ack(
) {
    let call = Call::bridged();
    call.callee_answers("");
    let relayed = relayed_answer(&call);

    call.callee_hangs_up();
    let sent = call.wire();
    assert_eq!(
        oks_to(&sent, callee(), "BYE"),
        1,
        "the callee's BYE is answered at once"
    );
    assert!(
        byes_to(&sent, caller()).is_empty(),
        "no BYE to a caller that has not ACKed its 2xx (RFC 3261 §15)"
    );
    assert!(!call_is_up(&call), "the rest of the call is torn down");

    tokio::time::sleep(Duration::from_millis(600)).await;
    sweep_unacked_uas_2xx(&call.state);
    let waiting = call.wire();
    assert!(
        oks_to(&waiting, caller(), "INVITE") > 0,
        "the 2xx is still retransmitted to the caller (RFC 3261 §13.3.1.4)"
    );
    assert!(byes_to(&waiting, caller()).is_empty());

    call.caller_acks(&relayed);
    let sent = call.wire();
    let byes = byes_to(&sent, caller());
    assert_eq!(byes.len(), 1, "the caller's ACK releases its BYE");
    assert_in_the_callers_dialog(&byes[0].message, &relayed);
    assert!(byes_to(&sent, callee()).is_empty());
    assert!(nothing_held(&call));

    // Nothing after that: no second BYE, no more copies of the 2xx, and a
    // retransmitted ACK draws nothing.
    tokio::time::sleep(Duration::from_secs(40)).await;
    sweep_unacked_uas_2xx(&call.state);
    call.caller_acks(&relayed);
    let after = call.wire();
    assert!(after.is_empty(), "nothing is sent once the BYE went out");
}

/// A caller that never ACKs is sent its held BYE by the 64*T1 sweep, and only that:
/// the callee, which hung up, is sent nothing more.
#[tokio::test(start_paused = true)]
async fn a_caller_that_never_acks_is_sent_its_held_bye_at_64_t1_and_nothing_else() {
    let call = Call::bridged();
    call.callee_answers("");
    let relayed = relayed_answer(&call);
    call.callee_hangs_up();
    call.wire();

    tokio::time::sleep(Duration::from_millis(31_900)).await;
    sweep_unacked_uas_2xx(&call.state);
    let waiting = call.wire();
    assert!(
        byes_to(&waiting, caller()).is_empty(),
        "no BYE inside 64*T1"
    );
    assert!(oks_to(&waiting, caller(), "INVITE") > 0);

    tokio::time::sleep(Duration::from_millis(200)).await;
    sweep_unacked_uas_2xx(&call.state);
    let sent = call.wire();
    let byes = byes_to(&sent, caller());
    assert_eq!(byes.len(), 1, "the held BYE, once");
    assert_in_the_callers_dialog(&byes[0].message, &relayed);
    assert!(
        byes_to(&sent, callee()).is_empty(),
        "the callee hung up and is sent no BYE"
    );
    assert!(nothing_held(&call));

    tokio::time::sleep(Duration::from_secs(10)).await;
    sweep_unacked_uas_2xx(&call.state);
    assert!(
        call.wire().is_empty(),
        "no second BYE and no more 2xx copies"
    );
}

/// Every teardown siphon starts itself holds the caller's BYE the same way, since
/// each ends the call through `b2bua_terminate_call_inner`: a script's
/// `b2bua.terminate`, a control-plane or admin hangup and an Ro credit cut (all
/// `b2bua_terminate_call`), a bridge peer's hangup, the session timer and the
/// maximum call duration. The callee is sent its BYE at once, the caller its own
/// right after its ACK, with the same Reason.
#[tokio::test(start_paused = true)]
async fn a_framework_teardown_before_the_caller_acks_holds_only_the_caller_bye() {
    type Teardown = fn(&str, &DispatcherState);
    let teardowns: [(&str, Teardown); 3] = [
        (NORMAL_CLEARING, |call_id, state| {
            b2bua_terminate_call_inner(call_id, Some(NORMAL_CLEARING), "b2bua", state);
        }),
        (
            "Q.850;cause=102;text=\"Session timer expired\"",
            b2bua_session_timer_terminate,
        ),
        (
            "Q.850;cause=102;text=\"Maximum call duration exceeded\"",
            b2bua_max_duration_terminate,
        ),
    ];
    for (expected_reason, teardown) in teardowns {
        let call = Call::bridged();
        call.callee_answers("");
        let relayed = relayed_answer(&call);

        teardown(&call.call_id, &call.state);
        let sent = call.wire();
        let to_callee = byes_to(&sent, callee());
        assert_eq!(
            to_callee.len(),
            1,
            "{expected_reason}: the callee is sent its BYE at once"
        );
        assert_eq!(reason(&to_callee[0].message), Some(expected_reason));
        assert!(
            byes_to(&sent, caller()).is_empty(),
            "{expected_reason}: the caller's BYE waits for its ACK"
        );
        assert!(!call_is_up(&call));

        call.caller_acks(&relayed);
        let sent = call.wire();
        let to_caller = byes_to(&sent, caller());
        assert_eq!(
            to_caller.len(),
            1,
            "{expected_reason}: the caller's BYE follows its ACK"
        );
        assert_in_the_callers_dialog(&to_caller[0].message, &relayed);
        assert_eq!(reason(&to_caller[0].message), Some(expected_reason));
        assert!(byes_to(&sent, callee()).is_empty());
        assert!(
            nothing_held(&call),
            "{expected_reason}: both stores drained"
        );
    }
}

/// A teardown the 64*T1 sweep runs itself is not held: the 2xx it ends the call
/// for is the one that went unACKed, so both legs get their BYE together. Covered
/// in `unacked_answer_tests`; here the hold is shown not to delay it.
#[tokio::test(start_paused = true)]
async fn the_64_t1_teardown_itself_is_never_held() {
    let call = Call::bridged();
    call.callee_answers("");
    call.wire();

    tokio::time::sleep(Duration::from_secs(33)).await;
    sweep_unacked_uas_2xx(&call.state);
    let sent = call.wire();
    assert_eq!(byes_to(&sent, caller()).len(), 1);
    assert_eq!(byes_to(&sent, callee()).len(), 1);
    assert!(nothing_held(&call));
}

/// A caller that sends a BYE while its own is held has ended the dialog itself: its
/// BYE is answered 200, not 481, the 2xx stops being retransmitted, and the held
/// BYE is dropped rather than sent later for a dialog that is gone.
#[tokio::test(flavor = "multi_thread")]
async fn a_caller_bye_while_its_bye_is_held_is_answered_and_the_held_bye_is_dropped() {
    let call = Call::bridged_with_script(B2BUA_SCRIPT);
    call.callee_answers("");
    let relayed = relayed_answer(&call);
    call.callee_hangs_up();
    call.wire();

    caller_hangs_up(&call.state, &relayed);
    let sent = call.wire();
    assert_eq!(
        oks_to(&sent, caller(), "BYE"),
        1,
        "the caller's BYE is answered 200"
    );
    assert!(byes_to(&sent, caller()).is_empty());
    assert!(nothing_held(&call));

    // T1 is 500 ms: a 2xx still being retransmitted would have been sent again.
    tokio::time::sleep(Duration::from_millis(1_200)).await;
    let after = call.wire();
    assert_eq!(
        oks_to(&after, caller(), "INVITE"),
        0,
        "the 2xx is no longer retransmitted"
    );
    assert!(byes_to(&after, caller()).is_empty());
}
