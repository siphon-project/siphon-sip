//! RFC 3261 §9.1 on every INVITE siphon sends as a UAC: a CANCEL goes out only
//! once the INVITE has drawn a provisional response, and never after its final.
//!
//! Each test gives up on an INVITE the far end has not answered at all and
//! reads what siphon puts on the wire from then on: nothing but the INVITE's
//! own retransmissions, until the far end's first response decides the rest.
//! A provisional draws the CANCEL, a 2xx an ACK and a BYE, any other final an
//! ACK alone, and silence up to Timer B nothing whatever.
//!
//! Here: the branches of a fork that lost to the one that answered, which is
//! also how a connecting `dial`, an LCR failover, `drop`, `terminate` and a
//! leg replacement give up on theirs. The same for a call siphon placed itself
//! is in [`super::originated_cancel_awaits_provisional_tests`], and for a
//! caller's own CANCEL in [`super::relayed_cancel_awaits_provisional_tests`].

use super::lcr_ring_timeout_tests::{Sequence, CALLER, FIRST_CARRIER, SECOND_CARRIER};
use super::originate_test_harness::{
    drain, phone_response, phone_sends, requests_to, socket, Sent,
};
use super::test_dispatcher::TestDispatcher;
use super::*;

/// The Via branch a request rode.
pub(super) fn branch_of(message: &SipMessage) -> String {
    message
        .headers
        .get("Via")
        .and_then(|raw| Via::parse_multi(raw).ok())
        .and_then(|vias| vias.first().and_then(|via| via.branch.clone()))
        .expect("a Via branch")
}

/// Every frame siphon sends, retransmissions included, until `done` holds.
///
/// The retransmit schedule runs off the dispatcher's timer tick, which no test
/// dispatcher starts, so the sweep is driven here until the frame waited for
/// shows up or the deadline passes.
pub(super) async fn wire_until(
    dispatcher: &TestDispatcher,
    done: impl Fn(&[Sent]) -> bool,
) -> Vec<Sent> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut sent = Vec::new();
    loop {
        super::timers::sweep_b2bua_retransmits(&dispatcher.state);
        sent.extend(drain(&dispatcher.udp));
        if done(&sent) || tokio::time::Instant::now() >= deadline {
            return sent;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

/// Wait for the INVITE on `branch` to be retransmitted to `phone`, and return
/// everything sent meanwhile.
pub(super) async fn until_invite_retransmitted(
    dispatcher: &TestDispatcher,
    phone: &str,
    branch: &str,
) -> Vec<Sent> {
    let sent = wire_until(dispatcher, |sent| {
        requests_to(sent, socket(phone), Method::Invite)
            .iter()
            .any(|frame| branch_of(&frame.message) == branch)
    })
    .await;
    assert!(
        requests_to(&sent, socket(phone), Method::Invite)
            .iter()
            .any(|frame| branch_of(&frame.message) == branch),
        "the unanswered INVITE to {phone} keeps retransmitting (RFC 3261 §17.1.1.2)"
    );
    sent
}

/// The far end's response to `request` (the INVITE, or the CANCEL sharing its
/// branch), from `phone`.
pub(super) fn phone_answers(
    state: &DispatcherState,
    phone: &str,
    request: &SipMessage,
    status_code: u16,
    reason: &str,
    body: Option<&str>,
) {
    phone_sends(
        state,
        socket(phone),
        &phone_response(
            request,
            status_code,
            reason,
            "late-tag",
            &format!("sip:late@{phone}"),
            body,
        ),
    );
}

/// Assert siphon sent `phone` no CANCEL among `sent`.
pub(super) fn assert_no_cancel(sent: &[Sent], phone: &str) {
    assert!(
        requests_to(sent, socket(phone), Method::Cancel).is_empty(),
        "no CANCEL for an INVITE that has drawn no provisional (RFC 3261 §9.1)"
    );
}

/// The one CANCEL among `sent` to `phone`, checked against the INVITE it
/// cancels: same Via branch, same CSeq number (RFC 3261 §9.1).
pub(super) fn the_cancel(sent: &[Sent], phone: &str, invite: &SipMessage) -> SipMessage {
    let cancels = requests_to(sent, socket(phone), Method::Cancel);
    assert_eq!(cancels.len(), 1, "one CANCEL to {phone}");
    let cancel = cancels[0].message.clone();
    assert_eq!(branch_of(&cancel), branch_of(invite));
    let number = |message: &SipMessage| {
        message
            .headers
            .cseq()
            .and_then(|cseq| cseq.split_whitespace().next().map(str::to_string))
    };
    assert_eq!(number(&cancel), number(invite));
    cancel
}

/// The INVITE among `sent` to `address`.
pub(super) fn invite_among(sent: &[Sent], address: &str) -> SipMessage {
    let invites = requests_to(sent, socket(address), Method::Invite);
    assert_eq!(invites.len(), 1, "one INVITE to {address}");
    invites[0].message.clone()
}

/// The branch siphon gave up on has had its response or timed out, and nothing
/// of it is left once its expiry has fired: no record, and no schedule.
pub(super) fn assert_branch_released(state: &DispatcherState, branch: &str) {
    assert_eq!(
        state.call_actors.deferred_cancel_count(),
        0,
        "no CANCEL is still owed"
    );
    state.call_actors.expire_cancelled_branch(
        branch,
        tokio::time::Instant::now() + crate::b2bua::actor::CANCELLED_BRANCH_LIFETIME,
    );
    assert!(!state.call_actors.is_cancelled_branch(branch));
    assert_eq!(
        state.b2bua_retransmits.disarm_branch(branch),
        0,
        "nothing was left retransmitting on the branch"
    );
}

/// A parallel fork whose first branch answered while the second had sent
/// nothing. Returns the fork and the second branch's INVITE.
fn fork_won_beside_a_silent_branch() -> (Sequence, SipMessage) {
    let sequence = Sequence::start_fork(&[FIRST_CARRIER, SECOND_CARRIER]);
    let state = &sequence.dispatcher.state;
    let sent = drain(&sequence.dispatcher.udp);
    let (winner, silent) = (
        invite_among(&sent, FIRST_CARRIER),
        invite_among(&sent, SECOND_CARRIER),
    );
    phone_answers(state, FIRST_CARRIER, &winner, 200, "OK", None);
    let sent = drain(&sequence.dispatcher.udp);
    assert_eq!(
        requests_to(&sent, socket(FIRST_CARRIER), Method::Ack).len(),
        1,
        "the winner is ACKed"
    );
    assert!(
        sent.iter().any(|frame| {
            frame.destination == socket(CALLER) && frame.message.status_code() == Some(200)
        }),
        "the caller is answered at once, whatever the other branch does"
    );
    assert_no_cancel(&sent, SECOND_CARRIER);
    assert_eq!(state.call_actors.deferred_cancel_count(), 1);
    (sequence, silent)
}

/// A fork branch that has sent nothing when its sibling answers is not
/// CANCELled then. Its INVITE retransmits, its first provisional draws the
/// CANCEL, and its 487 is ACKed, all on a call that has long been answered.
#[tokio::test(flavor = "multi_thread")]
async fn a_losing_fork_branch_that_has_not_responded_is_cancelled_on_its_first_provisional() {
    let (sequence, silent) = fork_won_beside_a_silent_branch();
    let dispatcher = &sequence.dispatcher;
    let state = &dispatcher.state;
    let branch = branch_of(&silent);

    let sent = until_invite_retransmitted(dispatcher, SECOND_CARRIER, &branch).await;
    assert_no_cancel(&sent, SECOND_CARRIER);

    phone_answers(
        state,
        SECOND_CARRIER,
        &silent,
        183,
        "Session Progress",
        None,
    );
    let sent = drain(&dispatcher.udp);
    let cancel = the_cancel(&sent, SECOND_CARRIER, &silent);
    assert!(
        sent.iter().all(|frame| frame.destination != socket(CALLER)),
        "the loser's provisional is not relayed to the answered caller"
    );

    phone_answers(state, SECOND_CARRIER, &cancel, 200, "OK", None);
    phone_answers(
        state,
        SECOND_CARRIER,
        &silent,
        487,
        "Request Terminated",
        None,
    );
    let sent = wire_until(dispatcher, |_| true).await;
    assert_eq!(sent.len(), 1, "the ACK of the 487 and nothing else");
    assert!(sent[0].is(Method::Ack));
    assert_eq!(branch_of(&sent[0].message), branch);
    assert!(!sequence.call_is_gone(), "the answered call stands");
    assert_branch_released(state, &branch);
}

/// The silent branch answers 200 after its sibling won: ACK and BYE, and no
/// CANCEL at any point.
#[tokio::test(flavor = "multi_thread")]
async fn a_losing_fork_branch_that_answers_without_a_provisional_is_acked_and_released() {
    let (sequence, silent) = fork_won_beside_a_silent_branch();
    let dispatcher = &sequence.dispatcher;
    let state = &dispatcher.state;
    let branch = branch_of(&silent);

    phone_answers(state, SECOND_CARRIER, &silent, 200, "OK", None);
    let sent = drain(&dispatcher.udp);
    assert_no_cancel(&sent, SECOND_CARRIER);
    assert_eq!(
        requests_to(&sent, socket(SECOND_CARRIER), Method::Ack).len(),
        1
    );
    let byes = requests_to(&sent, socket(SECOND_CARRIER), Method::Bye);
    assert_eq!(byes.len(), 1, "its dialog is released");
    assert!(
        sent.iter().all(|frame| frame.destination != socket(CALLER)),
        "the caller hears nothing of it"
    );
    assert_branch_released(state, &branch);
}

/// The silent branch declines after its sibling won: its final is ACKed and
/// nothing else goes out.
#[tokio::test(flavor = "multi_thread")]
async fn a_losing_fork_branch_that_fails_without_a_provisional_is_acked_and_nothing_else() {
    let (sequence, silent) = fork_won_beside_a_silent_branch();
    let dispatcher = &sequence.dispatcher;
    let state = &dispatcher.state;
    let branch = branch_of(&silent);

    phone_answers(
        state,
        SECOND_CARRIER,
        &silent,
        480,
        "Temporarily Unavailable",
        None,
    );
    let sent = wire_until(dispatcher, |_| true).await;
    assert_eq!(sent.len(), 1, "the ACK and nothing else: {sent:?}");
    assert!(sent[0].is(Method::Ack));
    assert_eq!(branch_of(&sent[0].message), branch);
    assert_branch_released(state, &branch);
}

/// The silent branch never responds: Timer B ends its INVITE, and no CANCEL
/// was ever sent.
#[tokio::test(flavor = "multi_thread")]
async fn a_losing_fork_branch_that_never_responds_ends_at_timer_b_without_a_cancel() {
    let (sequence, silent) = fork_won_beside_a_silent_branch();
    let dispatcher = &sequence.dispatcher;
    let state = &dispatcher.state;
    let branch = branch_of(&silent);

    super::timers::sweep_b2bua_retransmits_at(
        state,
        std::time::Instant::now() + state.b2bua_retransmits.transaction_timeout(),
    );
    assert_no_cancel(&drain(&dispatcher.udp), SECOND_CARRIER);
    assert_eq!(state.call_actors.deferred_cancel_count(), 0);
    assert!(
        !state.call_actors.is_cancelled_branch(&branch),
        "Timer B releases the branch"
    );
    assert!(!sequence.call_is_gone(), "the answered call stands");
}
