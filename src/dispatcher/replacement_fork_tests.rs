//! A leg replacement that rings every registered contact of its target.
//!
//! An answered call between two registered phones, and a replacement of the
//! callee named by an address-of-record with two contacts: both ring, each on
//! an INVITE and a Call-ID of its own. Driven through the dispatcher's own
//! entry points on a test dispatcher (the targets' responses through
//! [`handle_b2bua_response`] and, once their call or leg is gone, through
//! [`handle_response`] from the top), and read off the UDP egress: who was
//! ACKed, who was CANCELled, who was released with a BYE.
//!
//! What a controlling application hears is read where channel events are
//! published, keyed by the caller's Call-ID.

use super::dialog_state_events_tests::{
    header, inbound, responds, response_for, tag_of, wire, Sent,
};
use super::dialog_state_transfer_tests::{
    answer, establish, hang_up, host_of, in_dialog, respond, sent_invite_to, Established,
};
use super::lcr_ring_timeout_tests::top_via_branch;
use super::*;
use crate::b2bua::transfer::ReplacementOrigin;
use crate::control::channel_event_capture;
use crate::rtpengine::test_native_engine::NativeTestEngine;

/// An answered call whose callee is being replaced by an AoR with two
/// contacts, both ringing.
pub(super) struct Ringing {
    pub(super) call: Established,
    /// The call's internal id.
    pub(super) call_id: String,
    /// Where the second contact is; the first is the call's phone C.
    pub(super) mobile: &'static str,
    /// The INVITE each contact was sent.
    pub(super) to_desk: SipMessage,
    pub(super) to_mobile: SipMessage,
}

impl Ringing {
    fn state(&self) -> &DispatcherState {
        &self.call.dispatcher.state
    }

    pub(super) fn desk(&self) -> &'static str {
        self.call.c.1
    }

    /// Everything siphon sent since the last look, as `METHOD-or-status
    /// destination`.
    fn sent(&self) -> Vec<String> {
        summaries(&wire(&self.call.dispatcher))
    }

    /// The names of the channel events published for the call since the last
    /// look.
    fn events(&self) -> Vec<(String, serde_json::Value)> {
        channel_event_capture::take(&self.call.a_call_id)
    }

    /// The call's two original parties, with no other leg on it: what it is
    /// put back to when a replacement fails.
    fn original_pair(&self) -> (String, Option<String>, usize) {
        (
            self.call.a_call_id.clone(),
            Some(top_via_branch(&self.call.to_b)),
            1,
        )
    }

    /// The Call-ID of the call's caller-facing leg, the Via branch of its
    /// winning B-leg, and how many B-legs it carries.
    fn parties(&self) -> (String, Option<String>, usize) {
        let call = self
            .state()
            .call_actors
            .get_call(&self.call_id)
            .expect("the call exists");
        (
            call.a_leg.dialog.call_id.clone(),
            call.winning_b_leg().map(|leg| leg.branch.clone()),
            call.b_legs.len(),
        )
    }

    fn open_replacements(&self) -> usize {
        self.state()
            .call_actors
            .get_call(&self.call_id)
            .map(|call| call.refer_subscriptions.len())
            .unwrap_or(0)
    }

    /// The contact at `address` answers `invite` with `status_code`, through
    /// the whole response path: the branch lookup, and the handling a response
    /// gets when its call or leg is already gone.
    fn responds_from_the_top(&self, address: &str, invite: &SipMessage, status_code: u16) {
        let response = response_for(invite, status_code, "Request Terminated", "late-tag");
        tokio::task::block_in_place(|| {
            handle_response(inbound(address, ""), response, status_code, self.state())
        });
    }

    /// Set the replacement's deadline in the past and run the sweep.
    fn deadline_passes(&self) {
        if let Some(mut call) = self.state().call_actors.get_call_mut(&self.call_id) {
            for subscription in call.refer_subscriptions.iter_mut() {
                subscription.deadline =
                    Some(std::time::Instant::now() - std::time::Duration::from_secs(1));
            }
        }
        tokio::task::block_in_place(|| check_b2bua_replacement_timeouts(self.state()));
    }
}

fn summaries(sent: &[Sent]) -> Vec<String> {
    sent.iter()
        .map(|sent| {
            let what = match (sent.message.method(), sent.message.status_code()) {
                (Some(method), _) => method.as_str().to_string(),
                (None, Some(status_code)) => status_code.to_string(),
                (None, None) => "?".to_string(),
            };
            format!("{what} {}", sent.destination)
        })
        .collect()
}

/// Establish a call (A to B) and start a replacement of B that rings both
/// contacts of C's AoR: C's own phone, and a second one registered here.
fn ring_two(prefix: u32, origin: ReplacementOrigin) -> Ringing {
    ring_two_on(establish(prefix, "terminate"), prefix, origin, false)
}

/// [`ring_two`] on a call already established, replacing its caller when
/// `replace_a_leg` and its callee otherwise.
pub(super) fn ring_two_on(
    call: Established,
    prefix: u32,
    origin: ReplacementOrigin,
    replace_a_leg: bool,
) -> Ringing {
    let mobile: &'static str =
        Box::leak(format!("203.0.113.{}:5060", 120 + prefix % 50).into_boxed_str());
    let user = call
        .c
        .0
        .trim_start_matches("sip:")
        .split('@')
        .next()
        .unwrap_or_default();
    crate::script::api::test_registrar()
        .save_with_source(
            call.c.0,
            parse_uri_standalone(&format!("sip:{user}@{mobile}")).expect("a contact URI"),
            3600,
            1.0,
            format!("register-second-{prefix}"),
            1,
            None,
            None,
        )
        .expect("the second binding saves");
    channel_event_capture::watch(&call.a_call_id);
    let call_id = call.call_id();
    let _ = wire(&call.dispatcher);

    // The contacts as the control plane resolves an `{aor}` target.
    let contacts = dial_targets_for_aor(call.c.0).expect("the AoR is registered");
    assert_eq!(contacts.len(), 2, "two registered contacts");
    let (target, dial) = ReplacementDial::to_contacts(contacts, DialShaping::default(), Vec::new())
        .expect("a first contact");
    let dialled = tokio::task::block_in_place(|| {
        b2bua_start_leg_replacement(
            &call_id,
            replace_a_leg,
            &target,
            None,
            None,
            None,
            None,
            None,
            2,
            origin,
            30,
            &dial,
            &call.dispatcher.state,
        )
    });
    assert!(dialled, "an INVITE reached the transport");
    let sent = wire(&call.dispatcher);
    assert_eq!(
        sent.iter()
            .filter(|sent| sent.message.method() == Some(&Method::Invite))
            .count(),
        2,
        "one INVITE per contact: {:?}",
        summaries(&sent)
    );
    let to_desk = sent_invite_to(&sent, call.c.1);
    let to_mobile = sent_invite_to(&sent, mobile);
    assert_ne!(
        header(&to_desk, "Call-ID"),
        header(&to_mobile, "Call-ID"),
        "each target rings on a Call-ID of its own"
    );
    assert_ne!(top_via_branch(&to_desk), top_via_branch(&to_mobile));
    for invite in [&to_desk, &to_mobile] {
        assert_eq!(
            header(invite, "To"),
            format!("<{}>", call.c.0),
            "each contact is called as the AoR"
        );
    }
    Ringing {
        call,
        call_id,
        mobile,
        to_desk,
        to_mobile,
    }
}

fn names(events: &[(String, serde_json::Value)]) -> Vec<&str> {
    events.iter().map(|(name, _)| name.as_str()).collect()
}

/// One target answers: it is ACKed and brought into the call, the surviving
/// party is re-INVITEd, the replaced party released, and the other target
/// CANCELled. The `487` that CANCEL draws is ACKed and nothing else happens.
#[tokio::test(flavor = "multi_thread")]
async fn the_first_target_to_answer_is_kept_and_the_other_cancelled() {
    let ringing = ring_two(6300, ReplacementOrigin::SiphonInitiated);
    let (desk, mobile) = (ringing.desk(), ringing.mobile);
    assert!(
        ringing.events().is_empty(),
        "nothing is reported while both ring"
    );

    respond(
        &ringing.call.dispatcher,
        &ringing.call_id,
        desk,
        &ringing.to_desk,
        answer(&ringing.to_desk, desk, "desk-tag"),
    );
    let sent = wire(&ringing.call.dispatcher);
    let summary = summaries(&sent);
    assert_eq!(
        summary
            .iter()
            .filter(|line| **line == format!("ACK {desk}"))
            .count(),
        1,
        "the winner is ACKed: {summary:?}"
    );
    assert_eq!(
        summary
            .iter()
            .filter(|line| **line == format!("CANCEL {mobile}"))
            .count(),
        1,
        "the other target is CANCELled: {summary:?}"
    );
    assert!(
        !summary.contains(&format!("CANCEL {desk}")),
        "the winner is not: {summary:?}"
    );
    assert_eq!(
        summary
            .iter()
            .filter(|line| **line == format!("INVITE {}", ringing.call.a.1))
            .count(),
        1,
        "the surviving party is re-INVITEd: {summary:?}"
    );
    assert!(
        summary.contains(&format!("BYE {}", ringing.call.b.1)),
        "the replaced party is released: {summary:?}"
    );
    // The CANCEL is the loser's own INVITE's (RFC 3261 §9.1).
    let cancel = sent
        .iter()
        .find(|sent| sent.message.method() == Some(&Method::Cancel))
        .expect("a CANCEL");
    assert_eq!(
        top_via_branch(&cancel.message),
        top_via_branch(&ringing.to_mobile)
    );
    assert_eq!(
        header(&cancel.message, "Call-ID"),
        header(&ringing.to_mobile, "Call-ID")
    );

    let events = ringing.events();
    assert_eq!(names(&events), ["PeerReplaced"], "exactly one outcome");
    assert_eq!(
        events[0].1["target_sip_call_id"],
        header(&ringing.to_desk, "Call-ID")
    );
    let (a_leg, winner, _) = ringing.parties();
    assert_eq!(a_leg, ringing.call.a_call_id, "the survivor");
    assert_eq!(
        winner.as_deref(),
        Some(top_via_branch(&ringing.to_desk).as_str()),
        "and the target that answered"
    );
    assert_eq!(ringing.open_replacements(), 0, "the replacement is over");

    // The loser's 487: an ACK on its INVITE's branch, and nothing else.
    responds(
        &ringing.call.dispatcher,
        &ringing.call_id,
        mobile,
        &ringing.to_mobile,
        487,
        "Request Terminated",
        "mobile-tag",
    );
    let sent = wire(&ringing.call.dispatcher);
    assert_eq!(summaries(&sent), [format!("ACK {mobile}")]);
    assert_eq!(
        top_via_branch(&sent[0].message),
        top_via_branch(&ringing.to_mobile),
        "RFC 3261 §17.1.1.3: the ACK rides the INVITE's branch"
    );
    assert!(ringing.events().is_empty());

    // The call ends between the survivor and the winner, and nothing is left.
    hang_up(
        &ringing.call.dispatcher,
        ringing.call.a.1,
        "<sip:x@example.com>;tag=a-tag",
        &header(&ringing.call.answer_to_a, "To"),
        &ringing.call.a_call_id,
    );
    let summary = ringing.sent();
    assert!(summary.contains(&format!("BYE {desk}")), "{summary:?}");
    assert!(!summary.contains(&format!("BYE {mobile}")), "{summary:?}");
    assert!(
        !summary.contains(&format!("CANCEL {mobile}")),
        "{summary:?}"
    );
    assert_eq!(ringing.state().call_actors.count(), 0);
}

/// The other target answers after its CANCEL: the 2xx crossed it (RFC 3261
/// §9.1). The dialog it established is confirmed with an ACK and released with
/// a BYE, once, and the call the winner is in is not touched.
#[tokio::test(flavor = "multi_thread")]
async fn a_target_that_answers_after_losing_is_acked_and_released() {
    let ringing = ring_two(6350, ReplacementOrigin::SiphonInitiated);
    let (desk, mobile) = (ringing.desk(), ringing.mobile);
    respond(
        &ringing.call.dispatcher,
        &ringing.call_id,
        desk,
        &ringing.to_desk,
        answer(&ringing.to_desk, desk, "desk-tag"),
    );
    let _ = wire(&ringing.call.dispatcher);
    let _ = ringing.events();
    let before = ringing.parties();

    respond(
        &ringing.call.dispatcher,
        &ringing.call_id,
        mobile,
        &ringing.to_mobile,
        answer(&ringing.to_mobile, mobile, "mobile-tag"),
    );
    let sent = wire(&ringing.call.dispatcher);
    assert_eq!(
        summaries(&sent),
        [format!("ACK {mobile}"), format!("BYE {mobile}")],
        "ACK then BYE, to the late answerer only"
    );
    for sent in &sent {
        assert_eq!(
            header(&sent.message, "Call-ID"),
            header(&ringing.to_mobile, "Call-ID")
        );
        assert_eq!(tag_of(&header(&sent.message, "To")), "mobile-tag");
    }

    // Its 2xx retransmitted, because the ACK was lost: ACKed again, not BYEd.
    respond(
        &ringing.call.dispatcher,
        &ringing.call_id,
        mobile,
        &ringing.to_mobile,
        answer(&ringing.to_mobile, mobile, "mobile-tag"),
    );
    assert_eq!(ringing.sent(), [format!("ACK {mobile}")]);

    assert_eq!(ringing.parties(), before, "the call is unaffected");
    assert!(ringing.events().is_empty(), "and nothing more is reported");
    let answered = ringing
        .state()
        .call_actors
        .get_call(&ringing.call_id)
        .map(|call| call.state == CallState::Answered);
    assert_eq!(answered, Some(true));
}

/// Both targets answer at the same moment, each 2xx handled on a thread of
/// its own, as two workers handle them. One is brought into the call and the
/// other's dialog is released: one ACK each, one BYE, one outcome, and never a
/// second promotion over the first.
#[tokio::test(flavor = "multi_thread")]
async fn two_targets_answering_at_once_bring_in_one_and_release_the_other() {
    for round in 0..40u32 {
        let ringing = ring_two(6900 + round * 10, ReplacementOrigin::SiphonInitiated);
        let (desk, mobile) = (ringing.desk(), ringing.mobile);
        let barrier = std::sync::Barrier::new(2);
        let runtime = tokio::runtime::Handle::current();
        tokio::task::block_in_place(|| {
            std::thread::scope(|scope| {
                for (address, invite, tag) in [
                    (desk, &ringing.to_desk, "desk-tag"),
                    (mobile, &ringing.to_mobile, "mobile-tag"),
                ] {
                    let (barrier, runtime, ringing) = (&barrier, &runtime, &ringing);
                    scope.spawn(move || {
                        let _entered = runtime.enter();
                        let mut response = answer(invite, address, tag);
                        barrier.wait();
                        assert!(handle_b2bua_response(
                            &ringing.call_id,
                            &top_via_branch(invite),
                            &mut response,
                            200,
                            address.parse().expect("a literal address"),
                            ringing.state(),
                        ));
                    });
                }
            });
        });

        let summary = ringing.sent();
        let count = |line: String| summary.iter().filter(|sent| **sent == line).count();
        assert_eq!(
            count(format!("ACK {desk}")),
            1,
            "round {round}: {summary:?}"
        );
        assert_eq!(
            count(format!("ACK {mobile}")),
            1,
            "round {round}: {summary:?}"
        );
        let released = [desk, mobile]
            .into_iter()
            .filter(|address| count(format!("BYE {address}")) == 1)
            .collect::<Vec<_>>();
        assert_eq!(
            released.len(),
            1,
            "round {round}: exactly one target's dialog is released: {summary:?}"
        );
        assert_eq!(
            count(format!("BYE {}", ringing.call.b.1)),
            1,
            "round {round}: the replaced party is released once: {summary:?}"
        );
        assert_eq!(
            count(format!("INVITE {}", ringing.call.a.1)),
            1,
            "round {round}: the survivor is re-INVITEd once: {summary:?}"
        );
        assert_eq!(
            names(&ringing.events()),
            ["PeerReplaced"],
            "round {round}: one promotion"
        );
        let kept = if released[0] == desk {
            &ringing.to_mobile
        } else {
            &ringing.to_desk
        };
        let (a_leg, winner, _) = ringing.parties();
        assert_eq!(a_leg, ringing.call.a_call_id);
        assert_eq!(
            winner.as_deref(),
            Some(top_via_branch(kept).as_str()),
            "round {round}: the party in the call is the one that was not released"
        );
        assert_eq!(ringing.open_replacements(), 0);
    }
}

/// A target answers at the moment the deadline gives up on the replacement,
/// each on a thread of its own. Either the answer came first and the target is
/// in the call, or the deadline did and the target's dialog is released: one
/// outcome, never both, and the 2xx is ACKed either way.
#[tokio::test(flavor = "multi_thread")]
async fn a_target_answering_as_the_deadline_passes_wins_or_is_released_never_both() {
    for round in 0..30u32 {
        let ringing = ring_two(7300 + round * 10, ReplacementOrigin::SiphonInitiated);
        let (desk, mobile) = (ringing.desk(), ringing.mobile);
        if let Some(mut call) = ringing.state().call_actors.get_call_mut(&ringing.call_id) {
            for subscription in call.refer_subscriptions.iter_mut() {
                subscription.deadline =
                    Some(std::time::Instant::now() - std::time::Duration::from_secs(1));
            }
        }
        let barrier = std::sync::Barrier::new(2);
        let runtime = tokio::runtime::Handle::current();
        tokio::task::block_in_place(|| {
            std::thread::scope(|scope| {
                let (barrier, runtime, ringing) = (&barrier, &runtime, &ringing);
                scope.spawn(move || {
                    let _entered = runtime.enter();
                    let mut response = answer(&ringing.to_desk, desk, "desk-tag");
                    barrier.wait();
                    assert!(handle_b2bua_response(
                        &ringing.call_id,
                        &top_via_branch(&ringing.to_desk),
                        &mut response,
                        200,
                        desk.parse().expect("a literal address"),
                        ringing.state(),
                    ));
                });
                scope.spawn(move || {
                    let _entered = runtime.enter();
                    barrier.wait();
                    check_b2bua_replacement_timeouts(ringing.state());
                });
            });
        });

        let summary = ringing.sent();
        let count = |line: String| summary.iter().filter(|sent| **sent == line).count();
        let events = ringing.events();
        assert_eq!(
            count(format!("ACK {desk}")),
            1,
            "round {round}: {summary:?}"
        );
        assert_eq!(
            count(format!("CANCEL {mobile}")),
            1,
            "round {round}: the target that did not answer is CANCELled: {summary:?}"
        );
        match names(&events).as_slice() {
            ["PeerReplaced"] => {
                assert_eq!(
                    count(format!("BYE {desk}")),
                    0,
                    "round {round}: {summary:?}"
                );
                assert_eq!(
                    ringing.parties().1.as_deref(),
                    Some(top_via_branch(&ringing.to_desk).as_str()),
                    "round {round}: the target that answered is in the call"
                );
            }
            ["ReplaceFailed"] => {
                assert_eq!(
                    count(format!("BYE {desk}")),
                    1,
                    "round {round}: the answer that lost to the deadline is released: {summary:?}"
                );
                assert_eq!(
                    ringing.parties(),
                    ringing.original_pair(),
                    "round {round}: the original call is intact"
                );
            }
            other => panic!("round {round}: one outcome, got {other:?}: {summary:?}"),
        }
        assert_eq!(ringing.open_replacements(), 0);
    }
}

/// The caller is the party replaced, which takes the winner out of the call's
/// list of B-legs to put it in the caller's place, and moves every leg after
/// it. The target dialled first answers, so the other one is the leg that
/// moves: its `487` and a 2xx crossing its CANCEL are still matched to it.
#[tokio::test(flavor = "multi_thread")]
async fn replacing_the_caller_keeps_the_losing_target_answerable_after_the_promotion() {
    let ringing = ring_two_on(
        establish(6850, "terminate"),
        6850,
        ReplacementOrigin::SiphonInitiated,
        true,
    );
    let (desk, mobile) = (ringing.desk(), ringing.mobile);
    // The one dialled first sits ahead of the other in the leg list.
    let first_branch = ringing
        .state()
        .call_actors
        .get_call(&ringing.call_id)
        .map(|call| call.refer_subscriptions[0].targets[0].branch.clone())
        .expect("the call exists");
    let (winner, winner_invite, loser, loser_invite) =
        if first_branch == top_via_branch(&ringing.to_desk) {
            (desk, &ringing.to_desk, mobile, &ringing.to_mobile)
        } else {
            (mobile, &ringing.to_mobile, desk, &ringing.to_desk)
        };
    // Once promoted the winner is the call's caller-facing leg, and its
    // Call-ID is what the call's events are published under.
    let winner_call_id = header(winner_invite, "Call-ID");
    channel_event_capture::watch(&winner_call_id);

    respond(
        &ringing.call.dispatcher,
        &ringing.call_id,
        winner,
        winner_invite,
        answer(winner_invite, winner, "winner-tag"),
    );
    let summary = ringing.sent();
    for expected in [
        format!("ACK {winner}"),
        format!("CANCEL {loser}"),
        format!("INVITE {}", ringing.call.b.1),
    ] {
        assert_eq!(
            summary.iter().filter(|line| **line == expected).count(),
            1,
            "{expected}: {summary:?}"
        );
    }
    // The caller never ACKed the 2xx siphon answered it with, so the BYE that
    // releases it waits for that ACK (RFC 3261 §15) rather than going out now.
    assert!(!summary.contains(&format!("BYE {}", ringing.call.a.1)));
    assert_eq!(ringing.state().held_byes.len(), 1);
    assert_eq!(
        names(&channel_event_capture::take(&winner_call_id)),
        ["PeerReplaced"]
    );
    let (a_leg, survivor, legs) = ringing.parties();
    assert_eq!(a_leg, winner_call_id, "the winner took the caller's place");
    assert_eq!(
        survivor.as_deref(),
        Some(top_via_branch(&ringing.call.to_b).as_str()),
        "the callee is still the other party"
    );
    assert_eq!(
        legs, 3,
        "the callee, the cancelled target, and the leg tracking the callee's re-INVITE"
    );

    // The loser answers 2xx across its CANCEL, then again: ACK and BYE once,
    // ACK alone after, all in its own dialog.
    for expected in [
        vec![format!("ACK {loser}"), format!("BYE {loser}")],
        vec![format!("ACK {loser}")],
    ] {
        respond(
            &ringing.call.dispatcher,
            &ringing.call_id,
            loser,
            loser_invite,
            answer(loser_invite, loser, "loser-tag"),
        );
        let sent = wire(&ringing.call.dispatcher);
        assert_eq!(summaries(&sent), expected);
        for sent in &sent {
            assert_eq!(
                header(&sent.message, "Call-ID"),
                header(loser_invite, "Call-ID")
            );
        }
    }
    // And the winner's dialog was not written over by the loser's answer.
    let caller_facing = ringing
        .state()
        .call_actors
        .get_call(&ringing.call_id)
        .map(|call| call.a_leg.dialog.remote_tag.clone())
        .expect("the call exists");
    assert_eq!(caller_facing.as_deref(), Some("winner-tag"));
    assert_eq!(ringing.parties().1, survivor, "nor the callee's");
}

/// Both targets refuse. The first refusal reports nothing, since the other
/// still rings; the second fails the transfer once, on the best of the two
/// responses (RFC 3261 §16.7 step 6), and the original call is as it was.
#[tokio::test(flavor = "multi_thread")]
async fn the_transfer_fails_once_both_targets_have_and_on_the_best_response() {
    // A REFER's replacement: B is the referrer and is owed the sipfrag.
    let ringing = ring_two(6400, ReplacementOrigin::Refer);
    let (desk, mobile) = (ringing.desk(), ringing.mobile);
    let original = ringing.original_pair();

    responds(
        &ringing.call.dispatcher,
        &ringing.call_id,
        desk,
        &ringing.to_desk,
        486,
        "Busy Here",
        "desk-tag",
    );
    assert_eq!(
        ringing.sent(),
        [format!("ACK {desk}")],
        "the refusal is ACKed and nothing is reported while the other rings"
    );
    assert!(ringing.events().is_empty());
    assert_eq!(ringing.open_replacements(), 1);

    // The last response is a 503, and the transfer still fails on the 486.
    responds(
        &ringing.call.dispatcher,
        &ringing.call_id,
        mobile,
        &ringing.to_mobile,
        503,
        "Service Unavailable",
        "mobile-tag",
    );
    let sent = wire(&ringing.call.dispatcher);
    assert_eq!(
        summaries(&sent),
        [
            format!("ACK {mobile}"),
            format!("NOTIFY {}", ringing.call.b.1)
        ],
        "one failure, to the referrer"
    );
    let notify = &sent[1].message;
    let sipfrag = String::from_utf8_lossy(&notify.body).to_string();
    assert!(
        sipfrag.starts_with("SIP/2.0 486"),
        "the best response, not the last: {sipfrag}"
    );
    assert!(header(notify, "Subscription-State").starts_with("terminated"));

    let events = ringing.events();
    assert_eq!(names(&events), ["ReplaceFailed"], "exactly one outcome");
    assert_eq!(events[0].1["status"], 486);
    assert_eq!(events[0].1["call_kept"], true);

    assert_eq!(
        ringing.parties(),
        original,
        "both original parties, no other leg"
    );
    assert_eq!(ringing.open_replacements(), 0);
    for invite in [&ringing.to_desk, &ringing.to_mobile] {
        assert!(
            ringing
                .state()
                .call_actors
                .call_id_for_branch(&top_via_branch(invite))
                .is_none(),
            "a failed target's leg is off the call"
        );
    }

    // And the call still ends cleanly between its two original parties.
    hang_up(
        &ringing.call.dispatcher,
        ringing.call.a.1,
        "<sip:x@example.com>;tag=a-tag",
        &header(&ringing.call.answer_to_a, "To"),
        &ringing.call.a_call_id,
    );
    let summary = ringing.sent();
    assert!(
        summary.contains(&format!("BYE {}", ringing.call.b.1)),
        "{summary:?}"
    );
    assert_eq!(ringing.state().call_actors.count(), 0);
}

/// The deadline passes with both targets ringing: both are CANCELled, one
/// failure is reported, and the `487` each CANCEL draws is ACKed.
#[tokio::test(flavor = "multi_thread")]
async fn the_deadline_cancels_both_targets_and_their_487s_are_acked() {
    let ringing = ring_two(6450, ReplacementOrigin::SiphonInitiated);
    let (desk, mobile) = (ringing.desk(), ringing.mobile);
    let original = ringing.original_pair();

    ringing.deadline_passes();
    let mut summary = ringing.sent();
    summary.sort();
    let mut cancels = [format!("CANCEL {desk}"), format!("CANCEL {mobile}")];
    cancels.sort();
    assert_eq!(summary, cancels, "both targets are CANCELled, nothing else");
    let events = ringing.events();
    assert_eq!(names(&events), ["ReplaceFailed"], "one failure");
    assert_eq!(events[0].1["status"], 408);
    assert_eq!(ringing.parties(), original, "the original call is intact");
    assert_eq!(ringing.open_replacements(), 0);

    // A second sweep finds nothing to give up on.
    ringing.deadline_passes();
    assert!(ringing.sent().is_empty());
    assert!(ringing.events().is_empty());

    // Each target answers its CANCEL with a 487. Their legs are off the call
    // by now, so the response is matched as one for a leg siphon cancelled.
    for (address, invite) in [(desk, &ringing.to_desk), (mobile, &ringing.to_mobile)] {
        ringing.responds_from_the_top(address, invite, 487);
        let sent = wire(&ringing.call.dispatcher);
        assert_eq!(
            summaries(&sent),
            [format!("ACK {address}")],
            "RFC 3261 §17.1.1.3: a 487 after the deadline is ACKed"
        );
        assert_eq!(top_via_branch(&sent[0].message), top_via_branch(invite));
    }
    assert!(ringing.events().is_empty());
    assert_eq!(ringing.parties(), original);
}

/// A target whose 2xx crosses the deadline's CANCEL is ACKed and released
/// with a BYE, and the original call goes on.
#[tokio::test(flavor = "multi_thread")]
async fn a_target_answering_across_the_deadline_cancel_is_released() {
    let ringing = ring_two(6500, ReplacementOrigin::SiphonInitiated);
    let desk = ringing.desk();
    let original = ringing.original_pair();
    ringing.deadline_passes();
    let _ = wire(&ringing.call.dispatcher);
    let _ = ringing.events();

    let late = answer(&ringing.to_desk, desk, "desk-tag");
    tokio::task::block_in_place(|| handle_response(inbound(desk, ""), late, 200, ringing.state()));
    assert_eq!(
        ringing.sent(),
        [format!("ACK {desk}"), format!("BYE {desk}")]
    );
    assert!(ringing.events().is_empty());
    assert_eq!(ringing.parties(), original);
}

/// The surviving party hangs up while both targets ring: both are CANCELled
/// before the call is gone, and the `487` each sends afterwards is still ACKed.
#[tokio::test(flavor = "multi_thread")]
async fn the_survivor_hanging_up_cancels_both_ringing_targets() {
    let ringing = ring_two(6550, ReplacementOrigin::SiphonInitiated);
    let (desk, mobile) = (ringing.desk(), ringing.mobile);

    // A is the surviving party of a replacement of B.
    hang_up(
        &ringing.call.dispatcher,
        ringing.call.a.1,
        "<sip:x@example.com>;tag=a-tag",
        &header(&ringing.call.answer_to_a, "To"),
        &ringing.call.a_call_id,
    );
    let summary = ringing.sent();
    for address in [desk, mobile] {
        assert_eq!(
            summary
                .iter()
                .filter(|line| **line == format!("CANCEL {address}"))
                .count(),
            1,
            "the target at {address} is CANCELled: {summary:?}"
        );
    }
    let position = |line: String| {
        summary
            .iter()
            .position(|sent| *sent == line)
            .unwrap_or_else(|| panic!("no {line} in {summary:?}"))
    };
    let answered = position(format!("200 {}", ringing.call.a.1));
    assert!(
        position(format!("CANCEL {desk}")) < answered
            && position(format!("CANCEL {mobile}")) < answered,
        "the targets are CANCELled before the call is torn down: {summary:?}"
    );
    assert!(
        summary.contains(&format!("BYE {}", ringing.call.b.1)),
        "the other original party is released: {summary:?}"
    );
    assert_eq!(ringing.state().call_actors.count(), 0, "the call is gone");

    for (address, invite) in [(desk, &ringing.to_desk), (mobile, &ringing.to_mobile)] {
        ringing.responds_from_the_top(address, invite, 487);
        assert_eq!(ringing.sent(), [format!("ACK {address}")]);
    }
}

/// `terminate` on a call with targets ringing CANCELs them as a BYE does.
#[tokio::test(flavor = "multi_thread")]
async fn terminating_the_call_cancels_both_ringing_targets() {
    let ringing = ring_two(6600, ReplacementOrigin::SiphonInitiated);
    let (desk, mobile) = (ringing.desk(), ringing.mobile);
    assert!(tokio::task::block_in_place(|| b2bua_terminate_call_inner(
        &ringing.call_id,
        None,
        "b2bua",
        ringing.state(),
    )));
    let summary = ringing.sent();
    for address in [desk, mobile] {
        assert!(
            summary.contains(&format!("CANCEL {address}")),
            "the target at {address} is CANCELled: {summary:?}"
        );
    }
    assert_eq!(ringing.state().call_actors.count(), 0);
    ringing.responds_from_the_top(mobile, &ringing.to_mobile, 487);
    assert_eq!(ringing.sent(), [format!("ACK {mobile}")]);
}

/// The party being replaced hangs up while both targets ring: the call is kept
/// for them (RFC 5589 §7), and the first to answer still wins.
#[tokio::test(flavor = "multi_thread")]
async fn the_replaced_party_leaving_keeps_the_call_for_its_ringing_targets() {
    let ringing = ring_two(6650, ReplacementOrigin::SiphonInitiated);
    let (desk, mobile) = (ringing.desk(), ringing.mobile);
    // B, in its own dialog with siphon, sends the BYE.
    let (raw, message) = in_dialog(
        "BYE",
        ringing.call.b.1,
        &format!("{};tag=b-tag", header(&ringing.call.to_b, "To")),
        &header(&ringing.call.to_b, "From"),
        &header(&ringing.call.to_b, "Call-ID"),
        9,
        "",
    );
    tokio::task::block_in_place(|| {
        handle_b2bua_bye(inbound(ringing.call.b.1, &raw), message, ringing.state())
    });
    assert_eq!(
        ringing.sent(),
        [format!("200 {}", ringing.call.b.1)],
        "the BYE is answered and neither target is CANCELled"
    );
    assert_eq!(ringing.state().call_actors.count(), 1);

    respond(
        &ringing.call.dispatcher,
        &ringing.call_id,
        mobile,
        &ringing.to_mobile,
        answer(&ringing.to_mobile, mobile, "mobile-tag"),
    );
    let summary = ringing.sent();
    assert!(summary.contains(&format!("ACK {mobile}")), "{summary:?}");
    assert!(summary.contains(&format!("CANCEL {desk}")), "{summary:?}");
    assert!(
        !summary.contains(&format!("BYE {}", ringing.call.b.1)),
        "a party that already left is not BYEd: {summary:?}"
    );
    assert_eq!(names(&ringing.events()), ["PeerReplaced"]);
}

/// On a media-anchored call each target is offered the surviving party's media
/// on an engine call of its own. The one that answers completes its own; the
/// other's is deleted, and so is the anchor the replaced party was on.
#[tokio::test(flavor = "multi_thread")]
async fn each_losing_targets_engine_call_is_deleted_and_the_winners_is_kept() {
    let engine = NativeTestEngine::start().await;
    let (ringing, old_anchor) = ring_two_anchored(6700, &engine).await;
    let (desk, mobile) = (ringing.desk(), ringing.mobile);
    let desk_media = header(&ringing.to_desk, "Call-ID");
    let mobile_media = header(&ringing.to_mobile, "Call-ID");

    // One offer per target, each on that target's own Call-ID.
    let mut offered: Vec<String> = engine
        .commands("offer")
        .into_iter()
        .map(|command| command.call_id)
        .filter(|call_id| *call_id != old_anchor)
        .collect();
    offered.sort();
    let mut expected = vec![desk_media.clone(), mobile_media.clone()];
    expected.sort();
    assert_eq!(
        offered, expected,
        "each target has an engine call of its own"
    );
    assert!(engine.holds(&desk_media) && engine.holds(&mobile_media));

    respond(
        &ringing.call.dispatcher,
        &ringing.call_id,
        mobile,
        &ringing.to_mobile,
        answer(&ringing.to_mobile, mobile, "mobile-tag"),
    );
    let summary = ringing.sent();
    assert!(summary.contains(&format!("CANCEL {desk}")), "{summary:?}");

    // The deletes run off the signalling path: wait for them by what they do.
    assert!(
        eventually(|| !engine.holds(&desk_media) && !engine.holds(&old_anchor)).await,
        "the loser's engine call and the old anchor are deleted: {:?}",
        engine.commands("delete")
    );
    let deleted: Vec<String> = engine
        .commands("delete")
        .into_iter()
        .map(|command| command.call_id)
        .collect();
    assert_eq!(
        deleted
            .iter()
            .filter(|call_id| **call_id == desk_media)
            .count(),
        1,
        "the loser's is deleted once: {deleted:?}"
    );
    assert!(
        !deleted.contains(&mobile_media),
        "the winner's is not: {deleted:?}"
    );
    assert!(engine.holds(&mobile_media), "the winner's call is live");
    // The winner's answer completed the engine call its INVITE was offered from.
    assert!(engine
        .commands("answer")
        .iter()
        .any(|command| command.call_id == mobile_media && !command.refused));
    assert_eq!(
        engine.held_count(),
        1,
        "one engine call left: the new pair's"
    );
}

/// Both targets of an anchored call fail: each one's engine call is deleted
/// as it fails, and the anchor the original pair is on is kept.
#[tokio::test(flavor = "multi_thread")]
async fn a_failed_targets_engine_call_is_deleted_and_the_original_anchor_kept() {
    let engine = NativeTestEngine::start().await;
    let (ringing, old_anchor) = ring_two_anchored(6750, &engine).await;
    let desk = ringing.desk();
    let desk_media = header(&ringing.to_desk, "Call-ID");
    let mobile_media = header(&ringing.to_mobile, "Call-ID");

    responds(
        &ringing.call.dispatcher,
        &ringing.call_id,
        desk,
        &ringing.to_desk,
        486,
        "Busy Here",
        "desk-tag",
    );
    assert!(
        eventually(|| !engine.holds(&desk_media)).await,
        "a failed target's engine call is released at once"
    );
    assert!(
        engine.holds(&mobile_media),
        "the one still ringing keeps its own"
    );

    ringing.deadline_passes();
    assert!(
        eventually(|| !engine.holds(&mobile_media)).await,
        "a timed-out target's engine call is released"
    );
    assert!(
        engine.holds(&old_anchor),
        "the original pair's anchor is kept"
    );
    assert_eq!(engine.held_count(), 1);
}

/// Wait until `check` holds, or the deadline.
async fn eventually(check: impl Fn() -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        if check() {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    check()
}

/// [`ring_two`] on a call whose two parties are anchored on `engine`: the
/// caller offered and the callee answered on an engine call keyed by the
/// caller's Call-ID, as a script's `rtpengine.offer` / `answer` leave it.
/// Returns the engine call-id of that anchor too.
async fn ring_two_anchored(prefix: u32, engine: &NativeTestEngine) -> (Ringing, String) {
    let mut call = establish(prefix, "terminate");
    call.dispatcher.state.rtpengine_set = Some(engine.backend());
    call.dispatcher.state.rtpengine_profiles =
        Some(Arc::new(crate::rtpengine::ProfileRegistry::new()));
    let sessions = Arc::new(crate::rtpengine::MediaSessionStore::new());
    call.dispatcher.state.rtpengine_sessions = Some(Arc::clone(&sessions));

    let old_anchor = call.a_call_id.clone();
    let caller_sdp = format!(
        concat!(
            "v=0\r\n",
            "o=- 1 1 IN IP4 {host}\r\n",
            "s=-\r\n",
            "c=IN IP4 {host}\r\n",
            "t=0 0\r\n",
            "m=audio 40000 RTP/AVP 0\r\n",
        ),
        host = host_of(call.a.1),
    );
    let state = &call.dispatcher.state;
    tokio::task::block_in_place(|| {
        assert!(b2bua_transfer_rtpengine_offer(
            state,
            &old_anchor,
            "a-tag",
            caller_sdp.as_bytes(),
            &old_anchor,
            "rtp_passthrough",
            None,
        )
        .is_some());
        assert!(b2bua_transfer_rtpengine_answer(
            state,
            &old_anchor,
            "a-tag",
            "b-tag",
            caller_sdp.as_bytes(),
            &header(&call.to_b, "Call-ID"),
            "rtp_passthrough",
            None,
        )
        .is_some());
    });
    sessions.insert(crate::rtpengine::session::MediaSession {
        call_id: old_anchor.clone(),
        rtpengine_call_id: old_anchor.clone(),
        from_tag: "a-tag".to_string(),
        to_tag: Some("b-tag".to_string()),
        profile: "rtp_passthrough".to_string(),
        ws_uri: None,
        ws_tee: None,
        ws_bridge_attached: false,
        bridge_sides: None,
        created_at: std::time::Instant::now(),
    });
    assert!(engine.holds(&old_anchor));
    let ringing = ring_two_on(call, prefix, ReplacementOrigin::SiphonInitiated, false);
    (ringing, old_anchor)
}

/// One target, as before any of this: one INVITE, the Call-ID the call's own
/// rules give it, and on its answer exactly the round a replacement has always
/// run, with no CANCEL anywhere.
#[tokio::test(flavor = "multi_thread")]
async fn a_single_target_is_dialled_and_brought_in_with_no_cancel() {
    let call = establish(6800, "terminate");
    channel_event_capture::watch(&call.a_call_id);
    let call_id = call.call_id();
    let _ = wire(&call.dispatcher);
    assert!(tokio::task::block_in_place(|| {
        b2bua_start_leg_replacement(
            &call_id,
            false,
            &call.c_uri(),
            None,
            None,
            None,
            None,
            None,
            0,
            ReplacementOrigin::SiphonInitiated,
            30,
            &ReplacementDial::default(),
            &call.dispatcher.state,
        )
    }));
    let sent = wire(&call.dispatcher);
    assert_eq!(summaries(&sent), [format!("INVITE {}", call.c.1)]);
    let to_c = sent_invite_to(&sent, call.c.1);
    let targets = call
        .dispatcher
        .state
        .call_actors
        .get_call(&call_id)
        .map(|held| held.refer_subscriptions[0].targets.clone())
        .expect("the call exists");
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].branch, top_via_branch(&to_c));
    assert_eq!(targets[0].leg_call_id, header(&to_c, "Call-ID"));
    assert!(targets[0].media.is_none(), "the call is not anchored");

    respond(
        &call.dispatcher,
        &call_id,
        call.c.1,
        &to_c,
        answer(&to_c, call.c.1, "c-tag"),
    );
    let mut summary = summaries(&wire(&call.dispatcher));
    summary.sort();
    let mut expected = [
        format!("ACK {}", call.c.1),
        format!("BYE {}", call.b.1),
        format!("INVITE {}", call.a.1),
    ];
    expected.sort();
    assert_eq!(summary, expected);
    assert_eq!(
        names(&channel_event_capture::take(&call.a_call_id)),
        ["PeerReplaced"]
    );
    assert!(call
        .dispatcher
        .state
        .call_actors
        .zombie_cancelled
        .is_empty());
}
