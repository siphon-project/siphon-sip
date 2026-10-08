//! A REFER as a request that is always answered, and answered once.
//!
//! A call between two registered phones, owned by a control application or
//! left to its script, and a REFER from one of its parties. Two things are
//! pinned here, both read off the UDP egress and the application's event queue:
//!
//! * a retransmission of a REFER siphon has already decided on gets the final
//!   response that decision produced, again, and is not shown to anybody as a
//!   new request (RFC 3261 §17.2.2);
//! * a REFER held for an application's decision is answered whatever happens
//!   to its call in the meantime, and the held entry goes with it.

use super::dialog_state_events_tests::{header, inbound, register, responds, tag_of, wire, Sent};
use super::dialog_state_transfer_tests::{
    answer, control_plane, establish, establish_deciding, hang_up, host_of, in_dialog, invite,
    place, respond, response_to_phone, sent_to, Established,
};
use super::transfer_ingress_tests::refers;
use super::*;
use crate::script::api::call::ReferMode;

/// An answered call (A to B) a control application owns as `channel`.
struct Controlled {
    call: Established,
    bus: Arc<crate::control::ControlBus>,
    connection: Arc<crate::control::ConnHandle>,
    call_id: String,
}

fn controlled(prefix: u32) -> Controlled {
    // The script's own mode is never consulted: the application decides.
    let call = establish(prefix, "terminate");
    let call_id = call.call_id();
    let (bus, connection) = control_plane(&format!("refer-answer-{prefix}"));
    bus.register_channel(
        &format!("channel-{prefix}"),
        &connection,
        &call_id,
        &call.a_call_id,
        "hangup",
        std::collections::HashMap::new(),
    );
    let _ = wire(&call.dispatcher);
    Controlled {
        call,
        bus,
        connection,
        call_id,
    }
}

impl Controlled {
    fn state(&self) -> &DispatcherState {
        &self.call.dispatcher.state
    }

    /// The callee sends the REFER numbered `cseq`, through the entry point the
    /// dispatcher hands every REFER of a tracked call to. The same `cseq`
    /// twice is the same request, byte for byte: a retransmission.
    fn callee_refers(&self, cseq: u32) {
        refer(
            Some(self.bus.as_ref()),
            &self.call,
            self.call.b.1,
            &format!("{};tag=b-tag", header(&self.call.to_b, "To")),
            &header(&self.call.to_b, "From"),
            &header(&self.call.to_b, "Call-ID"),
            cseq,
        );
    }

    /// The events queued for the application since the last look. Events are
    /// pushed before the call that raises them returns, so the queue is read
    /// as it stands.
    async fn events(&self) -> Vec<String> {
        if self.connection.events.depth() == 0 {
            return Vec::new();
        }
        self.connection
            .events
            .recv_many()
            .await
            .into_iter()
            .filter_map(|frame| match frame {
                crate::control::OutboundFrame::Event(event) => Some(event.event),
                crate::control::OutboundFrame::Reply(_) => None,
            })
            .collect()
    }

    fn accept(&self, mode: ReferMode) -> bool {
        tokio::task::block_in_place(|| {
            b2bua_accept_refer_with_state(
                self.state(),
                &self.call.a_call_id,
                None,
                None,
                Some(mode),
                None,
                None,
                &ReplacementDial::default(),
            )
        })
    }

    fn callee_hangs_up(&self) {
        hang_up(
            &self.call.dispatcher,
            self.call.b.1,
            &format!("{};tag=b-tag", header(&self.call.to_b, "To")),
            &header(&self.call.to_b, "From"),
            &header(&self.call.to_b, "Call-ID"),
        );
    }

    fn caller_hangs_up(&self) {
        hang_up(
            &self.call.dispatcher,
            self.call.a.1,
            "<sip:x@example.com>;tag=a-tag",
            &header(&self.call.answer_to_a, "To"),
            &self.call.a_call_id,
        );
    }
}

/// A party at `source` sends a REFER to the call's phone C in its dialog.
fn refer(
    bus: Option<&crate::control::ControlBus>,
    call: &Established,
    source: &str,
    from: &str,
    to: &str,
    sip_call_id: &str,
    cseq: u32,
) {
    let (raw, message) = in_dialog(
        "REFER",
        source,
        from,
        to,
        sip_call_id,
        cseq,
        &format!("Refer-To: <{}>\r\n", call.c_uri()),
    );
    tokio::task::block_in_place(|| {
        handle_b2bua_refer_on(bus, inbound(source, &raw), message, &call.dispatcher.state)
    });
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

fn replacements(controlled: &Controlled) -> usize {
    controlled
        .state()
        .call_actors
        .get_call(&controlled.call_id)
        .map(|call| call.refer_subscriptions.len())
        .unwrap_or(0)
}

/// A REFER accepted for siphon to carry out is answered `202` once and its
/// target dialled once. The REFER again (its `202` was lost) gets that `202`
/// again: no second event, nothing held, no second NOTIFY and no second leg.
#[tokio::test(flavor = "multi_thread")]
async fn a_refer_retransmitted_after_it_was_accepted_gets_its_202_again() {
    let controlled = controlled(9700);
    let b = controlled.call.b.1;

    controlled.callee_refers(2);
    assert_eq!(controlled.events().await, ["TransferRequested"]);
    assert!(wire(&controlled.call.dispatcher).is_empty());
    assert!(controlled.accept(ReferMode::Terminate));
    let sent = wire(&controlled.call.dispatcher);
    assert_eq!(
        summaries(&sent),
        [
            format!("202 {b}"),
            format!("NOTIFY {b}"),
            format!("INVITE {}", controlled.call.c.1)
        ]
    );
    let accepted = sent[0].message.to_bytes();

    for _ in 0..2 {
        controlled.callee_refers(2);
        let again = wire(&controlled.call.dispatcher);
        assert_eq!(
            summaries(&again),
            [format!("202 {b}")],
            "the same final response, and nothing else"
        );
        assert_eq!(again[0].message.to_bytes(), accepted);
        assert!(
            controlled.events().await.is_empty(),
            "a retransmission is not a new transfer request"
        );
        assert_eq!(controlled.state().pending_inbound_refer.len(), 0);
        assert_eq!(replacements(&controlled), 1, "still the one replacement");
    }

    // A REFER with a new CSeq is not a retransmission. The transfer the first
    // one started is still in flight (its target rings), and a call is
    // re-paired once at a time, so this one is refused `491`: not held, and
    // not reported.
    controlled.callee_refers(3);
    let busy = wire(&controlled.call.dispatcher);
    assert_eq!(summaries(&busy), [format!("491 {b}")]);
    assert_eq!(header(&busy[0].message, "CSeq"), "3 REFER");
    assert!(controlled.events().await.is_empty());
    assert_eq!(controlled.state().pending_inbound_refer.len(), 0);
    assert_eq!(replacements(&controlled), 1, "still the one replacement");

    // The call ends: nothing is held to answer, and nothing is left that
    // remembers any of them.
    controlled.caller_hangs_up();
    let ended = summaries(&wire(&controlled.call.dispatcher));
    assert!(!ended.contains(&format!("603 {b}")), "{ended:?}");
    assert_eq!(controlled.state().pending_inbound_refer.len(), 0);
    assert_eq!(controlled.state().call_actors.count(), 0);
    assert_eq!(controlled.state().answered_refers.len(), 0);
}

impl Controlled {
    /// The caller sends the REFER numbered `cseq` in its dialog.
    fn caller_refers(&self, cseq: u32) {
        refer(
            Some(self.bus.as_ref()),
            &self.call,
            self.call.a.1,
            "<sip:x@example.com>;tag=a-tag",
            &header(&self.call.answer_to_a, "To"),
            &self.call.a_call_id,
            cseq,
        );
    }

    /// The transfer target, which siphon dialled with `invite`, answers it
    /// with `status_code`.
    fn target_responds(&self, invite: &SipMessage, status_code: u16) {
        if status_code == 200 {
            respond(
                &self.call.dispatcher,
                &self.call_id,
                self.call.c.1,
                invite,
                answer(invite, self.call.c.1, "c-tag"),
            );
        } else {
            responds(
                &self.call.dispatcher,
                &self.call_id,
                self.call.c.1,
                invite,
                status_code,
                "Busy Here",
                "c-tag",
            );
        }
    }

    /// The callee's REFER numbered `cseq` is refused `491` and nothing else
    /// happens: no event, nothing held, nobody dialled.
    async fn assert_callee_refer_refused(&self, cseq: u32) {
        self.callee_refers(cseq);
        let refused = wire(&self.call.dispatcher);
        assert_eq!(summaries(&refused), [format!("491 {}", self.call.b.1)]);
        assert_eq!(header(&refused[0].message, "CSeq"), format!("{cseq} REFER"));
        assert!(self.events().await.is_empty(), "nothing is reported");
        assert_eq!(self.state().pending_inbound_refer.len(), 0, "nothing held");
    }

    /// The callee's REFER numbered `cseq` is taken as any REFER is: held for
    /// its application and reported.
    async fn assert_callee_refer_taken(&self, cseq: u32) {
        self.callee_refers(cseq);
        assert!(wire(&self.call.dispatcher).is_empty(), "held, not answered");
        assert_eq!(self.events().await, ["TransferRequested"]);
        assert_eq!(self.state().pending_inbound_refer.len(), 1);
    }
}

/// While a transfer siphon carries out is in flight, a new REFER on the call
/// is refused `491` from either party, without being held or reported. Once
/// the target refuses and the transfer has failed, a new REFER is taken.
#[tokio::test(flavor = "multi_thread")]
async fn a_refer_is_refused_while_a_transfer_is_in_flight_and_taken_once_it_fails() {
    let controlled = controlled(10150);
    let (a, c) = (controlled.call.a.1, controlled.call.c.1);

    controlled.callee_refers(2);
    assert_eq!(controlled.events().await, ["TransferRequested"]);
    assert!(controlled.accept(ReferMode::Terminate));
    let to_c = sent_to(&wire(&controlled.call.dispatcher), c, Method::Invite)
        .expect("the target is dialled");

    controlled.assert_callee_refer_refused(3).await;
    // The other party's REFER is one for the same call.
    controlled.caller_refers(7);
    let refused = wire(&controlled.call.dispatcher);
    assert_eq!(summaries(&refused), [format!("491 {a}")]);
    assert_eq!(header(&refused[0].message, "CSeq"), "7 REFER");
    assert!(controlled.events().await.is_empty());
    assert_eq!(controlled.state().pending_inbound_refer.len(), 0);
    assert_eq!(replacements(&controlled), 1, "still the one replacement");

    controlled.target_responds(&to_c, 486);
    let _ = wire(&controlled.call.dispatcher);
    assert_eq!(replacements(&controlled), 0, "the transfer failed");
    let _ = controlled.events().await;

    controlled.assert_callee_refer_taken(4).await;
}

/// The transfer's deadline ends it as a failure does: a new REFER is taken.
#[tokio::test(flavor = "multi_thread")]
async fn a_refer_is_taken_once_the_transfer_in_flight_runs_out_of_time() {
    let controlled = controlled(10200);
    let state = controlled.state();

    controlled.callee_refers(2);
    assert_eq!(controlled.events().await, ["TransferRequested"]);
    assert!(controlled.accept(ReferMode::Terminate));
    let _ = wire(&controlled.call.dispatcher);
    controlled.assert_callee_refer_refused(3).await;

    if let Some(mut call) = state.call_actors.get_call_mut(&controlled.call_id) {
        for subscription in call.refer_subscriptions.iter_mut() {
            subscription.deadline =
                Some(std::time::Instant::now() - std::time::Duration::from_secs(1));
        }
    }
    tokio::task::block_in_place(|| check_b2bua_replacement_timeouts(state));
    let _ = wire(&controlled.call.dispatcher);
    assert_eq!(replacements(&controlled), 0, "the transfer ran out of time");
    let _ = controlled.events().await;

    controlled.assert_callee_refer_taken(4).await;
}

/// The transfer succeeds: the referrer is released and the caller is with the
/// target. A REFER from the caller, a new transfer of the new pair, is taken.
#[tokio::test(flavor = "multi_thread")]
async fn a_refer_is_taken_once_the_transfer_in_flight_has_succeeded() {
    let controlled = controlled(10250);
    let c = controlled.call.c.1;

    controlled.callee_refers(2);
    assert_eq!(controlled.events().await, ["TransferRequested"]);
    assert!(controlled.accept(ReferMode::Terminate));
    let to_c = sent_to(&wire(&controlled.call.dispatcher), c, Method::Invite)
        .expect("the target is dialled");
    controlled.caller_refers(7);
    assert_eq!(
        summaries(&wire(&controlled.call.dispatcher)),
        [format!("491 {}", controlled.call.a.1)]
    );

    controlled.target_responds(&to_c, 200);
    let _ = wire(&controlled.call.dispatcher);
    assert_eq!(replacements(&controlled), 0, "the transfer completed");
    let _ = controlled.events().await;

    controlled.caller_refers(8);
    assert!(wire(&controlled.call.dispatcher).is_empty(), "held");
    assert_eq!(controlled.events().await, ["TransferRequested"]);
    assert_eq!(controlled.state().pending_inbound_refer.len(), 1);
}

/// On a call its script decides for, a REFER arriving while the transfer the
/// script accepted is in flight is refused before `@b2bua.on_refer` runs: the
/// handler here accepts every REFER, and nobody is dialled a second time.
#[tokio::test(flavor = "multi_thread")]
async fn a_script_is_not_shown_a_refer_while_its_transfer_is_in_flight() {
    let call = establish(10300, "terminate");
    let _ = wire(&call.dispatcher);
    let callee_refers = |cseq: u32| {
        refer(
            None,
            &call,
            call.b.1,
            &format!("{};tag=b-tag", header(&call.to_b, "To")),
            &header(&call.to_b, "From"),
            &header(&call.to_b, "Call-ID"),
            cseq,
        )
    };
    let accepted = [
        format!("202 {}", call.b.1),
        format!("NOTIFY {}", call.b.1),
        format!("INVITE {}", call.c.1),
    ];
    callee_refers(2);
    let sent = wire(&call.dispatcher);
    assert_eq!(summaries(&sent), accepted);
    let to_c = sent_to(&sent, call.c.1, Method::Invite).expect("the target is dialled");

    callee_refers(3);
    let refused = wire(&call.dispatcher);
    assert_eq!(summaries(&refused), [format!("491 {}", call.b.1)]);
    assert_eq!(header(&refused[0].message, "CSeq"), "3 REFER");

    // The target refuses: the transfer is over, and the next REFER is the
    // script's to decide again.
    responds(
        &call.dispatcher,
        &call.call_id(),
        call.c.1,
        &to_c,
        486,
        "Busy Here",
        "c-tag",
    );
    let _ = wire(&call.dispatcher);
    callee_refers(4);
    assert_eq!(summaries(&wire(&call.dispatcher)), accepted);
}

/// A REFER relayed to the far end is a transfer in flight until the far end
/// answers it: another REFER meanwhile is refused `491` and not relayed. Once
/// the far end has answered, a new REFER is relayed as the first was.
#[tokio::test(flavor = "multi_thread")]
async fn a_refer_is_refused_while_a_relayed_refer_awaits_the_far_end() {
    let call = establish(10350, "transparent");
    let _ = wire(&call.dispatcher);
    let (a, b) = (call.a.1, call.b.1);
    let callee_refers = |cseq: u32| {
        refer(
            None,
            &call,
            b,
            &format!("{};tag=b-tag", header(&call.to_b, "To")),
            &header(&call.to_b, "From"),
            &header(&call.to_b, "Call-ID"),
            cseq,
        )
    };
    callee_refers(2);
    let sent = wire(&call.dispatcher);
    assert_eq!(summaries(&sent), [format!("REFER {a}")]);
    let relayed = sent_to(&sent, a, Method::Refer).expect("the relayed REFER");

    callee_refers(3);
    let refused = wire(&call.dispatcher);
    assert_eq!(
        summaries(&refused),
        [format!("491 {b}")],
        "refused, and not relayed"
    );
    assert_eq!(header(&refused[0].message, "CSeq"), "3 REFER");

    responds(
        &call.dispatcher,
        &call.call_id(),
        a,
        &relayed,
        202,
        "Accepted",
        "a-tag",
    );
    assert_eq!(summaries(&wire(&call.dispatcher)), [format!("202 {b}")]);

    callee_refers(4);
    assert_eq!(
        summaries(&wire(&call.dispatcher)),
        [format!("REFER {a}")],
        "the far end has answered: a new REFER is relayed"
    );
}

/// A `replace_peer` in flight is a transfer in flight: a REFER on the call is
/// refused `491` until its target has refused, and is then taken.
#[tokio::test(flavor = "multi_thread")]
async fn a_refer_is_refused_while_a_replace_peer_is_in_flight() {
    let controlled = controlled(10400);
    let state = controlled.state();
    let c = controlled.call.c.1;

    let started = tokio::task::block_in_place(|| {
        b2bua_replace_peer_with_state(
            state,
            &controlled.call.a_call_id,
            &controlled.call.c_uri(),
            None,
            false,
            None,
            None,
            30,
            &ReplacementDial::default(),
        )
    });
    assert!(started.is_ok(), "{started:?}");
    let to_c = sent_to(&wire(&controlled.call.dispatcher), c, Method::Invite)
        .expect("the target is dialled");
    let _ = controlled.events().await;

    controlled.assert_callee_refer_refused(2).await;
    assert_eq!(replacements(&controlled), 1, "the replacement rings on");

    controlled.target_responds(&to_c, 486);
    let _ = wire(&controlled.call.dispatcher);
    assert_eq!(replacements(&controlled), 0, "the replacement failed");
    let _ = controlled.events().await;

    controlled.assert_callee_refer_taken(3).await;
}

/// A REFER relayed to the far end is not relayed a second time when it is
/// retransmitted: while the far end has not answered the retransmission is
/// absorbed, and once it has, the response relayed then is sent again.
#[tokio::test(flavor = "multi_thread")]
async fn a_relayed_refer_is_relayed_once_and_its_response_repeated() {
    let controlled = controlled(9750);
    let (a, b) = (controlled.call.a.1, controlled.call.b.1);

    controlled.callee_refers(2);
    assert_eq!(controlled.events().await, ["TransferRequested"]);
    assert!(controlled.accept(ReferMode::Transparent));
    let sent = wire(&controlled.call.dispatcher);
    assert_eq!(summaries(&sent), [format!("REFER {a}")]);
    let relayed = sent_to(&sent, a, Method::Refer).expect("the relayed REFER");

    // Retransmitted before the far end answered: its transaction is still
    // proceeding, so there is nothing to send and nothing to start again.
    controlled.callee_refers(2);
    assert!(
        wire(&controlled.call.dispatcher).is_empty(),
        "not relayed a second time"
    );
    assert!(controlled.events().await.is_empty());
    assert_eq!(controlled.state().pending_inbound_refer.len(), 0);

    responds(
        &controlled.call.dispatcher,
        &controlled.call_id,
        a,
        &relayed,
        202,
        "Accepted",
        "a-tag",
    );
    let sent = wire(&controlled.call.dispatcher);
    assert_eq!(summaries(&sent), [format!("202 {b}")]);
    assert_eq!(header(&sent[0].message, "CSeq"), "2 REFER");
    let accepted = sent[0].message.to_bytes();

    controlled.callee_refers(2);
    let again = wire(&controlled.call.dispatcher);
    assert_eq!(summaries(&again), [format!("202 {b}")]);
    assert_eq!(again[0].message.to_bytes(), accepted);
    assert!(controlled.events().await.is_empty());
}

/// A REFER that was rejected, or declined at its decision deadline, gets that
/// response again when retransmitted, and a REFER with a new CSeq is a new
/// request: it is held and reported.
#[tokio::test(flavor = "multi_thread")]
async fn a_rejected_refer_is_rejected_again_and_a_new_one_is_a_new_request() {
    let controlled = controlled(9800);
    let state = controlled.state();
    let b = controlled.call.b.1;

    controlled.callee_refers(2);
    assert_eq!(controlled.events().await, ["TransferRequested"]);
    assert!(tokio::task::block_in_place(|| {
        b2bua_reject_refer_with_state(state, &controlled.call.a_call_id, 486, "Busy Here")
    }));
    assert_eq!(
        summaries(&wire(&controlled.call.dispatcher)),
        [format!("486 {b}")]
    );
    controlled.callee_refers(2);
    let again = wire(&controlled.call.dispatcher);
    assert_eq!(summaries(&again), [format!("486 {b}")]);
    assert_eq!(header(&again[0].message, "CSeq"), "2 REFER");
    assert!(controlled.events().await.is_empty());
    assert_eq!(state.pending_inbound_refer.len(), 0);

    // A new CSeq is a new REFER. Left undecided, the deadline declines it, and
    // its retransmission is declined the same way without being held again.
    controlled.callee_refers(3);
    assert_eq!(controlled.events().await, ["TransferRequested"]);
    assert!(wire(&controlled.call.dispatcher).is_empty());
    state
        .pending_inbound_refer
        .entries
        .get_mut(&controlled.call_id)
        .expect("the held REFER")
        .deadline = std::time::Instant::now() - std::time::Duration::from_secs(1);
    tokio::task::block_in_place(|| check_pending_inbound_refer_timeouts(state));
    let declined = wire(&controlled.call.dispatcher);
    assert_eq!(summaries(&declined), [format!("603 {b}")]);
    assert_eq!(header(&declined[0].message, "CSeq"), "3 REFER");
    assert_eq!(state.pending_inbound_refer.len(), 0);

    controlled.callee_refers(3);
    assert_eq!(
        summaries(&wire(&controlled.call.dispatcher)),
        [format!("603 {b}")]
    );
    assert!(controlled.events().await.is_empty());
    assert_eq!(state.pending_inbound_refer.len(), 0);
}

/// On a call no application owns, the script accepts the REFER. Retransmitted,
/// it is answered `202` again and the script is not run for it a second time,
/// which would dial the target twice.
#[tokio::test(flavor = "multi_thread")]
async fn a_scripts_accepted_refer_is_not_carried_out_twice() {
    let call = establish(9850, "terminate");
    let _ = wire(&call.dispatcher);
    let callee_refers = || {
        refer(
            None,
            &call,
            call.b.1,
            &format!("{};tag=b-tag", header(&call.to_b, "To")),
            &header(&call.to_b, "From"),
            &header(&call.to_b, "Call-ID"),
            2,
        )
    };
    callee_refers();
    assert_eq!(
        summaries(&wire(&call.dispatcher)),
        [
            format!("202 {}", call.b.1),
            format!("NOTIFY {}", call.b.1),
            format!("INVITE {}", call.c.1)
        ]
    );
    callee_refers();
    assert_eq!(
        summaries(&wire(&call.dispatcher)),
        [format!("202 {}", call.b.1)],
        "answered again, and nobody dialled again"
    );
}

/// The referrer hangs up while its REFER awaits a decision: the REFER is
/// answered `487` (RFC 3261 §15.1.2), its BYE `200`, and nothing stays held.
/// An accept that arrives afterwards finds nothing and sends nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_referrer_that_hangs_up_has_its_pending_refer_answered() {
    let controlled = controlled(9900);
    let state = controlled.state();
    let b = controlled.call.b.1;

    controlled.callee_refers(2);
    assert_eq!(state.pending_inbound_refer.len(), 1);
    controlled.callee_hangs_up();
    let sent = wire(&controlled.call.dispatcher);
    let terminated = sent
        .iter()
        .find(|sent| sent.destination == b && sent.message.status_code() == Some(487))
        .unwrap_or_else(|| panic!("the REFER is answered: {:?}", summaries(&sent)));
    assert_eq!(header(&terminated.message, "CSeq"), "2 REFER");
    assert!(summaries(&sent).contains(&format!("200 {b}")), "the BYE");
    assert_eq!(state.pending_inbound_refer.len(), 0, "nothing stays held");
    assert_eq!(state.call_actors.count(), 0);

    assert!(!controlled.accept(ReferMode::Terminate));
    assert!(wire(&controlled.call.dispatcher).is_empty());
    assert_eq!(state.answered_refers.len(), 0);
}

/// The other party hangs up while the REFER awaits a decision. The referrer's
/// dialog is still up when that happens, so its REFER gets a final response
/// before its BYE, nobody is dialled, and nothing stays held.
#[tokio::test(flavor = "multi_thread")]
async fn a_pending_refer_is_declined_when_the_other_party_hangs_up() {
    let controlled = controlled(9950);
    let state = controlled.state();
    let b = controlled.call.b.1;

    controlled.callee_refers(2);
    controlled.caller_hangs_up();
    let summary = summaries(&wire(&controlled.call.dispatcher));
    let declined = summary.iter().position(|line| *line == format!("603 {b}"));
    let released = summary.iter().position(|line| *line == format!("BYE {b}"));
    assert!(
        declined.is_some() && declined < released,
        "the REFER is answered ahead of the BYE that ends its dialog: {summary:?}"
    );
    assert!(
        !summary.iter().any(|line| line.starts_with("INVITE")),
        "{summary:?}"
    );
    assert_eq!(state.pending_inbound_refer.len(), 0, "nothing stays held");

    assert!(!controlled.accept(ReferMode::Terminate));
    assert!(wire(&controlled.call.dispatcher).is_empty());
}

/// A framework teardown (a script's `terminate`, a session timer) ends a call
/// with a REFER held the same way: answered, and released.
#[tokio::test(flavor = "multi_thread")]
async fn a_pending_refer_is_declined_when_the_call_is_torn_down() {
    let controlled = controlled(10000);
    let state = controlled.state();
    let b = controlled.call.b.1;

    controlled.callee_refers(2);
    assert!(tokio::task::block_in_place(|| {
        b2bua_terminate_call_inner(&controlled.call_id, None, "b2bua", state)
    }));
    let summary = summaries(&wire(&controlled.call.dispatcher));
    let declined = summary.iter().position(|line| *line == format!("603 {b}"));
    let released = summary.iter().position(|line| *line == format!("BYE {b}"));
    assert!(declined.is_some() && declined < released, "{summary:?}");
    assert_eq!(state.pending_inbound_refer.len(), 0);
}

/// A call that went without passing a teardown that answers its held REFER
/// still has it answered: by the accept that finds the call gone (`481`), and
/// otherwise by the decision deadline (`603`). Either way the entry goes.
#[tokio::test(flavor = "multi_thread")]
async fn a_refer_whose_call_is_gone_is_answered_by_the_accept_or_the_deadline() {
    let controlled = controlled(10050);
    let state = controlled.state();
    let b = controlled.call.b.1;

    controlled.callee_refers(2);
    state.call_actors.remove_call(&controlled.call_id);
    assert!(!controlled.accept(ReferMode::Terminate));
    let sent = wire(&controlled.call.dispatcher);
    assert_eq!(summaries(&sent), [format!("481 {b}")]);
    assert_eq!(header(&sent[0].message, "CSeq"), "2 REFER");
    assert_eq!(state.pending_inbound_refer.len(), 0);

    // The application never answers at all.
    let other = controlled_at_deadline(10100);
    tokio::task::block_in_place(|| check_pending_inbound_refer_timeouts(other.state()));
    assert_eq!(
        summaries(&wire(&other.call.dispatcher)),
        [format!("603 {}", other.call.b.1)]
    );
    assert_eq!(other.state().pending_inbound_refer.len(), 0);
    assert!(!other.accept(ReferMode::Terminate));
    assert!(wire(&other.call.dispatcher).is_empty());
}

/// A controlled call with a REFER held past its decision deadline, the sweep
/// not yet run.
fn controlled_at_deadline(prefix: u32) -> Controlled {
    let controlled = controlled(prefix);
    controlled.callee_refers(2);
    // Not due yet: the sweep leaves it alone.
    tokio::task::block_in_place(|| check_pending_inbound_refer_timeouts(controlled.state()));
    assert!(wire(&controlled.call.dispatcher).is_empty());
    assert_eq!(controlled.state().pending_inbound_refer.len(), 1);
    controlled
        .state()
        .pending_inbound_refer
        .entries
        .get_mut(&controlled.call_id)
        .expect("the held REFER")
        .deadline = std::time::Instant::now() - std::time::Duration::from_secs(1);
    controlled
}

/// A party that takes one side of a call over with an INVITE carrying
/// `Replaces` (RFC 3891), from a phone at `address`.
struct Newcomer {
    aor: &'static str,
    address: &'static str,
    call_id: &'static str,
    /// The 200 siphon answered its INVITE with.
    answered: SipMessage,
}

impl Controlled {
    /// A new party takes over the caller's side of the call when
    /// `replace_caller`, the callee's otherwise. The newcomer holds the call's
    /// A-leg slot afterwards, on a Call-ID of its own, and the call's control
    /// channel follows it there, as it does on a running control plane.
    fn taken_over(&self, replace_caller: bool) -> Newcomer {
        let (aor, address, call_id) = (
            "sip:takeover@example.com",
            "192.0.2.199:5060",
            "takeover@192.0.2.199",
        );
        register(aor, address);
        let replaces = if replace_caller {
            format!(
                "Replaces: {};to-tag={};from-tag=a-tag\r\n",
                self.call.a_call_id,
                tag_of(&header(&self.call.answer_to_a, "To"))
            )
        } else {
            format!(
                "Replaces: {};to-tag={};from-tag=b-tag\r\n",
                header(&self.call.to_b, "Call-ID"),
                tag_of(&header(&self.call.to_b, "From"))
            )
        };
        let previous = self.call.a_call_id.clone();
        place(
            &self.call.dispatcher,
            address,
            &invite(
                address,
                call_id,
                &format!("<{aor}>;tag=d-tag"),
                "sip:takeover@siphon.example.com",
                &replaces,
            ),
        );
        channel_follows_a_leg(&self.bus, self.state(), &self.call_id, &previous);
        let sent = wire(&self.call.dispatcher);
        let answered = response_to_phone(&sent, address, 200);
        // A replaced callee is released at once. A replaced caller that has
        // not ACKed its own 2xx gets its BYE behind that ACK (RFC 3261 §15),
        // so nothing is read for it here.
        if !replace_caller {
            assert!(
                sent_to(&sent, self.call.b.1, Method::Bye).is_some(),
                "the replaced callee is released: {:?}",
                summaries(&sent)
            );
        }
        let a_leg = self
            .state()
            .call_actors
            .get_call(&self.call_id)
            .map(|call| call.a_leg.dialog.call_id.clone());
        assert_eq!(
            a_leg.as_deref(),
            Some(call_id),
            "the newcomer holds the A-leg"
        );
        assert!(
            self.bus.channel_id_for_sip_call_id(call_id).is_some(),
            "the channel follows the call to the newcomer's dialog"
        );
        Newcomer {
            aor,
            address,
            call_id,
            answered,
        }
    }
}

impl Newcomer {
    fn hangs_up(&self, controlled: &Controlled) {
        hang_up(
            &controlled.call.dispatcher,
            self.address,
            &format!("<{}>;tag=d-tag", self.aor),
            &header(&self.answered, "To"),
            self.call_id,
        );
    }
}

/// The callee's REFER is held, and a new party takes the caller's place: the
/// call's A-leg is now the newcomer's dialog, on another Call-ID. The held
/// REFER belongs to the call, not to that Call-ID, so the newcomer hanging up
/// still has it answered ahead of the BYE that ends its sender's dialog, and
/// nothing stays held.
#[tokio::test(flavor = "multi_thread")]
async fn a_refer_held_across_a_takeover_of_the_caller_is_answered_when_the_call_ends() {
    let controlled = controlled(10450);
    let state = controlled.state();
    let b = controlled.call.b.1;

    controlled.callee_refers(2);
    assert_eq!(state.pending_inbound_refer.len(), 1);
    let newcomer = controlled.taken_over(true);
    assert_eq!(
        state.pending_inbound_refer.len(),
        1,
        "still awaiting a decision"
    );

    newcomer.hangs_up(&controlled);
    let summary = summaries(&wire(&controlled.call.dispatcher));
    let declined = summary.iter().position(|line| *line == format!("603 {b}"));
    let released = summary.iter().position(|line| *line == format!("BYE {b}"));
    assert!(
        declined.is_some() && declined < released,
        "the REFER is answered ahead of the BYE that ends its dialog: {summary:?}"
    );
    assert_eq!(state.pending_inbound_refer.len(), 0, "nothing stays held");
    assert_eq!(state.call_actors.count(), 0);
}

/// After the same takeover the application decides, naming the call by its
/// channel, which now stands on the newcomer's Call-ID: the held REFER is
/// found and carried out, on the referrer's own dialog.
#[tokio::test(flavor = "multi_thread")]
async fn a_refer_held_across_a_takeover_is_still_decided_by_its_channel() {
    let controlled = controlled(10500);
    let state = controlled.state();
    let (b, c) = (controlled.call.b.1, controlled.call.c.1);

    controlled.callee_refers(2);
    let newcomer = controlled.taken_over(true);
    let accepted = tokio::task::block_in_place(|| {
        b2bua_accept_refer_with_state(
            state,
            newcomer.call_id,
            None,
            None,
            Some(ReferMode::Terminate),
            None,
            None,
            &ReplacementDial::default(),
        )
    });
    assert!(accepted, "the REFER is found by the channel's Call-ID");
    let sent = summaries(&wire(&controlled.call.dispatcher));
    assert!(sent.contains(&format!("202 {b}")), "{sent:?}");
    assert!(sent.contains(&format!("INVITE {c}")), "{sent:?}");
    assert_eq!(state.pending_inbound_refer.len(), 0);
}

/// The caller's REFER is held, and a new party takes the callee's place. The
/// takeover moves the caller to the call's other slot. Its REFER is still its
/// own: when the caller hangs up, the REFER is answered `487` ahead of the
/// BYE's `200` (RFC 3261 §15.1.2), and nothing stays held.
#[tokio::test(flavor = "multi_thread")]
async fn a_refer_follows_its_sender_when_a_takeover_moves_it_to_the_other_leg() {
    let controlled = controlled(10550);
    let state = controlled.state();
    let a = controlled.call.a.1;

    controlled.caller_refers(2);
    assert_eq!(state.pending_inbound_refer.len(), 1);
    let _newcomer = controlled.taken_over(false);
    assert_eq!(state.pending_inbound_refer.len(), 1);

    controlled.caller_hangs_up();
    let sent = wire(&controlled.call.dispatcher);
    let terminated = sent
        .iter()
        .position(|sent| sent.destination == a && sent.message.status_code() == Some(487))
        .unwrap_or_else(|| panic!("the REFER is answered: {:?}", summaries(&sent)));
    assert_eq!(header(&sent[terminated].message, "CSeq"), "2 REFER");
    let bye_answered = sent
        .iter()
        .position(|sent| sent.destination == a && sent.message.status_code() == Some(200));
    assert!(Some(terminated) < bye_answered, "{:?}", summaries(&sent));
    assert_eq!(state.pending_inbound_refer.len(), 0, "nothing stays held");
}

/// Accepted after such a takeover, the transfer replaces the party the
/// referrer is talking to now, and the referrer is the one it reports to: the
/// leg the REFER came from is read off the REFER's own dialog, not off where
/// that dialog sat when the REFER arrived.
#[tokio::test(flavor = "multi_thread")]
async fn a_refer_accepted_after_a_takeover_names_its_sender_as_the_referrer() {
    let controlled = controlled(10600);
    let state = controlled.state();
    let (a, c) = (controlled.call.a.1, controlled.call.c.1);

    controlled.caller_refers(2);
    let newcomer = controlled.taken_over(false);
    let accepted = tokio::task::block_in_place(|| {
        b2bua_accept_refer_with_state(
            state,
            newcomer.call_id,
            None,
            None,
            Some(ReferMode::Terminate),
            None,
            None,
            &ReplacementDial::default(),
        )
    });
    assert!(accepted);
    let sent = wire(&controlled.call.dispatcher);
    let summary = summaries(&sent);
    assert!(summary.contains(&format!("202 {a}")), "{summary:?}");
    assert!(summary.contains(&format!("NOTIFY {a}")), "{summary:?}");
    assert!(summary.contains(&format!("INVITE {c}")), "{summary:?}");
    let notify = sent_to(&sent, a, Method::Notify).expect("the first NOTIFY");
    assert_eq!(
        header(&notify, "Call-ID"),
        controlled.call.a_call_id,
        "on the referrer's own dialog"
    );
    let referrer_on_a_leg = state
        .call_actors
        .get_call(&controlled.call_id)
        .and_then(|call| {
            call.refer_subscriptions
                .first()
                .map(|subscription| subscription.on_a_leg)
        });
    assert_eq!(
        referrer_on_a_leg,
        Some(false),
        "the referrer sits on the callee's side of the call now"
    );
}

/// The referrer itself is the party taken over: its dialog is ended by siphon,
/// so its held REFER is answered `487` ahead of that BYE and released.
#[tokio::test(flavor = "multi_thread")]
async fn a_referrer_that_is_taken_over_has_its_held_refer_answered() {
    let controlled = controlled(10650);
    let state = controlled.state();
    let b = controlled.call.b.1;

    controlled.callee_refers(2);
    assert_eq!(state.pending_inbound_refer.len(), 1);
    let (aor, address, call_id) = (
        "sip:takeover@example.com",
        "192.0.2.199:5060",
        "takeover-referrer@192.0.2.199",
    );
    register(aor, address);
    place(
        &controlled.call.dispatcher,
        address,
        &invite(
            address,
            call_id,
            &format!("<{aor}>;tag=d-tag"),
            "sip:takeover@siphon.example.com",
            &format!(
                "Replaces: {};to-tag={};from-tag=b-tag\r\n",
                header(&controlled.call.to_b, "Call-ID"),
                tag_of(&header(&controlled.call.to_b, "From"))
            ),
        ),
    );
    let summary = summaries(&wire(&controlled.call.dispatcher));
    let terminated = summary.iter().position(|line| *line == format!("487 {b}"));
    let released = summary.iter().position(|line| *line == format!("BYE {b}"));
    assert!(
        terminated.is_some() && terminated < released,
        "the REFER is answered ahead of the BYE that ends its dialog: {summary:?}"
    );
    assert_eq!(state.pending_inbound_refer.len(), 0, "nothing stays held");
}

impl Controlled {
    /// A `replace_peer` of the caller when `replace_caller`, of the callee
    /// otherwise, by the call's phone C, which answers.
    fn peer_replaced(&self, replace_caller: bool) {
        let started = tokio::task::block_in_place(|| {
            b2bua_replace_peer_with_state(
                self.state(),
                &self.call.a_call_id,
                &self.call.c_uri(),
                None,
                replace_caller,
                None,
                None,
                30,
                &ReplacementDial::default(),
            )
        });
        assert!(started.is_ok(), "{started:?}");
        let to_c = sent_to(&wire(&self.call.dispatcher), self.call.c.1, Method::Invite)
            .expect("the target is dialled");
        self.target_responds(&to_c, 200);
    }
}

/// The callee's REFER is held and the caller is replaced with `replace_peer`:
/// the target takes the A-leg slot on a Call-ID of its own. The call ending
/// still answers the REFER ahead of the BYE to its sender, and nothing stays
/// held.
#[tokio::test(flavor = "multi_thread")]
async fn a_refer_held_across_a_replacement_of_the_caller_is_answered_when_the_call_ends() {
    let controlled = controlled(10700);
    let state = controlled.state();
    let b = controlled.call.b.1;

    controlled.callee_refers(2);
    controlled.peer_replaced(true);
    let _ = wire(&controlled.call.dispatcher);
    let a_leg = state
        .call_actors
        .get_call(&controlled.call_id)
        .map(|call| call.a_leg.dialog.call_id.clone());
    assert_ne!(a_leg.as_deref(), Some(controlled.call.a_call_id.as_str()));
    assert_eq!(
        state.pending_inbound_refer.len(),
        1,
        "still awaiting a decision"
    );

    assert!(tokio::task::block_in_place(|| {
        b2bua_terminate_call_inner(&controlled.call_id, None, "b2bua", state)
    }));
    let summary = summaries(&wire(&controlled.call.dispatcher));
    let declined = summary.iter().position(|line| *line == format!("603 {b}"));
    let released = summary.iter().position(|line| *line == format!("BYE {b}"));
    assert!(declined.is_some() && declined < released, "{summary:?}");
    assert_eq!(state.pending_inbound_refer.len(), 0, "nothing stays held");
}

/// The callee's REFER is held and the callee itself is replaced with
/// `replace_peer`: its REFER is answered `487` ahead of the BYE that releases
/// it once the target has answered, and nothing stays held.
#[tokio::test(flavor = "multi_thread")]
async fn a_referrer_that_is_replaced_has_its_held_refer_answered() {
    let controlled = controlled(10750);
    let state = controlled.state();
    let b = controlled.call.b.1;

    controlled.callee_refers(2);
    assert_eq!(state.pending_inbound_refer.len(), 1);
    controlled.peer_replaced(false);
    let summary = summaries(&wire(&controlled.call.dispatcher));
    let terminated = summary.iter().position(|line| *line == format!("487 {b}"));
    let released = summary.iter().position(|line| *line == format!("BYE {b}"));
    assert!(
        terminated.is_some() && terminated < released,
        "the REFER is answered ahead of the BYE that ends its dialog: {summary:?}"
    );
    assert_eq!(state.pending_inbound_refer.len(), 0, "nothing stays held");
}

/// The call a script is handed in `@b2bua.on_refer` is the same call it was
/// handed in every other handler: `call.source_ip`, and so `from_gateway()`
/// and `source_ip_in()`, name where the caller came from. Which party sent
/// the REFER is `call.refer_side`. A REFER from the callee used to put the
/// callee's address there, so a script that told the two trunks of an SBC
/// apart by the caller's source read a transfer by the callee the wrong way
/// round.
#[tokio::test(flavor = "multi_thread")]
async fn on_refer_sees_the_callers_source_whichever_party_refers() {
    for (index, from_a_leg) in [true, false].into_iter().enumerate() {
        let call = establish_deciding(
            48000 + 10 * index as u32,
            "call.reject_refer(486, call.source_ip + ' ' + call.refer_side)",
        );
        let _ = wire(&call.dispatcher);

        refers(&call, from_a_leg, "203.0.113.250:5060");

        let referrer = if from_a_leg { call.a.1 } else { call.b.1 };
        let refused = response_to_phone(&wire(&call.dispatcher), referrer, 486);
        let StartLine::Response(status) = &refused.start_line else {
            panic!("a response");
        };
        let side = if from_a_leg { "a" } else { "b" };
        assert_eq!(
            status.reason_phrase,
            format!("{} {side}", host_of(call.a.1)),
            "a REFER from the {side} leg"
        );
    }
}
