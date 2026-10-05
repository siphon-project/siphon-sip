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

use super::dialog_state_events_tests::{header, inbound, responds, wire, Sent};
use super::dialog_state_transfer_tests::{
    control_plane, establish, hang_up, in_dialog, sent_to, Established,
};
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

    // A REFER with a new CSeq is not a retransmission, whatever the first is
    // doing: it is a request of its own, held for a decision of its own.
    controlled.callee_refers(3);
    assert!(wire(&controlled.call.dispatcher).is_empty());
    assert_eq!(controlled.events().await, ["TransferRequested"]);
    assert_eq!(controlled.state().pending_inbound_refer.len(), 1);
    // And while that one is undecided, a third is refused `491`, as before.
    controlled.callee_refers(4);
    let busy = wire(&controlled.call.dispatcher);
    assert_eq!(summaries(&busy), [format!("491 {b}")]);
    assert_eq!(header(&busy[0].message, "CSeq"), "4 REFER");
    assert!(controlled.events().await.is_empty());

    // The call ends: the held REFER is answered, and nothing is left that
    // remembers any of them.
    controlled.caller_hangs_up();
    let ended = summaries(&wire(&controlled.call.dispatcher));
    assert!(ended.contains(&format!("603 {b}")), "{ended:?}");
    assert_eq!(controlled.state().pending_inbound_refer.len(), 0);
    assert_eq!(controlled.state().call_actors.count(), 0);
    assert_eq!(controlled.state().answered_refers.len(), 0);
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
        .get_mut(&controlled.call.a_call_id)
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
        .get_mut(&controlled.call.a_call_id)
        .expect("the held REFER")
        .deadline = std::time::Instant::now() - std::time::Duration::from_secs(1);
    controlled
}
