//! Every B-leg a controller-issued `dial` rings is named to the controller.
//!
//! Each branch is its own SIP dialog with a Call-ID siphon generated, and nothing
//! else ties it back to the call the controller owns. Without these events a
//! controller that also sees the signalling cannot associate the legs with its
//! call: not which branch answered, which one was busy, or what each said.
//!
//! Driven through the dispatcher's own `dial` entry point on a test dispatcher.
//! Responses go in through [`handle_b2bua_response`], ring timeouts through
//! [`check_b2bua_answer_timeouts_at`], and what siphon sent is read back off the
//! UDP egress, so every Call-ID an event names is checked against the INVITE
//! that actually carried it.

use super::lcr_ring_timeout_tests::{carrier_response, summaries, top_via_branch, Sent};
use super::test_dispatcher::{test_dispatcher, TestDispatcher};
use super::*;
use crate::control::channel_event_capture;
use std::time::{Duration, Instant};

const CALLER: &str = "192.0.2.10:5060";
const FIRST_TARGET: &str = "198.51.100.7:5060";
const SECOND_TARGET: &str = "198.51.100.8:5060";

/// A caller INVITE with `sip_call_id`, unique to each test so the events one
/// test captures are its own.
fn caller_invite(sip_call_id: &str) -> SipMessage {
    let raw = format!(
        concat!(
            "INVITE sip:15550100077@siphon.example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-dial-branches\r\n",
            "Max-Forwards: 70\r\n",
            "From: <sip:15550100042@example.com>;tag=caller-tag\r\n",
            "To: <sip:15550100077@siphon.example.com>\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: 1 INVITE\r\n",
            "Contact: <sip:15550100042@192.0.2.10:5060>\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        call_id = sip_call_id,
    );
    parse_sip_message_bytes(raw.as_bytes()).expect("the caller INVITE parses")
}

/// A caller parked under external control with nothing dialed yet, its channel
/// events captured.
struct Parked {
    dispatcher: TestDispatcher,
    call_id: String,
    sip_call_id: String,
}

fn park(sip_call_id: &str) -> Parked {
    let dispatcher = test_dispatcher();
    let call_id = dispatcher.state.call_actors.create_call(Leg::new_a_leg(
        sip_call_id.to_string(),
        "caller-tag".to_string(),
        "z9hG4bK-dial-branches".to_string(),
        LegTransport {
            remote_addr: CALLER.parse().expect("a literal address"),
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: None,
        },
    ));
    dispatcher
        .state
        .call_actors
        .set_a_leg_invite(&call_id, Arc::new(Mutex::new(caller_invite(sip_call_id))));
    channel_event_capture::watch(sip_call_id);
    Parked {
        dispatcher,
        call_id,
        sip_call_id: sip_call_id.to_string(),
    }
}

impl Parked {
    fn dial(&self, addresses: &[&str], parallel: bool) {
        let targets = addresses
            .iter()
            .map(|address| DialTarget {
                uri: target_uri(address),
                ..Default::default()
            })
            .collect();
        let dialled = b2bua_dial_call_with_state(
            &self.sip_call_id,
            targets,
            parallel,
            30,
            &[],
            &DialShaping::default(),
            &self.dispatcher.state,
        )
        .expect("the dial runs");
        assert!(dialled, "the dial found its call");
    }

    fn wire(&self) -> Vec<Sent> {
        let mut sent = Vec::new();
        while let Ok(outbound) = self.dispatcher.udp.try_recv() {
            sent.push(Sent {
                destination: outbound.destination,
                message: parse_sip_message_bytes(&outbound.data)
                    .expect("siphon sent a message that parses"),
            });
        }
        sent
    }

    /// The INVITEs among what siphon has sent since the last look, by the
    /// address they went to.
    fn invites(&self) -> Vec<(String, SipMessage)> {
        self.wire()
            .into_iter()
            .filter(|sent| {
                matches!(&sent.message.start_line, StartLine::Request(_))
                    && sent
                        .message
                        .headers
                        .cseq()
                        .is_some_and(|cseq| cseq.ends_with("INVITE"))
            })
            .map(|sent| (sent.destination.to_string(), sent.message))
            .collect()
    }

    /// The target at `address` sends `status_code` for its `invite`.
    fn responds(&self, address: &str, invite: &SipMessage, status_code: u16, reason: &str) {
        let mut response = carrier_response(invite, status_code, reason);
        let handled = handle_b2bua_response(
            &self.call_id,
            &top_via_branch(invite),
            &mut response,
            status_code,
            address.parse().expect("a literal address"),
            &self.dispatcher.state,
        );
        assert!(handled, "the call was gone when the {status_code} arrived");
    }

    /// The channel events published since the last look.
    fn events(&self) -> Vec<(String, serde_json::Value)> {
        channel_event_capture::take(&self.sip_call_id)
    }
}

fn target_uri(address: &str) -> String {
    format!("sip:15550100077@{address}")
}

fn call_id_of(message: &SipMessage) -> String {
    message
        .headers
        .get("Call-ID")
        .map(|value| value.to_string())
        .expect("every INVITE carries a Call-ID")
}

/// The events named `name`, in order.
fn named<'a>(events: &'a [(String, serde_json::Value)], name: &str) -> Vec<&'a serde_json::Value> {
    events
        .iter()
        .filter(|(event, _)| event == name)
        .map(|(_, payload)| payload)
        .collect()
}

fn text<'a>(payload: &'a serde_json::Value, field: &str) -> &'a str {
    payload[field]
        .as_str()
        .unwrap_or_else(|| panic!("no string `{field}` in {payload}"))
}

/// The one `DialBranch` naming the leg whose INVITE carried `sip_call_id`.
fn branch_named<'a>(
    events: &'a [(String, serde_json::Value)],
    sip_call_id: &str,
) -> &'a serde_json::Value {
    let matching: Vec<_> = named(events, "DialBranch")
        .into_iter()
        .filter(|payload| payload["leg_sip_call_id"] == sip_call_id)
        .collect();
    assert_eq!(
        matching.len(),
        1,
        "exactly one DialBranch names {sip_call_id}: {events:?}"
    );
    matching[0]
}

/// A parallel fork names every branch as it is created, each by the Call-ID its
/// INVITE actually went out with and a leg id of its own.
#[tokio::test(flavor = "multi_thread")]
async fn a_parallel_dial_names_every_branch_with_the_call_id_on_the_wire() {
    let parked = park("dial-branches-fork@192.0.2.10");
    parked.dial(&[FIRST_TARGET, SECOND_TARGET], true);

    let invites = parked.invites();
    assert_eq!(invites.len(), 2, "both branches rang");
    let events = parked.events();
    assert_eq!(
        named(&events, "DialBranch").len(),
        2,
        "one DialBranch per branch: {events:?}"
    );
    let mut leg_ids = Vec::new();
    for (address, invite) in &invites {
        let branch = branch_named(&events, &call_id_of(invite));
        assert_eq!(text(branch, "target"), target_uri(address));
        assert_ne!(
            text(branch, "leg_sip_call_id"),
            parked.sip_call_id,
            "a branch is its own dialog, not the caller's"
        );
        leg_ids.push(text(branch, "leg_id").to_string());
    }
    assert!(!leg_ids[0].is_empty());
    assert_ne!(leg_ids[0], leg_ids[1], "each branch has its own leg id");
}

/// A sequential hunt names each later attempt at the moment it is placed, not
/// only the first, and names the attempt it moved on from with its failure.
#[tokio::test(flavor = "multi_thread")]
async fn a_sequential_dial_names_the_next_attempt_when_it_is_placed() {
    let parked = park("dial-branches-hunt@192.0.2.10");
    parked.dial(&[FIRST_TARGET, SECOND_TARGET], false);

    let first = parked.invites();
    assert_eq!(
        first.len(),
        1,
        "a sequential dial rings one target at a time"
    );
    let first_call_id = call_id_of(&first[0].1);
    let events = parked.events();
    let first_leg = text(branch_named(&events, &first_call_id), "leg_id").to_string();

    // A server failure is what moves a hunt on by default; a busy callee is a
    // definitive outcome that ends it.
    parked.responds(FIRST_TARGET, &first[0].1, 503, "Service Unavailable");

    let second = parked.invites();
    assert_eq!(
        second
            .iter()
            .map(|(address, _)| address.as_str())
            .collect::<Vec<_>>(),
        [SECOND_TARGET],
        "the hunt moved on to the second target"
    );
    let second_call_id = call_id_of(&second[0].1);
    assert_ne!(second_call_id, first_call_id);

    let events = parked.events();
    let order: Vec<&str> = events.iter().map(|(event, _)| event.as_str()).collect();
    assert_eq!(
        order,
        ["DialBranchFailed", "DialBranch"],
        "the first attempt's outcome, then the second attempt"
    );
    let failed = &events[0].1;
    assert_eq!(text(failed, "leg_id"), first_leg);
    assert_eq!(text(failed, "leg_sip_call_id"), first_call_id);
    assert_eq!(failed["code"], 503);
    assert_eq!(text(failed, "reason"), "Service Unavailable");
    assert_eq!(text(failed, "cause"), "rejected");
    let placed = branch_named(&events, &second_call_id);
    assert_eq!(text(placed, "target"), target_uri(SECOND_TARGET));
    assert_ne!(text(placed, "leg_id"), first_leg);
}

/// An attempt of a sequential hunt that rings out is named as timed out, and
/// the attempt the hunt moves on to is named when it is placed.
#[tokio::test(flavor = "multi_thread")]
async fn a_sequential_attempt_that_rings_out_is_named_before_the_next() {
    let parked = park("dial-branches-hunt-timeout@192.0.2.10");
    parked.dial(&[FIRST_TARGET, SECOND_TARGET], false);
    let first = parked.invites();
    let first_call_id = call_id_of(&first[0].1);
    let _ = parked.events();

    check_b2bua_answer_timeouts_at(
        &parked.dispatcher.state,
        Instant::now() + Duration::from_secs(31),
    );

    let second = parked.invites();
    assert_eq!(second.len(), 1, "the hunt moved on to the second target");
    let events = parked.events();
    let order: Vec<&str> = events.iter().map(|(event, _)| event.as_str()).collect();
    assert_eq!(order, ["DialBranchFailed", "DialBranch"], "{events:?}");
    assert_eq!(text(&events[0].1, "leg_sip_call_id"), first_call_id);
    assert_eq!(text(&events[0].1, "cause"), "timeout");
    assert_eq!(events[0].1["code"], 408);
    assert_eq!(
        text(&events[1].1, "leg_sip_call_id"),
        call_id_of(&second[0].1)
    );
}

/// One branch of a fork failing is named with its leg and its code while the
/// other still rings, and the dial itself is not over.
#[tokio::test(flavor = "multi_thread")]
async fn a_failing_fork_branch_is_named_with_its_code() {
    let parked = park("dial-branches-busy@192.0.2.10");
    parked.dial(&[FIRST_TARGET, SECOND_TARGET], true);
    let invites = parked.invites();
    let (_, busy) = invites
        .iter()
        .find(|(address, _)| address == FIRST_TARGET)
        .expect("the first target rang");
    let _ = parked.events();

    parked.responds(FIRST_TARGET, busy, 486, "Busy Here");

    let events = parked.events();
    let failed = named(&events, "DialBranchFailed");
    assert_eq!(failed.len(), 1, "{events:?}");
    assert_eq!(text(failed[0], "leg_sip_call_id"), call_id_of(busy));
    assert_eq!(text(failed[0], "target"), target_uri(FIRST_TARGET));
    assert_eq!(failed[0]["code"], 486);
    assert_eq!(text(failed[0], "cause"), "rejected");
    assert!(
        named(&events, "DialFailed").is_empty(),
        "the other branch can still answer: {events:?}"
    );
}

/// The branch that answers is named, and the branch it beat is named as
/// cancelled: that is exactly the leg an operator looks for.
#[tokio::test(flavor = "multi_thread")]
async fn the_answering_branch_is_named_and_the_losers_as_cancelled() {
    let parked = park("dial-branches-answer@192.0.2.10");
    parked.dial(&[FIRST_TARGET, SECOND_TARGET], true);
    let invites = parked.invites();
    let invite_to = |target: &str| {
        invites
            .iter()
            .find(|(address, _)| address == target)
            .map(|(_, invite)| invite.clone())
            .unwrap_or_else(|| panic!("no INVITE to {target}"))
    };
    let (winner, loser) = (invite_to(SECOND_TARGET), invite_to(FIRST_TARGET));
    let events = parked.events();
    let winner_leg = text(branch_named(&events, &call_id_of(&winner)), "leg_id").to_string();
    let loser_leg = text(branch_named(&events, &call_id_of(&loser)), "leg_id").to_string();

    parked.responds(SECOND_TARGET, &winner, 200, "OK");

    let events = parked.events();
    let answered = named(&events, "DialAnswered");
    assert_eq!(answered.len(), 1, "{events:?}");
    assert_eq!(text(answered[0], "leg_id"), winner_leg);
    assert_eq!(text(answered[0], "leg_sip_call_id"), call_id_of(&winner));
    assert_eq!(text(answered[0], "target"), target_uri(SECOND_TARGET));
    assert_eq!(answered[0]["code"], 200);

    let cancelled = named(&events, "DialBranchFailed");
    assert_eq!(cancelled.len(), 1, "{events:?}");
    assert_eq!(text(cancelled[0], "leg_id"), loser_leg);
    assert_eq!(text(cancelled[0], "leg_sip_call_id"), call_id_of(&loser));
    assert_eq!(text(cancelled[0], "cause"), "cancelled");
    let order: Vec<&str> = events.iter().map(|(event, _)| event.as_str()).collect();
    let answered_at = order.iter().position(|event| *event == "DialAnswered");
    let cancelled_at = order.iter().position(|event| *event == "DialBranchFailed");
    assert!(
        answered_at < cancelled_at,
        "the winner is named before the branches it beat: {order:?}"
    );
    assert!(
        summaries(&parked.wire())
            .iter()
            .any(|sent| sent == &format!("CANCEL to {FIRST_TARGET}")),
        "the losing branch was CANCELled on the wire"
    );
}

/// A fork every branch of which failed reports `DialFailed` carrying each branch
/// and what it answered, not just the one code the §16.7 ranking picked.
#[tokio::test(flavor = "multi_thread")]
async fn dial_failed_carries_every_branch_and_its_outcome() {
    let parked = park("dial-branches-exhausted@192.0.2.10");
    parked.dial(&[FIRST_TARGET, SECOND_TARGET], true);
    let invites = parked.invites();
    for (address, invite) in &invites {
        let (code, reason) = if address == FIRST_TARGET {
            (486, "Busy Here")
        } else {
            (480, "Temporarily Unavailable")
        };
        parked.responds(address, invite, code, reason);
    }

    let events = parked.events();
    let failed = named(&events, "DialFailed");
    assert_eq!(failed.len(), 1, "{events:?}");
    let branches = failed[0]["branches"]
        .as_array()
        .unwrap_or_else(|| panic!("DialFailed carries no branches: {}", failed[0]));
    assert_eq!(branches.len(), 2, "{branches:?}");
    for (address, invite) in &invites {
        let branch = branches
            .iter()
            .find(|branch| branch["leg_sip_call_id"] == call_id_of(invite))
            .unwrap_or_else(|| panic!("the branch to {address} is missing: {branches:?}"));
        assert_eq!(text(branch, "target"), target_uri(address));
        assert_eq!(text(branch, "cause"), "rejected");
        let expected = if address == FIRST_TARGET { 486 } else { 480 };
        assert_eq!(branch["code"], expected);
        assert!(!text(branch, "leg_id").is_empty());
    }
    assert_eq!(
        named(&events, "DialBranchFailed").len(),
        2,
        "each branch was named as it failed, before the dial did: {events:?}"
    );
}

/// A dial nobody answers names each branch as timed out, and `DialFailed` says
/// so for each.
#[tokio::test(flavor = "multi_thread")]
async fn a_dial_that_rings_out_names_every_branch_as_timed_out() {
    let parked = park("dial-branches-timeout@192.0.2.10");
    parked.dial(&[FIRST_TARGET, SECOND_TARGET], true);
    let invites = parked.invites();
    let _ = parked.events();

    check_b2bua_answer_timeouts_at(
        &parked.dispatcher.state,
        Instant::now() + Duration::from_secs(31),
    );

    let events = parked.events();
    let timed_out = named(&events, "DialBranchFailed");
    assert_eq!(timed_out.len(), 2, "{events:?}");
    for payload in &timed_out {
        assert_eq!(text(payload, "cause"), "timeout");
        assert_eq!(payload["code"], 408);
    }
    let failed = named(&events, "DialFailed");
    assert_eq!(failed.len(), 1, "{events:?}");
    assert_eq!(failed[0]["timed_out"], true);
    let branches = failed[0]["branches"].as_array().expect("branches");
    let mut named_call_ids: Vec<&str> = branches
        .iter()
        .map(|branch| text(branch, "leg_sip_call_id"))
        .collect();
    let mut wire_call_ids: Vec<String> = invites
        .iter()
        .map(|(_, invite)| call_id_of(invite))
        .collect();
    named_call_ids.sort_unstable();
    wire_call_ids.sort_unstable();
    assert_eq!(named_call_ids, wire_call_ids);
}

/// A second `dial` on the same channel after the first failed starts a fresh
/// list: its `DialFailed` does not carry the legs the first one rang.
#[tokio::test(flavor = "multi_thread")]
async fn a_redial_reports_only_its_own_branches() {
    let parked = park("dial-branches-redial@192.0.2.10");
    parked.dial(&[FIRST_TARGET], true);
    let first = parked.invites();
    parked.responds(FIRST_TARGET, &first[0].1, 486, "Busy Here");
    let _ = parked.events();

    parked.dial(&[SECOND_TARGET], true);
    let second = parked.invites();
    parked.responds(SECOND_TARGET, &second[0].1, 603, "Decline");

    let events = parked.events();
    let failed = named(&events, "DialFailed");
    assert_eq!(failed.len(), 1, "{events:?}");
    let branches = failed[0]["branches"].as_array().expect("branches");
    assert_eq!(branches.len(), 1, "{branches:?}");
    assert_eq!(
        text(&branches[0], "leg_sip_call_id"),
        call_id_of(&second[0].1)
    );
}
