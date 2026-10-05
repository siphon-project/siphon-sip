//! Reliable provisionals and failures from the targets of a leg replacement,
//! while the call's leg list changes under them.
//!
//! An answered call whose caller supports `100rel`, and a replacement of its
//! callee that rings two contacts. A contact that sends a reliable provisional
//! (RFC 3262 §3) is owed a PRACK on its own early dialog, naming its own RSeq:
//! siphon is the UAC of that INVITE and nobody else will send one, since a
//! target's provisional is never relayed to the caller of an answered call.
//!
//! A B-leg used to be addressed by its position on the call between a
//! response arriving and siphon acting on it. Here legs are taken off the call
//! in between, so a position read earlier names another leg, or none: the
//! PRACK and the recorded failure have to follow the Via branch instead.
//! Driven through the dispatcher's entry points and read off the UDP egress.

use super::dialog_state_events_tests::{header, register, responds, script, tag_of, wire, Sent};
use super::dialog_state_transfer_tests::{
    answer, host_of, invite, place, respond, response_to_phone, sent_invite_to, Established,
};
use super::lcr_ring_timeout_tests::top_via_branch;
use super::replacement_fork_tests::{ring_two_on, Ringing};
use super::test_dispatcher::test_dispatcher_with_script;
use super::*;
use crate::b2bua::actor::{HeldCalleePrack, ReplacementOutcome};
use crate::b2bua::transfer::ReplacementOrigin;

/// An answered call A to B between registered phones, as
/// [`establish`](super::dialog_state_transfer_tests::establish) sets one up,
/// with a caller whose INVITE says `Supported: 100rel`.
fn establish_with_a_caller_that_supports_100rel(prefix: u32) -> Established {
    let aor =
        |n: u32| -> &'static str { Box::leak(format!("sip:{n}@example.com").into_boxed_str()) };
    let address = |network: &str, port: u16| -> &'static str {
        Box::leak(format!("{network}.{}:{port}", 120 + prefix % 50).into_boxed_str())
    };
    let a = (aor(prefix + 1), address("192.0.2", 5060));
    let b = (aor(prefix + 2), address("198.51.100", 5060));
    let c = (aor(prefix + 3), address("198.51.100", 5070));
    for (aor, address) in [a, b, c] {
        register(aor, address);
    }
    let dispatcher = test_dispatcher_with_script(&script("call.dial(str(call.ruri))"));
    let a_call_id = format!("replacement-prack-{prefix}@{}", host_of(a.1));
    place(
        &dispatcher,
        a.1,
        &invite(
            a.1,
            &a_call_id,
            &format!("<{}>;tag=a-tag", a.0),
            &format!("sip:{}@{}", prefix + 2, b.1),
            "Supported: 100rel\r\n",
        ),
    );
    let call_id = dispatcher
        .state
        .call_actors
        .find_by_sip_call_id(&a_call_id)
        .expect("the call exists");
    let to_b = sent_invite_to(&wire(&dispatcher), b.1);
    respond(
        &dispatcher,
        &call_id,
        b.1,
        &to_b,
        answer(&to_b, b.1, "b-tag"),
    );
    let answer_to_a = response_to_phone(&wire(&dispatcher), a.1, 200);
    Established {
        dispatcher,
        a,
        b,
        c,
        a_call_id,
        to_b,
        answer_to_a,
    }
}

/// The target at `address` sends a reliable `183` numbered `rseq` for `invite`.
fn reliable_183(invite: &SipMessage, address: &str, to_tag: &str, rseq: u32) -> SipMessage {
    let mut raw = String::from("SIP/2.0 183 Session Progress\r\n");
    for via in invite.headers.get_all("Via").cloned().unwrap_or_default() {
        raw.push_str(&format!("Via: {via}\r\n"));
    }
    raw.push_str(&format!("From: {}\r\n", header(invite, "From")));
    raw.push_str(&format!("To: {};tag={to_tag}\r\n", header(invite, "To")));
    raw.push_str(&format!("Call-ID: {}\r\n", header(invite, "Call-ID")));
    raw.push_str(&format!("CSeq: {}\r\n", header(invite, "CSeq")));
    raw.push_str(&format!("Contact: <sip:phone@{address}>\r\n"));
    raw.push_str("Require: 100rel\r\n");
    raw.push_str(&format!("RSeq: {rseq}\r\n"));
    raw.push_str("Content-Length: 0\r\n\r\n");
    parse_sip_message_bytes(raw.as_bytes()).expect("the 183 parses")
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

/// The one PRACK among `sent`, checked to be on the dialog of `invite`'s leg
/// at `address`, acknowledging `rseq` of that INVITE.
fn the_prack(sent: &[Sent], address: &str, invite: &SipMessage, to_tag: &str, rseq: u32) {
    assert_eq!(
        summaries(sent),
        [format!("PRACK {address}")],
        "exactly one PRACK, to the target that sent the provisional"
    );
    let prack = &sent[0].message;
    assert_eq!(header(prack, "Call-ID"), header(invite, "Call-ID"));
    assert_eq!(
        tag_of(&header(prack, "From")),
        tag_of(&header(invite, "From"))
    );
    assert_eq!(tag_of(&header(prack, "To")), to_tag);
    let invite_cseq = header(invite, "CSeq");
    assert_eq!(
        header(prack, "RAck"),
        format!("{rseq} {invite_cseq}"),
        "RFC 3262 §7.2: the RSeq, then the CSeq of the INVITE it answers"
    );
    match &prack.start_line {
        StartLine::Request(request) => assert_eq!(
            request.request_uri.to_string(),
            format!("sip:phone@{address}"),
            "the early dialog's remote target"
        ),
        StartLine::Response(_) => panic!("a PRACK is a request"),
    }
}

fn outcomes(ringing: &Ringing) -> Vec<(String, ReplacementOutcome)> {
    ringing
        .call
        .dispatcher
        .state
        .call_actors
        .get_call(&ringing.call_id)
        .map(|call| {
            call.refer_subscriptions
                .iter()
                .flat_map(|subscription| subscription.targets.iter())
                .map(|target| (target.branch.clone(), target.outcome))
                .collect()
        })
        .unwrap_or_default()
}

/// Each target's reliable provisional is PRACKed at once, on that target's
/// own dialog with its own RSeq, although the caller supports `100rel`: the
/// caller never sees a target's provisional, so it will never PRACK it.
#[tokio::test(flavor = "multi_thread")]
async fn a_targets_reliable_provisional_is_pracked_on_its_own_dialog() {
    let call = establish_with_a_caller_that_supports_100rel(10200);
    let ringing = ring_two_on(call, 10200, ReplacementOrigin::SiphonInitiated, false);
    let dispatcher = &ringing.call.dispatcher;
    let (desk, mobile) = (ringing.desk(), ringing.mobile);

    respond(
        dispatcher,
        &ringing.call_id,
        mobile,
        &ringing.to_mobile,
        reliable_183(&ringing.to_mobile, mobile, "mobile-tag", 7),
    );
    the_prack(
        &wire(dispatcher),
        mobile,
        &ringing.to_mobile,
        "mobile-tag",
        7,
    );

    respond(
        dispatcher,
        &ringing.call_id,
        desk,
        &ringing.to_desk,
        reliable_183(&ringing.to_desk, desk, "desk-tag", 3),
    );
    the_prack(&wire(dispatcher), desk, &ringing.to_desk, "desk-tag", 3);

    // A retransmission of a provisional already PRACKed is discarded (§4).
    respond(
        dispatcher,
        &ringing.call_id,
        mobile,
        &ringing.to_mobile,
        reliable_183(&ringing.to_mobile, mobile, "mobile-tag", 7),
    );
    assert!(wire(dispatcher).is_empty());
    let held = dispatcher
        .state
        .call_actors
        .get_call_mut(&ringing.call_id)
        .map(|mut call| call.prack_bridge.take_all().len());
    assert_eq!(
        held,
        Some(0),
        "nothing waits for a PRACK the caller will not send"
    );
}

/// A leg ahead of the targets is taken off the call while they ring, so every
/// target moves down one position. The next reliable provisional is PRACKed on
/// the dialog of the target that sent it, and a target's failure is recorded
/// against that target, with the other still ringing.
#[tokio::test(flavor = "multi_thread")]
async fn a_target_is_pracked_and_failed_by_branch_when_the_leg_list_shifts() {
    let call = establish_with_a_caller_that_supports_100rel(10250);
    let state_call_id = call.call_id();
    // A leg tracking an in-dialog request siphon relayed for the caller sits
    // on the call ahead of the targets, as one does until its response is in.
    let tracking_branch = "z9hG4bK-tracked-request";
    assert!(call.dispatcher.state.call_actors.add_b_leg(
        &state_call_id,
        Leg::new_b_leg(
            header(&call.to_b, "Call-ID"),
            "tracking-tag".to_string(),
            "info:a2b".to_string(),
            tracking_branch.to_string(),
            LegTransport {
                remote_addr: call.b.1.parse().expect("a literal address"),
                connection_id: ConnectionId::default(),
                transport: Transport::Udp,
                local_addr: None,
            },
        ),
    ));
    let ringing = ring_two_on(call, 10250, ReplacementOrigin::SiphonInitiated, false);
    let dispatcher = &ringing.call.dispatcher;
    let state = &dispatcher.state;
    let (desk, mobile) = (ringing.desk(), ringing.mobile);
    let (desk_branch, mobile_branch) = (
        top_via_branch(&ringing.to_desk),
        top_via_branch(&ringing.to_mobile),
    );
    let position = |branch: &str| state.call_actors.b_leg_index(&ringing.call_id, branch);
    assert_eq!(position(&desk_branch), Some(2));
    assert_eq!(position(&mobile_branch), Some(3));

    // A PRACK built for the mobile, as its provisional arrived.
    let provisional = reliable_183(&ringing.to_mobile, mobile, "mobile-tag", 1);
    let target = early_dialog_target_from_response(&provisional);
    let held = HeldCalleePrack {
        branch: mobile_branch.clone(),
        to_tag: "mobile-tag".to_string(),
        rseq: 1,
        cseq_number: 1,
        cseq_method: "INVITE".to_string(),
        remote_contact: target.remote_contact,
        to_header: target.to_header,
        route_set: target.route_set,
        offer: None,
    };
    // Before it is sent, the tracked request is answered and its leg removed:
    // the desk is now where the tracking leg was, the mobile where the desk was.
    let tracking = position(tracking_branch).expect("the tracking leg");
    state.call_actors.remove_b_leg(&ringing.call_id, tracking);
    assert_eq!(position(&desk_branch), Some(1));
    assert_eq!(position(&mobile_branch), Some(2));

    let sent =
        tokio::task::block_in_place(|| send_callee_prack(&ringing.call_id, &held, None, state));
    assert_eq!(
        sent.map(|sent| sent.b_leg_call_id),
        Some(header(&ringing.to_mobile, "Call-ID")),
        "the PRACK is the mobile's, wherever its leg sits now"
    );
    the_prack(
        &wire(dispatcher),
        mobile,
        &ringing.to_mobile,
        "mobile-tag",
        1,
    );

    // The desk's own reliable provisional, after the shift.
    respond(
        dispatcher,
        &ringing.call_id,
        desk,
        &ringing.to_desk,
        reliable_183(&ringing.to_desk, desk, "desk-tag", 4),
    );
    the_prack(&wire(dispatcher), desk, &ringing.to_desk, "desk-tag", 4);

    // The desk refuses. Its failure is the desk's: the mobile still rings, the
    // replacement is not failed, and the refusal is ACKed on the desk's branch.
    responds(
        dispatcher,
        &ringing.call_id,
        desk,
        &ringing.to_desk,
        486,
        "Busy Here",
        "desk-tag",
    );
    let sent = wire(dispatcher);
    assert_eq!(summaries(&sent), [format!("ACK {desk}")]);
    assert_eq!(top_via_branch(&sent[0].message), desk_branch);
    assert_eq!(
        outcomes(&ringing),
        [
            (desk_branch.clone(), ReplacementOutcome::Failed(486)),
            (mobile_branch.clone(), ReplacementOutcome::Pending),
        ]
    );

    // And the mobile answers: it is the one brought in.
    respond(
        dispatcher,
        &ringing.call_id,
        mobile,
        &ringing.to_mobile,
        answer(&ringing.to_mobile, mobile, "mobile-tag"),
    );
    let summary = summaries(&wire(dispatcher));
    assert!(summary.contains(&format!("ACK {mobile}")), "{summary:?}");
    let winner = state
        .call_actors
        .get_call(&ringing.call_id)
        .and_then(|call| call.winning_b_leg().map(|leg| leg.branch.clone()));
    assert_eq!(winner, Some(mobile_branch));
}
