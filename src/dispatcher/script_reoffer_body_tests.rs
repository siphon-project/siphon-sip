//! `b2bua.reoffer()` on a call siphon is the UAS of: the session in force
//! re-offered with a body and headers of the script's beside it, the wait and
//! retry RFC 3261 §14.1 gives a `491`, the `491` siphon owes a request that
//! crosses its own re-INVITE (§14.2), and the party's answer handed to the
//! media engine where the engine is the far side of its session.
//!
//! TS 24.379 §10.1.1.4.2 has a group call upgraded this way: every other
//! participant is re-INVITEd with the service's part and the new
//! `Resource-Priority`, the media unchanged.

use super::cancel_awaits_provisional_tests::branch_of;
use super::dial_bridge_test_harness::{eventually, in_dialog_response};
use super::dialog_state_transfer_tests::respond;
use super::originate_test_harness::{drain, socket, Sent};
use super::seat_reoffer_tests::{
    engine_answered, final_response, parts, refresh, script, seated, Seat, CALLER, HOLD, INFO,
    INFO_TYPE, SEAT_ANSWER,
};
use super::*;
use crate::b2bua::reoffer::AnswerExtras;

const CONTACT: &str = "sip:15550100001@192.0.2.10:5060";

/// The service's part and the priority of the call, as a script gives them.
fn info_and_priority() -> AnswerExtras {
    AnswerExtras {
        body: Some((INFO_TYPE.to_string(), INFO.as_bytes().to_vec())),
        headers: vec![("Resource-Priority".to_string(), "mcpttp.5".to_string())],
    }
}

/// Re-offer the participant, as `b2bua.reoffer()` does.
fn reoffers(seat: &Seat, sdp: Option<&str>, extras: &AnswerExtras) -> Reoffered {
    tokio::task::block_in_place(|| {
        reoffer_leg_with(
            &seat.dispatcher.state,
            &seat.internal_call_id,
            true,
            sdp.map(|sdp| sdp.as_bytes().to_vec()),
            extras,
        )
    })
    .expect("the re-offer is taken")
}

fn sent(reoffered: Reoffered) -> (String, tokio::sync::oneshot::Receiver<u16>) {
    match reoffered {
        Reoffered::Sent { branch, status } => (branch, status),
        Reoffered::Crossing => panic!("nothing was pending"),
    }
}

/// The re-INVITE among what siphon sent the participant.
fn reinvite_in(frames: &[Sent]) -> Option<SipMessage> {
    frames
        .iter()
        .find(|frame| frame.is(Method::Invite) && frame.destination == socket(CALLER))
        .map(|frame| frame.message.clone())
}

fn reinvite(seat: &Seat) -> SipMessage {
    reinvite_in(&drain(&seat.dispatcher.udp)).expect("the participant is re-INVITEd")
}

/// The participant's final response to `request`.
fn answers(seat: &Seat, request: &SipMessage, status: u16, sdp: Option<&str>) -> Vec<Sent> {
    let reason = if status == 200 {
        "OK"
    } else {
        "Request Pending"
    };
    respond(
        &seat.dispatcher,
        &seat.internal_call_id,
        CALLER,
        request,
        in_dialog_response(request, status, reason, CONTACT, sdp),
    );
    drain(&seat.dispatcher.udp)
}

fn cseq_number(message: &SipMessage) -> u32 {
    message
        .headers
        .get("CSeq")
        .and_then(|cseq| cseq.split_whitespace().next())
        .and_then(|number| number.parse().ok())
        .expect("a CSeq")
}

/// The `<sess-version>` of an SDP's `o=` line (RFC 8866 §5.2).
fn version(sdp: &str) -> u64 {
    sdp.lines()
        .find_map(|line| line.strip_prefix("o="))
        .and_then(|origin| origin.split_whitespace().nth(2))
        .and_then(|version| version.parse().ok())
        .expect("an o= with a version")
}

/// An SDP without its `o=` line.
fn but_origin(sdp: &str) -> String {
    sdp.lines()
        .filter(|line| !line.starts_with("o="))
        .collect::<Vec<_>>()
        .join("\r\n")
}

fn acked(frames: &[Sent], request: &SipMessage) -> bool {
    frames.iter().any(|frame| {
        frame.is(Method::Ack)
            && frame.destination == socket(CALLER)
            && cseq_number(&frame.message) == cseq_number(request)
    })
}

/// A re-offer with a part and a header of the script's is one re-INVITE in
/// the participant's dialog: a multipart body of the session in force, under
/// siphon's `o=` at the dialog's next version (RFC 3264 §8), and the part;
/// the header beside the dialog's own. Its 200 is ACKed, hands the script
/// 200, and leaves the SDP alone as the session in force. The seat's engine
/// is told nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_reoffer_carries_the_session_in_force_with_the_scripts_part_and_header() {
    let seat = seated("reoffer-part@192.0.2.10", &script("")).await;
    let engine_before = seat.engine.commands("answer_local").len();
    let (branch, status) = sent(reoffers(&seat, None, &info_and_priority()));
    let request = reinvite(&seat);

    let content_type = request.headers.get("Content-Type").expect("a Content-Type");
    assert!(
        content_type.starts_with("multipart/mixed;boundary=siphon-"),
        "{content_type}"
    );
    let offered = parts(&request);
    assert_eq!(offered.len(), 2);
    assert_eq!(offered[0].0, "application/sdp");
    assert_eq!(
        but_origin(&offered[0].1),
        but_origin(SEAT_ANSWER),
        "the session in force, nothing but its o= changed"
    );
    // RFC 3264 §8: the o= the participant was sent, but for its version.
    let first_version = version(&offered[0].1);
    assert!(first_version > version(SEAT_ANSWER), "{}", offered[0].1);
    assert!(
        offered[0]
            .1
            .contains(&format!("o=- 5 {first_version} IN IP4 203.0.113.7\r\n")),
        "{}",
        offered[0].1
    );
    assert_eq!(offered[1], (INFO_TYPE.to_string(), INFO.to_string()));
    assert_eq!(
        request.headers.get("Resource-Priority").map(String::as_str),
        Some("mcpttp.5")
    );
    assert_eq!(
        request.headers.get("Call-ID").map(String::as_str),
        Some(seat.call_id.as_str())
    );
    assert!(request.headers.get("Contact").is_some());
    assert!(request
        .headers
        .to()
        .is_some_and(|to| to.contains(";tag=caller-tag")));

    let frames = answers(&seat, &request, 200, Some(&refresh()));
    assert!(acked(&frames, &request), "the 200 is ACKed: {frames:?}");
    assert_eq!(status.await, Ok(200));
    assert!(!is_script_reoffer(&branch), "the waiter drains");
    let (given, in_force) = seat.descriptions();
    assert_eq!(given.as_deref(), Some(refresh().as_str()));
    assert_eq!(
        in_force.as_deref().map(str::trim_end),
        Some(offered[0].1.as_str()),
        "the SDP alone, not the multipart body"
    );
    assert_eq!(seat.engine.commands("answer_local").len(), engine_before);

    // The next one is at the next version.
    let (_, status) = sent(reoffers(&seat, None, &info_and_priority()));
    let again = reinvite(&seat);
    assert_eq!(
        version(&parts(&again)[0].1),
        version(&offered[0].1) + 1,
        "RFC 3264 §8"
    );
    assert_eq!(cseq_number(&again), cseq_number(&request) + 1);
    answers(&seat, &again, 200, Some(&refresh()));
    assert_eq!(status.await, Ok(200));
}

/// A multipart body the script built without an SDP part takes the SDP part
/// first, under the script's boundary; one that cannot take it is refused
/// before anything is sent, and leaves no INVITE in progress behind.
#[tokio::test(flavor = "multi_thread")]
async fn a_multipart_body_takes_the_sdp_part_or_is_refused_unsent() {
    let seat = seated("reoffer-own-multipart@192.0.2.10", &script("")).await;
    let own = AnswerExtras {
        body: Some((
            "multipart/mixed;boundary=own".to_string(),
            format!("--own\r\nContent-Type: {INFO_TYPE}\r\n\r\n{INFO}\r\n--own--\r\n").into_bytes(),
        )),
        headers: Vec::new(),
    };
    let (_, status) = sent(reoffers(&seat, None, &own));
    let request = reinvite(&seat);
    assert_eq!(
        request.headers.get("Content-Type").map(String::as_str),
        Some("multipart/mixed;boundary=own")
    );
    let text = String::from_utf8_lossy(&request.body).into_owned();
    assert!(
        text.starts_with("--own\r\nContent-Type: application/sdp\r\n\r\nv=0\r\n"),
        "{text}"
    );
    assert_eq!(parts(&request).len(), 2);
    answers(&seat, &request, 200, Some(&refresh()));
    assert_eq!(status.await, Ok(200));

    let broken = AnswerExtras {
        body: Some(("multipart/mixed".to_string(), b"--own--\r\n".to_vec())),
        headers: Vec::new(),
    };
    let refused = tokio::task::block_in_place(|| {
        reoffer_leg_with(
            &seat.dispatcher.state,
            &seat.internal_call_id,
            true,
            None,
            &broken,
        )
    });
    assert!(
        matches!(&refused, Err(ReofferRefusal::BadBody(why)) if why.contains("boundary")),
        "refused for its body"
    );
    assert!(reinvite_in(&drain(&seat.dispatcher.udp)).is_none());
    let (_, status) = sent(reoffers(&seat, None, &AnswerExtras::default()));
    let request = reinvite(&seat);
    assert_eq!(
        request.headers.get("Content-Type").map(String::as_str),
        Some("application/sdp")
    );
    answers(&seat, &request, 200, Some(&refresh()));
    assert_eq!(status.await, Ok(200));
}

/// The participant answers `491`: its 491 is ACKed, siphon waits the 0 to 2
/// seconds RFC 3261 §14.1 gives the side that did not generate the Call-ID,
/// and sends the re-INVITE again, as a new request at the next CSeq and `o=`
/// version with the same part and header. The script is handed the 200 of
/// the second, and no waiter is left behind.
#[tokio::test(flavor = "multi_thread")]
async fn a_491_is_waited_out_and_the_reoffer_is_sent_again() {
    let seat = seated("reoffer-glare@192.0.2.10", &script("")).await;
    let extras = info_and_priority();
    let first = reoffers(&seat, None, &extras);
    let first_branch = match &first {
        Reoffered::Sent { branch, .. } => branch.clone(),
        Reoffered::Crossing => panic!("nothing was pending"),
    };
    let request = reinvite(&seat);
    let frames = answers(&seat, &request, 491, None);
    assert!(acked(&frames, &request), "the 491 is ACKed: {frames:?}");

    let started = std::time::Instant::now();
    let settle = settle_reoffer_through_glare(
        first,
        || {
            tokio::task::block_in_place(|| {
                reoffer_leg_with(
                    &seat.dispatcher.state,
                    &seat.internal_call_id,
                    true,
                    None,
                    &extras,
                )
            })
        },
        false,
        std::time::Duration::from_secs(10),
    );
    let participant = async {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if let Some(again) = reinvite_in(&drain(&seat.dispatcher.udp)) {
                let frames = answers(&seat, &again, 200, Some(&refresh()));
                return (again, frames);
            }
            assert!(std::time::Instant::now() < deadline, "no second re-INVITE");
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    };
    let (status, (again, frames)) = tokio::join!(settle, participant);
    assert_eq!(status, Some(200));
    assert!(
        started.elapsed() <= std::time::Duration::from_millis(2500),
        "within the 0-2 s of the side that does not own the Call-ID"
    );
    assert!(acked(&frames, &again), "the 200 is ACKed: {frames:?}");
    assert_eq!(cseq_number(&again), cseq_number(&request) + 1);
    assert_ne!(branch_of(&again), branch_of(&request));
    assert_eq!(
        version(&parts(&again)[0].1),
        version(&parts(&request)[0].1) + 1
    );
    assert_eq!(parts(&again)[1], (INFO_TYPE.to_string(), INFO.to_string()));
    assert_eq!(
        again.headers.get("Resource-Priority").map(String::as_str),
        Some("mcpttp.5")
    );
    let second_branch = branch_of(&again);
    assert!(
        eventually(|| !is_script_reoffer(&first_branch) && !is_script_reoffer(&second_branch))
            .await,
        "the waiters drain"
    );
}

/// While siphon's re-INVITE to the participant is in progress, a re-INVITE or
/// an UPDATE with an offer from the participant is answered `491`
/// (RFC 3261 §14.2, RFC 3311 §5.2) and the script is not shown it. Once
/// siphon's own is answered the participant's goes through as ever.
#[tokio::test(flavor = "multi_thread")]
async fn a_request_crossing_siphons_reinvite_is_answered_491() {
    let handler = concat!(
        "\n",
        "@b2bua.on_reoffer\n",
        "def on_reoffer(call, offer):\n",
        "    offer.reject(403, \"Shown\")\n",
    );
    let seat = seated("reoffer-crossing@192.0.2.10", &script(handler)).await;
    let (_, status) = sent(reoffers(&seat, None, &AnswerExtras::default()));
    let request = reinvite(&seat);

    let crossing = final_response(&seat.sends("INVITE", 2, Some(HOLD)));
    assert_eq!(crossing.status_code(), Some(491));
    let crossing = final_response(&seat.sends("UPDATE", 3, Some(HOLD)));
    assert_eq!(crossing.status_code(), Some(491));
    let (given, _) = seat.descriptions();
    assert!(
        given.is_some_and(|given| !given.contains("a=sendonly")),
        "a refused offer is not the participant's media"
    );

    answers(&seat, &request, 200, Some(&refresh()));
    assert_eq!(status.await, Ok(200));
    let shown = final_response(&seat.sends("INVITE", 4, Some(HOLD)));
    assert_eq!(shown.status_code(), Some(403), "the script is shown it now");
}

/// On a call the engine answered itself, the answer to a re-offer of the
/// session in force is the caller's description from then on. One that
/// repeats what the caller had tells the engine nothing; one that moves its
/// media is given to the engine as the description to answer. The answer to
/// a re-offer that carried the script's own SDP is not the engine's.
#[tokio::test(flavor = "multi_thread")]
async fn the_answer_to_the_session_in_force_reaches_the_engine_when_it_moves_the_media() {
    let call = engine_answered("reoffer-engine@192.0.2.10", &script("")).await;
    let told = || call.engine.commands("answer_local");
    let before = told().len();

    let (_, status) = sent(reoffers(&call, None, &info_and_priority()));
    let request = reinvite(&call);
    answers(&call, &request, 200, Some(&refresh()));
    assert_eq!(status.await, Ok(200));
    assert_eq!(told().len(), before, "the same media: nothing to tell");

    let moved = refresh()
        .replace("o=- 1 2", "o=- 1 3")
        .replace("c=IN IP4 192.0.2.10", "c=IN IP4 192.0.2.77")
        .replace("m=audio 40000", "m=audio 40010");
    let (_, status) = sent(reoffers(&call, None, &AnswerExtras::default()));
    let request = reinvite(&call);
    let frames = answers(&call, &request, 200, Some(&moved));
    assert!(acked(&frames, &request));
    assert_eq!(status.await, Ok(200));
    let commands = told();
    assert_eq!(commands.len(), before + 1, "the engine is given the answer");
    assert_eq!(
        commands
            .last()
            .and_then(|command| command.detail.as_deref()),
        Some(moved.as_str())
    );
    assert_eq!(call.descriptions().0.as_deref(), Some(moved.as_str()));

    let own = call
        .descriptions()
        .1
        .map(|session| format!("{session}a=record:off\r\n"))
        .expect("a session in force");
    let (_, status) = sent(reoffers(&call, Some(&own), &AnswerExtras::default()));
    let request = reinvite(&call);
    let back = moved.replace("192.0.2.77", "192.0.2.78");
    answers(&call, &request, 200, Some(&back));
    assert_eq!(status.await, Ok(200));
    assert_eq!(told().len(), before + 1, "not the engine's session");
}

/// A seat takes no new description: an answer that moves the participant's
/// media is kept as its description and the engine is sent nothing.
#[tokio::test(flavor = "multi_thread")]
async fn an_answer_that_moves_a_seats_media_is_not_sent_to_the_engine() {
    let seat = seated("reoffer-seat-moved@192.0.2.10", &script("")).await;
    let before = seat.engine.commands("answer_local").len();
    let (_, status) = sent(reoffers(&seat, None, &AnswerExtras::default()));
    let request = reinvite(&seat);
    let moved = refresh().replace("m=audio 40000", "m=audio 40010");
    answers(&seat, &request, 200, Some(&moved));
    assert_eq!(status.await, Ok(200));
    assert_eq!(seat.engine.commands("answer_local").len(), before);
    assert_eq!(seat.descriptions().0.as_deref(), Some(moved.as_str()));
}

/// A 200 that comes after the script stopped waiting (`timeout_ms`) is the
/// answer to its re-offer all the same: ACKed, kept as the caller's
/// description, and given to the engine where it moves the media. The entry
/// that knows so goes with that response.
#[tokio::test(flavor = "multi_thread")]
async fn a_late_answer_to_an_abandoned_reoffer_still_reaches_the_engine() {
    let call = engine_answered("reoffer-late@192.0.2.10", &script("")).await;
    let before = call.engine.commands("answer_local").len();
    let first = reoffers(&call, None, &AnswerExtras::default());
    let request = reinvite(&call);
    let branch = branch_of(&request);
    let status = settle_reoffer_through_glare(
        first,
        || panic!("not sent again"),
        false,
        std::time::Duration::from_millis(50),
    )
    .await;
    assert_eq!(status, None, "the script stopped waiting");
    assert!(
        is_script_reoffer(&branch),
        "the INVITE is still in progress"
    );

    let moved = refresh().replace("m=audio 40000", "m=audio 40020");
    let frames = answers(&call, &request, 200, Some(&moved));
    assert!(acked(&frames, &request));
    let commands = call.engine.commands("answer_local");
    assert_eq!(commands.len(), before + 1);
    assert_eq!(
        commands
            .last()
            .and_then(|command| command.detail.as_deref()),
        Some(moved.as_str())
    );
    assert!(!is_script_reoffer(&branch), "gone with its final response");
}

/// An answer that changes a codec parameter and nothing else is not the
/// description the caller had: the engine is given it.
#[tokio::test(flavor = "multi_thread")]
async fn an_answer_that_changes_a_codec_parameter_reaches_the_engine() {
    let call = engine_answered("reoffer-fmtp@192.0.2.10", &script("")).await;
    let before = call.engine.commands("answer_local").len();
    let (_, status) = sent(reoffers(&call, None, &AnswerExtras::default()));
    let request = reinvite(&call);
    let changed = format!("{}a=fmtp:101 0-11\r\n", refresh());
    answers(&call, &request, 200, Some(&changed));
    assert_eq!(status.await, Ok(200));
    assert_eq!(call.engine.commands("answer_local").len(), before + 1);
}

/// A call that ends with a re-offer still unanswered takes the re-offer's
/// entry along at the next sweep, however many there were.
#[tokio::test(flavor = "multi_thread")]
async fn the_reoffers_of_ended_calls_are_swept() {
    let mut branches = Vec::new();
    for round in 0..20 {
        let seat = seated(&format!("reoffer-swept-{round}@192.0.2.10"), &script("")).await;
        let (branch, _status) = sent(reoffers(&seat, None, &AnswerExtras::default()));
        assert!(script_reoffer_in_progress(&seat.internal_call_id, true));
        // The waiter gives up, and the call ends with no final response.
        forget_reoffer(&branch);
        sweep_ended_reoffers(&seat.dispatcher.state);
        assert!(is_script_reoffer(&branch), "round {round}: the call is up");
        seat.dispatcher
            .state
            .call_actors
            .remove_call(&seat.internal_call_id);
        sweep_ended_reoffers(&seat.dispatcher.state);
        assert!(!script_reoffer_in_progress(&seat.internal_call_id, true));
        branches.push(branch);
    }
    let left: Vec<_> = branches
        .iter()
        .filter(|branch| is_script_reoffer(branch))
        .collect();
    assert!(left.is_empty(), "entries never released: {left:?}");
}

/// A leg whose `pending_reinvite` flag another path holds (a bridge claims it
/// for a pairing as a whole) is not refused its re-INVITE for it: only a
/// script's re-INVITE in progress on the dialog draws the 491.
#[tokio::test(flavor = "multi_thread")]
async fn the_legs_pending_flag_alone_draws_no_491() {
    let seat = seated("reoffer-flag-only@192.0.2.10", &script("")).await;
    seat.dispatcher
        .state
        .call_actors
        .set_pending_reinvite(&seat.internal_call_id, true, true);
    // An offerless refresh, which siphon answers itself from the session in force.
    let answered = final_response(&seat.sends("INVITE", 2, None));
    assert_eq!(answered.status_code(), Some(200));
}
