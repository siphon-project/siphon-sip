//! `@b2bua.on_reoffer` and `@b2bua.on_reoffer_answered` on a bridged call.
//!
//! An answered call between two phones, then a re-INVITE or an UPDATE from one
//! of them: a hold (RFC 3264 §8.4), its resume, a session refresh (RFC 4028),
//! a refusal, a takeover siphon answers itself, a crossing offer siphon
//! answers 491 (RFC 3261 §14.1), and a handler that raises. What the script
//! was shown it writes onto the call (the stored A-leg INVITE every handler's
//! `call` wraps), and the wire says what happened to the request.

use super::dial_bridge_test_harness::in_dialog_response;
use super::dialog_state_events_tests::{header, inbound, wire, Sent};
use super::dialog_state_transfer_tests::{
    establish_deciding, host_of, respond, response_to_phone, Established,
};
use super::reoffer_ingress_tests::{acks, callee_of, caller_of, request_from, Party};
use super::transfer_ingress_tests::{anchored_on, sdp_naming, OPEN};
use super::*;
use crate::rtpengine::test_native_engine::NativeTestEngine;

/// What the handlers write onto the call: one line per offer the first one
/// saw, one per final response the second one saw.
const RECORDING: &str = concat!(
    "pass\n",
    "\n",
    "def note(call, name, line):\n",
    "    seen = call.get_header(name)\n",
    "    call.set_header(name, line if seen is None else seen + \" | \" + line)\n",
    "\n",
    "@b2bua.on_reoffer_answered\n",
    "def on_reoffer_answered(call, offer):\n",
    "    note(call, \"X-Answered\", f\"{offer.method} {offer.side} {offer.kind} \"\n",
    "         f\"{offer.status_code} {offer.answer_direction} {offer.answered_locally}\")\n",
    "\n",
    "@b2bua.on_reoffer\n",
    "def on_reoffer(call, offer):\n",
    "    note(call, \"X-Offered\", f\"{offer.method} {offer.side} {offer.kind} \"\n",
    "         f\"{offer.direction} {offer.previous_direction} {offer.early} {offer.sdp is None}\")\n",
);

/// A call whose script records as [`RECORDING`] does, then decides with
/// `decide`, the body of a statement under the `on_reoffer` handler.
fn call_deciding(prefix: u32, decide: &str) -> Established {
    let script = format!("{RECORDING}    {decide}\n");
    establish_deciding(prefix, &script)
}

/// What the script wrote under `name` onto the call.
fn written(call: &Established, name: &str) -> Option<String> {
    let call_id = call.call_id();
    let actor = call.dispatcher.state.call_actors.get_call(&call_id)?;
    let invite = actor.a_leg_invite.as_ref()?;
    let message = invite.lock().expect("the INVITE lock");
    message.headers.get(name).cloned()
}

/// The caller's SDP with `extra` lines at the end of its stream.
fn caller_sdp(call: &Established, extra: &str) -> String {
    format!("{}{extra}", sdp_naming(host_of(call.a.1)))
}

fn callee_sdp(call: &Established, extra: &str) -> String {
    format!("{}{extra}", sdp_naming(host_of(call.b.1)))
}

/// `party` sends `method` with `body`, through the handler the request path
/// hands it to. Returns what siphon sent.
fn offers(
    call: &Established,
    party: &Party,
    method: &str,
    cseq: u32,
    body: Option<&str>,
) -> Vec<Sent> {
    let (raw, message) = request_from(party, method, cseq, body);
    let arrived = inbound(&party.address, &raw);
    let state = &call.dispatcher.state;
    tokio::task::block_in_place(|| match method {
        "INVITE" => handle_b2bua_reinvite(arrived, message, state),
        _ => handle_b2bua_update(arrived, message, state),
    });
    wire(&call.dispatcher)
}

fn sent_with(sent: &[Sent], address: &str, method: Method) -> Option<SipMessage> {
    sent.iter()
        .find(|sent| sent.destination == address && sent.message.method() == Some(&method))
        .map(|sent| sent.message.clone())
}

fn final_to(sent: &[Sent], address: &str) -> Option<SipMessage> {
    sent.iter()
        .find(|sent| {
            sent.destination == address
                && sent.message.status_code().is_some_and(|code| code >= 200)
        })
        .map(|sent| sent.message.clone())
}

fn body_of(message: &SipMessage) -> String {
    String::from_utf8_lossy(&message.body).into_owned()
}

/// The party at `address` answers `relayed` 200 with `sdp`.
fn answers(call: &Established, address: &str, relayed: &SipMessage, sdp: &str) -> Vec<Sent> {
    respond(
        &call.dispatcher,
        &call.call_id(),
        address,
        relayed,
        in_dialog_response(
            relayed,
            200,
            "OK",
            &format!("sip:phone@{address}"),
            Some(sdp),
        ),
    );
    wire(&call.dispatcher)
}

/// The caller holds the callee with `sendonly`, the callee answers `recvonly`,
/// and the caller resumes. Both offers are relayed, and the script is told a
/// hold, then a resume, with the direction each answer came back with.
#[tokio::test(flavor = "multi_thread")]
async fn a_hold_and_its_resume_are_shown_before_they_are_relayed_and_after_they_are_answered() {
    let call = call_deciding(83010, "pass");
    let caller = caller_of(&call);
    acks(&call.dispatcher.state, &caller);

    let sent = offers(
        &call,
        &caller,
        "INVITE",
        2,
        Some(&caller_sdp(&call, "a=sendonly\r\n")),
    );
    let relayed = sent_with(&sent, call.b.1, Method::Invite).expect("the hold is relayed");
    assert!(
        body_of(&relayed).contains("a=sendonly"),
        "{}",
        body_of(&relayed)
    );
    assert_eq!(
        written(&call, "X-Offered").as_deref(),
        Some("INVITE a hold sendonly sendrecv False False")
    );
    assert_eq!(
        written(&call, "X-Answered"),
        None,
        "nothing is answered yet"
    );

    let sent = answers(
        &call,
        call.b.1,
        &relayed,
        &callee_sdp(&call, "a=recvonly\r\n"),
    );
    assert_eq!(
        response_to_phone(&sent, call.a.1, 200).status_code(),
        Some(200)
    );
    assert_eq!(
        written(&call, "X-Answered").as_deref(),
        Some("INVITE a hold 200 recvonly False")
    );

    let sent = offers(&call, &caller, "INVITE", 3, Some(&caller_sdp(&call, "")));
    let relayed = sent_with(&sent, call.b.1, Method::Invite).expect("the resume is relayed");
    let sent = answers(&call, call.b.1, &relayed, &callee_sdp(&call, ""));
    response_to_phone(&sent, call.a.1, 200);
    assert_eq!(
        written(&call, "X-Offered").as_deref(),
        Some(concat!(
            "INVITE a hold sendonly sendrecv False False | ",
            "INVITE a resume sendrecv sendonly False False"
        ))
    );
    assert_eq!(
        written(&call, "X-Answered").as_deref(),
        Some("INVITE a hold 200 recvonly False | INVITE a resume 200 sendrecv False")
    );
}

/// RFC 3264 §8.4: an old phone holds with a connection address of `0.0.0.0`,
/// and the callee holds too: the side is the callee's.
#[tokio::test(flavor = "multi_thread")]
async fn a_hold_by_unspecified_address_from_the_callee_is_a_hold() {
    let call = call_deciding(83020, "pass");
    let (caller, callee) = (caller_of(&call), callee_of(&call));
    acks(&call.dispatcher.state, &caller);
    let held = callee_sdp(&call, "").replace(
        &format!("c=IN IP4 {}", host_of(call.b.1)),
        "c=IN IP4 0.0.0.0",
    );
    let sent = offers(&call, &callee, "INVITE", 2, Some(&held));
    assert!(
        sent_with(&sent, call.a.1, Method::Invite).is_some(),
        "relayed to the caller"
    );
    assert_eq!(
        written(&call, "X-Offered").as_deref(),
        Some("INVITE b hold sendonly sendrecv False False")
    );
}

/// RFC 4028: a refresh repeats the session in force. On a held call that is a
/// `sendonly` offer again, and it must not read as a hold.
#[tokio::test(flavor = "multi_thread")]
async fn a_session_refresh_is_a_refresh_even_on_a_held_call() {
    let call = call_deciding(83030, "pass");
    let (caller, _) = (caller_of(&call), callee_of(&call));
    acks(&call.dispatcher.state, &caller);

    // The session in force, offered again: a refresh.
    let sent = offers(&call, &caller, "INVITE", 2, Some(&caller_sdp(&call, "")));
    let relayed = sent_with(&sent, call.b.1, Method::Invite).expect("relayed");
    answers(&call, call.b.1, &relayed, &callee_sdp(&call, ""));

    // Hold, then the refresh of the held session.
    let held = caller_sdp(&call, "a=sendonly\r\n");
    let sent = offers(&call, &caller, "INVITE", 3, Some(&held));
    let relayed = sent_with(&sent, call.b.1, Method::Invite).expect("relayed");
    answers(
        &call,
        call.b.1,
        &relayed,
        &callee_sdp(&call, "a=recvonly\r\n"),
    );
    let sent = offers(&call, &caller, "INVITE", 4, Some(&held));
    let relayed = sent_with(&sent, call.b.1, Method::Invite).expect("relayed");
    answers(
        &call,
        call.b.1,
        &relayed,
        &callee_sdp(&call, "a=recvonly\r\n"),
    );

    // An offerless re-INVITE: a refresh with no offer of its own.
    let sent = offers(&call, &caller, "INVITE", 5, None);
    assert!(
        sent_with(&sent, call.b.1, Method::Invite).is_some(),
        "relayed"
    );

    assert_eq!(
        written(&call, "X-Offered").as_deref(),
        Some(concat!(
            "INVITE a refresh sendrecv sendrecv False False | ",
            "INVITE a hold sendonly sendrecv False False | ",
            "INVITE a refresh sendonly sendonly False False | ",
            "INVITE a refresh None sendonly False True"
        ))
    );
}

/// `offer.reject()` answers the offerer with the script's status and relays
/// nothing; the target leg is left free for the next re-INVITE, and the
/// refused offer does not become the party's session.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_offer_is_answered_with_the_scripts_status_and_relayed_nowhere() {
    let call = call_deciding(83040, "offer.reject(488, \"Not Acceptable Here\")");
    let (caller, callee) = (caller_of(&call), callee_of(&call));
    acks(&call.dispatcher.state, &caller);

    let sent = offers(
        &call,
        &caller,
        "INVITE",
        2,
        Some(&caller_sdp(&call, "a=sendonly\r\n")),
    );
    assert!(
        sent_with(&sent, call.b.1, Method::Invite).is_none(),
        "nothing relayed"
    );
    let refusal = final_to(&sent, call.a.1).expect("the caller is answered");
    assert_eq!(refusal.status_code(), Some(488));
    assert_eq!(
        written(&call, "X-Answered").as_deref(),
        Some("INVITE a hold 488 None True")
    );

    // The same hold again is still a hold: the refused offer is not in force.
    // And the callee may re-offer: no re-INVITE is pending toward the caller.
    let sent = offers(&call, &callee, "INVITE", 2, Some(&callee_sdp(&call, "")));
    assert_eq!(
        final_to(&sent, call.b.1).and_then(|m| m.status_code()),
        Some(488)
    );
    let sent = offers(
        &call,
        &caller,
        "INVITE",
        3,
        Some(&caller_sdp(&call, "a=sendonly\r\n")),
    );
    assert_eq!(
        final_to(&sent, call.a.1).and_then(|m| m.status_code()),
        Some(488)
    );
    let offered = written(&call, "X-Offered").expect("recorded");
    assert!(
        offered.ends_with("INVITE a hold sendonly sendrecv False False"),
        "{offered}"
    );
    assert!(!offered.contains("491"), "{offered}");
}

/// `offer.answer()` takes a hold over: siphon answers the caller from the
/// session it has in force toward it, `recvonly`, with its own `o=` and
/// Contact, and the callee is sent nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_hold_taken_over_is_answered_here_from_the_session_in_force() {
    let call = call_deciding(83050, "offer.answer()");
    let (caller, callee) = (caller_of(&call), callee_of(&call));
    acks(&call.dispatcher.state, &caller);
    let in_force = body_of(&call.answer_to_a);

    let sent = offers(
        &call,
        &caller,
        "INVITE",
        2,
        Some(&caller_sdp(&call, "a=sendonly\r\n")),
    );
    assert!(
        sent_with(&sent, call.b.1, Method::Invite).is_none(),
        "nothing relayed"
    );
    let answer = response_to_phone(&sent, call.a.1, 200);
    let sdp = body_of(&answer);
    assert!(sdp.contains("a=recvonly"), "{sdp}");
    for line in in_force.lines().filter(|line| line.starts_with("c=")) {
        assert!(
            sdp.contains(line),
            "the address in force toward the caller: {sdp}"
        );
    }
    let origin = |sdp: &str| {
        sdp.lines()
            .find(|line| line.starts_with("o="))
            .map(str::to_string)
            .expect("an o= line")
    };
    assert_ne!(origin(&sdp), origin(&in_force), "a new o= version");
    assert!(
        answer.headers.get("Contact").is_some(),
        "a 2xx to a target refresh has a Contact"
    );
    assert_eq!(
        written(&call, "X-Answered").as_deref(),
        Some("INVITE a hold 200 recvonly True")
    );

    // The next offer is free to cross: nothing is pending toward the callee,
    // and the callee's own re-offer reaches the script.
    let _ = offers(&call, &callee, "INVITE", 2, Some(&callee_sdp(&call, "")));
    let sent = offers(&call, &caller, "INVITE", 3, Some(&caller_sdp(&call, "")));
    let resumed = response_to_phone(&sent, call.a.1, 200);
    assert!(
        !body_of(&resumed).contains("a=recvonly"),
        "{}",
        body_of(&resumed)
    );
    assert!(written(&call, "X-Offered")
        .expect("recorded")
        .ends_with("INVITE a resume sendrecv sendonly False False"));
}

/// A script that writes its own answer has it sent, under siphon's `o=`.
#[tokio::test(flavor = "multi_thread")]
async fn a_takeover_with_the_scripts_answer_sends_it() {
    let call = call_deciding(
        83060,
        "offer.answer(offer.sdp.replace(\"a=sendonly\", \"a=inactive\"))",
    );
    let caller = caller_of(&call);
    acks(&call.dispatcher.state, &caller);
    let sent = offers(
        &call,
        &caller,
        "INVITE",
        2,
        Some(&caller_sdp(&call, "a=sendonly\r\n")),
    );
    let sdp = body_of(&response_to_phone(&sent, call.a.1, 200));
    assert!(sdp.contains("a=inactive"), "{sdp}");
    assert!(!sdp.contains("o=- 1 1 "), "siphon's own o=: {sdp}");
}

/// An offer that only adds an attribute renegotiating nothing (RFC 7866's
/// `a=recordpref`) is a refresh, and a script answers it from the session in
/// force with one attribute of its own (`a=record`, the state it reports),
/// relaying nothing to the other party.
#[tokio::test(flavor = "multi_thread")]
async fn a_refresh_is_answered_from_the_session_in_force_the_script_edits() {
    let call = call_deciding(
        83160,
        concat!(
            "if offer.kind == \"refresh\" and offer.session_sdp:\n",
            "        offer.answer(offer.session_sdp + \"a=record:on\\r\\n\")",
        ),
    );
    let caller = caller_of(&call);
    acks(&call.dispatcher.state, &caller);
    let sent = offers(
        &call,
        &caller,
        "INVITE",
        2,
        Some(&caller_sdp(&call, "a=recordpref:on\r\n")),
    );
    assert!(
        written(&call, "X-Offered").is_some_and(|seen| seen.starts_with("INVITE a refresh")),
        "{:?}",
        written(&call, "X-Offered")
    );
    let sdp = body_of(&response_to_phone(&sent, call.a.1, 200));
    assert!(sdp.ends_with("a=record:on\r\n"), "{sdp}");
    assert!(
        sdp.contains(&format!("c=IN IP4 {}", host_of(call.b.1))),
        "the session in force toward the caller is the callee's: {sdp}"
    );
    assert!(
        sent_with(&sent, call.b.1, Method::Invite).is_none(),
        "nothing is relayed to the callee"
    );
}

/// An offerless re-INVITE taken over gets the session in force as siphon's
/// offer in the 200 (RFC 3261 §14.1).
#[tokio::test(flavor = "multi_thread")]
async fn an_offerless_reinvite_taken_over_is_offered_the_session_in_force() {
    let call = call_deciding(83070, "offer.answer()");
    let caller = caller_of(&call);
    acks(&call.dispatcher.state, &caller);
    let sent = offers(&call, &caller, "INVITE", 2, None);
    assert!(
        sent_with(&sent, call.b.1, Method::Invite).is_none(),
        "nothing relayed"
    );
    let offer = response_to_phone(&sent, call.a.1, 200);
    assert_eq!(
        body_of(&offer),
        body_of(&call.answer_to_a),
        "the session in force, as it was"
    );
}

/// A crossing re-INVITE is answered 491 by siphon (RFC 3261 §14.1) before the
/// script is shown it, and the first offer goes on.
#[tokio::test(flavor = "multi_thread")]
async fn a_crossing_offer_draws_491_without_reaching_the_script() {
    let call = call_deciding(83080, "pass");
    let (caller, callee) = (caller_of(&call), callee_of(&call));
    acks(&call.dispatcher.state, &caller);

    let sent = offers(
        &call,
        &caller,
        "INVITE",
        2,
        Some(&caller_sdp(&call, "a=sendonly\r\n")),
    );
    let relayed = sent_with(&sent, call.b.1, Method::Invite).expect("relayed");
    // The callee re-offers toward the caller while the caller's offer is out
    // to it: the target of that second offer has one pending.
    let _ = offers(&call, &callee, "INVITE", 2, Some(&callee_sdp(&call, "")));
    let sent = offers(&call, &caller, "INVITE", 3, Some(&caller_sdp(&call, "")));
    assert_eq!(
        final_to(&sent, call.a.1).and_then(|m| m.status_code()),
        Some(491)
    );
    let offered = written(&call, "X-Offered").expect("recorded");
    assert_eq!(
        offered.matches(" | ").count(),
        1,
        "the 491 reached no script: {offered}"
    );

    // The first exchange completes as it would have.
    let sent = answers(
        &call,
        call.b.1,
        &relayed,
        &callee_sdp(&call, "a=recvonly\r\n"),
    );
    response_to_phone(&sent, call.a.1, 200);
    assert!(written(&call, "X-Answered")
        .expect("recorded")
        .starts_with("INVITE a hold 200 recvonly False"));
}

/// A handler that raises decides nothing: the offer is relayed as it came,
/// and a header it set before raising does not go with it.
#[tokio::test(flavor = "multi_thread")]
async fn a_handler_that_raises_leaves_the_offer_relayed_as_it_came() {
    let call = call_deciding(
        83090,
        "offer.request.set_header(\"X-Script\", \"1\")\n    offer.reject(488, \"No\")\n    raise RuntimeError(\"boom\")",
    );
    let caller = caller_of(&call);
    acks(&call.dispatcher.state, &caller);
    let sent = offers(
        &call,
        &caller,
        "INVITE",
        2,
        Some(&caller_sdp(&call, "a=sendonly\r\n")),
    );
    let relayed = sent_with(&sent, call.b.1, Method::Invite).expect("relayed despite the raise");
    assert!(relayed.headers.get("X-Script").is_none());
    assert!(
        final_to(&sent, call.a.1).is_none(),
        "the caller waits for the callee's answer"
    );
}

/// A header the handler sets on `offer.request` goes out on the relayed
/// request.
#[tokio::test(flavor = "multi_thread")]
async fn a_header_set_on_the_request_is_relayed() {
    let call = call_deciding(83100, "offer.request.set_header(\"X-Held\", offer.kind)");
    let caller = caller_of(&call);
    acks(&call.dispatcher.state, &caller);
    let sent = offers(
        &call,
        &caller,
        "INVITE",
        2,
        Some(&caller_sdp(&call, "a=sendonly\r\n")),
    );
    let relayed = sent_with(&sent, call.b.1, Method::Invite).expect("relayed");
    assert_eq!(header(&relayed, "X-Held"), "hold");
}

/// An UPDATE (RFC 3311) is shown the same way: a hold the callee answers, and
/// one the script takes over, answered here with no ACK to follow.
#[tokio::test(flavor = "multi_thread")]
async fn an_update_hold_is_shown_relayed_and_answered() {
    let call = call_deciding(83110, "pass");
    let caller = caller_of(&call);
    acks(&call.dispatcher.state, &caller);
    let sent = offers(
        &call,
        &caller,
        "UPDATE",
        2,
        Some(&caller_sdp(&call, "a=inactive\r\n")),
    );
    let relayed = sent_with(&sent, call.b.1, Method::Update).expect("the UPDATE is relayed");
    let sent = answers(
        &call,
        call.b.1,
        &relayed,
        &callee_sdp(&call, "a=inactive\r\n"),
    );
    response_to_phone(&sent, call.a.1, 200);
    assert_eq!(
        written(&call, "X-Offered").as_deref(),
        Some("UPDATE a hold inactive sendrecv False False")
    );
    assert_eq!(
        written(&call, "X-Answered").as_deref(),
        Some("UPDATE a hold 200 inactive False")
    );

    let call = call_deciding(83120, "offer.answer()");
    let caller = caller_of(&call);
    acks(&call.dispatcher.state, &caller);
    let sent = offers(
        &call,
        &caller,
        "UPDATE",
        2,
        Some(&caller_sdp(&call, "a=sendonly\r\n")),
    );
    assert!(
        sent_with(&sent, call.b.1, Method::Update).is_none(),
        "nothing relayed"
    );
    let answer = response_to_phone(&sent, call.a.1, 200);
    assert!(
        body_of(&answer).contains("a=recvonly"),
        "{}",
        body_of(&answer)
    );
    // A session refresh UPDATE without an offer, taken over: a 200 with no body.
    let sent = offers(&call, &caller, "UPDATE", 3, None);
    let refreshed = response_to_phone(&sent, call.a.1, 200);
    assert!(refreshed.body.is_empty());
}

/// A script with neither hook relays as before, and the tracking leg keeps no
/// offer for a notification nobody listens for.
#[tokio::test(flavor = "multi_thread")]
async fn without_the_hooks_nothing_is_kept() {
    let call = establish_deciding(83130, "pass");
    let caller = caller_of(&call);
    acks(&call.dispatcher.state, &caller);
    let sent = offers(
        &call,
        &caller,
        "INVITE",
        2,
        Some(&caller_sdp(&call, "a=sendonly\r\n")),
    );
    let relayed = sent_with(&sent, call.b.1, Method::Invite).expect("relayed");
    let branch = relayed
        .headers
        .get("Via")
        .and_then(|via| via.split("branch=").nth(1))
        .map(|branch| branch.split(';').next().unwrap_or(branch).to_string())
        .expect("a branch");
    let kept = call
        .dispatcher
        .state
        .call_actors
        .read_b_leg_on(&call.call_id(), &branch, |leg| leg.reoffer.is_some());
    assert_eq!(kept, Some(false));
}

/// On a call anchored on a media engine, a hold taken over is answered here
/// and the engine is sent nothing: it keeps relaying the callee, whom a
/// script can then play an announcement to.
#[tokio::test(flavor = "multi_thread")]
async fn a_takeover_on_an_anchored_call_sends_the_media_engine_nothing() {
    let engine = NativeTestEngine::start().await;
    let call = anchored_on(call_deciding(83140, "offer.answer()"), &engine, OPEN).await;
    let caller = caller_of(&call);
    acks(&call.dispatcher.state, &caller);
    let before = (
        engine.commands("reoffer").len(),
        engine.commands("answer").len(),
    );
    let sent = offers(
        &call,
        &caller,
        "INVITE",
        2,
        Some(&caller_sdp(&call, "a=sendonly\r\n")),
    );
    assert!(
        sent_with(&sent, call.b.1, Method::Invite).is_none(),
        "nothing relayed"
    );
    assert!(body_of(&response_to_phone(&sent, call.a.1, 200)).contains("a=recvonly"));
    assert_eq!(
        (
            engine.commands("reoffer").len(),
            engine.commands("answer").len()
        ),
        before,
        "the engine is told nothing"
    );

    // Relayed, the same hold goes through the engine as before.
    let call = anchored_on(call_deciding(83150, "pass"), &engine, OPEN).await;
    let caller = caller_of(&call);
    acks(&call.dispatcher.state, &caller);
    let before = engine.commands("reoffer").len();
    let sent = offers(
        &call,
        &caller,
        "INVITE",
        2,
        Some(&caller_sdp(&call, "a=sendonly\r\n")),
    );
    assert!(sent_with(&sent, call.b.1, Method::Invite).is_some());
    assert_eq!(engine.commands("reoffer").len(), before + 1);
}

/// An async handler decides the same way a synchronous one does.
#[tokio::test(flavor = "multi_thread")]
async fn an_async_handler_decides_the_offer() {
    let script = concat!(
        "pass\n",
        "\n",
        "import asyncio\n",
        "\n",
        "@b2bua.on_reoffer\n",
        "async def on_reoffer(call, offer):\n",
        "    await asyncio.sleep(0)\n",
        "    if offer.kind == \"hold\":\n",
        "        offer.reject(403, \"Forbidden\")\n",
    );
    let call = establish_deciding(83160, script);
    let caller = caller_of(&call);
    acks(&call.dispatcher.state, &caller);
    let sent = offers(
        &call,
        &caller,
        "INVITE",
        2,
        Some(&caller_sdp(&call, "a=sendonly\r\n")),
    );
    assert_eq!(
        final_to(&sent, call.a.1).and_then(|m| m.status_code()),
        Some(403)
    );
    assert!(sent_with(&sent, call.b.1, Method::Invite).is_none());
}

/// `b2bua.reoffer()` sends the caller the session in force with what the
/// script changed (RFC 7866's `a=record`), under siphon's `o=`, tells the
/// callee nothing, hands the script the caller's final status, and makes the
/// offer the session in force. A second one while the first is pending is not
/// sent (RFC 3261 §14.1).
#[tokio::test(flavor = "multi_thread")]
async fn a_script_reoffer_reaches_the_caller_alone_and_settles_with_its_status() {
    let call = call_deciding(83170, "pass");
    let caller = caller_of(&call);
    acks(&call.dispatcher.state, &caller);
    let state = &call.dispatcher.state;
    let internal = call.call_id();
    let session = state
        .call_actors
        .clone_leg(&internal, true)
        .and_then(|leg| leg.dialog.last_sent_sdp)
        .expect("a session in force toward the caller");
    assert_eq!(
        super::b2bua::b2bua_session_sdp("no-such-call@example.com", true),
        None
    );
    let mut offer = session.clone();
    offer.extend_from_slice(b"a=record:on\r\n");

    let reoffered = tokio::task::block_in_place(|| {
        super::b2bua::reoffer_leg(state, &internal, true, Some(offer))
    })
    .expect("sent");
    let (branch, status) = match reoffered {
        super::b2bua::Reoffered::Sent { branch, status } => (branch, status),
        super::b2bua::Reoffered::Crossing => panic!("nothing was pending"),
    };
    let sent = wire(&call.dispatcher);
    let reinvite = sent_with(&sent, call.a.1, Method::Invite).expect("the caller is re-INVITEd");
    let body = body_of(&reinvite);
    assert!(body.ends_with("a=record:on\r\n"), "{body}");
    assert!(!body.contains("o=- 1 1 "), "siphon's own o=: {body}");
    assert!(
        sent_with(&sent, call.b.1, Method::Invite).is_none(),
        "the callee is told nothing"
    );

    let crossing =
        tokio::task::block_in_place(|| super::b2bua::reoffer_leg(state, &internal, true, None))
            .expect("refused as crossing, not as an error");
    assert!(matches!(crossing, super::b2bua::Reoffered::Crossing));
    assert!(
        sent_with(&wire(&call.dispatcher), call.a.1, Method::Invite).is_none(),
        "nothing crossing was sent"
    );

    answers(&call, call.a.1, &reinvite, &caller_sdp(&call, ""));
    let status = tokio::time::timeout(std::time::Duration::from_secs(2), status)
        .await
        .expect("settled")
        .expect("a status");
    assert_eq!(status, 200, "branch {branch}");
    let in_force = state
        .call_actors
        .clone_leg(&internal, true)
        .and_then(|leg| leg.dialog.last_sent_sdp)
        .expect("in force");
    assert!(
        String::from_utf8_lossy(&in_force).ends_with("a=record:on\r\n"),
        "the accepted offer is the session in force"
    );
    assert!(
        matches!(
            tokio::task::block_in_place(|| super::b2bua::reoffer_leg(state, &internal, true, None)),
            Ok(super::b2bua::Reoffered::Sent { .. })
        ),
        "the 200 ended the INVITE in progress"
    );
}

/// On a call anchored on a media engine, a script's re-offer is the session in
/// force with what the script changed, which the engine did not make: the
/// caller's answer to it is not the engine's to take, and is not sent there,
/// as an answer siphon gives itself is not.
#[tokio::test(flavor = "multi_thread")]
async fn a_script_reoffer_on_an_anchored_call_leaves_the_media_engine_alone() {
    let engine = NativeTestEngine::start().await;
    let call = anchored_on(call_deciding(83180, "pass"), &engine, OPEN).await;
    let caller = caller_of(&call);
    acks(&call.dispatcher.state, &caller);
    let state = &call.dispatcher.state;
    let internal = call.call_id();
    let before = (
        engine.commands("reoffer").len(),
        engine.commands("answer").len(),
    );
    let reoffered =
        tokio::task::block_in_place(|| super::b2bua::reoffer_leg(state, &internal, true, None))
            .expect("sent");
    let status = match reoffered {
        super::b2bua::Reoffered::Sent { status, .. } => status,
        super::b2bua::Reoffered::Crossing => panic!("nothing was pending"),
    };
    let reinvite = sent_with(&wire(&call.dispatcher), call.a.1, Method::Invite)
        .expect("the caller is re-INVITEd");
    answers(&call, call.a.1, &reinvite, &caller_sdp(&call, ""));
    let status = tokio::time::timeout(std::time::Duration::from_secs(2), status)
        .await
        .expect("settled")
        .expect("a status");
    assert_eq!(status, 200);
    assert_eq!(
        (
            engine.commands("reoffer").len(),
            engine.commands("answer").len()
        ),
        before,
        "the engine is told nothing"
    );
}

/// The waiters `b2bua.reoffer()` leaves for a final status drain: a re-offer
/// answered, one the script stopped waiting for (its `timeout_ms`) and then
/// answered late, and one refused as crossing all leave nothing behind. Checked
/// per branch, since the waiter map is shared with every other test.
#[tokio::test(flavor = "multi_thread")]
async fn script_reoffer_waiters_drain_after_answered_and_abandoned_reoffers() {
    const ROUNDS: usize = 50;
    let call = call_deciding(83190, "pass");
    let caller = caller_of(&call);
    acks(&call.dispatcher.state, &caller);
    let state = &call.dispatcher.state;
    let internal = call.call_id();
    let mut branches = Vec::with_capacity(2 * ROUNDS);

    for round in 0..2 * ROUNDS {
        let abandoned = round % 2 == 1;
        let reoffered =
            tokio::task::block_in_place(|| super::b2bua::reoffer_leg(state, &internal, true, None))
                .expect("sent");
        let (branch, status) = match reoffered {
            super::b2bua::Reoffered::Sent { branch, status } => (branch, status),
            super::b2bua::Reoffered::Crossing => panic!("round {round}: nothing was pending"),
        };
        assert!(super::b2bua::is_script_reoffer(&branch), "round {round}");
        let crossing =
            tokio::task::block_in_place(|| super::b2bua::reoffer_leg(state, &internal, true, None))
                .expect("refused as crossing");
        assert!(matches!(crossing, super::b2bua::Reoffered::Crossing));
        // The script stops waiting before the caller answers: what a
        // `timeout_ms` that runs out does.
        let status = if abandoned {
            super::b2bua::forget_reoffer(&branch);
            None
        } else {
            Some(status)
        };
        let reinvite = sent_with(&wire(&call.dispatcher), call.a.1, Method::Invite)
            .expect("the caller is re-INVITEd");
        answers(&call, call.a.1, &reinvite, &caller_sdp(&call, ""));
        if let Some(status) = status {
            let code = tokio::time::timeout(std::time::Duration::from_secs(2), status)
                .await
                .expect("settled")
                .expect("a status");
            assert_eq!(code, 200, "round {round}");
        }
        branches.push(branch);
    }

    let left: Vec<&String> = branches
        .iter()
        .filter(|branch| super::b2bua::is_script_reoffer(branch))
        .collect();
    assert!(left.is_empty(), "waiters never released: {left:?}");
}

/// Past Timer B with nothing answered: every armed request gives up.
fn past_timer_b(call: &Established) {
    let later = std::time::Instant::now() + std::time::Duration::from_secs(64);
    tokio::task::block_in_place(|| {
        super::timers::sweep_b2bua_retransmits_at(&call.dispatcher.state, later)
    });
}

/// A re-offer the caller never answers, not even with a provisional, ends at
/// Timer B as the 408 it stands for (RFC 3261 §17.1.1.2, §8.1.3.1): the script
/// waiting on it is told 408, nothing is ACKed to the silent caller, and the
/// next re-INVITE toward the caller goes out instead of reading as one that
/// crosses an INVITE still in progress.
#[tokio::test(flavor = "multi_thread")]
async fn a_reoffer_nobody_answers_ends_at_timer_b_as_408_and_frees_the_leg() {
    let call = call_deciding(83200, "pass");
    let caller = caller_of(&call);
    acks(&call.dispatcher.state, &caller);
    let state = &call.dispatcher.state;
    let internal = call.call_id();
    let reoffered =
        tokio::task::block_in_place(|| super::b2bua::reoffer_leg(state, &internal, true, None))
            .expect("sent");
    let (branch, status) = match reoffered {
        super::b2bua::Reoffered::Sent { branch, status } => (branch, status),
        super::b2bua::Reoffered::Crossing => panic!("nothing was pending"),
    };
    assert!(
        sent_with(&wire(&call.dispatcher), call.a.1, Method::Invite).is_some(),
        "the caller is re-INVITEd"
    );

    past_timer_b(&call);

    let code = tokio::time::timeout(std::time::Duration::from_secs(2), status)
        .await
        .expect("settled at Timer B")
        .expect("a status");
    assert_eq!(code, 408);
    assert!(!super::b2bua::is_script_reoffer(&branch));
    let sent = wire(&call.dispatcher);
    assert!(
        sent_with(&sent, call.a.1, Method::Ack).is_none(),
        "a 408 nobody sent is not ACKed"
    );
    assert!(
        matches!(
            tokio::task::block_in_place(|| super::b2bua::reoffer_leg(state, &internal, true, None)),
            Ok(super::b2bua::Reoffered::Sent { .. })
        ),
        "the INVITE toward the caller is no longer in progress"
    );
}

/// A re-INVITE relayed to a callee that never answers ends at Timer B as a
/// 408 the caller is answered with, rather than leaving the caller's INVITE
/// unanswered (RFC 3261 §16.7 step 2 has a proxy do the same), and the callee's
/// leg takes the caller's next re-INVITE instead of answering it 491.
#[tokio::test(flavor = "multi_thread")]
async fn a_relayed_reinvite_the_callee_never_answers_is_answered_408_at_timer_b() {
    let call = call_deciding(83210, "pass");
    let caller = caller_of(&call);
    acks(&call.dispatcher.state, &caller);

    let sent = offers(
        &call,
        &caller,
        "INVITE",
        2,
        Some(&caller_sdp(&call, "a=sendonly\r\n")),
    );
    assert!(
        sent_with(&sent, call.b.1, Method::Invite).is_some(),
        "the hold is relayed"
    );

    past_timer_b(&call);

    let sent = wire(&call.dispatcher);
    let answered = final_to(&sent, call.a.1).expect("the caller is answered");
    assert_eq!(answered.status_code(), Some(408));
    assert!(
        sent_with(&sent, call.b.1, Method::Ack).is_none(),
        "nothing is ACKed to the silent callee"
    );

    let sent = offers(&call, &caller, "INVITE", 3, Some(&caller_sdp(&call, "")));
    assert!(
        sent_with(&sent, call.b.1, Method::Invite).is_some(),
        "the next re-INVITE is relayed"
    );
    assert_ne!(
        final_to(&sent, call.a.1).and_then(|response| response.status_code()),
        Some(491),
        "not refused as crossing"
    );
}
