//! The provisional responses of a call siphon placed: `@b2bua.on_originate_progress`
//! for a call a script placed, and the PRACK every reliable one is owed
//! (RFC 3262 §4), whoever placed the call.
//!
//! A script that holds a caller and rings a called party with
//! `b2bua.originate()` has to tell the caller the party is being alerted (a
//! `180` of its own), and the only place it can learn that is the `180` the
//! party sends on the leg siphon placed. siphon is the UAC of that leg, so a
//! reliable `180` is also siphon's to acknowledge: nobody else can PRACK it.
//!
//! Driven through the dispatcher's response path, what siphon sent read back
//! off the UDP egress, and what the handler saw read back from the script.

use std::time::Duration;

use super::originate_test_harness::{
    anchored_dispatcher, anchored_params, drain, phone_offer, phone_response, phone_sends,
    requests_to, socket, Sent,
};
use super::test_dispatcher::{test_dispatcher_with_script, TestDispatcher};
use super::*;
use crate::rtpengine::test_native_engine::NativeTestEngine;

const PHONE: &str = "198.51.100.30:5060";
const PHONE_CONTACT: &str = "sip:callee@198.51.100.30:5060";
const PHONE_TAG: &str = "callee-tag";

/// The offer of a call placed with `b2bua.originate(sdp=...)`.
const OFFER: &str = concat!(
    "v=0\r\n",
    "o=- 1 1 IN IP4 192.0.2.1\r\n",
    "s=-\r\n",
    "c=IN IP4 192.0.2.1\r\n",
    "t=0 0\r\n",
    "m=audio 40000 RTP/AVP 0\r\n",
);

/// A script whose handlers note what they are called with in `builtins.<slot>`.
fn recording_script(slot: &str) -> String {
    format!(
        concat!(
            "import builtins\n",
            "from siphon import b2bua\n",
            "\n",
            "builtins.{slot} = []\n",
            "\n",
            "@b2bua.on_originate_progress\n",
            "def progress(call_id, code, reason, reply):\n",
            "    body = reply.body\n",
            "    builtins.{slot}.append(\n",
            "        f\"{{code}} {{reason}} call={{call_id}} status={{reply.status_code}} \"\n",
            "        f\"rseq={{reply.get_header('RSeq')}} body={{len(body) if body else 0}}\"\n",
            "    )\n",
            "\n",
            "@b2bua.on_answer\n",
            "def answer(call, reply):\n",
            "    builtins.{slot}.append(\"answer\")\n",
        ),
        slot = slot
    )
}

/// What the handlers of [`recording_script`] noted, in order.
fn noted(slot: &str) -> Vec<String> {
    Python::attach(|python| {
        python
            .import("builtins")
            .and_then(|builtins| builtins.getattr(slot))
            .and_then(|notes| notes.extract())
            .expect("the script's notes")
    })
}

fn offer_params(headers: &[(&str, &str)]) -> OriginateParams {
    OriginateParams {
        to: PHONE_CONTACT.to_string(),
        to_display: None,
        from: Some("sip:server@siphon.example.com".to_string()),
        from_display: None,
        next_hop: None,
        p_asserted_identity: None,
        privacy: None,
        headers: headers
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect(),
        timeout_secs: 30,
        media: OriginateMedia::Offer {
            body: OFFER.as_bytes().to_vec(),
            content_type: "application/sdp".to_string(),
        },
        session_timer: None,
    }
}

/// Place a call the way `b2bua.originate()` does: staged, marked as the
/// script's, then dialled. Returns it with its INVITE off the wire.
fn script_places(dispatcher: &TestDispatcher, params: OriginateParams) -> PreparedOriginate {
    let prepared = prepare_originate(&dispatcher.state, params).expect("the originate stages");
    dispatcher
        .state
        .call_actors
        .mark_script_originated(&prepared.internal_call_id);
    assert!(dial_originate(&dispatcher.state, &prepared));
    let sent = drain(&dispatcher.udp);
    assert_eq!(requests_to(&sent, socket(PHONE), Method::Invite).len(), 1);
    prepared
}

/// The phone's response to the call's INVITE, reliable under `rseq` when given.
fn phone_says(
    prepared: &PreparedOriginate,
    status_code: u16,
    reason: &str,
    rseq: Option<u32>,
    body: Option<&str>,
) -> SipMessage {
    let mut response = phone_response(
        &prepared.invite,
        status_code,
        reason,
        PHONE_TAG,
        PHONE_CONTACT,
        body,
    );
    if let Some(rseq) = rseq {
        response.headers.set("Require", "100rel".to_string());
        response.headers.set("RSeq", rseq.to_string());
    }
    response
}

fn phone_answers(dispatcher: &TestDispatcher, response: &SipMessage) -> Vec<Sent> {
    phone_sends(&dispatcher.state, socket(PHONE), response);
    drain(&dispatcher.udp)
}

fn header(message: &SipMessage, name: &str) -> Option<String> {
    message.headers.get(name).cloned()
}

/// A plain `180` then the `200`: the handler runs once, with the response in
/// hand, before `@b2bua.on_answer`. Nothing is sent for an unreliable `180`.
#[tokio::test(flavor = "multi_thread")]
async fn a_180_runs_the_handler_once_before_on_answer() {
    let slot = "progress_180_then_200";
    let dispatcher = test_dispatcher_with_script(&recording_script(slot));
    let prepared = script_places(&dispatcher, offer_params(&[]));

    let sent = phone_answers(
        &dispatcher,
        &phone_says(&prepared, 180, "Ringing", None, None),
    );
    assert!(sent.is_empty(), "an unreliable 180 is owed nothing");
    assert_eq!(
        noted(slot),
        [format!(
            "180 Ringing call={} status=180 rseq=None body=0",
            prepared.sip_call_id
        )]
    );

    let sent = phone_answers(
        &dispatcher,
        &phone_says(&prepared, 200, "OK", None, Some(OFFER)),
    );
    assert_eq!(requests_to(&sent, socket(PHONE), Method::Ack).len(), 1);
    let notes = noted(slot);
    assert_eq!(notes.len(), 2, "{notes:?}");
    assert_eq!(notes[1], "answer");

    // A provisional overtaken by the answer, reliable or not, is dropped: no
    // handler after `on_answer`, no PRACK, and the call stays answered.
    for rseq in [None, Some(1)] {
        let late = phone_says(&prepared, 180, "Ringing", rseq, None);
        assert!(phone_answers(&dispatcher, &late).is_empty());
    }
    assert_eq!(noted(slot).len(), 2);
    assert_eq!(
        dispatcher
            .state
            .call_actors
            .get_call(&prepared.internal_call_id)
            .map(|call| call.state.clone()),
        Some(CallState::Answered)
    );
}

/// A `183` with a session description hands the handler the body, and a `100`
/// runs nothing: it is hop by hop (RFC 3261 §16.7 step 2).
#[tokio::test(flavor = "multi_thread")]
async fn a_183_with_sdp_hands_the_handler_its_body_and_a_100_runs_nothing() {
    let slot = "progress_183_with_sdp";
    let dispatcher = test_dispatcher_with_script(&recording_script(slot));
    let prepared = script_places(&dispatcher, offer_params(&[]));

    phone_answers(
        &dispatcher,
        &phone_says(&prepared, 100, "Trying", None, None),
    );
    assert!(noted(slot).is_empty());

    phone_answers(
        &dispatcher,
        &phone_says(&prepared, 183, "Session Progress", None, Some(OFFER)),
    );
    assert_eq!(
        noted(slot),
        [format!(
            "183 Session Progress call={} status=183 rseq=None body={}",
            prepared.sip_call_id,
            OFFER.len()
        )]
    );
}

/// RFC 3262 §4: a reliable `180` is PRACKed on its early dialog and then
/// handed to the handler, once. Its retransmission is discarded: no second
/// PRACK, no second call. The next reliable provisional takes the next CSeq,
/// and the BYE that ends the call later is numbered past every PRACK
/// (RFC 3261 §12.2.1.1).
#[tokio::test(flavor = "multi_thread")]
async fn a_reliable_180_is_pracked_and_handed_to_the_handler_once() {
    let slot = "progress_reliable_180";
    let dispatcher = test_dispatcher_with_script(&recording_script(slot));
    let prepared = script_places(&dispatcher, offer_params(&[("Supported", "100rel")]));
    assert_eq!(
        header(&prepared.invite, "Supported").as_deref(),
        Some("100rel")
    );

    let ringing = phone_says(&prepared, 180, "Ringing", Some(7), None);
    let sent = phone_answers(&dispatcher, &ringing);
    let pracks = requests_to(&sent, socket(PHONE), Method::Prack);
    assert_eq!(pracks.len(), 1, "one PRACK for the reliable 180");
    assert_eq!(sent.len(), 1, "and nothing else");
    let prack = &pracks[0].message;
    assert_eq!(header(prack, "RAck").as_deref(), Some("7 1 INVITE"));
    assert_eq!(header(prack, "CSeq").as_deref(), Some("2 PRACK"));
    assert_eq!(
        header(prack, "Call-ID").as_deref(),
        Some(prepared.sip_call_id.as_str())
    );
    assert_eq!(header(prack, "From"), header(&prepared.invite, "From"));
    assert_eq!(header(prack, "To"), header(&ringing, "To"));
    assert!(
        prack
            .to_bytes()
            .starts_with(b"PRACK sip:callee@198.51.100.30:5060 SIP/2.0\r\n"),
        "the PRACK goes to the early dialog's remote target"
    );
    assert!(prack.body.is_empty());
    assert_eq!(noted(slot).len(), 1);
    assert!(noted(slot)[0].starts_with("180 Ringing "));
    assert!(noted(slot)[0].contains(" rseq=7 "));

    // The phone has not seen the PRACK yet and sends the 180 again.
    let sent = phone_answers(&dispatcher, &ringing);
    assert!(sent.is_empty(), "a retransmission is discarded");
    assert_eq!(noted(slot).len(), 1, "and runs no handler");

    let progress = phone_says(&prepared, 183, "Session Progress", Some(8), Some(OFFER));
    let sent = phone_answers(&dispatcher, &progress);
    let pracks = requests_to(&sent, socket(PHONE), Method::Prack);
    assert_eq!(pracks.len(), 1);
    assert_eq!(
        header(&pracks[0].message, "RAck").as_deref(),
        Some("8 1 INVITE")
    );
    assert_eq!(
        header(&pracks[0].message, "CSeq").as_deref(),
        Some("3 PRACK")
    );
    assert!(
        pracks[0].message.body.is_empty(),
        "SDP answering siphon's offer is not answered"
    );
    assert_eq!(noted(slot).len(), 2);

    // One that arrives ahead of its turn (9 is missing) is neither PRACKed
    // nor processed (RFC 3262 §4): the phone sends 9 and then it again.
    let ahead = phone_says(&prepared, 180, "Ringing", Some(10), None);
    assert!(phone_answers(&dispatcher, &ahead).is_empty());
    assert_eq!(noted(slot).len(), 2);

    // The 200 need not repeat the answer the reliable 183 gave (RFC 3261
    // §13.2.1).
    let sent = phone_answers(&dispatcher, &phone_says(&prepared, 200, "OK", None, None));
    assert_eq!(requests_to(&sent, socket(PHONE), Method::Ack).len(), 1);
    assert_eq!(noted(slot).last().map(String::as_str), Some("answer"));

    assert!(b2bua_terminate_call_inner(
        &prepared.internal_call_id,
        None,
        "b2bua",
        &dispatcher.state
    ));
    let byes = requests_to(&drain(&dispatcher.udp), socket(PHONE), Method::Bye);
    assert_eq!(byes.len(), 1);
    assert_eq!(header(&byes[0].message, "CSeq").as_deref(), Some("4 BYE"));
}

/// With no handler registered the provisionals do what they did: the call
/// rings and nothing is sent. A reliable one is still PRACKed, which is the
/// protocol's and no handler's.
#[tokio::test(flavor = "multi_thread")]
async fn without_a_handler_a_provisional_only_moves_the_call() {
    let dispatcher = test_dispatcher_with_script("");
    let prepared = script_places(&dispatcher, offer_params(&[]));

    let sent = phone_answers(
        &dispatcher,
        &phone_says(&prepared, 180, "Ringing", None, None),
    );
    assert!(sent.is_empty());
    assert_eq!(
        dispatcher
            .state
            .call_actors
            .get_call(&prepared.internal_call_id)
            .map(|call| call.state.clone()),
        Some(CallState::Ringing)
    );

    let sent = phone_answers(
        &dispatcher,
        &phone_says(&prepared, 180, "Ringing", Some(1), None),
    );
    assert_eq!(requests_to(&sent, socket(PHONE), Method::Prack).len(), 1);
}

/// A call the control plane placed runs no script handler for its progress,
/// whatever the script registers: it is reported as channel events. Its
/// reliable provisionals are PRACKed all the same.
#[tokio::test(flavor = "multi_thread")]
async fn a_call_the_control_plane_placed_runs_no_handler() {
    let slot = "progress_control_plane";
    let dispatcher = test_dispatcher_with_script(&recording_script(slot));
    let prepared =
        prepare_originate(&dispatcher.state, offer_params(&[])).expect("the originate stages");
    assert!(dial_originate(&dispatcher.state, &prepared));
    let _ = drain(&dispatcher.udp);

    phone_answers(
        &dispatcher,
        &phone_says(&prepared, 180, "Ringing", None, None),
    );
    let sent = phone_answers(
        &dispatcher,
        &phone_says(&prepared, 183, "Progress", Some(1), None),
    );
    assert_eq!(requests_to(&sent, socket(PHONE), Method::Prack).len(), 1);
    assert!(noted(slot).is_empty(), "{:?}", noted(slot));
}

/// RFC 3262 §5: SDP in a reliable provisional to an INVITE that carried none
/// is the callee's offer, and siphon's PRACK answers it on the media engine.
/// The 2xx is then ACKed without a second answer, and the call is anchored
/// once.
#[tokio::test(flavor = "multi_thread")]
async fn an_offerless_call_answers_a_reliable_provisionals_offer_in_its_prack() {
    let slot = "progress_offer_in_183";
    let engine = NativeTestEngine::start().await;
    let mut dispatcher = anchored_dispatcher(&engine);
    dispatcher.state.engine = Arc::new(
        crate::script::engine::ScriptEngine::new_embedded(&recording_script(slot))
            .expect("the test script compiles"),
    );
    let mut params = anchored_params(PHONE_CONTACT);
    params
        .headers
        .push(("Supported".to_string(), "100rel".to_string()));
    let prepared = script_places(&dispatcher, params);
    assert!(prepared.invite.body.is_empty());

    let offer = phone_offer("198.51.100.30");
    let sent = phone_answers(
        &dispatcher,
        &phone_says(&prepared, 183, "Session Progress", Some(1), Some(&offer)),
    );
    let pracks = requests_to(&sent, socket(PHONE), Method::Prack);
    assert_eq!(pracks.len(), 1);
    let answer = String::from_utf8(pracks[0].message.body.clone()).expect("an SDP answer");
    assert!(answer.contains("m=audio "), "the PRACK answers: {answer:?}");
    assert_eq!(
        header(&pracks[0].message, "Content-Type").as_deref(),
        Some("application/sdp")
    );
    assert_eq!(noted(slot).len(), 1);
    let sessions = dispatcher
        .state
        .rtpengine_sessions
        .clone()
        .expect("a media session store");
    assert_eq!(sessions.len(), 1, "the leg is anchored at the PRACK");

    // A later reliable provisional of the same dialog repeats the session.
    let sent = phone_answers(
        &dispatcher,
        &phone_says(&prepared, 180, "Ringing", Some(2), Some(&offer)),
    );
    let pracks = requests_to(&sent, socket(PHONE), Method::Prack);
    assert_eq!(pracks.len(), 1);
    assert!(pracks[0].message.body.is_empty());

    let sent = phone_answers(
        &dispatcher,
        &phone_says(&prepared, 200, "OK", None, Some(&offer)),
    );
    let acks = requests_to(&sent, socket(PHONE), Method::Ack);
    assert_eq!(acks.len(), 1);
    assert!(
        acks[0].message.body.is_empty(),
        "the offer was answered in the PRACK, not again in the ACK"
    );
    assert_eq!(sessions.len(), 1, "and anchored once");
    assert_eq!(
        dispatcher
            .state
            .call_actors
            .clone_leg(&prepared.internal_call_id, true)
            .and_then(|leg| leg.dialog.last_sent_sdp),
        Some(answer.into_bytes()),
        "the PRACK's answer is the session in force on the dialog"
    );
}

/// RFC 3261 §9.1, §12.2.1.1: a leg given up after a PRACK, whose phone answers
/// anyway, is released with an ACK and a BYE numbered past that PRACK.
#[tokio::test(flavor = "multi_thread")]
async fn a_leg_cancelled_after_a_prack_is_released_with_a_bye_numbered_past_it() {
    let dispatcher = test_dispatcher_with_script("");
    let prepared = script_places(&dispatcher, offer_params(&[("Supported", "100rel")]));
    let sent = phone_answers(
        &dispatcher,
        &phone_says(&prepared, 180, "Ringing", Some(1), None),
    );
    let pracks = requests_to(&sent, socket(PHONE), Method::Prack);
    assert_eq!(
        header(&pracks[0].message, "CSeq").as_deref(),
        Some("2 PRACK")
    );

    assert!(cancel_originated_call(
        &dispatcher.state,
        &prepared.sip_call_id,
        None
    ));
    let sent = drain(&dispatcher.udp);
    assert_eq!(requests_to(&sent, socket(PHONE), Method::Cancel).len(), 1);

    // The 200 crossed the CANCEL.
    let sent = phone_answers(
        &dispatcher,
        &phone_says(&prepared, 200, "OK", None, Some(OFFER)),
    );
    assert_eq!(requests_to(&sent, socket(PHONE), Method::Ack).len(), 1);
    let byes = requests_to(&sent, socket(PHONE), Method::Bye);
    assert_eq!(byes.len(), 1, "the dialog the 200 opened is released");
    assert_eq!(header(&byes[0].message, "CSeq").as_deref(), Some("3 BYE"));
}

/// RFC 3261 §13.2.1: an answer to the offer in siphon's INVITE that came in a
/// reliable provisional need not be repeated in the 2xx. It is kept, and the
/// 2xx without SDP connects the call with it.
#[tokio::test(flavor = "multi_thread")]
async fn a_reliable_answer_to_siphons_offer_serves_a_200_that_does_not_repeat_it() {
    let engine = NativeTestEngine::start().await;
    let dispatcher = anchored_dispatcher(&engine);
    let mut params = anchored_params(PHONE_CONTACT);
    params
        .headers
        .push(("Supported".to_string(), "100rel".to_string()));
    let prepared = script_places(&dispatcher, params);
    // The leg's INVITE carried an engine allocation as its offer, as a
    // bridging dial with an early offer places it.
    dispatcher.state.call_actors.set_originate_offer(
        &prepared.internal_call_id,
        crate::b2bua::actor::OriginateOffer {
            media_call_id: "bridge-media".to_string(),
            offerer_tag: "caller-tag".to_string(),
        },
    );

    let answer = phone_offer("198.51.100.30");
    let sent = phone_answers(
        &dispatcher,
        &phone_says(&prepared, 183, "Session Progress", Some(1), Some(&answer)),
    );
    let pracks = requests_to(&sent, socket(PHONE), Method::Prack);
    assert_eq!(pracks.len(), 1);
    assert!(
        pracks[0].message.body.is_empty(),
        "an answer is not answered"
    );

    let sent = phone_answers(&dispatcher, &phone_says(&prepared, 200, "OK", None, None));
    assert_eq!(requests_to(&sent, socket(PHONE), Method::Ack).len(), 1);
    assert!(
        requests_to(&sent, socket(PHONE), Method::Bye).is_empty(),
        "the call was released as unanswered"
    );
    let call = dispatcher
        .state
        .call_actors
        .get_call(&prepared.internal_call_id)
        .expect("the call is up");
    assert_eq!(call.state, CallState::Answered);
    assert_eq!(call.a_leg.last_sdp, Some(answer.into_bytes()));
}

/// RFC 3261 §12.3, §22.2: an INVITE challenged after its reliable provisional
/// is sent again as a new transaction. The early dialog whose offer a PRACK
/// answered ended with the challenge, so its media is released and the new
/// dialog's offer is answered afresh, not rejected as a second fork's.
#[tokio::test(flavor = "multi_thread")]
async fn a_credentialed_retry_starts_the_session_over() {
    let engine = NativeTestEngine::start().await;
    let dispatcher = anchored_dispatcher(&engine);
    let sessions = dispatcher
        .state
        .rtpengine_sessions
        .clone()
        .expect("a media session store");
    let mut params = anchored_params(PHONE_CONTACT);
    params
        .headers
        .push(("Supported".to_string(), "100rel".to_string()));
    let prepared = script_places(&dispatcher, params);
    if let Some(mut call) = dispatcher
        .state
        .call_actors
        .get_call_mut(&prepared.internal_call_id)
    {
        call.outbound_credentials = Some(Arc::new(crate::auth::StoredCredentials {
            username: "server".to_string(),
            secret: crate::auth::StoredSecret::Password("secret".to_string()),
        }));
    }
    let offer = phone_offer("198.51.100.30");
    let sent = phone_answers(
        &dispatcher,
        &phone_says(&prepared, 183, "Session Progress", Some(1), Some(&offer)),
    );
    assert!(!requests_to(&sent, socket(PHONE), Method::Prack)[0]
        .message
        .body
        .is_empty());
    assert_eq!(sessions.len(), 1);

    let mut challenge = phone_says(&prepared, 401, "Unauthorized", None, None);
    challenge.headers.set(
        "WWW-Authenticate",
        r#"Digest realm="example.com", nonce="abc123", qop="auth", algorithm=MD5"#.to_string(),
    );
    let sent = phone_answers(&dispatcher, &challenge);
    let retries = requests_to(&sent, socket(PHONE), Method::Invite);
    assert_eq!(
        retries.len(),
        1,
        "the INVITE is sent again with credentials"
    );
    let retry = &retries[0].message;
    assert_eq!(header(retry, "CSeq").as_deref(), Some("4 INVITE"));
    assert_eq!(sessions.len(), 0, "the ended dialog's media is released");

    // The new transaction's early dialog, under its own tag.
    let mut progress = phone_response(
        retry,
        183,
        "Session Progress",
        "second-tag",
        PHONE_CONTACT,
        Some(&offer),
    );
    progress.headers.set("Require", "100rel".to_string());
    progress.headers.set("RSeq", "1".to_string());
    let sent = phone_answers(&dispatcher, &progress);
    let pracks = requests_to(&sent, socket(PHONE), Method::Prack);
    assert_eq!(pracks.len(), 1);
    let answer = String::from_utf8(pracks[0].message.body.clone()).expect("an SDP answer");
    assert!(
        answer.contains("m=audio ") && !answer.contains("m=audio 0 "),
        "the new dialog's offer is accepted, not rejected: {answer:?}"
    );
    assert_eq!(
        header(&pracks[0].message, "CSeq").as_deref(),
        Some("5 PRACK")
    );
    assert_eq!(sessions.len(), 1);

    let ok = phone_response(retry, 200, "OK", "second-tag", PHONE_CONTACT, None);
    let sent = phone_answers(&dispatcher, &ok);
    assert_eq!(requests_to(&sent, socket(PHONE), Method::Ack).len(), 1);
    assert!(requests_to(&sent, socket(PHONE), Method::Bye).is_empty());
}

/// Leak gate: calls that ring reliably and are then rejected, or answered and
/// hung up, leave no call and no media session behind.
#[tokio::test(flavor = "multi_thread")]
async fn calls_with_reliable_provisionals_leave_nothing_behind() {
    let engine = NativeTestEngine::start().await;
    let dispatcher = anchored_dispatcher(&engine);
    let sessions = dispatcher
        .state
        .rtpengine_sessions
        .clone()
        .expect("a media session store");
    let baseline = dispatcher.state.call_actors.count();

    for round in 0..50 {
        let mut params = anchored_params(PHONE_CONTACT);
        params
            .headers
            .push(("Supported".to_string(), "100rel".to_string()));
        let prepared = script_places(&dispatcher, params);
        let offer = phone_offer("198.51.100.30");
        phone_answers(
            &dispatcher,
            &phone_says(&prepared, 183, "Session Progress", Some(1), Some(&offer)),
        );
        if round % 2 == 0 {
            phone_answers(
                &dispatcher,
                &phone_says(&prepared, 486, "Busy Here", None, None),
            );
        } else {
            phone_answers(&dispatcher, &phone_says(&prepared, 200, "OK", None, None));
            assert!(b2bua_terminate_call_inner(
                &prepared.internal_call_id,
                None,
                "b2bua",
                &dispatcher.state
            ));
        }
        let _ = drain(&dispatcher.udp);
    }

    assert_eq!(dispatcher.state.call_actors.count(), baseline);
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !sessions.is_empty() && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(sessions.len(), 0, "every media session was released");
}

const SCRIPTED: &str = "dispatcher::originate_progress_tests::a_script_hears_the_reliable_ringing_of_a_leg_it_placed_after_the_prack";

/// End to end from the scripting API, in a process of its own because
/// `b2bua.originate()` reaches the dispatcher through a process-wide handle:
/// the script places the leg, the phone rings reliably, and the handler,
/// which places a second leg, runs after the PRACK has left.
#[test]
fn a_script_hears_the_reliable_ringing_of_a_leg_it_placed_after_the_prack() {
    super::own_process_test::run_in_own_process(SCRIPTED, Duration::from_secs(60), scripted);
}

fn scripted() {
    let script = concat!(
        "import builtins\n",
        "from siphon import b2bua\n",
        "\n",
        "builtins.scripted_progress = []\n",
        "OFFER = (\n",
        "    \"v=0\\r\\no=- 1 1 IN IP4 192.0.2.1\\r\\ns=-\\r\\n\"\n",
        "    \"c=IN IP4 192.0.2.1\\r\\nt=0 0\\r\\nm=audio 40002 RTP/AVP 0\\r\\n\"\n",
        ")\n",
        "\n",
        "@b2bua.on_originate_progress\n",
        "def progress(call_id, code, reason, reply):\n",
        "    builtins.scripted_progress.append(f\"{code} {reason} {call_id}\")\n",
        "    b2bua.originate(to=\"sip:other@198.51.100.31:5060\", sdp=OFFER)\n",
    );
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("a runtime");
    runtime.block_on(async {
        // What `b2bua.originate()` reaches the dispatcher through goes in
        // before the script engine is built, which is when it is injected.
        Python::initialize();
        Python::attach(crate::script::api::set_b2bua_control_singleton)
            .expect("the script reaches the dispatcher");
        let TestDispatcher { state, udp } = test_dispatcher_with_script(script);
        let state = Arc::new(state);
        install_charging_hooks(&state);

        let call_id: String = Python::attach(|python| {
            let arguments = pyo3::types::PyDict::new(python);
            arguments.set_item("to", PHONE_CONTACT)?;
            arguments.set_item("from_uri", "sip:server@siphon.example.com")?;
            arguments.set_item("sdp", OFFER)?;
            let headers = pyo3::types::PyDict::new(python);
            headers.set_item("Supported", "100rel")?;
            arguments.set_item("headers", headers)?;
            python
                .import("siphon")?
                .getattr("b2bua")?
                .call_method("originate", (), Some(&arguments))?
                .extract()
        })
        .expect("b2bua.originate() places the call");
        let invites = requests_to(&drain(&udp), socket(PHONE), Method::Invite);
        assert_eq!(invites.len(), 1);
        let invite = &invites[0].message;
        assert_eq!(header(invite, "Call-ID").as_deref(), Some(call_id.as_str()));

        let mut ringing = phone_response(invite, 180, "Ringing", PHONE_TAG, PHONE_CONTACT, None);
        ringing.headers.set("Require", "100rel".to_string());
        ringing.headers.set("RSeq", "1".to_string());
        phone_sends(&state, socket(PHONE), &ringing);

        let sent = drain(&udp);
        let methods: Vec<_> = sent
            .iter()
            .filter_map(|frame| frame.message.method().cloned())
            .collect();
        assert_eq!(
            methods,
            [Method::Prack, Method::Invite],
            "the PRACK leaves before what the handler sends"
        );
        assert_eq!(sent[0].destination, socket(PHONE));
        assert_eq!(sent[1].destination, socket("198.51.100.31:5060"));
        assert_eq!(
            noted("scripted_progress"),
            [format!("180 Ringing {call_id}")]
        );
    });
}
