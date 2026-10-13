//! A callee's UPDATE with an offer while the caller takes its answer in the 2xx
//! (RFC 3311 §5, RFC 3312 §5, RFC 3261 §13.2.1).
//!
//! A callee that uses preconditions answers siphon's INVITE in a reliable 183,
//! is PRACKed, and reports its resources reserved in an UPDATE with a new
//! offer. Toward that callee siphon is the UAC of the dialog and owes the
//! UPDATE an answer. The caller's dialog cannot be sent an UPDATE with an offer
//! before it has had its answer reliably (RFC 3311 §5.1), which for a caller
//! without `100rel`, or one a script kept the session description from, is its
//! 2xx. So siphon answers the UPDATE on the callee's dialog, and the caller's
//! 2xx carries the callee's description as that offer left it.
//!
//! Driven with the harness of [`super::a_leg_reliable_provisional_tests`].

use super::a_leg_reliable_provisional_tests::{
    default_dial, dial_script, is_reliable, only, statuses, Call, CALLEE, CALLEE_SDP, PLAIN,
    RELIABLY, SUPPORTS,
};
use super::answer_after_preview_tests::hex_dump;
use super::lcr_ring_timeout_tests::{summaries, Sent};
use super::test_dispatcher::{test_dispatcher_with_script, TestDispatcher};
use super::*;
use crate::rtpengine::test_engine::TestEngine;

const CALLER: &str = "192.0.2.10:5060";

/// The callee's answer in its reliable 183: nothing reserved on either access
/// network yet (RFC 3312 §13.2, SDP2).
const PROGRESS_ANSWER: &str = concat!(
    "v=0\r\n",
    "o=- 2 2 IN IP4 198.51.100.7\r\n",
    "s=-\r\n",
    "c=IN IP4 198.51.100.7\r\n",
    "t=0 0\r\n",
    "m=audio 50000 RTP/AVP 0\r\n",
    "a=curr:qos local none\r\n",
    "a=curr:qos remote none\r\n",
    "a=des:qos mandatory local sendrecv\r\n",
    "a=des:qos optional remote sendrecv\r\n",
    "a=conf:qos remote sendrecv\r\n",
);

/// The callee's offer in its UPDATE once its own access network is reserved,
/// from another address and port than its 183 named.
const UPDATE_OFFER: &str = concat!(
    "v=0\r\n",
    "o=- 2 3 IN IP4 198.51.100.7\r\n",
    "s=-\r\n",
    "c=IN IP4 198.51.100.9\r\n",
    "t=0 0\r\n",
    "m=audio 50002 RTP/AVP 0\r\n",
    "a=curr:qos local sendrecv\r\n",
    "a=curr:qos remote none\r\n",
    "a=des:qos mandatory local sendrecv\r\n",
    "a=des:qos optional remote sendrecv\r\n",
);

/// [`CALLEE_SDP`] again as an offer: the same description at its next version.
const UNCHANGED_OFFER: &str = concat!(
    "v=0\r\n",
    "o=- 2 3 IN IP4 198.51.100.7\r\n",
    "s=-\r\n",
    "c=IN IP4 198.51.100.7\r\n",
    "t=0 0\r\n",
    "m=audio 50000 RTP/AVP 0\r\n",
);

/// Relay a provisional without its session description.
const WITHOUT_BODY: &str = concat!(
    "\n",
    "@b2bua.on_provisional\n",
    "def on_provisional(call, reply):\n",
    "    if reply.has_body(\"application/sdp\"):\n",
    "        reply.relay(body=False)\n",
);

fn text(body: &[u8]) -> String {
    String::from_utf8_lossy(body).into_owned()
}

fn header(message: &SipMessage, name: &str) -> String {
    message
        .headers
        .get(name)
        .cloned()
        .unwrap_or_else(|| panic!("the message has no {name}"))
}

fn origin(message: &SipMessage) -> String {
    text(&message.body)
        .lines()
        .find(|line| line.starts_with("o="))
        .map(str::to_string)
        .expect("an o= line")
}

/// The `a=curr:` and `a=des:` lines of a session description, in order.
fn precondition_lines(message: &SipMessage) -> Vec<String> {
    text(&message.body)
        .lines()
        .filter(|line| line.starts_with("a=curr:") || line.starts_with("a=des:"))
        .map(str::to_string)
        .collect()
}

fn to(sent: &[Sent], party: &str) -> Vec<SipMessage> {
    let address: SocketAddr = party.parse().expect("a literal address");
    sent.iter()
        .filter(|sent| sent.destination == address)
        .map(|sent| sent.message.clone())
        .collect()
}

/// The callee sends an UPDATE numbered `cseq` on the early dialog its 183
/// opened, with `body` as its offer, and siphon's one response to it comes
/// back. Nothing may go to the caller for it.
fn callee_updates(call: &Call, cseq: u32, body: Option<&str>) -> SipMessage {
    callee_at_updates(
        call,
        &call.callee_invite,
        (CALLEE, "callee-tag"),
        cseq,
        body,
    )
}

/// [`callee_updates`] for the callee at `source` that siphon sent `invite`, on
/// the early dialog its To tag `tag` names.
fn callee_at_updates(
    call: &Call,
    invite: &SipMessage,
    (source, tag): (&str, &str),
    cseq: u32,
    body: Option<&str>,
) -> SipMessage {
    let content = match body {
        Some(sdp) => format!(
            "Content-Type: application/sdp\r\nContent-Length: {}\r\n\r\n{sdp}",
            sdp.len()
        ),
        None => "Content-Length: 0\r\n\r\n".to_string(),
    };
    let raw = format!(
        concat!(
            "UPDATE sip:192.0.2.1:5060 SIP/2.0\r\n",
            "Via: SIP/2.0/UDP {callee};branch=z9hG4bK-callee-update-{cseq}\r\n",
            "Max-Forwards: 70\r\n",
            "From: {from};tag={tag}\r\n",
            "To: {to}\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: {cseq} UPDATE\r\n",
            "Contact: <sip:callee@{callee}>\r\n",
            "{content}",
        ),
        callee = source,
        cseq = cseq,
        tag = tag,
        from = header(invite, "To"),
        to = header(invite, "From"),
        call_id = header(invite, "Call-ID"),
        content = content,
    );
    let inbound = InboundMessage {
        client_transport: None,
        connection_id: ConnectionId::default(),
        transport: Transport::Udp,
        local_addr: call.state.local_addr,
        remote_addr: source.parse().expect("a literal address"),
        data: Bytes::from(raw.clone().into_bytes()),
    };
    let message = parse_sip_message_bytes(raw.as_bytes()).expect("the UPDATE parses");
    tokio::task::block_in_place(|| {
        super::request::handle_request(inbound, message, "UPDATE".to_string(), &call.state)
    });
    let sent = call.wire();
    assert!(
        to(&sent, CALLER).is_empty(),
        "nothing goes to the caller for the callee's UPDATE: {:?}",
        summaries(&sent)
    );
    let mut responses: Vec<SipMessage> = to(&sent, source)
        .into_iter()
        .filter(|message| message.status_code().is_some_and(|status| status >= 200))
        .collect();
    assert_eq!(responses.len(), 1, "{:?}", summaries(&sent));
    responses.remove(0)
}

/// The `o=` session id and version the next session description siphon sends
/// the caller goes out under.
fn next_origin_toward_caller(call: &Call) -> (u64, u64) {
    call.state
        .call_actors
        .reserve_leg_sdp_version(&call.call_id, true)
        .expect("the caller's leg")
}

/// The session id of the caller's dialog before siphon has sent it anything.
fn callers_own_session_id(call: &Call) -> u64 {
    call.state
        .call_actors
        .clone_leg(&call.call_id, true)
        .expect("the caller's leg")
        .dialog
        .sdp_session_id
}

/// What the answer to [`UPDATE_OFFER`] says of the preconditions: siphon has
/// nothing to reserve, so its own access network is ready, and it confirms what
/// the callee reported of the callee's, with every tag turned round for the
/// answerer (RFC 3312 §5.2, table 4).
const ANSWERED_STATUS: [&str; 4] = [
    "a=curr:qos local sendrecv",
    "a=curr:qos remote sendrecv",
    "a=des:qos optional local sendrecv",
    "a=des:qos mandatory remote sendrecv",
];

fn assert_answers_the_update(call: &Call, ok: &SipMessage, cseq: u32) {
    assert_eq!(ok.status_code(), Some(200), "{}", text(&ok.to_bytes()));
    assert_eq!(header(ok, "CSeq"), format!("{cseq} UPDATE"));
    assert_eq!(
        header(ok, "Call-ID"),
        header(&call.callee_invite, "Call-ID")
    );
    assert_eq!(header(ok, "To"), header(&call.callee_invite, "From"));
    assert_eq!(header(ok, "Content-Type"), "application/sdp");
    assert_eq!(header(ok, "Content-Length"), ok.body.len().to_string());
    assert_eq!(ok.headers.get("Retry-After"), None);
    assert!(
        header(ok, "Contact").contains("192.0.2.1"),
        "siphon's own Contact on the callee's dialog (RFC 3311 §5.2): {}",
        header(ok, "Contact")
    );
}

/// The defect: a caller without `100rel` was shown the callee's answer in an
/// unreliable 183, and the callee's UPDATE was refused 500 because the caller's
/// dialog cannot carry an offer before its 2xx. siphon answers it instead: its
/// own description on the callee's dialog, unchanged, with the precondition
/// status of an answerer that has nothing to reserve. The caller's 2xx then
/// carries the callee's description as the UPDATE left it, one version on from
/// the preview and without the callee's precondition attributes.
#[tokio::test(flavor = "multi_thread")]
async fn a_callees_update_is_answered_when_the_caller_takes_its_answer_in_the_2xx() {
    let call = Call::place(PLAIN, &default_dial());
    call.callee_sends(183, "Session Progress", RELIABLY, Some(PROGRESS_ANSWER));
    let progress = only(call.to_caller(), 183);
    assert!(!is_reliable(&progress));
    assert_eq!(origin(&progress), "o=siphon 2 2 IN IP4 192.0.2.1");

    let ok = callee_updates(&call, 1, Some(UPDATE_OFFER));
    assert_answers_the_update(&call, &ok, 1);
    let answer = text(&ok.body);
    // RFC 3264 §8: the stream siphon offered this callee, unchanged, with the
    // one format both sides have.
    assert!(answer.contains("c=IN IP4 192.0.2.10\r\n"), "{answer}");
    assert!(answer.contains("m=audio 40000 RTP/AVP 0\r\n"), "{answer}");
    assert_eq!(precondition_lines(&ok), ANSWERED_STATUS, "{answer}");
    assert!(!answer.contains("a=conf:"), "{answer}");
    // The session siphon's INVITE named on this dialog, at a later version.
    let offered = origin(&call.callee_invite);
    let offered: Vec<&str> = offered.split(' ').collect();
    let answered = origin(&ok);
    let answered: Vec<&str> = answered.split(' ').collect();
    assert_eq!(
        answered[1], offered[1],
        "one session on the callee's dialog"
    );
    assert!(
        answered[2].parse::<u64>().expect("a version")
            > offered[2].parse::<u64>().expect("a version"),
        "{answer}"
    );

    call.callee_sends(180, "Ringing", &[], None);
    assert!(only(call.to_caller(), 180).body.is_empty());

    call.callee_sends(200, "OK", &[], None);
    let answered = only(call.to_caller(), 200);
    let description = text(&answered.body);
    assert!(
        description.contains("c=IN IP4 198.51.100.9\r\n")
            && description.contains("m=audio 50002 RTP/AVP 0\r\n"),
        "the callee's address and port as its UPDATE gave them: {description}"
    );
    assert!(
        precondition_lines(&answered).is_empty() && !description.contains("a=conf:"),
        "the caller's leg negotiated no preconditions: {description}"
    );
    // The session the 183 previewed, revised once (RFC 3264 §8).
    assert_eq!(origin(&answered), "o=siphon 2 3 IN IP4 192.0.2.1");
    assert_eq!(header(&answered, "Content-Type"), "application/sdp");
    assert_eq!(next_origin_toward_caller(&call), (2, 4));
}

/// A caller a script kept the session description from has been shown nothing,
/// so its 2xx carries the callee's description after the UPDATE as the first
/// one it is sent: under its own dialog's session id at its first version.
#[tokio::test(flavor = "multi_thread")]
async fn the_2xx_after_an_answered_update_is_the_first_description_of_a_caller_shown_none() {
    let script = dial_script("transparent-b2bua@2026", WITHOUT_BODY);
    let call = Call::place(PLAIN, &script);
    let own = callers_own_session_id(&call);
    call.callee_sends(183, "Session Progress", RELIABLY, Some(PROGRESS_ANSWER));
    assert!(only(call.to_caller(), 183).body.is_empty());

    let ok = callee_updates(&call, 1, Some(UPDATE_OFFER));
    assert_answers_the_update(&call, &ok, 1);
    assert_eq!(precondition_lines(&ok), ANSWERED_STATUS);

    call.callee_sends(180, "Ringing", &[], None);
    assert!(only(call.to_caller(), 180).body.is_empty());

    call.callee_sends(200, "OK", &[], None);
    let answered = only(call.to_caller(), 200);
    let description = text(&answered.body);
    assert_eq!(
        origin(&answered),
        format!("o=siphon {own} 0 IN IP4 192.0.2.1")
    );
    assert!(
        description.contains("c=IN IP4 198.51.100.9\r\n")
            && description.contains("m=audio 50002 RTP/AVP 0\r\n"),
        "{description}"
    );
    assert!(precondition_lines(&answered).is_empty(), "{description}");
    assert_eq!(next_origin_toward_caller(&call), (own, 1));
}

/// An UPDATE that offers the description the 183 previewed changes nothing for
/// the caller, whose 2xx is then "the same exact answer" (RFC 6337 §3.1.1): the
/// preview's origin at the preview's version.
#[tokio::test(flavor = "multi_thread")]
async fn the_2xx_after_an_update_that_changed_nothing_repeats_the_preview() {
    let call = Call::place(PLAIN, &default_dial());
    call.callee_sends(183, "Session Progress", RELIABLY, Some(CALLEE_SDP));
    let progress = only(call.to_caller(), 183);

    let ok = callee_updates(&call, 1, Some(UNCHANGED_OFFER));
    assert_answers_the_update(&call, &ok, 1);
    assert!(
        precondition_lines(&ok).is_empty(),
        "no preconditions offered, none answered: {}",
        text(&ok.body)
    );

    call.callee_sends(200, "OK", &[], None);
    let answered = only(call.to_caller(), 200);
    assert_eq!(text(&answered.body), text(&progress.body));
    assert_eq!(next_origin_toward_caller(&call), (2, 3));
}

/// A callee whose 2xx carries a session description of its own is relayed as
/// before: that description, as a revision of the session the 183 previewed.
#[tokio::test(flavor = "multi_thread")]
async fn a_2xx_with_sdp_after_an_answered_update_is_the_callees_own() {
    let call = Call::place(PLAIN, &default_dial());
    call.callee_sends(183, "Session Progress", RELIABLY, Some(CALLEE_SDP));
    call.to_caller();
    callee_updates(&call, 1, Some(UPDATE_OFFER));

    call.callee_sends(200, "OK", &[], Some(UNCHANGED_OFFER));
    let answered = only(call.to_caller(), 200);
    assert!(text(&answered.body).contains("m=audio 50000 RTP/AVP 0\r\n"));
    assert_eq!(origin(&answered), "o=siphon 2 2 IN IP4 192.0.2.1");
}

/// A second UPDATE is answered like the first, the callee's dialog moving one
/// version on each time, and the caller's 2xx carries the last.
#[tokio::test(flavor = "multi_thread")]
async fn each_update_is_answered_and_the_2xx_carries_the_last() {
    let call = Call::place(PLAIN, &default_dial());
    call.callee_sends(183, "Session Progress", RELIABLY, Some(PROGRESS_ANSWER));
    call.to_caller();

    let first = callee_updates(&call, 1, Some(UPDATE_OFFER));
    let second = callee_updates(
        &call,
        2,
        Some(&UPDATE_OFFER.replace("50002", "50004").replace("2 3", "2 4")),
    );
    assert_answers_the_update(&call, &second, 2);
    let version = |message: &SipMessage| -> u64 {
        origin(message)
            .split(' ')
            .nth(2)
            .and_then(|version| version.parse().ok())
            .expect("a version")
    };
    assert_eq!(version(&second), version(&first) + 1);

    call.callee_sends(200, "OK", &[], None);
    let answered = only(call.to_caller(), 200);
    assert!(
        text(&answered.body).contains("m=audio 50004 RTP/AVP 0\r\n"),
        "{}",
        text(&answered.body)
    );
    assert_eq!(origin(&answered), "o=siphon 2 3 IN IP4 192.0.2.1");
}

/// A stream the callee puts on hold in its UPDATE is answered the other way
/// round (RFC 3264 §6.1), and the caller's 2xx says what the callee offered.
#[tokio::test(flavor = "multi_thread")]
async fn a_direction_the_callee_offers_is_answered_and_passed_on() {
    let call = Call::place(PLAIN, &default_dial());
    call.callee_sends(183, "Session Progress", RELIABLY, Some(CALLEE_SDP));
    call.to_caller();

    let offer = format!("{UNCHANGED_OFFER}a=sendonly\r\n");
    let ok = callee_updates(&call, 1, Some(&offer));
    assert!(
        text(&ok.body).contains("a=recvonly\r\n"),
        "{}",
        text(&ok.body)
    );

    call.callee_sends(200, "OK", &[], None);
    let answered = only(call.to_caller(), 200);
    assert!(
        text(&answered.body).contains("a=sendonly\r\n"),
        "{}",
        text(&answered.body)
    );
}

/// On an anchored call the callee's offer goes to the media engine as a
/// re-offer from the callee's side, as a relayed UPDATE's does, and the
/// caller's side of it as the answer: the callee is answered with the engine's
/// description toward it, and the caller's 2xx carries the engine's toward the
/// caller, cut down to what the caller offered.
#[tokio::test(flavor = "multi_thread")]
async fn an_answered_update_goes_through_the_media_engine_both_ways() {
    let engine = TestEngine::start(false).await;
    let call = place_anchored(&engine, "callee-tag").await;
    call.callee_sends(183, "Session Progress", RELIABLY, Some(PROGRESS_ANSWER));
    call.to_caller();
    let offers_before = engine.commands("offer").len();
    let answers_before = engine.commands("answer").len();

    let ok = callee_updates(&call, 1, Some(UPDATE_OFFER));
    assert_answers_the_update(&call, &ok, 1);
    let answer = text(&ok.body);
    assert!(answer.contains("c=IN IP4 203.0.113.50\r\n"), "{answer}");
    assert!(!answer.contains("192.0.2.10"), "{answer}");
    assert_eq!(precondition_lines(&ok), ANSWERED_STATUS, "{answer}");

    let offers = engine.commands("offer");
    assert_eq!(offers.len(), offers_before + 1);
    let reoffer = offers.last().expect("the re-offer");
    assert_eq!(reoffer.from_tag.as_deref(), Some("callee-tag"));
    assert!(reoffer.sdp.as_deref().is_some_and(|sdp| {
        sdp.contains("c=IN IP4 198.51.100.9") && sdp.contains("m=audio 50002 ")
    }));
    let answers = engine.commands("answer");
    assert_eq!(answers.len(), answers_before + 1);
    let answered = answers.last().expect("the answer");
    assert_eq!(answered.from_tag.as_deref(), Some("callee-tag"));
    assert_eq!(answered.to_tag.as_deref(), Some("caller-tag"));
    assert!(
        answered.sdp.as_deref().is_some_and(|sdp| {
            sdp.contains("c=IN IP4 192.0.2.10")
                && sdp.contains("m=audio 40000 RTP/AVP 0\r\n")
                && !sdp.contains("a=curr:")
        }),
        "the caller's own description answers for it: {:?}",
        answered.sdp
    );

    call.callee_sends(200, "OK", &[], None);
    let answered = only(call.to_caller(), 200);
    let description = text(&answered.body);
    assert!(
        description.contains("c=IN IP4 203.0.113.50\r\n"),
        "{description}"
    );
    assert!(
        description.contains("m=audio 50000 RTP/AVP 0\r\n"),
        "only the format the caller offered: {description}"
    );
    assert!(!description.contains("198.51.100."), "{description}");
}

/// The call of [`an_answered_update_goes_through_the_media_engine_both_ways`]:
/// anchored on `engine`, whose session names `answerer` as the callee.
async fn place_anchored(engine: &TestEngine, answerer: &str) -> Call {
    let TestDispatcher { mut state, udp } = test_dispatcher_with_script(&default_dial());
    state.rtpengine_set = Some(engine.backend().await);
    let sessions = Arc::new(crate::rtpengine::MediaSessionStore::new());
    sessions.insert(crate::rtpengine::MediaSession {
        call_id: "a-leg-100rel@192.0.2.10".to_string(),
        rtpengine_call_id: "a-leg-100rel@192.0.2.10".to_string(),
        from_tag: "caller-tag".to_string(),
        to_tag: Some(answerer.to_string()),
        profile: "rtp_passthrough".to_string(),
        ws_uri: None,
        ws_tee: None,
        ws_bridge_attached: false,
        bridge_sides: None,
        created_at: std::time::Instant::now(),
    });
    state.rtpengine_sessions = Some(sessions);
    state.rtpengine_profiles = Some(Arc::new(crate::rtpengine::ProfileRegistry::new()));
    Call::place_on(TestDispatcher { state, udp }, PLAIN, true).0
}

/// An engine that refuses the answer leaves the callee's offer refused 488, as
/// a relayed UPDATE's offer the engine will not take is: never a 200 with media
/// the engine does not relay. The caller's 2xx carries what it was shown.
#[tokio::test(flavor = "multi_thread")]
async fn an_update_the_media_engine_will_not_answer_is_refused_488() {
    let engine = TestEngine::start(true).await;
    let call = place_anchored(&engine, "callee-tag").await;
    call.callee_sends(183, "Session Progress", RELIABLY, Some(CALLEE_SDP));
    let progress = only(call.to_caller(), 183);

    let refusal = callee_updates(&call, 1, Some(UPDATE_OFFER));
    assert_eq!(refusal.status_code(), Some(488));
    assert!(refusal.body.is_empty());

    call.callee_sends(200, "OK", &[], None);
    let answered = only(call.to_caller(), 200);
    assert_eq!(text(&answered.body), text(&progress.body));
}

/// Left as it was: a media session that names another callee's dialog cannot
/// take this callee's offer under its own name. Refused as before, and the
/// engine is sent nothing.
#[tokio::test(flavor = "multi_thread")]
async fn an_update_on_a_session_anchored_for_another_callee_is_refused_as_before() {
    let engine = TestEngine::start(false).await;
    let call = place_anchored(&engine, "another-callee-tag").await;
    call.callee_sends(183, "Session Progress", RELIABLY, Some(CALLEE_SDP));
    call.to_caller();
    let before = engine.all_commands().len();

    assert_refused_as_before(&callee_updates(&call, 1, Some(UPDATE_OFFER)));
    assert_eq!(engine.all_commands().len(), before);
}

/// The second callee of a fork, and its To tag.
const SECOND: (&str, &str) = ("198.51.100.8:5060", "second-callee-tag");

const FORK: &str = concat!(
    "from siphon import b2bua\n",
    "\n",
    "@b2bua.on_invite\n",
    "def on_invite(call):\n",
    "    call.fork([\"sip:15550100042@198.51.100.7:5060\", \"sip:15550100042@198.51.100.8:5060\"])\n",
);

/// Each callee of a fork has an early dialog of its own, on which siphon is its
/// UAC. An UPDATE on one is answered there, and the caller's 2xx carries the
/// description of the callee that answers the call, as its own UPDATE left it.
#[tokio::test(flavor = "multi_thread")]
async fn each_callee_of_a_fork_is_answered_on_its_own_dialog() {
    let (call, others) = Call::place_on(test_dispatcher_with_script(FORK), PLAIN, true);
    let second_invite = others.first().expect("the second callee was dialled");
    call.callee_sends(183, "Session Progress", RELIABLY, Some(CALLEE_SDP));
    call.callee_at_sends(
        second_invite,
        SECOND,
        183,
        "Session Progress",
        RELIABLY,
        Some(&CALLEE_SDP.replace("198.51.100.7", "198.51.100.8")),
    );
    call.to_caller();

    let first = callee_updates(&call, 1, Some(UPDATE_OFFER));
    assert_eq!(first.status_code(), Some(200));
    let offer = UPDATE_OFFER.replace("50002", "52002");
    let second = callee_at_updates(&call, second_invite, SECOND, 1, Some(&offer));
    assert_eq!(second.status_code(), Some(200));
    assert_eq!(header(&second, "Call-ID"), header(second_invite, "Call-ID"));
    assert_eq!(precondition_lines(&second), ANSWERED_STATUS);

    call.callee_at_sends(second_invite, SECOND, 200, "OK", &[], None);
    let answered = only(call.to_caller(), 200);
    assert!(
        text(&answered.body).contains("m=audio 52002 RTP/AVP 0\r\n"),
        "{}",
        text(&answered.body)
    );
}

/// A caller that uses `100rel` and was relayed the 183 without its session
/// description has PRACKed a provisional that answered nothing: it still takes
/// its answer in the 2xx, so the callee's UPDATE is answered for it too.
#[tokio::test(flavor = "multi_thread")]
async fn a_caller_with_100rel_that_was_shown_no_description_is_answered_for_too() {
    let script = dial_script("transparent-b2bua@2026", WITHOUT_BODY);
    let call = Call::place(SUPPORTS, &script);
    call.callee_sends(183, "Session Progress", RELIABLY, Some(PROGRESS_ANSWER));
    let progress = only(call.to_caller(), 183);
    assert!(is_reliable(&progress) && progress.body.is_empty());
    call.caller_pracks(&progress, 2);
    call.wire();

    let ok = callee_updates(&call, 1, Some(UPDATE_OFFER));
    assert_answers_the_update(&call, &ok, 1);

    call.callee_sends(200, "OK", &[], None);
    let answered = only(call.to_caller(), 200);
    assert!(
        text(&answered.body).contains("m=audio 50002 RTP/AVP 0\r\n"),
        "{}",
        text(&answered.body)
    );
}

/// Left as it was: a caller whose own offer carries preconditions negotiates
/// them end to end, and only the caller can say what it has reserved. Its
/// callee's UPDATE is not answered for it.
#[tokio::test(flavor = "multi_thread")]
async fn an_update_toward_a_caller_with_preconditions_of_its_own_is_refused_as_before() {
    let script = dial_script("transparent-b2bua@2026", WITHOUT_BODY);
    let call = Call::place(PLAIN, &script);
    {
        let mut actor = call
            .state
            .call_actors
            .get_call_mut(&call.call_id)
            .expect("the call");
        let mut offer = actor.a_leg.last_sdp.clone().expect("the caller's offer");
        offer.extend_from_slice(b"a=curr:qos e2e none\r\na=des:qos mandatory e2e sendrecv\r\n");
        actor.a_leg.last_sdp = Some(offer);
    }
    call.callee_sends(183, "Session Progress", RELIABLY, Some(PROGRESS_ANSWER));
    call.to_caller();
    assert_refused_as_before(&callee_updates(&call, 1, Some(UPDATE_OFFER)));
}

/// A session description the callee repeats in a later provisional is not a
/// new one (RFC 3261 §13.2.1): the caller's 2xx still carries what the UPDATE
/// left.
#[tokio::test(flavor = "multi_thread")]
async fn a_later_provisional_does_not_undo_what_the_update_changed() {
    let call = Call::place(PLAIN, &default_dial());
    call.callee_sends(183, "Session Progress", RELIABLY, Some(CALLEE_SDP));
    call.to_caller();
    callee_updates(&call, 1, Some(UPDATE_OFFER));
    call.callee_sends(180, "Ringing", &[], Some(CALLEE_SDP));
    call.to_caller();

    call.callee_sends(200, "OK", &[], None);
    let answered = only(call.to_caller(), 200);
    assert!(
        text(&answered.body).contains("m=audio 50002 RTP/AVP 0\r\n"),
        "{}",
        text(&answered.body)
    );
    assert_eq!(origin(&answered), "o=siphon 2 3 IN IP4 192.0.2.1");
}

fn retry_after(response: &SipMessage) -> Option<u32> {
    response
        .headers
        .get("Retry-After")
        .and_then(|value| value.trim().parse().ok())
}

fn assert_refused_as_before(refusal: &SipMessage) {
    assert_eq!(refusal.status_code(), Some(500));
    assert!(retry_after(refusal).is_some_and(|seconds| seconds <= 10));
    assert!(refusal.body.is_empty());
}

/// Unchanged: an UPDATE without an offer changes nothing about the session and
/// is answered 200 with no body, in this state as in any other.
#[tokio::test(flavor = "multi_thread")]
async fn an_update_without_an_offer_is_answered_without_a_body_as_before() {
    let call = Call::place(PLAIN, &default_dial());
    call.callee_sends(183, "Session Progress", RELIABLY, Some(PROGRESS_ANSWER));
    let progress = only(call.to_caller(), 183);

    let ok = callee_updates(&call, 1, None);
    assert_eq!(ok.status_code(), Some(200));
    assert!(ok.body.is_empty());

    call.callee_sends(200, "OK", &[], None);
    let answered = only(call.to_caller(), 200);
    assert_eq!(text(&answered.body), text(&progress.body));
}

/// Unchanged: while a caller that uses `100rel` has not PRACKed the reliable
/// 183 that carries its answer, siphon holds its own PRACK to the callee, so
/// the callee's dialog has no acknowledged answer either and its offer crosses
/// the one in siphon's INVITE: 491, as before (RFC 3311 §5.2). Once the caller
/// has PRACKed, its dialog can carry the offer and the UPDATE is relayed
/// (`early_update_bridge_tests`).
#[tokio::test(flavor = "multi_thread")]
async fn an_update_while_the_callers_reliable_answer_is_unacknowledged_is_refused_as_before() {
    let call = Call::place(SUPPORTS, &default_dial());
    call.callee_sends(183, "Session Progress", RELIABLY, Some(PROGRESS_ANSWER));
    let sent = call.wire();
    let progress = only(to(&sent, CALLER), 183);
    assert!(is_reliable(&progress));
    let refusal = callee_updates(&call, 1, Some(UPDATE_OFFER));
    assert_eq!(refusal.status_code(), Some(491));
    assert!(refusal.body.is_empty());
}

/// Unchanged: to an INVITE without an offer the callee's session description
/// is an offer of its own, and nothing is in force on the caller's dialog that
/// an UPDATE could revise. Refused as before.
#[tokio::test(flavor = "multi_thread")]
async fn an_update_on_a_call_whose_caller_offered_nothing_is_refused_as_before() {
    let (call, _) = Call::place_on(test_dispatcher_with_script(&default_dial()), PLAIN, false);
    call.callee_sends(183, "Session Progress", RELIABLY, Some(CALLEE_SDP));
    call.to_caller();
    let refusal = callee_updates(&call, 1, Some(UNCHANGED_OFFER));
    assert!(
        refusal.status_code().is_some_and(|status| status >= 400),
        "{:?}",
        refusal.status_code()
    );
    assert!(refusal.body.is_empty());
}

/// Left as it was: an offer whose streams are keyed (SDES here) needs a
/// key exchange siphon cannot make for the caller, so it is still refused 500
/// with a Retry-After, and the caller's 2xx carries what it was shown.
#[tokio::test(flavor = "multi_thread")]
async fn an_offer_siphon_cannot_answer_for_the_caller_is_refused_as_before() {
    let call = Call::place(PLAIN, &default_dial());
    call.callee_sends(183, "Session Progress", RELIABLY, Some(CALLEE_SDP));
    let progress = only(call.to_caller(), 183);

    let keyed = format!(
        "{UNCHANGED_OFFER}a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{}\r\n",
        "d0RmdmcmVCspeEc3QGZiNWpVLFJhQX1cfHAwJSoj"
    );
    assert_refused_as_before(&callee_updates(&call, 1, Some(&keyed)));

    call.callee_sends(200, "OK", &[], None);
    let answered = only(call.to_caller(), 200);
    assert_eq!(text(&answered.body), text(&progress.body));
}

/// Left as it was: an offer that shares no format with what the caller offered
/// cannot be answered for it. Refused as before.
#[tokio::test(flavor = "multi_thread")]
async fn an_offer_with_no_format_of_the_callers_is_refused_as_before() {
    let call = Call::place(PLAIN, &default_dial());
    call.callee_sends(183, "Session Progress", RELIABLY, Some(CALLEE_SDP));
    call.to_caller();
    let other = UNCHANGED_OFFER.replace("RTP/AVP 0", "RTP/AVP 8");
    assert_refused_as_before(&callee_updates(&call, 1, Some(&other)));
}

/// Unchanged: the caller's 2xx after a refused UPDATE and the statuses of the
/// provisionals relayed around an answered one.
#[tokio::test(flavor = "multi_thread")]
async fn the_provisionals_around_an_answered_update_are_relayed_as_before() {
    let call = Call::place(PLAIN, &default_dial());
    call.callee_sends(183, "Session Progress", RELIABLY, Some(PROGRESS_ANSWER));
    call.callee_sends(180, "Ringing", &[], None);
    assert_eq!(statuses(&call.to_caller()), [183, 180]);
    callee_updates(&call, 1, Some(UPDATE_OFFER));
    call.callee_sends(180, "Ringing", &[], None);
    assert_eq!(statuses(&call.to_caller()), [180]);
}

/// Emit the 200 that answers a callee's UPDATE and the 2xx the caller is sent
/// afterwards, as hex for `scripts/validate_b2bua_early_update_answer.sh` to
/// feed to tshark: for a caller that was shown the answer in an unreliable 183
/// and for one a script kept it from, in that order.
///
/// The tests above read siphon's messages back with siphon's own parser, which
/// shares whatever siphon gets wrong about a session description it builds.
/// Wireshark's SIP and SDP dissectors do not.
#[tokio::test(flavor = "multi_thread")]
async fn emit_answered_update_for_external_dissection() {
    let Ok(path) = std::env::var("SIPHON_B2BUA_EARLY_UPDATE_ANSWER_HEX_OUT") else {
        // Nothing to do in an ordinary test run.
        return;
    };
    let mut frames = Vec::new();
    for script in [
        default_dial(),
        dial_script("transparent-b2bua@2026", WITHOUT_BODY),
    ] {
        let call = Call::place(PLAIN, &script);
        call.callee_sends(183, "Session Progress", RELIABLY, Some(PROGRESS_ANSWER));
        call.to_caller();
        frames.push(callee_updates(&call, 1, Some(UPDATE_OFFER)));
        call.callee_sends(200, "OK", &[], None);
        frames.push(only(call.to_caller(), 200));
    }
    std::fs::write(&path, hex_dump(&frames)).expect("hex dump must be writable");
}
