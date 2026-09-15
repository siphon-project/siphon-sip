//! RFC 4028 session timers on both legs of a B2BUA call.
//!
//! siphon runs a session timer per dialog: the caller's, where siphon is the UAS
//! of the INVITE, and the callee's, where siphon is the UAC. Each dialog has its
//! own session interval and its own refresher, negotiated by the 2xx of the
//! session refresh request that set it (RFC 4028 §7.2, §9). siphon refreshes a
//! dialog only where it is the refresher, and releases a dialog whose refresher
//! let the session run out (§10).
//!
//! Every test drives the real answer, relay and sweep paths and reads what the
//! peers would have been sent off the UDP egress channel.

use super::sdp_strip_tests::{
    address, body_text, callee_response, caller_call, caller_invite, caller_response, dial_callee,
    endpoint_sdp, in_dialog_request, inbound_from, request_to, response_to, ringing_call,
    siphon_a_leg_tag, snapshot, strip_dispatcher, A_LEG_CALL_ID, B_LEG_BRANCH, CALLEE, CALLEE_TAG,
    CALLEE_TARGET, CALLER, CALLER_TAG,
};
use super::test_dispatcher::TestDispatcher;
use super::*;

/// A dispatcher with `config` as its `session_timer:` block, or none.
pub(super) fn timer_dispatcher(config: Option<&str>) -> TestDispatcher {
    let mut dispatcher = strip_dispatcher(&[]);
    dispatcher.state.session_timer_config =
        config.map(|yaml| serde_yaml_ng::from_str(yaml).expect("a session timer config"));
    dispatcher
}

/// Everything siphon has put on the wire since the last look, in order, the
/// followers of an ordered group (an ACK and the BYE after it) included.
pub(super) fn wire(dispatcher: &TestDispatcher) -> Vec<(SocketAddr, SipMessage)> {
    dispatcher
        .udp
        .try_iter()
        .flat_map(|sent| {
            sent.frames()
                .map(|frame| {
                    (
                        sent.destination,
                        parse_sip_message_bytes(frame).expect("siphon sent a message that parses"),
                    )
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

/// A call ringing at the callee whose caller's INVITE carries `caller_headers`.
/// siphon dialled the callee with an offer, and the callee's leg has the dialog
/// identity the callee's answer gives it.
fn ringing_call_from(dispatcher: &TestDispatcher, caller_headers: &[(&str, &str)]) -> String {
    let state = &dispatcher.state;
    let call_id = ringing_call(dispatcher);
    let mut invite = caller_invite(&endpoint_sdp("192.0.2.10"));
    for (name, value) in caller_headers {
        invite.headers.set(name, value.to_string());
    }
    state
        .call_actors
        .set_a_leg_invite(&call_id, Arc::new(std::sync::Mutex::new(invite)));
    if let Some(mut call) = state.call_actors.get_call_mut(&call_id) {
        if let Some(callee) = call.b_legs.get_mut(0) {
            callee.b_leg_invite = Some(Arc::new(std::sync::Mutex::new(caller_invite(
                &endpoint_sdp("192.0.2.1"),
            ))));
            callee.dialog.remote_tag = Some(CALLEE_TAG.to_string());
            callee.dialog.remote_contact = Some(CALLEE_TARGET.to_string());
            callee.dialog.local_contact = Some("<sip:192.0.2.1:5060;transport=udp>".to_string());
            callee.dialog.local_from_uri = Some("<sip:caller@192.0.2.1>".to_string());
            callee.dialog.remote_to_uri = Some("<sip:callee@198.51.100.20:5060>".to_string());
        }
    }
    call_id
}

/// The callee answers with a 200 carrying `callee_headers` and `body`, and the
/// caller ACKs the 200 siphon relays it, which it returns.
fn callee_answers(
    dispatcher: &TestDispatcher,
    call_id: &str,
    callee_headers: &[(&str, &str)],
    body: &str,
) -> SipMessage {
    let relayed = callee_answers_unacked(dispatcher, call_id, callee_headers, body);
    caller_acks(dispatcher, &relayed);
    relayed
}

/// [`callee_answers`] without the caller's ACK: siphon's 2xx to the caller is
/// still being retransmitted.
fn callee_answers_unacked(
    dispatcher: &TestDispatcher,
    call_id: &str,
    callee_headers: &[(&str, &str)],
    body: &str,
) -> SipMessage {
    let mut answer = callee_response(200, "OK", B_LEG_BRANCH, "1 INVITE", body);
    for (name, value) in callee_headers {
        answer.headers.set(name, value.to_string());
    }
    b_leg_answered(
        call_id,
        &mut answer,
        200,
        address(CALLEE),
        &dispatcher.state,
        &snapshot(dispatcher, call_id, B_LEG_BRANCH),
    );
    response_to(&wire(dispatcher), CALLER, 200)
}

/// The caller ACKs `relayed_200`, the 2xx siphon sent it, through the ACK path
/// the request dispatcher takes for it.
pub(super) fn caller_acks(dispatcher: &TestDispatcher, relayed_200: &SipMessage) {
    let raw = format!(
        concat!(
            "ACK sip:192.0.2.1:5060 SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-caller-ack-{branch}\r\n",
            "Max-Forwards: 70\r\n",
            "From: {from}\r\n",
            "To: {to}\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: 1 ACK\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        branch = uuid::Uuid::new_v4().simple(),
        from = relayed_200
            .headers
            .from()
            .expect("the relayed 200 has a From"),
        to = relayed_200.headers.to().expect("the relayed 200 has a To"),
        call_id = A_LEG_CALL_ID,
    );
    let message = parse_sip_message_bytes(raw.as_bytes()).expect("the caller's ACK parses");
    assert!(
        absorb_b2bua_ack(A_LEG_CALL_ID, &message, &dispatcher.state),
        "the caller's ACK matched no dialog"
    );
}

/// Move the session on one leg's dialog `seconds` past its last refresh.
pub(super) fn age(dispatcher: &TestDispatcher, call_id: &str, on_a_leg: bool, seconds: u64) {
    let then = std::time::Instant::now()
        .checked_sub(std::time::Duration::from_secs(seconds))
        .expect("the clock reaches back that far");
    assert!(
        dispatcher
            .state
            .call_actors
            .update_leg_session_timer(call_id, on_a_leg, |timer| timer.last_refresh = then),
        "the {} dialog runs no session timer",
        if on_a_leg { "caller's" } else { "callee's" }
    );
}

/// Run the session timer sweep once, and return what it put on the wire.
pub(super) fn sweep(dispatcher: &TestDispatcher) -> Vec<(SocketAddr, SipMessage)> {
    let _ = wire(dispatcher);
    session_timer_sweep(&dispatcher.state);
    wire(dispatcher)
}

/// The requests of `method` sent to `destination`.
pub(super) fn requests(
    sent: &[(SocketAddr, SipMessage)],
    destination: &str,
    method: Method,
) -> Vec<SipMessage> {
    sent.iter()
        .filter(|(to, message)| *to == address(destination) && message.method() == Some(&method))
        .map(|(_, message)| message.clone())
        .collect()
}

/// The topmost Via branch of a request.
pub(super) fn branch_of(request: &SipMessage) -> String {
    request
        .headers
        .get("Via")
        .and_then(|via| via.split(";branch=").nth(1))
        .map(|rest| rest.split([';', ',', ' ']).next().unwrap_or("").to_string())
        .expect("the request has a Via branch")
}

/// Whether a `Require` or `Supported` header lists `tag` as a token.
pub(super) fn lists_option_tag(message: &SipMessage, header: &str, tag: &str) -> bool {
    message.headers.get_all(header).is_some_and(|values| {
        values
            .iter()
            .flat_map(|value| value.split(','))
            .any(|token| token.trim().eq_ignore_ascii_case(tag))
    })
}

/// The callee answers a request siphon sent it with `status_code`, carrying
/// `headers` and `body`, through the re-INVITE response arm.
fn callee_answers_reinvite(
    dispatcher: &TestDispatcher,
    call_id: &str,
    request: &SipMessage,
    status_code: u16,
    headers: &[(&str, &str)],
    body: &str,
) -> Vec<(SocketAddr, SipMessage)> {
    let branch = branch_of(request);
    let cseq = request
        .headers
        .cseq()
        .cloned()
        .expect("the request has a CSeq");
    let mut response = callee_response(status_code, "Answer", &branch, &cseq, body);
    for (name, value) in headers {
        response.headers.set(name, value.to_string());
    }
    let _ = wire(dispatcher);
    assert!(forward_reinvite_response(
        call_id,
        &branch,
        &mut response,
        status_code,
        address(CALLEE),
        &dispatcher.state,
        &snapshot(dispatcher, call_id, &branch),
    ));
    wire(dispatcher)
}

/// A call whose callee named siphon the refresher of a 90 second session, with
/// siphon's refresh of it out. Returns the call and the refresh.
fn call_with_refresh_out(dispatcher: &TestDispatcher) -> (String, SipMessage) {
    let call_id = ringing_call_from(dispatcher, &[]);
    callee_answers(
        dispatcher,
        &call_id,
        &[
            ("Supported", "timer"),
            ("Session-Expires", "90;refresher=uac"),
        ],
        &endpoint_sdp("198.51.100.20"),
    );
    age(dispatcher, &call_id, false, 46);
    let mut refresh = requests(&sweep(dispatcher), CALLEE, Method::Invite);
    assert_eq!(refresh.len(), 1, "no refresh went out");
    (call_id, refresh.remove(0))
}

// ---------------------------------------------------------------------------
// The callee's dialog: siphon is the UAC of the INVITE
// ---------------------------------------------------------------------------

/// RFC 4028 §7.2: `refresher=uac` in the callee's 2xx names siphon, the UAC of
/// the INVITE, and siphon refreshes at half the interval.
#[tokio::test(flavor = "multi_thread")]
async fn siphon_refreshes_a_callee_whose_answer_names_it_the_refresher() {
    let dispatcher = timer_dispatcher(Some("session_expires: 90\n"));
    let call_id = ringing_call_from(&dispatcher, &[]);
    callee_answers(
        &dispatcher,
        &call_id,
        &[
            ("Supported", "timer"),
            ("Require", "timer"),
            ("Session-Expires", "90;refresher=uac"),
        ],
        &endpoint_sdp("198.51.100.20"),
    );

    age(&dispatcher, &call_id, false, 44);
    assert!(
        requests(&sweep(&dispatcher), CALLEE, Method::Invite).is_empty(),
        "refreshed before half the session interval"
    );

    age(&dispatcher, &call_id, false, 46);
    let sent = sweep(&dispatcher);
    let refreshes = requests(&sent, CALLEE, Method::Invite);
    assert_eq!(
        refreshes.len(),
        1,
        "siphon did not refresh the dialog it is the refresher of"
    );
    assert_eq!(
        refreshes[0]
            .headers
            .get("Session-Expires")
            .map(String::as_str),
        Some("90;refresher=uac")
    );
    assert!(requests(&sent, CALLER, Method::Bye).is_empty());
}

/// RFC 4028 §10: when the callee refreshes and lets the session run out, siphon
/// sends the BYE slightly before the expiration, the smaller of 32 seconds and a
/// third of the interval ahead of it. Until then it neither refreshes nor ends
/// the call.
#[tokio::test(flavor = "multi_thread")]
async fn a_callee_that_refreshes_is_released_just_before_its_session_expires() {
    let dispatcher = timer_dispatcher(Some("session_expires: 90\n"));
    let call_id = ringing_call_from(&dispatcher, &[]);
    callee_answers(
        &dispatcher,
        &call_id,
        &[
            ("Supported", "timer"),
            ("Session-Expires", "90;refresher=uas"),
        ],
        &endpoint_sdp("198.51.100.20"),
    );

    age(&dispatcher, &call_id, false, 59);
    let sent = sweep(&dispatcher);
    assert!(
        requests(&sent, CALLEE, Method::Invite).is_empty(),
        "siphon refreshed a dialog the callee refreshes"
    );
    assert!(requests(&sent, CALLEE, Method::Bye).is_empty());

    age(&dispatcher, &call_id, false, 61);
    let sent = sweep(&dispatcher);
    assert_eq!(
        requests(&sent, CALLEE, Method::Bye).len(),
        1,
        "the callee's dialog was not released before its session expired"
    );
    assert_eq!(requests(&sent, CALLER, Method::Bye).len(), 1);
}

/// A 2xx to a refresh sets the session again, refresher included (RFC 4028
/// §7.2): a callee that takes the refreshes over stops siphon refreshing.
#[tokio::test(flavor = "multi_thread")]
async fn the_answer_to_a_refresh_decides_who_refreshes_next() {
    let dispatcher = timer_dispatcher(Some("session_expires: 90\n"));
    let (call_id, refresh) = call_with_refresh_out(&dispatcher);

    callee_answers_reinvite(
        &dispatcher,
        &call_id,
        &refresh,
        200,
        &[("Session-Expires", "90;refresher=uas")],
        &endpoint_sdp("198.51.100.20"),
    );

    age(&dispatcher, &call_id, false, 46);
    assert!(
        requests(&sweep(&dispatcher), CALLEE, Method::Invite).is_empty(),
        "siphon kept refreshing after the callee took the refreshes over"
    );
    age(&dispatcher, &call_id, false, 61);
    assert_eq!(requests(&sweep(&dispatcher), CALLEE, Method::Bye).len(), 1);
}

/// RFC 4028 §10: a refresh that draws a 408 or a 481 ends the session.
#[tokio::test(flavor = "multi_thread")]
async fn a_refresh_answered_408_or_481_ends_the_call() {
    for status_code in [408, 481] {
        let dispatcher = timer_dispatcher(Some("session_expires: 90\n"));
        let (call_id, refresh) = call_with_refresh_out(&dispatcher);

        let sent = callee_answers_reinvite(&dispatcher, &call_id, &refresh, status_code, &[], "");

        assert_eq!(
            requests(&sent, CALLER, Method::Bye).len(),
            1,
            "a refresh answered {status_code} left the call up"
        );
    }
}

/// RFC 4028 §10: a refresh whose transaction times out ends the session. Sending
/// it restarted nothing, and while it waits for its response it is not sent again.
#[tokio::test(flavor = "multi_thread")]
async fn a_refresh_nobody_answers_ends_the_call() {
    let dispatcher = timer_dispatcher(Some("session_expires: 90\n"));
    let (call_id, _) = call_with_refresh_out(&dispatcher);

    let sent = sweep(&dispatcher);
    assert!(
        requests(&sent, CALLEE, Method::Invite).is_empty(),
        "a refresh awaiting its response was sent again"
    );
    assert!(requests(&sent, CALLER, Method::Bye).is_empty());

    let timeout = dispatcher.state.b2bua_retransmits.transaction_timeout();
    assert!(dispatcher
        .state
        .call_actors
        .update_leg_session_timer(&call_id, false, |timer| {
            if let Some(in_flight) = timer.refresh_in_flight.as_mut() {
                in_flight.sent_at = std::time::Instant::now()
                    .checked_sub(timeout)
                    .expect("the clock reaches back that far");
            }
        }));
    let sent = sweep(&dispatcher);
    assert_eq!(
        requests(&sent, CALLER, Method::Bye).len(),
        1,
        "a refresh unanswered for 64*T1 left the call up"
    );
    assert_eq!(requests(&sent, CALLEE, Method::Bye).len(), 1);
}

/// RFC 4028 §10: a refresh refused with anything but 408, 481 or 422 is retried,
/// before the session expires and not at once.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_refresh_is_retried_before_the_session_expires() {
    let dispatcher = timer_dispatcher(Some("session_expires: 90\n"));
    let (call_id, refresh) = call_with_refresh_out(&dispatcher);

    let sent = callee_answers_reinvite(&dispatcher, &call_id, &refresh, 500, &[], "");
    assert!(requests(&sent, CALLER, Method::Bye).is_empty());
    assert!(
        requests(&sweep(&dispatcher), CALLEE, Method::Invite).is_empty(),
        "a refused refresh was retried at once"
    );

    let timer = dispatcher
        .state
        .call_actors
        .leg_session_timer(&call_id, false)
        .expect("the callee's session timer");
    let retry_at = timer.retry_at.expect("a retry time");
    assert!(
        retry_at < timer.expires_at(),
        "the retry falls after the expiration"
    );
    assert!(dispatcher
        .state
        .call_actors
        .update_leg_session_timer(&call_id, false, |timer| {
            timer.retry_at =
                std::time::Instant::now().checked_sub(std::time::Duration::from_secs(1));
        }));
    assert_eq!(
        requests(&sweep(&dispatcher), CALLEE, Method::Invite).len(),
        1,
        "the refused refresh was not retried"
    );
}

/// RFC 4028 §7.1: the configured refresher is what siphon asks the callee for.
/// `uac` and `b2bua` name siphon; `uas` leaves the parameter out, since a UAC may
/// only ask for `uac` or leave the choice to the UAS.
#[tokio::test(flavor = "multi_thread")]
async fn the_configured_refresher_is_what_siphon_asks_the_callee_for() {
    for (config, expected) in [
        (
            "session_expires: 1800\nrefresher: uac\n",
            "1800;refresher=uac",
        ),
        (
            "session_expires: 1800\nrefresher: b2bua\n",
            "1800;refresher=uac",
        ),
        ("session_expires: 1800\nrefresher: uas\n", "1800"),
    ] {
        let dispatcher = timer_dispatcher(Some(config));
        let call_id = caller_call(&dispatcher);
        dial_callee(
            &dispatcher,
            &call_id,
            &caller_invite(&endpoint_sdp("192.0.2.10")),
        );
        let invite = request_to(&wire(&dispatcher), CALLEE, Method::Invite);
        assert_eq!(
            invite.headers.get("Session-Expires").map(String::as_str),
            Some(expected),
            "{config:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// The caller's dialog: siphon is the UAS of the INVITE
// ---------------------------------------------------------------------------

/// RFC 4028 §9: siphon answers the caller's own request for a session timer
/// from the caller's INVITE (Table 2), never with the callee's Session-Expires,
/// which belongs to the other dialog. It never raises the caller's interval, never
/// goes below the caller's Min-SE, cannot override a refresher the caller chose,
/// and makes a caller that does not support timers the non-refresher.
#[tokio::test(flavor = "multi_thread")]
async fn the_answer_to_the_caller_negotiates_the_callers_own_session_timer() {
    struct Case {
        config: &'static str,
        caller: &'static [(&'static str, &'static str)],
        session_expires: Option<&'static str>,
        require_timer: bool,
    }
    let cases = [
        Case {
            config: "session_expires: 900\nrefresher: b2bua\n",
            caller: &[("Supported", "timer"), ("Session-Expires", "1800")],
            session_expires: Some("900;refresher=uas"),
            require_timer: true,
        },
        Case {
            config: "session_expires: 900\n",
            caller: &[
                ("Supported", "timer"),
                ("Session-Expires", "600;refresher=uac"),
            ],
            session_expires: Some("600;refresher=uac"),
            require_timer: true,
        },
        Case {
            config: "session_expires: 900\nrefresher: uas\n",
            caller: &[
                ("Supported", "timer"),
                ("Session-Expires", "1800;refresher=uac"),
            ],
            session_expires: Some("900;refresher=uac"),
            require_timer: true,
        },
        Case {
            config: "session_expires: 900\nrefresher: uac\n",
            caller: &[("Session-Expires", "1800")],
            session_expires: Some("900;refresher=uas"),
            require_timer: false,
        },
        Case {
            config: "session_expires: 900\n",
            caller: &[("Supported", "timer"), ("Min-SE", "1200")],
            session_expires: Some("1200;refresher=uac"),
            require_timer: true,
        },
        Case {
            config: "session_expires: 900\n",
            caller: &[],
            session_expires: None,
            require_timer: false,
        },
    ];
    for case in cases {
        let dispatcher = timer_dispatcher(Some(case.config));
        let call_id = ringing_call_from(&dispatcher, case.caller);

        let answer = callee_answers(
            &dispatcher,
            &call_id,
            &[
                ("Supported", "timer"),
                ("Require", "timer"),
                ("Session-Expires", "900;refresher=uac"),
            ],
            &endpoint_sdp("198.51.100.20"),
        );

        let context = format!("{} {:?}", case.config.replace('\n', " "), case.caller);
        assert_eq!(
            answer.headers.get("Session-Expires").map(String::as_str),
            case.session_expires,
            "{context}"
        );
        assert_eq!(
            lists_option_tag(&answer, "Require", "timer"),
            case.require_timer,
            "{context}"
        );
    }
}

/// When the answer siphon gave the caller names siphon the refresher, siphon
/// refreshes the caller: a re-INVITE on the caller's own dialog, with siphon's
/// Contact and option tags, offering the session description in force there.
#[tokio::test(flavor = "multi_thread")]
async fn siphon_refreshes_the_caller_when_its_answer_named_siphon() {
    let dispatcher = timer_dispatcher(Some("session_expires: 90\nrefresher: b2bua\n"));
    let call_id = ringing_call_from(&dispatcher, &[("Supported", "timer")]);
    let answer = callee_answers(
        &dispatcher,
        &call_id,
        &[
            ("Supported", "timer"),
            ("Session-Expires", "90;refresher=uas"),
        ],
        &endpoint_sdp("198.51.100.20"),
    );
    assert_eq!(
        answer.headers.get("Session-Expires").map(String::as_str),
        Some("90;refresher=uas")
    );

    age(&dispatcher, &call_id, true, 46);
    let sent = sweep(&dispatcher);

    let refreshes = requests(&sent, CALLER, Method::Invite);
    assert_eq!(refreshes.len(), 1, "siphon did not refresh the caller");
    let refresh = &refreshes[0];
    match &refresh.start_line {
        StartLine::Request(request_line) => assert_eq!(
            request_line.request_uri.to_string(),
            "sip:caller@192.0.2.10:5060"
        ),
        StartLine::Response(_) => panic!("a refresh is a request"),
    }
    assert_eq!(
        refresh.headers.call_id().map(String::as_str),
        Some(A_LEG_CALL_ID)
    );
    let siphon_tag = siphon_a_leg_tag(&dispatcher, &call_id);
    assert!(refresh
        .headers
        .from()
        .is_some_and(|from| from.ends_with(&format!(";tag={siphon_tag}"))));
    assert!(refresh
        .headers
        .to()
        .is_some_and(|to| to.ends_with(&format!(";tag={CALLER_TAG}"))));
    assert_eq!(
        refresh.headers.get("Contact").map(String::as_str),
        Some("<sip:192.0.2.1:5060;transport=udp>")
    );
    assert_eq!(
        refresh.headers.get("Session-Expires").map(String::as_str),
        Some("90;refresher=uac")
    );
    assert!(lists_option_tag(refresh, "Supported", "timer"));
    assert_eq!(body_text(refresh), body_text(&answer));
    assert!(
        requests(&sent, CALLEE, Method::Invite).is_empty(),
        "siphon refreshed the callee, which refreshes its own dialog"
    );
}

/// RFC 4028 §10 on the caller's dialog: a caller that refreshes and lets the
/// session run out is released just before the expiration.
#[tokio::test(flavor = "multi_thread")]
async fn a_caller_that_refreshes_is_released_just_before_its_session_expires() {
    let dispatcher = timer_dispatcher(Some("session_expires: 90\n"));
    let call_id = ringing_call_from(
        &dispatcher,
        &[
            ("Supported", "timer"),
            ("Session-Expires", "90;refresher=uac"),
        ],
    );
    callee_answers(
        &dispatcher,
        &call_id,
        &[
            ("Supported", "timer"),
            ("Session-Expires", "90;refresher=uas"),
        ],
        &endpoint_sdp("198.51.100.20"),
    );

    age(&dispatcher, &call_id, true, 59);
    assert!(requests(&sweep(&dispatcher), CALLER, Method::Bye).is_empty());

    age(&dispatcher, &call_id, true, 61);
    let sent = sweep(&dispatcher);
    assert_eq!(
        requests(&sent, CALLER, Method::Bye).len(),
        1,
        "the caller's dialog was not released before its session expired"
    );
    assert_eq!(requests(&sent, CALLEE, Method::Bye).len(), 1);
}

/// A relayed re-INVITE refreshes both dialogs, each negotiated from its own side.
/// On the dialog siphon sent the request on, siphon is the UAC and the responder's
/// 2xx names the refresher (RFC 4028 §7.2). On the dialog the request came from,
/// siphon is the UAS and answers the originator's request itself (§9): the 2xx it
/// relays there carries siphon's Session-Expires, not the responder's, which
/// describes the other dialog.
#[tokio::test(flavor = "multi_thread")]
async fn a_relayed_refresh_sets_each_dialogs_refresher_from_its_own_side() {
    let dispatcher = timer_dispatcher(Some("session_expires: 90\nrefresher: b2bua\n"));
    let call_id = ringing_call_from(&dispatcher, &[("Supported", "timer")]);
    callee_answers(
        &dispatcher,
        &call_id,
        &[
            ("Supported", "timer"),
            ("Session-Expires", "90;refresher=uac"),
        ],
        &endpoint_sdp("198.51.100.20"),
    );

    // The callee refreshes and takes the refreshes of its dialog on itself.
    let mut reinvite = in_dialog_request("INVITE", false, &endpoint_sdp("198.51.100.20"));
    reinvite.headers.set("Supported", "timer".to_string());
    reinvite
        .headers
        .set("Session-Expires", "90;refresher=uac".to_string());
    handle_b2bua_reinvite(inbound_from(CALLEE), reinvite, &dispatcher.state);
    let forwarded = request_to(&wire(&dispatcher), CALLER, Method::Invite);
    let branch = branch_of(&forwarded);
    let siphon_tag = siphon_a_leg_tag(&dispatcher, &call_id);
    // The caller's 2xx names the caller the refresher of the caller's dialog.
    let mut accepted = caller_response(
        &branch,
        forwarded.headers.cseq().map(String::as_str).unwrap_or(""),
        &siphon_tag,
        &endpoint_sdp("192.0.2.10"),
    );
    accepted
        .headers
        .set("Session-Expires", "90;refresher=uas".to_string());
    assert!(forward_reinvite_response(
        &call_id,
        &branch,
        &mut accepted,
        200,
        address(CALLER),
        &dispatcher.state,
        &snapshot(&dispatcher, &call_id, &branch),
    ));
    let relayed = response_to(&wire(&dispatcher), CALLEE, 200);
    assert_eq!(
        relayed.headers.get("Session-Expires").map(String::as_str),
        Some("90;refresher=uac"),
        "the callee was relayed the caller's Session-Expires instead of siphon's answer"
    );

    // Neither dialog is siphon's to refresh, and both still run their timer.
    age(&dispatcher, &call_id, true, 46);
    age(&dispatcher, &call_id, false, 46);
    let sent = sweep(&dispatcher);
    assert!(
        requests(&sent, CALLER, Method::Invite).is_empty(),
        "siphon refreshed the caller, whose 2xx named the caller the refresher"
    );
    assert!(
        requests(&sent, CALLEE, Method::Invite).is_empty(),
        "siphon refreshed the callee, which chose to refresh its own dialog"
    );
    age(&dispatcher, &call_id, true, 61);
    age(&dispatcher, &call_id, false, 61);
    let sent = sweep(&dispatcher);
    assert_eq!(requests(&sent, CALLER, Method::Bye).len(), 1);
    assert_eq!(requests(&sent, CALLEE, Method::Bye).len(), 1);
}

// ---------------------------------------------------------------------------
// What a refresh offers
// ---------------------------------------------------------------------------

/// When the callee's 2xx carries no SDP, the answer siphon relayed to the caller
/// in the callee's early media is the session description in force on the
/// caller's dialog.
#[tokio::test(flavor = "multi_thread")]
async fn early_media_sdp_is_the_session_in_force_when_the_answer_carries_none() {
    let dispatcher = timer_dispatcher(None);
    let call_id = ringing_call(&dispatcher);
    let mut progress = callee_response(
        183,
        "Session Progress",
        B_LEG_BRANCH,
        "1 INVITE",
        &endpoint_sdp("198.51.100.20"),
    );
    b_leg_provisional(
        &call_id,
        B_LEG_BRANCH,
        &mut progress,
        183,
        address(CALLEE),
        &dispatcher.state,
        &snapshot(&dispatcher, &call_id, B_LEG_BRANCH),
    );
    let early = response_to(&wire(&dispatcher), CALLER, 183);

    let mut answer = callee_response(200, "OK", B_LEG_BRANCH, "1 INVITE", "");
    prepare_a_leg_answer(
        &call_id,
        &mut answer,
        &dispatcher.state,
        &snapshot(&dispatcher, &call_id, B_LEG_BRANCH),
    );

    let in_force = dispatcher
        .state
        .call_actors
        .clone_leg(&call_id, true)
        .and_then(|leg| leg.dialog.last_sent_sdp);
    assert_eq!(in_force, Some(early.body.clone()));
}

/// RFC 4028 §7.4: with no session description to offer, a refresh toward a peer
/// that allows UPDATE is an UPDATE without a body, and its response is siphon's
/// own business.
#[tokio::test(flavor = "multi_thread")]
async fn with_no_session_in_force_a_refresh_is_a_bodyless_update_where_allowed() {
    let dispatcher = timer_dispatcher(Some("session_expires: 90\n"));
    let call_id = ringing_call_from(&dispatcher, &[]);
    callee_answers(
        &dispatcher,
        &call_id,
        &[
            ("Session-Expires", "90"),
            ("Allow", "INVITE, ACK, BYE, CANCEL, UPDATE"),
        ],
        &endpoint_sdp("198.51.100.20"),
    );

    age(&dispatcher, &call_id, false, 46);
    let sent = sweep(&dispatcher);

    assert!(requests(&sent, CALLEE, Method::Invite).is_empty());
    let updates = requests(&sent, CALLEE, Method::Update);
    assert_eq!(updates.len(), 1, "the refresh was not an UPDATE");
    assert!(
        updates[0].body.is_empty(),
        "the UPDATE refresh carried a body"
    );
    assert_eq!(
        updates[0]
            .headers
            .get("Session-Expires")
            .map(String::as_str),
        Some("90;refresher=uac")
    );

    let branch = branch_of(&updates[0]);
    let cseq = updates[0].headers.cseq().cloned().expect("a CSeq");
    let mut accepted = callee_response(200, "OK", &branch, &cseq, "");
    accepted
        .headers
        .set("Session-Expires", "90;refresher=uac".to_string());
    assert!(forward_update_response(
        &call_id,
        &mut accepted,
        200,
        address(CALLEE),
        &dispatcher.state,
        &snapshot(&dispatcher, &call_id, &branch),
    ));
    assert!(
        wire(&dispatcher)
            .iter()
            .all(|(to, _)| *to != address(CALLER)),
        "the response to siphon's UPDATE refresh was relayed to the caller"
    );
    age(&dispatcher, &call_id, false, 10);
    assert!(
        requests(&sweep(&dispatcher), CALLEE, Method::Update).is_empty(),
        "the 2xx to the UPDATE did not restart the session"
    );
}

/// The offer the callee's 2xx brings back to siphon's offerless refresh.
const CALLEE_REFRESH_OFFER: &str = concat!(
    "v=0\r\n",
    "o=callee 7 7 IN IP4 198.51.100.20\r\n",
    "s=-\r\n",
    "c=IN IP4 198.51.100.20\r\n",
    "t=0 0\r\n",
    "m=audio 40000 RTP/AVP 0 8\r\n",
    "a=rtpmap:0 PCMU/8000\r\n",
    "m=video 40002 RTP/AVP 96\r\n",
    "a=rtpmap:96 H264/90000\r\n",
);

/// The caller's answer to that offer, relayed to it.
const CALLER_REFRESH_ANSWER: &str = concat!(
    "v=0\r\n",
    "o=caller 3 3 IN IP4 192.0.2.10\r\n",
    "s=-\r\n",
    "c=IN IP4 192.0.2.10\r\n",
    "t=0 0\r\n",
    "m=audio 41000 RTP/AVP 0\r\n",
    "a=rtpmap:0 PCMU/8000\r\n",
    "m=video 0 RTP/AVP 96\r\n",
);

/// A call where siphon refreshes the callee's dialog and holds no session
/// description on it, toward a callee that allows no UPDATE: the refresh is a
/// re-INVITE without an offer. Returns the call and that refresh.
fn call_with_offerless_refresh_out(dispatcher: &TestDispatcher) -> (String, SipMessage) {
    let call_id = ringing_call_from(dispatcher, &[]);
    callee_answers(
        dispatcher,
        &call_id,
        &[("Session-Expires", "90")],
        &endpoint_sdp("198.51.100.20"),
    );
    age(dispatcher, &call_id, false, 46);
    let mut refresh = requests(&sweep(dispatcher), CALLEE, Method::Invite);
    assert_eq!(refresh.len(), 1, "no refresh went out");
    assert!(refresh[0].body.is_empty(), "the refresh carried an offer");
    (call_id, refresh.remove(0))
}

/// The callee answers `request`, one siphon sent it, with `status_code`, through
/// the dispatcher's response entry. Returns what siphon put on the wire.
fn callee_responds(
    dispatcher: &TestDispatcher,
    call_id: &str,
    request: &SipMessage,
    status_code: u16,
    body: &str,
) -> Vec<(SocketAddr, SipMessage)> {
    let branch = branch_of(request);
    let cseq = request
        .headers
        .cseq()
        .cloned()
        .expect("the request has a CSeq");
    let mut response = callee_response(status_code, "Answer", &branch, &cseq, body);
    response
        .headers
        .set("Session-Expires", "90;refresher=uac".to_string());
    let _ = wire(dispatcher);
    assert!(handle_b2bua_response(
        call_id,
        &branch,
        &mut response,
        status_code,
        address(CALLEE),
        &dispatcher.state,
    ));
    wire(dispatcher)
}

/// The caller answers `request`, one siphon sent it, with `status_code`, through
/// the dispatcher's response entry. Returns what siphon put on the wire.
fn caller_responds(
    dispatcher: &TestDispatcher,
    call_id: &str,
    request: &SipMessage,
    status_code: u16,
    body: &str,
) -> Vec<(SocketAddr, SipMessage)> {
    let branch = branch_of(request);
    let cseq = request
        .headers
        .cseq()
        .cloned()
        .expect("the request has a CSeq");
    let siphon_tag = siphon_a_leg_tag(dispatcher, call_id);
    let ok = caller_response(&branch, &cseq, &siphon_tag, body);
    let text = String::from_utf8(ok.to_bytes())
        .expect("the response is text")
        .replacen(
            "SIP/2.0 200 OK",
            &format!("SIP/2.0 {status_code} Answer"),
            1,
        );
    let mut response = parse_sip_message_bytes(text.as_bytes()).expect("the response parses");
    let _ = wire(dispatcher);
    assert!(handle_b2bua_response(
        call_id,
        &branch,
        &mut response,
        status_code,
        address(CALLER),
        &dispatcher.state,
    ));
    wire(dispatcher)
}

/// The session description siphon has in force on one leg's dialog.
fn in_force(dispatcher: &TestDispatcher, call_id: &str, on_a_leg: bool) -> Option<Vec<u8>> {
    dispatcher
        .state
        .call_actors
        .clone_leg(call_id, on_a_leg)
        .and_then(|leg| leg.dialog.last_sent_sdp)
}

/// RFC 3261 §14.1, RFC 3264 §4: an offerless refresh draws the callee's offer in
/// its 2xx, and the ACK has to carry the answer. siphon has none of its own: the
/// caller has it. So the offer goes to the caller in a re-INVITE on the caller's
/// dialog, with siphon's identity on it, and the caller's answer goes in the
/// callee's ACK. Until then copies of the callee's 2xx are absorbed; afterwards
/// each draws that same ACK. Media continues as the two parties agree.
#[tokio::test(flavor = "multi_thread")]
async fn the_offer_an_offerless_refresh_draws_is_answered_by_the_other_party_in_the_ack() {
    let dispatcher = timer_dispatcher(Some("session_expires: 90\n"));
    let (call_id, refresh) = call_with_offerless_refresh_out(&dispatcher);

    let sent = callee_responds(&dispatcher, &call_id, &refresh, 200, CALLEE_REFRESH_OFFER);
    assert!(
        requests(&sent, CALLEE, Method::Ack).is_empty(),
        "the callee's 2xx was ACKed before there was an answer to put in the ACK"
    );
    let relayed = requests(&sent, CALLER, Method::Invite);
    assert_eq!(
        relayed.len(),
        1,
        "the callee's offer was not relayed to the caller"
    );
    let relayed_offer = body_text(&relayed[0]);
    assert!(
        relayed_offer.contains("m=audio 40000 RTP/AVP 0 8\r\n")
            && relayed_offer.contains("m=video 40002 RTP/AVP 96\r\n"),
        "{relayed_offer}"
    );
    assert!(!relayed_offer.contains("o=callee"), "{relayed_offer}");
    assert_eq!(
        relayed[0].headers.call_id().map(String::as_str),
        Some(A_LEG_CALL_ID)
    );

    let copy = callee_responds(&dispatcher, &call_id, &refresh, 200, CALLEE_REFRESH_OFFER);
    assert!(requests(&copy, CALLEE, Method::Ack).is_empty());
    assert!(
        requests(&copy, CALLER, Method::Invite).is_empty(),
        "a copy of the 2xx relayed the offer again"
    );

    let sent = caller_responds(
        &dispatcher,
        &call_id,
        &relayed[0],
        200,
        CALLER_REFRESH_ANSWER,
    );
    assert_eq!(requests(&sent, CALLER, Method::Ack).len(), 1);
    let acks = requests(&sent, CALLEE, Method::Ack);
    assert_eq!(
        acks.len(),
        1,
        "the callee was not ACKed once the answer was in"
    );
    let answer = body_text(&acks[0]);
    assert!(answer.contains("m=audio 41000 RTP/AVP 0\r\n"), "{answer}");
    assert!(answer.contains("m=video 0 RTP/AVP 96\r\n"), "{answer}");
    assert!(!answer.contains("o=caller"), "{answer}");
    let callee_session_id = dispatcher
        .state
        .call_actors
        .clone_leg(&call_id, false)
        .map(|leg| leg.dialog.sdp_session_id)
        .expect("the callee leg");
    assert!(
        answer.lines().any(|line| line.starts_with("o=")
            && line.split(' ').nth(1) == Some(callee_session_id.to_string().as_str())),
        "the answer does not carry siphon's origin toward the callee: {answer}"
    );
    assert_eq!(
        in_force(&dispatcher, &call_id, false),
        Some(acks[0].body.clone())
    );
    assert_eq!(
        in_force(&dispatcher, &call_id, true),
        Some(relayed[0].body.clone())
    );

    let again = callee_responds(&dispatcher, &call_id, &refresh, 200, CALLEE_REFRESH_OFFER);
    let again = requests(&again, CALLEE, Method::Ack);
    assert_eq!(again.len(), 1, "a later copy of the 2xx is ACKed");
    assert_eq!(again[0].to_bytes(), acks[0].to_bytes());
    assert!(dispatcher.state.call_actors.get_call(&call_id).is_some());
}

/// Every frame sent to `destination`, as methods and status codes in order.
fn sequence_to(sent: &[(SocketAddr, SipMessage)], destination: &str) -> Vec<String> {
    sent.iter()
        .filter(|(to, _)| *to == address(destination))
        .map(|(_, message)| match message.method() {
            Some(method) => method.as_str().to_string(),
            None => message
                .status_code()
                .map(|code| code.to_string())
                .unwrap_or_default(),
        })
        .collect()
}

/// A caller that refuses the relayed offer leaves siphon no answer for the
/// callee. The callee's 2xx is still owed an ACK with a valid answer, every stream
/// rejected (RFC 3264 §6), and the call ends through its teardown, that ACK going
/// out ahead of the callee's BYE (RFC 3261 §13.2.2.4).
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_relay_of_a_refresh_offer_ends_the_call_after_the_ack_the_callee_is_owed() {
    let dispatcher = timer_dispatcher(Some("session_expires: 90\n"));
    let (call_id, refresh) = call_with_offerless_refresh_out(&dispatcher);
    let sent = callee_responds(&dispatcher, &call_id, &refresh, 200, CALLEE_REFRESH_OFFER);
    let relayed = requests(&sent, CALLER, Method::Invite);
    assert_eq!(
        relayed.len(),
        1,
        "the callee's offer was not relayed to the caller"
    );

    let sent = caller_responds(&dispatcher, &call_id, &relayed[0], 488, "");

    assert_eq!(sequence_to(&sent, CALLEE), vec!["ACK", "BYE"]);
    let ack = request_to(&sent, CALLEE, Method::Ack);
    let answer = body_text(&ack);
    assert!(answer.contains("m=audio 0 RTP/AVP 0\r\n"), "{answer}");
    assert!(answer.contains("m=video 0 RTP/AVP 96\r\n"), "{answer}");
    assert_eq!(requests(&sent, CALLER, Method::Bye).len(), 1);
    assert!(dispatcher.state.call_actors.get_call(&call_id).is_none());
}

/// A caller that never answers the relayed offer ends the call like a refresh
/// nobody answers (RFC 3261 §17.1.1.2, RFC 4028 §10), again with the callee ACKed
/// ahead of its BYE.
#[tokio::test(flavor = "multi_thread")]
async fn a_relay_of_a_refresh_offer_nobody_answers_ends_the_call() {
    let dispatcher = timer_dispatcher(Some("session_expires: 90\n"));
    let (call_id, refresh) = call_with_offerless_refresh_out(&dispatcher);
    let sent = callee_responds(&dispatcher, &call_id, &refresh, 200, CALLEE_REFRESH_OFFER);
    assert_eq!(requests(&sent, CALLER, Method::Invite).len(), 1);

    let timeout = dispatcher.state.b2bua_retransmits.transaction_timeout();
    assert!(
        dispatcher
            .state
            .call_actors
            .update_leg_session_timer(&call_id, false, |timer| {
                if let Some(in_flight) = timer.refresh_in_flight.as_mut() {
                    in_flight.sent_at = std::time::Instant::now()
                        .checked_sub(timeout)
                        .expect("the clock reaches back that far");
                }
            }),
        "the callee's dialog runs no session timer"
    );
    let sent = sweep(&dispatcher);

    assert_eq!(sequence_to(&sent, CALLEE), vec!["ACK", "BYE"]);
    assert_eq!(requests(&sent, CALLER, Method::Bye).len(), 1);
}

// ---------------------------------------------------------------------------
// The per-call timer
// ---------------------------------------------------------------------------

/// `call.session_timer()` runs a session timer on a call even with no
/// `session_timer:` block configured.
#[tokio::test(flavor = "multi_thread")]
async fn a_per_call_session_timer_runs_without_a_configured_one() {
    let dispatcher = timer_dispatcher(None);
    let call_id = ringing_call_from(&dispatcher, &[("Supported", "timer")]);
    if let Some(mut call) = dispatcher.state.call_actors.get_call_mut(&call_id) {
        call.session_timer_override = Some(crate::script::api::call::SessionTimerOverride {
            session_expires: 1800,
            min_se: 90,
            refresher: crate::config::SessionRefresher::B2bua,
        });
    }

    let answer = callee_answers(
        &dispatcher,
        &call_id,
        &[
            ("Supported", "timer"),
            ("Session-Expires", "1800;refresher=uac"),
        ],
        &endpoint_sdp("198.51.100.20"),
    );
    assert_eq!(
        answer.headers.get("Session-Expires").map(String::as_str),
        Some("1800;refresher=uas")
    );

    age(&dispatcher, &call_id, false, 901);
    let refreshes = requests(&sweep(&dispatcher), CALLEE, Method::Invite);
    assert_eq!(refreshes.len(), 1, "the per-call timer did not refresh");
    assert_eq!(
        refreshes[0]
            .headers
            .get("Session-Expires")
            .map(String::as_str),
        Some("1800;refresher=uac")
    );
}

// ---------------------------------------------------------------------------
// Alongside the call's one teardown, the §15 BYE hold and the retransmit path
// ---------------------------------------------------------------------------

/// A session that runs out before the caller has ACKed siphon's 2xx is ended
/// through the call's teardown: the callee's BYE goes at once, and the caller's
/// waits for its ACK (RFC 3261 §15).
#[tokio::test(flavor = "multi_thread")]
async fn a_session_that_runs_out_before_the_caller_acks_holds_the_callers_bye_for_the_ack() {
    let dispatcher = timer_dispatcher(Some("session_expires: 90\n"));
    let call_id = ringing_call_from(&dispatcher, &[]);
    let relayed = callee_answers_unacked(
        &dispatcher,
        &call_id,
        &[
            ("Supported", "timer"),
            ("Session-Expires", "90;refresher=uas"),
        ],
        &endpoint_sdp("198.51.100.20"),
    );

    age(&dispatcher, &call_id, false, 61);
    let sent = sweep(&dispatcher);
    assert_eq!(requests(&sent, CALLEE, Method::Bye).len(), 1);
    assert!(
        requests(&sent, CALLER, Method::Bye).is_empty(),
        "the caller was sent a BYE before it ACKed the 2xx"
    );

    caller_acks(&dispatcher, &relayed);
    assert_eq!(
        requests(&wire(&dispatcher), CALLER, Method::Bye).len(),
        1,
        "the caller's ACK did not release its BYE"
    );
}

/// A call another teardown has already claimed is that teardown's to end. The
/// session timer sends no BYE of its own, and stops acting on the call.
#[tokio::test(flavor = "multi_thread")]
async fn a_session_timer_leaves_a_call_another_teardown_has_claimed_alone() {
    let dispatcher = timer_dispatcher(Some("session_expires: 90\n"));
    let call_id = ringing_call_from(&dispatcher, &[]);
    callee_answers(
        &dispatcher,
        &call_id,
        &[
            ("Supported", "timer"),
            ("Session-Expires", "90;refresher=uas"),
        ],
        &endpoint_sdp("198.51.100.20"),
    );
    age(&dispatcher, &call_id, false, 61);
    assert!(dispatcher.state.call_actors.claim_teardown(&call_id));

    let transaction_timeout = dispatcher.state.b2bua_retransmits.transaction_timeout();
    assert!(
        dispatcher
            .state
            .call_actors
            .session_timers_due(std::time::Instant::now(), transaction_timeout)
            .is_empty(),
        "the sweep still acts on a call another teardown has claimed"
    );
    let sent = sweep(&dispatcher);
    assert!(requests(&sent, CALLER, Method::Bye).is_empty());
    assert!(requests(&sent, CALLEE, Method::Bye).is_empty());
}

/// Every HEP packet the collector has received, until none arrives for 300 ms.
async fn hep_packets(collector: &tokio::net::UdpSocket) -> Vec<Vec<u8>> {
    let mut packets = Vec::new();
    let mut buffer = vec![0u8; 65_536];
    while let Ok(Ok(length)) = tokio::time::timeout(
        std::time::Duration::from_millis(300),
        collector.recv(&mut buffer),
    )
    .await
    {
        packets.push(buffer[..length].to_vec());
    }
    packets
}

/// A session refresh over UDP goes on the RFC 3261 §17.1 retransmit schedule of
/// every request siphon originates, and each retransmission leaves through the
/// same send as the first, HEP capture included.
#[tokio::test(flavor = "multi_thread")]
async fn a_session_refresh_is_retransmitted_and_every_copy_is_captured() {
    let collector = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("a collector socket");
    let endpoint = collector.local_addr().expect("the collector's address");
    let mut dispatcher = timer_dispatcher(Some("session_expires: 90\n"));
    let sender = HepSender::new(&crate::config::HepConfig {
        endpoint: endpoint.to_string(),
        version: 3,
        transport: crate::config::HepTransport::Udp,
        agent_id: None,
        ca_cert: None,
        tls_server_name: None,
        error_log_interval: 60,
    })
    .await
    .expect("a HEP sender");
    dispatcher.state.hep_sender = Some(Arc::new(sender));
    let (_, refresh) = call_with_refresh_out(&dispatcher);
    let _ = hep_packets(&collector).await;

    // Past T1, with no response to the refresh.
    tokio::time::sleep(std::time::Duration::from_millis(600)).await;
    sweep_b2bua_retransmits(&dispatcher.state);

    let frames: Vec<Vec<u8>> = dispatcher
        .udp
        .try_iter()
        .flat_map(|sent| {
            sent.frames()
                .map(|frame| frame.to_vec())
                .collect::<Vec<_>>()
        })
        .collect();
    let retransmitted: Vec<&Vec<u8>> = frames
        .iter()
        .filter(|frame| {
            parse_sip_message_bytes(frame).is_ok_and(|message| {
                message.method() == Some(&Method::Invite)
                    && branch_of(&message) == branch_of(&refresh)
            })
        })
        .collect();
    assert_eq!(retransmitted.len(), 1, "the refresh was not retransmitted");
    let packets = hep_packets(&collector).await;
    assert!(
        packets.iter().any(|packet| packet
            .windows(retransmitted[0].len())
            .any(|window| window == retransmitted[0].as_slice())),
        "the retransmitted refresh was not captured"
    );
}
