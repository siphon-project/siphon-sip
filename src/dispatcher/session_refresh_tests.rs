//! The RFC 4028 session refresh siphon sends the callee.
//!
//! It is a re-INVITE on the dialog it refreshes (RFC 4028 §7.4): the callee
//! leg's Call-ID, tags, route set, CSeq counter and remote target, siphon's own
//! Contact, the option tags of the INVITE that set the dialog up, and nothing of
//! the caller's INVITE. Its offer is the session description siphon has in force
//! on that dialog, so a held call stays held and an unchanged session keeps its
//! `o=` version (RFC 3264 §8).
//!
//! Every test drives the real paths and reads what the callee would have been
//! sent off the UDP egress channel.

use super::sdp_strip_tests::{
    address, answered_call, body_text, callee_response, caller_call, caller_invite,
    caller_response, dial_callee, endpoint_sdp, in_dialog_request, inbound_from, request_to,
    response_to, ringing_call, siphon_a_leg_tag, snapshot, strip_dispatcher, wire, B_LEG_BRANCH,
    B_LEG_CALL_ID, B_LEG_TAG, CALLEE, CALLEE_TAG, CALLEE_TARGET, CALLER,
};
use super::test_dispatcher::TestDispatcher;
use super::*;

/// The first hop of the callee dialog's route set.
const ROUTE_HOP: &str = "198.51.100.30:5060";
const ROUTE: &str = "<sip:198.51.100.30;lr>";

/// A session description siphon sent the callee, under the callee leg's session
/// id at `version`, with media `direction`.
fn session_toward_callee(session_id: u64, version: u64, direction: &str) -> String {
    format!(
        concat!(
            "v=0\r\n",
            "o=siphon {session_id} {version} IN IP4 192.0.2.1\r\n",
            "s=siphon\r\n",
            "c=IN IP4 203.0.113.60\r\n",
            "t=0 0\r\n",
            "m=audio 30000 RTP/AVP 0\r\n",
            "a=rtpmap:0 PCMU/8000\r\n",
            "a={direction}\r\n",
        ),
        session_id = session_id,
        version = version,
        direction = direction,
    )
}

/// The INVITE that set the callee's dialog up, as siphon sent it.
fn invite_siphon_sent_the_callee() -> SipMessage {
    parse_sip_message_bytes(
        concat!(
            "INVITE sip:callee@198.51.100.20:5060 SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-sdp-strip-b\r\n",
            "Max-Forwards: 69\r\n",
            "From: <sip:caller@192.0.2.1>;tag=b-leg-tag\r\n",
            "To: <sip:callee@198.51.100.20:5060>\r\n",
            "Call-ID: sdp-strip-b@192.0.2.1\r\n",
            "CSeq: 1 INVITE\r\n",
            "Contact: <sip:192.0.2.1:5060;transport=udp>\r\n",
            "Supported: replaces,timer\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        )
        .as_bytes(),
    )
    .expect("the callee INVITE parses")
}

/// An answered call whose callee dialog is set up the way dialling and answering
/// leave it: a route set, a CSeq counter a few requests in, the INVITE siphon sent
/// stashed on the leg, and that INVITE's session description in force at version
/// 0. The caller's stored INVITE carries headers of the caller's own that have no
/// place on the callee's dialog. Returns the call and the callee leg's session id.
fn refreshable_call(dispatcher: &TestDispatcher) -> (String, u64) {
    let state = &dispatcher.state;
    let call_id = answered_call(dispatcher);

    let mut stored = caller_invite(&endpoint_sdp("192.0.2.10"));
    stored
        .headers
        .add("X-Caller-Account", "account-7".to_string());
    stored.headers.add(
        "P-Asserted-Identity",
        "<sip:caller@example.com>".to_string(),
    );
    stored
        .headers
        .add("Record-Route", "<sip:192.0.2.40;lr>".to_string());
    stored
        .headers
        .add("Supported", "caller-only-tag".to_string());
    state
        .call_actors
        .set_a_leg_invite(&call_id, Arc::new(std::sync::Mutex::new(stored)));

    let session_id = state
        .call_actors
        .clone_leg(&call_id, false)
        .map(|leg| leg.dialog.sdp_session_id)
        .expect("the callee leg");
    if let Some(mut call) = state.call_actors.get_call_mut(&call_id) {
        if let Some(callee) = call.b_legs.get_mut(0) {
            callee.dialog.route_set = vec![ROUTE.to_string()];
            callee.dialog.local_cseq = 5;
            callee.dialog.sdp_version = 1;
            callee.dialog.last_sent_sdp =
                Some(session_toward_callee(session_id, 0, "sendrecv").into_bytes());
            callee.b_leg_invite = Some(Arc::new(std::sync::Mutex::new(
                invite_siphon_sent_the_callee(),
            )));
        }
    }
    (call_id, session_id)
}

/// Send a session refresh, and return the one INVITE siphon put on the wire with
/// where it went.
fn refresh(dispatcher: &TestDispatcher, call_id: &str) -> (SocketAddr, SipMessage) {
    b2bua_send_refresh_reinvite(call_id, &dispatcher.state);
    let mut invites: Vec<(SocketAddr, SipMessage)> = wire(dispatcher)
        .into_iter()
        .filter(|(_, message)| message.method() == Some(&Method::Invite))
        .collect();
    assert_eq!(invites.len(), 1, "a refresh is one INVITE");
    invites.remove(0)
}

/// The one INVITE siphon forwarded since the last look.
fn forwarded_invite(dispatcher: &TestDispatcher) -> SipMessage {
    let mut invites: Vec<SipMessage> = wire(dispatcher)
        .into_iter()
        .map(|(_, message)| message)
        .filter(|message| message.method() == Some(&Method::Invite))
        .collect();
    assert_eq!(invites.len(), 1, "one re-INVITE forwarded");
    invites.remove(0)
}

/// The branch of the tracking leg a forwarded re-INVITE left, by its direction
/// marker (`reinvite:a2b`, `reinvite:b2a`).
fn tracking_branch(dispatcher: &TestDispatcher, call_id: &str, marker: &str) -> String {
    dispatcher
        .state
        .call_actors
        .get_call(call_id)
        .and_then(|call| {
            call.b_legs
                .iter()
                .find(|leg| leg.dialog.target_uri.as_deref() == Some(marker))
                .map(|leg| leg.branch.clone())
        })
        .unwrap_or_else(|| panic!("no {marker} tracking leg"))
}

/// The caller puts the call on hold and siphon forwards the offer to the callee.
/// Returns the hold offer as the callee was sent it, and its tracking branch.
fn caller_holds(dispatcher: &TestDispatcher, call_id: &str) -> (SipMessage, String) {
    let hold = endpoint_sdp("192.0.2.10").replace("a=sendrecv", "a=sendonly");
    handle_b2bua_reinvite(
        inbound_from(CALLER),
        in_dialog_request("INVITE", true, &hold),
        &dispatcher.state,
    );
    let offered = forwarded_invite(dispatcher);
    (
        offered,
        tracking_branch(dispatcher, call_id, "reinvite:a2b"),
    )
}

/// The callee answers the hold offer with `status_code`.
fn callee_answers_hold(dispatcher: &TestDispatcher, call_id: &str, branch: &str, status_code: u16) {
    let body = if status_code == 200 {
        endpoint_sdp("198.51.100.20").replace("a=sendrecv", "a=recvonly")
    } else {
        String::new()
    };
    let mut response = callee_response(status_code, "Answer", branch, "5 INVITE", &body);
    assert!(forward_reinvite_response(
        call_id,
        branch,
        &mut response,
        status_code,
        address(CALLEE),
        &dispatcher.state,
        &snapshot(dispatcher, call_id, branch),
    ));
    let _ = wire(dispatcher);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_refresh_is_a_request_on_the_callee_dialog() {
    let dispatcher = strip_dispatcher(&[]);
    let (call_id, _) = refreshable_call(&dispatcher);

    let (destination, refresh) = refresh(&dispatcher, &call_id);

    assert_eq!(
        destination,
        address(ROUTE_HOP),
        "not sent to the first hop of the callee's route set"
    );
    assert_eq!(
        refresh.headers.get_all("Route").cloned(),
        Some(vec![ROUTE.to_string()])
    );
    match &refresh.start_line {
        StartLine::Request(request_line) => {
            assert_eq!(request_line.request_uri.to_string(), CALLEE_TARGET)
        }
        StartLine::Response(_) => panic!("a refresh is a request"),
    }
    assert_eq!(
        refresh.headers.call_id().map(String::as_str),
        Some(B_LEG_CALL_ID)
    );
    assert_eq!(
        refresh.headers.from().map(String::as_str),
        Some(format!("<sip:caller@192.0.2.1>;tag={B_LEG_TAG}").as_str())
    );
    assert_eq!(
        refresh.headers.to().map(String::as_str),
        Some(format!("<sip:callee@198.51.100.20:5060>;tag={CALLEE_TAG}").as_str())
    );
    assert_eq!(refresh.headers.cseq().map(String::as_str), Some("5 INVITE"));
    assert_eq!(
        refresh.headers.get("Contact").map(String::as_str),
        Some("<sip:192.0.2.1:5060;transport=udp>")
    );
    // RFC 4028 §7.4: the option tags of the request that set the session up.
    assert_eq!(
        refresh.headers.get_all("Supported").cloned(),
        Some(vec!["replaces,timer".to_string()])
    );
    assert_eq!(
        refresh.headers.get("Session-Expires").map(String::as_str),
        Some("1800;refresher=uac")
    );
    for caller_header in ["X-Caller-Account", "P-Asserted-Identity", "Record-Route"] {
        assert!(
            refresh.headers.get(caller_header).is_none(),
            "{caller_header} crossed from the caller's INVITE"
        );
    }
}

/// RFC 4028 §7.4: a refresh re-INVITE carries an offer even when nothing
/// changed, and says so with the same `o=` (RFC 3264 §8).
#[tokio::test(flavor = "multi_thread")]
async fn an_unchanged_session_is_offered_again_with_its_version() {
    let dispatcher = strip_dispatcher(&[]);
    let (call_id, session_id) = refreshable_call(&dispatcher);
    let in_force = session_toward_callee(session_id, 0, "sendrecv");

    let (_, first) = refresh(&dispatcher, &call_id);
    let (_, second) = refresh(&dispatcher, &call_id);

    assert_eq!(body_text(&first), in_force);
    assert_eq!(
        body_text(&second),
        in_force,
        "a second refresh with nothing changed moved the session on"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_held_call_stays_held_across_a_session_refresh() {
    let dispatcher = strip_dispatcher(&[]);
    let (call_id, _) = refreshable_call(&dispatcher);
    let (offered_hold, branch) = caller_holds(&dispatcher, &call_id);
    callee_answers_hold(&dispatcher, &call_id, &branch, 200);

    let (_, refresh) = refresh(&dispatcher, &call_id);

    assert!(body_text(&offered_hold).contains("a=sendonly\r\n"));
    assert_eq!(
        body_text(&refresh),
        body_text(&offered_hold),
        "the refresh did not offer the hold the callee accepted"
    );
}

/// A hold the callee refuses changes nothing, so the refresh offers the session
/// still in force. That offer has to come under a version past the refused one's,
/// which the callee has already seen (RFC 3264 §8).
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_hold_leaves_the_refresh_on_the_session_in_force() {
    let dispatcher = strip_dispatcher(&[]);
    let (call_id, session_id) = refreshable_call(&dispatcher);
    let (_, branch) = caller_holds(&dispatcher, &call_id);
    callee_answers_hold(&dispatcher, &call_id, &branch, 488);

    let (_, refresh) = refresh(&dispatcher, &call_id);

    assert_eq!(
        body_text(&refresh),
        session_toward_callee(session_id, 2, "sendrecv")
    );
}

/// When the callee is the one that re-offered, the session in force on its dialog
/// is the answer siphon relayed to it.
#[tokio::test(flavor = "multi_thread")]
async fn the_answer_siphon_relays_to_the_callee_is_what_a_refresh_offers() {
    let dispatcher = strip_dispatcher(&[]);
    let (call_id, _) = refreshable_call(&dispatcher);
    handle_b2bua_reinvite(
        inbound_from(CALLEE),
        in_dialog_request("INVITE", false, &endpoint_sdp("198.51.100.20")),
        &dispatcher.state,
    );
    let _ = wire(&dispatcher);
    let branch = tracking_branch(&dispatcher, &call_id, "reinvite:b2a");
    let siphon_tag = siphon_a_leg_tag(&dispatcher, &call_id);
    let mut answer = caller_response(
        &branch,
        "2 INVITE",
        &siphon_tag,
        &endpoint_sdp("192.0.2.10").replace("a=sendrecv", "a=recvonly"),
    );
    assert!(forward_reinvite_response(
        &call_id,
        &branch,
        &mut answer,
        200,
        address(CALLER),
        &dispatcher.state,
        &snapshot(&dispatcher, &call_id, &branch),
    ));
    let relayed = response_to(&wire(&dispatcher), CALLEE, 200);

    let (_, refresh) = refresh(&dispatcher, &call_id);

    assert_eq!(body_text(&refresh), body_text(&relayed));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_offer_dialled_to_the_callee_is_the_session_in_force_on_its_dialog() {
    let dispatcher = strip_dispatcher(&[]);
    let call_id = caller_call(&dispatcher);

    dial_callee(
        &dispatcher,
        &call_id,
        &caller_invite(&endpoint_sdp("192.0.2.10")),
    );

    let offer = request_to(&wire(&dispatcher), CALLEE, Method::Invite);
    let in_force = dispatcher
        .state
        .call_actors
        .get_call(&call_id)
        .and_then(|call| {
            call.b_legs
                .first()
                .and_then(|leg| leg.dialog.last_sent_sdp.clone())
        });
    assert_eq!(in_force, Some(offer.body.clone()));
}

/// The answers siphon gives the caller are the session in force on the caller's
/// dialog: a relayed 2xx, and one siphon answers itself.
#[tokio::test(flavor = "multi_thread")]
async fn the_answers_siphon_sends_the_caller_are_the_session_in_force_on_its_dialog() {
    let caller_session = |dispatcher: &TestDispatcher, call_id: &str| {
        dispatcher
            .state
            .call_actors
            .clone_leg(call_id, true)
            .and_then(|leg| leg.dialog.last_sent_sdp)
    };

    let dispatcher = strip_dispatcher(&[]);
    let call_id = ringing_call(&dispatcher);
    let mut answer = callee_response(
        200,
        "OK",
        B_LEG_BRANCH,
        "1 INVITE",
        &endpoint_sdp("198.51.100.20"),
    );
    prepare_a_leg_answer(
        &call_id,
        &mut answer,
        &dispatcher.state,
        &snapshot(&dispatcher, &call_id, B_LEG_BRANCH),
    );
    assert_eq!(
        caller_session(&dispatcher, &call_id),
        Some(answer.body.clone())
    );

    let dispatcher = strip_dispatcher(&[]);
    let call_id = caller_call(&dispatcher);
    let local_answer = endpoint_sdp("203.0.113.70").into_bytes();
    assert!(send_uas_response(
        &dispatcher.state,
        &call_id,
        &caller_invite(""),
        200,
        "OK",
        Some(local_answer.clone()),
        Some("application/sdp"),
        true,
    ));
    assert_eq!(caller_session(&dispatcher, &call_id), Some(local_answer));
}
