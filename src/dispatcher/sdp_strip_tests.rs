//! `media.sdp_strip_attributes`: the named SDP attributes are removed from the
//! SDP siphon relays between the two legs of a B2BUA call, at session and media
//! level, in both directions, on every path an offer or an answer crosses.
//!
//! Also the `o=`/`s=` topology hiding on the paths that send a leg SDP someone
//! else described: a 422 retry, a session refresh, a siphon-originated
//! re-INVITE and the 200 to a `Replaces` newcomer, `o=` session version included
//! (RFC 3264 §8).
//!
//! Every test drives the real relay path and reads the SDP off what the far
//! party would have been sent: the UDP egress channel, or the message a path
//! hands to the send. With nothing configured the relayed SDP is the one siphon
//! sent before the setting existed.

use super::test_dispatcher::{test_dispatcher, TestDispatcher};
use super::*;

pub(super) const CALLER: &str = "192.0.2.10:5060";
pub(super) const CALLEE: &str = "198.51.100.20:5060";
pub(super) const CALLEE_TARGET: &str = "sip:callee@198.51.100.20:5060";

pub(super) const A_LEG_CALL_ID: &str = "sdp-strip-a@192.0.2.10";
pub(super) const CALLER_TAG: &str = "caller-tag";
pub(super) const B_LEG_CALL_ID: &str = "sdp-strip-b@192.0.2.1";
/// siphon's own From-tag on the B-leg.
pub(super) const B_LEG_TAG: &str = "b-leg-tag";
pub(super) const CALLEE_TAG: &str = "callee-tag";
pub(super) const B_LEG_BRANCH: &str = "z9hG4bK-sdp-strip-b";

/// What the tests configure: one name in the case the SDP uses and one in a
/// different case.
pub(super) const STRIP: [&str; 2] = ["msid", "X-HIDDEN"];

/// An endpoint's SDP. It carries the configured attributes at both levels,
/// `x-hidden` with and without a value and in a different case than configured,
/// next to attributes that must survive: `msid-semantic` shares a prefix with
/// `msid` and is a different attribute.
pub(super) fn endpoint_sdp(address: &str) -> String {
    format!(
        concat!(
            "v=0\r\n",
            "o=endpoint 2890844526 2890844526 IN IP4 {address}\r\n",
            "s=endpoint session\r\n",
            "c=IN IP4 {address}\r\n",
            "t=0 0\r\n",
            "a=x-hidden\r\n",
            "a=msid-semantic: WMS stream-a\r\n",
            "m=audio 40000 RTP/AVP 0 101\r\n",
            "a=rtpmap:0 PCMU/8000\r\n",
            "a=rtpmap:101 telephone-event/8000\r\n",
            "a=MSID:stream-a track-a\r\n",
            "a=X-Hidden:detail\r\n",
            "a=sendrecv\r\n",
        ),
        address = address,
    )
}

/// The same endpoint SDP with none of the configured attributes in it.
pub(super) fn plain_sdp(address: &str) -> String {
    format!(
        concat!(
            "v=0\r\n",
            "o=endpoint 2890844526 2890844526 IN IP4 {address}\r\n",
            "s=endpoint session\r\n",
            "c=IN IP4 {address}\r\n",
            "t=0 0\r\n",
            "a=msid-semantic: WMS stream-a\r\n",
            "m=audio 40000 RTP/AVP 0 101\r\n",
            "a=rtpmap:0 PCMU/8000\r\n",
            "a=sendrecv\r\n",
        ),
        address = address,
    )
}

pub(super) fn strip_dispatcher(configured: &[&str]) -> TestDispatcher {
    let mut dispatcher = test_dispatcher();
    dispatcher.state.sdp_strip_attributes =
        configured.iter().map(|name| name.to_string()).collect();
    dispatcher
}

pub(super) fn address(literal: &str) -> SocketAddr {
    literal.parse().expect("a literal address")
}

pub(super) fn udp_transport(remote: &str) -> LegTransport {
    LegTransport {
        remote_addr: address(remote),
        connection_id: ConnectionId::default(),
        transport: Transport::Udp,
        local_addr: None,
    }
}

pub(super) fn inbound_from(remote: &str) -> InboundMessage {
    InboundMessage {
        client_transport: None,
        connection_id: ConnectionId::default(),
        transport: Transport::Udp,
        local_addr: address("192.0.2.1:5060"),
        remote_addr: address(remote),
        data: Bytes::new(),
    }
}

pub(super) fn parse(raw: &str) -> SipMessage {
    parse_sip_message_bytes(raw.as_bytes()).expect("the test message parses")
}

/// The caller's INVITE, carrying `body` as its offer.
pub(super) fn caller_invite(body: &str) -> SipMessage {
    parse(&format!(
        concat!(
            "INVITE sip:callee@siphon.example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-caller\r\n",
            "Max-Forwards: 70\r\n",
            "From: <sip:caller@example.com>;tag={caller_tag}\r\n",
            "To: <sip:callee@siphon.example.com>\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: 1 INVITE\r\n",
            "Contact: <sip:caller@192.0.2.10:5060>\r\n",
            "Content-Type: application/sdp\r\n",
            "Content-Length: {length}\r\n",
            "\r\n",
            "{body}",
        ),
        caller_tag = CALLER_TAG,
        call_id = A_LEG_CALL_ID,
        length = body.len(),
        body = body,
    ))
}

/// An in-dialog request from the caller (`from_caller`) or from the callee.
pub(super) fn in_dialog_request(method: &str, from_caller: bool, body: &str) -> SipMessage {
    let (via, from, to, call_id, contact) = if from_caller {
        (
            "192.0.2.10:5060;branch=z9hG4bK-caller-2",
            format!("<sip:caller@example.com>;tag={CALLER_TAG}"),
            "<sip:callee@siphon.example.com>;tag=siphon-a-tag".to_string(),
            A_LEG_CALL_ID,
            "<sip:caller@192.0.2.10:5060>",
        )
    } else {
        (
            "198.51.100.20:5060;branch=z9hG4bK-callee-2",
            format!("<sip:callee@198.51.100.20:5060>;tag={CALLEE_TAG}"),
            format!("<sip:caller@192.0.2.1>;tag={B_LEG_TAG}"),
            B_LEG_CALL_ID,
            "<sip:callee@198.51.100.20:5060>",
        )
    };
    parse(&format!(
        concat!(
            "{method} sip:192.0.2.1:5060 SIP/2.0\r\n",
            "Via: SIP/2.0/UDP {via}\r\n",
            "Max-Forwards: 70\r\n",
            "From: {from}\r\n",
            "To: {to}\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: 2 {method}\r\n",
            "Contact: {contact}\r\n",
            "Content-Type: application/sdp\r\n",
            "Content-Length: {length}\r\n",
            "\r\n",
            "{body}",
        ),
        method = method,
        via = via,
        from = from,
        to = to,
        call_id = call_id,
        contact = contact,
        length = body.len(),
        body = body,
    ))
}

/// A response from the callee in the B-leg dialog.
pub(super) fn callee_response(
    status_code: u16,
    reason: &str,
    branch: &str,
    cseq: &str,
    body: &str,
) -> SipMessage {
    parse(&format!(
        concat!(
            "SIP/2.0 {status_code} {reason}\r\n",
            "Via: SIP/2.0/UDP 192.0.2.1:5060;branch={branch}\r\n",
            "From: <sip:caller@192.0.2.1>;tag={b_leg_tag}\r\n",
            "To: <sip:callee@198.51.100.20:5060>;tag={callee_tag}\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: {cseq}\r\n",
            "Contact: <sip:callee@198.51.100.20:5060>\r\n",
            "Content-Type: application/sdp\r\n",
            "Content-Length: {length}\r\n",
            "\r\n",
            "{body}",
        ),
        status_code = status_code,
        reason = reason,
        branch = branch,
        b_leg_tag = B_LEG_TAG,
        callee_tag = CALLEE_TAG,
        call_id = B_LEG_CALL_ID,
        cseq = cseq,
        length = body.len(),
        body = body,
    ))
}

/// A response from the caller in the A-leg dialog, where siphon's tag is
/// `siphon_tag`.
pub(super) fn caller_response(
    branch: &str,
    cseq: &str,
    siphon_tag: &str,
    body: &str,
) -> SipMessage {
    parse(&format!(
        concat!(
            "SIP/2.0 200 OK\r\n",
            "Via: SIP/2.0/UDP 192.0.2.1:5060;branch={branch}\r\n",
            "From: <sip:callee@siphon.example.com>;tag={siphon_tag}\r\n",
            "To: <sip:caller@example.com>;tag={caller_tag}\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: {cseq}\r\n",
            "Contact: <sip:caller@192.0.2.10:5060>\r\n",
            "Content-Type: application/sdp\r\n",
            "Content-Length: {length}\r\n",
            "\r\n",
            "{body}",
        ),
        branch = branch,
        siphon_tag = siphon_tag,
        caller_tag = CALLER_TAG,
        call_id = A_LEG_CALL_ID,
        cseq = cseq,
        length = body.len(),
        body = body,
    ))
}

/// A call from the caller with no B-leg yet. Its stored INVITE carries the
/// caller's offer.
pub(super) fn caller_call(dispatcher: &TestDispatcher) -> String {
    let state = &dispatcher.state;
    let mut a_leg = Leg::new_a_leg(
        A_LEG_CALL_ID.to_string(),
        CALLER_TAG.to_string(),
        "z9hG4bK-caller".to_string(),
        udp_transport(CALLER),
    );
    a_leg.dialog.remote_contact = Some("sip:caller@192.0.2.10:5060".to_string());
    a_leg.dialog.local_contact = Some("<sip:192.0.2.1:5060;transport=udp>".to_string());
    a_leg.dialog.local_from_uri = Some("<sip:callee@siphon.example.com>".to_string());
    a_leg.dialog.remote_to_uri = Some("<sip:caller@example.com>".to_string());
    let call_id = state.call_actors.create_call(a_leg);
    state.call_actors.set_a_leg_invite(
        &call_id,
        Arc::new(std::sync::Mutex::new(caller_invite(&endpoint_sdp(
            "192.0.2.10",
        )))),
    );
    call_id
}

/// A call whose INVITE is out to the callee and not yet answered.
pub(super) fn ringing_call(dispatcher: &TestDispatcher) -> String {
    let call_id = caller_call(dispatcher);
    let mut b_leg = Leg::new_b_leg(
        B_LEG_CALL_ID.to_string(),
        B_LEG_TAG.to_string(),
        CALLEE_TARGET.to_string(),
        B_LEG_BRANCH.to_string(),
        udp_transport(CALLEE),
    );
    b_leg.b_leg_invite = Some(Arc::new(std::sync::Mutex::new(caller_invite(""))));
    assert!(dispatcher.state.call_actors.add_b_leg(&call_id, b_leg));
    call_id
}

/// A call the callee answered and both parties ACKed.
pub(super) fn answered_call(dispatcher: &TestDispatcher) -> String {
    let state = &dispatcher.state;
    let call_id = caller_call(dispatcher);
    if let Some(mut call) = state.call_actors.get_call_mut(&call_id) {
        call.a_leg.initial_acked = true;
    }
    let mut b_leg = Leg::new_b_leg(
        B_LEG_CALL_ID.to_string(),
        B_LEG_TAG.to_string(),
        CALLEE_TARGET.to_string(),
        B_LEG_BRANCH.to_string(),
        udp_transport(CALLEE),
    );
    b_leg.dialog.remote_tag = Some(CALLEE_TAG.to_string());
    b_leg.dialog.remote_contact = Some(CALLEE_TARGET.to_string());
    b_leg.dialog.local_contact = Some("<sip:192.0.2.1:5060;transport=udp>".to_string());
    b_leg.dialog.local_from_uri = Some("<sip:caller@192.0.2.1>".to_string());
    b_leg.dialog.remote_to_uri = Some("<sip:callee@198.51.100.20:5060>".to_string());
    b_leg.initial_acked = true;
    assert!(state.call_actors.add_b_leg(&call_id, b_leg));
    state.call_actors.set_winner(&call_id, 0);
    state.call_actors.set_state(&call_id, CallState::Answered);
    call_id
}

/// siphon's own tag on the A-leg dialog.
pub(super) fn siphon_a_leg_tag(dispatcher: &TestDispatcher, call_id: &str) -> String {
    dispatcher
        .state
        .call_actors
        .get_call(call_id)
        .map(|call| call.a_leg.dialog.local_tag.clone())
        .expect("the call is live")
}

/// Register the tracking leg a forwarded re-INVITE or UPDATE leaves on the call,
/// the way `handle_b2bua_reinvite` / `handle_b2bua_update` do, and return its
/// branch. `toward_callee` is the direction the request was forwarded in.
pub(super) fn track_forwarded(
    dispatcher: &TestDispatcher,
    call_id: &str,
    method: &str,
    marker: &str,
    toward_callee: bool,
) -> String {
    let branch = format!("z9hG4bK-{}", marker.replace(':', "-"));
    let (leg_call_id, leg_tag, destination) = if toward_callee {
        (B_LEG_CALL_ID, B_LEG_TAG, CALLEE)
    } else {
        (A_LEG_CALL_ID, CALLER_TAG, CALLER)
    };
    let originator = in_dialog_request(method, toward_callee, "");
    let mut leg = Leg::new_b_leg(
        leg_call_id.to_string(),
        leg_tag.to_string(),
        marker.to_string(),
        branch.clone(),
        udp_transport(destination),
    );
    leg.stored_vias = originator
        .headers
        .get_all("Via")
        .cloned()
        .unwrap_or_default();
    leg.stored_cseq = originator.headers.cseq().cloned();
    leg.stored_from = originator.headers.from().cloned();
    leg.stored_to = originator.headers.to().cloned();
    assert!(dispatcher.state.call_actors.add_b_leg(call_id, leg));
    branch
}

pub(super) fn snapshot(
    dispatcher: &TestDispatcher,
    call_id: &str,
    branch: &str,
) -> BLegResponseSnapshot {
    b_leg_response_snapshot(call_id, branch, &dispatcher.state).expect("the call is live")
}

/// Everything siphon has put on the wire since the last look.
pub(super) fn wire(dispatcher: &TestDispatcher) -> Vec<(SocketAddr, SipMessage)> {
    dispatcher
        .udp
        .try_iter()
        .map(|sent| {
            (
                sent.destination,
                parse_sip_message_bytes(&sent.data).expect("siphon sent a message that parses"),
            )
        })
        .collect()
}

pub(super) fn request_to(
    sent: &[(SocketAddr, SipMessage)],
    destination: &str,
    method: Method,
) -> SipMessage {
    sent.iter()
        .find(|(to, message)| *to == address(destination) && message.method() == Some(&method))
        .map(|(_, message)| message.clone())
        .unwrap_or_else(|| panic!("no {method:?} to {destination} among {} sent", sent.len()))
}

pub(super) fn response_to(
    sent: &[(SocketAddr, SipMessage)],
    destination: &str,
    status_code: u16,
) -> SipMessage {
    sent.iter()
        .find(|(to, message)| {
            *to == address(destination) && message.status_code() == Some(status_code)
        })
        .map(|(_, message)| message.clone())
        .unwrap_or_else(|| {
            panic!(
                "no {status_code} to {destination} among {} sent",
                sent.len()
            )
        })
}

pub(super) fn body_text(message: &SipMessage) -> String {
    String::from_utf8(message.body.clone()).expect("the SDP is text")
}

/// None of the configured attributes crossed, everything else of the SDP did,
/// and `Content-Length` still describes the body.
pub(super) fn assert_stripped(message: &SipMessage, context: &str) {
    let body = body_text(message);
    for line in body.lines() {
        if let Some(attribute) = line.strip_prefix("a=") {
            let name = attribute.split(':').next().unwrap_or(attribute);
            assert!(
                !STRIP
                    .iter()
                    .any(|configured| name.eq_ignore_ascii_case(configured)),
                "{context}: a={attribute} crossed:\n{body}"
            );
        }
    }
    for kept in [
        "a=msid-semantic: WMS stream-a\r\n",
        "m=audio 40000 RTP/AVP 0 101\r\n",
        "a=rtpmap:0 PCMU/8000\r\n",
        "a=sendrecv\r\n",
    ] {
        assert!(body.contains(kept), "{context}: {kept:?} was lost:\n{body}");
    }
    assert_eq!(
        message.headers.get("Content-Length").map(String::as_str),
        Some(body.len().to_string().as_str()),
        "{context}: Content-Length does not describe the body"
    );
}

/// Every line of `sent` other than the origin and the session name, the two
/// lines topology hiding owns, crossed byte for byte and in order.
pub(super) fn assert_crossed_unchanged(message: &SipMessage, sent: &str, context: &str) {
    fn without_identity(sdp: &str) -> Vec<&str> {
        sdp.split_inclusive('\n')
            .filter(|line| !line.starts_with("o=") && !line.starts_with("s="))
            .collect()
    }
    let relayed = body_text(message);
    assert_eq!(
        without_identity(&relayed),
        without_identity(sent),
        "{context}"
    );
    assert_eq!(
        message.headers.get("Content-Length").map(String::as_str),
        Some(relayed.len().to_string().as_str()),
        "{context}: Content-Length does not describe the body"
    );
}

/// Dial the callee with `invite` as the A-leg INVITE.
pub(super) fn dial_callee(dispatcher: &TestDispatcher, call_id: &str, invite: &SipMessage) {
    assert!(
        b2bua_send_b_leg_invite(
            call_id,
            CALLEE_TARGET,
            Some("sip:198.51.100.20:5060"),
            None,
            &[],
            None,
            None,
            invite,
            None,
            None,
            None,
            None,
            &[],
            &dispatcher.state,
        ),
        "the callee was not dialled"
    );
}

// ---------------------------------------------------------------------------
// The initial offer/answer
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn the_offer_dialled_to_the_callee_loses_the_named_attributes() {
    let dispatcher = strip_dispatcher(&STRIP);
    let call_id = caller_call(&dispatcher);

    dial_callee(
        &dispatcher,
        &call_id,
        &caller_invite(&endpoint_sdp("192.0.2.10")),
    );

    let offer = request_to(&wire(&dispatcher), CALLEE, Method::Invite);
    assert_stripped(&offer, "INVITE to the callee");

    // A 401/407 retry is rebuilt from the INVITE stashed on the leg rather than
    // from the caller's, so the stash is the copy that has to be stripped.
    let stashed = dispatcher
        .state
        .call_actors
        .get_call(&call_id)
        .and_then(|call| call.b_legs.first().and_then(|leg| leg.b_leg_invite.clone()))
        .expect("the sent INVITE is stashed on its leg");
    let stashed = stashed.lock().expect("the stash lock").clone();
    assert_stripped(&stashed, "INVITE stashed for the credentialed retry");
}

#[tokio::test(flavor = "multi_thread")]
async fn with_nothing_configured_the_offer_to_the_callee_is_unchanged() {
    let dispatcher = strip_dispatcher(&[]);
    let call_id = caller_call(&dispatcher);
    let offer_sdp = endpoint_sdp("192.0.2.10");

    dial_callee(&dispatcher, &call_id, &caller_invite(&offer_sdp));

    let offer = request_to(&wire(&dispatcher), CALLEE, Method::Invite);
    assert_crossed_unchanged(&offer, &offer_sdp, "INVITE to the callee");
}

/// The line of `message`'s SDP that starts with `prefix` (`"o="`, `"s="`),
/// without its line ending.
pub(super) fn sdp_line(message: &SipMessage, prefix: &str) -> Option<String> {
    body_text(message)
        .lines()
        .find(|line| line.starts_with(prefix))
        .map(str::to_string)
}

/// `status_code` from the callee for `invite`, as its server transaction would
/// send it (RFC 3261 §8.2.6.2): the INVITE's Via, From, Call-ID and CSeq, and
/// its To with the callee's tag.
pub(super) fn response_to_request(
    invite: &SipMessage,
    status_code: u16,
    reason: &str,
) -> SipMessage {
    let header = |name: &str| {
        invite
            .headers
            .get(name)
            .cloned()
            .unwrap_or_else(|| panic!("the INVITE has no {name}"))
    };
    parse(&format!(
        concat!(
            "SIP/2.0 {status_code} {reason}\r\n",
            "Via: {via}\r\n",
            "From: {from}\r\n",
            "To: {to};tag={callee_tag}\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: {cseq}\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        status_code = status_code,
        reason = reason,
        via = header("Via"),
        from = header("From"),
        to = header("To"),
        callee_tag = CALLEE_TAG,
        call_id = header("Call-ID"),
        cseq = header("CSeq"),
    ))
}

/// The session timer siphon runs, with an interval a callee can refuse.
pub(super) fn with_session_timer(dispatcher: &mut TestDispatcher) {
    dispatcher.state.session_timer_config =
        Some(serde_yaml_ng::from_str("session_expires: 90\n").expect("a session timer config"));
}

/// A 422 retry re-sends the offer the callee refused (RFC 4028 §6), so it is
/// rebuilt from the INVITE siphon sent the callee rather than the caller's: the
/// same topology-hidden `o=` and `s=`, the attributes still stripped, siphon's
/// own Contact, and the next CSeq (RFC 3261 §8.1.3.5). An identical offer keeps
/// its `o=` version (RFC 3264 §8), and the leg the retry supersedes hands over
/// its session id, so the next offer on the dialog goes on from there.
#[tokio::test(flavor = "multi_thread")]
async fn the_422_retry_resends_the_offer_the_callee_was_sent() {
    let mut dispatcher = strip_dispatcher(&STRIP);
    with_session_timer(&mut dispatcher);
    let call_id = caller_call(&dispatcher);
    dial_callee(
        &dispatcher,
        &call_id,
        &caller_invite(&endpoint_sdp("192.0.2.10")),
    );
    let refused = request_to(&wire(&dispatcher), CALLEE, Method::Invite);
    let (branch, session_id) = dispatcher
        .state
        .call_actors
        .get_call(&call_id)
        .and_then(|call| {
            call.b_legs
                .first()
                .map(|leg| (leg.branch.clone(), leg.dialog.sdp_session_id))
        })
        .expect("the callee's leg");
    let mut too_small = response_to_request(&refused, 422, "Session Interval Too Small");
    too_small.headers.set("Min-SE", "1800".to_string());

    assert!(retry_after_422(
        &call_id,
        &mut too_small,
        422,
        &dispatcher.state,
        &snapshot(&dispatcher, &call_id, &branch),
    ));

    let retry = request_to(&wire(&dispatcher), CALLEE, Method::Invite);
    assert_eq!(sdp_line(&retry, "o="), sdp_line(&refused, "o="));
    assert_eq!(sdp_line(&retry, "s="), Some("s=siphon".to_string()));
    assert_stripped(&retry, "422 retry to the callee");
    assert_eq!(
        retry.headers.get("Contact"),
        refused.headers.get("Contact"),
        "the retry names the caller's Contact instead of siphon's"
    );
    assert_eq!(retry.headers.cseq().map(String::as_str), Some("2 INVITE"));
    assert_eq!(
        retry.headers.get("Session-Expires").map(String::as_str),
        Some("1800;refresher=uac")
    );
    assert_eq!(
        retry.headers.get("Min-SE").map(String::as_str),
        Some("1800")
    );

    let (retry_branch, retry_origin) = dispatcher
        .state
        .call_actors
        .get_call(&call_id)
        .and_then(|call| {
            call.b_legs.first().map(|leg| {
                (
                    leg.branch.clone(),
                    (leg.dialog.sdp_session_id, leg.dialog.sdp_version),
                )
            })
        })
        .expect("the retry's leg");
    assert_ne!(retry_branch, branch, "the retry did not supersede the leg");
    assert_eq!(retry_origin, (session_id, 1));
}

#[tokio::test(flavor = "multi_thread")]
async fn early_media_relayed_to_the_caller_loses_the_named_attributes() {
    let dispatcher = strip_dispatcher(&STRIP);
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

    assert_stripped(
        &response_to(&wire(&dispatcher), CALLER, 183),
        "183 to the caller",
    );
}

/// Relay one 183 carrying `sdp` through a dispatcher configured with
/// `configured`, and return what the caller was sent.
pub(super) fn relayed_early_media(configured: &[&str], sdp: &str) -> SipMessage {
    let dispatcher = strip_dispatcher(configured);
    let call_id = ringing_call(&dispatcher);
    let mut progress = callee_response(183, "Session Progress", B_LEG_BRANCH, "1 INVITE", sdp);
    b_leg_provisional(
        &call_id,
        B_LEG_BRANCH,
        &mut progress,
        183,
        address(CALLEE),
        &dispatcher.state,
        &snapshot(&dispatcher, &call_id, B_LEG_BRANCH),
    );
    response_to(&wire(&dispatcher), CALLER, 183)
}

#[tokio::test(flavor = "multi_thread")]
async fn with_nothing_configured_early_media_to_the_caller_is_unchanged() {
    let sdp = endpoint_sdp("198.51.100.20");
    let relayed = relayed_early_media(&[], &sdp);
    assert_crossed_unchanged(&relayed, &sdp, "183 to the caller");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_configured_name_the_sdp_does_not_carry_leaves_the_relay_byte_identical() {
    let sdp = plain_sdp("198.51.100.20");
    let unconfigured = relayed_early_media(&[], &sdp);
    let configured = relayed_early_media(&STRIP, &sdp);
    assert_eq!(configured.body, unconfigured.body);
    assert_eq!(
        configured.headers.get("Content-Length"),
        unconfigured.headers.get("Content-Length")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_answer_relayed_to_the_caller_loses_the_named_attributes() {
    let dispatcher = strip_dispatcher(&STRIP);
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
        &[],
    );

    assert_stripped(&answer, "2xx to the caller");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_relayed_failure_carrying_sdp_loses_the_named_attributes() {
    // RFC 3261 §21.4.26: a 488 may describe the media the callee does support.
    let dispatcher = strip_dispatcher(&STRIP);
    let call_id = ringing_call(&dispatcher);
    let mut not_acceptable = callee_response(
        488,
        "Not Acceptable Here",
        B_LEG_BRANCH,
        "1 INVITE",
        &endpoint_sdp("198.51.100.20"),
    );

    relay_failure_to_a_leg(
        &call_id,
        &mut not_acceptable,
        &snapshot(&dispatcher, &call_id, B_LEG_BRANCH),
        &dispatcher.state,
    );

    assert_stripped(
        &response_to(&wire(&dispatcher), CALLER, 488),
        "488 to the caller",
    );
}

// ---------------------------------------------------------------------------
// In-dialog offers and answers
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn a_re_invite_offer_loses_the_named_attributes_in_both_directions() {
    for from_caller in [true, false] {
        let dispatcher = strip_dispatcher(&STRIP);
        answered_call(&dispatcher);
        let (origin, target) = if from_caller {
            (CALLER, CALLEE)
        } else {
            (CALLEE, CALLER)
        };

        handle_b2bua_reinvite(
            inbound_from(origin),
            in_dialog_request("INVITE", from_caller, &endpoint_sdp("192.0.2.30")),
            &dispatcher.state,
        );

        let forwarded = request_to(&wire(&dispatcher), target, Method::Invite);
        assert_stripped(&forwarded, &format!("re-INVITE from {origin} to {target}"));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_update_offer_loses_the_named_attributes_in_both_directions() {
    for from_caller in [true, false] {
        let dispatcher = strip_dispatcher(&STRIP);
        answered_call(&dispatcher);
        let (origin, target) = if from_caller {
            (CALLER, CALLEE)
        } else {
            (CALLEE, CALLER)
        };

        handle_b2bua_update(
            inbound_from(origin),
            in_dialog_request("UPDATE", from_caller, &endpoint_sdp("192.0.2.30")),
            &dispatcher.state,
        );

        let forwarded = request_to(&wire(&dispatcher), target, Method::Update);
        assert_stripped(&forwarded, &format!("UPDATE from {origin} to {target}"));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_re_invite_answer_loses_the_named_attributes_in_both_directions() {
    for toward_callee in [true, false] {
        let dispatcher = strip_dispatcher(&STRIP);
        let call_id = answered_call(&dispatcher);
        let marker = if toward_callee {
            "reinvite:a2b"
        } else {
            "reinvite:b2a"
        };
        let branch = track_forwarded(&dispatcher, &call_id, "INVITE", marker, toward_callee);
        let (mut answer, responder, originator) = if toward_callee {
            (
                callee_response(
                    200,
                    "OK",
                    &branch,
                    "2 INVITE",
                    &endpoint_sdp("198.51.100.20"),
                ),
                CALLEE,
                CALLER,
            )
        } else {
            let siphon_tag = siphon_a_leg_tag(&dispatcher, &call_id);
            (
                caller_response(
                    &branch,
                    "2 INVITE",
                    &siphon_tag,
                    &endpoint_sdp("192.0.2.10"),
                ),
                CALLER,
                CALLEE,
            )
        };

        assert!(forward_reinvite_response(
            &call_id,
            &branch,
            &mut answer,
            200,
            address(responder),
            &dispatcher.state,
            &snapshot(&dispatcher, &call_id, &branch),
        ));

        let relayed = response_to(&wire(&dispatcher), originator, 200);
        assert_stripped(
            &relayed,
            &format!("re-INVITE 2xx from {responder} to {originator}"),
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_update_answer_loses_the_named_attributes_in_both_directions() {
    for toward_callee in [true, false] {
        let dispatcher = strip_dispatcher(&STRIP);
        let call_id = answered_call(&dispatcher);
        let marker = if toward_callee {
            "update:a2b"
        } else {
            "update:b2a"
        };
        let branch = track_forwarded(&dispatcher, &call_id, "UPDATE", marker, toward_callee);
        let (mut answer, responder, originator) = if toward_callee {
            (
                callee_response(
                    200,
                    "OK",
                    &branch,
                    "2 UPDATE",
                    &endpoint_sdp("198.51.100.20"),
                ),
                CALLEE,
                CALLER,
            )
        } else {
            let siphon_tag = siphon_a_leg_tag(&dispatcher, &call_id);
            (
                caller_response(
                    &branch,
                    "2 UPDATE",
                    &siphon_tag,
                    &endpoint_sdp("192.0.2.10"),
                ),
                CALLER,
                CALLEE,
            )
        };

        assert!(forward_update_response(
            &call_id,
            &mut answer,
            200,
            address(responder),
            &dispatcher.state,
            &snapshot(&dispatcher, &call_id, &branch),
        ));

        let relayed = response_to(&wire(&dispatcher), originator, 200);
        assert_stripped(
            &relayed,
            &format!("UPDATE 2xx from {responder} to {originator}"),
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_re_invite_siphon_sends_with_the_other_legs_sdp_loses_the_named_attributes() {
    // A transfer's re-anchor, a Replaces takeover and a controller bridge all
    // re-INVITE one leg with SDP another party described.
    for surviving_on_a_leg in [true, false] {
        let dispatcher = strip_dispatcher(&STRIP);
        let call_id = answered_call(&dispatcher);
        let target = if surviving_on_a_leg { CALLER } else { CALLEE };

        b2bua_send_media_reinvite(
            &call_id,
            surviving_on_a_leg,
            endpoint_sdp("203.0.113.40").into_bytes(),
            &dispatcher.state,
        );

        let reinvite = request_to(&wire(&dispatcher), target, Method::Invite);
        assert_stripped(
            &reinvite,
            &format!("siphon-originated re-INVITE to {target}"),
        );
    }
}

// ---------------------------------------------------------------------------
// o= and s= on the paths that carry SDP from elsewhere
// ---------------------------------------------------------------------------

pub(super) const NEWCOMER: &str = "192.0.2.50:5060";
pub(super) const NEWCOMER_CALL_ID: &str = "sdp-strip-newcomer@192.0.2.50";

/// The SDP session id siphon owns toward the caller (`on_a_leg`) or the callee.
pub(super) fn leg_session_id(dispatcher: &TestDispatcher, call_id: &str, on_a_leg: bool) -> u64 {
    dispatcher
        .state
        .call_actors
        .clone_leg(call_id, on_a_leg)
        .map(|leg| leg.dialog.sdp_session_id)
        .expect("the leg")
}

/// A re-INVITE siphon sends with SDP another party described keeps the `o=` that
/// leg has always had from siphon: siphon's owner and address, the leg's own
/// session id at its next version. RFC 3264 §8 lets only the version change, and
/// the other party's address in `o=` was both a leak and a change.
#[tokio::test(flavor = "multi_thread")]
async fn a_re_invite_siphon_sends_with_the_other_legs_sdp_carries_siphons_origin() {
    for surviving_on_a_leg in [true, false] {
        let dispatcher = strip_dispatcher(&[]);
        let call_id = answered_call(&dispatcher);
        let target = if surviving_on_a_leg { CALLER } else { CALLEE };
        let session_id = leg_session_id(&dispatcher, &call_id, surviving_on_a_leg);
        let host = dispatcher
            .state
            .a_leg_advertised_host(None, &Transport::Udp);

        b2bua_send_media_reinvite(
            &call_id,
            surviving_on_a_leg,
            endpoint_sdp("203.0.113.40").into_bytes(),
            &dispatcher.state,
        );

        let reinvite = request_to(&wire(&dispatcher), target, Method::Invite);
        assert_eq!(
            sdp_line(&reinvite, "o="),
            Some(format!("o=siphon {session_id} 0 IN IP4 {host}")),
            "re-INVITE to {target}"
        );
        assert_eq!(
            sdp_line(&reinvite, "s="),
            Some("s=siphon".to_string()),
            "re-INVITE to {target}"
        );
    }
}

/// The INVITE with `Replaces` that takes over the caller's dialog.
pub(super) fn newcomer_invite(body: &str) -> SipMessage {
    parse(&format!(
        concat!(
            "INVITE sip:callee@siphon.example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP 192.0.2.50:5060;branch=z9hG4bK-newcomer\r\n",
            "Max-Forwards: 70\r\n",
            "From: <sip:newcomer@example.com>;tag=newcomer-tag\r\n",
            "To: <sip:callee@siphon.example.com>\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: 1 INVITE\r\n",
            "Contact: <sip:newcomer@192.0.2.50:5060>\r\n",
            "Replaces: {replaced};to-tag=siphon-a-tag;from-tag={caller_tag}\r\n",
            "Content-Type: application/sdp\r\n",
            "Content-Length: {length}\r\n",
            "\r\n",
            "{body}",
        ),
        call_id = NEWCOMER_CALL_ID,
        replaced = A_LEG_CALL_ID,
        caller_tag = CALLER_TAG,
        length = body.len(),
        body = body,
    ))
}

/// The 200 that accepts a `Replaces` takeover (RFC 3891) hands the newcomer the
/// survivor's SDP, so it gets the hiding every relayed answer gets: siphon's
/// `s=`, an `o=` with siphon's owner and address and the newcomer leg's own
/// session id at its first version (RFC 3264 §8), and the attributes stripped.
/// Driven through the takeover itself, reading the 200 off the wire.
#[tokio::test(flavor = "multi_thread")]
async fn the_200_to_a_replaces_newcomer_hides_the_survivors_sdp() {
    let dispatcher = strip_dispatcher(&STRIP);
    let state = &dispatcher.state;
    let replaced_call_id = answered_call(&dispatcher);
    state.call_actors.set_leg_last_sdp(
        &replaced_call_id,
        false,
        endpoint_sdp("198.51.100.20").as_bytes(),
    );
    let newcomer_leg = Leg::new_a_leg(
        NEWCOMER_CALL_ID.to_string(),
        "newcomer-tag".to_string(),
        "z9hG4bK-newcomer".to_string(),
        udp_transport(NEWCOMER),
    );
    let session_id = newcomer_leg.dialog.sdp_session_id;
    let new_call_id = state.call_actors.create_call(newcomer_leg);
    let invite = newcomer_invite(&endpoint_sdp("192.0.2.50"));
    state.call_actors.set_a_leg_invite(
        &new_call_id,
        Arc::new(std::sync::Mutex::new(invite.clone())),
    );
    let inbound = inbound_from(NEWCOMER);
    let pending = crate::b2bua::actor::PendingReplaces {
        replaced_call_id: replaced_call_id.clone(),
        replaced_on_a_leg: true,
        early_only: false,
    };

    b2bua_bridge_inbound_replaces(&inbound, &invite, &new_call_id, &pending, state);

    let accepted = response_to(&wire(&dispatcher), NEWCOMER, 200);
    let host = state.a_leg_advertised_host(Some(inbound.local_addr), &inbound.transport);
    assert_eq!(
        sdp_line(&accepted, "o="),
        Some(format!("o=siphon {session_id} 0 IN IP4 {host}"))
    );
    assert_eq!(sdp_line(&accepted, "s="), Some("s=siphon".to_string()));
    assert_stripped(&accepted, "200 to the Replaces newcomer");
    assert_eq!(
        state
            .call_actors
            .reserve_leg_sdp_version(&replaced_call_id, true),
        Some((session_id, 1)),
        "the newcomer's next SDP does not go on from the version it was answered with"
    );
}

// ---------------------------------------------------------------------------
// Order against the media engine
// ---------------------------------------------------------------------------

/// A media engine that answers one NG command with `returned_sdp`, and hands
/// the test the SDP it was sent.
async fn fake_media_engine(returned_sdp: String) -> (SocketAddr, tokio::task::JoinHandle<String>) {
    use crate::rtpengine::bencode::{self, BencodeValue};

    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("a loopback socket");
    let engine_address = socket.local_addr().expect("a bound address");
    let task = tokio::spawn(async move {
        let mut buffer = vec![0u8; 65535];
        let (size, source) = socket.recv_from(&mut buffer).await.expect("an NG command");
        let datagram = &buffer[..size];
        let space = datagram
            .iter()
            .position(|&byte| byte == b' ')
            .expect("a cookie");
        let command = bencode::decode_full_dict(&datagram[space + 1..]).expect("a bencode dict");
        let offered = command.dict_get_str("sdp").unwrap_or_default().to_string();
        let response = BencodeValue::dict(vec![
            ("result", BencodeValue::string("ok")),
            ("sdp", BencodeValue::string(&returned_sdp)),
        ]);
        let mut reply = datagram[..=space].to_vec();
        reply.extend_from_slice(&bencode::encode(&response));
        socket
            .send_to(&reply, source)
            .await
            .expect("the reply is sent");
        offered
    });
    (engine_address, task)
}

/// The engine is handed the SDP as the peer sent it, and the strip runs on what
/// the engine hands back: an attribute the engine carries through or adds never
/// reaches the far party.
#[tokio::test(flavor = "multi_thread")]
async fn the_strip_runs_on_the_sdp_the_media_engine_returns() {
    let mut dispatcher = strip_dispatcher(&STRIP);
    let (engine_address, offered) = fake_media_engine(endpoint_sdp("203.0.113.5")).await;
    let engine = crate::rtpengine::client::RtpEngineSet::new(vec![(engine_address, 2000, 1)])
        .await
        .expect("an engine client");
    dispatcher.state.rtpengine_set = Some(Arc::new(crate::rtpengine::MediaBackend::RtpEngine(
        Arc::new(engine),
    )));
    let sessions = crate::rtpengine::session::MediaSessionStore::new();
    sessions.insert(crate::rtpengine::session::MediaSession {
        call_id: A_LEG_CALL_ID.to_string(),
        rtpengine_call_id: A_LEG_CALL_ID.to_string(),
        from_tag: CALLER_TAG.to_string(),
        to_tag: Some(CALLEE_TAG.to_string()),
        profile: "rtp_passthrough".to_string(),
        ws_uri: None,
        ws_tee: None,
        ws_bridge_attached: false,
        created_at: std::time::Instant::now(),
    });
    dispatcher.state.rtpengine_sessions = Some(Arc::new(sessions));
    dispatcher.state.rtpengine_profiles = Some(Arc::new(crate::rtpengine::ProfileRegistry::new()));
    answered_call(&dispatcher);

    handle_b2bua_reinvite(
        inbound_from(CALLER),
        in_dialog_request("INVITE", true, &endpoint_sdp("192.0.2.10")),
        &dispatcher.state,
    );

    let forwarded = request_to(&wire(&dispatcher), CALLEE, Method::Invite);
    assert_stripped(&forwarded, "anchored re-INVITE to the callee");
    assert!(
        body_text(&forwarded).contains("c=IN IP4 203.0.113.5\r\n"),
        "the engine's SDP is not what crossed:\n{}",
        body_text(&forwarded)
    );
    let engine_saw = offered.await.expect("the engine was sent an offer");
    assert!(
        engine_saw.contains("a=MSID:stream-a track-a\r\n") && engine_saw.contains("a=x-hidden\r\n"),
        "the engine was not handed the caller's SDP as sent:\n{engine_saw}"
    );
}
