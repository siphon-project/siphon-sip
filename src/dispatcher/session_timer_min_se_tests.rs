//! RFC 4028 §9: a request for a session interval shorter than siphon's minimum is
//! refused with 422 (Session Interval Too Small) and siphon's minimum in `Min-SE`,
//! where the requester supports the extension, instead of being accepted at an
//! interval siphon's own refreshes then raise.
//!
//! siphon is the UAS of that request on the caller's dialog of every call, and on
//! whichever dialog an in-dialog refresh arrives. Its minimum is the `min_se` of
//! the session timer it runs on the call, configured or the script's. A requester
//! that does not support the extension cannot act on a 422, so its request is
//! taken as §9 allows.

use super::sdp_strip_tests::{
    address, answered_call, caller_call, caller_invite, endpoint_sdp, in_dialog_request,
    inbound_from, response_to, A_LEG_CALL_ID, CALLEE, CALLER,
};
use super::session_timer_tests::{requests, wire};
use super::test_dispatcher::{test_dispatcher_with_script, TestDispatcher};
use super::*;

/// Dials the callee for every call.
const DIAL_THE_CALLEE: &str = r#"
from siphon import b2bua

@b2bua.on_invite
def route(call):
    call.dial("sip:callee@198.51.100.20:5060")
"#;

/// Dials the callee with a session timer of the script's own, whose minimum is
/// 300 s.
const DIAL_WITH_A_300_SECOND_MINIMUM: &str = r#"
from siphon import b2bua

@b2bua.on_invite
def route(call):
    call.session_timer(expires=1800, min_se=300, refresher="uac")
    call.dial("sip:callee@198.51.100.20:5060")
"#;

/// Hands every call over to a control app.
const HAND_OVER: &str = r#"
from siphon import b2bua

@b2bua.on_invite
def route(call):
    call.handover("ivr")
"#;

/// A `session_timer:` block whose minimum is 300 s.
const MINIMUM_300: &str = "session_expires: 1800\nmin_se: 300\n";

/// A dispatcher running `script`, with `config` as its `session_timer:` block.
fn dispatcher_with(script: &str, config: Option<&str>) -> TestDispatcher {
    let mut dispatcher = test_dispatcher_with_script(script);
    dispatcher.state.session_timer_config =
        config.map(|yaml| serde_yaml_ng::from_str(yaml).expect("a session timer config"));
    dispatcher
}

/// The caller's INVITE, carrying `headers` besides its offer.
fn invite_with(headers: &[(&str, &str)]) -> SipMessage {
    let mut invite = caller_invite(&endpoint_sdp("192.0.2.10"));
    for (name, value) in headers {
        invite.headers.set(name, value.to_string());
    }
    invite
}

/// The 422 `peer` was sent, naming `min_se` as siphon's minimum.
fn assert_refused_too_brief(
    sent: &[(SocketAddr, SipMessage)],
    peer: &str,
    min_se: &str,
    context: &str,
) {
    let refusal = response_to(sent, peer, 422);
    assert_eq!(
        refusal.headers.get("Min-SE").map(String::as_str),
        Some(min_se),
        "{context}: the 422 does not carry siphon's minimum"
    );
    assert!(
        refusal.headers.to().is_some_and(|to| to.contains(";tag=")),
        "{context}: the 422 has no To tag"
    );
}

/// Whether siphon sent `peer` a response with `status_code`.
fn answered_with(sent: &[(SocketAddr, SipMessage)], peer: &str, status_code: u16) -> bool {
    sent.iter()
        .any(|(to, message)| *to == address(peer) && message.status_code() == Some(status_code))
}

/// A caller that supports the extension and asks for an interval below siphon's
/// minimum, the configured one or the script's, is refused with 422 and that
/// minimum before the call goes anywhere, dialled or handed over, and the call is
/// gone.
#[tokio::test(flavor = "multi_thread")]
async fn a_caller_asking_for_less_than_siphons_minimum_is_refused_before_the_call_goes_anywhere() {
    for (script, config) in [
        (DIAL_THE_CALLEE, Some(MINIMUM_300)),
        (DIAL_WITH_A_300_SECOND_MINIMUM, None),
        (HAND_OVER, Some(MINIMUM_300)),
    ] {
        let dispatcher = dispatcher_with(script, config);
        let _ = wire(&dispatcher);

        handle_b2bua_invite(
            inbound_from(CALLER),
            invite_with(&[("Supported", "timer"), ("Session-Expires", "120")]),
            &dispatcher.state,
        );

        let sent = wire(&dispatcher);
        let context = format!("{script} with config {config:?}");
        assert_refused_too_brief(&sent, CALLER, "300", &context);
        assert!(
            sent.iter()
                .filter(|(to, _)| *to == address(CALLER))
                .all(|(_, message)| matches!(message.status_code(), Some(100) | Some(422))),
            "{context}: the caller was sent more than the 422"
        );
        assert!(
            requests(&sent, CALLEE, Method::Invite).is_empty(),
            "{context}: the callee was dialled"
        );
        assert!(
            dispatcher
                .state
                .call_actors
                .find_by_sip_call_id(A_LEG_CALL_ID)
                .is_none(),
            "{context}: the refused call is still up"
        );
    }
}

/// §9 lets siphon refuse only a requester that supports the extension, and only
/// an interval below its minimum. A caller without timer support, one asking for
/// the minimum itself, and one asking for no timer at all are dialled.
#[tokio::test(flavor = "multi_thread")]
async fn only_a_supporting_caller_asking_below_the_minimum_is_refused() {
    let callers: [&[(&str, &str)]; 3] = [
        &[("Session-Expires", "120")],
        &[("Supported", "timer"), ("Session-Expires", "300")],
        &[("Supported", "timer")],
    ];
    for caller in callers {
        let dispatcher = dispatcher_with(DIAL_THE_CALLEE, Some(MINIMUM_300));
        let _ = wire(&dispatcher);

        handle_b2bua_invite(inbound_from(CALLER), invite_with(caller), &dispatcher.state);

        let sent = wire(&dispatcher);
        assert!(!answered_with(&sent, CALLER, 422), "{caller:?} was refused");
        assert_eq!(
            requests(&sent, CALLEE, Method::Invite).len(),
            1,
            "{caller:?} was not dialled"
        );
    }
}

/// An answer siphon gives the caller itself refuses an interval below siphon's
/// minimum the same way: the caller gets the 422, never a 2xx, and the call is
/// gone.
#[tokio::test(flavor = "multi_thread")]
async fn an_answer_siphon_gives_itself_refuses_an_interval_below_its_minimum() {
    let dispatcher = dispatcher_with("", Some(MINIMUM_300));
    let call_id = caller_call(&dispatcher);
    let _ = wire(&dispatcher);

    let answered = send_uas_response(
        &dispatcher.state,
        &call_id,
        &invite_with(&[("Supported", "timer"), ("Session-Expires", "120")]),
        200,
        "OK",
        Some(endpoint_sdp("203.0.113.70").into_bytes()),
        Some("application/sdp"),
        true,
    );

    assert!(!answered, "the refused answer was reported as sent");
    let sent = wire(&dispatcher);
    assert_refused_too_brief(&sent, CALLER, "300", "call.answer()");
    assert!(
        !answered_with(&sent, CALLER, 200),
        "the caller was answered 2xx"
    );
    assert!(dispatcher.state.call_actors.get_call(&call_id).is_none());
}

/// A session refresh on an established call asking for an interval below
/// siphon's minimum is refused with 422 and that minimum, and is not relayed: a
/// re-INVITE and an UPDATE, from either party of a call with a callee and from
/// the caller of one siphon answered itself. The call stays up.
#[tokio::test(flavor = "multi_thread")]
async fn a_refresh_asking_for_less_than_siphons_minimum_is_refused_and_not_relayed() {
    for method in ["INVITE", "UPDATE"] {
        for (with_callee, from_caller) in [(true, true), (true, false), (false, true)] {
            let dispatcher = dispatcher_with("", Some(MINIMUM_300));
            let call_id = if with_callee {
                answered_call(&dispatcher)
            } else {
                caller_call(&dispatcher)
            };
            let (sender, other) = if from_caller {
                (CALLER, CALLEE)
            } else {
                (CALLEE, CALLER)
            };
            let mut refresh = in_dialog_request(method, from_caller, &endpoint_sdp("192.0.2.10"));
            refresh.headers.set("Supported", "timer".to_string());
            refresh.headers.set("Session-Expires", "120".to_string());
            let _ = wire(&dispatcher);

            if method == "INVITE" {
                handle_b2bua_reinvite(inbound_from(sender), refresh, &dispatcher.state);
            } else {
                handle_b2bua_update(inbound_from(sender), refresh, &dispatcher.state);
            }

            let sent = wire(&dispatcher);
            let context = format!("{method} from {sender}, with a callee: {with_callee}");
            assert_refused_too_brief(&sent, sender, "300", &context);
            assert!(
                sent.iter().all(|(to, _)| *to != address(other)),
                "{context}: the refresh was relayed"
            );
            assert!(
                !answered_with(&sent, sender, 200),
                "{context}: answered 2xx"
            );
            assert!(dispatcher.state.call_actors.get_call(&call_id).is_some());
        }
    }
}
