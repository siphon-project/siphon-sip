//! `request.reply()` from `@proxy.on_failure`: the handler answers the caller
//! itself instead of passing the failure on, with the headers and body it set
//! (`request.set_reply_header()`, `request.set_reply_body()`).
//!
//! The case that needs it: an IMS edge proxy whose next hop does not answer
//! returns 504 with a 3GPP IM CN subsystem XML body, so the UE registers again
//! (TS 24.229 §5.2.6.3.2A). The `408` of the timed-out branch must not reach
//! the UE, and neither may silence.

use super::proxy_cancel_awaits_provisional_tests::{
    answers, call, fire, forking_proxy, relaying_proxy, CALLER, FAILED, RINGING, SILENT,
};
use super::proxy_dialog_state_tests::Sent;
use super::*;

const BODY: &str = "<ims-3gpp version=\"1\"><alternative-service><type>restoration</type>\
                    </alternative-service></ims-3gpp>";

/// An on_failure handler that answers every failure with `code`, a header and
/// the XML body.
fn replying_handler(code: u16, reason: &str) -> String {
    format!(
        concat!(
            "@proxy.on_failure\n",
            "def failed(request, reply):\n",
            "    request.set_reply_header(\"P-Asserted-Identity\", \"<sip:edge@example.com>\")\n",
            "    request.set_reply_body('{body}', \"application/3gpp-ims+xml\")\n",
            "    request.reply({code}, \"{reason}\")\n",
        ),
        body = BODY,
        code = code,
        reason = reason,
    )
}

/// The final responses the caller was sent, whole.
fn finals_to_caller(sent: &[Sent]) -> Vec<SipMessage> {
    sent.iter()
        .filter(|sent| sent.destination == CALLER)
        .filter(|sent| sent.message.status_code().is_some_and(|code| code >= 200))
        .map(|sent| sent.message.clone())
        .collect()
}

fn assert_the_scripts_reply(sent: &[Sent], code: u16, call_id: &str) {
    let finals = finals_to_caller(sent);
    assert_eq!(
        finals.len(),
        1,
        "one final response, the script's: {finals:?}"
    );
    let response = &finals[0];
    assert_eq!(response.status_code(), Some(code));
    assert_eq!(
        response
            .headers
            .get("P-Asserted-Identity")
            .map(String::as_str),
        Some("<sip:edge@example.com>")
    );
    assert_eq!(
        response.headers.get("Content-Type").map(String::as_str),
        Some("application/3gpp-ims+xml")
    );
    assert_eq!(response.body, BODY.as_bytes());
    assert_eq!(
        response.headers.call_id().map(String::as_str),
        Some(call_id)
    );
    // The caller's own Via, not the one this proxy put on the branch.
    let via = response.headers.get("Via").cloned().unwrap_or_default();
    assert!(via.contains(CALLER), "Via {via}");
}

/// A branch that never answers times out as a 408 the handler replaces with
/// its 504.
#[tokio::test(flavor = "multi_thread")]
async fn a_timed_out_branch_is_answered_with_the_handlers_reply() {
    let proxy = relaying_proxy(SILENT, &replying_handler(504, "Server Time-out"));
    let (_, branches) = call(&proxy, "failure-reply-timeout@example.com");
    let (_, to_silent) = &branches[0];

    fire(&proxy, to_silent, TimerName::B);
    assert_the_scripts_reply(&proxy.wire(), 504, "failure-reply-timeout@example.com");
}

/// A failure the next hop sent is replaced the same way.
#[tokio::test(flavor = "multi_thread")]
async fn a_branchs_failure_is_replaced_by_the_handlers_reply() {
    let proxy = relaying_proxy(FAILED, &replying_handler(480, "Temporarily Unavailable"));
    let (_, branches) = call(&proxy, "failure-reply-486@example.com");
    let (_, to_failed) = &branches[0];

    answers(&proxy, FAILED, to_failed, 486, "Busy Here");
    assert_the_scripts_reply(&proxy.wire(), 480, "failure-reply-486@example.com");
}

/// A fork whose every branch failed: the handler's reply instead of the best
/// failure.
#[tokio::test(flavor = "multi_thread")]
async fn a_failed_fork_is_answered_with_the_handlers_reply() {
    let proxy = forking_proxy(
        &[FAILED, RINGING],
        "parallel",
        &replying_handler(504, "Server Time-out"),
    );
    let (_, branches) = call(&proxy, "failure-reply-fork@example.com");
    for (target, branch) in &branches {
        answers(&proxy, target, branch, 486, "Busy Here");
    }
    assert_the_scripts_reply(&proxy.wire(), 504, "failure-reply-fork@example.com");
}

/// The 503 a script chooses is its own answer, not a downstream failure the
/// proxy forwards (RFC 3261 §16.7 step 6 turns only those into 500).
#[tokio::test(flavor = "multi_thread")]
async fn a_503_the_handler_replies_is_not_turned_into_500() {
    let proxy = relaying_proxy(FAILED, &replying_handler(503, "Service Unavailable"));
    let (_, branches) = call(&proxy, "failure-reply-503@example.com");
    let (_, to_failed) = &branches[0];

    answers(&proxy, FAILED, to_failed, 486, "Busy Here");
    assert_the_scripts_reply(&proxy.wire(), 503, "failure-reply-503@example.com");
}
