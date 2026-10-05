//! RFC 3261 §9.1 on the proxy path: a branch is sent its CANCEL once its
//! INVITE has drawn a provisional response and before it has a final one.
//!
//! "If no provisional response has been received, the CANCEL request MUST NOT
//! be sent; rather, the client MUST wait for the arrival of a provisional
//! response before sending the request." §16.10 and §16.7 step 10 have a proxy
//! CANCEL its *pending* client transactions, which is the same set.
//!
//! Every reason the proxy has to CANCEL a branch is driven here through the
//! dispatcher's own entry points, on the proxy harness of
//! [`super::proxy_dialog_state_tests`]: another fork branch answering 2xx or
//! 6xx, `reply.reject()`, and the caller's own CANCEL. Each is checked against
//! a branch that rang (CANCELled at once), a branch that has sent nothing (not
//! CANCELled, its INVITE still retransmitting, until its first provisional),
//! and a branch that already failed (never CANCELled); and a silent branch is
//! followed to each of its ends: a provisional, a 2xx, a failure, Timer B.

use std::sync::Barrier;
use std::time::Instant;

use super::proxy_dialog_state_tests::{
    find, header, inbound, invite, invites_by_destination, response_to, Proxy, Sent,
};
use super::test_dispatcher::test_dispatcher_with_script;
use super::*;

pub(super) const CALLER: &str = "192.0.2.50:5060";
pub(super) const RINGING: &str = "198.51.100.11:5060";
pub(super) const SILENT: &str = "198.51.100.12:5060";
pub(super) const FAILED: &str = "198.51.100.13:5060";
pub(super) const DECIDING: &str = "198.51.100.14:5060";

/// A proxy that forks every INVITE to `targets` and runs `handlers` beside it.
pub(super) fn forking_proxy(targets: &[&str], strategy: &str, handlers: &str) -> Proxy {
    let uris: Vec<String> = targets
        .iter()
        .map(|target| format!("\"sip:callee@{target}\""))
        .collect();
    let script = format!(
        concat!(
            "from siphon import proxy\n",
            "\n",
            "@proxy.on_request\n",
            "def route(request):\n",
            "    request.fork([{uris}], strategy=\"{strategy}\")\n",
            "\n",
            "{handlers}",
        ),
        uris = uris.join(", "),
        strategy = strategy,
        handlers = handlers,
    );
    let dispatcher = test_dispatcher_with_script(&script);
    Proxy {
        state: Arc::new(dispatcher.state),
        udp: dispatcher.udp,
    }
}

/// A proxy that relays every INVITE to `target` and runs `handlers` beside it.
pub(super) fn relaying_proxy(target: &str, handlers: &str) -> Proxy {
    let script = format!(
        concat!(
            "from siphon import proxy\n",
            "\n",
            "@proxy.on_request\n",
            "def route(request):\n",
            "    request.relay(\"sip:callee@{target}\")\n",
            "\n",
            "{handlers}",
        ),
        target = target,
        handlers = handlers,
    );
    let dispatcher = test_dispatcher_with_script(&script);
    Proxy {
        state: Arc::new(dispatcher.state),
        udp: dispatcher.udp,
    }
}

/// `@proxy.on_reply` failing the INVITE on a `183`, as a media-authorization
/// failure at answer time does.
pub(super) const REJECT_ON_183: &str = concat!(
    "@proxy.on_reply\n",
    "def answered(request, reply):\n",
    "    if reply.status_code == 183:\n",
    "        reply.reject(503, \"Service Unavailable\")\n",
    "        return\n",
    "    reply.relay()\n",
);

pub(super) fn caller_invite(call_id: &str) -> String {
    invite(
        CALLER,
        call_id,
        "<sip:caller@example.com>;tag=caller-tag",
        "sip:callee@example.com",
    )
}

/// The caller sends its INVITE; returns it and what the proxy sent each target.
pub(super) fn call(proxy: &Proxy, call_id: &str) -> (String, Vec<(String, SipMessage)>) {
    let raw = caller_invite(call_id);
    proxy.request(CALLER, &raw);
    (raw, invites_by_destination(&proxy.wire()))
}

/// The caller's CANCEL for the INVITE it sent as `raw`.
pub(super) fn caller_cancels(proxy: &Proxy, raw: &str) {
    let cancel = raw
        .replacen("INVITE", "CANCEL", 1)
        .replace("CSeq: 5 INVITE", "CSeq: 5 CANCEL")
        .replace(&format!("Contact: <sip:phone@{CALLER}>\r\n"), "");
    proxy.request(CALLER, &cancel);
}

/// `target` answers `request`, the INVITE or the CANCEL it was sent.
pub(super) fn answers(
    proxy: &Proxy,
    target: &str,
    request: &SipMessage,
    status_code: u16,
    reason: &str,
) {
    let tag = format!("tag-{}", target.replace(['.', ':'], "-"));
    proxy.response(
        target,
        response_to(
            request,
            status_code,
            reason,
            &tag,
            &format!("sip:callee@{target}"),
            "",
        ),
    );
}

pub(super) fn requests_to(sent: &[Sent], destination: &str, method: Method) -> Vec<SipMessage> {
    sent.iter()
        .filter(|sent| sent.destination == destination && sent.message.method() == Some(&method))
        .map(|sent| sent.message.clone())
        .collect()
}

pub(super) fn cancels_to(sent: &[Sent], destination: &str) -> Vec<SipMessage> {
    requests_to(sent, destination, Method::Cancel)
}

/// The final and ringing responses the caller was sent (a `100` is the
/// proxy's own and is not what these tests are about).
pub(super) fn responses_to_caller(sent: &[Sent]) -> Vec<u16> {
    sent.iter()
        .filter(|sent| sent.destination == CALLER)
        .filter_map(|sent| sent.message.status_code())
        .filter(|status_code| *status_code != 100)
        .collect()
}

pub(super) fn branch_of(message: &SipMessage) -> String {
    TransactionManager::key_from_message(message)
        .expect("a Via branch")
        .branch
}

/// The one CANCEL `target` was sent among `sent`, checked against the INVITE
/// it cancels. RFC 3261 §9.1: the same Request-URI, Call-ID, To, From, CSeq
/// number and Route, and a single Via equal to the INVITE's top Via.
pub(super) fn the_cancel(sent: &[Sent], target: &str, branch_invite: &SipMessage) -> SipMessage {
    let cancels = cancels_to(sent, target);
    assert_eq!(cancels.len(), 1, "exactly one CANCEL to {target}");
    let cancel = cancels[0].clone();
    let request_uri = |message: &SipMessage| match &message.start_line {
        StartLine::Request(request_line) => request_line.request_uri.to_string(),
        StartLine::Response(_) => panic!("a request"),
    };
    assert_eq!(
        request_uri(&cancel),
        request_uri(branch_invite),
        "the Request-URI of the INVITE on this branch"
    );
    let invite_vias = branch_invite
        .headers
        .get_all("Via")
        .cloned()
        .unwrap_or_default();
    assert_eq!(
        cancel.headers.get_all("Via").cloned().unwrap_or_default(),
        invite_vias[..1],
        "one Via, the INVITE's top Via"
    );
    assert_eq!(header(&cancel, "CSeq"), "5 CANCEL");
    for name in ["Call-ID", "From", "To", "Max-Forwards"] {
        assert_eq!(header(&cancel, name), header(branch_invite, name), "{name}");
    }
    assert_eq!(
        cancel.headers.get_all("Route"),
        branch_invite.headers.get_all("Route"),
        "the INVITE's Route set"
    );
    assert!(cancel.headers.get("Contact").is_none());
    assert!(cancel.body.is_empty());
    cancel
}

/// Make timer `name` of the INVITE client transaction that sent `branch_invite`
/// due, and fire what is due.
pub(super) fn fire(proxy: &Proxy, branch_invite: &SipMessage, name: TimerName) {
    let key = TransactionManager::key_from_message(branch_invite).expect("a transaction key");
    let timer_id = format!("{}:{:?}", key, name);
    proxy
        .state
        .timer_wheel
        .get_mut(&timer_id)
        .unwrap_or_else(|| panic!("no timer {timer_id}"))
        .fires_at = Instant::now();
    tokio::task::block_in_place(|| fire_expired_timers(&proxy.state));
}

pub(super) fn waiting_cancels(proxy: &Proxy) -> usize {
    proxy.state.transaction_manager.waiting_cancel_count()
}

/// The INVITE of a silent branch is still an unanswered request: Timer A
/// retransmits it, and no CANCEL goes with it.
fn assert_still_retransmitting(proxy: &Proxy, target: &str, branch_invite: &SipMessage) {
    fire(proxy, branch_invite, TimerName::A);
    let sent = proxy.wire();
    let retransmitted = requests_to(&sent, target, Method::Invite);
    assert_eq!(retransmitted.len(), 1, "the INVITE is retransmitted");
    assert_eq!(branch_of(&retransmitted[0]), branch_of(branch_invite));
    assert!(cancels_to(&sent, target).is_empty());
}

/// A provisional from a branch whose CANCEL waited: the CANCEL goes, its 487
/// is ACKed, and the caller is sent nothing of it.
fn assert_provisional_draws_the_cancel(
    proxy: &Proxy,
    target: &str,
    branch_invite: &SipMessage,
    status_code: u16,
    reason: &str,
) {
    answers(proxy, target, branch_invite, status_code, reason);
    let sent = proxy.wire();
    let cancel = the_cancel(&sent, target, branch_invite);
    assert!(
        responses_to_caller(&sent).is_empty(),
        "nothing of it reaches the caller: {:?}",
        responses_to_caller(&sent)
    );
    assert_eq!(waiting_cancels(proxy), 0);

    // A second provisional sends no second CANCEL.
    answers(proxy, target, branch_invite, 180, "Ringing");
    assert!(cancels_to(&proxy.wire(), target).is_empty());

    answers(proxy, target, &cancel, 200, "OK");
    answers(proxy, target, branch_invite, 487, "Request Terminated");
    let sent = proxy.wire();
    assert!(
        !requests_to(&sent, target, Method::Ack).is_empty(),
        "the 487 is ACKed"
    );
    assert!(cancels_to(&sent, target).is_empty());
    assert!(
        responses_to_caller(&sent).is_empty(),
        "the 487 is not forwarded: {:?}",
        responses_to_caller(&sent)
    );
}

// ---------------------------------------------------------------------------
// Another branch settles the fork: a 2xx, or a 6xx
// ---------------------------------------------------------------------------

/// A parallel fork of four. One branch rings, one has sent nothing, one has
/// failed, and then the fourth settles the fork with `deciding_status`.
/// Returns the proxy and the INVITE sent to the silent branch.
fn fork_settled(call_id: &str, deciding_status: u16, reason: &str) -> (Proxy, SipMessage) {
    let proxy = forking_proxy(&[RINGING, SILENT, FAILED, DECIDING], "parallel", "");
    let (_, invites) = call(&proxy, call_id);
    let (to_ringing, to_silent, to_failed, to_deciding) = (
        find(&invites, RINGING).clone(),
        find(&invites, SILENT).clone(),
        find(&invites, FAILED).clone(),
        find(&invites, DECIDING).clone(),
    );
    answers(&proxy, RINGING, &to_ringing, 180, "Ringing");
    answers(&proxy, FAILED, &to_failed, 486, "Busy Here");
    let _ = proxy.wire();

    answers(&proxy, DECIDING, &to_deciding, deciding_status, reason);
    let sent = proxy.wire();
    assert_eq!(responses_to_caller(&sent), [deciding_status]);
    the_cancel(&sent, RINGING, &to_ringing);
    assert!(
        cancels_to(&sent, SILENT).is_empty(),
        "RFC 3261 §9.1: no CANCEL for an INVITE with no provisional"
    );
    assert!(
        cancels_to(&sent, FAILED).is_empty(),
        "RFC 3261 §9.1: no CANCEL for an INVITE with its final response"
    );
    assert!(cancels_to(&sent, DECIDING).is_empty());
    assert_eq!(waiting_cancels(&proxy), 1);
    (proxy, to_silent)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_fork_won_by_a_2xx_cancels_a_silent_branch_on_its_first_provisional() {
    let (proxy, to_silent) = fork_settled("fork-2xx-100@example.com", 200, "OK");
    assert_still_retransmitting(&proxy, SILENT, &to_silent);
    assert_provisional_draws_the_cancel(&proxy, SILENT, &to_silent, 100, "Trying");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_fork_won_by_a_2xx_cancels_a_silent_branch_when_it_starts_ringing() {
    let (proxy, to_silent) = fork_settled("fork-2xx-180@example.com", 200, "OK");
    assert_provisional_draws_the_cancel(&proxy, SILENT, &to_silent, 180, "Ringing");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_fork_ended_by_a_6xx_cancels_a_silent_branch_on_its_first_provisional() {
    let (proxy, to_silent) = fork_settled("fork-6xx-100@example.com", 603, "Decline");
    assert_still_retransmitting(&proxy, SILENT, &to_silent);
    assert_provisional_draws_the_cancel(&proxy, SILENT, &to_silent, 100, "Trying");
}

/// The silent branch of a settled fork answers 2xx without ever sending a
/// provisional: its INVITE has a final response, so no CANCEL is sent, and the
/// 2xx goes to the caller, who alone can release that dialog (RFC 3261 §16.7
/// step 5; followed through in [`super::proxy_late_answer_tests`]).
#[tokio::test(flavor = "multi_thread")]
async fn a_silent_branch_of_a_settled_fork_that_answers_is_not_cancelled() {
    for (call_id, deciding_status, reason) in [
        ("fork-2xx-late-200@example.com", 200, "OK"),
        ("fork-6xx-late-200@example.com", 603, "Decline"),
    ] {
        let (proxy, to_silent) = fork_settled(call_id, deciding_status, reason);
        answers(&proxy, SILENT, &to_silent, 200, "OK");
        let sent = proxy.wire();
        assert!(cancels_to(&sent, SILENT).is_empty());
        assert_eq!(responses_to_caller(&sent), [200]);
        assert_eq!(waiting_cancels(&proxy), 0);
    }
}

/// The silent branch of a settled fork fails: ACKed, and nothing else.
#[tokio::test(flavor = "multi_thread")]
async fn a_silent_branch_of_a_settled_fork_that_fails_is_acked_and_not_cancelled() {
    let (proxy, to_silent) = fork_settled("fork-2xx-late-486@example.com", 200, "OK");
    answers(&proxy, SILENT, &to_silent, 486, "Busy Here");
    let sent = proxy.wire();
    assert!(!requests_to(&sent, SILENT, Method::Ack).is_empty());
    assert!(cancels_to(&sent, SILENT).is_empty());
    assert!(responses_to_caller(&sent).is_empty());
    assert_eq!(waiting_cancels(&proxy), 0);

    // Nor does anything that comes after the final response draw one.
    answers(&proxy, SILENT, &to_silent, 180, "Ringing");
    assert!(cancels_to(&proxy.wire(), SILENT).is_empty());
}

/// The silent branch of a settled fork never responds: Timer B ends its
/// INVITE, and the CANCEL that waited is never sent.
#[tokio::test(flavor = "multi_thread")]
async fn a_silent_branch_of_a_settled_fork_that_times_out_is_never_cancelled() {
    let (proxy, to_silent) = fork_settled("fork-2xx-timer-b@example.com", 200, "OK");
    let client_key = TransactionManager::key_from_message(&to_silent).expect("a key");
    fire(&proxy, &to_silent, TimerName::B);
    let sent = proxy.wire();
    assert!(cancels_to(&sent, SILENT).is_empty());
    assert!(responses_to_caller(&sent).is_empty());
    assert_eq!(waiting_cancels(&proxy), 0);
    assert!(!proxy.state.transaction_manager.contains(&client_key));

    // A response after the timeout matches no transaction and draws nothing.
    answers(&proxy, SILENT, &to_silent, 180, "Ringing");
    assert!(cancels_to(&proxy.wire(), SILENT).is_empty());
}

// ---------------------------------------------------------------------------
// reply.reject()
// ---------------------------------------------------------------------------

/// `reply.reject()` on one branch's `183` fails the INVITE and CANCELs that
/// branch at once; the branch that has sent nothing is CANCELled when it does.
#[tokio::test(flavor = "multi_thread")]
async fn a_reply_time_reject_cancels_a_silent_branch_on_its_first_provisional() {
    let proxy = forking_proxy(&[RINGING, SILENT], "parallel", REJECT_ON_183);
    let (_, invites) = call(&proxy, "reject-fork@example.com");
    let (to_ringing, to_silent) = (
        find(&invites, RINGING).clone(),
        find(&invites, SILENT).clone(),
    );
    answers(&proxy, RINGING, &to_ringing, 183, "Session Progress");
    let sent = proxy.wire();
    assert_eq!(responses_to_caller(&sent), [503]);
    the_cancel(&sent, RINGING, &to_ringing);
    assert!(cancels_to(&sent, SILENT).is_empty());
    assert_eq!(waiting_cancels(&proxy), 1);

    assert_still_retransmitting(&proxy, SILENT, &to_silent);
    assert_provisional_draws_the_cancel(&proxy, SILENT, &to_silent, 100, "Trying");
}

/// The branch a reject left waiting answers 2xx, fails, or never responds.
#[tokio::test(flavor = "multi_thread")]
async fn a_silent_branch_of_a_rejected_invite_is_not_cancelled_once_it_has_its_final_response() {
    for (call_id, ending) in [
        ("reject-late-200@example.com", Some((200, "OK"))),
        ("reject-late-486@example.com", Some((486, "Busy Here"))),
        ("reject-timer-b@example.com", None),
    ] {
        let proxy = forking_proxy(&[RINGING, SILENT], "parallel", REJECT_ON_183);
        let (_, invites) = call(&proxy, call_id);
        let (to_ringing, to_silent) = (
            find(&invites, RINGING).clone(),
            find(&invites, SILENT).clone(),
        );
        answers(&proxy, RINGING, &to_ringing, 183, "Session Progress");
        let _ = proxy.wire();
        assert_eq!(waiting_cancels(&proxy), 1, "{call_id}");

        match ending {
            Some((status_code, reason)) => answers(&proxy, SILENT, &to_silent, status_code, reason),
            None => fire(&proxy, &to_silent, TimerName::B),
        }
        let sent = proxy.wire();
        assert!(cancels_to(&sent, SILENT).is_empty(), "{call_id}");
        // A 2xx is the caller's to release (RFC 3261 §16.7 step 5); nothing
        // else reaches a caller that already has its final response.
        let forwarded: &[u16] = match ending {
            Some((200, _)) => &[200],
            _ => &[],
        };
        assert_eq!(responses_to_caller(&sent), forwarded, "{call_id}");
        if ending.is_some_and(|(status_code, _)| status_code >= 300) {
            assert!(!requests_to(&sent, SILENT, Method::Ack).is_empty());
        }
        assert_eq!(waiting_cancels(&proxy), 0, "{call_id}");
    }
}

/// The caller CANCELs an INVITE a reject has already failed. Each branch is
/// still owed one CANCEL and no more: the one sent by the reject is not sent
/// again, and the silent branch still waits for its provisional.
#[tokio::test(flavor = "multi_thread")]
async fn a_branch_cancelled_by_a_reject_is_not_cancelled_again_by_the_caller() {
    let proxy = forking_proxy(&[RINGING, SILENT], "parallel", REJECT_ON_183);
    let (raw, invites) = call(&proxy, "reject-then-cancel@example.com");
    let (to_ringing, to_silent) = (
        find(&invites, RINGING).clone(),
        find(&invites, SILENT).clone(),
    );
    answers(&proxy, RINGING, &to_ringing, 183, "Session Progress");
    the_cancel(&proxy.wire(), RINGING, &to_ringing);

    caller_cancels(&proxy, &raw);
    let sent = proxy.wire();
    assert!(
        cancels_to(&sent, RINGING).is_empty(),
        "one CANCEL per INVITE"
    );
    assert!(cancels_to(&sent, SILENT).is_empty());
    assert_eq!(waiting_cancels(&proxy), 1);

    answers(&proxy, SILENT, &to_silent, 180, "Ringing");
    the_cancel(&proxy.wire(), SILENT, &to_silent);
    assert_eq!(waiting_cancels(&proxy), 0);
}

/// A single relay rejected on its `183`: the branch has a provisional, so its
/// CANCEL goes at once.
#[tokio::test(flavor = "multi_thread")]
async fn a_reply_time_reject_cancels_the_branch_that_drew_it_at_once() {
    let proxy = relaying_proxy(RINGING, REJECT_ON_183);
    let (_, invites) = call(&proxy, "reject-relay@example.com");
    let to_ringing = find(&invites, RINGING).clone();
    answers(&proxy, RINGING, &to_ringing, 183, "Session Progress");
    let sent = proxy.wire();
    assert_eq!(responses_to_caller(&sent), [503]);
    the_cancel(&sent, RINGING, &to_ringing);
    assert_eq!(waiting_cancels(&proxy), 0);
}

// ---------------------------------------------------------------------------
// The caller's own CANCEL
// ---------------------------------------------------------------------------

/// A parallel fork of three, one ringing, one silent, one failed, abandoned by
/// the caller. Returns the proxy and the INVITE sent to the silent branch.
fn caller_gave_up(call_id: &str) -> (Proxy, SipMessage) {
    let proxy = forking_proxy(&[RINGING, SILENT, FAILED], "parallel", "");
    let (raw, invites) = call(&proxy, call_id);
    let (to_ringing, to_silent, to_failed) = (
        find(&invites, RINGING).clone(),
        find(&invites, SILENT).clone(),
        find(&invites, FAILED).clone(),
    );
    answers(&proxy, RINGING, &to_ringing, 180, "Ringing");
    answers(&proxy, FAILED, &to_failed, 486, "Busy Here");
    let _ = proxy.wire();

    caller_cancels(&proxy, &raw);
    let sent = proxy.wire();
    assert_eq!(
        responses_to_caller(&sent),
        [200, 487],
        "the caller's CANCEL is answered and its INVITE ended at once"
    );
    the_cancel(&sent, RINGING, &to_ringing);
    assert!(
        cancels_to(&sent, SILENT).is_empty(),
        "RFC 3261 §9.1: no CANCEL for an INVITE with no provisional"
    );
    assert!(
        cancels_to(&sent, FAILED).is_empty(),
        "RFC 3261 §9.1: no CANCEL for an INVITE with its final response"
    );
    assert_eq!(waiting_cancels(&proxy), 1);
    (proxy, to_silent)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_callers_cancel_reaches_a_silent_branch_on_its_first_provisional() {
    let (proxy, to_silent) = caller_gave_up("caller-cancel-100@example.com");
    assert_still_retransmitting(&proxy, SILENT, &to_silent);
    assert_provisional_draws_the_cancel(&proxy, SILENT, &to_silent, 100, "Trying");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_callers_cancel_reaches_a_silent_branch_when_it_starts_ringing() {
    let (proxy, to_silent) = caller_gave_up("caller-cancel-180@example.com");
    assert_provisional_draws_the_cancel(&proxy, SILENT, &to_silent, 180, "Ringing");
}

/// The caller's CANCEL carries what it came with (a Reason, say) to the branch
/// whenever it gets there, on the Via the branch's INVITE had.
#[tokio::test(flavor = "multi_thread")]
async fn a_callers_cancel_sent_late_is_the_cancel_the_caller_sent() {
    let proxy = relaying_proxy(SILENT, "");
    let (raw, invites) = call(&proxy, "caller-cancel-reason@example.com");
    let to_silent = find(&invites, SILENT).clone();
    let cancel = raw
        .replacen("INVITE", "CANCEL", 1)
        .replace("CSeq: 5 INVITE", "CSeq: 5 CANCEL")
        .replace(
            &format!("Contact: <sip:phone@{CALLER}>\r\n"),
            "Reason: SIP;cause=200;text=\"Call completed elsewhere\"\r\n",
        );
    proxy.request(CALLER, &cancel);
    let sent = proxy.wire();
    assert_eq!(responses_to_caller(&sent), [200, 487]);
    assert!(cancels_to(&sent, SILENT).is_empty());

    answers(&proxy, SILENT, &to_silent, 180, "Ringing");
    let sent = proxy.wire();
    let relayed = the_cancel(&sent, SILENT, &to_silent);
    assert_eq!(
        header(&relayed, "Reason"),
        "SIP;cause=200;text=\"Call completed elsewhere\""
    );
    assert!(responses_to_caller(&sent).is_empty());
}

/// The branch the caller's CANCEL left waiting answers 2xx, fails, or never
/// responds: no CANCEL, and the caller, already answered 487, hears nothing
/// but a 2xx.
#[tokio::test(flavor = "multi_thread")]
async fn a_silent_branch_the_caller_gave_up_on_is_not_cancelled_once_it_has_its_final_response() {
    for (call_id, ending) in [
        ("caller-cancel-late-200@example.com", Some((200, "OK"))),
        (
            "caller-cancel-late-486@example.com",
            Some((486, "Busy Here")),
        ),
        ("caller-cancel-timer-b@example.com", None),
    ] {
        let (proxy, to_silent) = caller_gave_up(call_id);
        match ending {
            Some((status_code, reason)) => answers(&proxy, SILENT, &to_silent, status_code, reason),
            None => fire(&proxy, &to_silent, TimerName::B),
        }
        let sent = proxy.wire();
        assert!(cancels_to(&sent, SILENT).is_empty(), "{call_id}");
        // A 2xx is the caller's to release (RFC 3261 §16.7 step 5); nothing
        // else reaches a caller that already has its final response.
        let forwarded: &[u16] = match ending {
            Some((200, _)) => &[200],
            _ => &[],
        };
        assert_eq!(responses_to_caller(&sent), forwarded, "{call_id}");
        if ending.is_some_and(|(status_code, _)| status_code >= 300) {
            assert_eq!(
                requests_to(&sent, SILENT, Method::Ack).len(),
                1,
                "{call_id}: the failure is ACKed"
            );
        }
        assert_eq!(waiting_cancels(&proxy), 0, "{call_id}");
    }
}

/// A retransmitted CANCEL from the caller is answered and changes nothing: the
/// branch still gets one CANCEL, on its first provisional.
#[tokio::test(flavor = "multi_thread")]
async fn a_retransmitted_caller_cancel_does_not_cancel_a_silent_branch_twice() {
    let proxy = relaying_proxy(SILENT, "");
    let (raw, invites) = call(&proxy, "caller-cancel-twice@example.com");
    let to_silent = find(&invites, SILENT).clone();
    caller_cancels(&proxy, &raw);
    caller_cancels(&proxy, &raw);
    let sent = proxy.wire();
    assert_eq!(responses_to_caller(&sent), [200, 487, 200]);
    assert!(cancels_to(&sent, SILENT).is_empty());
    assert_eq!(waiting_cancels(&proxy), 1);
    assert_provisional_draws_the_cancel(&proxy, SILENT, &to_silent, 100, "Trying");
}

// ---------------------------------------------------------------------------
// Sequential forking and failure retargeting abandon no pending branch
// ---------------------------------------------------------------------------

/// A sequential fork moves on only when the branch it is on has its final
/// response, or its INVITE has timed out. Either way that INVITE's transaction
/// is over, and it is never CANCELled.
#[tokio::test(flavor = "multi_thread")]
async fn a_sequential_fork_moves_on_without_cancelling_the_branch_it_leaves() {
    for (call_id, timed_out) in [
        ("sequential-failed@example.com", false),
        ("sequential-timer-b@example.com", true),
    ] {
        let proxy = forking_proxy(&[SILENT, RINGING], "sequential", "");
        let (_, invites) = call(&proxy, call_id);
        assert_eq!(invites.len(), 1, "one branch at a time");
        let to_first = find(&invites, SILENT).clone();
        if timed_out {
            fire(&proxy, &to_first, TimerName::B);
        } else {
            answers(&proxy, SILENT, &to_first, 480, "Temporarily Unavailable");
        }
        let sent = proxy.wire();
        assert_eq!(
            requests_to(&sent, RINGING, Method::Invite).len(),
            1,
            "{call_id}: the next branch is tried"
        );
        assert!(cancels_to(&sent, SILENT).is_empty(), "{call_id}");
        assert!(responses_to_caller(&sent).is_empty(), "{call_id}");
        assert_eq!(waiting_cancels(&proxy), 0, "{call_id}");
    }
}

/// `@proxy.on_failure` re-targeting a failed relay: the branch it leaves has
/// its final response and is not CANCELled.
#[tokio::test(flavor = "multi_thread")]
async fn a_failure_retarget_does_not_cancel_the_branch_that_failed() {
    let proxy = relaying_proxy(
        FAILED,
        &format!(
            concat!(
                "@proxy.on_failure\n",
                "def failed(request, reply):\n",
                "    request.relay(\"sip:callee@{next}\")\n",
            ),
            next = RINGING
        ),
    );
    let (_, invites) = call(&proxy, "failure-retarget@example.com");
    let to_failed = find(&invites, FAILED).clone();
    answers(&proxy, FAILED, &to_failed, 503, "Service Unavailable");
    let sent = proxy.wire();
    assert_eq!(requests_to(&sent, RINGING, Method::Invite).len(), 1);
    assert!(cancels_to(&sent, FAILED).is_empty());
    assert!(responses_to_caller(&sent).is_empty());
    assert_eq!(waiting_cancels(&proxy), 0);
}

/// RFC 3261 §9.1: "A CANCEL request SHOULD NOT be sent to cancel a request
/// other than INVITE." The other branch of a forked MESSAGE is left alone when
/// one answers.
#[tokio::test(flavor = "multi_thread")]
async fn a_forked_request_other_than_invite_is_not_cancelled() {
    let proxy = forking_proxy(&[SILENT, DECIDING], "parallel", "");
    let message = caller_invite("forked-message@example.com")
        .replacen("INVITE", "MESSAGE", 1)
        .replace("CSeq: 5 INVITE", "CSeq: 5 MESSAGE");
    proxy.request(CALLER, &message);
    let sent = proxy.wire();
    let to_deciding = requests_to(&sent, DECIDING, Method::Message);
    assert_eq!(to_deciding.len(), 1);
    assert_eq!(requests_to(&sent, SILENT, Method::Message).len(), 1);

    answers(&proxy, DECIDING, &to_deciding[0], 200, "OK");
    let sent = proxy.wire();
    assert_eq!(responses_to_caller(&sent), [200]);
    assert!(cancels_to(&sent, SILENT).is_empty());
    assert!(cancels_to(&sent, DECIDING).is_empty());
    assert_eq!(waiting_cancels(&proxy), 0);
}

// ---------------------------------------------------------------------------
// A response and a CANCEL at the same moment
// ---------------------------------------------------------------------------

/// Run `first` and `second` on two threads released together.
pub(super) async fn race(
    first: impl FnOnce() + Send + 'static,
    second: impl FnOnce() + Send + 'static,
) {
    let barrier = Arc::new(Barrier::new(2));
    let (first_barrier, second_barrier) = (Arc::clone(&barrier), Arc::clone(&barrier));
    let first = tokio::task::spawn_blocking(move || {
        first_barrier.wait();
        first();
    });
    let second = tokio::task::spawn_blocking(move || {
        second_barrier.wait();
        second();
    });
    first.await.expect("the first side ran");
    second.await.expect("the second side ran");
}

pub(super) fn deliver(state: &Arc<DispatcherState>, source: &str, message: SipMessage) {
    let raw = String::from_utf8(message.to_bytes()).expect("UTF-8");
    match message.status_code() {
        Some(status_code) => handle_response(inbound(source, &raw), message, status_code, state),
        None => {
            let method = message.method().expect("a request").as_str().to_string();
            handle_request(inbound(source, &raw), message, method, state);
        }
    }
}

/// The callee's first provisional and the caller's CANCEL arrive together, on
/// two workers. Whichever is handled first, the provisional has been seen by
/// the time both are, so the callee is sent exactly one CANCEL.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_first_provisional_racing_the_callers_cancel_draws_exactly_one_cancel() {
    let proxy = relaying_proxy(SILENT, "");
    for round in 0..150usize {
        let (raw, invites) = call(&proxy, &format!("race-caller-cancel-{round}@example.com"));
        let to_silent = find(&invites, SILENT).clone();
        let ringing = response_to(
            &to_silent,
            180,
            "Ringing",
            "callee-tag",
            &format!("sip:callee@{SILENT}"),
            "",
        );
        let cancel = parse_sip_message_bytes(
            raw.replacen("INVITE", "CANCEL", 1)
                .replace("CSeq: 5 INVITE", "CSeq: 5 CANCEL")
                .replace(&format!("Contact: <sip:phone@{CALLER}>\r\n"), "")
                .as_bytes(),
        )
        .expect("the CANCEL parses");

        let (responding, cancelling) = (Arc::clone(&proxy.state), Arc::clone(&proxy.state));
        race(
            move || deliver(&responding, SILENT, ringing),
            move || deliver(&cancelling, CALLER, cancel),
        )
        .await;

        let sent = proxy.wire();
        the_cancel(&sent, SILENT, &to_silent);
        let to_caller = responses_to_caller(&sent);
        assert!(
            to_caller.contains(&200) && to_caller.contains(&487),
            "round {round}: {to_caller:?}"
        );
        assert_eq!(waiting_cancels(&proxy), 0, "round {round}");
    }
}

/// A losing branch's first provisional and the winning branch's 2xx arrive
/// together: the loser is sent exactly one CANCEL, and the caller one 2xx.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_first_provisional_racing_the_winning_2xx_draws_exactly_one_cancel() {
    let proxy = forking_proxy(&[SILENT, DECIDING], "parallel", "");
    for round in 0..150usize {
        let (_, invites) = call(&proxy, &format!("race-fork-winner-{round}@example.com"));
        let (to_silent, to_deciding) = (
            find(&invites, SILENT).clone(),
            find(&invites, DECIDING).clone(),
        );
        let trying = response_to(
            &to_silent,
            100,
            "Trying",
            "loser-tag",
            &format!("sip:callee@{SILENT}"),
            "",
        );
        let answer = response_to(
            &to_deciding,
            200,
            "OK",
            "winner-tag",
            &format!("sip:callee@{DECIDING}"),
            "",
        );

        let (responding, answering) = (Arc::clone(&proxy.state), Arc::clone(&proxy.state));
        race(
            move || deliver(&responding, SILENT, trying),
            move || deliver(&answering, DECIDING, answer),
        )
        .await;

        let sent = proxy.wire();
        the_cancel(&sent, SILENT, &to_silent);
        assert!(cancels_to(&sent, DECIDING).is_empty(), "round {round}");
        assert_eq!(responses_to_caller(&sent), [200], "round {round}");
        assert_eq!(waiting_cancels(&proxy), 0, "round {round}");
    }
}

// ---------------------------------------------------------------------------
// A branch over a reliable transport
// ---------------------------------------------------------------------------

const STREAM_CALLEE: &str = "198.51.100.30:5060";
const STREAM_CONNECTION: ConnectionId = ConnectionId(41);

/// A proxied INVITE whose one branch went to [`STREAM_CALLEE`] over TCP and
/// has drawn nothing, abandoned by the caller. Built on the session and the
/// client transaction the relay path creates for such a branch, with the TCP
/// egress a channel the test reads. Returns the proxy, that channel and the
/// branch's INVITE.
fn caller_gave_up_on_a_silent_stream_branch(
    call_id: &str,
) -> (Proxy, flume::Receiver<OutboundMessage>, SipMessage) {
    let mut dispatcher = test_dispatcher_with_script("");
    let (udp_sender, udp) = flume::unbounded();
    let (tcp_sender, tcp) = flume::unbounded();
    let (other_sender, _) = flume::unbounded();
    dispatcher.state.outbound = Arc::new(OutboundRouter {
        udp: udp_sender.into(),
        udp_by_local: std::collections::HashMap::new(),
        tcp: tcp_sender,
        tls: other_sender.clone(),
        ws: other_sender.clone(),
        wss: other_sender.clone(),
        sctp: Some(other_sender),
    });
    let proxy = Proxy {
        state: Arc::new(dispatcher.state),
        udp,
    };
    let state = &proxy.state;

    let raw = caller_invite(call_id);
    let original = parse_sip_message_bytes(raw.as_bytes()).expect("the INVITE parses");
    let server_key = TransactionManager::key_from_message(&original).expect("a server key");
    let mut relayed = original.clone();
    let branch = core::add_via(&mut relayed.headers, "TCP", "192.0.2.1", Some(5060));
    let destination: SocketAddr = STREAM_CALLEE.parse().expect("a literal address");

    let (client_key, actions) = state
        .transaction_manager
        .new_client_transaction(
            &relayed,
            Bytes::from(relayed.to_bytes()),
            crate::transaction::state::Transport::Reliable,
        )
        .expect("the client transaction starts");
    assert_eq!(client_key.branch, branch);
    // As the relay path does: the hop before the send, and the connection the
    // send established once it is known.
    state.transaction_manager.set_client_hop(
        &client_key,
        crate::transaction::state::BranchHop {
            destination,
            transport: Transport::Tcp,
            connection_id: ConnectionId::default(),
            source_local_addr: None,
        },
    );
    state
        .transaction_manager
        .set_client_connection(&client_key, STREAM_CONNECTION);
    process_timer_actions(
        &actions,
        &client_key,
        Some(destination),
        Some(Transport::Tcp),
        Some(STREAM_CONNECTION),
        None,
        state,
    );
    let on_the_wire = tcp.try_recv().expect("the INVITE went out over TCP");
    assert_eq!(on_the_wire.data, Bytes::from(relayed.to_bytes()));
    let mut session = ProxySession::new(
        server_key,
        CALLER.parse().expect("a literal address"),
        "192.0.2.1:5060".parse().expect("a literal address"),
        ConnectionId::default(),
        Transport::Udp,
        original,
        false,
    );
    session.add_client_key(client_key.clone());
    session.set_client_branch(
        client_key.clone(),
        ClientBranch {
            destination,
            transport: Transport::Tcp,
            connection_id: STREAM_CONNECTION,
        },
    );
    state.session_store.insert(session);

    caller_cancels(&proxy, &raw);
    assert_eq!(responses_to_caller(&proxy.wire()), [200, 487]);
    assert!(
        tcp.try_recv().is_err(),
        "no CANCEL for an INVITE with no provisional"
    );
    assert_eq!(waiting_cancels(&proxy), 1);
    assert!(
        !state
            .timer_wheel
            .contains_key(&format!("{}:{:?}", client_key, TimerName::A)),
        "nothing retransmits over a reliable transport (RFC 3261 §17.1.1.2)"
    );
    (proxy, tcp, relayed)
}

/// Over TCP the silent branch's INVITE is not retransmitted, and its first
/// provisional still draws the CANCEL, on the connection the INVITE went on.
#[tokio::test(flavor = "multi_thread")]
async fn a_silent_stream_branch_is_cancelled_on_its_first_provisional() {
    let (proxy, tcp, relayed) = caller_gave_up_on_a_silent_stream_branch("stream-100@example.com");
    let trying = response_to(
        &relayed,
        100,
        "Trying",
        "callee-tag",
        &format!("sip:callee@{STREAM_CALLEE}"),
        "",
    );
    let raw = String::from_utf8(trying.to_bytes()).expect("UTF-8");
    let mut arrived = inbound(STREAM_CALLEE, &raw);
    arrived.transport = Transport::Tcp;
    arrived.connection_id = STREAM_CONNECTION;
    tokio::task::block_in_place(|| handle_response(arrived, trying, 100, &proxy.state));

    let sent = tcp.try_recv().expect("the CANCEL went out over TCP");
    let cancel = parse_sip_message_bytes(&sent.data).expect("the CANCEL parses");
    assert_eq!(cancel.method(), Some(&Method::Cancel));
    assert_eq!(branch_of(&cancel), branch_of(&relayed));
    assert_eq!(sent.destination.to_string(), STREAM_CALLEE);
    assert_eq!(sent.connection_id, STREAM_CONNECTION);
    assert!(tcp.try_recv().is_err(), "one CANCEL");
    assert_eq!(waiting_cancels(&proxy), 0);
}

/// Over TCP a branch that never responds has only Timer B, and it ends the
/// waiting CANCEL unsent.
#[tokio::test(flavor = "multi_thread")]
async fn a_silent_stream_branch_that_never_responds_ends_at_the_transaction_timeout() {
    let (proxy, tcp, relayed) =
        caller_gave_up_on_a_silent_stream_branch("stream-timer-b@example.com");
    let client_key = TransactionManager::key_from_message(&relayed).expect("a key");
    fire(&proxy, &relayed, TimerName::B);
    assert!(tcp.try_recv().is_err(), "nothing is sent");
    assert!(responses_to_caller(&proxy.wire()).is_empty());
    assert_eq!(waiting_cancels(&proxy), 0);
    assert!(!proxy.state.transaction_manager.contains(&client_key));
    assert!(!proxy
        .state
        .timer_wheel
        .iter()
        .any(|entry| entry.key == client_key));
}

// ---------------------------------------------------------------------------
// Nothing is left behind
// ---------------------------------------------------------------------------

/// Many calls abandoned on a silent callee, ended every way a waiting CANCEL
/// can end: the CANCELs waiting, the transactions and the timers all return to
/// where they started.
#[tokio::test(flavor = "multi_thread")]
async fn waiting_cancels_drain_to_baseline_over_every_exit() {
    let proxy = relaying_proxy(SILENT, "");
    let state = &proxy.state;
    let mut abandoned = Vec::new();
    for index in 0..40usize {
        let (raw, invites) = call(&proxy, &format!("drain-{index}@example.com"));
        caller_cancels(&proxy, &raw);
        abandoned.push(find(&invites, SILENT).clone());
    }
    let sent = proxy.wire();
    assert!(cancels_to(&sent, SILENT).is_empty());
    assert_eq!(waiting_cancels(&proxy), 40);
    assert_eq!(
        state.session_store.session_count(),
        40,
        "each held for its one branch still owed a final response"
    );

    let mut cancels_sent = 0;
    for (index, to_silent) in abandoned.iter().enumerate() {
        match index % 4 {
            // A provisional: CANCEL, then its 487, then Timer D.
            0 => {
                answers(&proxy, SILENT, to_silent, 180, "Ringing");
                answers(&proxy, SILENT, to_silent, 487, "Request Terminated");
                fire(&proxy, to_silent, TimerName::D);
            }
            // A late 2xx.
            1 => answers(&proxy, SILENT, to_silent, 200, "OK"),
            // A late failure, then Timer D.
            2 => {
                answers(&proxy, SILENT, to_silent, 486, "Busy Here");
                fire(&proxy, to_silent, TimerName::D);
            }
            // Nothing: Timer B.
            _ => fire(&proxy, to_silent, TimerName::B),
        }
        cancels_sent += cancels_to(&proxy.wire(), SILENT).len();
    }
    assert_eq!(
        cancels_sent, 10,
        "one CANCEL per branch that got a provisional"
    );
    assert_eq!(waiting_cancels(&proxy), 0);
    let client_transactions = abandoned
        .iter()
        .filter(|to_silent| {
            let key = TransactionManager::key_from_message(to_silent).expect("a key");
            state.transaction_manager.contains(&key)
        })
        .count();
    assert_eq!(client_transactions, 0, "every INVITE's transaction is gone");
    let client_timers = state
        .timer_wheel
        .iter()
        .filter(|entry| {
            abandoned
                .iter()
                .any(|to_silent| branch_of(to_silent) == entry.key.branch)
        })
        .count();
    assert_eq!(client_timers, 0, "and so is every timer it had");
    assert_eq!(state.session_store.session_count(), 0);
    assert_eq!(state.session_store.client_key_count(), 0);
}
