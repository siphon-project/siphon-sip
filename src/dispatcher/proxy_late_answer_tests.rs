//! RFC 3261 §16.7 step 5: a 2xx to a proxied INVITE that already has its final
//! response upstream is forwarded to the caller, whose user agent ACKs it and
//! ends the dialog it opened (§13.2.2.4).
//!
//! Each way the proxy gives up on a branch that then answers: another branch
//! of the fork answered, or declined with a 6xx; `reply.reject()` failed the
//! request; the caller cancelled. For each, on the proxy harness of
//! [`super::proxy_cancel_awaits_provisional_tests`] and read off the UDP
//! egress: the 2xx reaches the caller with the caller's own Via stack, the
//! caller's ACK and BYE for that dialog reach the callee and the BYE's 200
//! comes back, no reply handler runs for it, the call's record is not marked
//! answered by it, and nothing is left in the stores.

use std::time::Duration;

use super::proxy_cancel_awaits_provisional_tests::{
    answers, call, caller_cancels, cancels_to, requests_to, the_cancel, waiting_cancels, CALLER,
    DECIDING, RINGING, SILENT,
};
use super::proxy_dialog_state_tests::{
    find, header, headers, in_dialog, knows_itself, response_to, Proxy, Sent,
};
use super::test_dispatcher::test_dispatcher_with_script;
use super::*;

/// A proxy that Record-Routes and forks every INVITE to `targets`, follows
/// the route set of an in-dialog request, and marks every response its
/// `@proxy.on_reply` handler sees. `reject_on_183` makes that handler fail the
/// INVITE on a `183`.
fn proxy_for(targets: &[&str], reject_on_183: bool) -> Proxy {
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
            "    if request.in_dialog:\n",
            "        request.loose_route()\n",
            "        request.relay()\n",
            "        return\n",
            "    request.record_route()\n",
            "    request.fork([{uris}])\n",
            "\n",
            "@proxy.on_reply\n",
            "def answered(request, reply):\n",
            "    if {reject} and reply.status_code == 183:\n",
            "        reply.reject(503, \"Service Unavailable\")\n",
            "        return\n",
            "    reply.set_header(\"X-Reply-Handler\", \"ran\")\n",
            "    reply.relay()\n",
        ),
        uris = uris.join(", "),
        reject = if reject_on_183 { "True" } else { "False" },
    );
    let mut dispatcher = test_dispatcher_with_script(&script);
    knows_itself(&mut dispatcher.state);
    Proxy {
        state: Arc::new(dispatcher.state),
        udp: dispatcher.udp,
    }
}

/// The 2xx responses to the INVITE the caller was sent among `sent`.
fn answers_to_caller(sent: &[Sent]) -> Vec<SipMessage> {
    sent.iter()
        .filter(|sent| sent.destination == CALLER)
        .filter(|sent| sent.message.status_code() == Some(200))
        .filter(|sent| header(&sent.message, "CSeq").ends_with("INVITE"))
        .map(|sent| sent.message.clone())
        .collect()
}

/// `callee` answers `branch_invite` 2xx after the proxy gave up on it, and the
/// proxy hands that answer to the caller; the caller then ACKs the dialog and
/// ends it. Everything RFC 3261 §16.7 step 5 and §13.2.2.4 need of the proxy.
fn assert_late_answer_is_forwarded_and_released(
    proxy: &Proxy,
    callee: &str,
    branch_invite: &SipMessage,
    call_id: &str,
) {
    let client_key = TransactionManager::key_from_message(branch_invite).expect("a key");
    let record_before = call_record(proxy, call_id);
    let caller_via = format!("SIP/2.0/UDP {CALLER};branch=z9hG4bK-{call_id}");
    answers(proxy, callee, branch_invite, 200, "OK");
    let sent = proxy.wire();
    assert!(
        cancels_to(&sent, callee).is_empty(),
        "an INVITE with its final response is not CANCELled"
    );
    let forwarded = answers_to_caller(&sent);
    assert_eq!(forwarded.len(), 1, "the late 2xx reaches the caller");
    let answer = &forwarded[0];
    assert_eq!(
        headers(answer, "Via"),
        [caller_via],
        "with the proxy's Via removed and the caller's left"
    );
    let callee_tag = format!(";tag=tag-{}", callee.replace(['.', ':'], "-"));
    assert!(header(answer, "To").ends_with(&callee_tag));
    assert_eq!(header(answer, "Contact"), format!("<sip:callee@{callee}>"));
    let record_route = headers(answer, "Record-Route");
    assert!(
        !record_route.is_empty(),
        "the Record-Route the INVITE went out with comes back"
    );
    assert!(
        answer.headers.get("X-Reply-Handler").is_none(),
        "no reply handler runs for it"
    );
    assert!(!proxy.state.transaction_manager.contains(&client_key));
    assert_eq!(
        call_record(proxy, call_id),
        record_before,
        "the late 2xx is not the call's answer: nothing is stamped on its record"
    );

    // The same 2xx again is this branch's retransmission, not another answer.
    answers(proxy, callee, branch_invite, 200, "OK");
    assert!(answers_to_caller(&proxy.wire()).is_empty());

    // The caller ACKs the dialog (a request of its own, on the route set)...
    let route_set: Vec<String> = record_route.into_iter().rev().collect();
    let (from, to) = (header(answer, "From"), header(answer, "To"));
    let target = format!("sip:callee@{callee}");
    proxy.request(
        CALLER,
        &in_dialog("ACK", &target, CALLER, &from, &to, call_id, &route_set, 5),
    );
    let sent = proxy.wire();
    let acks = requests_to(&sent, callee, Method::Ack);
    assert_eq!(acks.len(), 1, "the caller's ACK reaches the callee");
    assert_eq!(header(&acks[0], "To"), to);
    assert!(acks[0].headers.get("Route").is_none());

    // ...and ends it, on a transaction of this dialog's own.
    let bye_cseq = if callee == SILENT { 7 } else { 6 };
    proxy.request(
        CALLER,
        &in_dialog(
            "BYE", &target, CALLER, &from, &to, call_id, &route_set, bye_cseq,
        ),
    );
    let sent = proxy.wire();
    let byes = requests_to(&sent, callee, Method::Bye);
    assert_eq!(
        byes.len(),
        1,
        "the caller's BYE reaches the callee: {:?}",
        sent.iter()
            .map(|sent| format!(
                "{} {}",
                sent.destination,
                String::from_utf8_lossy(&sent.message.to_bytes())
            ))
            .collect::<Vec<_>>()
    );
    proxy.response(
        callee,
        response_to(&byes[0], 200, "OK", "ignored", &target, ""),
    );
    let sent = proxy.wire();
    assert!(
        sent.iter().any(|sent| sent.destination == CALLER
            && sent.message.status_code() == Some(200)
            && header(&sent.message, "CSeq").ends_with("BYE")),
        "and its 200 comes back"
    );
    assert_eq!(
        call_record(proxy, call_id),
        record_before,
        "ending the late dialog does not end the call's record"
    );
    assert_eq!(proxy.state.session_store.late_dialog_count(), 0);
}

/// Nothing of the call is left: no session, no client key, no waiting CANCEL,
/// and no dialog entry once the sweep has passed the ACK's grace.
fn assert_drained(proxy: &Proxy) {
    let store = &proxy.state.session_store;
    assert_eq!(store.session_count(), 0);
    assert_eq!(store.client_key_count(), 0);
    assert_eq!(waiting_cancels(proxy), 0);
    store.sweep_stale_with_ack_grace(Duration::from_secs(3600), Duration::ZERO);
    assert_eq!(
        store.dialog_key_count(),
        0,
        "the dialog entry went with its ACK"
    );
    assert_eq!(store.late_dialog_count(), 0);
}

/// The call's record under `cdr.auto_emit`, as text.
fn call_record(proxy: &Proxy, call_id: &str) -> Option<String> {
    proxy
        .state
        .cdr_sessions
        .get(&cdr_dialog_key(call_id, "caller-tag"))
        .map(|session| format!("{:?}", *session))
}

/// Another branch won the fork with a 2xx, or ended it with a 6xx; the branch
/// that had sent nothing then answers.
#[tokio::test(flavor = "multi_thread")]
async fn a_branch_answering_after_the_fork_settled_is_forwarded() {
    let _records = crate::cdr::capture_auto_emitted_cdrs();
    for (call_id, deciding_status, reason) in [
        ("late-answer-after-2xx@example.com", 200, "OK"),
        ("late-answer-after-6xx@example.com", 603, "Decline"),
    ] {
        let proxy = proxy_for(&[DECIDING, SILENT], false);
        let (_, invites) = call(&proxy, call_id);
        let (to_deciding, to_silent) = (
            find(&invites, DECIDING).clone(),
            find(&invites, SILENT).clone(),
        );
        answers(&proxy, DECIDING, &to_deciding, deciding_status, reason);
        let sent = proxy.wire();
        let settled: Vec<_> = sent
            .iter()
            .filter(|sent| sent.destination == CALLER)
            .filter(|sent| sent.message.status_code() == Some(deciding_status))
            .collect();
        assert_eq!(settled.len(), 1, "{call_id}");
        assert_eq!(
            header(&settled[0].message, "X-Reply-Handler"),
            "ran",
            "the response that settles the fork is the script's to see"
        );
        let record_before = call_record(&proxy, call_id);
        if deciding_status == 200 {
            let record = record_before.as_deref().expect("a tracked call");
            assert!(
                record.contains("198.51.100.14"),
                "answered by the branch that won: {record}"
            );
        }

        assert_late_answer_is_forwarded_and_released(&proxy, SILENT, &to_silent, call_id);
        assert_eq!(
            call_record(&proxy, call_id),
            record_before,
            "{call_id}: the call's record is as the fork's own answer left it"
        );
        assert_drained(&proxy);
    }
}

/// `reply.reject()` failed the INVITE on one branch's `183`; that branch then
/// answers across its CANCEL, and the branch that had sent nothing answers
/// too.
#[tokio::test(flavor = "multi_thread")]
async fn a_branch_answering_after_a_reject_is_forwarded() {
    let call_id = "late-answer-after-reject@example.com";
    let proxy = proxy_for(&[RINGING, SILENT], true);
    let (_, invites) = call(&proxy, call_id);
    let (to_ringing, to_silent) = (
        find(&invites, RINGING).clone(),
        find(&invites, SILENT).clone(),
    );
    answers(&proxy, RINGING, &to_ringing, 183, "Session Progress");
    let sent = proxy.wire();
    assert!(sent
        .iter()
        .any(|sent| sent.destination == CALLER && sent.message.status_code() == Some(503)));
    the_cancel(&sent, RINGING, &to_ringing);

    assert_late_answer_is_forwarded_and_released(&proxy, RINGING, &to_ringing, call_id);
    assert_late_answer_is_forwarded_and_released(&proxy, SILENT, &to_silent, call_id);
    assert_drained(&proxy);
}

/// The caller cancelled and was answered `487`; the branch that rang answers
/// across its CANCEL, and the branch that had sent nothing answers too.
#[tokio::test(flavor = "multi_thread")]
async fn a_branch_answering_after_the_caller_cancelled_is_forwarded() {
    let _records = crate::cdr::capture_auto_emitted_cdrs();
    let call_id = "late-answer-after-cancel@example.com";
    let proxy = proxy_for(&[RINGING, SILENT], false);
    let (raw, invites) = call(&proxy, call_id);
    let (to_ringing, to_silent) = (
        find(&invites, RINGING).clone(),
        find(&invites, SILENT).clone(),
    );
    answers(&proxy, RINGING, &to_ringing, 180, "Ringing");
    let _ = proxy.wire();
    caller_cancels(&proxy, &raw);
    let sent = proxy.wire();
    the_cancel(&sent, RINGING, &to_ringing);
    assert!(cancels_to(&sent, SILENT).is_empty());
    let record_before = call_record(&proxy, call_id);

    assert_late_answer_is_forwarded_and_released(&proxy, RINGING, &to_ringing, call_id);
    assert_late_answer_is_forwarded_and_released(&proxy, SILENT, &to_silent, call_id);
    assert_eq!(
        call_record(&proxy, call_id),
        record_before,
        "a 2xx to an abandoned call does not answer it"
    );
    assert_drained(&proxy);
}

/// A cancelled INVITE's session is held only for the branches still owed a
/// final response, and each of their ends releases it: a failure, the `487`
/// of the CANCEL, and the transaction timing out.
#[tokio::test(flavor = "multi_thread")]
async fn a_cancelled_invite_is_released_by_the_last_branch_to_end() {
    for ending in ["failure", "terminated", "timeout"] {
        let call_id = format!("cancelled-{ending}@example.com");
        let proxy = proxy_for(&[RINGING, SILENT], false);
        let (raw, invites) = call(&proxy, &call_id);
        let (to_ringing, to_silent) = (
            find(&invites, RINGING).clone(),
            find(&invites, SILENT).clone(),
        );
        answers(&proxy, RINGING, &to_ringing, 180, "Ringing");
        caller_cancels(&proxy, &raw);
        let _ = proxy.wire();
        let store = &proxy.state.session_store;
        assert_eq!(store.client_key_count(), 2, "{ending}: both still pending");
        assert_eq!(store.dialog_key_count(), 0, "{ending}: no dialog to route");

        answers(&proxy, RINGING, &to_ringing, 487, "Request Terminated");
        assert_eq!(store.client_key_count(), 1, "{ending}");
        match ending {
            "failure" => answers(&proxy, SILENT, &to_silent, 486, "Busy Here"),
            "terminated" => {
                answers(&proxy, SILENT, &to_silent, 100, "Trying");
                answers(&proxy, SILENT, &to_silent, 487, "Request Terminated");
            }
            _ => {
                super::proxy_cancel_awaits_provisional_tests::fire(&proxy, &to_silent, TimerName::B)
            }
        }
        let sent = proxy.wire();
        assert!(
            sent.iter().all(|sent| sent.destination != CALLER),
            "{ending}: the caller, answered 487, hears nothing more"
        );
        assert_drained(&proxy);
    }
}
