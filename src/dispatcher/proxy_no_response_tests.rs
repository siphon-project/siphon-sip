//! `relay(no_response_ms=…)` / `fork(no_response_ms=…)` on the proxy path: a
//! per-branch bound on drawing any response at all, below Timer B / Timer F.
//!
//! TS 24.229 §5.4.3.3 (HSS based P-CSCF restoration) has an S-CSCF treat a
//! next hop that "fails to receive any SIP response" within a configurable
//! time as failed, the time being "less than timer B and timer F" (NOTE 24).
//! A branch silent that long ends as a locally generated `408`, down the same
//! RFC 3261 §16.7 path a Timer B / F expiry takes, so the script's failure
//! handling sees what it already handles. Any response, `100 Trying`
//! included, stops it; an INVITE that rang and went quiet is Timer C's.
//!
//! The timer wheel runs on [`std::time::Instant`]; the tests move its clock by
//! hand ([`fire_expired_timers_at`]) rather than sleeping, so a regression
//! fails an assertion instead of hanging.

use std::time::{Duration, Instant};

use super::proxy_cancel_awaits_provisional_tests::{
    answers, call, caller_cancels, cancels_to, fire, requests_to, responses_to_caller, the_cancel,
    waiting_cancels, CALLER, DECIDING, RINGING, SILENT,
};
use super::proxy_dialog_state_tests::{find, header, Proxy};
use super::test_dispatcher::test_dispatcher_with_script;
use super::*;

/// The bound every test here asks for.
const BOUND: Duration = Duration::from_millis(2000);

fn proxy_running(script: &str) -> Proxy {
    let dispatcher = test_dispatcher_with_script(script);
    Proxy {
        state: Arc::new(dispatcher.state),
        udp: dispatcher.udp,
    }
}

/// `@proxy.on_failure` records what it was handed on the retry it sends to
/// `RINGING`, so a test can read off the wire exactly what the handler saw.
const RECORD_AND_FAIL_OVER: &str = concat!(
    "@proxy.on_failure\n",
    "def failed(request, reply):\n",
    "    seen = '|'.join(str(part) for part in (\n",
    "        reply.status_code, reply.reason, reply.source_ip, reply.source_port,\n",
    "        reply.call_id, reply.get_header('To'), reply.get_header('From'),\n",
    "        reply.get_header('CSeq'), reply.get_headers('Via'),\n",
    "    ))\n",
    "    request.set_header('X-Failure-Seen', seen)\n",
    "    request.relay('sip:callee@198.51.100.11:5060')\n",
);

/// A proxy relaying every request to `SILENT`, with `relay_arguments` added to
/// the relay, failing over to `RINGING` from `@proxy.on_failure`.
fn relaying_with(relay_arguments: &str) -> Proxy {
    proxy_running(&format!(
        concat!(
            "from siphon import proxy\n",
            "\n",
            "@proxy.on_request\n",
            "def route(request):\n",
            "    request.relay('sip:callee@{silent}'{arguments})\n",
            "\n",
            "{failure}",
        ),
        silent = SILENT,
        arguments = relay_arguments,
        failure = RECORD_AND_FAIL_OVER,
    ))
}

/// A proxy forking every request to `targets` with `fork_arguments`, failing
/// over to `RINGING` from `@proxy.on_failure` once every branch has failed.
fn forking_with(targets: &[&str], fork_arguments: &str) -> Proxy {
    let uris: Vec<String> = targets
        .iter()
        .map(|target| format!("'sip:callee@{target}'"))
        .collect();
    proxy_running(&format!(
        concat!(
            "from siphon import proxy\n",
            "\n",
            "@proxy.on_request\n",
            "def route(request):\n",
            "    request.fork([{uris}]{arguments})\n",
            "\n",
            "{failure}",
        ),
        uris = uris.join(", "),
        arguments = fork_arguments,
        failure = RECORD_AND_FAIL_OVER,
    ))
}

fn no_response_id(request: &SipMessage) -> String {
    let key = TransactionManager::key_from_message(request).expect("a transaction key");
    // `TimerName::NoResponse`, spelled as the wheel keys it.
    format!("{key}:NoResponse")
}

/// When the no-response timer of the client transaction that sent `request`
/// fires, if it is running.
fn no_response_due(proxy: &Proxy, request: &SipMessage) -> Option<Instant> {
    proxy
        .state
        .timer_wheel
        .get(&no_response_id(request))
        .map(|entry| entry.fires_at)
}

/// Move the timer wheel's clock to `now`.
fn advance_to(proxy: &Proxy, now: Instant) {
    tokio::task::block_in_place(|| fire_expired_timers_at(&proxy.state, now));
}

/// The caller's INVITE is relayed; returns what `SILENT` was sent and the
/// moments just before and after.
fn invite_relayed(proxy: &Proxy, call_id: &str) -> (SipMessage, Instant, Instant) {
    let before = Instant::now();
    let (_, invites) = call(proxy, call_id);
    let after = Instant::now();
    (find(&invites, SILENT).clone(), before, after)
}

fn failovers(sent: &[super::proxy_dialog_state_tests::Sent], method: Method) -> Vec<SipMessage> {
    requests_to(sent, RINGING, method)
}

// ---------------------------------------------------------------------------
// A silent next hop
// ---------------------------------------------------------------------------

/// The silent branch ends as a `408` into `@proxy.on_failure` at the bound,
/// not at Timer B: the script fails over 30 s sooner. No CANCEL goes, the
/// INVITE is not retransmitted any more, and the caller sees nothing of it.
#[tokio::test(flavor = "multi_thread")]
async fn a_silent_invite_branch_fails_over_at_the_bound_not_at_timer_b() {
    let proxy = relaying_with(", no_response_ms=2000");
    let (to_silent, before, after) = invite_relayed(&proxy, "silent-invite@example.com");

    advance_to(&proxy, before + BOUND - Duration::from_millis(1));
    let sent = proxy.wire();
    assert!(
        failovers(&sent, Method::Invite).is_empty(),
        "nothing before the bound"
    );
    assert!(responses_to_caller(&sent).is_empty());

    advance_to(&proxy, after + BOUND);
    let sent = proxy.wire();
    let to_next = failovers(&sent, Method::Invite);
    assert_eq!(to_next.len(), 1, "on_failure failed over at the bound");
    assert!(header(&to_next[0], "X-Failure-Seen").starts_with("408|Request Timeout|"));
    assert!(
        responses_to_caller(&sent).is_empty(),
        "the 408 is the branch's"
    );
    assert!(
        cancels_to(&sent, SILENT).is_empty(),
        "RFC 3261 §9.1: no CANCEL"
    );
    assert_eq!(no_response_due(&proxy, &to_silent), None);

    // Long past the bound, up to Timer B: the silent branch is never sent its
    // INVITE again, and never a CANCEL.
    advance_to(&proxy, after + Duration::from_secs(31));
    let sent = proxy.wire();
    assert!(
        requests_to(&sent, SILENT, Method::Invite).is_empty(),
        "no retransmission"
    );
    assert!(cancels_to(&sent, SILENT).is_empty());

    answers(&proxy, RINGING, &to_next[0], 200, "OK");
    assert_eq!(responses_to_caller(&proxy.wire()), [200]);
}

/// The same on a non-INVITE (Timer F's territory), through the relay's own
/// `on_failure=` callback.
#[tokio::test(flavor = "multi_thread")]
async fn a_silent_non_invite_fails_over_through_the_relay_callback() {
    let proxy = proxy_running(concat!(
        "from siphon import proxy\n",
        "\n",
        "def failed(request, code, reason):\n",
        "    request.set_header('X-Failure-Seen', f'{code} {reason}')\n",
        "    request.relay('sip:registrar@198.51.100.11:5060')\n",
        "\n",
        "@proxy.on_request\n",
        "def route(request):\n",
        "    request.relay('sip:registrar@198.51.100.12:5060', on_failure=failed,\n",
        "                  no_response_ms=1500)\n",
    ));
    let before = Instant::now();
    proxy.request(CALLER, &message("silent-message@example.com"));
    let after = Instant::now();
    let to_silent = requests_to(&proxy.wire(), SILENT, Method::Message);
    assert_eq!(to_silent.len(), 1);

    advance_to(&proxy, before + Duration::from_millis(1499));
    let sent = proxy.wire();
    assert!(failovers(&sent, Method::Message).is_empty());
    assert!(
        !requests_to(&sent, SILENT, Method::Message).is_empty(),
        "Timer E retransmits until then"
    );

    advance_to(&proxy, after + Duration::from_millis(1500));
    let sent = proxy.wire();
    let to_next = failovers(&sent, Method::Message);
    assert_eq!(to_next.len(), 1, "the relay's on_failure failed over");
    assert_eq!(header(&to_next[0], "X-Failure-Seen"), "408 Request Timeout");
    assert!(responses_to_caller(&sent).is_empty());

    advance_to(&proxy, after + Duration::from_secs(10));
    assert!(
        requests_to(&proxy.wire(), SILENT, Method::Message).is_empty(),
        "no retransmission after the give-up"
    );
}

fn message(call_id: &str) -> String {
    format!(
        concat!(
            "MESSAGE sip:callee@example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP {caller};branch=z9hG4bK-{call_id}\r\n",
            "Max-Forwards: 70\r\n",
            "From: <sip:caller@example.com>;tag=caller-tag\r\n",
            "To: <sip:callee@example.com>\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: 1 MESSAGE\r\n",
            "Content-Type: text/plain\r\n",
            "Content-Length: 2\r\n",
            "\r\n",
            "hi",
        ),
        caller = CALLER,
        call_id = call_id,
    )
}

// ---------------------------------------------------------------------------
// Any response stops it
// ---------------------------------------------------------------------------

/// A `180`, and a bare `100 Trying` (TS 24.229: "any SIP response"), each stop
/// the timer; the branch rings on well past the bound and nothing fails it.
#[tokio::test(flavor = "multi_thread")]
async fn a_provisional_stops_the_timer() {
    for (status_code, reason) in [(180, "Ringing"), (100, "Trying")] {
        let proxy = relaying_with(", no_response_ms=2000");
        let (to_silent, _, after) =
            invite_relayed(&proxy, &format!("provisional-{status_code}@example.com"));
        assert!(no_response_due(&proxy, &to_silent).is_some(), "armed");

        answers(&proxy, SILENT, &to_silent, status_code, reason);
        let _ = proxy.wire();
        assert_eq!(
            no_response_due(&proxy, &to_silent),
            None,
            "a {status_code} stops the timer"
        );

        advance_to(&proxy, after + BOUND * 4);
        let sent = proxy.wire();
        assert!(
            failovers(&sent, Method::Invite).is_empty(),
            "{status_code}: no failover"
        );
        assert!(cancels_to(&sent, SILENT).is_empty());
        assert!(proxy.state.transaction_manager.invite_client_is_pending(
            &TransactionManager::key_from_message(&to_silent).expect("a key")
        ));
    }
}

/// An INVITE that rang and then went silent is past the bound's reach: past
/// Timer B it is Timer C that runs, and the bound changes nothing.
#[tokio::test(flavor = "multi_thread")]
async fn an_invite_that_rang_and_went_silent_is_left_to_timer_c() {
    let proxy = relaying_with(", no_response_ms=2000");
    let (to_silent, _, after) = invite_relayed(&proxy, "rang-then-silent@example.com");
    answers(&proxy, SILENT, &to_silent, 183, "Session Progress");
    let _ = proxy.wire();

    advance_to(&proxy, after + Duration::from_secs(33));
    let sent = proxy.wire();
    assert!(failovers(&sent, Method::Invite).is_empty());
    assert!(responses_to_caller(&sent).is_empty());
    assert!(cancels_to(&sent, SILENT).is_empty());
    let key = TransactionManager::key_from_message(&to_silent).expect("a key");
    assert!(
        proxy
            .state
            .timer_wheel
            .contains_key(&format!("{}:{:?}", key, TimerName::C)),
        "Timer C bounds it now"
    );
}

/// A response just inside the bound is the answer.
#[tokio::test(flavor = "multi_thread")]
async fn a_final_response_just_inside_the_bound_wins() {
    let proxy = relaying_with(", no_response_ms=2000");
    let (to_silent, before, after) = invite_relayed(&proxy, "answer-in-time@example.com");
    advance_to(&proxy, before + BOUND - Duration::from_millis(1));
    let _ = proxy.wire();
    answers(&proxy, SILENT, &to_silent, 200, "OK");
    assert_eq!(responses_to_caller(&proxy.wire()), [200]);
    assert_eq!(no_response_due(&proxy, &to_silent), None);

    advance_to(&proxy, after + BOUND * 2);
    assert!(failovers(&proxy.wire(), Method::Invite).is_empty());
}

// ---------------------------------------------------------------------------
// CANCEL only when RFC 3261 §9.1 allows it
// ---------------------------------------------------------------------------

/// The next hop wakes up after the give-up: its first provisional is sent the
/// CANCEL (now allowed), nothing of it reaches the caller, and the `487` that
/// answers the CANCEL is ACKed and absorbed.
#[tokio::test(flavor = "multi_thread")]
async fn a_provisional_after_the_give_up_draws_the_cancel() {
    let proxy = relaying_with(", no_response_ms=2000");
    let (to_silent, _, after) = invite_relayed(&proxy, "late-provisional@example.com");
    advance_to(&proxy, after + BOUND);
    let sent = proxy.wire();
    let to_next = failovers(&sent, Method::Invite);
    assert_eq!(to_next.len(), 1);
    assert!(
        cancels_to(&sent, SILENT).is_empty(),
        "no CANCEL before a provisional"
    );
    assert_eq!(
        waiting_cancels(&proxy),
        1,
        "the CANCEL waits for a provisional"
    );

    answers(&proxy, SILENT, &to_silent, 180, "Ringing");
    let sent = proxy.wire();
    let cancel = the_cancel(&sent, SILENT, &to_silent);
    assert!(
        responses_to_caller(&sent).is_empty(),
        "the late 180 is not forwarded"
    );
    assert_eq!(waiting_cancels(&proxy), 0);

    answers(&proxy, SILENT, &to_silent, 180, "Ringing");
    assert!(cancels_to(&proxy.wire(), SILENT).is_empty(), "one CANCEL");

    answers(&proxy, SILENT, &cancel, 200, "OK");
    answers(&proxy, SILENT, &to_silent, 487, "Request Terminated");
    let sent = proxy.wire();
    assert_eq!(
        requests_to(&sent, SILENT, Method::Ack).len(),
        1,
        "the 487 is ACKed"
    );
    assert!(
        responses_to_caller(&sent).is_empty(),
        "the 487 is not forwarded"
    );

    // The failover branch is the call.
    answers(&proxy, RINGING, &to_next[0], 200, "OK");
    assert_eq!(responses_to_caller(&proxy.wire()), [200]);
}

/// A next hop that never wakes up is never sent a CANCEL: Timer B ends its
/// transaction quietly, without a second failure.
#[tokio::test(flavor = "multi_thread")]
async fn a_next_hop_that_never_answers_is_never_sent_a_cancel() {
    let proxy = relaying_with(", no_response_ms=2000");
    let (to_silent, _, after) = invite_relayed(&proxy, "never-answers@example.com");
    advance_to(&proxy, after + BOUND);
    let to_next = failovers(&proxy.wire(), Method::Invite);
    assert_eq!(to_next.len(), 1);
    // The failover target rings, so it is not retransmitted to either.
    answers(&proxy, RINGING, &to_next[0], 180, "Ringing");
    let _ = proxy.wire();

    advance_to(&proxy, after + Duration::from_secs(33));
    let sent = proxy.wire();
    assert!(cancels_to(&sent, SILENT).is_empty());
    assert!(
        failovers(&sent, Method::Invite).is_empty(),
        "no second failure"
    );
    let key = TransactionManager::key_from_message(&to_silent).expect("a key");
    assert!(!proxy.state.transaction_manager.contains(&key));
    assert_eq!(waiting_cancels(&proxy), 0);
}

// ---------------------------------------------------------------------------
// Something else gives up on the branch first
// ---------------------------------------------------------------------------

/// The caller's CANCEL stops the timer: the branch is not failed a second
/// time, and no `on_failure` retry goes out.
#[tokio::test(flavor = "multi_thread")]
async fn the_callers_cancel_stops_the_timer() {
    let proxy = relaying_with(", no_response_ms=2000");
    let raw =
        super::proxy_cancel_awaits_provisional_tests::caller_invite("caller-cancels@example.com");
    proxy.request(CALLER, &raw);
    let after = Instant::now();
    let to_silent = requests_to(&proxy.wire(), SILENT, Method::Invite)[0].clone();
    assert!(no_response_due(&proxy, &to_silent).is_some());

    caller_cancels(&proxy, &raw);
    let _ = proxy.wire();
    assert_eq!(
        no_response_due(&proxy, &to_silent),
        None,
        "the CANCEL stops it"
    );

    advance_to(&proxy, after + BOUND * 2);
    let sent = proxy.wire();
    assert!(
        failovers(&sent, Method::Invite).is_empty(),
        "no on_failure retry"
    );
    // The INVITE still waits for a provisional to send its CANCEL to (§9.1).
    assert_eq!(waiting_cancels(&proxy), 1);
}

/// Parallel fork: one branch is silent, the other rings and answers. The
/// silent one is failed at the bound without failing the fork, and the `200`
/// is the caller's answer.
#[tokio::test(flavor = "multi_thread")]
async fn a_fork_with_a_silent_branch_is_answered_by_the_other() {
    let proxy = forking_with(&[SILENT, DECIDING], ", no_response_ms=2000");
    let (_, invites) = call(&proxy, "fork-one-silent@example.com");
    let after = Instant::now();
    let (to_silent, to_deciding) = (
        find(&invites, SILENT).clone(),
        find(&invites, DECIDING).clone(),
    );
    answers(&proxy, DECIDING, &to_deciding, 180, "Ringing");
    assert_eq!(responses_to_caller(&proxy.wire()), [180]);

    advance_to(&proxy, after + BOUND);
    let sent = proxy.wire();
    assert!(
        failovers(&sent, Method::Invite).is_empty(),
        "the fork is still open"
    );
    assert!(
        responses_to_caller(&sent).is_empty(),
        "the silent branch's 408 is aggregated"
    );
    assert!(cancels_to(&sent, SILENT).is_empty());
    assert_eq!(no_response_due(&proxy, &to_silent), None);

    answers(&proxy, DECIDING, &to_deciding, 200, "OK");
    let sent = proxy.wire();
    assert_eq!(responses_to_caller(&sent), [200]);
    assert!(
        cancels_to(&sent, SILENT).is_empty(),
        "§9.1: still nothing from it"
    );
}

/// Parallel fork, still open: the given-up branch wakes up. Its provisional
/// draws its CANCEL and is not forwarded, though the fork is still waiting on
/// its other branch; that branch then answers the call.
#[tokio::test(flavor = "multi_thread")]
async fn a_late_provisional_on_an_open_fork_is_cancelled_not_forwarded() {
    let proxy = forking_with(&[SILENT, DECIDING], ", no_response_ms=2000");
    let (_, invites) = call(&proxy, "fork-late-provisional@example.com");
    let after = Instant::now();
    let (to_silent, to_deciding) = (
        find(&invites, SILENT).clone(),
        find(&invites, DECIDING).clone(),
    );
    answers(&proxy, DECIDING, &to_deciding, 180, "Ringing");
    let _ = proxy.wire();
    advance_to(&proxy, after + BOUND);
    let _ = proxy.wire();

    answers(&proxy, SILENT, &to_silent, 183, "Session Progress");
    let sent = proxy.wire();
    the_cancel(&sent, SILENT, &to_silent);
    assert!(
        responses_to_caller(&sent).is_empty(),
        "the given-up branch's 183 is not forwarded: {:?}",
        responses_to_caller(&sent)
    );

    answers(&proxy, DECIDING, &to_deciding, 200, "OK");
    assert_eq!(responses_to_caller(&proxy.wire()), [200]);
}

/// Parallel fork: the other branch answers `200` before the bound. That 2xx
/// stops the silent branch's timer, and its INVITE waits for a provisional to
/// be CANCELled, as any silent branch of a won fork does.
#[tokio::test(flavor = "multi_thread")]
async fn a_2xx_on_another_branch_stops_the_timer() {
    let proxy = forking_with(&[SILENT, DECIDING], ", no_response_ms=2000");
    let (_, invites) = call(&proxy, "fork-won-first@example.com");
    let after = Instant::now();
    let (to_silent, to_deciding) = (
        find(&invites, SILENT).clone(),
        find(&invites, DECIDING).clone(),
    );
    assert!(no_response_due(&proxy, &to_silent).is_some());

    answers(&proxy, DECIDING, &to_deciding, 200, "OK");
    assert_eq!(responses_to_caller(&proxy.wire()), [200]);
    assert_eq!(
        no_response_due(&proxy, &to_silent),
        None,
        "the 2xx stops it"
    );

    advance_to(&proxy, after + BOUND * 2);
    let sent = proxy.wire();
    assert!(failovers(&sent, Method::Invite).is_empty());
    assert!(responses_to_caller(&sent).is_empty());
    assert_eq!(waiting_cancels(&proxy), 1);
}

/// Every branch of a fork silent: each is failed at the bound, and the fork
/// fails into `fork(on_failure=…)`.
#[tokio::test(flavor = "multi_thread")]
async fn a_fork_takes_on_failure_too() {
    let proxy = proxy_running(&format!(
        concat!(
            "from siphon import proxy\n",
            "\n",
            "def failed(request, code, reason):\n",
            "    request.set_header('X-Failure-Seen', f'{{code}} {{reason}}')\n",
            "    request.relay('sip:callee@{ringing}')\n",
            "\n",
            "@proxy.on_request\n",
            "def route(request):\n",
            "    request.fork(['sip:callee@{silent}', 'sip:callee@{deciding}'],\n",
            "                 no_response_ms=2000, on_failure=failed)\n",
        ),
        ringing = RINGING,
        silent = SILENT,
        deciding = DECIDING,
    ));
    let (_, _) = call(&proxy, "fork-all-silent@example.com");
    let after = Instant::now();
    advance_to(&proxy, after + BOUND);
    let to_next = failovers(&proxy.wire(), Method::Invite);
    assert_eq!(to_next.len(), 1, "fork(on_failure=…) ran once");
    assert_eq!(header(&to_next[0], "X-Failure-Seen"), "408 Request Timeout");
}

/// Sequential fork: the silent first target is given up on at the bound and
/// the fork moves straight on to the next.
#[tokio::test(flavor = "multi_thread")]
async fn a_sequential_fork_moves_on_at_the_bound() {
    let proxy = forking_with(
        &[SILENT, DECIDING],
        ", strategy='sequential', no_response_ms=2000",
    );
    let (_, invites) = call(&proxy, "sequential-silent@example.com");
    let after = Instant::now();
    assert_eq!(invites.len(), 1, "one target at a time");

    advance_to(&proxy, after + BOUND);
    let sent = proxy.wire();
    let to_deciding = requests_to(&sent, DECIDING, Method::Invite);
    assert_eq!(
        to_deciding.len(),
        1,
        "the next target is tried at the bound"
    );
    assert!(
        no_response_due(&proxy, &to_deciding[0]).is_some(),
        "and bounded the same way"
    );
    answers(&proxy, DECIDING, &to_deciding[0], 200, "OK");
    assert_eq!(responses_to_caller(&proxy.wire()), [200]);
}

// ---------------------------------------------------------------------------
// The same failure as Timer B / Timer F
// ---------------------------------------------------------------------------

/// What `@proxy.on_failure` was handed when the branch failed.
fn failure_seen(proxy: &Proxy) -> String {
    let to_next = failovers(&proxy.wire(), Method::Invite);
    assert_eq!(to_next.len(), 1, "on_failure ran and failed over");
    header(&to_next[0], "X-Failure-Seen")
}

/// `seen` with every Via branch value taken out: the proxy picks a fresh
/// branch for each relay, so two runs differ there and nowhere else.
fn without_branches(seen: &str) -> String {
    let mut parts = seen.split("branch=");
    let mut out = parts.next().unwrap_or_default().to_string();
    for part in parts {
        let value_end = part.find(['\'', ';', ',', '|', ']']).unwrap_or(part.len());
        out.push_str("branch=");
        out.push_str(&part[value_end..]);
    }
    out
}

/// The bound's `408` and Timer B's `408` are the same failure to the script:
/// same status, reason, source, To, From, CSeq and Via stack.
#[tokio::test(flavor = "multi_thread")]
async fn on_failure_sees_the_bound_exactly_as_it_sees_timer_b() {
    let call_id = "equivalence@example.com";

    let bounded = relaying_with(", no_response_ms=2000");
    let (_, _, after) = invite_relayed(&bounded, call_id);
    advance_to(&bounded, after + BOUND);
    let by_bound = failure_seen(&bounded);

    let unbounded = relaying_with("");
    let (to_silent, _, _) = invite_relayed(&unbounded, call_id);
    fire(&unbounded, &to_silent, TimerName::B);
    let by_timer_b = failure_seen(&unbounded);

    assert!(by_bound.starts_with("408|Request Timeout|"), "{by_bound}");
    // The Via the proxy stamped carries its own branch, which differs between
    // the two runs; everything else is the same failure.
    assert_eq!(without_branches(&by_bound), without_branches(&by_timer_b));
}

/// The same for a non-INVITE against Timer F.
#[tokio::test(flavor = "multi_thread")]
async fn on_failure_sees_the_bound_exactly_as_it_sees_timer_f() {
    let seen = |relay_arguments: &str, fire_timer: &dyn Fn(&Proxy, &SipMessage, Instant)| {
        let proxy = relaying_with(relay_arguments);
        proxy.request(CALLER, &message("equivalence-f@example.com"));
        let after = Instant::now();
        let to_silent = requests_to(&proxy.wire(), SILENT, Method::Message)[0].clone();
        fire_timer(&proxy, &to_silent, after);
        let to_next = failovers(&proxy.wire(), Method::Message);
        assert_eq!(to_next.len(), 1);
        header(&to_next[0], "X-Failure-Seen")
    };
    let by_bound = seen(", no_response_ms=1500", &|proxy, _, after| {
        advance_to(proxy, after + Duration::from_millis(1500));
    });
    let by_timer_f = seen("", &|proxy, to_silent, _| {
        fire(proxy, to_silent, TimerName::F);
    });
    assert!(by_bound.starts_with("408|Request Timeout|"), "{by_bound}");
    assert_eq!(without_branches(&by_bound), without_branches(&by_timer_f));
}

// ---------------------------------------------------------------------------
// Nothing left behind
// ---------------------------------------------------------------------------

/// N branches given up on and N answered leave the timer wheel, the
/// transactions and the sessions where they started.
#[tokio::test(flavor = "multi_thread")]
async fn timed_out_and_answered_branches_leave_nothing_behind() {
    const CALLS: usize = 25;
    let proxy = proxy_running(concat!(
        "from siphon import proxy\n",
        "\n",
        "@proxy.on_request\n",
        "def route(request):\n",
        "    request.relay('sip:callee@198.51.100.12:5060', no_response_ms=2000)\n",
    ));
    let state = &proxy.state;
    let (wheel, transactions) = (state.timer_wheel.len(), state.transaction_manager.count());

    let mut answered = Vec::new();
    for index in 0..CALLS * 2 {
        let (_, invites) = call(&proxy, &format!("leak-{index}@example.com"));
        let to_silent = find(&invites, SILENT).clone();
        if index % 2 == 0 {
            answers(&proxy, SILENT, &to_silent, 200, "OK");
            answered.push(to_silent);
        }
    }
    let after = Instant::now();
    advance_to(&proxy, after + BOUND);
    let sent = proxy.wire();
    assert_eq!(
        sent.iter()
            .filter(|sent| sent.destination == CALLER && sent.message.status_code() == Some(408))
            .count(),
        CALLS,
        "every silent branch is answered 408 upstream"
    );
    assert!(answered
        .iter()
        .all(|request| no_response_due(&proxy, request).is_none()));

    // Past Timer B and Timer D.
    advance_to(&proxy, after + Duration::from_secs(70));
    let _ = proxy.wire();
    assert!(
        !state
            .timer_wheel
            .iter()
            .any(|entry| format!("{:?}", entry.name) == "NoResponse"),
        "no no-response timer left"
    );
    assert_eq!(
        state.timer_wheel.len(),
        wheel,
        "timer wheel back to baseline"
    );
    assert_eq!(
        state.transaction_manager.count(),
        transactions,
        "client transactions back to baseline"
    );
    assert_eq!(waiting_cancels(&proxy), 0);
}
