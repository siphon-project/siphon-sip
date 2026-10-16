//! `transaction.timeout_secs` on the proxy path: Timer F of a relayed
//! non-INVITE request (RFC 3261 §17.1.2.2).
//!
//! A non-INVITE client transaction with no final response when Timer F fires
//! has timed out, and the TU is told so as a `408` (§8.1.3.1). For a proxy that
//! is the branch's final response (§16.7 step 2), so `@proxy.on_failure` gets
//! it and can try the next target. Timer E retransmits the request over UDP
//! until then.
//!
//! The timer wheel runs on [`std::time::Instant`], so the tests move its clock
//! by hand with [`fire_expired_timers_at`] rather than sleeping.

use std::time::{Duration, Instant};

use super::proxy_cancel_awaits_provisional_tests::{
    answers, requests_to, responses_to_caller, CALLER, RINGING, SILENT,
};
use super::proxy_dialog_state_tests::Proxy;
use super::test_dispatcher::test_dispatcher_with_script;
use super::*;
use crate::transaction::timer::TimerConfig;

/// Relays every request to `SILENT` and, on a `408` from that branch, to
/// `RINGING`: the failover an I-CSCF does when an S-CSCF stops answering.
const FAIL_OVER_ON_408: &str = concat!(
    "from siphon import proxy\n",
    "\n",
    "@proxy.on_request\n",
    "def route(request):\n",
    "    request.relay(\"sip:registrar@198.51.100.12:5060\")\n",
    "\n",
    "@proxy.on_failure\n",
    "def failed(request, reply):\n",
    "    if reply.status_code == 408:\n",
    "        request.relay(\"sip:registrar@198.51.100.11:5060\")\n",
    "    else:\n",
    "        request.reply(500, \"Unexpected Failure\")\n",
);

/// A proxy running [`FAIL_OVER_ON_408`] whose transaction layer has
/// `timeout_secs` (`None`: unset) as `transaction.timeout_secs`.
fn failing_over_proxy(timeout_secs: Option<u32>) -> Proxy {
    let transaction: crate::config::TransactionConfig = serde_yaml_ng::from_str(
        &timeout_secs.map_or("{}".to_string(), |secs| format!("timeout_secs: {secs}")),
    )
    .expect("the transaction block parses");
    let timers: TimerConfig = transaction_timers(Some(&transaction));
    let mut dispatcher = test_dispatcher_with_script(FAIL_OVER_ON_408);
    dispatcher.state.transaction_manager = Arc::new(TransactionManager::new(timers));
    Proxy {
        state: Arc::new(dispatcher.state),
        udp: dispatcher.udp,
    }
}

fn register(call_id: &str) -> String {
    format!(
        concat!(
            "REGISTER sip:example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP {caller};branch=z9hG4bK-{call_id}\r\n",
            "Max-Forwards: 70\r\n",
            "From: <sip:alice@example.com>;tag=alice-tag\r\n",
            "To: <sip:alice@example.com>\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: 1 REGISTER\r\n",
            "Contact: <sip:alice@{caller}>\r\n",
            "Expires: 600\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        caller = CALLER,
        call_id = call_id,
    )
}

/// When timer `name` of the client transaction that sent `request` fires, if
/// it is running.
fn fires_at(proxy: &Proxy, request: &SipMessage, name: TimerName) -> Option<Instant> {
    let key = TransactionManager::key_from_message(request).expect("a transaction key");
    proxy
        .state
        .timer_wheel
        .get(&format!("{}:{:?}", key, name))
        .map(|entry| entry.fires_at)
}

/// Move the timer wheel's clock to `now`.
fn advance_to(proxy: &Proxy, now: Instant) {
    tokio::task::block_in_place(|| fire_expired_timers_at(&proxy.state, now));
}

/// The caller registers; returns the REGISTER `SILENT` was sent, and the
/// moments just before and after it was relayed.
fn caller_registers(proxy: &Proxy, call_id: &str) -> (SipMessage, Instant, Instant) {
    let before = Instant::now();
    proxy.request(CALLER, &register(call_id));
    let after = Instant::now();
    let relayed = requests_to(&proxy.wire(), SILENT, Method::Register);
    assert_eq!(
        relayed.len(),
        1,
        "the REGISTER is relayed to the first target"
    );
    (relayed[0].clone(), before, after)
}

/// The configured timeout ends the silent branch as a `408` the script's
/// failure handler sees, in time to register with the next target. Until then
/// Timer E retransmits the REGISTER, and nothing is decided.
#[tokio::test(flavor = "multi_thread")]
async fn a_register_to_a_silent_next_hop_fails_over_at_the_configured_timeout() {
    let proxy = failing_over_proxy(Some(2));
    let (to_silent, before, after) = caller_registers(&proxy, "timeout-failover@example.com");

    let timeout_at = fires_at(&proxy, &to_silent, TimerName::F).expect("Timer F runs");
    assert!(
        timeout_at >= before + Duration::from_secs(2)
            && timeout_at <= after + Duration::from_secs(2),
        "Timer F is the configured 2 s, not 64*T1"
    );

    // Timer E: T1, then 2*T1, retransmitting the request as it left.
    let mut retransmits = 0;
    while let Some(due) = fires_at(&proxy, &to_silent, TimerName::E) {
        if due >= timeout_at {
            break;
        }
        advance_to(&proxy, due);
        let sent = proxy.wire();
        let again = requests_to(&sent, SILENT, Method::Register);
        assert_eq!(again.len(), 1, "Timer E retransmits the REGISTER");
        assert_eq!(again[0].to_bytes(), to_silent.to_bytes());
        assert!(responses_to_caller(&sent).is_empty());
        retransmits += 1;
    }
    assert_eq!(retransmits, 2, "retransmitted at T1 and 2*T1 inside 2 s");

    advance_to(&proxy, timeout_at - Duration::from_millis(1));
    let sent = proxy.wire();
    assert!(requests_to(&sent, RINGING, Method::Register).is_empty());
    assert!(responses_to_caller(&sent).is_empty());

    advance_to(&proxy, timeout_at);
    let sent = proxy.wire();
    let to_next = requests_to(&sent, RINGING, Method::Register);
    assert_eq!(to_next.len(), 1, "on_failure saw the 408 and failed over");
    assert!(
        responses_to_caller(&sent).is_empty(),
        "the 408 is the branch's, not the caller's"
    );
    assert_eq!(fires_at(&proxy, &to_silent, TimerName::E), None);
    assert_eq!(fires_at(&proxy, &to_silent, TimerName::F), None);

    answers(&proxy, RINGING, &to_next[0], 200, "OK");
    assert_eq!(responses_to_caller(&proxy.wire()), [200]);
}

/// Without `timeout_secs` Timer F is 64*T1: the branch is still waited for at
/// 5 s, and fails over at 32 s.
#[tokio::test(flavor = "multi_thread")]
async fn without_a_configured_timeout_a_silent_next_hop_is_given_64_t1() {
    let proxy = failing_over_proxy(None);
    let (to_silent, before, after) = caller_registers(&proxy, "default-timeout@example.com");

    let timeout_at = fires_at(&proxy, &to_silent, TimerName::F).expect("Timer F runs");
    assert!(
        timeout_at >= before + Duration::from_secs(32)
            && timeout_at <= after + Duration::from_secs(32),
        "Timer F is 64*T1"
    );

    advance_to(&proxy, after + Duration::from_secs(5));
    let sent = proxy.wire();
    assert!(requests_to(&sent, RINGING, Method::Register).is_empty());
    assert!(responses_to_caller(&sent).is_empty());

    advance_to(&proxy, timeout_at);
    let to_next = requests_to(&proxy.wire(), RINGING, Method::Register);
    assert_eq!(to_next.len(), 1, "fails over at 64*T1");
}

/// A final response that arrives just inside the timeout is the answer: the
/// caller gets it, and the timeout that would have come never fails it over.
#[tokio::test(flavor = "multi_thread")]
async fn a_response_just_before_the_timeout_wins() {
    let proxy = failing_over_proxy(Some(2));
    let (to_silent, _, _) = caller_registers(&proxy, "answer-in-time@example.com");
    let timeout_at = fires_at(&proxy, &to_silent, TimerName::F).expect("Timer F runs");

    advance_to(&proxy, timeout_at - Duration::from_millis(1));
    let _ = proxy.wire();
    answers(&proxy, SILENT, &to_silent, 200, "OK");
    assert_eq!(responses_to_caller(&proxy.wire()), [200]);
    assert_eq!(
        fires_at(&proxy, &to_silent, TimerName::F),
        None,
        "the final response stops Timer F"
    );

    advance_to(&proxy, timeout_at + Duration::from_secs(1));
    let sent = proxy.wire();
    assert!(requests_to(&sent, RINGING, Method::Register).is_empty());
    assert!(responses_to_caller(&sent).is_empty());
}

/// A request siphon sends itself and waits on (an OPTIONS probe, a SUBSCRIBE)
/// is a non-INVITE transaction too: the sweep tells a waiter still without a
/// response that it timed out once the configured Timer F has passed, and not
/// before.
#[tokio::test(flavor = "multi_thread")]
async fn a_request_siphon_sends_itself_times_out_at_the_configured_timeout() {
    let proxy = failing_over_proxy(Some(2));
    let mut receiver = proxy.state.uac_sender.send_options(
        SILENT.parse().expect("a literal address"),
        Transport::Udp,
        crate::sip::uri::SipUri::new("198.51.100.12".to_string()),
    );
    assert_eq!(requests_to(&proxy.wire(), SILENT, Method::Options).len(), 1);

    proxy
        .state
        .uac_sender
        .age_pending(Duration::from_millis(1900));
    sweep_stale_entries(&proxy.state).await;
    assert!(receiver.try_recv().is_err(), "still waiting inside 2 s");
    assert_eq!(proxy.state.uac_sender.pending_count(), 1);

    proxy
        .state
        .uac_sender
        .age_pending(Duration::from_millis(200));
    sweep_stale_entries(&proxy.state).await;
    assert!(matches!(
        receiver.try_recv(),
        Ok(crate::uac::UacResult::Timeout)
    ));
    assert_eq!(proxy.state.uac_sender.pending_count(), 0);
}
