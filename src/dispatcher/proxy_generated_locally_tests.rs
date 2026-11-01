//! `reply.generated_locally`: a script told a branch failed with a `408` can
//! tell the one siphon synthesized (Timer B, Timer F, `no_response_ms`) from
//! one the next hop sent. Status and reason are the same for both.

use std::time::{Duration, Instant};

use super::proxy_cancel_awaits_provisional_tests::{
    answers, call, fire, requests_to, CALLER, DECIDING, RINGING, SILENT,
};
use super::proxy_dialog_state_tests::{find, header, Proxy};
use super::test_dispatcher::test_dispatcher_with_script;
use super::*;

const FAILURE: &str = concat!(
    "@proxy.on_failure\n",
    "def failed(request, reply):\n",
    "    request.set_header('X-Local', str(reply.generated_locally))\n",
    "    request.relay('sip:callee@198.51.100.11:5060')\n",
);

fn proxy_with(route: &str) -> Proxy {
    let script = format!(
        "from siphon import proxy\n\n@proxy.on_request\ndef route(request):\n    {route}\n\n{FAILURE}"
    );
    let dispatcher = test_dispatcher_with_script(&script);
    Proxy {
        state: Arc::new(dispatcher.state),
        udp: dispatcher.udp,
    }
}

fn relaying(arguments: &str) -> Proxy {
    proxy_with(&format!("request.relay('sip:callee@{SILENT}'{arguments})"))
}

fn forking(arguments: &str) -> Proxy {
    proxy_with(&format!(
        "request.fork(['sip:callee@{SILENT}', 'sip:callee@{DECIDING}']{arguments})"
    ))
}

fn advance(proxy: &Proxy, now: Instant) {
    tokio::task::block_in_place(|| fire_expired_timers_at(&proxy.state, now));
}

/// What `on_failure` saw, read off the retry it sent.
fn local_seen(proxy: &Proxy) -> String {
    let retries = requests_to(&proxy.wire(), RINGING, Method::Invite);
    assert_eq!(retries.len(), 1, "on_failure ran once and failed over");
    header(&retries[0], "X-Local")
}

#[tokio::test(flavor = "multi_thread")]
async fn the_no_response_deadline_is_generated_locally() {
    let proxy = relaying(", no_response_ms=2000");
    call(&proxy, "gl-bound@example.com");
    advance(&proxy, Instant::now() + Duration::from_secs(2));
    assert_eq!(local_seen(&proxy), "True");
}

#[tokio::test(flavor = "multi_thread")]
async fn timer_b_is_generated_locally() {
    let proxy = relaying("");
    let (_, invites) = call(&proxy, "gl-timer-b@example.com");
    fire(&proxy, find(&invites, SILENT), TimerName::B);
    assert_eq!(local_seen(&proxy), "True");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_408_from_the_next_hop_is_not() {
    let proxy = relaying(", no_response_ms=2000");
    let (_, invites) = call(&proxy, "gl-received@example.com");
    answers(
        &proxy,
        SILENT,
        find(&invites, SILENT),
        408,
        "Request Timeout",
    );
    assert_eq!(local_seen(&proxy), "False");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_fork_whose_best_failure_is_local_says_so() {
    let proxy = forking(", no_response_ms=2000");
    call(&proxy, "gl-fork-local@example.com");
    advance(&proxy, Instant::now() + Duration::from_secs(2));
    assert_eq!(local_seen(&proxy), "True");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_fork_whose_best_failure_was_received_says_not() {
    let proxy = forking(", no_response_ms=2000");
    let (_, invites) = call(&proxy, "gl-fork-received@example.com");
    answers(&proxy, DECIDING, find(&invites, DECIDING), 404, "Not Found");
    advance(&proxy, Instant::now() + Duration::from_secs(2));
    assert_eq!(local_seen(&proxy), "False");
}

#[tokio::test(flavor = "multi_thread")]
async fn timer_f_is_generated_locally() {
    let proxy = relaying("");
    let message = format!(
        concat!(
            "MESSAGE sip:callee@example.com SIP/2.0\r\n",
            "Via: SIP/2.0/UDP {caller};branch=z9hG4bKglf\r\n",
            "From: <sip:alice@example.com>;tag=glf\r\n",
            "To: <sip:callee@example.com>\r\n",
            "Call-ID: gl-timer-f@example.com\r\n",
            "CSeq: 1 MESSAGE\r\n",
            "Max-Forwards: 70\r\n",
            "Content-Type: text/plain\r\n",
            "Content-Length: 2\r\n\r\nhi"
        ),
        caller = CALLER
    );
    proxy.request(CALLER, &message);
    let sent = requests_to(&proxy.wire(), SILENT, Method::Message);
    fire(&proxy, &sent[0], TimerName::F);
    let retries = requests_to(&proxy.wire(), RINGING, Method::Message);
    assert_eq!(retries.len(), 1);
    assert_eq!(header(&retries[0], "X-Local"), "True");
}
