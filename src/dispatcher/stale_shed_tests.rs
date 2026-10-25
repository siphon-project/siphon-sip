//! Age-based load shedding: an initial request that waited in the script
//! executor's queue past its budget is answered `503 Service Unavailable` with a
//! `Retry-After` through a server transaction, and the script never sees it.
//! In-dialog requests, ACKs and requests under the budget run as before.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use super::ipsec_lifecycle_tests::{install, p_cscf, ANSWER};
use super::proxy_dialog_state_tests::inbound;
use super::test_dispatcher::test_dispatcher_with_script;
use super::*;
use prometheus::Encoder;

/// The UE / phone the requests come from.
const PHONE: &str = "198.51.100.40:5070";

/// Past the default budget.
const STALE: Duration = Duration::from_secs(9);

/// A dispatcher answering every request 200 from its script, on fast timers
/// so a test can run its transactions to completion.
struct Node {
    state: Arc<DispatcherState>,
    udp: flume::Receiver<OutboundMessage>,
}

fn node_with_budget(budget: Duration) -> Node {
    let mut dispatcher = test_dispatcher_with_script(ANSWER);
    dispatcher.state.transaction_manager = Arc::new(TransactionManager::new(TimerConfig::new(
        Duration::from_millis(2),
        Duration::from_millis(8),
        Duration::from_millis(10),
    )));
    dispatcher.state.stale_request_budget = budget;
    Node {
        state: Arc::new(dispatcher.state),
        udp: dispatcher.udp,
    }
}

fn node() -> Node {
    node_with_budget(stale_shed::STALE_REQUEST_BUDGET)
}

impl Node {
    /// Hand the dispatcher `raw` from `source` as a job that queued `waited`.
    fn deliver_from(&self, source: &str, raw: &str, waited: Duration) {
        tokio::task::block_in_place(|| {
            inbound::handle_inbound_after_queue(inbound(source, raw), waited, &self.state)
        });
    }

    fn deliver(&self, raw: &str, waited: Duration) {
        self.deliver_from(PHONE, raw, waited);
    }

    fn sent(&self) -> Vec<SipMessage> {
        let mut sent = Vec::new();
        while let Ok(outbound) = self.udp.try_recv() {
            for frame in outbound.frames() {
                sent.push(
                    parse_sip_message_bytes(frame).expect("siphon sent a message that parses"),
                );
            }
        }
        sent
    }

    fn codes(&self) -> Vec<u16> {
        self.sent()
            .iter()
            .filter_map(SipMessage::status_code)
            .collect()
    }

    /// Fire every transaction timer due within the next hour, until none is
    /// left that schedules another.
    fn run_timers_out(&self) {
        for _ in 0..16 {
            tokio::task::block_in_place(|| {
                fire_expired_timers_at(&self.state, Instant::now() + Duration::from_secs(3600))
            });
        }
    }
}

/// An out-of-dialog request: no To tag.
fn request(method: &str, branch: &str) -> String {
    format!(
        concat!(
            "{method} sip:ims.example.invalid SIP/2.0\r\n",
            "Via: SIP/2.0/UDP {phone};branch=z9hG4bK-{branch}\r\n",
            "Max-Forwards: 70\r\n",
            "From: <sip:001010000000001@ims.example.invalid>;tag=ue-tag\r\n",
            "To: <sip:001010000000001@ims.example.invalid>\r\n",
            "Call-ID: {branch}@ue\r\n",
            "CSeq: 1 {method}\r\n",
            "Contact: <sip:001010000000001@{phone}>\r\n",
            "Expires: 600000\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        method = method,
        phone = PHONE,
        branch = branch,
    )
}

/// An in-dialog request: a To tag.
fn in_dialog(method: &str, branch: &str) -> String {
    request(method, branch).replace(
        "To: <sip:001010000000001@ims.example.invalid>\r\n",
        "To: <sip:001010000000001@ims.example.invalid>;tag=far-tag\r\n",
    )
}

/// The ACK for a non-2xx final response to the INVITE on `branch`.
fn ack(branch: &str) -> String {
    request("ACK", branch)
}

fn assert_shed(response: &SipMessage, waited: Duration) {
    assert_eq!(response.status_code(), Some(503), "{response:?}");
    let retry_after: u64 = response
        .headers
        .get("Retry-After")
        .expect("a 503 for overload carries Retry-After")
        .trim()
        .parse()
        .expect("Retry-After is delta-seconds");
    let base = waited.as_secs().max(1);
    assert!(
        (base..=base + base / 2).contains(&retry_after),
        "Retry-After {retry_after} is the queue wait {base} plus at most half again"
    );
    assert!(
        response.headers.get("Expires").is_none(),
        "a refused REGISTER is granted no Expires"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_register_queued_past_the_budget_is_answered_503_and_never_reaches_the_script() {
    let node = node();
    node.deliver(&request("REGISTER", "stale-register"), STALE);
    let sent = node.sent();
    assert_eq!(sent.len(), 1, "one answer and nothing else: {sent:?}");
    // The script answers 200 to everything, so a 503 means it never ran.
    assert_shed(&sent[0], STALE);
}

#[tokio::test(flavor = "multi_thread")]
async fn every_initial_request_kind_is_shed_past_the_budget() {
    let node = node();
    for method in ["INVITE", "OPTIONS", "SUBSCRIBE", "MESSAGE", "PUBLISH"] {
        node.deliver(
            &request(method, &format!("stale-{}", method.to_lowercase())),
            STALE,
        );
        assert_eq!(node.codes(), [503], "{method} is shed");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_request_under_the_budget_runs_the_script() {
    let node = node();
    node.deliver(
        &request("REGISTER", "fresh-register"),
        stale_shed::STALE_REQUEST_BUDGET - Duration::from_millis(1),
    );
    assert_eq!(node.codes(), [200]);
    node.deliver(&request("OPTIONS", "fresh-options"), Duration::ZERO);
    assert_eq!(node.codes(), [200]);
}

/// A BYE, and any in-dialog request, runs however long it queued: it is the
/// cheap work that releases a dialog, and a shed one leaves it dangling.
#[tokio::test(flavor = "multi_thread")]
async fn an_in_dialog_bye_queued_past_the_budget_still_runs() {
    let node = node();
    let long_past = Duration::from_secs(30);
    node.deliver(&in_dialog("BYE", "stale-bye"), long_past);
    assert_eq!(node.codes(), [200], "the BYE reached the script");

    for method in ["INVITE", "UPDATE", "INFO", "NOTIFY", "OPTIONS"] {
        node.deliver(
            &in_dialog(
                method,
                &format!("stale-in-dialog-{}", method.to_lowercase()),
            ),
            long_past,
        );
        assert_eq!(node.codes(), [200], "in-dialog {method} reached the script");
    }

    // A BYE is never shed, even one missing its To tag.
    node.deliver(&request("BYE", "stale-bye-no-tag"), long_past);
    assert_eq!(node.codes(), [200]);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_ack_is_never_answered_however_long_it_queued() {
    let node = node();
    // A stray ACK: matches nothing, never answered.
    node.deliver(&ack("stale-stray-ack"), Duration::from_secs(30));
    assert!(node.sent().is_empty(), "nothing answers an ACK");

    // The ACK for a shed INVITE's 503 is absorbed by its transaction.
    node.deliver(&request("INVITE", "stale-acked"), STALE);
    assert_eq!(node.codes(), [503]);
    node.deliver(&ack("stale-acked"), Duration::from_secs(30));
    assert!(node.sent().is_empty(), "the ACK for the 503 is absorbed");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_cancel_is_never_shed() {
    let node = node();
    // A CANCEL for nothing is answered 481 by the framework, as before; a
    // 503 would tell the client to retry a cancel of a request it never sent.
    node.deliver(&request("CANCEL", "stale-cancel"), Duration::from_secs(30));
    assert_eq!(node.codes(), [481]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_retransmission_of_a_shed_request_gets_the_same_503_from_the_transaction() {
    let node = node();
    let raw = request("REGISTER", "stale-resent");
    node.deliver(&raw, STALE);
    let first = node.sent();
    assert_eq!(first.len(), 1);
    assert_shed(&first[0], STALE);

    // Fresh or stale, the resend is answered from the cached 503: the script
    // never runs for it, and the Retry-After is the one already sent.
    for waited in [Duration::ZERO, Duration::from_secs(20)] {
        node.deliver(&raw, waited);
        let again = node.sent();
        assert_eq!(again.len(), 1, "{again:?}");
        assert_eq!(again[0].to_bytes(), first[0].to_bytes(), "the same 503");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_shed_is_counted_by_method() {
    crate::metrics::init().expect("the metrics build");
    let node = node();
    let before = crate::metrics::stale_shed::shed(&Method::Message).expect("metrics are up");
    let queue_full_before = crate::metrics::try_metrics()
        .map(|metrics| metrics.pyexec_jobs_shed_total.get())
        .expect("metrics are up");

    node.deliver(&request("MESSAGE", "counted-1"), STALE);
    node.deliver(&request("MESSAGE", "counted-2"), STALE);
    // Under the budget, and in-dialog: not counted.
    node.deliver(&request("MESSAGE", "counted-fresh"), Duration::ZERO);
    node.deliver(&in_dialog("MESSAGE", "counted-in-dialog"), STALE);
    node.sent();

    let after = crate::metrics::stale_shed::shed(&Method::Message).expect("metrics are up");
    assert_eq!(after - before, 2, "two MESSAGEs shed for age");

    let exposition = crate::metrics::try_metrics()
        .map(|metrics| {
            let mut text = Vec::new();
            prometheus::TextEncoder::new()
                .encode(&metrics.registry.gather(), &mut text)
                .expect("the exposition encodes");
            String::from_utf8(text).expect("UTF-8")
        })
        .expect("metrics are up");
    assert!(
        exposition.contains("siphon_pyexec_stale_requests_shed_total{method=\"MESSAGE\"}"),
        "the counter is exposed with its method label"
    );
    // An age-shed is not a queue-full shed. Other tests share the process,
    // so this reads only that the age-shed path does not bump it.
    let queue_full_after = crate::metrics::try_metrics()
        .map(|metrics| metrics.pyexec_jobs_shed_total.get())
        .expect("metrics are up");
    assert!(queue_full_after >= queue_full_before);
}

#[test]
fn retry_after_is_the_queue_wait_plus_a_spread_from_the_call_id() {
    for waited in [
        Duration::from_millis(8_001),
        Duration::from_secs(9),
        Duration::from_secs(27),
        Duration::from_secs(300),
    ] {
        let base = (waited.as_secs() + u64::from(waited.subsec_nanos() > 0)).min(32);
        let mut spread = std::collections::HashSet::new();
        for call in 0..64 {
            let value = stale_shed::retry_after_secs(waited, &format!("call-{call}@ue"));
            assert!(
                (base..=base + base / 2).contains(&value),
                "{value} for a {waited:?} wait"
            );
            spread.insert(value);
        }
        assert!(
            spread.len() > 1,
            "clients shed together do not all come back together"
        );
        assert_eq!(
            stale_shed::retry_after_secs(waited, "same@ue"),
            stale_shed::retry_after_secs(waited, "same@ue"),
            "deterministic per Call-ID"
        );
    }
}

/// Leak gate: after a storm of shed requests, every server transaction and
/// every transaction timer they started is gone once the timers run out, and
/// so is the ACK-absorbing state of the INVITEs.
#[tokio::test(flavor = "multi_thread")]
async fn a_shed_storm_leaves_no_transaction_or_timer_behind() {
    let node = node();
    let transactions_before = node.state.transaction_manager.count();
    let timers_before = node.state.timer_wheel.len();

    for index in 0..300 {
        let method = ["REGISTER", "INVITE", "OPTIONS"][index % 3];
        let branch = format!("storm-{index}");
        node.deliver(&request(method, &branch), STALE);
        // A retransmission of each, and the ACK for half the INVITEs.
        node.deliver(&request(method, &branch), Duration::ZERO);
        if method == "INVITE" && index % 2 == 0 {
            node.deliver(&ack(&branch), STALE);
        }
    }
    let codes = node.codes();
    assert_eq!(codes.len(), 600, "every request and resend answered");
    assert!(codes.iter().all(|code| *code == 503));
    assert!(node.state.transaction_manager.count() > transactions_before);

    node.run_timers_out();
    node.sent();
    assert_eq!(
        node.state.transaction_manager.count(),
        transactions_before,
        "every shed request's transaction ended"
    );
    assert_eq!(
        node.state.timer_wheel.len(),
        timers_before,
        "every timer they started is gone"
    );
}

/// End to end on a one-worker executor: a handler holds the worker, requests
/// queue behind it, and once it lets go the initial request that waited past
/// the budget is answered 503 while the in-dialog BYE that waited as long, and
/// a request that came in after the backlog cleared, run their script.
#[tokio::test(flavor = "multi_thread")]
async fn on_a_saturated_executor_a_request_queued_past_the_budget_is_shed() {
    pyo3::Python::initialize();
    let node = node_with_budget(Duration::from_millis(100));
    let pool = crate::script::py_executor::test_pool(tokio::runtime::Handle::current(), 1);

    let (held_tx, held_rx) = std::sync::mpsc::channel::<()>();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    crate::script::py_executor::spawn_with_queue_wait_on(&pool, move |_| {
        let _ = held_tx.send(());
        let _ = release_rx.recv();
    });
    held_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("the blocking handler took the worker");

    let queue = |raw: String| {
        let state = Arc::clone(&node.state);
        crate::script::py_executor::spawn_with_queue_wait_on(&pool, move |waited| {
            inbound::handle_inbound_after_queue(inbound(PHONE, &raw), waited, &state);
        });
    };
    queue(request("REGISTER", "queued-register"));
    queue(in_dialog("BYE", "queued-bye"));
    tokio::time::sleep(Duration::from_millis(300)).await;
    let _ = release_tx.send(());

    let mut answers: Vec<(String, u16)> = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    while answers.len() < 2 && Instant::now() < deadline {
        if let Ok(outbound) = node.udp.recv_timeout(Duration::from_millis(50)) {
            for frame in outbound.frames() {
                let message = parse_sip_message_bytes(frame).expect("a message");
                let method = message
                    .headers
                    .cseq()
                    .and_then(|cseq| cseq.split_whitespace().nth(1).map(str::to_string))
                    .unwrap_or_default();
                answers.push((method, message.status_code().unwrap_or_default()));
            }
        }
    }

    // The backlog has cleared: a new request runs.
    queue(request("OPTIONS", "after-backlog"));
    let mut after = None;
    let deadline = Instant::now() + Duration::from_secs(10);
    while after.is_none() && Instant::now() < deadline {
        if let Ok(outbound) = node.udp.recv_timeout(Duration::from_millis(50)) {
            after = outbound
                .frames()
                .next()
                .and_then(|frame| parse_sip_message_bytes(frame).ok())
                .and_then(|message| message.status_code());
        }
    }
    drop(pool);

    answers.sort();
    assert_eq!(
        answers,
        [("BYE".to_string(), 200), ("REGISTER".to_string(), 503)],
        "the stale REGISTER is shed, the BYE that waited as long runs"
    );
    assert_eq!(after, Some(200), "a request that did not queue runs");
}

/// A REGISTER from a UE over its security association, shed for its age: the
/// 503 and its retransmission leave over the SA, from the P-CSCF's protected
/// client port to the UE's protected server port (TS 33.203 clause 7.1, UDP
/// case), through the same egress as every response.
#[tokio::test(flavor = "multi_thread")]
async fn a_shed_protected_register_is_answered_over_the_security_association() {
    let (proxy, manager) = p_cscf(ANSWER);
    let ue: SocketAddr = "198.51.100.140:6100".parse().expect("an address");
    install(&manager, ue).await;

    let raw = format!(
        concat!(
            "REGISTER sip:ims.example.invalid SIP/2.0\r\n",
            "Via: SIP/2.0/UDP {host}:{port_s};branch=z9hG4bK-protected-140;rport\r\n",
            "Max-Forwards: 70\r\n",
            "From: <sip:001010000000001@ims.example.invalid>;tag=ue-tag\r\n",
            "To: <sip:001010000000001@ims.example.invalid>\r\n",
            "Call-ID: protected-140@ue\r\n",
            "CSeq: 2 REGISTER\r\n",
            "Contact: <sip:001010000000001@{host}:{port_s}>\r\n",
            "Expires: 600000\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        host = ue.ip(),
        port_s = ue.port() + 1,
    );
    let source = ue.to_string();
    for waited in [STALE, Duration::ZERO] {
        tokio::task::block_in_place(|| {
            inbound::handle_inbound_after_queue(inbound(&source, &raw), waited, &proxy.state)
        });
    }

    let mut answers = Vec::new();
    while let Ok(outbound) = proxy.udp.try_recv() {
        for frame in outbound.frames() {
            let message = parse_sip_message_bytes(frame).expect("a message");
            answers.push((
                message.status_code(),
                outbound.destination,
                outbound.source_local_addr,
                outbound.transport,
            ));
        }
    }
    let protected = (
        Some(503),
        SocketAddr::new(ue.ip(), ue.port() + 1),
        Some("192.0.2.1:5064".parse().expect("an address")),
        Transport::Udp,
    );
    assert_eq!(
        answers,
        [protected, protected],
        "the 503 and its retransmission go from the protected client port to the UE's protected server port"
    );
}
