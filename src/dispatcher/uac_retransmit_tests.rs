//! The requests the UAC sender originates under the dispatcher's client
//! transactions (RFC 3261 §17.1.2.2): over UDP retransmitted on Timer E from
//! T1 doubling to T2, at T2 once a provisional response has come, byte for
//! byte and from the same socket; ended by a final response, or by Timer F,
//! which whoever waits for the final response hears as a timeout; held for
//! Timer K so a repeat of the final response is absorbed; over a reliable
//! transport sent exactly once. And nothing is left behind either way.
//!
//! The peer here is the receiving end of the egress channels: a copy the test
//! reads and does not answer is a datagram the network lost.

use super::subscribe_test_harness::subscribe_harness;
use super::test_dispatcher::{test_dispatcher, TestDispatcher};
use super::*;
use crate::uac::{UacResult, UacSender};
use std::collections::HashMap;
use std::time::{Duration, Instant};

const T1: Duration = Duration::from_millis(500);
const T2: Duration = Duration::from_secs(4);
const T4: Duration = Duration::from_secs(5);

const PEER: &str = "192.0.2.30:5060";

fn peer() -> SocketAddr {
    PEER.parse().expect("a literal address")
}

/// A dispatcher whose UAC sender sends under its transaction layer, as
/// `dispatcher::run` attaches it, with the receiving end of the UDP and the
/// TCP egress.
struct Setup {
    dispatcher: TestDispatcher,
    udp: flume::Receiver<OutboundMessage>,
    tcp: flume::Receiver<OutboundMessage>,
}

impl Setup {
    fn new() -> Self {
        let mut dispatcher = test_dispatcher();
        let (udp_sender, udp) = flume::unbounded();
        let (tcp_sender, tcp) = flume::unbounded();
        let (other, _) = flume::unbounded();
        let outbound = Arc::new(OutboundRouter {
            udp: udp_sender.into(),
            udp_by_local: HashMap::new(),
            udp_dynamic: None,
            tcp: tcp_sender,
            tls: other.clone(),
            ws: other.clone(),
            wss: other.clone(),
            sctp: Some(other),
        });
        dispatcher.state.outbound = Arc::clone(&outbound);
        dispatcher.state.uac_sender = Arc::new(UacSender::new(
            outbound,
            dispatcher.state.local_addr,
            HashMap::new(),
            HashMap::new(),
            None,
            None,
            Arc::clone(&dispatcher.state.identity),
        ));
        attach_uac_transactions(&dispatcher.state);
        Self {
            dispatcher,
            udp,
            tcp,
        }
    }

    fn state(&self) -> &DispatcherState {
        &self.dispatcher.state
    }

    fn uac(&self) -> &UacSender {
        &self.dispatcher.state.uac_sender
    }

    /// When timer `name` of the transaction of `request` fires.
    fn timer(&self, request: &SipMessage, name: TimerName) -> Option<Instant> {
        let key = TransactionManager::key_from_message(request).expect("a key");
        self.state()
            .timer_wheel
            .iter()
            .find(|entry| entry.key == key && entry.name == name)
            .map(|entry| entry.fires_at)
    }

    fn fire(&self, at: Instant) {
        fire_expired_timers_at(self.state(), at);
    }

    /// Deliver the response `status` to `request` as received from the peer.
    fn answer(&self, request: &SipMessage, status: &str) {
        let raw = response_to(request, status);
        let response = parse_sip_message_bytes(raw.as_bytes()).expect("a response that parses");
        let code = response.status_code().expect("a status code");
        let inbound = InboundMessage {
            client_transport: None,
            connection_id: ConnectionId::default(),
            transport: Transport::Udp,
            local_addr: self.state().local_addr,
            remote_addr: peer(),
            data: Bytes::from(raw),
        };
        handle_response(inbound, response, code, self.state());
    }

    fn transactions(&self) -> usize {
        self.state().transaction_manager.count()
    }

    /// Nothing of any request is left: no transaction, no timer, no waiter.
    fn assert_drained(&self) {
        assert_eq!(self.transactions(), 0, "transactions");
        assert_eq!(self.state().timer_wheel.len(), 0, "timers");
        assert_eq!(self.uac().pending_count(), 0, "pending responses");
    }
}

/// A request of `method` as the script API builds one: a UAC branch on a Via
/// naming `transport`.
fn request_on(method: &str, transport: &str, branch: &str) -> SipMessage {
    let raw = format!(
        concat!(
            "{method} sip:001010123456789@192.0.2.30:5060 SIP/2.0\r\n",
            "Via: SIP/2.0/{transport} 192.0.2.1:5060;branch={branch}\r\n",
            "From: <sip:siphon@siphon.example.com>;tag=notifier\r\n",
            "To: <sip:001010123456789@siphon.example.com>;tag=watcher\r\n",
            "Call-ID: {branch}@siphon.example.com\r\n",
            "CSeq: 7 {method}\r\n",
            "Max-Forwards: 70\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        method = method,
        transport = transport,
        branch = branch,
    );
    parse_sip_message_bytes(raw.as_bytes()).expect("a request that parses")
}

fn notify(branch: &str) -> SipMessage {
    request_on("NOTIFY", "UDP", branch)
}

fn response_to(request: &SipMessage, status: &str) -> String {
    let header = |name: &str| request.headers.get(name).cloned().expect(name);
    format!(
        concat!(
            "SIP/2.0 {status}\r\n",
            "Via: {via}\r\n",
            "From: {from}\r\n",
            "To: {to}\r\n",
            "Call-ID: {call_id}\r\n",
            "CSeq: {cseq}\r\n",
            "Content-Length: 0\r\n",
            "\r\n",
        ),
        status = status,
        via = header("Via"),
        from = header("From"),
        to = header("To"),
        call_id = header("Call-ID"),
        cseq = header("CSeq"),
    )
}

fn assert_retransmission_of(first: &OutboundMessage, again: &OutboundMessage) {
    assert_eq!(
        again.data, first.data,
        "a retransmission is the same octets: same branch, same CSeq"
    );
    assert_eq!(again.destination, first.destination);
    assert_eq!(again.transport, first.transport);
    assert_eq!(again.source_local_addr, first.source_local_addr);
    assert_eq!(again.connection_id, first.connection_id);
}

/// `timer` was set `expected` after it was armed. `since` is an instant taken
/// just before the call that armed it, and now is after that call, so the
/// timer lies between the two plus `expected` however slowly the test runs.
fn assert_set(timer: Instant, since: Instant, expected: Duration, name: &str) {
    assert!(
        since + expected <= timer && timer <= Instant::now() + expected,
        "{name} set {:?} after it was armed, expected {expected:?}",
        timer.saturating_duration_since(since),
    );
}

/// Timer E of `request`, armed `expected` after `since`.
fn timer_e_set(setup: &Setup, request: &SipMessage, since: Instant, expected: Duration) -> Instant {
    let timer_e = setup.timer(request, TimerName::E).expect("Timer E armed");
    assert_set(timer_e, since, expected, "Timer E");
    timer_e
}

/// RFC 3261 §17.1.2.2: with the first copies lost, the request goes again at
/// T1, then at twice the interval each time up to T2, the same octets to the
/// same address; Timer F at 64·T1 reports the timeout and ends it.
#[tokio::test]
async fn an_unanswered_udp_request_is_retransmitted_on_timer_e_until_timer_f() {
    let setup = Setup::new();
    let request = notify("z9hG4bK-uac-py-unanswered");
    let sent_at = Instant::now();
    let mut answered =
        setup
            .uac()
            .send_request_with_response(request.clone(), peer(), Transport::Udp);
    let first = setup.udp.try_recv().expect("the first copy");
    assert_eq!(first.data, Bytes::from(request.to_bytes()));

    let timer_f = setup.timer(&request, TimerName::F).expect("Timer F");
    assert_set(timer_f, sent_at, 64 * T1, "Timer F");

    // 0.5 s, 1 s, 2 s, 4 s, then 4 s for as long as it lasts.
    let mut expected = T1;
    let mut armed = sent_at;
    for _ in 0..7 {
        let timer_e = timer_e_set(&setup, &request, armed, expected);
        setup.fire(timer_e - Duration::from_millis(1));
        assert!(setup.udp.try_recv().is_err(), "not before Timer E");
        armed = Instant::now();
        setup.fire(timer_e);
        let again = setup.udp.try_recv().expect("retransmitted");
        assert_retransmission_of(&first, &again);
        assert!(setup.udp.try_recv().is_err(), "one copy per Timer E");
        expected = (expected * 2).min(T2);
    }
    assert!(
        matches!(
            answered.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ),
        "a retransmission reports nothing"
    );

    setup.fire(timer_f);
    assert!(
        matches!(answered.try_recv(), Ok(UacResult::Timeout)),
        "Timer F is the timeout whoever waits for the response hears"
    );
    let _ = setup.udp.try_iter().count();
    setup.assert_drained();
    setup.fire(Instant::now() + 64 * T1);
    assert!(setup.udp.try_recv().is_err(), "nothing after Timer F");
}

/// A final response ends the retransmissions; Timer K (T4 over UDP) then
/// holds the transaction, so a repeat of that response is absorbed, and one
/// that comes after it is a stray that starts nothing.
#[tokio::test]
async fn a_final_response_stops_the_retransmissions_and_a_repeat_starts_nothing() {
    let setup = Setup::new();
    let request = notify("z9hG4bK-uac-py-answered");
    let sent_at = Instant::now();
    let mut answered =
        setup
            .uac()
            .send_request_with_response(request.clone(), peer(), Transport::Udp);
    let first = setup.udp.try_recv().expect("the first copy, which is lost");

    let timer_e = timer_e_set(&setup, &request, sent_at, T1);
    setup.fire(timer_e);
    assert_retransmission_of(&first, &setup.udp.try_recv().expect("the retransmission"));

    let answered_at = Instant::now();
    setup.answer(&request, "200 OK");
    match answered.try_recv() {
        Ok(UacResult::Response(response)) => assert_eq!(response.status_code(), Some(200)),
        other => panic!("the 200 was not delivered: {other:?}"),
    }
    assert!(setup.timer(&request, TimerName::E).is_none(), "Timer E off");
    assert!(setup.timer(&request, TimerName::F).is_none(), "Timer F off");
    let timer_k = setup.timer(&request, TimerName::K).expect("Timer K");
    assert_set(timer_k, answered_at, T4, "Timer K");
    setup.fire(timer_k - Duration::from_millis(1));
    assert!(setup.udp.try_recv().is_err(), "nothing after the response");

    // The peer did not see our request stop and repeats its answer.
    let (transactions, timers) = (setup.transactions(), setup.state().timer_wheel.len());
    setup.answer(&request, "200 OK");
    assert_eq!(setup.transactions(), transactions);
    assert_eq!(setup.state().timer_wheel.len(), timers);
    assert_eq!(setup.uac().pending_count(), 0);

    setup.fire(timer_k);
    setup.assert_drained();
    // And once more after the transaction is gone.
    setup.answer(&request, "200 OK");
    setup.assert_drained();
    assert!(setup.udp.try_recv().is_err());
}

/// RFC 3261 §17.1.2.2: after a provisional response the request is still
/// retransmitted, every T2 rather than at the doubling interval.
#[tokio::test]
async fn a_provisional_response_moves_timer_e_to_t2() {
    let setup = Setup::new();
    let request = notify("z9hG4bK-uac-py-proceeding");
    let mut answered = setup
        .uac()
        .expect_final_response("z9hG4bK-uac-py-proceeding");
    let sent_at = Instant::now();
    setup
        .uac()
        .send_request(request.clone(), peer(), Transport::Udp);
    let first = setup.udp.try_recv().expect("the first copy");

    setup.answer(&request, "100 Trying");
    assert!(
        matches!(
            answered.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ),
        "a provisional response is not the final one"
    );

    // The Timer E already running fires where it was set, and from then on
    // the interval is T2: 4 s where the doubling would have given 1 s.
    let timer_e = timer_e_set(&setup, &request, sent_at, T1);
    let mut armed = Instant::now();
    setup.fire(timer_e);
    assert_retransmission_of(&first, &setup.udp.try_recv().expect("retransmitted"));
    for _ in 0..2 {
        let timer_e = timer_e_set(&setup, &request, armed, T2);
        armed = Instant::now();
        setup.fire(timer_e);
        assert_retransmission_of(&first, &setup.udp.try_recv().expect("retransmitted"));
    }

    setup.answer(&request, "481 Call/Transaction Does Not Exist");
    match answered.try_recv() {
        Ok(UacResult::Response(response)) => assert_eq!(response.status_code(), Some(481)),
        other => panic!("the final response was not delivered: {other:?}"),
    }
    assert!(setup.timer(&request, TimerName::E).is_none());
    setup.fire(setup.timer(&request, TimerName::K).expect("Timer K"));
    setup.assert_drained();
}

/// A request nobody waits on is retransmitted all the same, and answered or
/// not it leaves nothing.
#[tokio::test]
async fn a_request_sent_without_waiting_is_retransmitted_until_it_is_answered() {
    let setup = Setup::new();
    let request = notify("z9hG4bK-uac-py-forgotten");
    let sent_at = Instant::now();
    setup
        .uac()
        .send_request(request.clone(), peer(), Transport::Udp);
    let first = setup.udp.try_recv().expect("the first copy");
    let timer_e = timer_e_set(&setup, &request, sent_at, T1);
    setup.fire(timer_e);
    assert_retransmission_of(&first, &setup.udp.try_recv().expect("retransmitted"));

    setup.answer(&request, "200 OK");
    assert!(setup.timer(&request, TimerName::E).is_none());
    let timer_k = setup.timer(&request, TimerName::K).expect("Timer K");
    setup.fire(timer_k - Duration::from_millis(1));
    assert!(setup.udp.try_recv().is_err(), "nothing after the response");
    setup.fire(timer_k);
    setup.assert_drained();
}

/// RFC 3261 §17.1.2.2: Timer E is for unreliable transports only. Over TCP the
/// request is written once, has Timer F alone, and ends with its response.
#[tokio::test]
async fn a_request_over_tcp_is_sent_exactly_once() {
    let setup = Setup::new();
    let request = request_on("NOTIFY", "TCP", "z9hG4bK-uac-py-stream");
    let mut answered =
        setup
            .uac()
            .send_request_with_response(request.clone(), peer(), Transport::Tcp);
    let sent = setup.tcp.try_recv().expect("the request");
    assert_eq!(sent.data, Bytes::from(request.to_bytes()));
    assert!(setup.timer(&request, TimerName::E).is_none(), "no Timer E");
    let timer_f = setup.timer(&request, TimerName::F).expect("Timer F");

    setup.fire(timer_f - Duration::from_millis(1));
    assert!(setup.tcp.try_recv().is_err(), "exactly one copy");
    assert!(setup.udp.try_recv().is_err());

    setup.answer(&request, "200 OK");
    assert!(matches!(
        answered.try_recv(),
        Ok(UacResult::Response(response)) if response.status_code() == Some(200)
    ));
    // Timer K is zero over a reliable transport: gone with the response.
    setup.assert_drained();

    // Unanswered, it times out at Timer F without ever being sent again.
    let request = request_on("NOTIFY", "TCP", "z9hG4bK-uac-py-stream-unanswered");
    let mut answered =
        setup
            .uac()
            .send_request_with_response(request.clone(), peer(), Transport::Tcp);
    let _ = setup.tcp.try_recv().expect("the request");
    let timer_f = setup.timer(&request, TimerName::F).expect("Timer F");
    setup.fire(timer_f);
    assert!(matches!(answered.try_recv(), Ok(UacResult::Timeout)));
    assert!(setup.tcp.try_recv().is_err(), "exactly one copy");
    setup.assert_drained();
}

/// The leak gate: N requests answered and N that time out leave the
/// transaction store, the timer wheel and the pending responses where they
/// started.
#[tokio::test]
async fn answered_and_timed_out_requests_leave_the_stores_at_baseline() {
    const EACH: usize = 200;
    let setup = Setup::new();
    setup.assert_drained();

    let mut waiting = Vec::new();
    for index in 0..EACH {
        let answered = notify(&format!("z9hG4bK-uac-py-leak-answered-{index}"));
        let unanswered = notify(&format!("z9hG4bK-uac-py-leak-unanswered-{index}"));
        // One of each kind of send: waited on, and not.
        waiting.push(setup.uac().send_request_with_response(
            answered.clone(),
            peer(),
            Transport::Udp,
        ));
        setup
            .uac()
            .send_request(unanswered.clone(), peer(), Transport::Udp);
        waiting.push(setup.uac().send_request_with_response(
            notify(&format!("z9hG4bK-uac-py-leak-waited-{index}")),
            peer(),
            Transport::Udp,
        ));
        setup.answer(&answered, "200 OK");
        // A repeat while Timer K runs, as a peer that missed nothing sends.
        setup.answer(&answered, "200 OK");
    }
    assert_eq!(setup.transactions(), 3 * EACH);

    // Past Timer K of the answered ones and Timer F of the rest.
    setup.fire(Instant::now() + 64 * T1);
    setup.assert_drained();
    let (answered, timed_out) =
        waiting
            .iter_mut()
            .fold((0, 0), |(answered, timed_out), receiver| {
                match receiver.try_recv() {
                    Ok(UacResult::Response(_)) => (answered + 1, timed_out),
                    Ok(UacResult::Timeout) => (answered, timed_out + 1),
                    Err(error) => panic!("a request ended with no outcome: {error:?}"),
                }
            });
    assert_eq!((answered, timed_out), (EACH, EACH));

    // A late answer to a request that timed out starts nothing.
    setup.answer(&notify("z9hG4bK-uac-py-leak-unanswered-0"), "200 OK");
    setup.assert_drained();
}

/// A caller that stops waiting before Timer F ends the transaction with its
/// wait (a dialog probe's `probe_timeout_secs`): no copy after that.
#[tokio::test]
async fn a_caller_that_stops_waiting_ends_the_retransmissions() {
    let setup = Setup::new();
    let request = request_on("OPTIONS", "UDP", "z9hG4bK-uac-probe");
    let mut answered =
        setup
            .uac()
            .send_request_with_response(request.clone(), peer(), Transport::Udp);
    let _ = setup.udp.try_recv().expect("the first copy");
    assert_eq!(setup.transactions(), 1);

    setup.uac().expire_branch("z9hG4bK-uac-probe");
    assert!(matches!(answered.try_recv(), Ok(UacResult::Timeout)));
    setup.assert_drained();
    setup.fire(Instant::now() + 64 * T1);
    assert!(
        setup.udp.try_recv().is_err(),
        "no copy after the wait ended"
    );
}

/// A branch sent again while its transaction runs: the second copy goes out
/// as it is, and whoever waits on it now ends that transaction with its wait.
#[tokio::test]
async fn a_waiter_on_a_branch_sent_twice_ends_the_transaction_it_rides_on() {
    let setup = Setup::new();
    let request = request_on("OPTIONS", "UDP", "z9hG4bK-uac-probe-twice");
    let _first = setup
        .uac()
        .send_request_with_response(request.clone(), peer(), Transport::Udp);
    let mut second = setup
        .uac()
        .send_request_with_response(request, peer(), Transport::Udp);
    assert_eq!(setup.udp.try_iter().count(), 2);
    assert_eq!(setup.transactions(), 1);

    setup.uac().expire_branch("z9hG4bK-uac-probe-twice");
    assert!(matches!(second.try_recv(), Ok(UacResult::Timeout)));
    setup.assert_drained();
    setup.fire(Instant::now() + 64 * T1);
    assert!(
        setup.udp.try_recv().is_err(),
        "no copy after the wait ended"
    );
}

/// A NOTIFY a P-CSCF sends behind its reply to a UE with a security
/// association leaves where the reply leaves: from the protected client port
/// to the UE's protected server port (TS 33.203 clause 7.1). Its
/// retransmission takes that same flow.
#[tokio::test]
async fn a_followup_to_a_protected_ue_is_retransmitted_over_the_replys_flow() {
    let (proxy, manager) = super::ipsec_lifecycle_tests::p_cscf("");
    let ue: SocketAddr = "192.0.2.50:6000".parse().expect("a literal address");
    super::ipsec_lifecycle_tests::install(&manager, ue).await;
    attach_uac_transactions(&proxy.state);
    let request = notify("z9hG4bK-uac-py-protected");
    let frame = Bytes::from(request.to_bytes());

    // The UE's request arrived from its protected client port on the
    // P-CSCF's protected server port.
    let inbound = super::proxy_dialog_state_tests::inbound("192.0.2.50:6000", "");
    track_reply_followup(&request, &frame, &inbound, &proxy.state);

    let key = TransactionManager::key_from_message(&request).expect("a key");
    let timer_e = proxy
        .state
        .timer_wheel
        .iter()
        .find(|entry| entry.key == key && entry.name == TimerName::E)
        .map(|entry| entry.fires_at)
        .expect("Timer E armed");
    fire_expired_timers_at(&proxy.state, timer_e);
    let again = proxy.udp.try_recv().expect("retransmitted");
    assert_eq!(again.data, frame);
    assert_eq!(again.destination.to_string(), "192.0.2.50:6001");
    assert_eq!(
        again
            .source_local_addr
            .map(|from| from.to_string())
            .as_deref(),
        Some("192.0.2.1:5064")
    );
}

/// A request the transport refused is not on its way: no transaction is left
/// retransmitting it, and whoever waits is told at once.
#[tokio::test]
async fn a_request_the_transport_refused_leaves_no_transaction() {
    let setup = Setup::new();
    let request = request_on("NOTIFY", "TLS", "z9hG4bK-uac-py-refused");
    // The fixture's TLS egress has no reader.
    let mut answered = setup
        .uac()
        .send_request_with_response(request, peer(), Transport::Tls);
    assert!(matches!(answered.try_recv(), Ok(UacResult::Timeout)));
    setup.assert_drained();
}

/// What stays one send: an OPTIONS probe, whose caller counts a miss and
/// probes again on its own schedule; an INVITE and an ACK, which are not
/// non-INVITE transactions; a branch whose response would not come back to
/// the UAC sender; a branch a transaction still runs on.
#[tokio::test]
async fn requests_outside_a_non_invite_transaction_are_sent_once() {
    let setup = Setup::new();
    let ruri = crate::sip::parser::parse_uri_standalone("sip:192.0.2.30:5060").expect("a URI");
    let _probe = setup.uac().send_options(peer(), Transport::Udp, ruri);
    setup.uac().send_request(
        request_on("INVITE", "UDP", "z9hG4bK-uac-py-invite"),
        peer(),
        Transport::Udp,
    );
    setup.uac().send_request(
        request_on("ACK", "UDP", "z9hG4bK-uac-py-ack"),
        peer(),
        Transport::Udp,
    );
    setup.uac().send_request(
        request_on("MESSAGE", "UDP", "z9hG4bK-script-own"),
        peer(),
        Transport::Udp,
    );
    assert_eq!(setup.udp.try_iter().count(), 4, "each left once");
    assert_eq!(setup.transactions(), 0);
    assert_eq!(setup.state().timer_wheel.len(), 0);
    setup.fire(Instant::now() + 64 * T1);
    assert!(setup.udp.try_recv().is_err());

    // The same branch twice: the first transaction stands, the second copy
    // goes out as it is, and one retransmission follows, not two.
    let request = request_on("MESSAGE", "UDP", "z9hG4bK-uac-py-twice");
    for _ in 0..2 {
        setup
            .uac()
            .send_request(request.clone(), peer(), Transport::Udp);
    }
    assert_eq!(setup.udp.try_iter().count(), 2);
    assert_eq!(setup.transactions(), 1);
    setup.fire(setup.timer(&request, TimerName::E).expect("Timer E"));
    assert_eq!(setup.udp.try_iter().count(), 1);
}

/// A request in flight for a script does not hold a drain: nothing upstream
/// waits on it, and it would hold shutdown until Timer F.
#[tokio::test]
async fn an_originated_request_does_not_hold_the_drain() {
    let setup = Setup::new();
    let drain = &setup.state().is_draining;
    let _ = drain
        .transaction_manager
        .set(Arc::clone(&setup.state().transaction_manager));
    setup
        .uac()
        .send_request(notify("z9hG4bK-uac-py-drain"), peer(), Transport::Udp);
    assert_eq!(setup.transactions(), 1);
    assert_eq!(drain.active_counts().0, 0);
}

const SUBSCRIBER: &str = "192.0.2.20:5070";

fn subscribe() -> String {
    concat!(
        "SUBSCRIBE sip:201@siphon.example.com SIP/2.0\r\n",
        "Via: SIP/2.0/UDP 192.0.2.20:5070;branch=z9hG4bK-lost-notify\r\n",
        "From: <sip:201@siphon.example.com>;tag=watcher\r\n",
        "To: <sip:201@siphon.example.com>\r\n",
        "Call-ID: lost-notify@example.com\r\n",
        "CSeq: 1 SUBSCRIBE\r\n",
        "Contact: <sip:201@192.0.2.20:5070>\r\n",
        "Event: message-summary\r\n",
        "Expires: 60\r\n",
        "Max-Forwards: 70\r\n",
        "Content-Length: 0\r\n",
        "\r\n",
    )
    .to_string()
}

/// End to end through `proxy.subscribe_state`: the initial NOTIFY of an
/// accepted subscription is lost, its retransmission is answered 200, and the
/// subscription stands. The NOTIFY leaves as a frame behind the 200 to the
/// SUBSCRIBE (RFC 6665 §4.1.2.3), a path of its own to the wire, and is
/// retransmitted from the socket the SUBSCRIBE arrived on.
#[test]
fn a_lost_initial_notify_is_retransmitted_and_its_200_keeps_the_subscription() {
    let _serial = crate::script::async_pool::pool_test_guard();
    let (_turn, harness) = subscribe_harness();
    let state = &harness.state;
    let ours = |frames: Vec<(SocketAddr, Bytes)>| -> Vec<Bytes> {
        frames
            .into_iter()
            .map(|(_, frame)| frame)
            .filter(|frame| {
                String::from_utf8_lossy(frame).contains("Call-ID: lost-notify@example.com")
            })
            .collect()
    };
    let call_id = "lost-notify@example.com";
    assert!(!harness.store.holds_call_id(call_id), "a fresh Call-ID");

    harness.receive_request(&subscribe(), SUBSCRIBER);
    let sent = ours(harness.frames());
    assert_eq!(sent.len(), 2, "the 200 and the initial NOTIFY");
    assert!(sent[0].starts_with(b"SIP/2.0 200"));
    assert!(sent[1].starts_with(b"NOTIFY "));
    assert!(
        harness.store.holds_call_id(call_id),
        "the SUBSCRIBE made a dialog"
    );

    // That NOTIFY never reaches the subscriber.
    let lost = sent[1].clone();
    let notify = parse_sip_message_bytes(&lost).expect("the NOTIFY parses");
    let key = TransactionManager::key_from_message(&notify).expect("a key");
    let timer = |name: TimerName| {
        state
            .timer_wheel
            .iter()
            .find(|entry| entry.key == key && entry.name == name)
            .map(|entry| (**entry).clone())
    };
    let timer_e = timer(TimerName::E).expect("Timer E armed for the NOTIFY");
    assert!(
        timer_e.fires_at <= Instant::now() + T1,
        "Timer E is T1 from when the NOTIFY left"
    );
    assert_eq!(
        timer_e.destination.map(|to| to.to_string()).as_deref(),
        Some(SUBSCRIBER)
    );
    assert_eq!(
        timer_e
            .source_local_addr
            .map(|from| from.to_string())
            .as_deref(),
        Some("192.0.2.1:5060"),
        "from the socket the SUBSCRIBE arrived on"
    );

    fire_expired_timers_at(state, timer_e.fires_at);
    let again = ours(harness.frames());
    assert_eq!(again, vec![lost], "the same NOTIFY, byte for byte");

    harness.receive_response(&response_to(&notify, "200 OK"), SUBSCRIBER);
    assert!(timer(TimerName::E).is_none(), "the 200 ends Timer E");
    let timer_k = timer(TimerName::K).expect("Timer K");
    fire_expired_timers_at(state, timer_k.fires_at);
    assert!(ours(harness.frames()).is_empty(), "no NOTIFY after its 200");
    assert!(
        harness.store.holds_call_id(call_id),
        "the subscription stands"
    );
    assert!(!state.transaction_manager.contains(&key));
}
