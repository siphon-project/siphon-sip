//! `handle.notify()` leaves a watch on its NOTIFY's final response, and a
//! failure RFC 6665 §4.2.2 names removes the subscription, from the local
//! store and from the cache; read off the wire.

use std::sync::Arc;
use std::time::{Duration, Instant};

use pyo3::prelude::*;

use super::super::PySubscribeHandle;
use super::send_notify_through;
use crate::dns::SipResolver;
use crate::sip::message::SipMessage;
use crate::sip::parser::parse_sip_message_bytes;
use crate::subscribe_state::{SubscribeDialog, SubscribeStore};
use crate::uac::UacSender;

const RESOURCE: &str = "sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org";
const ID: &str = "watched";

fn subscription() -> SubscribeDialog {
    SubscribeDialog {
        id: ID.to_string(),
        call_id: "notify-response@example.com".to_string(),
        local_tag: "notifier".to_string(),
        remote_tag: "watcher".to_string(),
        local_uri: RESOURCE.to_string(),
        remote_uri: "sip:watcher@example.com".to_string(),
        remote_target: "sip:watcher@192.0.2.20:5060".to_string(),
        received_address: None,
        received_transport: None,
        received_connection_id: None,
        route_set: Vec::new(),
        event: "reg".to_string(),
        expires_secs: 3600,
        created_at_unix: super::super::now_unix(),
        cseq: 0,
        event_version: 0,
        terminated: false,
        is_outbound: false,
        registrant_flow: None,
        body: None,
        local_contact: None,
        generation: 0,
    }
}

/// A notifier with one subscription, sending over a UDP channel the test
/// reads the wire off.
struct Notifier {
    uac: crate::gateway::tests::TestUac,
    resolver: Arc<SipResolver>,
    store: Arc<SubscribeStore>,
}

impl Notifier {
    fn new() -> Self {
        Self::over(SubscribeStore::new())
    }

    fn over(store: SubscribeStore) -> Self {
        let store = Arc::new(store);
        store.put(subscription());
        Notifier {
            uac: crate::gateway::tests::test_uac(),
            resolver: Arc::new(SipResolver::from_system().expect("a resolver")),
            store,
        }
    }

    fn sender(&self) -> &Arc<UacSender> {
        &self.uac.sender
    }

    fn handle(&self) -> PySubscribeHandle {
        PySubscribeHandle {
            store: Arc::clone(&self.store),
            id: ID.to_string(),
            reply_gate: None,
        }
    }

    /// What `handle.notify()` does, with this notifier's UAC: take the next
    /// CSeq, send, and return what went on the wire.
    async fn notify(&self, subscription_state: &str) -> SipMessage {
        let dialog = self
            .handle()
            .bump_cseq()
            .expect("the dialog is there")
            .expect("and still is");
        self.send(&dialog, subscription_state).await
    }

    async fn send(&self, dialog: &SubscribeDialog, subscription_state: &str) -> SipMessage {
        send_notify_through(
            self.sender(),
            &self.resolver,
            &self.store,
            dialog,
            subscription_state,
            Some("application/reginfo+xml"),
            Some(b"<reginfo/>"),
            None,
            &[],
        )
        .await
        .expect("the NOTIFY is sent");
        let sent = tokio::time::timeout(Duration::from_secs(5), self.uac.udp.recv_async())
            .await
            .expect("the NOTIFY reached the transport")
            .expect("the channel is open");
        parse_sip_message_bytes(&sent.data).expect("a NOTIFY")
    }

    /// The subscriber answers `notify` with `status`, as the dispatcher would
    /// hand it over.
    fn answer(&self, notify: &SipMessage, status: u16) {
        assert!(
            self.sender().match_response(&response_to(notify, status)),
            "the response to the NOTIFY is the UAC sender's"
        );
    }

    /// Timer F fires for every NOTIFY still unanswered, the way the
    /// dispatcher's sweep fires it.
    fn time_out(&self) {
        self.sender().age_pending(Duration::from_secs(33));
        assert!(self.sender().sweep_stale(Duration::from_secs(32)) >= 1);
    }

    fn held(&self) -> bool {
        self.store.get_local(ID).is_some()
    }

    /// Wait for the watch to remove the subscription.
    async fn removed(&self) -> bool {
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.held() {
            if Instant::now() > deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        true
    }

    /// Give a watch that has nothing to remove the time to have run.
    async fn kept(&self) -> bool {
        tokio::time::sleep(Duration::from_millis(100)).await;
        self.held()
    }
}

fn response_to(notify: &SipMessage, status: u16) -> SipMessage {
    let header = |name: &str| notify.headers.get(name).cloned().expect(name);
    let raw = format!(
        "SIP/2.0 {status} Reason\r\nVia: {}\r\nFrom: {}\r\nTo: {}\r\nCall-ID: {}\r\n\
         CSeq: {}\r\nContent-Length: 0\r\n\r\n",
        header("Via"),
        header("From"),
        header("To"),
        header("Call-ID"),
        header("CSeq"),
    );
    parse_sip_message_bytes(raw.as_bytes()).expect("a response")
}

fn failures(outcome: Option<u16>) -> u64 {
    crate::metrics::init().expect("metrics");
    crate::metrics::subscribe_notify::failures(outcome).expect("the metrics are up")
}

/// The subscriber lost the dialog and answers 481 (RFC 6665 §4.1.3): the
/// notifier removes the subscription, from the local store and from the
/// cache, so the next `notify()` on the handle finds no dialog and the
/// resource no longer lists the subscriber.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_notify_answered_481_removes_the_subscription() {
    let (store, cache) = SubscribeStore::new().with_recording_cache();
    let notifier = Notifier::over(store);
    let before = failures(Some(481));

    let notify = notifier.notify("active;expires=3600").await;
    assert_eq!(
        notify.headers.get("CSeq").map(String::as_str),
        Some("1 NOTIFY")
    );
    assert!(notifier.kept().await, "held until the answer comes");
    assert!(cache.ttl_of(ID).is_some(), "and in the cache");
    notifier.answer(&notify, 481);

    assert!(notifier.removed().await);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(cache.key_count(), 0, "the key went with it");
    assert!(notifier.store.get(ID).await.is_none());
    assert!(notifier.store.for_resource(RESOURCE, "reg").is_empty());
    assert_eq!(notifier.store.local_count(), 0);
    assert!(failures(Some(481)) > before);
    assert_eq!(notifier.sender().pending_count(), 0);

    // The next notify() on the handle: no dialog, as for any unknown one.
    Python::initialize();
    let handle = notifier.handle();
    Python::attach(|python| {
        let error = handle.bump_cseq().expect_err("the dialog is gone");
        assert!(error.is_instance_of::<pyo3::exceptions::PyLookupError>(python));
    });
}

/// A 200 keeps the subscription, and so does a failure §4.2.2 does not name:
/// a complaint about the transaction only. Those are still counted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_accepted_or_transaction_only_failure_keeps_the_subscription() {
    let (store, cache) = SubscribeStore::new().with_recording_cache();
    let notifier = Notifier::over(store);
    let before = failures(Some(503));
    for (round, status) in [200, 401, 500, 503].into_iter().enumerate() {
        let notify = notifier.notify("active;expires=3600").await;
        assert_eq!(
            notify.headers.get("CSeq").cloned(),
            Some(format!("{} NOTIFY", round + 1))
        );
        notifier.answer(&notify, status);
        assert!(notifier.kept().await, "a {status} keeps the subscription");
    }
    assert!(failures(Some(503)) > before);
    assert_eq!(notifier.sender().pending_count(), 0);
    assert!(cache.ttl_of(ID).is_some(), "the key is kept too");
}

/// No final response before Timer F: the notifier removes the subscription
/// (RFC 6665 §4.2.2), and a 408 counts the same (RFC 5057 §5.1).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_timed_out_notify_removes_the_subscription() {
    let notifier = Notifier::new();
    let before = failures(None);
    let _notify = notifier.notify("active;expires=3600").await;
    notifier.time_out();
    assert!(notifier.removed().await);
    assert!(failures(None) > before);

    let notifier = Notifier::new();
    let notify = notifier.notify("active;expires=3600").await;
    notifier.answer(&notify, 408);
    assert!(notifier.removed().await);
}

/// Every final response §4.2.2 names removes the subscription.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_listed_failure_removes_the_subscription() {
    for status in [
        404, 405, 410, 416, 480, 481, 482, 483, 484, 485, 489, 501, 604,
    ] {
        let notifier = Notifier::new();
        let notify = notifier.notify("active;expires=3600").await;
        notifier.answer(&notify, status);
        assert!(
            notifier.removed().await,
            "a {status} removes the subscription"
        );
    }
}

/// A provisional response does not end the NOTIFY transaction: the final
/// response that follows it decides.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_provisional_response_waits_for_the_final_one() {
    let notifier = Notifier::new();
    let notify = notifier.notify("active;expires=3600").await;
    notifier.answer(&notify, 100);
    assert!(notifier.kept().await);
    assert_eq!(notifier.sender().pending_count(), 1);

    notifier.answer(&notify, 481);
    assert!(notifier.removed().await);
}

/// A refresh SUBSCRIBE that lands while a NOTIFY is out proves the subscriber
/// still holds the dialog: the NOTIFY's late failure leaves the refreshed
/// subscription alone. A NOTIFY sent after the refresh still removes it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refresh_in_flight_outlives_the_failure_of_an_older_notify() {
    let notifier = Notifier::new();
    let stale = notifier.notify("active;expires=3600").await;
    notifier
        .store
        .update(ID, |dialog| dialog.refresh(3600))
        .expect("the dialog is there");

    notifier.answer(&stale, 481);
    assert!(notifier.kept().await, "the refreshed subscription is kept");

    let current = notifier.notify("active;expires=3600").await;
    notifier.answer(&current, 481);
    assert!(notifier.removed().await);
}

/// The terminating NOTIFY of the expiry sweep goes out for a dialog the store
/// no longer holds; its failure afterwards finds nothing to remove and leaves
/// nothing pending.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_failure_of_a_terminating_notify_is_a_no_op() {
    let notifier = Notifier::new();
    notifier
        .store
        .update(ID, |dialog| dialog.created_at_unix -= 3600);
    let mut reaped = notifier.store.take_stale();
    assert_eq!(reaped.len(), 1);
    let mut dialog = reaped.remove(0);
    dialog.next_cseq();

    let notify = notifier.send(&dialog, "terminated;reason=timeout").await;
    assert_eq!(
        notify.headers.get("Subscription-State").map(String::as_str),
        Some("terminated;reason=timeout")
    );
    notifier.answer(&notify, 481);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(notifier.store.local_count(), 0);
    assert_eq!(notifier.sender().pending_count(), 0);
}

/// The NOTIFY's Via names the notifier's own sent-by, where the subscriber
/// sends the response (RFC 3261 §18.2.2), and its branch is one the UAC
/// sender matches, so the response reaches the watch.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_notify_via_names_the_notifier() {
    let notifier = Notifier::new();
    let notify = notifier.notify("active;expires=3600").await;
    let via = notify.headers.get("Via").cloned().expect("a Via");
    assert!(
        via.starts_with("SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-uac-"),
        "{via}"
    );
    notifier.answer(&notify, 200);
}

/// A NOTIFY that cannot leave, because the stream its SUBSCRIBE came over is
/// gone, raises as before and leaves no transaction waiting for an answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_notify_with_no_stream_to_leave_on_leaves_nothing_pending() {
    let notifier = Notifier::new();
    let dialog = notifier
        .store
        .update(ID, |dialog| {
            dialog.received_address = Some("192.0.2.20:49152".parse().expect("an address"));
            dialog.received_transport = Some("tcp".to_string());
            dialog.received_connection_id = Some(u64::MAX);
            dialog.next_cseq();
        })
        .expect("the dialog is there");

    let error = send_notify_through(
        notifier.sender(),
        &notifier.resolver,
        &notifier.store,
        &dialog,
        "active;expires=3600",
        None,
        None,
        None,
        &[],
    )
    .await
    .expect_err("there is no such connection");
    assert!(error.to_string().contains("no longer connected"), "{error}");
    assert_eq!(notifier.sender().pending_count(), 0);
    assert!(notifier.kept().await, "the subscription is left as it was");
}

/// Every NOTIFY answered or timed out leaves nothing behind: no pending UAC
/// transaction, and a store holding what the outcomes left.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn completed_notifies_drain_the_pending_transactions() {
    let notifier = Notifier::new();
    for round in 0..200 {
        let notify = notifier.notify("active;expires=3600").await;
        match round % 3 {
            0 => notifier.answer(&notify, 200),
            1 => {
                notifier.answer(&notify, 100);
                notifier.answer(&notify, 500);
            }
            // Unanswered until Timer F: the subscription goes, and comes
            // back as a new one for the next round.
            _ => {
                notifier.time_out();
                assert!(notifier.removed().await);
                notifier.store.put(subscription());
            }
        }
        assert_eq!(notifier.sender().pending_count(), 0);
    }
    assert!(notifier.kept().await);
    assert_eq!(notifier.store.local_count(), 1);
    assert_eq!(notifier.sender().pending_count(), 0);
}

/// More NOTIFYs in flight at once than there are workers to wait on them:
/// the watches are tasks, not threads, so every one of them ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn many_notifies_in_flight_all_end() {
    let notifier = Notifier::new();
    let mut sent = Vec::new();
    for _ in 0..64 {
        sent.push(notifier.notify("active;expires=3600").await);
    }
    assert_eq!(notifier.sender().pending_count(), 64);
    for notify in &sent[..63] {
        notifier.answer(notify, 200);
    }
    assert!(notifier.kept().await);
    notifier.answer(&sent[63], 481);
    assert!(notifier.removed().await);
    assert_eq!(notifier.sender().pending_count(), 0);
}

/// The script path end to end, from Python: `await handle.notify(...)` on an
/// asyncio loop while another thread keeps forcing garbage collections. The
/// awaitable's future must not attach, and neither may the watch it leaves: a
/// thread blocked attached would wedge the stop-the-world. The subscriber
/// answers nothing until every NOTIFY is out, so a `notify()` that waited for
/// its answer would never resolve; the 481 to the last NOTIFY then removes
/// the subscription under the handle. Runs in a child process with a budget,
/// so a regression fails instead of hanging.
#[test]
fn notify_from_a_script_survives_forced_collections() {
    use crate::script::stop_the_world_tests::{collect_garbage_until, in_child};
    use std::sync::atomic::{AtomicBool, Ordering};

    if !in_child(
        concat!(
            module_path!(),
            "::notify_from_a_script_survives_forced_collections"
        ),
        Duration::from_secs(60),
    ) {
        return;
    }

    Python::initialize();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");
    let notifier = Arc::new(runtime.block_on(async { Notifier::new() }));
    super::super::set_uac_sender(Arc::clone(notifier.sender()));
    super::super::set_resolver(Arc::clone(&notifier.resolver));

    let stop = Arc::new(AtomicBool::new(false));
    let collector = collect_garbage_until(Arc::clone(&stop));

    // The subscriber: silent until every NOTIFY has arrived, then answers
    // each 200 but the last, which it answers 481, the way a subscriber that
    // lost the dialog does.
    const ROUNDS: usize = 20;
    let answering = Arc::clone(&notifier);
    let subscriber = std::thread::spawn(move || {
        let notifies: Vec<SipMessage> = (0..ROUNDS)
            .map(|_| {
                let sent = answering
                    .uac
                    .udp
                    .recv_timeout(Duration::from_secs(20))
                    .expect("a NOTIFY");
                parse_sip_message_bytes(&sent.data).expect("a NOTIFY")
            })
            .collect();
        assert_eq!(answering.sender().pending_count(), ROUNDS);
        for (round, notify) in notifies.iter().enumerate() {
            let status = if round + 1 == ROUNDS { 481 } else { 200 };
            answering.answer(notify, status);
        }
    });

    let handle = notifier.handle();
    let (sent, lost): (usize, bool) = Python::attach(|python| {
        let handle = Py::new(python, handle).expect("the handle");
        let source = std::ffi::CString::new(concat!(
            "import asyncio\n",
            "def run(handle, rounds):\n",
            "    async def main():\n",
            "        sent = 0\n",
            "        for _ in range(rounds):\n",
            "            if await handle.notify(\n",
            "                    body='<reginfo/>',\n",
            "                    content_type='application/reginfo+xml'):\n",
            "                sent += 1\n",
            "        for _ in range(400):\n",
            "            try:\n",
            "                handle.expires\n",
            "            except LookupError:\n",
            "                return sent, True\n",
            "            await asyncio.sleep(0.05)\n",
            "        return sent, False\n",
            "    return asyncio.run(main())\n",
        ))
        .expect("helper source");
        let helper = pyo3::types::PyModule::from_code(
            python,
            source.as_c_str(),
            c"subscribe_notify_gc.py",
            c"subscribe_notify_gc",
        )
        .expect("the helper");
        helper
            .getattr("run")
            .and_then(|run| run.call1((handle, ROUNDS)))
            .and_then(|outcome| outcome.extract())
            .expect("the NOTIFYs resolve")
    });

    subscriber.join().expect("the subscriber ran");
    stop.store(true, Ordering::SeqCst);
    collector.join().expect("the collector ran");

    assert_eq!(sent, ROUNDS, "every notify() resolved True, unanswered");
    assert!(lost, "the 481 removed the subscription under the handle");
    assert!(!notifier.held());
}
