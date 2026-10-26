//! `presence.notify()` observes its NOTIFY's final response, and a failure
//! RFC 6665 §4.2.2 names ends the subscription; read off the wire.

use std::sync::Arc;
use std::time::Duration;

use super::{await_notify_status, PyPresence};
use crate::dns::SipResolver;
use crate::presence::{NotifyFailure, PresenceStore};
use crate::sip::message::SipMessage;
use crate::sip::parser::parse_sip_message_bytes;
use crate::uac::UacSender;

const AOR: &str = "sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org";
const CONTACT: &str = "sip:watcher@192.0.2.7:5060";

/// A notifier with one reg-event subscription, sending over a UDP channel the
/// test reads the wire off.
struct Notifier {
    uac: crate::gateway::tests::TestUac,
    resolver: Arc<SipResolver>,
    store: Arc<PresenceStore>,
    subscription_id: String,
}

impl Notifier {
    fn new() -> Self {
        let store = Arc::new(PresenceStore::new());
        let subscription_id = PyPresence::new(Arc::clone(&store))
            .subscribe_dialog(
                CONTACT,
                AOR,
                "reg",
                600,
                "notify-outcome-call",
                "ftag-watcher",
                "notifier-tag",
                None,
                Some(AOR.to_string()),
                Some(AOR.to_string()),
                0,
            )
            .expect("a subscription");
        Notifier {
            uac: crate::gateway::tests::test_uac(),
            resolver: Arc::new(SipResolver::from_system().expect("a resolver")),
            store,
            subscription_id,
        }
    }

    fn sender(&self) -> &Arc<UacSender> {
        &self.uac.sender
    }

    /// Send a NOTIFY and return what went on the wire, and the receiver of
    /// its outcome.
    async fn notify(
        &self,
        subscription_state: &str,
    ) -> (SipMessage, tokio::sync::oneshot::Receiver<Option<u16>>) {
        let outcome = PyPresence::notify_inner(
            Arc::clone(&self.store),
            Arc::clone(self.sender()),
            Arc::clone(&self.resolver),
            &self.subscription_id,
            Some("<reginfo/>"),
            Some("application/reginfo+xml"),
            subscription_state,
        )
        .await
        .expect("the NOTIFY is sent");
        let sent = tokio::time::timeout(Duration::from_secs(5), self.uac.udp.recv_async())
            .await
            .expect("the NOTIFY reached the transport")
            .expect("the channel is open");
        (
            parse_sip_message_bytes(&sent.data).expect("a NOTIFY"),
            outcome,
        )
    }

    /// The subscriber answers `notify` with `status`, as the dispatcher would
    /// hand it over.
    fn answer(&self, notify: &SipMessage, status: u16) {
        let response = response_to(notify, status);
        assert!(
            self.sender().match_response(&response),
            "the response to the NOTIFY is the UAC sender's"
        );
    }

    /// Timer F fires for every NOTIFY still unanswered, the way the
    /// dispatcher's sweep fires it.
    fn time_out(&self) {
        self.sender().age_pending(Duration::from_secs(33));
        assert!(self.sender().sweep_stale(Duration::from_secs(32)) >= 1);
    }

    fn listed(&self) -> bool {
        self.store
            .subscriptions_for(AOR)
            .iter()
            .any(|subscription| subscription.id == self.subscription_id)
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

/// The outcome, or a failure instead of a hang.
async fn outcome_of(outcome: tokio::sync::oneshot::Receiver<Option<u16>>) -> Option<u16> {
    tokio::time::timeout(Duration::from_secs(5), outcome)
        .await
        .expect("the outcome arrives")
        .expect("the watcher reports it")
}

fn removed(failure: NotifyFailure) -> u64 {
    crate::metrics::init().expect("metrics");
    crate::presence::metrics::removed(failure).expect("the presence metrics")
}

/// The subscriber lost the dialog and answers 481 (RFC 6665 §4.1.3): the
/// notifier removes the subscription, and the next `subscribers()` no longer
/// lists it, so later state changes stop fanning NOTIFYs out to it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_notify_answered_481_ends_the_subscription() {
    let notifier = Notifier::new();
    let before = removed(NotifyFailure::Rejected);

    let (notify, outcome) = notifier.notify("active;expires=600").await;
    assert!(notifier.listed(), "listed until the answer comes");
    notifier.answer(&notify, 481);

    assert_eq!(outcome_of(outcome).await, Some(481));
    assert!(!notifier.listed());
    assert!(notifier
        .store
        .get_subscription(&notifier.subscription_id)
        .is_none());
    assert!(removed(NotifyFailure::Rejected) > before);

    // presence.subscribers(), the call a script fans NOTIFYs out with.
    let store = Arc::clone(&notifier.store);
    let listed = tokio::task::spawn_blocking(move || {
        pyo3::Python::initialize();
        pyo3::Python::attach(|python| {
            PyPresence::new(store)
                .subscribers(python, AOR)
                .expect("subscribers")
                .len()
        })
    })
    .await
    .expect("subscribers ran");
    assert_eq!(listed, 0);
}

/// No final response before Timer F: the notifier removes the subscription
/// (RFC 6665 §4.2.2), and a 408 counts the same (RFC 5057 §5.1, note 4).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_timed_out_notify_ends_the_subscription() {
    let notifier = Notifier::new();
    let before = removed(NotifyFailure::TimedOut);

    let (_notify, outcome) = notifier.notify("active;expires=600").await;
    notifier.time_out();

    assert_eq!(outcome_of(outcome).await, None);
    assert!(!notifier.listed());
    assert!(removed(NotifyFailure::TimedOut) > before);

    let notifier = Notifier::new();
    let (notify, outcome) = notifier.notify("active;expires=600").await;
    notifier.answer(&notify, 408);
    assert_eq!(outcome_of(outcome).await, Some(408));
    assert!(!notifier.listed());
}

/// A 200 keeps the subscription, and so does a failure §4.2.2 does not name:
/// a complaint about the transaction only.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_accepted_or_transaction_only_failure_keeps_the_subscription() {
    let notifier = Notifier::new();
    for status in [200, 500, 503] {
        let (notify, outcome) = notifier.notify("active;expires=600").await;
        notifier.answer(&notify, status);
        assert_eq!(outcome_of(outcome).await, Some(status));
        assert!(notifier.listed(), "a {status} keeps the subscription");
    }
}

/// Every final response §4.2.2 names ends the subscription.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_listed_failure_ends_the_subscription() {
    for status in [404, 405, 410, 416, 480, 482, 483, 484, 485, 489, 501, 604] {
        let notifier = Notifier::new();
        let (notify, outcome) = notifier.notify("active;expires=600").await;
        notifier.answer(&notify, status);
        assert_eq!(outcome_of(outcome).await, Some(status));
        assert!(!notifier.listed(), "a {status} ends the subscription");
    }
}

/// A provisional response does not end the NOTIFY transaction: the final
/// response that follows it decides.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_provisional_response_waits_for_the_final_one() {
    let notifier = Notifier::new();
    let (notify, mut outcome) = notifier.notify("active;expires=600").await;
    notifier.answer(&notify, 100);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        outcome.try_recv().is_err(),
        "no outcome on a provisional response"
    );
    assert!(notifier.listed());

    notifier.answer(&notify, 481);
    assert_eq!(outcome_of(outcome).await, Some(481));
    assert!(!notifier.listed());
}

/// A refresh SUBSCRIBE that lands while a NOTIFY is out proves the subscriber
/// still holds the dialog: the NOTIFY's late failure leaves the refreshed
/// subscription alone. A NOTIFY sent after the refresh still ends it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refresh_in_flight_outlives_the_failure_of_an_older_notify() {
    let notifier = Notifier::new();
    let (stale, stale_outcome) = notifier.notify("active;expires=600").await;
    assert!(notifier
        .store
        .refresh_subscription(&notifier.subscription_id, Duration::from_secs(600)));

    notifier.answer(&stale, 481);
    assert_eq!(outcome_of(stale_outcome).await, Some(481));
    assert!(notifier.listed(), "the refreshed subscription is kept");

    notifier.assert_nothing_pending();
    let (current, current_outcome) = notifier.notify("active;expires=600").await;
    notifier.answer(&current, 481);
    assert_eq!(outcome_of(current_outcome).await, Some(481));
    assert!(!notifier.listed());
}

impl Notifier {
    /// Nothing is left pending: every NOTIFY sent so far was answered.
    fn assert_nothing_pending(&self) {
        assert_eq!(self.sender().pending_count(), 0);
    }
}

/// A terminating NOTIFY removes the subscription when it is sent; its failure
/// afterwards is a no-op, counted nowhere.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_failure_of_a_terminating_notify_is_a_no_op() {
    let notifier = Notifier::new();
    let (notify, outcome) = notifier.notify("terminated;reason=timeout").await;
    assert!(notifier
        .store
        .get_subscription(&notifier.subscription_id)
        .is_none());
    notifier.answer(&notify, 481);
    assert_eq!(outcome_of(outcome).await, Some(481));
    assert_eq!(notifier.store.subscription_count(), 0);
}

/// The NOTIFY's Via names the notifier's own sent-by, where the subscriber
/// sends the response (RFC 3261 §18.2.2), and its branch is one the UAC
/// sender matches, so the response reaches the outcome watcher.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_notify_via_names_the_notifier() {
    let notifier = Notifier::new();
    let (notify, _outcome) = notifier.notify("active;expires=600").await;
    let via = notify.headers.get("Via").cloned().expect("a Via");
    assert!(
        via.starts_with("SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-uac-"),
        "{via}"
    );
    notifier.answer(&notify, 200);
}

/// Every NOTIFY answered or timed out leaves nothing behind: no pending UAC
/// transaction, and the store holds what the outcomes left.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn completed_notifies_drain_the_pending_transactions() {
    let notifier = Notifier::new();
    for round in 0..200 {
        let (notify, outcome) = notifier.notify("active;expires=600").await;
        if round % 2 == 0 {
            notifier.answer(&notify, 200);
        } else {
            notifier.answer(&notify, 100);
            notifier.answer(&notify, 500);
        }
        outcome_of(outcome).await;
    }
    assert_eq!(notifier.sender().pending_count(), 0);
    assert!(notifier.listed());
}

/// `wait_for_response=True` resolves to the final status, `None` without one
/// in time.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn waiting_resolves_to_the_status_or_none() {
    let notifier = Notifier::new();
    let (notify, outcome) = notifier.notify("active;expires=600").await;
    notifier.answer(&notify, 200);
    assert_eq!(
        await_notify_status(outcome, Duration::from_secs(5)).await,
        Some(200)
    );

    let (_notify, outcome) = notifier.notify("active;expires=600").await;
    assert_eq!(
        await_notify_status(outcome, Duration::from_millis(20)).await,
        None
    );
    // The removal does not depend on anyone waiting.
    notifier.time_out();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!notifier.listed());
}

/// The script path end to end, from Python: `await presence.notify(...,
/// wait_for_response=True)` on an asyncio loop while another thread keeps
/// forcing garbage collections. The awaitable's future must not attach, and
/// nothing it spawns may: a thread blocked attached would wedge the
/// stop-the-world. Runs in a child process with a budget, so a regression
/// fails instead of hanging.
#[test]
fn notify_from_a_script_survives_forced_collections() {
    use crate::script::stop_the_world_tests::{collect_garbage_until, in_child};
    use pyo3::prelude::*;
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

    pyo3::Python::initialize();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime");
    let notifier = Arc::new(runtime.block_on(async { Notifier::new() }));
    super::super::proxy_utils::set_uac_sender(
        Arc::clone(notifier.sender()),
        Arc::clone(&notifier.resolver),
    );

    let stop = Arc::new(AtomicBool::new(false));
    let collector = collect_garbage_until(Arc::clone(&stop));

    // The subscriber: answers every NOTIFY 200 but the last, which it answers
    // 481, the way a subscriber that lost the dialog does.
    const ROUNDS: usize = 20;
    let answering = Arc::clone(&notifier);
    let subscriber = std::thread::spawn(move || {
        for round in 0..ROUNDS {
            let sent = answering
                .uac
                .udp
                .recv_timeout(Duration::from_secs(20))
                .expect("a NOTIFY");
            let notify = parse_sip_message_bytes(&sent.data).expect("a NOTIFY");
            let status = if round + 1 == ROUNDS { 481 } else { 200 };
            answering.answer(&notify, status);
        }
    });

    let presence = PyPresence::new(Arc::clone(&notifier.store));
    let subscription_id = notifier.subscription_id.clone();
    let statuses: Vec<Option<u16>> = pyo3::Python::attach(|python| {
        let presence = Py::new(python, presence).expect("the namespace");
        let source = std::ffi::CString::new(concat!(
            "import asyncio\n",
            "def run(presence, subscription_id, rounds):\n",
            "    async def main():\n",
            "        statuses = []\n",
            "        for _ in range(rounds):\n",
            "            statuses.append(await presence.notify(\n",
            "                subscription_id, body='<reginfo/>',\n",
            "                content_type='application/reginfo+xml',\n",
            "                wait_for_response=True, timeout_ms=10000))\n",
            "        return statuses\n",
            "    return asyncio.run(main())\n",
        ))
        .expect("helper source");
        let helper = pyo3::types::PyModule::from_code(
            python,
            source.as_c_str(),
            c"presence_notify_gc.py",
            c"presence_notify_gc",
        )
        .expect("the helper");
        helper
            .getattr("run")
            .and_then(|run| run.call1((presence, subscription_id, ROUNDS)))
            .and_then(|statuses| statuses.extract())
            .expect("the NOTIFYs resolve")
    });

    subscriber.join().expect("the subscriber ran");
    stop.store(true, Ordering::SeqCst);
    collector.join().expect("the collector ran");

    let mut expected = vec![Some(200); ROUNDS - 1];
    expected.push(Some(481));
    assert_eq!(statuses, expected);
    // The watcher removes the subscription before it resolves the outcome.
    assert!(!notifier.listed(), "the 481 ended the subscription");
}
