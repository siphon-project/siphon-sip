//! The timer sweep keeps its beat however deep the Python executor's queue is,
//! and the liveness watchdog still aborts a sweep that genuinely stops.
//!
//! With a next hop dead, every relayed request ends in Timer F and its
//! `@proxy.on_failure` handler, and a handler that blocks (a re-route probing a
//! TCP path, say) lets thousands of them queue on the executor. The sweep used
//! to run each turn as an executor job it awaited, so it queued behind all of
//! them: no retransmission or timeout fired anywhere in the process, and the
//! watchdog, seeing the sweep stand still, aborted a node that was only busy.

use std::time::{Duration, Instant};

use super::proxy_cancel_awaits_provisional_tests::{CALLER, SILENT};
use super::proxy_dialog_state_tests::Proxy;
use super::test_dispatcher::test_dispatcher_with_script;
use super::*;
use crate::script::liveness::{run_liveness_watchdog, Beat, Loops, Stalled};
use crate::transaction::timer::TimerConfig;

/// Relays everything to a next hop that never answers. Each `slow-` call's
/// failure handler blocks its worker for a second, as a re-route probing a
/// dead path does; every handler then answers 504.
const SCRIPT: &str = concat!(
    "import time\n",
    "from siphon import proxy\n",
    "\n",
    "@proxy.on_request\n",
    "def route(request):\n",
    "    request.relay(\"sip:registrar@198.51.100.12:5060\")\n",
    "\n",
    "@proxy.on_failure\n",
    "def failed(request, reply):\n",
    "    if request.call_id.startswith(\"slow-\"):\n",
    "        time.sleep(1)\n",
    "    request.reply(504, \"Gave Up\")\n",
);

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

/// A proxy whose non-INVITE transactions time out (Timer F) after 2 s, with
/// Timer E retransmitting at 500 ms and 1.5 s.
fn proxy() -> Proxy {
    let transaction: crate::config::TransactionConfig =
        crate::config::yaml::from_str("timeout_secs: 2").expect("the transaction block parses");
    let timers: TimerConfig = transaction_timers(Some(&transaction));
    let mut dispatcher = test_dispatcher_with_script(SCRIPT);
    dispatcher.state.transaction_manager = Arc::new(TransactionManager::new(timers));
    Proxy {
        state: Arc::new(dispatcher.state),
        udp: dispatcher.udp,
    }
}

/// How many times `call_id`'s REGISTER has gone to the dead next hop in `sent`.
fn sends_to_next_hop(sent: &[super::proxy_dialog_state_tests::Sent], call_id: &str) -> usize {
    sent.iter()
        .filter(|sent| {
            sent.destination == SILENT
                && sent.message.headers.call_id().map(String::as_str) == Some(call_id)
        })
        .count()
}

fn runtime(workers: usize) -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .on_thread_park(crate::script::attach::mark_tokio_worker)
        .build()
        .expect("a runtime")
}

/// 2000 failure handlers each blocking a second queue on a 3-worker executor,
/// more than ten minutes of work. Meanwhile another transaction still
/// retransmits and times out on time, and the sweep keeps turning, so the
/// watchdog has no reason to abort.
#[test]
fn a_backlog_of_slow_failure_handlers_does_not_stop_the_timers() {
    super::own_process_test::run_in_own_process(
        "dispatcher::sweep_backlog_tests::a_backlog_of_slow_failure_handlers_does_not_stop_the_timers",
        Duration::from_secs(60),
        backlog_scenario,
    );
}

fn backlog_scenario() {
    const BACKLOG: usize = 2000;
    crate::script::async_pool::ensure_test_pools();
    let runtime = runtime(2);
    runtime.block_on(async {
        let proxy = proxy();
        let stamp = spawn_timer_sweep(&proxy.state);

        for index in 0..BACKLOG {
            proxy.request(CALLER, &register(&format!("slow-{index}@example.com")));
        }
        // Their Timer F fires after 2 s, and their handlers pile up.
        tokio::time::sleep(Duration::from_millis(2_500)).await;
        let _ = proxy.wire();
        let backlog = crate::script::py_executor::queue_depth();
        assert!(
            backlog > BACKLOG / 2,
            "the failure handlers are queued behind each other ({backlog} queued)"
        );

        // The watchdog, judging the sweep over a 1 s window.
        let loops = Loops::new();
        loops.watch(&stamp);
        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let watchdog = {
            let handle = tokio::runtime::Handle::current();
            let shutdown = Arc::clone(&shutdown);
            std::thread::spawn(move || {
                let fired = std::sync::Mutex::new(None);
                run_liveness_watchdog(
                    handle,
                    Arc::new(Beat::default()),
                    &loops,
                    20,
                    Duration::from_millis(50),
                    shutdown,
                    |which| {
                        let mut slot = fired.lock().expect("the stall slot");
                        slot.get_or_insert(which);
                    },
                    || std::thread::sleep(Duration::from_millis(50)),
                );
                fired.into_inner().expect("the stall slot")
            })
        };

        let probe_sent = Instant::now();
        proxy.request(CALLER, &register("probe@example.com"));
        let mut sent = proxy.wire();
        let relayed = sent
            .iter()
            .find(|sent| {
                sent.destination == SILENT
                    && sent.message.headers.call_id().map(String::as_str)
                        == Some("probe@example.com")
            })
            .map(|sent| sent.message.clone())
            .expect("the probe's REGISTER is relayed");
        let timer_f = format!(
            "{}:{:?}",
            TransactionManager::key_from_message(&relayed).expect("a transaction key"),
            TimerName::F
        );
        assert!(
            proxy.state.timer_wheel.contains_key(&timer_f),
            "the probe's Timer F is armed"
        );
        let mut retransmitted_at = None;
        while probe_sent.elapsed() < Duration::from_millis(2_600) {
            tokio::time::sleep(Duration::from_millis(50)).await;
            sent.extend(proxy.wire());
            if retransmitted_at.is_none() && sends_to_next_hop(&sent, "probe@example.com") >= 2 {
                retransmitted_at = Some(probe_sent.elapsed());
            }
        }
        let probe_sends = sends_to_next_hop(&sent, "probe@example.com");
        let probe_timed_out = !proxy.state.timer_wheel.contains_key(&timer_f);
        shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
        let stalled = watchdog.join().expect("the watchdog thread");

        let retransmitted_at = retransmitted_at.expect(
            "the probe's REGISTER was retransmitted (Timer E): the sweep did not run behind the \
             executor backlog",
        );
        assert!(
            retransmitted_at < Duration::from_millis(1_000),
            "Timer E's first retransmission is due at 500 ms, it came at {retransmitted_at:?}"
        );
        assert_eq!(
            probe_sends, 3,
            "the REGISTER, Timer E's retransmissions at 0.5 s and 1.5 s, and nothing after \
             Timer F at 2 s"
        );
        assert!(
            probe_timed_out,
            "Timer F ended the probe's transaction on time"
        );
        assert_eq!(
            stalled, None::<Stalled>,
            "the watchdog found the sweep turning"
        );
        assert!(
            stamp.idle_for() < Duration::from_millis(500),
            "the sweep's stamp is fresh"
        );
    });
}

/// A sweep that genuinely stops, its turn stuck on a lock it needs, still
/// trips the watchdog, while the rest of the runtime is healthy.
#[test]
fn the_watchdog_still_trips_on_a_sweep_that_stops() {
    let runtime = runtime(2);
    runtime.block_on(async {
        let proxy = proxy();
        let stamp = spawn_timer_sweep(&proxy.state);
        // A relayed request puts timers in the wheel; hold one of them, and
        // with it the shard the sweep's turn has to walk.
        proxy.request(CALLER, &register("held@example.com"));
        let held_id = proxy
            .state
            .timer_wheel
            .iter()
            .next()
            .map(|entry| entry.key().clone())
            .expect("a timer is armed");
        let held = proxy
            .state
            .timer_wheel
            .get_mut(&held_id)
            .expect("the timer");

        let loops = Loops::new();
        loops.watch(&stamp);
        let handle = tokio::runtime::Handle::current();
        let stalled = tokio::task::spawn_blocking(move || {
            let fired = std::sync::Mutex::new(None);
            let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let stop = Arc::clone(&shutdown);
            let mut samples = 0;
            run_liveness_watchdog(
                handle,
                Arc::new(Beat::default()),
                &loops,
                10,
                Duration::from_millis(50),
                shutdown,
                |which| {
                    let mut slot = fired.lock().expect("the stall slot");
                    slot.get_or_insert(which);
                },
                move || {
                    std::thread::sleep(Duration::from_millis(50));
                    samples += 1;
                    if samples >= 60 {
                        stop.store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                },
            );
            fired.into_inner().expect("the stall slot")
        });
        let stalled = tokio::time::timeout(Duration::from_secs(10), stalled)
            .await
            .expect("the watchdog ran its samples")
            .expect("the watchdog thread");
        drop(held);
        assert_eq!(stalled, Some(Stalled::Loop("timer-sweep")));
    });
}
