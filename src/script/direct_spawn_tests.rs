//! `tasks.spawn`, `tasks.wait_first` and `tasks.event` through real script
//! dispatch: a Python handler uses them, and the tests assert what ran where,
//! what was cancelled, and that nothing is left behind.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use pyo3::prelude::*;

use crate::script::async_pool::{ensure_test_pools, pending_coroutines};
use crate::script::direct::{background_outstanding, clear_demoted, demoted_count};
use crate::script::direct_tests::{with_pools_running, NEVER_DROPPED};
use crate::script::stop_the_world_tests::{collect_garbage_until, in_child};

const SCRIPT: &str = r#"
import asyncio
from siphon import tasks
import _siphon_registry as _r
import _direct_probe as probe

where = probe.thread_name

def on_driver(name):
    return name.startswith("siphon-asyncio")

threads = []
done = []
cancelled = []

async def child(value, millis=1):
    threads.append(where())
    result = await probe.sleep_ms(millis, value)
    threads.append(where())
    done.append(value)
    return result

async def child_with_asyncio(value):
    await probe.ready(1)
    await asyncio.sleep(0.01)
    threads.append(where())
    done.append(value)
    return value

async def child_fails():
    await probe.fail("child boom")

async def child_fails_slowly():
    await probe.sleep_ms(40, 0)
    raise ValueError("slow child boom")

async def child_wedged():
    try:
        await probe.never()
    except asyncio.CancelledError:
        cancelled.append(1)
        raise

async def child_instant(value):
    return value

async def setter(event):
    await probe.sleep_ms(5, 0)
    event.set()

def thread_report(*_):
    return ",".join(threads)

def done_report(*_):
    return ",".join(str(value) for value in sorted(done))

def cancelled_count(*_):
    return str(len(cancelled))

async def fire_and_forget(x):
    tasks.spawn(child(x, 20))
    return "returned"

async def many_background(x):
    for index in range(x):
        tasks.spawn(child(index, 300))
    return "spawned"

async def spawn_then_await(x):
    handle = tasks.spawn(child(x, 5))
    return f"{await handle}|{on_driver(where())}"

async def spawn_instant(x):
    handle = tasks.spawn(child_instant(x))
    return f"{await handle}|{on_driver(where())}"

async def spawn_fails_awaited(x):
    handle = tasks.spawn(child_fails_slowly(), name="awaited-release")
    try:
        await handle
    except ValueError as error:
        return f"caught:{error}"
    return "not raised"

async def spawn_fails_unawaited(x):
    tasks.spawn(child_fails_slowly(), name="unawaited-release")
    return "returned"

async def spawn_with_asyncio(x):
    handle = tasks.spawn(child_with_asyncio(x))
    return f"{await handle}|{on_driver(where())}"

def spawn_from_sync(x):
    tasks.spawn(child(x, 5))
    return "spawned"

async def spawn_from_a_driver(x):
    await asyncio.sleep(0)
    handle = tasks.spawn(child(x, 5))
    return f"{await handle}|{on_driver(where())}"

async def first_of(x):
    release = tasks.spawn(child(x, 5), name="release")
    slow = probe.sleep_ms(200, 99)
    first = await tasks.wait_first([slow, release], timeout=5)
    return f"{first.index}|{first.result()}|{await slow}|{on_driver(where())}"

async def first_of_cancelling(x):
    release = tasks.spawn(child(x, 5), name="release")
    wedged = tasks.spawn(child_wedged(), name="wedged")
    first = await tasks.wait_first([wedged, release], timeout=5, cancel_losers=True)
    await probe.sleep_ms(20, 0)
    try:
        await wedged
    except asyncio.CancelledError:
        return f"{first.index}|{first.result()}|wedged cancelled|{wedged.cancelled()}"
    return "wedged not cancelled"

async def first_failing(x):
    failing = tasks.spawn(child_fails())
    first = await tasks.wait_first([failing, probe.sleep_ms(200, 1)], timeout=5)
    try:
        first.result()
    except ValueError as error:
        return f"{first.index}|raised:{error}|{type(first.exception).__name__}"
    return "no error"

async def timeout_leaves_losers(x):
    slow = probe.sleep_ms(80, 7)
    first = await tasks.wait_first([slow], timeout=0.02)
    kept = f"{first.timed_out}|{first.index}|{first.awaitable}|{first.exception}"
    try:
        first.result()
    except TimeoutError:
        kept += "|TimeoutError"
    return f"{kept}|{await slow}"

async def timeout_cancels_losers(x):
    work = tasks.spawn(child_wedged(), name="wedged")
    first = await tasks.wait_first([work], timeout=0.02, cancel_losers=True)
    await probe.sleep_ms(20, 0)
    return f"{first.timed_out}|{work.cancelled()}"

async def event_wakes_the_waiter(x):
    event = tasks.event()
    tasks.spawn(setter(event))
    first = await tasks.wait_first(
        [event.wait(), probe.sleep_ms(500, 0)], timeout=5, cancel_losers=True
    )
    return f"{first.index}|{first.result()}|{event.is_set()}|{on_driver(where())}"

async def event_already_set(x):
    event = tasks.event()
    event.set()
    return f"{await event.wait()}|{event.is_set()}"

async def event_clear(x):
    event = tasks.event()
    event.set()
    event.clear()
    first = await tasks.wait_first([event.wait()], timeout=0.02, cancel_losers=True)
    return f"{first.timed_out}|{event.is_set()}"

async def cancel_a_handle(x):
    work = tasks.spawn(child_wedged(), name="wedged")
    await probe.sleep_ms(5, 0)
    first = work.cancel()
    again = work.cancel()
    await probe.sleep_ms(20, 0)
    try:
        await work
    except asyncio.CancelledError:
        return f"{first}|{again}|{work.cancelled()}|{work.done()}|{on_driver(where())}"
    return "not cancelled"

async def handle_state(x):
    work = tasks.spawn(child(x, 20))
    try:
        work.result()
    except asyncio.InvalidStateError:
        pending = "pending"
    value = await work
    return f"{pending}|{work.done()}|{work.result()}|{work.exception()}|{value}"

def set_event():
    event = tasks.event()
    event.set()
    return event

async def bad_arguments(x):
    out = []
    for call in (
        lambda: tasks.spawn(len),
        lambda: tasks.wait_first([]),
        lambda: tasks.wait_first([1]),
        lambda: tasks.wait_first([set_event().wait()], timeout=-1),
    ):
        try:
            call()
        except Exception as error:
            out.append(type(error).__name__)
    return ",".join(out)

async def watch_and_abandon(x):
    slow = probe.sleep_ms(30, 1)
    probe.kept = slow
    first = await tasks.wait_first([slow], timeout=0.001)
    return f"{first.timed_out}|{await slow}"

async def cancelled_wait(x):
    slow = probe.sleep_ms(30, 1)
    probe.kept = slow
    waiter = tasks.wait_first([slow])
    cancelled_it = waiter.cancel()
    return f"{cancelled_it}|{await slow}"

async def spawn_wedged(x):
    tasks.spawn(child_wedged(), name="wedged-forever")
    return "spawned"

for name, fn, is_async in [
    ("thread_report", thread_report, False), ("done_report", done_report, False),
    ("cancelled_count", cancelled_count, False),
    ("fire_and_forget", fire_and_forget, True), ("many_background", many_background, True),
    ("spawn_then_await", spawn_then_await, True), ("spawn_instant", spawn_instant, True),
    ("spawn_fails_awaited", spawn_fails_awaited, True),
    ("spawn_fails_unawaited", spawn_fails_unawaited, True),
    ("spawn_with_asyncio", spawn_with_asyncio, True),
    ("spawn_from_sync", spawn_from_sync, False),
    ("spawn_from_a_driver", spawn_from_a_driver, True),
    ("first_of", first_of, True), ("first_of_cancelling", first_of_cancelling, True),
    ("first_failing", first_failing, True),
    ("timeout_leaves_losers", timeout_leaves_losers, True),
    ("timeout_cancels_losers", timeout_cancels_losers, True),
    ("event_wakes_the_waiter", event_wakes_the_waiter, True),
    ("event_already_set", event_already_set, True), ("event_clear", event_clear, True),
    ("cancel_a_handle", cancel_a_handle, True), ("handle_state", handle_state, True),
    ("bad_arguments", bad_arguments, True),
    ("watch_and_abandon", watch_and_abandon, True),
    ("cancelled_wait", cancelled_wait, True), ("spawn_wedged", spawn_wedged, True),
]:
    _r.register("direct." + name, None, fn, is_async, None)
"#;

fn with_spawn_pools<F, Fut>(scenario: F)
where
    F: FnOnce(crate::script::direct_tests::Rig) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    with_pools_running(SCRIPT, scenario);
}

/// Poll until `condition` holds, failing with `what` after `within`.
async fn eventually(within: Duration, what: &str, condition: impl Fn() -> bool) {
    let deadline = Instant::now() + within;
    while !condition() {
        assert!(Instant::now() < deadline, "{what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// The awaitable a handler stored on the probe module as `kept`, as the
/// number of watchers still registered on it.
fn kept_awaitable_watchers() -> usize {
    Python::attach(|python| {
        let kept = python
            .import("_direct_probe")
            .and_then(|module| module.getattr("kept"))
            .expect("the handler kept an awaitable");
        let awaitable = kept
            .cast::<crate::script::direct::TestAwaitable>()
            .expect("a siphon awaitable");
        awaitable.get().watcher_count_for_test()
    })
}

async fn settled() {
    eventually(Duration::from_secs(10), "background tasks drained", || {
        background_outstanding() == 0
    })
    .await;
}

/// A handler that spawns background work and waits for the first of several
/// siphon awaitables never leaves the executor: no part of it, the child
/// included, ran on an asyncio driver, and no handler was handed to one.
#[test]
fn spawn_and_wait_first_stay_on_the_executor() {
    with_spawn_pools(|rig| async move {
        clear_demoted();
        for _ in 0..3 {
            assert_eq!(
                rig.call("first_of", 7).await,
                Ok("1|7|99|False".to_string())
            );
            assert_eq!(
                rig.call("spawn_then_await", 3).await,
                Ok("3|False".to_string())
            );
            assert_eq!(
                rig.call("event_wakes_the_waiter", 0).await,
                Ok("0|True|True|False".to_string())
            );
        }
        let threads = rig.call("thread_report", 0).await.expect("a sync probe");
        assert!(!threads.is_empty());
        assert!(
            !threads.contains("siphon-asyncio"),
            "a spawned coroutine ran on an asyncio driver: {threads}"
        );
        assert_eq!(demoted_count(), 0, "a handler was handed to asyncio");
        settled().await;
    });
}

/// Background work outlives the handler that started it and still finishes.
#[test]
fn a_spawned_coroutine_outlives_its_handler() {
    with_spawn_pools(|rig| async move {
        let before = rig.call("done_report", 0).await.expect("a sync probe");
        assert_eq!(rig.call("fire_and_forget", 41).await, Ok("returned".into()));
        let expected = if before.is_empty() {
            "41".to_string()
        } else {
            format!("{before},41")
        };
        let mut seen = String::new();
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            seen = rig.call("done_report", 0).await.expect("a sync probe");
            let mut values: Vec<&str> = seen.split(',').filter(|value| !value.is_empty()).collect();
            values.sort_unstable();
            let mut wanted: Vec<&str> = expected.split(',').collect();
            wanted.sort_unstable();
            if values == wanted {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            seen.contains("41"),
            "the background coroutine finished: {seen}"
        );
        settled().await;
    });
}

/// The handle finishes with the coroutine's value or raises its exception,
/// including for a coroutine that finished in its first step.
#[test]
fn a_handle_returns_the_value_and_raises_the_exception() {
    with_spawn_pools(|rig| async move {
        assert_eq!(rig.call("spawn_then_await", 6).await, Ok("6|False".into()));
        assert_eq!(rig.call("spawn_instant", 8).await, Ok("8|False".into()));
        assert_eq!(
            rig.call("spawn_fails_awaited", 0).await,
            Ok("caught:slow child boom".into())
        );
        assert_eq!(
            rig.call("handle_state", 4).await,
            Ok("pending|True|4|None|4".into())
        );
        settled().await;
    });
}

/// A coroutine that uses asyncio is handed to a driver intact, as a handler
/// is, while the handler that spawned it stays on the executor. Spawned from
/// a thread running an event loop, or from a synchronous handler, it works
/// too.
#[test]
fn a_coroutine_that_uses_asyncio_falls_back_to_a_driver() {
    with_spawn_pools(|rig| async move {
        assert_eq!(
            rig.call("spawn_with_asyncio", 5).await,
            Ok("5|False".into())
        );
        assert_eq!(
            rig.call("spawn_with_asyncio", 6).await,
            Ok("6|False".into())
        );
        let threads = rig.call("thread_report", 0).await.expect("a sync probe");
        assert!(
            threads.contains("siphon-asyncio"),
            "the asyncio-using child finished on a driver: {threads}"
        );

        assert_eq!(
            rig.call("spawn_from_a_driver", 9).await,
            Ok("9|True".into())
        );
        assert_eq!(rig.call("spawn_from_sync", 12).await, Ok("spawned".into()));
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let done = rig.call("done_report", 0).await.expect("a sync probe");
            if done.split(',').any(|value| value == "12") {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "the sync handler's child finished: {done}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        settled().await;
    });
}

/// Cancelling a handle cancels the coroutine behind it, from a direct handler
/// and without leaving the executor.
#[test]
fn cancelling_a_handle_cancels_the_coroutine() {
    with_spawn_pools(|rig| async move {
        clear_demoted();
        let before: usize = rig
            .call("cancelled_count", 0)
            .await
            .expect("a sync probe")
            .parse()
            .expect("a count");
        assert_eq!(
            rig.call("cancel_a_handle", 0).await,
            Ok("True|False|True|True|False".into())
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let now: usize = rig
                .call("cancelled_count", 0)
                .await
                .expect("a sync probe")
                .parse()
                .expect("a count");
            if now == before + 1 {
                break;
            }
            assert!(Instant::now() < deadline, "cancelled children: {now}");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(demoted_count(), 0, "cancel() handed the handler to asyncio");
        settled().await;
    });
}

/// `wait_first` reports the winner by position, with its value or exception.
#[test]
fn wait_first_reports_the_winner() {
    with_spawn_pools(|rig| async move {
        assert_eq!(rig.call("first_of", 2).await, Ok("1|2|99|False".into()));
        assert_eq!(
            rig.call("first_failing", 0).await,
            Ok("0|raised:child boom|ValueError".into())
        );
        assert_eq!(
            rig.call("bad_arguments", 0).await,
            Ok("TypeError,ValueError,TypeError,ValueError".into())
        );
        settled().await;
    });
}

/// A timeout leaves the awaitables running unless told to cancel them.
#[test]
fn a_timeout_leaves_or_cancels_the_losers_as_asked() {
    with_spawn_pools(|rig| async move {
        assert_eq!(
            rig.call("timeout_leaves_losers", 0).await,
            Ok("True|None|None|None|TimeoutError|7".into())
        );
        assert_eq!(
            rig.call("timeout_cancels_losers", 0).await,
            Ok("True|True".into())
        );
        assert_eq!(
            rig.call("first_of_cancelling", 3).await,
            Ok("1|3|wedged cancelled|True".into())
        );
        settled().await;
    });
}

/// An event wakes a waiter whichever order they come in, and clearing it makes
/// the next wait wait.
#[test]
fn an_event_wakes_its_waiters() {
    with_spawn_pools(|rig| async move {
        assert_eq!(
            rig.call("event_wakes_the_waiter", 0).await,
            Ok("0|True|True|False".into())
        );
        assert_eq!(
            rig.call("event_already_set", 0).await,
            Ok("True|True".into())
        );
        assert_eq!(rig.call("event_clear", 0).await, Ok("True|False".into()));
        settled().await;
    });
}

/// N spawns that complete, N cancelled through their handle, N cancelled as
/// losers and N whose wait timed out leave nothing behind: the background
/// count, the pending coroutines, the watchers on a kept awaitable, and the
/// futures of the cancelled work all return to where they were.
#[test]
fn spawned_work_and_waits_leave_nothing_behind() {
    with_spawn_pools(|rig| async move {
        let rig = Arc::new(rig);
        let baseline = pending_coroutines();
        let dropped_before = NEVER_DROPPED.load(Ordering::SeqCst);
        const CALLS: usize = 8;

        let mut joins = Vec::new();
        for index in 0..CALLS {
            for name in [
                "spawn_then_await",
                "fire_and_forget",
                "cancel_a_handle",
                "timeout_cancels_losers",
                "watch_and_abandon",
                "cancelled_wait",
            ] {
                let rig = Arc::clone(&rig);
                joins.push(tokio::spawn(
                    async move { rig.call(name, index as i64).await },
                ));
            }
        }
        for join in joins {
            join.await.expect("joined").expect("returned");
        }

        eventually(Duration::from_secs(10), "background tasks drained", || {
            background_outstanding() == 0 && pending_coroutines() <= baseline
        })
        .await;
        // `cancel_a_handle` and `timeout_cancels_losers` each cancel one
        // wedged child per call.
        eventually(
            Duration::from_secs(10),
            "cancelled work dropped its futures",
            || NEVER_DROPPED.load(Ordering::SeqCst) - dropped_before == 2 * CALLS,
        )
        .await;
        assert_eq!(kept_awaitable_watchers(), 0, "a wait left a watcher behind");
        assert_eq!(background_outstanding(), 0);
    });
}

/// Background work that never settles is cancelled at the coroutine timeout
/// and its entry released, as a handler's is.
#[test]
fn background_work_that_never_settles_is_timed_out() {
    with_spawn_pools(|rig| async move {
        let rig = Arc::new(rig);
        let dropped_before = NEVER_DROPPED.load(Ordering::SeqCst);
        const CALLS: usize = 4;
        for index in 0..CALLS {
            assert_eq!(
                rig.call("spawn_wedged", index as i64).await,
                Ok("spawned".into())
            );
        }
        assert_eq!(background_outstanding(), CALLS);
        let (_, async_pool) = ensure_test_pools();
        eventually(
            async_pool.coroutine_timeout() + Duration::from_secs(5),
            "wedged background work was timed out",
            || background_outstanding() == 0,
        )
        .await;
        eventually(Duration::from_secs(5), "its futures were dropped", || {
            NEVER_DROPPED.load(Ordering::SeqCst) - dropped_before == CALLS
        })
        .await;
    });
}

/// More background coroutines than the executor has threads all complete,
/// concurrently: awaiting one holds no worker.
#[test]
fn more_background_coroutines_than_executor_threads_all_complete() {
    with_spawn_pools(|rig| async move {
        let (executor, _) = ensure_test_pools();
        let count = 4 * executor.max_size() + 1;
        let started = Instant::now();
        let before = rig.call("done_report", 0).await.expect("a sync probe");
        assert_eq!(
            rig.call("many_background", count as i64).await,
            Ok("spawned".into())
        );
        assert_eq!(background_outstanding(), count);
        eventually(
            Duration::from_secs(10),
            "all the background coroutines finished",
            || background_outstanding() == 0,
        )
        .await;
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_millis(1500),
            "{count} background coroutines each awaiting 300 ms took {elapsed:?}"
        );
        let after = rig.call("done_report", 0).await.expect("a sync probe");
        let added = after.split(',').count() - before.split(',').filter(|v| !v.is_empty()).count();
        assert_eq!(added, count, "{after}");
    });
}

/// What a graceful shutdown does: the drain waits for background work
/// (the participant's `outstanding`), and what is left is cancelled and
/// unwinds, well before the coroutine timeout would have.
#[test]
fn shutdown_cancels_the_background_work_that_is_left() {
    with_spawn_pools(|rig| async move {
        use crate::lifecycle::LifecycleParticipant;
        let before: usize = rig
            .call("cancelled_count", 0)
            .await
            .expect("a sync probe")
            .parse()
            .expect("a count");
        for index in 0..3 {
            assert_eq!(rig.call("spawn_wedged", index).await, Ok("spawned".into()));
        }
        let participant = crate::script::direct::BackgroundTasks;
        assert_eq!(participant.outstanding(), 3);

        let started = Instant::now();
        crate::script::direct::cancel_all_and_wait(Duration::from_secs(2)).await;
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(participant.outstanding(), 0);
        let cancelled: usize = rig
            .call("cancelled_count", 0)
            .await
            .expect("a sync probe")
            .parse()
            .expect("a count");
        assert_eq!(cancelled - before, 3);
    });
}

/// A failure nobody is awaiting is logged at error level with the task's
/// name and the exception; one the handler awaits is not logged. Run in a
/// process of its own: the tasks finish on executor threads, so the capture
/// has to be the process-wide subscriber.
#[test]
fn an_unawaited_failure_is_logged() {
    if !in_child(
        concat!(module_path!(), "::an_unawaited_failure_is_logged"),
        Duration::from_secs(120),
    ) {
        return;
    }
    let log = crate::log_capture::LogBuffer::default();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_max_level(tracing::Level::ERROR)
        .with_writer(log.clone())
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("the first subscriber");
    with_spawn_pools(|rig| async move {
        assert_eq!(
            rig.call("spawn_fails_awaited", 0).await,
            Ok("caught:slow child boom".into())
        );
        assert_eq!(
            rig.call("spawn_fails_unawaited", 0).await,
            Ok("returned".into())
        );
        eventually(Duration::from_secs(10), "the failure was logged", || {
            log.rendered().contains("unawaited-release")
        })
        .await;
        settled().await;
        let rendered = log.rendered();
        assert!(rendered.contains("slow child boom"), "{rendered}");
        assert!(rendered.contains("ValueError"), "{rendered}");
        assert!(
            !rendered.contains("awaited-release\"") && !rendered.contains("task=awaited-release"),
            "an awaited failure was logged as unobserved: {rendered}"
        );
    });
}

/// Spawn, wait and event keep working while another thread forces
/// stop-the-world collections: nothing on their paths waits attached. Run in a
/// child process so a deadlock is a failure, not a hung test run.
#[test]
fn spawn_and_wait_survive_stop_the_world_collections() {
    if !in_child(
        concat!(
            module_path!(),
            "::spawn_and_wait_survive_stop_the_world_collections"
        ),
        Duration::from_secs(120),
    ) {
        return;
    }
    with_spawn_pools(|rig| async move {
        let stop = Arc::new(AtomicBool::new(false));
        let collector = collect_garbage_until(Arc::clone(&stop));
        let rig = Arc::new(rig);
        for (name, expected) in [
            ("first_of", "1|5|99|False"),
            ("event_wakes_the_waiter", "0|True|True|False"),
            ("spawn_then_await", "5|False"),
        ] {
            let joins: Vec<_> = (0..48)
                .map(|_| {
                    let rig = Arc::clone(&rig);
                    tokio::spawn(async move { rig.call(name, 5).await })
                })
                .collect();
            for join in joins {
                let answer = tokio::time::timeout(Duration::from_secs(40), join)
                    .await
                    .expect("no handler hung behind a collection")
                    .expect("joined");
                assert_eq!(answer, Ok(expected.to_string()));
            }
        }
        eventually(Duration::from_secs(20), "background tasks drained", || {
            background_outstanding() == 0
        })
        .await;
        stop.store(true, Ordering::Relaxed);
        collector.join().expect("the collector stops");
    });
}
