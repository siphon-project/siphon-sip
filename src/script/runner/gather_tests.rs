//! `tasks.gather` with `script.direct_dispatch` on and off: the same results
//! either way; with it on the children run on the handler's own runner, the
//! handler stays off asyncio, and nothing of a gather is left behind however
//! it ends.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::direct_tests::{settles_to, totals, with_pools_running, Rig, NEVER_DROPPED};
use crate::script::async_pool::ensure_test_pools;
use crate::script::stop_the_world_tests::{collect_garbage_until, in_child};

const SCRIPT: &str = r#"
import asyncio
import contextvars
import _siphon_registry as _r
import _direct_probe as probe
from siphon import tasks

direct = probe.direct
tag = contextvars.ContextVar("tag", default="unset")
cancelled = []
finished = []
events = []

async def child(x, delay=1):
    value = await probe.sleep_ms(delay, x)
    return value * 10

async def ordered(x):
    # The slowest first: results come in argument order, not completion order.
    results = await tasks.gather(
        child(1, 30), child(2, 1), probe.sleep_ms(10, 3), probe.ready(4))
    return f"{results}|{direct()}"

async def empty(x):
    await probe.ready(0)
    return f"{await tasks.gather()}|{direct()}"

async def mixed(x):
    profile, stored = await tasks.gather(child(x), probe.sleep_ms(2, 7))
    return f"{profile},{stored}|{direct()}"

async def nested_child(x):
    inner = await tasks.gather(child(x), child(x + 1))
    return sum(inner)

async def nested(x):
    outer = await tasks.gather(
        nested_child(1), nested_child(3), tasks.gather(probe.ready(8), child(9)))
    return f"{outer}|{direct()}"

async def now(value):
    return value

async def never_suspends(x):
    await probe.ready(0)
    return f"{await tasks.gather(now(1), now(2))}|{direct()}"

async def duplicates(x):
    await probe.ready(0)
    awaitable = probe.sleep_ms(1, 5)
    coroutine = child(2)
    return f"{await tasks.gather(awaitable, coroutine, awaitable, coroutine)}|{direct()}"

async def who():
    await probe.ready(0)
    return asyncio.current_task()

async def child_tasks(x):
    parent = asyncio.current_task()
    first, second = await tasks.gather(who(), who())
    same = asyncio.current_task() is parent
    return f"{first is not parent}|{first is not second}|{same}|{direct()}"

async def reads_the_context():
    seen = tag.get()
    tag.set("child")
    await probe.ready(0)
    return seen + ">" + tag.get()

async def context_is_copied(x):
    tag.set("parent")
    got = await tasks.gather(reads_the_context(), reads_the_context())
    return f"{got}|{tag.get()}|{direct()}"

async def slow_sibling(name):
    try:
        await probe.never()
    except asyncio.CancelledError:
        cancelled.append(name)
        raise
    finished.append(name)

async def failing(delay):
    await probe.sleep_ms(delay, 0)
    raise ValueError("child failed")

async def first_exception(x):
    del cancelled[:]
    held = probe.never()
    try:
        await tasks.gather(slow_sibling("a"), failing(5), held, slow_sibling("b"))
    except ValueError as error:
        after = await probe.ready(1)
        return f"{error}|{sorted(cancelled)}|{held.cancelled()}|{after}|{direct()}"
    return "not raised"

async def awaitable_fails(x):
    del cancelled[:]
    try:
        await tasks.gather(slow_sibling("a"), probe.fail("awaitable failed"))
    except ValueError as error:
        await probe.ready(0)
        return f"{error}|{cancelled}|{direct()}"
    return "not raised"

async def fails_quietly(x):
    try:
        await tasks.gather(probe.never(), failing(2), slow_sibling(("sibling", x)))
    except ValueError:
        return "failed"
    return "not raised"

async def fails_at_once(x):
    await probe.ready(0)
    del cancelled[:]
    async def boom():
        raise KeyError("at once")
    try:
        await tasks.gather(slow_sibling("first"), boom(), slow_sibling("never started"))
    except KeyError as error:
        return f"{error}|{cancelled}|{direct()}"
    return "not raised"

async def keeps_exceptions(x):
    results = await tasks.gather(
        failing(1), child(2), probe.fail("awaitable failed"), return_exceptions=True)
    names = [type(result).__name__ for result in results]
    return f"{names}|{results[0]}|{results[1]}|{results[2]}|{direct()}"

async def not_awaitable(x):
    await probe.ready(0)
    try:
        tasks.gather(now(1), 5)
    except TypeError:
        return f"TypeError|{direct()}"
    return "not raised"

async def sleeper(value):
    await asyncio.sleep(0.01)
    return value

async def a_child_uses_asyncio(x):
    got = await tasks.gather(sleeper(1), child(2), asyncio.sleep(0.005, "slept"))
    return f"{got}|{direct()}"

async def a_future_argument(x):
    await probe.ready(0)
    loop = asyncio.get_running_loop()
    future = loop.create_future()
    loop.call_later(0.005, future.set_result, "future")
    got = await tasks.gather(future, child(2))
    return f"{got}|{direct()}"

async def demoted_parent(x):
    await asyncio.sleep(0)
    got = await tasks.gather(child(1), probe.sleep_ms(1, 2))
    return f"{got}|{direct()}"

async def demoted_parent_fails(x):
    await asyncio.sleep(0)
    del cancelled[:]
    try:
        await tasks.gather(slow_sibling("a"), failing(5))
    except ValueError as error:
        await asyncio.sleep(0.01)
        return f"{error}|{cancelled}|{direct()}"
    return "not raised"

async def wedged(x):
    try:
        await tasks.gather(
            slow_sibling(("child", x, 0)), slow_sibling(("child", x, 1)), probe.never())
    except asyncio.CancelledError:
        cancelled.append(("parent", x))
        raise
    finished.append(("parent", x))

def wedged_counts(*_):
    children = len([name for name in cancelled if name[0] == "child"])
    parents = len([name for name in cancelled if name[0] == "parent"])
    return f"{children}|{parents}|{len(finished)}"

def forget(*_):
    del cancelled[:]
    del finished[:]
    del events[:]
    return "forgotten"

async def stubborn(x):
    try:
        await probe.never()
    except asyncio.CancelledError:
        events.append("ignored the cancellation")
    try:
        await probe.never()
    finally:
        events.append("closed")

async def leaves_children(x):
    await probe.ready(0)
    tasks.gather(stubborn(x), slow_sibling("left"))
    return "returned"

def the_events(*_):
    return ",".join(events) + "|" + ",".join(str(name) for name in cancelled)

async def gathers_then_hands_over(x):
    pending = tasks.gather(child(1, 20), probe.sleep_ms(20, 2))
    await asyncio.sleep(0)
    return f"{await pending}|{direct()}"

async def gathers_twice(x):
    total = 0
    for index in range(12):
        left, right = await tasks.gather(child(index), probe.ready(index))
        total += left + right
    return f"{total}|{direct()}"

async def cancels_itself(x):
    asyncio.current_task().cancel()
    try:
        await tasks.gather(slow_sibling("self"), probe.never())
    except asyncio.CancelledError:
        return "cancelled"
    return "not cancelled"

async def churn(x):
    total = 0
    for index in range(6):
        junk = [[index]]
        junk[0].append(junk)
        left, right = await tasks.gather(child(1), probe.sleep_ms(1, 1))
        total += left + right
    return total

for name, fn, is_async in [
    ("ordered", ordered, True), ("empty", empty, True), ("mixed", mixed, True),
    ("nested", nested, True), ("never_suspends", never_suspends, True),
    ("duplicates", duplicates, True), ("child_tasks", child_tasks, True),
    ("context_is_copied", context_is_copied, True),
    ("first_exception", first_exception, True),
    ("awaitable_fails", awaitable_fails, True),
    ("fails_at_once", fails_at_once, True),
    ("fails_quietly", fails_quietly, True),
    ("keeps_exceptions", keeps_exceptions, True),
    ("not_awaitable", not_awaitable, True),
    ("a_child_uses_asyncio", a_child_uses_asyncio, True),
    ("a_future_argument", a_future_argument, True),
    ("demoted_parent", demoted_parent, True),
    ("demoted_parent_fails", demoted_parent_fails, True),
    ("wedged", wedged, True), ("wedged_counts", wedged_counts, False),
    ("forget", forget, False),
    ("leaves_children", leaves_children, True), ("the_events", the_events, False),
    ("gathers_then_hands_over", gathers_then_hands_over, True),
    ("gathers_twice", gathers_twice, True),
    ("cancels_itself", cancels_itself, True), ("churn", churn, True),
]:
    _r.register("direct." + name, None, fn, is_async, None)
"#;

fn with_pools<F, Fut>(on: bool, scenario: F)
where
    F: FnOnce(Rig) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    with_pools_running(on, SCRIPT, scenario);
}

fn in_both_modes<F, Fut>(scenario: F)
where
    F: Fn(Rig, bool) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    for on in [false, true] {
        with_pools(on, |rig| scenario(rig, on));
    }
}

fn py(flag: bool) -> &'static str {
    if flag {
        "True"
    } else {
        "False"
    }
}

/// Results come back in argument order whatever order the children finish
/// in, for coroutines and siphon awaitables alike, and with the switch on the
/// handler is still stepped by the runner afterwards.
#[test]
fn results_come_in_argument_order_and_the_handler_stays_direct() {
    in_both_modes(|rig, on| async move {
        let before = totals();
        let demotions = crate::script::runner::demotions();
        assert_eq!(
            rig.call("ordered", 0).await,
            Ok(format!("[10, 20, 3, 4]|{}", py(on)))
        );
        assert_eq!(rig.call("empty", 0).await, Ok(format!("[]|{}", py(on))));
        assert_eq!(rig.call("mixed", 4).await, Ok(format!("40,7|{}", py(on))));
        assert_eq!(
            rig.call("never_suspends", 0).await,
            Ok(format!("[1, 2]|{}", py(on)))
        );
        assert_eq!(
            rig.call("duplicates", 0).await,
            Ok(format!("[5, 20, 5, 20]|{}", py(on)))
        );
        assert_eq!(
            rig.call("gathers_twice", 0).await,
            Ok(format!(
                "{}|{}",
                (0..12).map(|i| i * 11).sum::<i64>(),
                py(on)
            ))
        );
        if on {
            assert_eq!(
                crate::script::runner::demotions(),
                demotions,
                "no handler and no child was handed to asyncio"
            );
            assert!(totals().direct_steps > before.direct_steps);
        }
        settles_to(before, "after the gathers").await;
    });
}

/// A coroutine child is a coroutine of its own: it may gather in turn, and a
/// gather may be an argument of another.
#[test]
fn gathers_nest() {
    in_both_modes(|rig, on| async move {
        let before = totals();
        assert_eq!(
            rig.call("nested", 0).await,
            Ok(format!("[30, 70, [8, 90]]|{}", py(on)))
        );
        settles_to(before, "after the nested gathers").await;
    });
}

/// Each coroutine child has its own task and a copy of the handler's context,
/// as a task `asyncio.gather` makes would.
#[test]
fn a_child_has_its_own_task_and_a_copy_of_the_context() {
    in_both_modes(|rig, on| async move {
        assert_eq!(
            rig.call("child_tasks", 0).await,
            Ok(format!("True|True|True|{}", py(on)))
        );
        assert_eq!(
            rig.call("context_is_copied", 0).await,
            Ok(format!(
                "['parent>child', 'parent>child']|parent|{}",
                py(on)
            ))
        );
    });
}

/// A child that raises ends the gather with its exception and cancels the
/// others: coroutines get `CancelledError` at their await, a siphon awaitable
/// is cancelled. The handler goes on, still direct.
#[test]
fn the_first_exception_is_raised_and_cancels_the_siblings() {
    in_both_modes(|rig, on| async move {
        let before = totals();
        let dropped = NEVER_DROPPED.load(Ordering::SeqCst);
        assert_eq!(
            rig.call("first_exception", 0).await,
            Ok(format!("child failed|['a', 'b']|True|1|{}", py(on)))
        );
        assert_eq!(
            rig.call("awaitable_fails", 0).await,
            Ok(format!("awaitable failed|['a']|{}", py(on)))
        );
        settles_to(before, "after the failed gathers").await;
        if on {
            // Two siblings and the held awaitable, then one sibling: their
            // Rust futures were dropped, not left parked.
            let deadline = Instant::now() + Duration::from_secs(5);
            while NEVER_DROPPED.load(Ordering::SeqCst) - dropped < 4 {
                assert!(Instant::now() < deadline, "the cancelled futures dropped");
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
    });
}

/// A child that raises before it ever suspends still cancels the ones around
/// it, including one that had not started.
#[test]
fn a_child_that_fails_at_once_cancels_the_rest() {
    with_pools(true, |rig| async move {
        let before = totals();
        assert_eq!(
            rig.call("fails_at_once", 0).await,
            Ok("'at once'|['first']|True".to_string())
        );
        settles_to(before, "after a child failed at once").await;
    });
}

/// With `return_exceptions` nothing is cancelled and an exception is that
/// argument's result.
#[test]
fn return_exceptions_makes_an_exception_a_result() {
    in_both_modes(|rig, on| async move {
        assert_eq!(
            rig.call("keeps_exceptions", 0).await,
            Ok(format!(
                "['ValueError', 'int', 'ValueError']|child failed|20|awaitable failed|{}",
                py(on)
            ))
        );
    });
}

/// An argument that cannot be awaited is refused when the gather is made.
#[test]
fn an_argument_that_is_not_awaitable_is_a_type_error() {
    in_both_modes(|rig, on| async move {
        let before = totals();
        assert_eq!(
            rig.call("not_awaitable", 0).await,
            Ok(format!("TypeError|{}", py(on)))
        );
        settles_to(before, "after the refused gather").await;
    });
}

/// A child that uses asyncio is handed to a task of its own, on the same
/// thread, and the handler that gathered it stays direct. An asyncio future
/// is an argument like any other.
#[test]
fn a_child_that_uses_asyncio_does_not_demote_the_handler() {
    in_both_modes(|rig, on| async move {
        let before = totals();
        for _ in 0..3 {
            // The second and third call start the remembered child as a task.
            assert_eq!(
                rig.call("a_child_uses_asyncio", 0).await,
                Ok(format!("[1, 20, 'slept']|{}", py(on)))
            );
        }
        assert_eq!(
            rig.call("a_future_argument", 0).await,
            Ok(format!("['future', 20]|{}", py(on)))
        );
        settles_to(before, "after the gathers with asyncio children").await;
    });
}

/// In a handler that runs as an asyncio task the gather is asyncio's, with
/// the same results and the same cancellation of siblings.
#[test]
fn under_a_demoted_handler_the_gather_runs_as_asyncio_tasks() {
    in_both_modes(|rig, _on| async move {
        let before = totals();
        for _ in 0..2 {
            assert_eq!(
                rig.call("demoted_parent", 0).await,
                Ok("[10, 2]|False".to_string())
            );
        }
        assert_eq!(
            rig.call("demoted_parent_fails", 0).await,
            Ok("child failed|['a']|False".to_string())
        );
        settles_to(before, "after the demoted handlers").await;
        assert_eq!(totals().gathers, before.gathers);
    });
}

/// A gather made in a direct step and awaited after the handler was handed
/// to asyncio still completes: its children stay on the runner.
#[test]
fn a_gather_survives_its_handler_being_handed_over() {
    in_both_modes(|rig, _on| async move {
        let before = totals();
        assert_eq!(
            rig.call("gathers_then_hands_over", 0).await,
            Ok("[10, 2]|False".to_string())
        );
        settles_to(before, "after the hand-over").await;
    });
}

/// A handler cancelled while it awaits a gather takes the children with it.
#[test]
fn cancelling_the_handler_cancels_its_gather() {
    in_both_modes(|rig, _on| async move {
        let before = totals();
        assert_eq!(
            rig.call("cancels_itself", 0).await,
            Ok("cancelled".to_string())
        );
        settles_to(before, "after the self-cancelled handler").await;
    });
}

/// The leak test: a batch of handlers whose gathers complete and a batch
/// whose gathers never do. Every timed-out handler was cancelled once, each
/// of its children was cancelled once and none resumed, their Rust futures
/// were dropped, and the slab, the gathers, the tracked awaitables, the
/// admissions and the pending count are all back where they started.
#[test]
fn completed_and_timed_out_gathers_leak_nothing() {
    in_both_modes(|rig, on| async move {
        let (_, async_pool) = ensure_test_pools();
        let rig = Arc::new(rig);
        assert_eq!(rig.call("forget", 0).await, Ok("forgotten".to_string()));
        let baseline = totals();
        let pending_baseline = crate::script::async_pool::pending_coroutines();
        let dropped_before = NEVER_DROPPED.load(Ordering::SeqCst);

        const CALLS: usize = 5;
        let mut joins = Vec::new();
        for index in 0..CALLS {
            for name in ["wedged", "nested", "mixed", "fails_quietly"] {
                let rig = Arc::clone(&rig);
                joins.push((
                    name,
                    tokio::spawn(async move { rig.call(name, index as i64).await }),
                ));
            }
        }
        if on {
            // While they run they are counted: the test would pass on
            // counters nothing moves. A wedged handler is itself, two
            // coroutine children and one gather.
            let deadline = Instant::now() + Duration::from_secs(2);
            while totals().drives < baseline.drives + 3 * CALLS
                || totals().gathers < baseline.gathers + CALLS
            {
                assert!(
                    Instant::now() < deadline,
                    "the wedged gathers are in the slab: {:?}",
                    totals()
                );
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            assert!(totals().in_flight >= baseline.in_flight + CALLS);
        }
        for (name, join) in joins {
            let outcome = join.await.expect("joined");
            match name {
                "wedged" => {
                    let error = outcome.expect_err("timed out");
                    assert!(error.contains("did not settle"), "{error}");
                }
                _ => assert!(outcome.is_ok(), "{name}: {outcome:?}"),
            }
        }

        // Per wedged call: two children and the handler cancelled, three
        // futures dropped. A gather that failed drops two more per call.
        let deadline = Instant::now() + async_pool.coroutine_timeout();
        loop {
            let counts = rig.call("wedged_counts", 0).await.expect("a sync probe");
            let dropped = NEVER_DROPPED.load(Ordering::SeqCst) - dropped_before;
            let pending = crate::script::async_pool::pending_coroutines();
            if counts == format!("{}|{CALLS}|0", 2 * CALLS)
                && dropped == 5 * CALLS
                && pending <= pending_baseline
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "children|parents|finished = {counts}, futures dropped = {dropped}, \
                 pending = {pending} (baseline {pending_baseline})"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        settles_to(baseline, "after completed and timed-out gathers").await;
        // Settled, not merely passing through: nothing resumes later.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            rig.call("wedged_counts", 0).await,
            Ok(format!("{}|{CALLS}|0", 2 * CALLS)),
            "a cancelled child was resumed, or cancelled twice"
        );
        let after = totals();
        assert_eq!(after.drives, baseline.drives);
        assert_eq!(after.gathers, baseline.gathers);
        assert_eq!(after.awaitables, baseline.awaitables);
        assert_eq!(after.in_flight, baseline.in_flight);
    });
}

/// Nothing gathered outlives the handler: one that returns with children
/// still running has them cancelled, and a child that ignores the
/// cancellation is closed, its `finally` blocks run.
#[test]
fn children_never_outlive_the_handler() {
    with_pools(true, |rig| async move {
        assert_eq!(rig.call("forget", 0).await, Ok("forgotten".to_string()));
        let before = totals();
        let dropped = NEVER_DROPPED.load(Ordering::SeqCst);
        assert_eq!(
            rig.call("leaves_children", 0).await,
            Ok("returned".to_string())
        );
        settles_to(before, "after a handler left its children").await;
        assert_eq!(
            rig.call("the_events", 0).await,
            Ok("ignored the cancellation,closed|left".to_string())
        );
        // The stubborn child's two awaitables and the sibling's one.
        let deadline = Instant::now() + Duration::from_secs(5);
        while NEVER_DROPPED.load(Ordering::SeqCst) - dropped < 3 {
            assert!(Instant::now() < deadline, "the children's futures dropped");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    });
}

/// Gathers keep completing, failing and nesting while another thread forces
/// stop-the-world collections: a child's wake, the gather's completion and
/// the handler's resume all happen on the driver with the world being stopped
/// around them, and no thread on the path waits attached. Run in a child
/// process so that a deadlock is a failure, not a hung test run.
#[test]
fn gathering_survives_stop_the_world_collections() {
    if !in_child(
        concat!(
            module_path!(),
            "::gathering_survives_stop_the_world_collections"
        ),
        Duration::from_secs(150),
    ) {
        return;
    }
    with_pools(true, |rig| async move {
        let stop = Arc::new(AtomicBool::new(false));
        let collector = collect_garbage_until(Arc::clone(&stop));
        let rig = Arc::new(rig);
        let baseline = totals();
        for name in ["churn", "nested", "first_exception", "a_child_uses_asyncio"] {
            let joins: Vec<_> = (0..48)
                .map(|index| {
                    let rig = Arc::clone(&rig);
                    tokio::spawn(async move { rig.call(name, index).await })
                })
                .collect();
            for join in joins {
                let answer = tokio::time::timeout(Duration::from_secs(40), join)
                    .await
                    .expect("no gather hung behind a collection")
                    .expect("joined")
                    .expect("the handler returned");
                match name {
                    "churn" => assert_eq!(answer, "66"),
                    "nested" => assert_eq!(answer, "[30, 70, [8, 90]]|True"),
                    "a_child_uses_asyncio" => assert_eq!(answer, "[1, 20, 'slept']|True"),
                    // The cancelled list is shared by the concurrent calls.
                    _ => assert!(answer.starts_with("child failed|"), "{answer}"),
                }
            }
        }
        settles_to(baseline, "under collections").await;
        stop.store(true, Ordering::Relaxed);
        collector.join().expect("the collector stops");
    });
}

/// A timed-out handler's gather is torn down with the world being stopped
/// around the cancellations.
#[test]
fn cancelling_a_gather_survives_stop_the_world_collections() {
    if !in_child(
        concat!(
            module_path!(),
            "::cancelling_a_gather_survives_stop_the_world_collections"
        ),
        Duration::from_secs(150),
    ) {
        return;
    }
    with_pools(true, |rig| async move {
        let stop = Arc::new(AtomicBool::new(false));
        let collector = collect_garbage_until(Arc::clone(&stop));
        let rig = Arc::new(rig);
        let baseline = totals();
        const CALLS: usize = 24;
        let joins: Vec<_> = (0..CALLS)
            .map(|index| {
                let rig = Arc::clone(&rig);
                tokio::spawn(async move { rig.call("wedged", index as i64).await })
            })
            .collect();
        for join in joins {
            let error = tokio::time::timeout(Duration::from_secs(40), join)
                .await
                .expect("no timeout hung behind a collection")
                .expect("joined")
                .expect_err("timed out");
            assert!(error.contains("did not settle"), "{error}");
        }
        settles_to(baseline, "after the cancellations").await;
        assert_eq!(
            rig.call("wedged_counts", 0).await,
            Ok(format!("{}|{CALLS}|0", 2 * CALLS))
        );
        stop.store(true, Ordering::Relaxed);
        collector.join().expect("the collector stops");
    });
}
