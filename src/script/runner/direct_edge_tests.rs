//! The narrow places of direct dispatch: a cancellation landing at an exact
//! point of a coroutine's life, a loop handlers must not be stepped on, what
//! an awaitable keeps alive, and a driver shutting down under its coroutines.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use pyo3::prelude::*;
use pyo3::types::PyModule;

use super::direct_tests::{gate_is_set, open_gate, settles_to, totals, with_pools, NEVER_DROPPED};
use super::{Message, SiphonAwaitable, Waited, Work};
use crate::script::async_pool::{ensure_test_pools, test_pools_runtime, AsyncPool};
use crate::script::stop_the_world_tests::{collect_garbage_until, in_child};

/// Every runner of the shared pool, held inside one item until released, so
/// that what is posted meanwhile is all queued when the drains move on.
struct HeldRunners {
    release: Vec<mpsc::Sender<()>>,
}

impl HeldRunners {
    fn hold() -> Self {
        let (_, pool) = ensure_test_pools();
        let mut release = Vec::new();
        for index in 0..pool.size() {
            let (entered_tx, entered_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel::<()>();
            let posted = pool
                .runner(index)
                .expect("a runner")
                .post(Message::Start(Work::new(move |python, _fate| {
                    let _ = entered_tx.send(());
                    python.detach(move || {
                        let _ = release_rx.recv_timeout(Duration::from_secs(30));
                    });
                })));
            assert!(posted.is_ok(), "a live runner takes the post");
            entered_rx
                .recv_timeout(Duration::from_secs(10))
                .expect("the holding item ran");
            release.push(release_tx);
        }
        Self { release }
    }

    fn release(self) {
        for release in self.release {
            let _ = release.send(());
        }
    }
}

fn queued() -> usize {
    let (_, pool) = ensure_test_pools();
    (0..pool.size())
        .map(|index| pool.runner(index).expect("a runner").stats().queued)
        .sum()
}

async fn until(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
}

/// A cancellation that arrives after the awaitable finished and before the
/// coroutine was resumed is not lost and does not resume it twice: cancels
/// drain before wakes, so the coroutine gets `CancelledError` at its await,
/// once, and the wake that follows finds nothing to do.
#[test]
fn a_cancellation_queued_with_the_wake_wins_and_the_coroutine_steps_once() {
    with_pools(true, |rig| async move {
        let rig = Arc::new(rig);
        let baseline = totals();
        let call = {
            let rig = Arc::clone(&rig);
            tokio::spawn(async move { rig.call("gated", 0).await })
        };
        until("the handler to suspend on its gate", || {
            gate_is_set() && totals().drives == baseline.drives + 1
        })
        .await;
        let steps_before = totals().direct_steps;

        let held = tokio::task::spawn_blocking(HeldRunners::hold)
            .await
            .expect("joined");
        let queued_before = queued();
        open_gate();
        until("the wake to be queued", || queued() > queued_before).await;
        assert_eq!(
            rig.call("cancels_the_last_kept_task", 0).await,
            Ok("True".to_string())
        );
        until("the cancel to be queued", || queued() > queued_before + 1).await;
        held.release();

        let outcome = tokio::time::timeout(Duration::from_secs(20), call)
            .await
            .expect("the handler finished")
            .expect("joined");
        let error = outcome.expect_err("cancelled, not returned");
        assert!(error.contains("CancelledError"), "{error}");
        assert_eq!(rig.call("wedged_counts", 0).await, Ok("1|0".to_string()));
        settles_to(baseline, "after the cancelled handler").await;
        assert_eq!(
            totals().direct_steps - steps_before,
            1,
            "one step threw the cancellation; the wake behind it stepped nothing"
        );
    });
}

/// A waiter that gives up before its coroutine's first step ran: the
/// coroutine is closed without running at all, and nothing is left.
#[test]
fn a_handler_whose_waiter_gave_up_before_it_started_never_runs() {
    with_pools(true, |rig| async move {
        let (_, async_pool) = ensure_test_pools();
        let baseline = totals();
        let dropped_before = NEVER_DROPPED.load(Ordering::SeqCst);
        let held = tokio::task::spawn_blocking(HeldRunners::hold)
            .await
            .expect("joined");

        let error = rig.call("wedged", 0).await.expect_err("timed out");
        assert!(error.contains("did not settle"), "{error}");
        assert!(
            totals().in_flight > baseline.in_flight,
            "it holds its place until the runner lets go of it"
        );
        held.release();

        settles_to(baseline, "after the handler that never started").await;
        assert_eq!(totals().direct_starts, baseline.direct_starts);
        assert_eq!(rig.call("wedged_counts", 0).await, Ok("0|0".to_string()));
        assert_eq!(NEVER_DROPPED.load(Ordering::SeqCst), dropped_before);
        assert!(async_pool.coroutine_timeout() >= Duration::from_secs(1));
    });
}

/// Reading a finished awaitable from many threads while another forces
/// collections: no thread makes a Python object while holding the awaitable's
/// lock, so none parks for the collection with the lock held. In a child
/// process, so a deadlock is a failure.
#[test]
fn reading_an_awaitable_survives_stop_the_world_collections() {
    if !in_child(
        concat!(
            module_path!(),
            "::reading_an_awaitable_survives_stop_the_world_collections"
        ),
        Duration::from_secs(120),
    ) {
        return;
    }
    with_pools(true, |rig| async move {
        let baseline = totals();
        assert_eq!(
            rig.call("holds_a_cancelled_awaitable", 1).await,
            Ok("1".to_string())
        );
        assert_eq!(totals().awaitables, baseline.awaitables + 1);
        let handler = rig
            .handle
            .handlers_for("direct.the_held_awaitable")
            .into_iter()
            .next()
            .expect("registered");
        let awaitable = rig
            .handle
            .call_handler(&handler, Vec::new())
            .await
            .expect("the held awaitable");
        Python::attach(|python| {
            let held = awaitable.bind(python).cast::<SiphonAwaitable>().unwrap();
            // From a thread that is not its owner.
            assert!(held.get().cancel_for_test(python));
            python
                .run(c"import gc\ngc.set_threshold(1)\n", None, None)
                .unwrap();
        });
        settles_to(baseline, "after the awaitable was cancelled").await;

        let stop = Arc::new(AtomicBool::new(false));
        let collector = collect_garbage_until(Arc::clone(&stop));
        let awaitable = Arc::new(awaitable);
        let readers: Vec<_> = (0..8)
            .map(|_| {
                let awaitable = Arc::clone(&awaitable);
                std::thread::spawn(move || {
                    for _ in 0..5_000 {
                        let raised = Python::attach(|python| {
                            awaitable.bind(python).call_method0("__next__").is_err()
                        });
                        assert!(raised, "a cancelled awaitable raises");
                    }
                })
            })
            .collect();
        tokio::task::spawn_blocking(move || {
            for reader in readers {
                reader.join().expect("a reader finished");
            }
        })
        .await
        .expect("joined");
        stop.store(true, Ordering::Relaxed);
        collector.join().expect("the collector stops");
    });
}

/// Something set on every driver loop for a test, undone when dropped.
struct OnEveryLoop {
    undo: &'static std::ffi::CStr,
}

fn on_every_loop(code: &std::ffi::CStr) {
    let (_, pool) = ensure_test_pools();
    Python::attach(|python| {
        for index in 0..pool.size() {
            let event_loop = pool.driver_loop(python, index).expect("a driver");
            let scope = pyo3::types::PyDict::new(python);
            scope.set_item("loop", event_loop).unwrap();
            python.run(code, Some(&scope), None).unwrap();
        }
    });
}

impl OnEveryLoop {
    fn set(set: &std::ffi::CStr, undo: &'static std::ffi::CStr) -> Self {
        on_every_loop(set);
        Self { undo }
    }
}

impl Drop for OnEveryLoop {
    fn drop(&mut self) {
        on_every_loop(self.undo);
    }
}

/// An eager task factory runs a coroutine inside whatever step creates its
/// task, where a siphon awaitable it awaits would be yielded to a task that
/// cannot take it. On a loop with a task factory handlers start as tasks, and
/// are stepped by the runner again once it is removed.
#[test]
fn a_loop_with_a_task_factory_starts_handlers_as_tasks() {
    with_pools(true, |rig| async move {
        let baseline = totals();
        {
            let _eager = OnEveryLoop::set(
                c"import asyncio\nloop.set_task_factory(asyncio.eager_task_factory)\n",
                c"loop.set_task_factory(None)\n",
            );
            for _ in 0..2 {
                assert_eq!(
                    rig.call("sleeps_for_real", 8).await,
                    Ok("8|False|False|True".to_string())
                );
                assert_eq!(rig.call("one_await", 5).await, Ok("5|False".to_string()));
                assert_eq!(rig.call("gathers", 0).await, Ok("1,2".to_string()));
            }
            let error = rig.call("uncaught", 0).await.expect_err("raised");
            assert!(error.contains("escapes"), "{error}");
            assert_eq!(totals().direct_starts, baseline.direct_starts);
            settles_to(baseline, "after handlers that started as tasks").await;
        }
        assert_eq!(rig.call("one_await", 5).await, Ok("5|True".to_string()));
    });
}

/// A task a handler starts eagerly from its own step awaits a siphon
/// awaitable made in that step: it gets an asyncio future, not the yield only
/// the runner understands.
#[test]
fn an_eager_task_inside_a_step_awaits_through_asyncio() {
    with_pools(true, |rig| async move {
        let handler = Python::attach(|python| -> Py<PyAny> {
            let module = PyModule::from_code(
                python,
                c"import asyncio\n\
                  import _direct_probe as probe\n\
                  async def inner(pending):\n    return await pending + 1\n\
                  async def handler():\n\
                  \x20   loop = asyncio.get_running_loop()\n\
                  \x20   task = asyncio.Task(inner(probe.sleep_ms(2, 4)), loop=loop, eager_start=True)\n\
                  \x20   own = await probe.ready(1)\n\
                  \x20   return f'{await task},{own}'\n",
                c"direct_eager_probe.py",
                c"direct_eager_probe",
            )
            .expect("the probe compiles");
            module.getattr("handler").unwrap().unbind()
        });
        let (_, pool) = ensure_test_pools();
        let drive = tokio::task::spawn_blocking(move || {
            Python::attach(|python| {
                let coroutine = handler.bind(python).call0().unwrap();
                crate::script::runner::start(
                    &pool,
                    python,
                    &coroutine,
                    None,
                    crate::script::runner::Admit::Bounded,
                )
                .expect("admitted")
                .expect("taken by a runner")
            })
        })
        .await
        .expect("joined");
        let Waited::Settled(result) = drive.wait().await else {
            panic!("timed out");
        };
        let text = Python::attach(|python| {
            result
                .map(|value| value.extract::<String>(python).unwrap())
                .map_err(|error| error.to_string())
        });
        assert_eq!(text, Ok("5,1".to_string()));
        let _ = rig;
    });
}

/// An awaitable that failed does not outlive the handler: the exception it
/// keeps points, through its traceback and the handler's frame, back at the
/// awaitable, and the collector has to be able to see that ring.
#[test]
fn a_failed_awaitable_is_collected_after_the_handler() {
    with_pools(true, |rig| async move {
        assert_eq!(
            rig.call("fails_and_recovers", 0).await,
            Ok("recovered".to_string())
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let collected = rig
                .call("failed_awaitables_collected", 0)
                .await
                .expect("a sync probe");
            if collected == "True" {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "the failed awaitable is still alive: {collected}"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    });
}

/// Stop a driver with coroutines suspended on it: each is closed on its own
/// thread (its `finally` runs), its waiter is failed, its awaitable's Rust
/// future is dropped, and the runner's counts are back to zero.
fn shutdown_closes_suspended_coroutines(collect: bool) {
    const COROUTINES: usize = 24;
    Python::initialize();
    let runtime = test_pools_runtime();
    let pool = Arc::new(AsyncPool::spawn(
        1,
        runtime.handle().clone(),
        Duration::from_secs(30),
    ));
    let runner = Arc::clone(pool.runner(0).expect("the pool has one driver"));
    let dropped_before = NEVER_DROPPED.load(Ordering::SeqCst);

    let (module, drives) = Python::attach(|python| {
        let module = PyModule::from_code(
            python,
            c"import asyncio\n\
              closed = []\n\
              never = None\n\
              async def wedged(index):\n\
              \x20   try:\n\
              \x20       await never()\n\
              \x20   finally:\n\
              \x20       closed.append(index)\n\
              async def demoted(index):\n\
              \x20   try:\n\
              \x20       await asyncio.sleep(0)\n\
              \x20       await never()\n\
              \x20   finally:\n\
              \x20       closed.append(index)\n",
            c"direct_shutdown_probe.py",
            c"direct_shutdown_probe",
        )
        .expect("the probe compiles");
        module
            .setattr(
                "never",
                pyo3::wrap_pyfunction!(never_for_shutdown, python).unwrap(),
            )
            .unwrap();
        let drives: Vec<_> = (0..COROUTINES)
            .map(|index| {
                // Most stay direct; a few are tasks by the time the driver stops.
                let name = if index % 6 == 5 { "demoted" } else { "wedged" };
                let coroutine = module.getattr(name).unwrap().call1((index,)).unwrap();
                crate::script::runner::start(
                    &pool,
                    python,
                    &coroutine,
                    None,
                    crate::script::runner::Admit::Bounded,
                )
                .expect("admitted")
                .expect("taken by the runner")
            })
            .collect();
        (module.unbind(), drives)
    });

    // The handed-over ones are their task's from then on; the direct ones
    // stay the runner's, each suspended on a tracked awaitable.
    let direct = COROUTINES - COROUTINES / 6;
    let deadline = Instant::now() + Duration::from_secs(20);
    while runner.stats().awaitables < direct {
        assert!(
            Instant::now() < deadline,
            "every coroutine suspended: {:?}",
            runner.stats()
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(runner.stats().drives, COROUTINES);
    assert_eq!(runner.stats().in_flight, COROUTINES);

    let stop = Arc::new(AtomicBool::new(false));
    let collector = collect.then(|| collect_garbage_until(Arc::clone(&stop)));
    // Joins the driver thread: a shutdown that waits attached never returns.
    let (stopped_tx, stopped_rx) = mpsc::channel();
    std::thread::spawn(move || {
        drop(pool);
        let _ = stopped_tx.send(());
    });
    let stopped = stopped_rx.recv_timeout(Duration::from_secs(60)).is_ok();
    let waited = runtime.block_on(async {
        let mut failed = 0;
        for drive in drives {
            match tokio::time::timeout(Duration::from_secs(20), drive.wait()).await {
                Ok(Waited::Settled(Err(_))) => failed += 1,
                Ok(Waited::Settled(Ok(_))) => panic!("a closed coroutine returned a value"),
                Ok(Waited::TimedOut(_)) | Err(_) => {}
            }
        }
        failed
    });
    stop.store(true, Ordering::Relaxed);
    if let Some(collector) = collector {
        collector.join().expect("the collector stops");
    }

    assert!(stopped, "the driver did not stop");
    assert_eq!(waited, COROUTINES, "every waiter was failed");
    let stats = runner.stats();
    assert_eq!(
        (stats.drives, stats.in_flight, stats.awaitables),
        (0, 0, 0),
        "the slab drained"
    );
    let closed = Python::attach(|python| {
        module
            .bind(python)
            .getattr("closed")
            .unwrap()
            .len()
            .unwrap()
    });
    assert!(
        closed >= direct,
        "{closed} of {direct} coroutines were closed"
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    while NEVER_DROPPED.load(Ordering::SeqCst) - dropped_before < direct {
        assert!(
            Instant::now() < deadline,
            "every awaitable's Rust future was dropped"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

struct CountsDrop;

impl Drop for CountsDrop {
    fn drop(&mut self) {
        NEVER_DROPPED.fetch_add(1, Ordering::SeqCst);
    }
}

#[pyfunction]
fn never_for_shutdown(py: Python<'_>) -> PyResult<Bound<'_, PyAny>> {
    crate::script::awaitable(py, async move {
        let _guard = CountsDrop;
        std::future::pending::<()>().await;
        Ok(0i64)
    })
}

/// In a child process: the switch and `NEVER_DROPPED` are the process's.
#[test]
fn shutdown_closes_what_is_in_the_slab() {
    if !in_child(
        concat!(module_path!(), "::shutdown_closes_what_is_in_the_slab"),
        Duration::from_secs(120),
    ) {
        return;
    }
    crate::script::runner::set_enabled_for_test(true);
    shutdown_closes_suspended_coroutines(false);
}

/// The same with another thread forcing stop-the-world collections while the
/// driver closes its coroutines.
#[test]
fn shutdown_survives_stop_the_world_collections() {
    if !in_child(
        concat!(
            module_path!(),
            "::shutdown_survives_stop_the_world_collections"
        ),
        Duration::from_secs(150),
    ) {
        return;
    }
    crate::script::runner::set_enabled_for_test(true);
    shutdown_closes_suspended_coroutines(true);
}
