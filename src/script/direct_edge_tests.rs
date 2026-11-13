//! The narrow places of direct dispatch: a timeout or a cancellation landing
//! at an exact point of a step, a loop the direct path must stay off, and
//! what an awaitable keeps alive.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use pyo3::prelude::*;

use crate::script::async_pool::ensure_test_pools;
use crate::script::direct::test_hooks::{self, Point};
use crate::script::direct::{Drive, TestAwaitable};
use crate::script::direct_tests::{open_gate, start_on_executor, with_pools};
use crate::script::stop_the_world_tests::{collect_garbage_until, in_child};

/// A flag threads wait on.
#[derive(Default)]
struct Latch {
    open: Mutex<bool>,
    changed: Condvar,
}

impl Latch {
    fn open(&self) {
        *self.open.lock().unwrap() = true;
        self.changed.notify_all();
    }

    fn wait(&self) {
        let mut open = self.open.lock().unwrap();
        while !*open {
            open = self.changed.wait(open).unwrap();
        }
    }
}

/// Every executor worker, held until dropped.
struct BlockedExecutor(Arc<Latch>);

impl Drop for BlockedExecutor {
    fn drop(&mut self) {
        self.0.open();
    }
}

async fn block_executor() -> BlockedExecutor {
    let (executor, _) = ensure_test_pools();
    let workers = executor.max_size();
    let latch = Arc::new(Latch::default());
    let entered = Arc::new(AtomicUsize::new(0));
    for _ in 0..workers {
        let latch = Arc::clone(&latch);
        let entered = Arc::clone(&entered);
        crate::script::py_executor::spawn(move || {
            entered.fetch_add(1, Ordering::SeqCst);
            latch.wait();
        });
    }
    let deadline = Instant::now() + Duration::from_secs(20);
    while entered.load(Ordering::SeqCst) < workers {
        assert!(Instant::now() < deadline, "the executor workers were taken");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    BlockedExecutor(latch)
}

/// Fill the executor queue to its capacity with jobs that do nothing.
fn fill_executor_queue() {
    for _ in 0..1_000_000 {
        let before = crate::script::py_executor::queue_depth();
        crate::script::py_executor::spawn(|| {});
        if crate::script::py_executor::queue_depth() == before {
            return;
        }
    }
    panic!("the executor queue never filled");
}

/// Run `work` attached, off the runtime's workers.
async fn attached<T: Send + 'static>(
    work: impl for<'py> FnOnce(Python<'py>) -> T + Send + 'static,
) -> T {
    tokio::task::spawn_blocking(move || Python::attach(work))
        .await
        .expect("the attached work ran")
}

/// Install a hook that hands the test each drive reaching `point`, and holds
/// the stepping thread there until `resume` opens when `hold` is set.
fn watch(
    point: Point,
    hold: bool,
) -> (
    test_hooks::Installed,
    std::sync::mpsc::Receiver<Arc<Drive>>,
    Arc<Latch>,
) {
    let (seen, reached) = std::sync::mpsc::channel();
    let seen = Mutex::new(seen);
    let resume = Arc::new(Latch::default());
    let held = Arc::clone(&resume);
    let fired = AtomicBool::new(false);
    let installed = test_hooks::install(Arc::new(move |at, drive| {
        if at != point || fired.swap(true, Ordering::SeqCst) {
            return;
        }
        let _ = seen.lock().unwrap().send(Arc::clone(drive));
        if hold {
            held.wait();
        }
    }));
    (installed, reached, resume)
}

async fn drive_at(reached: std::sync::mpsc::Receiver<Arc<Drive>>) -> Arc<Drive> {
    tokio::task::spawn_blocking(move || reached.recv_timeout(Duration::from_secs(20)))
        .await
        .expect("joined")
        .expect("the coroutine reached the hook")
}

/// A timeout that is being delivered when its watchdog is stopped is still
/// delivered. With the executor queue full the delivery waits for room; the
/// waiter must get its `TimeoutError` however that wait ends.
#[test]
fn a_timeout_whose_delivery_is_interrupted_still_reaches_the_waiter() {
    with_pools(|_rig| async move {
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let deadline = start_on_executor("wedged")
            .await
            .resume_on_executor_watched(move |result| {
                let _ = sender.send(result.map(|_| ()).map_err(|error| error.to_string()));
            })
            .expect("driven by the executor");

        let blocked = block_executor().await;
        fill_executor_queue();
        // The queue is full, so the delivery has to wait for room. Whatever
        // started it must be free to go away meanwhile: the watchdog task is
        // aborted, and a waiting caller dropped, the moment the handler
        // finishes or is handed over.
        let expiry = tokio::spawn(async move { deadline.expire() });
        tokio::time::sleep(Duration::from_millis(200)).await;
        expiry.abort();
        drop(blocked);

        let outcome = tokio::time::timeout(Duration::from_secs(20), receiver)
            .await
            .expect("the waiter was answered")
            .expect("the waiter's completion was dropped");
        let error = outcome.expect_err("times out");
        assert!(error.contains("did not settle"), "{error}");
    });
}

/// A cancellation that arrives after the coroutine yielded an awaitable and
/// before it is registered as its waiter still raises `CancelledError` in the
/// coroutine, once, wherever in that window it lands.
#[test]
fn a_cancellation_between_yield_and_wait_wakes_the_coroutine() {
    with_pools(|rig| async move {
        let (_, async_pool) = ensure_test_pools();
        let patience = (async_pool.coroutine_timeout() / 2).min(Duration::from_millis(1500));
        let rig = Arc::new(rig);
        for (round, point) in [Point::AtSuspend, Point::BeforeRegister]
            .into_iter()
            .enumerate()
        {
            let (_hook, reached, resume) = watch(point, true);
            let call = {
                let rig = Arc::clone(&rig);
                tokio::spawn(async move { rig.call("wedged", 0).await })
            };
            let drive = drive_at(reached).await;
            assert!(attached(move |python| drive.cancel(python)).await);
            resume.open();

            let outcome = tokio::time::timeout(patience, call)
                .await
                .unwrap_or_else(|_| panic!("cancelled at {point:?}, never woken"))
                .expect("joined");
            let error = outcome.expect_err("cancelled");
            assert!(error.contains("CancelledError"), "{error}");
            assert_eq!(
                rig.call("wedged_counts", 0).await,
                Ok(format!("{}|0", round + 1)),
                "at {point:?}"
            );
        }
    });
}

/// A cancellation that arrives after the awaitable finished and before the
/// coroutine was resumed is not lost: the resume raises `CancelledError` at
/// the await, and nothing after it runs.
#[test]
fn a_cancellation_after_the_awaitable_finished_is_raised_on_resume() {
    with_pools(|rig| async move {
        let rig = Arc::new(rig);
        let (_hook, reached, _resume) = watch(Point::BeforeRegister, false);
        let call = {
            let rig = Arc::clone(&rig);
            tokio::spawn(async move { rig.call("gated", 0).await })
        };
        let drive = drive_at(reached).await;

        // With every worker taken the resume step can only queue.
        let blocked = block_executor().await;
        let queued = crate::script::py_executor::queue_depth();
        open_gate();
        let deadline = Instant::now() + Duration::from_secs(20);
        while crate::script::py_executor::queue_depth() <= queued {
            assert!(Instant::now() < deadline, "the resume step was queued");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(attached(move |python| drive.cancel(python)).await);
        drop(blocked);

        let outcome = tokio::time::timeout(Duration::from_secs(20), call)
            .await
            .expect("the handler finished")
            .expect("joined");
        let error = outcome.expect_err("cancelled, not returned");
        assert!(error.contains("CancelledError"), "{error}");
        assert_eq!(rig.call("wedged_counts", 0).await, Ok("1|0".to_string()));
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
    with_pools(|rig| async move {
        assert_eq!(
            rig.call("holds_a_cancelled_awaitable", 1).await,
            Ok("1".to_string())
        );
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
            let held = awaitable.bind(python).cast::<TestAwaitable>().unwrap();
            assert!(held.get().cancel_for_test(python));
            python
                .run(c"import gc\ngc.set_threshold(1)\n", None, None)
                .unwrap();
        });

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
            let event_loop = &pool.driver_loop(index).expect("a driver").event_loop;
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

/// An eager task factory would run the hand-over's task before the step that
/// hands over has ended. On a loop with a task factory handlers start on the
/// driver, and are driven directly again once it is removed.
#[test]
fn a_loop_with_a_task_factory_is_not_driven_directly() {
    with_pools(|rig| async move {
        {
            let _eager = OnEveryLoop::set(
                c"import asyncio\nloop.set_task_factory(asyncio.eager_task_factory)\n",
                c"loop.set_task_factory(None)\n",
            );
            for _ in 0..2 {
                assert_eq!(
                    rig.call("sleeps_for_real", 8).await,
                    Ok("8|True".to_string())
                );
                assert_eq!(rig.call("one_await", 5).await, Ok("5|True".to_string()));
            }
        }
        assert_eq!(rig.call("one_await", 5).await, Ok("5|False".to_string()));
    });
}

/// asyncio's debug mode refuses loop calls from any thread but the loop's.
/// On a loop in debug mode handlers start on the driver, and are driven
/// directly again once it is switched off.
#[test]
fn a_loop_in_debug_mode_is_not_driven_directly() {
    with_pools(|rig| async move {
        {
            let _debug = OnEveryLoop::set(c"loop.set_debug(True)\n", c"loop.set_debug(False)\n");
            assert_eq!(
                rig.call("ordered", 0).await,
                Ok("handler,callback".to_string())
            );
            assert_eq!(rig.call("one_await", 5).await, Ok("5|True".to_string()));
        }
        assert_eq!(rig.call("one_await", 5).await, Ok("5|False".to_string()));
    });
}

/// An awaitable that failed does not outlive the handler: the exception it
/// keeps points, through its traceback and the handler's frame, back at the
/// awaitable, and the collector has to be able to see that ring.
#[test]
fn a_failed_awaitable_is_collected_after_the_handler() {
    with_pools(|rig| async move {
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

/// Direct dispatch is on only after its self-test passed on this interpreter,
/// and with it off every handler runs on a driver, as before.
#[test]
fn direct_dispatch_follows_its_self_test() {
    with_pools(|rig| async move {
        assert!(
            crate::script::direct::is_enabled(),
            "the self-test passed when the pool was installed"
        );
        assert_eq!(rig.call("one_await", 5).await, Ok("5|False".to_string()));
        crate::script::direct::set_enabled(false);
        let off = rig.call("one_await", 5).await;
        crate::script::direct::set_enabled(true);
        assert_eq!(off, Ok("5|True".to_string()));
        assert_eq!(rig.call("one_await", 5).await, Ok("5|False".to_string()));
    });
}
