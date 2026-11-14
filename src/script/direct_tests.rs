//! Behaviour of `async def` handlers that await siphon's own awaitables:
//! driven from the executor without an asyncio task while that is all they
//! do, and handed to an asyncio driver, intact, the moment they use asyncio
//! for anything else.

use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use pyo3::prelude::*;
use pyo3::types::{PyModule, PyModuleMethods};
use tempfile::NamedTempFile;

use crate::script::async_pool::{ensure_test_pools, pool_test_guard, test_pools_runtime};
use crate::script::engine::ScriptEngine;
use crate::script::handle::ScriptHandle;
use crate::script::stop_the_world_tests::{collect_garbage_until, in_child};

/// Futures behind `never()` that were dropped: a cancelled awaitable must
/// drop its Rust future, not leave it parked on tokio.
pub(super) static NEVER_DROPPED: AtomicUsize = AtomicUsize::new(0);

struct CountsDrop;

impl Drop for CountsDrop {
    fn drop(&mut self) {
        NEVER_DROPPED.fetch_add(1, Ordering::SeqCst);
    }
}

#[pyfunction]
fn ready(py: Python<'_>, value: i64) -> PyResult<Bound<'_, PyAny>> {
    crate::script::awaitable(py, async move { Ok(value) })
}

#[pyfunction]
fn sleep_ms(py: Python<'_>, millis: u64, value: i64) -> PyResult<Bound<'_, PyAny>> {
    crate::script::awaitable(py, async move {
        tokio::time::sleep(Duration::from_millis(millis)).await;
        Ok(value)
    })
}

#[pyfunction]
fn fail(py: Python<'_>, message: String) -> PyResult<Bound<'_, PyAny>> {
    crate::script::awaitable(py, async move {
        tokio::time::sleep(Duration::from_millis(1)).await;
        Err::<i64, _>(pyo3::exceptions::PyValueError::new_err(message))
    })
}

#[pyfunction]
fn never(py: Python<'_>) -> PyResult<Bound<'_, PyAny>> {
    crate::script::awaitable(py, async move {
        let _guard = CountsDrop;
        std::future::pending::<()>().await;
        Ok(0i64)
    })
}

/// The sender that completes the awaitable `gate()` last made.
static GATE: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>> =
    std::sync::Mutex::new(None);

/// An awaitable that completes when the test calls [`open_gate`].
#[pyfunction]
fn gate(py: Python<'_>) -> PyResult<Bound<'_, PyAny>> {
    let (sender, receiver) = tokio::sync::oneshot::channel();
    *GATE.lock().unwrap() = Some(sender);
    crate::script::awaitable(py, async move {
        let _ = receiver.await;
        Ok(5i64)
    })
}

pub(super) fn open_gate() {
    if let Some(sender) = GATE.lock().unwrap().take() {
        let _ = sender.send(());
    }
}

#[pyfunction]
fn deferred(py: Python<'_>, text: String) -> PyResult<Bound<'_, PyAny>> {
    crate::script::awaitable(py, async move {
        tokio::time::sleep(Duration::from_millis(1)).await;
        Ok(crate::script::Deferred::build(move |_python| {
            Ok(format!("built:{text}"))
        }))
    })
}

/// The OS thread name: Python's `threading` only knows threads it started.
#[pyfunction]
pub(super) fn thread_name() -> String {
    std::thread::current()
        .name()
        .unwrap_or("<unnamed>")
        .to_string()
}

pub(super) fn install_probe_module() {
    Python::initialize();
    Python::attach(|python| {
        let modules = python.import("sys").unwrap().getattr("modules").unwrap();
        if modules.contains("_direct_probe").unwrap() {
            return;
        }
        let module = PyModule::new(python, "_direct_probe").unwrap();
        for function in [
            pyo3::wrap_pyfunction!(ready, &module).unwrap(),
            pyo3::wrap_pyfunction!(sleep_ms, &module).unwrap(),
            pyo3::wrap_pyfunction!(fail, &module).unwrap(),
            pyo3::wrap_pyfunction!(never, &module).unwrap(),
            pyo3::wrap_pyfunction!(gate, &module).unwrap(),
            pyo3::wrap_pyfunction!(deferred, &module).unwrap(),
            pyo3::wrap_pyfunction!(thread_name, &module).unwrap(),
        ] {
            module.add_function(function).unwrap();
        }
        modules.set_item("_direct_probe", &module).unwrap();
    });
}

const SCRIPT: &str = r#"
import asyncio
import contextvars
import gc
import logging
import weakref
import _siphon_registry as _r
import _direct_probe as probe

where = probe.thread_name
log = logging.getLogger("direct-tests")
request_id = contextvars.ContextVar("request_id", default="unset")

def on_driver(name):
    return name.startswith("siphon-asyncio")

async def one_await(x):
    value = await probe.ready(x)
    return f"{value}|{on_driver(where())}"

async def many_awaits(x):
    total = 0
    drivers = 0
    for index in range(50):
        total += await (probe.sleep_ms(1, index) if index % 5 == 0 else probe.ready(index))
        drivers += on_driver(where())
    return f"{total}|{drivers}"

async def nested(x):
    async def inner(y):
        return await probe.sleep_ms(1, y) + 1
    value = await inner(x)
    return f"{value}|{on_driver(where())}"

async def built(x):
    return await probe.deferred("abc") + f"|{on_driver(where())}"

async def caught(x):
    try:
        await probe.fail("boom")
    except ValueError as error:
        return f"caught:{error}|{on_driver(where())}"
    return "not raised"

async def uncaught(x):
    await probe.fail("escapes")

async def raises_after(x):
    await probe.ready(x)
    raise KeyError("after the await")

async def mixed(x):
    before = asyncio.current_task()
    first = await probe.ready(3)
    await asyncio.sleep(0)
    second = await probe.sleep_ms(1, 4)
    same = asyncio.current_task() is before
    return f"{first + second}|{same}"

async def sleeps_for_real(x):
    first = await probe.ready(x)
    await asyncio.sleep(0.01)
    return f"{first}|{on_driver(where())}"

spawned = []

async def background(tag):
    value = await probe.sleep_ms(20, 9)
    spawned.append(f"{tag}:{value}")

async def spawns_then_awaits(x):
    asyncio.create_task(background("then-awaits"))
    return await probe.ready(x)

async def awaits_then_spawns(x):
    value = await probe.ready(x)
    asyncio.create_task(background("awaits-then"))
    return value

def spawned_tags(*_):
    return ",".join(sorted(spawned))

order = []

async def scheduled_callbacks_wait_for_the_step(x):
    loop = asyncio.get_running_loop()
    loop.call_soon(order.append, "callback")
    asyncio.create_task(background("ordered"))
    # A callback the handler scheduled must not run under it: asyncio runs
    # one thing at a time per handler.
    for _ in range(20000):
        pass
    order.append("handler")
    await asyncio.sleep(0)
    await probe.ready(1)
    return ",".join(order)

async def waits_within_a_timeout(x):
    return await asyncio.wait_for(probe.sleep_ms(1, x), timeout=5)

async def timeout_fires(x):
    task = asyncio.current_task()
    try:
        await asyncio.wait_for(probe.never(), timeout=0.05)
    except TimeoutError:
        after = await probe.ready(x)
        return f"timed out|{after}|{asyncio.current_task() is task}|{task.cancelling()}"
    return "no timeout"

async def timeout_block_spans_the_handover(x):
    task = asyncio.current_task()
    try:
        async with asyncio.timeout(0.05):
            await probe.ready(1)
            await asyncio.sleep(0)
            await probe.never()
    except TimeoutError:
        return f"timed out|{asyncio.current_task() is task}"
    return "no timeout"

async def gathers(x):
    left, right = await asyncio.gather(probe.sleep_ms(2, 1), probe.ready(2))
    return f"{left},{right}"

async def logs_then_awaits(x):
    log.warning("a log record reads the current task's name")
    name = asyncio.current_task().get_name()
    value = await probe.ready(x)
    return f"{value}|{on_driver(where())}|{bool(name)}"

async def context_survives(x):
    request_id.set(f"req-{x}")
    await probe.sleep_ms(1, 0)
    first = request_id.get()
    await asyncio.sleep(0)
    await probe.ready(0)
    return f"{first}|{request_id.get()}"

async def context_is_per_call(x):
    seen = request_id.get()
    request_id.set("leaked")
    await probe.ready(0)
    return seen

async def generator(limit):
    for index in range(limit):
        yield await probe.ready(index)

async def iterates(x):
    total = 0
    async for value in generator(4):
        total += value
    return f"{total}|{on_driver(where())}"

async def awaits_twice(x):
    pending = probe.sleep_ms(1, x)
    first = await pending
    second = await pending
    return f"{first},{second}"

async def started_before_awaited(x):
    slow = probe.sleep_ms(30, 1)
    quick = probe.ready(2)
    return f"{await quick},{await slow}"

async def future_api(x):
    pending = probe.sleep_ms(1, x)
    seen = []
    pending.add_done_callback(lambda future: seen.append(future.result()))
    done, _ = await asyncio.wait([pending])
    await asyncio.sleep(0)
    return f"{len(done)}|{pending.done()}|{pending.result()}|{seen}"

resumed = []
cancelled = []

async def wedged(x):
    try:
        await probe.never()
    except asyncio.CancelledError:
        cancelled.append(x)
        raise
    resumed.append(x)

def wedged_counts(*_):
    return f"{len(cancelled)}|{len(resumed)}"

async def slow(x):
    return await probe.sleep_ms(300, x)

async def churn(x):
    total = 0
    for index in range(20):
        total += await probe.sleep_ms(1, 1)
        junk = [[index]]
        junk[0].append(junk)
    return total

async def suspends_then_sleeps(x):
    value = await probe.sleep_ms(5, x)
    await asyncio.sleep(0.01)
    return f"{value}|{on_driver(where())}"

stages = []

async def counts_its_stages(x):
    stages.append("a")
    await probe.sleep_ms(1, 0)
    stages.append("b")
    await asyncio.sleep(0)
    stages.append("c")
    await probe.ready(0)
    stages.append("d")
    return "".join(stages)

shared = []

async def shares_first(x):
    shared.append(probe.sleep_ms(100, 5))
    return await shared[0]

async def shares_second(x):
    while not shared:
        await probe.sleep_ms(1, 0)
    return await shared[0]

async def cancels_itself(x):
    asyncio.current_task().cancel()
    await probe.ready(x)
    return "not cancelled"

kept = []

async def keeps_its_task(x):
    kept.append(asyncio.current_task())
    return await probe.ready(x)

def uses_a_kept_task(*_):
    task = kept[0]
    called = []
    task.add_done_callback(called.append)
    return f"{task.done()}|{task.cancel()}|{task.cancelled()}|{task.get_name() != ''}"

async def gated(x):
    try:
        value = await probe.gate()
    except asyncio.CancelledError:
        cancelled.append(x)
        raise
    resumed.append(value)
    return "returned"

held = []

async def holds_a_cancelled_awaitable(x):
    held.append(probe.never())
    return await probe.ready(x)

def the_held_awaitable(*_):
    return held[0]

failed = []

async def fails_and_recovers(x):
    pending = probe.fail("boom")
    failed.append(weakref.ref(pending))
    try:
        await pending
    except ValueError:
        pass
    return "recovered"

def failed_awaitables_collected(*_):
    gc.collect()
    return ",".join(str(ref() is None) for ref in failed)

def from_sync(x):
    return probe.ready(x)

for name, fn, is_async in [
    ("one_await", one_await, True), ("many_awaits", many_awaits, True),
    ("nested", nested, True), ("built", built, True), ("caught", caught, True),
    ("uncaught", uncaught, True), ("raises_after", raises_after, True),
    ("mixed", mixed, True), ("sleeps_for_real", sleeps_for_real, True),
    ("spawns_then_awaits", spawns_then_awaits, True),
    ("awaits_then_spawns", awaits_then_spawns, True),
    ("spawned_tags", spawned_tags, False),
    ("ordered", scheduled_callbacks_wait_for_the_step, True),
    ("waits_within_a_timeout", waits_within_a_timeout, True),
    ("timeout_fires", timeout_fires, True),
    ("timeout_block", timeout_block_spans_the_handover, True),
    ("gathers", gathers, True), ("logs_then_awaits", logs_then_awaits, True),
    ("context_survives", context_survives, True),
    ("context_is_per_call", context_is_per_call, True),
    ("iterates", iterates, True), ("awaits_twice", awaits_twice, True),
    ("started_before_awaited", started_before_awaited, True),
    ("future_api", future_api, True), ("wedged", wedged, True),
    ("wedged_counts", wedged_counts, False), ("slow", slow, True),
    ("churn", churn, True), ("from_sync", from_sync, False),
    ("suspends_then_sleeps", suspends_then_sleeps, True),
    ("counts_its_stages", counts_its_stages, True),
    ("shares_first", shares_first, True), ("shares_second", shares_second, True),
    ("cancels_itself", cancels_itself, True),
    ("keeps_its_task", keeps_its_task, True),
    ("uses_a_kept_task", uses_a_kept_task, False),
    ("gated", gated, True),
    ("holds_a_cancelled_awaitable", holds_a_cancelled_awaitable, True),
    ("the_held_awaitable", the_held_awaitable, False),
    ("fails_and_recovers", fails_and_recovers, True),
    ("failed_awaitables_collected", failed_awaitables_collected, False),
]:
    _r.register("direct." + name, None, fn, is_async, None)
"#;

pub(super) struct Rig {
    pub(super) handle: ScriptHandle,
    // The engine owns the handlers the handle reads.
    _engine: Arc<ScriptEngine>,
}

impl Rig {
    /// A rig running `script`, whose handlers register as `direct.<name>`.
    pub(super) fn with_script(script: &str) -> Self {
        install_probe_module();
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(script.as_bytes()).unwrap();
        file.flush().unwrap();
        let engine = Arc::new(
            ScriptEngine::new(&crate::config::ScriptConfig {
                path: file.path().to_str().unwrap().to_owned(),
                reload: crate::config::ReloadMode::Sighup,
                async_pool_size: None,
                sync_pool_size: None,
                sync_pool_max: None,
                handler_stall_abort_secs: 30,
                process_stall_abort_secs: 30,
                handler_timeout_secs: None,
                executor_queue_capacity: 1024,
                include_paths: Vec::new(),
            })
            .unwrap(),
        );
        let handle = ScriptHandle::new(engine.state_arc(), tokio::runtime::Handle::current());
        Self {
            handle,
            _engine: engine,
        }
    }

    /// Call `direct.<name>(argument)`: its result as `str()`, or its error's
    /// text.
    pub(super) async fn call(&self, name: &str, argument: i64) -> Result<String, String> {
        let handler = self
            .handle
            .handlers_for(&format!("direct.{name}"))
            .into_iter()
            .next()
            .unwrap_or_else(|| panic!("direct.{name} is registered"));
        self.handle
            .call_handler_with(
                &handler,
                move |python| Ok(vec![argument.into_pyobject(python)?.into_any().unbind()]),
                |_python, outcome| {
                    outcome
                        .and_then(|value| value.str()?.extract::<String>())
                        .map_err(|error| error.to_string())
                },
            )
            .await
            .expect("the handler was dispatched")
    }
}

/// Run `scenario` on the pools' runtime with the pools installed, one test at
/// a time.
pub(super) fn with_pools<F, Fut>(scenario: F)
where
    F: FnOnce(Rig) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    with_pools_running(SCRIPT, scenario);
}

/// [`with_pools`] for a rig running `script`.
pub(super) fn with_pools_running<F, Fut>(script: &'static str, scenario: F)
where
    F: FnOnce(Rig) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let _serial = pool_test_guard();
    test_pools_runtime().block_on(async {
        ensure_test_pools();
        // No test waits longer than this: a hang is a failure, not a stall.
        tokio::time::timeout(Duration::from_secs(60), scenario(Rig::with_script(script)))
            .await
            .expect("the scenario finished");
    });
}

/// One await of a siphon awaitable resumes on the executor: no asyncio driver
/// runs any part of the handler.
#[test]
fn one_await_resumes_off_the_asyncio_drivers() {
    with_pools(|rig| async move {
        assert_eq!(rig.call("one_await", 5).await, Ok("5|False".to_string()));
        assert_eq!(rig.call("nested", 5).await, Ok("6|False".to_string()));
        assert_eq!(
            rig.call("built", 0).await,
            Ok("built:abc|False".to_string())
        );
    });
}

/// Fifty awaits, ready and not: the sum is right and none of the fifty
/// continuations ran on a driver.
#[test]
fn many_awaits_all_resume_off_the_asyncio_drivers() {
    with_pools(|rig| async move {
        let expected: i64 = (0..50).sum();
        assert_eq!(
            rig.call("many_awaits", 0).await,
            Ok(format!("{expected}|0"))
        );
    });
}

/// An awaitable's error is raised at the `await`: the coroutine can catch it,
/// and one it lets go is the handler's error.
#[test]
fn an_awaitable_error_is_thrown_into_the_coroutine() {
    with_pools(|rig| async move {
        assert_eq!(
            rig.call("caught", 0).await,
            Ok("caught:boom|False".to_string())
        );
        let escaped = rig.call("uncaught", 0).await.expect_err("raised");
        assert!(escaped.contains("escapes"), "{escaped}");
        let after = rig.call("raises_after", 0).await.expect_err("raised");
        assert!(after.contains("after the await"), "{after}");
    });
}

/// A coroutine that awaits a siphon awaitable and then asyncio is handed to a
/// driver mid-flight and finishes there with the right value, as the same
/// task it started as. Repeated, because the first hand-over is remembered.
#[test]
fn a_mixed_coroutine_is_handed_to_asyncio_and_returns_the_right_value() {
    with_pools(|rig| async move {
        for _ in 0..3 {
            assert_eq!(rig.call("mixed", 0).await, Ok("7|True".to_string()));
            assert_eq!(
                rig.call("sleeps_for_real", 8).await,
                Ok("8|True".to_string())
            );
        }
    });
}

/// A hand-over after the handler was resumed by the executor reaches the
/// caller that is already waiting for it, and no stage of a handler runs
/// twice or is skipped on the way.
#[test]
fn a_hand_over_after_a_suspension_finishes_once() {
    with_pools(|rig| async move {
        for _ in 0..2 {
            assert_eq!(
                rig.call("suspends_then_sleeps", 3).await,
                Ok("3|True".to_string())
            );
        }
        assert_eq!(
            rig.call("counts_its_stages", 0).await,
            Ok("abcd".to_string())
        );
        assert_eq!(
            rig.call("counts_its_stages", 0).await,
            Ok("abcdabcd".to_string())
        );
    });
}

/// Two handlers awaiting one awaitable both get its value.
#[test]
fn two_handlers_can_await_one_awaitable() {
    with_pools(|rig| async move {
        let rig = Arc::new(rig);
        let first = {
            let rig = Arc::clone(&rig);
            tokio::spawn(async move { rig.call("shares_first", 0).await })
        };
        let second = rig.call("shares_second", 0).await;
        assert_eq!(first.await.expect("joined"), Ok("5".to_string()));
        assert_eq!(second, Ok("5".to_string()));
    });
}

/// A handler's task answers for itself: cancelling it raises
/// `CancelledError` at the next await, and one kept past the handler reads as
/// a finished task.
#[test]
fn the_current_task_behaves_as_a_task() {
    with_pools(|rig| async move {
        let cancelled = rig.call("cancels_itself", 1).await.expect_err("cancelled");
        assert!(cancelled.contains("CancelledError"), "{cancelled}");
        assert_eq!(rig.call("keeps_its_task", 4).await, Ok("4".to_string()));
        assert_eq!(
            rig.call("uses_a_kept_task", 0).await,
            Ok("True|False|False|True".to_string())
        );
    });
}

/// `asyncio.create_task` from a handler is driven to completion, called
/// before the handler's first await or after it, including by a handler that
/// returns straight after.
#[test]
fn a_task_created_by_a_handler_still_completes() {
    with_pools(|rig| async move {
        for _ in 0..2 {
            assert_eq!(rig.call("spawns_then_awaits", 1).await, Ok("1".to_string()));
            assert_eq!(rig.call("awaits_then_spawns", 2).await, Ok("2".to_string()));
        }
        let expected = "awaits-then:9,awaits-then:9,then-awaits:9,then-awaits:9";
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let tags = rig.call("spawned_tags", 0).await.expect("a sync probe");
            if tags == expected {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "background tasks finished: {tags}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });
}

/// What a handler schedules on its loop runs after the step that scheduled
/// it, never alongside.
#[test]
fn callbacks_a_handler_schedules_do_not_run_under_it() {
    with_pools(|rig| async move {
        assert_eq!(
            rig.call("ordered", 0).await,
            Ok("handler,callback".to_string())
        );
    });
}

/// `asyncio.wait_for` and `asyncio.timeout` around siphon awaitables: they
/// need a current task and a loop from the first step on.
#[test]
fn asyncio_timeouts_work_around_siphon_awaitables() {
    with_pools(|rig| async move {
        for _ in 0..2 {
            assert_eq!(
                rig.call("waits_within_a_timeout", 4).await,
                Ok("4".to_string())
            );
            assert_eq!(
                rig.call("timeout_fires", 6).await,
                Ok("timed out|6|True|0".to_string())
            );
            assert_eq!(
                rig.call("timeout_block", 0).await,
                Ok("timed out|True".to_string())
            );
        }
    });
}

#[test]
fn gather_over_siphon_awaitables_returns_both() {
    with_pools(|rig| async move {
        for _ in 0..2 {
            assert_eq!(rig.call("gathers", 0).await, Ok("1,2".to_string()));
        }
    });
}

/// The awaitable is a future to asyncio's own helpers, done callbacks and
/// all, and can be awaited more than once.
#[test]
fn an_awaitable_keeps_the_future_api() {
    with_pools(|rig| async move {
        for _ in 0..2 {
            assert_eq!(
                rig.call("future_api", 5).await,
                Ok("1|True|5|[5]".to_string())
            );
            assert_eq!(rig.call("awaits_twice", 3).await, Ok("3,3".to_string()));
        }
    });
}

/// The Rust future starts when the awaitable is made, not when it is awaited.
#[test]
fn an_awaitable_runs_before_it_is_awaited() {
    with_pools(|rig| async move {
        assert_eq!(
            rig.call("started_before_awaited", 0).await,
            Ok("2,1".to_string())
        );
    });
}

/// Logging reads `asyncio.current_task().get_name()` for every record; that
/// must not cost the handler its direct path.
#[test]
fn logging_in_a_handler_keeps_it_off_the_drivers() {
    with_pools(|rig| async move {
        assert_eq!(
            rig.call("logs_then_awaits", 2).await,
            Ok("2|False|True".to_string())
        );
    });
}

/// A context variable set before an await is there after it, on whichever
/// thread the handler resumes and across the hand-over, and never leaks into
/// the next call.
#[test]
fn context_variables_follow_the_coroutine() {
    with_pools(|rig| async move {
        assert_eq!(
            rig.call("context_survives", 7).await,
            Ok("req-7|req-7".to_string())
        );
        for _ in 0..8 {
            assert_eq!(
                rig.call("context_is_per_call", 0).await,
                Ok("unset".to_string())
            );
        }
    });
}

#[test]
fn an_async_generator_over_siphon_awaitables_iterates() {
    with_pools(|rig| async move {
        assert_eq!(rig.call("iterates", 0).await, Ok("6|False".to_string()));
    });
}

/// A synchronous handler cannot await: making the awaitable there fails with
/// the error that says to use `async def`.
#[test]
fn a_sync_handler_is_told_to_be_async() {
    with_pools(|rig| async move {
        let error = rig
            .call("from_sync", 1)
            .await
            .expect_err("no loop to await on");
        assert!(error.contains("async def"), "{error}");
    });
}

/// More awaiting handlers than executor workers run at once: a pending
/// awaitable holds no thread.
#[test]
fn pending_awaitables_hold_no_executor_worker() {
    with_pools(|rig| async move {
        let (executor, _) = ensure_test_pools();
        let rig = Arc::new(rig);
        let calls = 4 * executor.max_size() + 1;
        let started = Instant::now();
        let joins: Vec<_> = (0..calls)
            .map(|index| {
                let rig = Arc::clone(&rig);
                tokio::spawn(async move { rig.call("slow", index as i64).await })
            })
            .collect();
        let mut answers = Vec::new();
        for join in joins {
            answers.push(join.await.expect("joined").expect("returned"));
        }
        let elapsed = started.elapsed();
        let mut expected: Vec<String> = (0..calls).map(|index| index.to_string()).collect();
        answers.sort();
        expected.sort();
        assert_eq!(answers, expected);
        assert!(
            elapsed < Duration::from_millis(1200),
            "{calls} handlers each awaiting 300 ms took {elapsed:?}"
        );
    });
}

/// A handler whose awaitable never completes fails with the coroutine
/// timeout. Its coroutine is cancelled exactly once and never resumed past
/// the await, its Rust future is dropped, and nothing stays pending.
#[test]
fn a_timed_out_handler_is_cancelled_once_and_leaks_nothing() {
    with_pools(|rig| async move {
        let (_, async_pool) = ensure_test_pools();
        let rig = Arc::new(rig);
        let baseline = crate::script::async_pool::pending_coroutines();
        let dropped_before = NEVER_DROPPED.load(Ordering::SeqCst);

        const CALLS: usize = 6;
        let joins: Vec<_> = (0..CALLS)
            .map(|index| {
                let rig = Arc::clone(&rig);
                tokio::spawn(async move { rig.call("wedged", index as i64).await })
            })
            .collect();
        for join in joins {
            let error = join.await.expect("joined").expect_err("timed out");
            assert!(error.contains("did not settle"), "{error}");
        }

        let deadline = Instant::now() + async_pool.coroutine_timeout();
        loop {
            let counts = rig.call("wedged_counts", 0).await.expect("a sync probe");
            let dropped = NEVER_DROPPED.load(Ordering::SeqCst) - dropped_before;
            let pending = crate::script::async_pool::pending_coroutines();
            if counts == format!("{CALLS}|0") && dropped == CALLS && pending <= baseline {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "cancelled|resumed = {counts}, futures dropped = {dropped}, \
                 pending = {pending} (baseline {baseline})"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        // Settled, not merely passing through: nothing resumes later.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            rig.call("wedged_counts", 0).await,
            Ok(format!("{CALLS}|0")),
            "a cancelled coroutine was resumed a second time"
        );
    });
}

/// Handlers awaiting siphon awaitables keep completing while another thread
/// forces stop-the-world collections: no thread on the path waits attached.
/// Run in a child process so a deadlock is a failure, not a hung test run.
#[test]
fn awaiting_survives_stop_the_world_collections() {
    if !in_child(
        concat!(
            module_path!(),
            "::awaiting_survives_stop_the_world_collections"
        ),
        Duration::from_secs(120),
    ) {
        return;
    }
    with_pools(|rig| async move {
        let stop = Arc::new(AtomicBool::new(false));
        let collector = collect_garbage_until(Arc::clone(&stop));
        let rig = Arc::new(rig);
        for name in ["churn", "mixed"] {
            let joins: Vec<_> = (0..64)
                .map(|index| {
                    let rig = Arc::clone(&rig);
                    tokio::spawn(async move { rig.call(name, index).await })
                })
                .collect();
            for join in joins {
                let answer = tokio::time::timeout(Duration::from_secs(40), join)
                    .await
                    .expect("no handler hung behind a collection")
                    .expect("joined");
                let expected = if name == "churn" { "20" } else { "7|True" };
                assert_eq!(answer, Ok(expected.to_string()));
            }
        }
        stop.store(true, Ordering::Relaxed);
        collector.join().expect("the collector stops");
    });
}

/// Start `function()` from a script on an executor worker, as a dispatcher
/// does, and hand back what is left to wait for.
pub(super) async fn start_on_executor(
    function: &'static str,
) -> crate::script::async_pool::PendingCoroutine {
    install_probe_module();
    crate::script::py_executor::run(move || {
        Python::attach(|python| {
            let module = PyModule::from_code(
                python,
                c"import _direct_probe as probe\n\
                  async def waits():\n    return await probe.sleep_ms(5, 11)\n\
                  async def wedged():\n    await probe.never()\n",
                c"direct_wait_probe.py",
                c"direct_wait_probe",
            )
            .expect("the probe compiles");
            let coroutine = module.getattr(function).unwrap().call0().unwrap();
            match crate::script::inline_dispatch::start_coroutine(python, &coroutine) {
                Ok(crate::script::inline_dispatch::CoroutineStart::Suspended(pending)) => pending,
                Ok(crate::script::inline_dispatch::CoroutineStart::Finished(_)) => {
                    panic!("{function} finished without suspending")
                }
                Err(error) => panic!("{function} failed to start: {error}"),
            }
        })
    })
    .await
}

/// A caller that waits on a tokio task instead of being resumed on the
/// executor gets the same result, and the same timeout.
#[test]
fn a_direct_coroutine_can_be_waited_for_from_a_task() {
    with_pools(|_rig| async move {
        let pending = start_on_executor("waits").await;
        assert!(pending.is_direct(), "driven by the executor");
        let value = pending.wait().await.expect("settles");
        assert_eq!(
            Python::attach(|python| value.extract::<i64>(python).ok()),
            Some(11)
        );

        let dropped_before = NEVER_DROPPED.load(Ordering::SeqCst);
        let pending = start_on_executor("wedged").await;
        let error = pending.wait().await.expect_err("times out");
        assert!(error.to_string().contains("did not settle"), "{error}");
        let deadline = Instant::now() + Duration::from_secs(5);
        while NEVER_DROPPED.load(Ordering::SeqCst) == dropped_before {
            assert!(Instant::now() < deadline, "the awaitable was not cancelled");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });
}

/// A caller that asks to be resumed on the executor, as the request
/// dispatcher does, is resumed there with the result, and with the timeout
/// when the coroutine never settles.
#[test]
fn a_direct_coroutine_resumes_its_caller_on_the_executor() {
    with_pools(|_rig| async move {
        let (sender, receiver) = tokio::sync::oneshot::channel();
        start_on_executor("waits")
            .await
            .resume_on_executor(move |result| {
                let value =
                    result.map(|value| Python::attach(|python| value.extract::<i64>(python).ok()));
                let _ = sender.send((value.ok().flatten(), thread_name()));
            });
        let (value, thread) = receiver.await.expect("resumed");
        assert_eq!(value, Some(11));
        assert!(thread.starts_with("siphon-pyexec"), "resumed on {thread}");

        let baseline = crate::script::async_pool::pending_coroutines();
        let (sender, receiver) = tokio::sync::oneshot::channel();
        start_on_executor("wedged")
            .await
            .resume_on_executor(move |result| {
                let _ = sender.send(result.map(|_| ()).map_err(|error| error.to_string()));
            });
        let error = receiver.await.expect("resumed").expect_err("times out");
        assert!(error.contains("did not settle"), "{error}");
        assert!(
            crate::script::async_pool::pending_coroutines() <= baseline,
            "the timed-out coroutine is still counted as pending"
        );
    });
}
