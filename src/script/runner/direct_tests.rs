//! Behaviour of `async def` handlers called through the script handle, with
//! `script.direct_dispatch` on and off: stepped on their asyncio driver
//! without a task while all they await is siphon's own awaitables, handed to
//! a task on the same thread, intact, the moment they use asyncio for
//! anything else, and the same results either way.

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

pub(super) fn gate_is_set() -> bool {
    GATE.lock().unwrap().is_some()
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
fn thread_name() -> String {
    std::thread::current()
        .name()
        .unwrap_or("<unnamed>")
        .to_string()
}

/// Whether the caller is being stepped by a runner, without an asyncio task.
#[pyfunction]
fn direct() -> bool {
    crate::script::runner::in_direct_step()
}

fn install_probe_module() {
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
            pyo3::wrap_pyfunction!(direct, &module).unwrap(),
        ] {
            module.add_function(function).unwrap();
        }
        let outer = python
            .import("contextvars")
            .unwrap()
            .call_method1("ContextVar", ("outer",))
            .unwrap();
        module.add("outer", outer).unwrap();
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
direct = probe.direct
log = logging.getLogger("direct-tests")
request_id = contextvars.ContextVar("request_id", default="unset")

async def one_await(x):
    value = await probe.ready(x)
    return f"{value}|{direct()}"

async def many_awaits(x):
    total = 0
    steps = 0
    threads = {where()}
    for index in range(50):
        total += await (probe.sleep_ms(1, index) if index % 5 == 0 else probe.ready(index))
        steps += direct()
        threads.add(where())
    return f"{total}|{steps}|{len(threads)}"

async def nested(x):
    async def inner(y):
        return await probe.sleep_ms(1, y) + 1
    value = await inner(x)
    return f"{value}|{direct()}"

async def built(x):
    return await probe.deferred("abc") + f"|{direct()}"

async def caught(x):
    try:
        await probe.fail("boom")
    except ValueError as error:
        return f"caught:{error}|{direct()}"
    return "not raised"

async def uncaught(x):
    await probe.fail("escapes")

async def raises_after(x):
    await probe.ready(x)
    raise KeyError("after the await")

async def returns_a_dict(x):
    await probe.ready(x)
    return {"x": x, "items": [1, 2, 3]}

async def mixed(x):
    before = asyncio.current_task()
    first = await probe.ready(3)
    await asyncio.sleep(0)
    second = await probe.sleep_ms(1, 4)
    same = asyncio.current_task() is before
    return f"{first + second}|{same}"

async def sleeps_for_real(x):
    started = f"{direct()}"
    thread = where()
    first = await probe.ready(x)
    await asyncio.sleep(0.01)
    return f"{first}|{started}|{direct()}|{where() == thread}"

async def awaits_a_foreign_future(x):
    started = f"{direct()}"
    thread = where()
    loop = asyncio.get_running_loop()
    future = loop.create_future()
    loop.call_later(0.005, future.set_result, x + 1)
    first = await probe.ready(x)
    second = await future
    return f"{first},{second}|{started}|{direct()}|{where() == thread}"

task_log = []

async def asks_its_task(x):
    started = f"{direct()}"
    thread = where()
    asyncio.current_task().add_done_callback(
        lambda task: task_log.append(task.result().split("|")[0]))
    value = await probe.sleep_ms(1, x)
    return f"{value}|{started}|{direct()}|{where() == thread}"

async def asked_while_suspended(x):
    task = asyncio.current_task()
    asyncio.get_running_loop().call_soon(
        lambda: task.add_done_callback(lambda done: task_log.append("asked:" + done.result())))
    value = await probe.sleep_ms(20, x)
    return f"{value}|{direct()}"

def task_log_text(*_):
    return ",".join(str(item) for item in task_log)

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
    del order[:]
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

async def timeout_block_stays_direct(x):
    try:
        async with asyncio.timeout(0.05):
            await probe.ready(1)
            await probe.never()
    except TimeoutError:
        after = await probe.ready(x)
        return f"timed out|{after}|{direct()}"
    return "no timeout"

async def gathers(x):
    left, right = await asyncio.gather(probe.sleep_ms(2, 1), probe.ready(2))
    return f"{left},{right}"

async def logs_then_awaits(x):
    log.warning("a log record reads the current task's name")
    name = asyncio.current_task().get_name()
    value = await probe.ready(x)
    return f"{value}|{direct()}|{bool(name)}"

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

async def reads_the_callers_context(x):
    before = probe.outer.get("unset")
    await probe.sleep_ms(1, 0)
    return f"{before}|{probe.outer.get('unset')}"

async def generator(limit):
    for index in range(limit):
        yield await probe.ready(index)

async def iterates(x):
    total = 0
    async for value in generator(4):
        total += value
    return f"{total}|{direct()}"

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

async def holds(x):
    return await probe.sleep_ms(1500, x)

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
    return f"{value}|{direct()}"

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
    kept.append(asyncio.current_task())
    asyncio.current_task().cancel()
    await probe.ready(x)
    return "not cancelled"

async def cancels_itself_with_a_message(x):
    task = asyncio.current_task()
    kept.append(task)
    task.cancel("on purpose")
    try:
        await probe.ready(x)
    except asyncio.CancelledError as error:
        return f"{error.args}|{task.cancelling()}"
    return "not cancelled"

async def cancelled_from_the_loop_with_a_message(x):
    task = asyncio.current_task()
    asyncio.get_running_loop().call_soon(task.cancel, "from the loop")
    try:
        await probe.never()
    except asyncio.CancelledError as error:
        return f"{error.args}|{direct()}"
    return "not cancelled"

def the_kept_task_ended_cancelled(*_):
    return f"{kept[-1].done()}|{kept[-1].cancelled()}"

ring = []

async def returns_its_own_task(x):
    task = asyncio.current_task()
    ring.append(weakref.ref(task))
    await probe.ready(x)
    await asyncio.sleep(0)
    # The real task's result is now the handler's task, which leads back to
    # the real task.
    return task

async def raises_holding_its_task(x):
    task = asyncio.current_task()
    ring.append(weakref.ref(task))
    await probe.ready(x)
    await asyncio.sleep(0)
    raise ValueError("the traceback holds the task")

def ring_collected(*_):
    gc.collect()
    return ",".join(str(ref() is None) for ref in ring)

kept = []

async def keeps_its_task(x):
    kept.append(asyncio.current_task())
    return await probe.ready(x)

def uses_a_kept_task(*_):
    task = kept[-1]
    called = []
    task.add_done_callback(called.append)
    return f"{task.done()}|{task.cancel()}|{task.cancelled()}|{task.get_name() != ''}"

async def gated(x):
    kept.append(asyncio.current_task())
    try:
        value = await probe.gate()
    except asyncio.CancelledError:
        cancelled.append(x)
        raise
    resumed.append(value)
    return "returned"

def cancels_the_last_kept_task(*_):
    return str(kept[-1].cancel())

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
    ("returns_a_dict", returns_a_dict, True),
    ("mixed", mixed, True), ("sleeps_for_real", sleeps_for_real, True),
    ("awaits_a_foreign_future", awaits_a_foreign_future, True),
    ("asks_its_task", asks_its_task, True),
    ("asked_while_suspended", asked_while_suspended, True),
    ("task_log", task_log_text, False),
    ("spawns_then_awaits", spawns_then_awaits, True),
    ("awaits_then_spawns", awaits_then_spawns, True),
    ("spawned_tags", spawned_tags, False),
    ("ordered", scheduled_callbacks_wait_for_the_step, True),
    ("waits_within_a_timeout", waits_within_a_timeout, True),
    ("timeout_fires", timeout_fires, True),
    ("timeout_block", timeout_block_spans_the_handover, True),
    ("timeout_block_stays_direct", timeout_block_stays_direct, True),
    ("gathers", gathers, True), ("logs_then_awaits", logs_then_awaits, True),
    ("context_survives", context_survives, True),
    ("context_is_per_call", context_is_per_call, True),
    ("reads_the_callers_context", reads_the_callers_context, True),
    ("iterates", iterates, True), ("awaits_twice", awaits_twice, True),
    ("started_before_awaited", started_before_awaited, True),
    ("future_api", future_api, True), ("wedged", wedged, True),
    ("wedged_counts", wedged_counts, False), ("slow", slow, True),
    ("holds", holds, True),
    ("churn", churn, True), ("from_sync", from_sync, False),
    ("suspends_then_sleeps", suspends_then_sleeps, True),
    ("counts_its_stages", counts_its_stages, True),
    ("shares_first", shares_first, True), ("shares_second", shares_second, True),
    ("cancels_itself", cancels_itself, True),
    ("cancels_itself_with_a_message", cancels_itself_with_a_message, True),
    ("cancelled_from_the_loop_with_a_message", cancelled_from_the_loop_with_a_message, True),
    ("the_kept_task_ended_cancelled", the_kept_task_ended_cancelled, False),
    ("returns_its_own_task", returns_its_own_task, True),
    ("raises_holding_its_task", raises_holding_its_task, True),
    ("ring_collected", ring_collected, False),
    ("keeps_its_task", keeps_its_task, True),
    ("uses_a_kept_task", uses_a_kept_task, False),
    ("gated", gated, True),
    ("cancels_the_last_kept_task", cancels_the_last_kept_task, False),
    ("holds_a_cancelled_awaitable", holds_a_cancelled_awaitable, True),
    ("the_held_awaitable", the_held_awaitable, False),
    ("fails_and_recovers", fails_and_recovers, True),
    ("failed_awaitables_collected", failed_awaitables_collected, False),
]:
    _r.register("direct." + name, None, fn, is_async, None)
"#;

pub(super) struct Rig {
    pub(super) handle: ScriptHandle,
    /// The engine owns the handlers the handle reads.
    pub(super) engine: Arc<ScriptEngine>,
    /// Kept so that the script can be reloaded.
    _file: NamedTempFile,
}

impl Rig {
    fn new() -> Self {
        install_probe_module();
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(SCRIPT.as_bytes()).unwrap();
        file.flush().unwrap();
        let engine = Arc::new(
            ScriptEngine::new(&crate::config::ScriptConfig {
                path: file.path().to_str().unwrap().to_owned(),
                reload: crate::config::ReloadMode::Sighup,
                ..Default::default()
            })
            .unwrap(),
        );
        let handle = ScriptHandle::new(engine.state_arc(), tokio::runtime::Handle::current());
        Self {
            handle,
            engine,
            _file: file,
        }
    }

    /// Call `direct.<name>(argument)`: `Err` if it was never dispatched, else
    /// its result as `str()`, or its error's text.
    pub(super) async fn try_call(
        &self,
        name: &str,
        argument: i64,
    ) -> PyResult<Result<String, String>> {
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
    }

    pub(super) async fn call(&self, name: &str, argument: i64) -> Result<String, String> {
        self.try_call(name, argument)
            .await
            .expect("the handler was dispatched")
    }
}

/// The runners' counters, summed over the pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Totals {
    pub(super) in_flight: usize,
    pub(super) drives: usize,
    pub(super) awaitables: usize,
    pub(super) direct_starts: u64,
    pub(super) direct_steps: u64,
}

pub(super) fn totals() -> Totals {
    let (_, pool) = ensure_test_pools();
    let mut totals = Totals {
        in_flight: 0,
        drives: 0,
        awaitables: 0,
        direct_starts: 0,
        direct_steps: 0,
    };
    for index in 0..pool.size() {
        let stats = pool.runner(index).expect("a runner").stats();
        totals.in_flight += stats.in_flight;
        totals.drives += stats.drives;
        totals.awaitables += stats.awaitables;
        totals.direct_starts += stats.direct_starts;
        totals.direct_steps += stats.direct_steps;
    }
    totals
}

/// Wait until nothing is in flight on any runner: slab, admissions and
/// tracked awaitables all back to `baseline`.
pub(super) async fn settles_to(baseline: Totals, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let now = totals();
        if now.in_flight == baseline.in_flight
            && now.drives == baseline.drives
            && now.awaitables == baseline.awaitables
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{what}: {now:?} never came back to {baseline:?}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Puts the switch back off when a scenario ends, however it ends.
struct Switch;

impl Switch {
    fn set(on: bool) -> Self {
        crate::script::runner::set_enabled_for_test(on);
        Self
    }
}

impl Drop for Switch {
    fn drop(&mut self) {
        crate::script::runner::set_enabled_for_test(false);
        crate::script::runner::set_admission_limit_for_test(
            crate::script::runner::DEFAULT_ADMISSION_LIMIT,
        );
    }
}

/// Run `scenario` on the pools' runtime with the pools installed and the
/// switch at `on`, one test at a time.
pub(super) fn with_pools<F, Fut>(on: bool, scenario: F)
where
    F: FnOnce(Rig) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    let _serial = pool_test_guard();
    test_pools_runtime().block_on(async {
        ensure_test_pools();
        let _switch = Switch::set(on);
        // No test waits longer than this: a hang is a failure, not a stall.
        tokio::time::timeout(Duration::from_secs(90), scenario(Rig::new()))
            .await
            .expect("the scenario finished");
    });
}

/// Run `scenario` once with the switch off and once with it on. It is told
/// which.
fn in_both_modes<F, Fut>(scenario: F)
where
    F: Fn(Rig, bool) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    for on in [false, true] {
        with_pools(on, |rig| scenario(rig, on));
    }
}

/// `True` or `False`, as Python prints it.
fn py(flag: bool) -> &'static str {
    if flag {
        "True"
    } else {
        "False"
    }
}

/// The switch really is a switch: off, no handler is stepped by a runner; on,
/// one that awaits only siphon awaitables is, for every step.
#[test]
fn one_await_is_stepped_by_the_runner_only_with_the_switch_on() {
    in_both_modes(|rig, on| async move {
        let before = totals();
        assert_eq!(rig.call("one_await", 5).await, Ok(format!("5|{}", py(on))));
        assert_eq!(rig.call("nested", 5).await, Ok(format!("6|{}", py(on))));
        assert_eq!(
            rig.call("built", 0).await,
            Ok(format!("built:abc|{}", py(on)))
        );
        let after = totals();
        assert_eq!(
            after.direct_starts - before.direct_starts,
            if on { 3 } else { 0 }
        );
        assert_eq!(after.direct_steps > before.direct_steps, on);
    });
}

/// Fifty awaits, ready and not: the sum is right, every continuation was a
/// direct step, and all of them ran on the one driver thread the coroutine
/// started on.
#[test]
fn many_awaits_all_resume_on_the_owning_driver() {
    in_both_modes(|rig, on| async move {
        let expected: i64 = (0..50).sum();
        let steps = if on { 50 } else { 0 };
        assert_eq!(
            rig.call("many_awaits", 0).await,
            Ok(format!("{expected}|{steps}|1"))
        );
    });
}

/// An awaitable's error is raised at the `await`: the coroutine can catch it,
/// and one it lets go is the handler's error.
#[test]
fn an_awaitable_error_is_thrown_into_the_coroutine() {
    in_both_modes(|rig, on| async move {
        assert_eq!(
            rig.call("caught", 0).await,
            Ok(format!("caught:boom|{}", py(on)))
        );
        let escaped = rig.call("uncaught", 0).await.expect_err("raised");
        assert!(escaped.contains("escapes"), "{escaped}");
        let after = rig.call("raises_after", 0).await.expect_err("raised");
        assert!(after.contains("after the await"), "{after}");
    });
}

/// What a handler returns or raises reads the same with the switch on as
/// with it off, for every shape of handler here.
#[test]
fn results_and_exceptions_are_identical_in_both_modes() {
    const HANDLERS: [&str; 16] = [
        "uncaught",
        "raises_after",
        "returns_a_dict",
        "mixed",
        "gathers",
        "awaits_twice",
        "started_before_awaited",
        "context_survives",
        "context_is_per_call",
        "waits_within_a_timeout",
        "timeout_fires",
        "timeout_block",
        "future_api",
        "from_sync",
        "wedged",
        "counts_its_stages",
    ];
    let results = std::sync::Mutex::new(Vec::new());
    in_both_modes(|rig, _on| {
        let results = &results;
        async move {
            let mut seen = Vec::new();
            for name in HANDLERS {
                seen.push((name, rig.call(name, 3).await));
            }
            results.lock().unwrap().push(seen);
        }
    });
    let results = results.into_inner().unwrap();
    assert_eq!(results.len(), 2);
    for (off, on) in results[0].iter().zip(&results[1]) {
        assert_eq!(off, on, "off and on disagree");
    }
    let wedged = &results[1][14].1;
    assert!(
        wedged
            .as_ref()
            .is_err_and(|error| error.contains("async handler 'wedged' did not settle within 3s")),
        "{wedged:?}"
    );
}

/// A coroutine that awaits a siphon awaitable and then asyncio is handed to a
/// task mid-flight and finishes with the right value, as the same task it
/// started as.
#[test]
fn a_mixed_coroutine_is_handed_to_asyncio_and_returns_the_right_value() {
    in_both_modes(|rig, _on| async move {
        for _ in 0..3 {
            assert_eq!(rig.call("mixed", 0).await, Ok("7|True".to_string()));
        }
    });
}

/// Each way of needing asyncio (`asyncio.sleep`, a future that is not
/// siphon's, a task method only a real task answers) hands the handler to a
/// task on the thread it is on, where it finishes correctly. The handler is
/// remembered: its next call starts as a task. A reload forgets.
#[test]
fn a_handler_that_needs_asyncio_is_demoted_once_and_remembered() {
    with_pools(true, |rig| async move {
        let cases = [
            ("sleeps_for_real", "8"),
            ("awaits_a_foreign_future", "8,9"),
            ("asks_its_task", "8"),
        ];
        let baseline = totals();
        for (name, value) in cases {
            let demoted_before = crate::script::runner::demoted_handlers();
            let before = totals();
            // Started direct, ended as a task, on the same thread.
            assert_eq!(
                rig.call(name, 8).await,
                Ok(format!("{value}|True|False|True")),
                "{name}, first call"
            );
            assert_eq!(totals().direct_starts - before.direct_starts, 1, "{name}");
            assert_eq!(
                crate::script::runner::demoted_handlers(),
                demoted_before + 1,
                "{name} is remembered"
            );
            // From now on a task from the first step.
            let before = totals();
            for _ in 0..3 {
                assert_eq!(
                    rig.call(name, 8).await,
                    Ok(format!("{value}|False|False|True")),
                    "{name}, later calls"
                );
            }
            assert_eq!(totals().direct_starts, before.direct_starts, "{name}");
            assert_eq!(
                crate::script::runner::demoted_handlers(),
                demoted_before + 1,
                "{name} is remembered once"
            );
        }
        assert_eq!(
            rig.call("task_log", 0).await,
            Ok("8,8,8,8".to_string()),
            "the done callbacks a handler put on its task ran"
        );
        settles_to(baseline, "after the demoted handlers").await;

        // A reload replaces the handlers: nothing is remembered about them.
        rig.engine.reload().expect("the script reloads");
        assert_eq!(crate::script::runner::demoted_handlers(), 0);
        assert_eq!(
            rig.call("sleeps_for_real", 8).await,
            Ok("8|True|False|True".to_string()),
            "after the reload the handler starts direct again"
        );
    });
}

/// Something else on the loop asks a suspended handler's task for what only a
/// real task answers: the handler becomes one where it is, and still gets its
/// awaitable's value.
#[test]
fn a_task_asked_from_the_loop_while_its_handler_is_suspended_becomes_real() {
    with_pools(true, |rig| async move {
        assert_eq!(
            rig.call("asked_while_suspended", 4).await,
            Ok("4|False".to_string())
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let log = rig.call("task_log", 0).await.expect("a sync probe");
            if log == "asked:4|False" {
                break;
            }
            assert!(Instant::now() < deadline, "the done callback ran: {log}");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });
}

/// A hand-over after the handler was resumed by the runner reaches the caller
/// that is already waiting for it, and no stage of a handler runs twice or is
/// skipped on the way.
#[test]
fn a_hand_over_after_a_suspension_finishes_once() {
    in_both_modes(|rig, _on| async move {
        for _ in 0..2 {
            assert_eq!(
                rig.call("suspends_then_sleeps", 3).await,
                Ok("3|False".to_string())
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

/// Two handlers awaiting one awaitable both get its value, whichever drivers
/// they run on.
#[test]
fn two_handlers_can_await_one_awaitable() {
    with_pools(true, |rig| async move {
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
    with_pools(true, |rig| async move {
        let before = crate::script::runner::demoted_handlers();
        let cancelled = rig.call("cancels_itself", 1).await.expect_err("cancelled");
        assert!(cancelled.contains("CancelledError"), "{cancelled}");
        assert_eq!(
            rig.call("the_kept_task_ended_cancelled", 0).await,
            Ok("True|True".to_string()),
            "a task that ended cancelled says so"
        );
        // The message given to `cancel()` is the `CancelledError`'s, from the
        // handler's own step and from a callback on its loop, and a handler
        // that catches it goes on.
        assert_eq!(
            rig.call("cancels_itself_with_a_message", 1).await,
            Ok("('on purpose',)|1".to_string())
        );
        assert_eq!(
            rig.call("the_kept_task_ended_cancelled", 0).await,
            Ok("True|False".to_string())
        );
        assert_eq!(
            rig.call("cancelled_from_the_loop_with_a_message", 1).await,
            Ok("('from the loop',)|True".to_string())
        );
        assert_eq!(rig.call("keeps_its_task", 4).await, Ok("4".to_string()));
        assert_eq!(
            rig.call("uses_a_kept_task", 0).await,
            Ok("True|False|False|True".to_string())
        );
        assert_eq!(
            crate::script::runner::demoted_handlers(),
            before,
            "none of that needed a real task"
        );
    });
}

/// `asyncio.create_task` from a handler is driven to completion, called
/// before the handler's first await or after it, including by a handler that
/// returns straight after. Creating a task is no reason to become one.
#[test]
fn a_task_created_by_a_handler_still_completes() {
    in_both_modes(|rig, on| async move {
        let before = totals();
        for _ in 0..2 {
            assert_eq!(rig.call("spawns_then_awaits", 1).await, Ok("1".to_string()));
            assert_eq!(rig.call("awaits_then_spawns", 2).await, Ok("2".to_string()));
        }
        assert_eq!(
            totals().direct_starts - before.direct_starts,
            if on { 4 } else { 0 }
        );
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
    in_both_modes(|rig, _on| async move {
        assert_eq!(
            rig.call("ordered", 0).await,
            Ok("handler,callback".to_string())
        );
    });
}

/// `asyncio.wait_for` and `asyncio.timeout` around siphon awaitables: they
/// need a current task and a loop from the first step on, and a timeout that
/// fires cancels the handler's await, not the handler.
#[test]
fn asyncio_timeouts_work_around_siphon_awaitables() {
    in_both_modes(|rig, on| async move {
        let dropped_before = NEVER_DROPPED.load(Ordering::SeqCst);
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
            // A timeout needs the loop's clock, not a task: the handler is
            // still stepped by the runner after it fired.
            assert_eq!(
                rig.call("timeout_block_stays_direct", 2).await,
                Ok(format!("timed out|2|{}", py(on)))
            );
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while NEVER_DROPPED.load(Ordering::SeqCst) - dropped_before < 6 {
            assert!(
                Instant::now() < deadline,
                "every timed-out awaitable's Rust future was dropped"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });
}

#[test]
fn gather_over_siphon_awaitables_returns_both() {
    in_both_modes(|rig, _on| async move {
        for _ in 0..2 {
            assert_eq!(rig.call("gathers", 0).await, Ok("1,2".to_string()));
        }
    });
}

/// The awaitable is a future to asyncio's own helpers, done callbacks and
/// all, and can be awaited more than once.
#[test]
fn an_awaitable_keeps_the_future_api() {
    in_both_modes(|rig, _on| async move {
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
    in_both_modes(|rig, _on| async move {
        assert_eq!(
            rig.call("started_before_awaited", 0).await,
            Ok("2,1".to_string())
        );
    });
}

/// Logging reads `asyncio.current_task().get_name()` for every record; that
/// must not cost the handler its direct path.
#[test]
fn logging_in_a_handler_keeps_it_direct() {
    with_pools(true, |rig| async move {
        assert_eq!(
            rig.call("logs_then_awaits", 2).await,
            Ok("2|True|True".to_string())
        );
    });
}

/// A context variable set before an await is there after it and across the
/// hand-over, never leaks into the next call, and one the caller set before
/// the call is the handler's to read.
#[test]
fn context_variables_follow_the_coroutine() {
    in_both_modes(|rig, _on| async move {
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

        let handler = rig
            .handle
            .handlers_for("direct.reads_the_callers_context")
            .into_iter()
            .next()
            .expect("registered");
        let seen = rig
            .handle
            .call_handler_with(
                &handler,
                |python| {
                    // In the job that calls the handler: its context is what
                    // the coroutine starts from.
                    python
                        .import("_direct_probe")?
                        .getattr("outer")?
                        .call_method1("set", ("from-the-caller",))?;
                    Ok(vec![0i64.into_pyobject(python)?.into_any().unbind()])
                },
                |_python, outcome| {
                    outcome
                        .and_then(|value| value.extract::<String>())
                        .map_err(|error| error.to_string())
                },
            )
            .await
            .expect("dispatched");
        assert_eq!(seen, Ok("from-the-caller|from-the-caller".to_string()));
    });
}

#[test]
fn an_async_generator_over_siphon_awaitables_iterates() {
    in_both_modes(|rig, on| async move {
        assert_eq!(rig.call("iterates", 0).await, Ok(format!("6|{}", py(on))));
    });
}

/// A synchronous handler cannot await: making the awaitable there fails with
/// the error that says to use `async def`.
#[test]
fn a_sync_handler_is_told_to_be_async() {
    in_both_modes(|rig, _on| async move {
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
    in_both_modes(|rig, _on| async move {
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

/// The leak test: after a batch of handlers that complete and a batch whose
/// awaitable never does, nothing is left. Every timed-out coroutine was
/// cancelled exactly once and never resumed past its await, its Rust future
/// was dropped, and the slab, the admissions, the tracked awaitables and the
/// pending count are all back where they started.
#[test]
fn completed_and_timed_out_handlers_leak_nothing() {
    in_both_modes(|rig, on| async move {
        let (_, async_pool) = ensure_test_pools();
        let rig = Arc::new(rig);
        let baseline = totals();
        let pending_baseline = crate::script::async_pool::pending_coroutines();
        let dropped_before = NEVER_DROPPED.load(Ordering::SeqCst);

        const CALLS: usize = 6;
        let mut joins = Vec::new();
        for index in 0..CALLS {
            for name in ["wedged", "churn", "one_await"] {
                let rig = Arc::clone(&rig);
                joins.push((
                    name,
                    tokio::spawn(async move { rig.call(name, index as i64).await }),
                ));
            }
        }
        if on {
            // While they run they are counted: the test would pass on
            // counters nothing moves.
            let deadline = Instant::now() + Duration::from_secs(2);
            while totals().drives < baseline.drives + CALLS {
                assert!(
                    Instant::now() < deadline,
                    "the wedged handlers are in the slab"
                );
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            assert!(totals().in_flight >= baseline.in_flight + CALLS);
            assert!(totals().awaitables >= baseline.awaitables + CALLS);
        }
        for (name, join) in joins {
            let outcome = join.await.expect("joined");
            match name {
                "wedged" => {
                    let error = outcome.expect_err("timed out");
                    assert!(error.contains("did not settle"), "{error}");
                }
                "churn" => assert_eq!(outcome, Ok("20".to_string())),
                _ => assert!(outcome.is_ok(), "{outcome:?}"),
            }
        }

        let deadline = Instant::now() + async_pool.coroutine_timeout();
        loop {
            let counts = rig.call("wedged_counts", 0).await.expect("a sync probe");
            let dropped = NEVER_DROPPED.load(Ordering::SeqCst) - dropped_before;
            let pending = crate::script::async_pool::pending_coroutines();
            if counts == format!("{CALLS}|0") && dropped == CALLS && pending <= pending_baseline {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "cancelled|resumed = {counts}, futures dropped = {dropped}, \
                 pending = {pending} (baseline {pending_baseline})"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        settles_to(baseline, "after completed and timed-out handlers").await;
        // Settled, not merely passing through: nothing resumes later.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            rig.call("wedged_counts", 0).await,
            Ok(format!("{CALLS}|0")),
            "a cancelled coroutine was resumed a second time"
        );
        assert_eq!(totals().drives, baseline.drives);
        assert_eq!(totals().in_flight, baseline.in_flight);
        assert_eq!(totals().awaitables, baseline.awaitables);
    });
}

/// A caller that stops waiting (its future is dropped) leaves a handler that
/// still finishes, and nothing behind once it has.
#[test]
fn a_dropped_caller_leaves_nothing_behind() {
    with_pools(true, |rig| async move {
        let rig = Arc::new(rig);
        let baseline = totals();
        let calls: Vec<_> = (0..8)
            .map(|index| {
                let rig = Arc::clone(&rig);
                tokio::spawn(async move { rig.call("slow", index).await })
            })
            .collect();
        let deadline = Instant::now() + Duration::from_secs(2);
        while totals().drives < baseline.drives + 8 {
            assert!(Instant::now() < deadline, "the handlers started");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        for call in calls {
            call.abort();
        }
        settles_to(baseline, "after the callers were dropped").await;
    });
}

/// A caller that went away does not take the coroutine timeout with it: a
/// handler nobody waits for is still cancelled when its time is up, and
/// nothing is left of it.
#[test]
fn a_handler_whose_caller_went_away_is_still_timed_out() {
    with_pools(true, |rig| async move {
        let (_, async_pool) = ensure_test_pools();
        let rig = Arc::new(rig);
        let baseline = totals();
        let dropped_before = NEVER_DROPPED.load(Ordering::SeqCst);
        const CALLS: usize = 5;
        let calls: Vec<_> = (0..CALLS)
            .map(|index| {
                let rig = Arc::clone(&rig);
                tokio::spawn(async move { rig.call("wedged", index as i64).await })
            })
            .collect();
        let deadline = Instant::now() + Duration::from_secs(2);
        while totals().awaitables < baseline.awaitables + CALLS {
            assert!(Instant::now() < deadline, "the handlers suspended");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        for call in calls {
            call.abort();
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(
            totals().drives,
            baseline.drives + CALLS,
            "a dropped caller does not cancel its handler"
        );

        let deadline = Instant::now() + async_pool.coroutine_timeout() + Duration::from_secs(5);
        loop {
            let counts = rig.call("wedged_counts", 0).await.expect("a sync probe");
            if counts == format!("{CALLS}|0") {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "the unattended handlers were cancelled at their timeout: {counts}"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        settles_to(baseline, "after the unattended handlers timed out").await;
        assert_eq!(
            NEVER_DROPPED.load(Ordering::SeqCst) - dropped_before,
            CALLS,
            "their Rust futures were dropped"
        );
    });
}

/// A handler's task can end up in what its real task keeps (its result, or
/// an exception whose traceback holds it), which leads back to the real task.
/// The collector has to be able to see that ring through siphon's objects.
#[test]
fn a_task_held_by_its_own_outcome_is_collected() {
    with_pools(true, |rig| async move {
        let returned = rig.call("returns_its_own_task", 1).await;
        assert!(
            returned
                .as_ref()
                .is_ok_and(|text| text.contains("SiphonHandlerTask")),
            "{returned:?}"
        );
        let raised = rig
            .call("raises_holding_its_task", 1)
            .await
            .expect_err("raised");
        assert!(raised.contains("the traceback holds the task"), "{raised}");
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let collected = rig.call("ring_collected", 0).await.expect("a sync probe");
            if collected == "True,True" {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "a handler's task is still alive: {collected}"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    });
}

/// Admission is bounded per runner. With every runner full a call fails as
/// one that was never dispatched, at once, is counted, and leaves nothing
/// behind; once there is room calls go through again.
#[test]
fn a_call_is_refused_when_every_runner_is_full() {
    with_pools(true, |rig| async move {
        let (_, async_pool) = ensure_test_pools();
        let rig = Arc::new(rig);
        let baseline = totals();
        let pending_baseline = crate::script::async_pool::pending_coroutines();
        crate::script::runner::set_admission_limit_for_test(2);
        let room = 2 * async_pool.size();

        let holders: Vec<_> = (0..room)
            .map(|index| {
                let rig = Arc::clone(&rig);
                tokio::spawn(async move { rig.call("holds", index as i64).await })
            })
            .collect();
        let deadline = Instant::now() + Duration::from_secs(2);
        while totals().in_flight < baseline.in_flight + room {
            assert!(Instant::now() < deadline, "every runner filled");
            tokio::time::sleep(Duration::from_millis(2)).await;
        }

        let rejected_before = crate::script::runner::admission_rejected();
        let started = Instant::now();
        for _ in 0..3 {
            let refused = rig
                .try_call("one_await", 1)
                .await
                .expect_err("refused, not run");
            assert!(refused.to_string().contains("in flight"), "{refused}");
        }
        assert!(
            started.elapsed() < Duration::from_millis(250),
            "a refusal waited for room: {:?}",
            started.elapsed()
        );
        assert_eq!(
            crate::script::runner::admission_rejected() - rejected_before,
            3
        );
        assert_eq!(
            totals().in_flight,
            baseline.in_flight + room,
            "a refused call took no place"
        );
        // A handler that cannot suspend never needs a place.
        assert_eq!(
            rig.call("task_log", 0).await.map(|_| ()),
            Ok(()),
            "sync handlers are not admission-bound"
        );

        for (index, holder) in holders.into_iter().enumerate() {
            assert_eq!(holder.await.expect("joined"), Ok(index.to_string()));
        }
        settles_to(baseline, "after the holders finished").await;
        assert!(crate::script::async_pool::pending_coroutines() <= pending_baseline);
        assert_eq!(rig.call("one_await", 1).await, Ok("1|True".to_string()));
    });
}

/// The self-test a server runs before it turns the switch on passes on this
/// interpreter, and leaves nothing behind.
#[test]
fn the_self_test_passes_and_turns_the_switch_on() {
    with_pools(false, |rig| async move {
        let (_, async_pool) = ensure_test_pools();
        let baseline = totals();
        let turned_on = tokio::task::spawn_blocking(move || {
            crate::script::runner::configure(true, &async_pool)
        })
        .await
        .expect("joined");
        assert!(turned_on, "the self-test passed");
        assert_eq!(rig.call("one_await", 5).await, Ok("5|True".to_string()));
        settles_to(baseline, "after the self-test").await;

        let (_, async_pool) = ensure_test_pools();
        assert!(!crate::script::runner::configure(false, &async_pool));
        assert_eq!(rig.call("one_await", 5).await, Ok("5|False".to_string()));
    });
}

/// Handlers awaiting siphon awaitables keep completing while another thread
/// forces stop-the-world collections: wakes, completions and hand-overs all
/// happen with the world being stopped around them, and no thread on the path
/// waits attached. Run in a child process so a deadlock is a failure, not a
/// hung test run.
#[test]
fn awaiting_survives_stop_the_world_collections() {
    if !in_child(
        concat!(
            module_path!(),
            "::awaiting_survives_stop_the_world_collections"
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
        for name in ["churn", "mixed", "one_await"] {
            let joins: Vec<_> = (0..64)
                .map(|index| {
                    let rig = Arc::clone(&rig);
                    tokio::spawn(async move { rig.call(name, index).await })
                })
                .collect();
            for (index, join) in joins.into_iter().enumerate() {
                let answer = tokio::time::timeout(Duration::from_secs(40), join)
                    .await
                    .expect("no handler hung behind a collection")
                    .expect("joined");
                let expected = match name {
                    "churn" => "20".to_string(),
                    "mixed" => "7|True".to_string(),
                    _ => format!("{index}|True"),
                };
                assert_eq!(answer, Ok(expected));
            }
        }
        settles_to(baseline, "under collections").await;
        stop.store(true, Ordering::Relaxed);
        collector.join().expect("the collector stops");
    });
}

/// The coroutine timeout's cancellation, with the world being stopped around
/// it: every waiter gets its timeout, every coroutine is cancelled once, and
/// nothing is left in the slab.
#[test]
fn cancelling_survives_stop_the_world_collections() {
    if !in_child(
        concat!(
            module_path!(),
            "::cancelling_survives_stop_the_world_collections"
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
        const CALLS: usize = 32;
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
        assert_eq!(rig.call("wedged_counts", 0).await, Ok(format!("{CALLS}|0")));
        stop.store(true, Ordering::Relaxed);
        collector.join().expect("the collector stops");
    });
}
