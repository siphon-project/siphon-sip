//! The Python callables direct dispatch uses on every step, looked up once.

use std::sync::OnceLock;

use pyo3::prelude::*;
use tracing::error;

/// The helpers that are one Python call instead of several Rust-to-Python
/// crossings.
const SOURCE: &str = r#"
import asyncio


def make_task(loop, coroutine, context, done):
    # The task that takes a handler over from its direct steps. It must not
    # run before the step handing over has ended, and a task factory may start
    # tasks eagerly, so with one set it is made without the factory.
    if loop.get_task_factory() is None:
        task = loop.create_task(coroutine, context=context)
    else:
        task = asyncio.Task(coroutine, loop=loop, context=context)
    task.add_done_callback(done)
    return task


def start_task(loop, coroutine, context, done):
    # A handler that starts as a task: whatever the loop's factory makes.
    task = loop.create_task(coroutine, context=context)
    task.add_done_callback(done)
    return task


def has_task_factory(loop):
    return loop.get_task_factory() is not None


async def self_test(awaitable, report):
    """What a directly driven handler relies on, on this interpreter: a
    current task in the runner's steps, a siphon awaitable resumed without
    asyncio, and the same task and loop after a hand-over."""
    try:
        loop = asyncio.get_running_loop()
        task = asyncio.current_task()
        checks = [task is not None, type(task).__name__ == "SiphonHandlerTask"]
        checks.append(await awaitable() == 41)
        checks.append(asyncio.current_task() is task)
        await asyncio.sleep(0)
        checks.append(asyncio.current_task() is task)
        checks.append(asyncio.get_running_loop() is loop)
        report(all(checks))
    except BaseException:
        report(False)
        raise


def settle(future, ok, value):
    if future.done():
        return
    if ok:
        future.set_result(value)
    else:
        future.set_exception(value)


def settle_now(future, ok, value, cancelled):
    if cancelled:
        future.cancel()
    else:
        settle(future, ok, value)
"#;

pub(super) struct Helpers {
    pub(super) make_task: Py<PyAny>,
    pub(super) start_task: Py<PyAny>,
    pub(super) has_task_factory: Py<PyAny>,
    /// `self_test(awaitable, report)`, a coroutine function.
    pub(super) self_test: Py<PyAny>,
    pub(super) self_test_awaitable: Py<PyAny>,
    pub(super) settle: Py<PyAny>,
    pub(super) settle_now: Py<PyAny>,
    pub(super) get_running_loop: Py<PyAny>,
    pub(super) current_task: Py<PyAny>,
    /// `asyncio.tasks._swap_current_task(loop, task)`.
    pub(super) swap_current_task: Py<PyAny>,
    pub(super) cancelled_error: Py<PyAny>,
    pub(super) invalid_state_error: Py<PyAny>,
}

/// The helpers, or `None` if they could not be built: direct dispatch then
/// fails its self-test and stays off.
pub(super) fn helpers(python: Python<'_>) -> Option<&'static Helpers> {
    static HELPERS: OnceLock<Option<Helpers>> = OnceLock::new();
    if let Some(helpers) = HELPERS.get() {
        return helpers.as_ref();
    }
    // Built outside `get_or_init`: that would hold its lock across Python
    // calls. Two threads racing build two, and one is dropped.
    let built = match build(python) {
        Ok(helpers) => Some(helpers),
        Err(error) => {
            error!(
                %error,
                "could not build the direct-dispatch helpers; async handlers \
                 run as asyncio tasks only"
            );
            None
        }
    };
    HELPERS.get_or_init(|| built).as_ref()
}

fn build(python: Python<'_>) -> PyResult<Helpers> {
    let module = PyModule::from_code(
        python,
        &std::ffi::CString::new(SOURCE)?,
        &std::ffi::CString::new("siphon_direct_dispatch.py")?,
        &std::ffi::CString::new("siphon_direct_dispatch")?,
    )?;
    let asyncio = python.import("asyncio")?;
    let tasks = python.import("asyncio.tasks")?;
    let get = |name: &str| -> PyResult<Py<PyAny>> { Ok(module.getattr(name)?.unbind()) };
    Ok(Helpers {
        make_task: get("make_task")?,
        start_task: get("start_task")?,
        has_task_factory: get("has_task_factory")?,
        self_test: get("self_test")?,
        self_test_awaitable: pyo3::wrap_pyfunction!(self_test_awaitable, python)?
            .into_any()
            .unbind(),
        settle: get("settle")?,
        settle_now: get("settle_now")?,
        get_running_loop: asyncio.getattr("get_running_loop")?.unbind(),
        current_task: asyncio.getattr("current_task")?.unbind(),
        swap_current_task: tasks.getattr("_swap_current_task")?.unbind(),
        cancelled_error: asyncio.getattr("CancelledError")?.unbind(),
        invalid_state_error: asyncio.getattr("InvalidStateError")?.unbind(),
    })
}

/// The awaitable the self-test awaits.
#[pyfunction]
fn self_test_awaitable(python: Python<'_>) -> PyResult<Bound<'_, PyAny>> {
    crate::script::awaitable(python, async move { Ok(41i64) })
}

pub(super) fn cancelled_error(python: Python<'_>) -> PyErr {
    match helpers(python) {
        Some(helpers) => match helpers.cancelled_error.bind(python).call0() {
            Ok(error) => PyErr::from_value(error),
            Err(error) => error,
        },
        None => pyo3::exceptions::PyRuntimeError::new_err("cancelled"),
    }
}

pub(super) fn invalid_state(python: Python<'_>) -> PyErr {
    match helpers(python) {
        Some(helpers) => match helpers
            .invalid_state_error
            .bind(python)
            .call1(("Result is not set.",))
        {
            Ok(error) => PyErr::from_value(error),
            Err(error) => error,
        },
        None => pyo3::exceptions::PyRuntimeError::new_err("Result is not set."),
    }
}
