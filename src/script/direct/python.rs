//! The Python side of direct dispatch: the driver loop class, and the
//! callables a step uses, looked up once.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use pyo3::prelude::*;
use tracing::{error, info, warn};

use super::active_drive;

/// The driver loop class and the few helpers that are one Python call instead
/// of several Rust-to-Python crossings.
const DRIVER_SOURCE: &str = r#"
import asyncio
import threading

_get_ident = threading.get_ident
_classes = {}


def _guarded(inherited, touch):
    def method(self, *args, **kwargs):
        if _get_ident() != self._siphon_thread:
            touch(self)
        return inherited(self, *args, **kwargs)
    method.__name__ = inherited.__name__
    method.__qualname__ = inherited.__qualname__
    return method


def _driver_loop_class(base, touch):
    base_call_soon = base.call_soon
    base_call_at = base.call_at

    class SiphonDriverLoop(base):
        """The default event loop, telling siphon when a thread other than
        its own schedules on it. Only a handler step driven from the executor
        does, and it then holds this loop still until the step ends."""

        _siphon_thread = None
        _siphon_switch = None

        def _siphon_report(self):
            # Tell siphon whether handlers may be driven directly against
            # this loop: not with a task factory (an eager one would run a
            # hand-over's task before the step handing over has ended), and
            # not in debug mode (asyncio then refuses loop calls from any
            # thread but the loop's own).
            switch = self._siphon_switch
            if switch is not None:
                switch(self.get_task_factory() is not None, bool(self.get_debug()))

        def set_task_factory(self, factory):
            base.set_task_factory(self, factory)
            self._siphon_report()

        def set_debug(self, enabled):
            base.set_debug(self, enabled)
            self._siphon_report()

        def call_soon(self, callback, *args, context=None):
            if _get_ident() != self._siphon_thread:
                touch(self)
            return base_call_soon(self, callback, *args, context=context)

        def call_at(self, when, callback, *args, context=None):
            if _get_ident() != self._siphon_thread:
                touch(self)
            return base_call_at(self, when, callback, *args, context=context)

    # Selector registrations and the default thread pool: loop state a
    # transport or `to_thread` changes without scheduling a callback first.
    for name in ("_add_reader", "_remove_reader", "_add_writer",
                 "_remove_writer", "run_in_executor"):
        inherited = getattr(base, name, None)
        if inherited is not None:
            setattr(SiphonDriverLoop, name, _guarded(inherited, touch))
    return SiphonDriverLoop


def new_driver_loop(touch, switch):
    probe = asyncio.new_event_loop()
    base = type(probe)
    probe.close()
    cls = _classes.get(base)
    if cls is None:
        cls = _classes[base] = _driver_loop_class(base, touch)
    loop = cls()
    loop._siphon_thread = _get_ident()
    loop._siphon_switch = switch
    loop._siphon_report()
    return loop


def asyncgen_hooks(loop):
    # What `run_forever` installs on the loop's own thread. Both are safe from
    # another: the first adds to a weak set, the second schedules with
    # `call_soon_threadsafe`.
    firstiter = getattr(loop, "_asyncgen_firstiter_hook", None)
    finalizer = getattr(loop, "_asyncgen_finalizer_hook", None)
    if firstiter is None or finalizer is None:
        return None
    return firstiter, finalizer


class TaskCancel:
    """`cancel()` for a task from any thread."""

    __slots__ = ("loop", "task")

    def __init__(self, loop, task):
        self.loop = loop
        self.task = task

    def cancel(self):
        if self.task.done():
            return False
        self.loop.call_soon_threadsafe(self.task.cancel)
        return True


def make_task(loop, coroutine, context, done):
    if loop.get_task_factory() is None:
        task = loop.create_task(coroutine, context=context)
    else:
        # A factory set while this handler was already being driven directly.
        # It may start tasks eagerly, and this one must not run before the
        # step handing it over has ended, so it is made without the factory.
        task = asyncio.Task(coroutine, loop=loop, context=context)
    task.add_done_callback(done)
    return task, TaskCancel(loop, task)


async def self_test(awaitable, report):
    """What a directly driven handler relies on, on this interpreter: a
    running loop and a current task in the executor's steps, a siphon
    awaitable resumed without asyncio, and both unchanged by a hand-over."""
    try:
        loop = asyncio.get_running_loop()
        task = asyncio.current_task()
        checks = [task is not None, loop.is_running()]
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

/// Python callables the direct path uses on every step, looked up once.
pub(super) struct Helpers {
    /// `new_driver_loop(touch, switch)`.
    pub(super) new_driver_loop: Py<PyAny>,
    /// `asyncgen_hooks(loop)`.
    pub(super) asyncgen_hooks: Py<PyAny>,
    pub(super) make_task: Py<PyAny>,
    /// `self_test(awaitable, report)`, a coroutine function.
    pub(super) self_test: Py<PyAny>,
    pub(super) self_test_awaitable: Py<PyAny>,
    /// `asyncio._get_running_loop`.
    pub(super) peek_running_loop: Py<PyAny>,
    pub(super) settle: Py<PyAny>,
    pub(super) settle_now: Py<PyAny>,
    pub(super) touch: Py<PyAny>,
    pub(super) set_running_loop: Py<PyAny>,
    pub(super) get_running_loop: Py<PyAny>,
    pub(super) swap_current_task: Py<PyAny>,
    pub(super) set_asyncgen_hooks: Py<PyAny>,
    pub(super) cancelled_error: Py<PyAny>,
    pub(super) invalid_state_error: Py<PyAny>,
}

/// The helpers, or `None` if they could not be built: the direct path is then
/// off and every coroutine goes to a driver as before.
pub(super) fn helpers(python: Python<'_>) -> Option<&'static Helpers> {
    static HELPERS: OnceLock<Option<Helpers>> = OnceLock::new();
    if let Some(helpers) = HELPERS.get() {
        return helpers.as_ref();
    }
    // Built outside `get_or_init`: that would hold its lock across Python
    // calls. Two threads racing build two, and one is dropped.
    let built = match build_helpers(python) {
        Ok(helpers) => Some(helpers),
        Err(error) => {
            error!(
                %error,
                "could not build the direct-dispatch helpers; async handlers \
                 run on the asyncio drivers only"
            );
            None
        }
    };
    HELPERS.get_or_init(|| built).as_ref()
}

fn build_helpers(python: Python<'_>) -> PyResult<Helpers> {
    let module = PyModule::from_code(
        python,
        &std::ffi::CString::new(DRIVER_SOURCE)?,
        &std::ffi::CString::new("siphon_direct_dispatch.py")?,
        &std::ffi::CString::new("siphon_direct_dispatch")?,
    )?;
    let asyncio = python.import("asyncio")?;
    let tasks = python.import("asyncio.tasks")?;
    let get = |name: &str| -> PyResult<Py<PyAny>> { Ok(module.getattr(name)?.unbind()) };
    Ok(Helpers {
        new_driver_loop: get("new_driver_loop")?,
        asyncgen_hooks: get("asyncgen_hooks")?,
        make_task: get("make_task")?,
        self_test: get("self_test")?,
        self_test_awaitable: pyo3::wrap_pyfunction!(self_test_awaitable, python)?
            .into_any()
            .unbind(),
        peek_running_loop: asyncio.getattr("_get_running_loop")?.unbind(),
        settle: get("settle")?,
        settle_now: get("settle_now")?,
        touch: pyo3::wrap_pyfunction!(touch_loop, python)?
            .into_any()
            .unbind(),
        set_running_loop: asyncio.getattr("_set_running_loop")?.unbind(),
        get_running_loop: asyncio.getattr("get_running_loop")?.unbind(),
        swap_current_task: tasks.getattr("_swap_current_task")?.unbind(),
        set_asyncgen_hooks: python
            .import("sys")?
            .getattr("set_asyncgen_hooks")?
            .unbind(),
        cancelled_error: asyncio.getattr("CancelledError")?.unbind(),
        invalid_state_error: asyncio.getattr("InvalidStateError")?.unbind(),
    })
}

/// A driver thread's event loop and, when it is the kind a handler step can
/// be driven against, the async-generator hooks a step installs.
pub(crate) struct DriverLoop {
    pub(crate) event_loop: Py<PyAny>,
    /// `(firstiter, finalizer)`; `None` when the loop is a plain asyncio
    /// loop, which cannot tell siphon about a step scheduling on it, so no
    /// coroutine is driven directly against it.
    pub(crate) direct: Option<DirectHooks>,
}

pub(crate) struct DirectHooks {
    pub(super) firstiter: Py<PyAny>,
    pub(super) finalizer: Py<PyAny>,
    pub(super) switch: Py<DirectSwitch>,
}

/// Whether handlers may be driven directly against one driver loop, kept up
/// to date by the loop itself (`_siphon_report`), so that starting a handler
/// reads two atomics instead of asking the loop.
#[pyclass(frozen)]
pub(crate) struct DirectSwitch {
    task_factory: AtomicBool,
    debug: AtomicBool,
}

impl DirectSwitch {
    pub(super) fn allows(&self) -> bool {
        !self.task_factory.load(Ordering::Acquire) && !self.debug.load(Ordering::Acquire)
    }
}

#[pymethods]
impl DirectSwitch {
    fn __call__(&self, task_factory: bool, debug_mode: bool) {
        let allowed = self.allows();
        self.task_factory.store(task_factory, Ordering::Release);
        self.debug.store(debug_mode, Ordering::Release);
        match (allowed, self.allows()) {
            (true, false) => warn!(
                has_task_factory = task_factory,
                debug_mode,
                "an asyncio driver loop has a task factory or is in debug \
                 mode: async handlers bound to it start on the driver instead \
                 of being driven from the executor"
            ),
            (false, true) => info!(
                "an asyncio driver loop is back to defaults: async handlers \
                 bound to it are driven from the executor again"
            ),
            _ => {}
        }
    }
}

/// The awaitable the start-up self-test awaits.
#[pyfunction]
fn self_test_awaitable(python: Python<'_>) -> PyResult<Bound<'_, PyAny>> {
    crate::script::awaitable(python, async move { Ok(41i64) })
}

/// Build the event loop for the calling driver thread.
pub(crate) fn new_driver_loop(python: Python<'_>) -> PyResult<DriverLoop> {
    let plain = |python: Python<'_>| -> PyResult<DriverLoop> {
        Ok(DriverLoop {
            event_loop: python
                .import("asyncio")?
                .call_method0("new_event_loop")?
                .unbind(),
            direct: None,
        })
    };
    let Some(helpers) = helpers(python) else {
        return plain(python);
    };
    let built = Py::new(
        python,
        DirectSwitch {
            task_factory: AtomicBool::new(false),
            debug: AtomicBool::new(false),
        },
    )
    .and_then(|switch| {
        let event_loop = helpers
            .new_driver_loop
            .bind(python)
            .call1((&helpers.touch, &switch))?;
        Ok((event_loop, switch))
    })
    .and_then(|(event_loop, switch)| {
        let hooks = helpers.asyncgen_hooks.bind(python).call1((&event_loop,))?;
        let (firstiter, finalizer): (Py<PyAny>, Py<PyAny>) = hooks.extract()?;
        Ok(DriverLoop {
            event_loop: event_loop.unbind(),
            direct: Some(DirectHooks {
                firstiter,
                finalizer,
                switch,
            }),
        })
    });
    match built {
        Ok(driver_loop) => Ok(driver_loop),
        Err(error) => {
            error!(
                %error,
                "could not build siphon's driver loop; using the default loop, \
                 on which async handlers are not driven directly"
            );
            plain(python)
        }
    }
}

/// Called by the driver loop class when a thread other than the loop's own
/// schedules on it. If that thread is stepping a coroutine bound to the loop,
/// the step takes the loop's baton; anything else is left as asyncio has it.
#[pyfunction]
fn touch_loop(python: Python<'_>, event_loop: &Bound<'_, PyAny>) -> PyResult<()> {
    match active_drive() {
        Some(drive) if drive.event_loop.bind(python).is(event_loop) => drive.take_baton(python),
        _ => Ok(()),
    }
}
