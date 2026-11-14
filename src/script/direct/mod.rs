//! Driving an `async def` handler from the executor, without an asyncio task,
//! for as long as all it awaits is siphon's own awaitables.
//!
//! # Why
//!
//! An awaitable ([`super::blocking::awaitable`]) is a Rust future on tokio.
//! Awaiting one through asyncio costs an event-loop task and four thread
//! handoffs that do no work of the handler's: executor to driver to start the
//! coroutine, tokio to a completion thread to the driver to resume it, driver
//! to tokio to executor to finish. Most of the CPU of such a call is asyncio's
//! own loop, selector and `concurrent.futures` bytecode.
//!
//! None of it is needed to resume a coroutine when a Rust future completes.
//! Here the executor steps the coroutine itself: the awaitable yields itself,
//! the step registers the coroutine as the awaitable's waiter and returns its
//! worker, and the future's completion queues the next step as an executor
//! job. No driver thread runs and no asyncio object is made.
//!
//! # What keeps it correct
//!
//! A handler is free to use asyncio at any point, and nothing says so before
//! it does. So a step runs with everything asyncio looks at in place:
//!
//! - the **running loop** is a driver's loop, chosen when the coroutine
//!   starts, so `asyncio.sleep`, `create_task`, `gather` and friends bind to a
//!   loop that is really running;
//! - the **current task** is a [`DirectTask`], so `asyncio.timeout`,
//!   `wait_for` and `TaskGroup` find one, and it stays `current_task()` for
//!   the rest of the handler's life whichever thread runs it;
//! - the coroutine's **context** (`contextvars`) is one `Context` entered
//!   around every step, as a task would.
//!
//! The first time the handler really uses the loop, it is **handed over**:
//!
//! 1. Scheduling on the loop from a step (`call_soon`, `call_at`, a selector
//!    registration; every asyncio primitive ends in one) is seen by the
//!    driver loop class, which is siphon's (`python::DRIVER_SOURCE`). The step takes
//!    the loop's **baton**: the driver thread parks in a callback until the
//!    step ends. The step is then the only thing running on that loop, which
//!    is what asyncio code assumes, and what it scheduled runs after it, as
//!    it would have under a task.
//! 2. When the step ends, or as soon as the handler asks its task for
//!    anything a real task must answer (`cancel`, `add_done_callback`), a real
//!    `asyncio.Task` is created on the driver thread around a
//!    [`HandoverCoroutine`], which replays what the last step produced (the
//!    object it yielded, its return value or its exception) and from then on
//!    forwards to the coroutine. The handler continues on the driver exactly
//!    as if it had started there.
//!
//! A handler that was handed over is remembered by its code object and goes
//! straight to a driver from then on ([`is_demoted`]), so the hand-over is
//! paid once per handler, not per call.
//!
//! # What keeps it off
//!
//! - A driver loop with a task factory, or in asyncio's debug mode: an eager
//!   factory would run the hand-over's task before the step handing over has
//!   ended, and debug mode refuses loop calls from any thread but the loop's.
//!   The loop reports both (`python::DirectSwitch`) and its handlers start on
//!   the driver.
//! - An interpreter on which the asyncio internals this leans on do not
//!   behave as expected: one handler is driven through every step when the
//!   pool starts ([`self_test`]), and a step that cannot put a thread's
//!   asyncio state back turns the path off for good.
//!
//! # Cancellation
//!
//! As `asyncio.Task.cancel`: a cancellation is remembered under the same lock
//! as the coroutine's phase, the next resume throws `CancelledError` into the
//! coroutine instead of sending, once, and a coroutine that is waiting is
//! woken for it. The coroutine timeout is such a cancellation, and its
//! `TimeoutError` reaches the waiter whatever happens to the task that
//! noticed it ([`Drive::time_out`]).
//!
//! Nothing here blocks while attached to the interpreter: the baton's waits
//! release it and completions arrive on tokio workers that never attach. No
//! Python runs under one of its locks either; a source scan in
//! `attached_scan_tests` holds that.

use std::cell::RefCell;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use pyo3::exceptions::{PyRuntimeError, PyTimeoutError};
use pyo3::intern;
use pyo3::prelude::*;
use tokio::sync::oneshot;
use tracing::{debug, error};

use crate::script::async_pool::{AsyncPool, PendingCoroutine};

mod awaitable;
mod baton;
mod python;
mod task;
#[cfg(test)]
pub(crate) mod test_hooks;

pub(crate) use awaitable::awaitable_in_step;
#[cfg(test)]
pub(crate) use awaitable::SiphonAwaitable as TestAwaitable;
pub(crate) use python::{new_driver_loop, DriverLoop};

use awaitable::{Registered, SiphonAwaitable};
use baton::{Baton, LoopCommand, LoopPark};
use python::helpers;
use task::{DirectTask, HandoverCoroutine, HandoverLive};

/// Lock a mutex whose critical sections are a few moves of plain data: a
/// poisoned one is still consistent, and failing here would strand a
/// coroutine.
fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

// ---------------------------------------------------------------------------
// Whether direct dispatch is on at all.
// ---------------------------------------------------------------------------

const UNTESTED: u8 = 0;
const ON: u8 = 1;
const OFF: u8 = 2;

/// Direct dispatch leans on asyncio internals (`_set_running_loop`,
/// `_swap_current_task`, the future protocol of `Task`). That they exist says
/// nothing about what they do on the interpreter siphon is running on, so it
/// stays off until [`self_test`] has driven a handler through all of it and
/// seen the right answers.
static DIRECT: AtomicU8 = AtomicU8::new(UNTESTED);

fn enabled() -> bool {
    DIRECT.load(Ordering::Acquire) == ON
}

/// Turn direct dispatch off or back on, as the self-test would.
#[cfg(test)]
pub(crate) fn set_enabled(on: bool) {
    DIRECT.store(if on { ON } else { OFF }, Ordering::Release);
}

#[cfg(test)]
pub(crate) fn is_enabled() -> bool {
    enabled()
}

/// A step could not put this thread's asyncio state back. The thread may now
/// look like a loop thread to whatever runs on it next, so this is never
/// passed over: it is logged and no further handler is driven directly.
fn thread_state_broken(what: &str, error: &PyErr) {
    DIRECT.store(OFF, Ordering::Release);
    error!(
        %error,
        "direct dispatch failed {what} on an executor thread; async handlers \
         run on the asyncio drivers only from now on"
    );
}

/// Done-callback of the self-test coroutine.
#[pyclass(frozen)]
struct SelfTestReport {
    sender: Mutex<Option<std::sync::mpsc::Sender<bool>>>,
}

#[pymethods]
impl SelfTestReport {
    fn __call__(&self, passed: bool) {
        let sender = locked(&self.sender).take();
        if let Some(sender) = sender {
            let _ = sender.send(passed);
        }
    }
}

/// How long the self-test may take. It is three thread handoffs on an idle
/// process; the bound is for an interpreter on which it never finishes.
const SELF_TEST_PATIENCE: Duration = Duration::from_secs(5);

/// Drive one handler directly on this interpreter, through an await of a
/// siphon awaitable and a hand-over to a driver, and turn direct dispatch on
/// only if every step behaved. Called once the pool's drivers run; failing
/// costs nothing but the speed-up, and says so in the log.
pub(crate) fn self_test(pool: &Arc<AsyncPool>) {
    if DIRECT.load(Ordering::Acquire) != UNTESTED {
        return;
    }
    let verdict = Python::attach(|python| run_self_test(pool, python));
    match verdict {
        Ok(()) => {
            // Unless a step of the test itself found the thread state broken.
            let _ = DIRECT.compare_exchange(UNTESTED, ON, Ordering::AcqRel, Ordering::Acquire);
        }
        Err(reason) => {
            DIRECT.store(OFF, Ordering::Release);
            error!(
                %reason,
                "direct dispatch failed its self-test on this interpreter; \
                 async handlers run on the asyncio drivers only"
            );
        }
    }
}

fn run_self_test(pool: &Arc<AsyncPool>, python: Python<'_>) -> Result<(), String> {
    let helpers = helpers(python).ok_or("the helpers could not be built")?;
    let text = |error: PyErr| error.to_string();
    let peek = helpers.peek_running_loop.bind(python);
    let loop_before = peek.call0().map_err(text)?;
    let (sender, receiver) = std::sync::mpsc::channel();
    let report = Py::new(
        python,
        SelfTestReport {
            sender: Mutex::new(Some(sender)),
        },
    )
    .map_err(text)?;
    let coroutine = helpers
        .self_test
        .bind(python)
        .call1((&helpers.self_test_awaitable, report))
        .map_err(text)?;
    // Held until the verdict is in: dropping it is not what ends the test.
    let started = match start_unchecked(pool, python, &coroutine, None) {
        Some(DirectStart::Pending(pending)) => pending,
        Some(DirectStart::Finished(_)) => {
            return Err("the handler finished without being handed to a driver".into())
        }
        None => {
            let _ = coroutine.call_method0(intern!(python, "close"));
            return Err("no driver loop can be driven against".into());
        }
    };
    let loop_after = peek.call0().map_err(text)?;
    if !loop_after.is(&loop_before) {
        return Err("a step left its running loop on the thread".into());
    }
    let passed = python.detach(move || receiver.recv_timeout(SELF_TEST_PATIENCE));
    drop(started);
    match passed {
        Ok(true) => Ok(()),
        Ok(false) => Err("a handler saw the wrong loop, task or value".into()),
        Err(_) => Err("the handler did not finish".into()),
    }
}

// ---------------------------------------------------------------------------
// Which handlers are driven directly.
// ---------------------------------------------------------------------------

/// Code objects of handlers that were handed to asyncio once, keyed by
/// address. The value keeps the code object alive, which is what makes the
/// address a sound key (see `inline_dispatch::INLINE_VERDICTS`).
static DEMOTED: OnceLock<DashMap<usize, Py<PyAny>>> = OnceLock::new();

fn demoted() -> &'static DashMap<usize, Py<PyAny>> {
    DEMOTED.get_or_init(DashMap::new)
}

/// Forget which handlers use asyncio. Called on reload, which replaces the
/// code objects.
pub(crate) fn clear_demoted() {
    if let Some(map) = DEMOTED.get() {
        map.clear();
    }
}

/// Verdicts remembered, and a way to record one, for the tests.
#[cfg(test)]
pub(crate) fn demoted_len() -> usize {
    demoted().len()
}

#[cfg(test)]
pub(crate) fn demote_for_test(coroutine: &Bound<'_, PyAny>, key: Option<&Bound<'_, PyAny>>) {
    demote(coroutine, key);
}

/// Whether this coroutine's handler used asyncio on an earlier call. Such a
/// handler starts on a driver: handing it over each time would cost more than
/// the direct steps save, and a task it creates from an executor thread costs
/// a stop-the-world when it finishes on the driver.
fn is_demoted(coroutine: &Bound<'_, PyAny>, key: Option<&Bound<'_, PyAny>>) -> bool {
    if let Some(key) = key {
        return demoted().contains_key(&(key.as_ptr() as usize));
    }
    let Ok(code) = coroutine.getattr(intern!(coroutine.py(), "cr_code")) else {
        // Not a native coroutine: nothing to key a verdict on.
        return true;
    };
    demoted().contains_key(&(code.as_ptr() as usize))
}

/// Remember that the unit `key` names (the coroutine's code object when the
/// caller gave none) uses asyncio.
fn demote(coroutine: &Bound<'_, PyAny>, key: Option<&Bound<'_, PyAny>>) {
    let python = coroutine.py();
    let Ok(code) = coroutine.getattr(intern!(python, "cr_code")) else {
        return;
    };
    let code = match key {
        Some(key) => key.clone(),
        None => code,
    };
    let key = code.as_ptr() as usize;
    if demoted().contains_key(&key) {
        return;
    }
    debug!(
        handler = %code
            .getattr(intern!(python, "co_qualname"))
            .and_then(|name| name.extract::<String>())
            .unwrap_or_else(|_| "<unknown>".to_string()),
        "async handler uses asyncio beyond siphon's awaitables; it starts on \
         an asyncio driver from now on"
    );
    demoted().insert(key, code.unbind());
}

// ---------------------------------------------------------------------------
// The step in progress on this thread.
// ---------------------------------------------------------------------------

thread_local! {
    /// The coroutine this thread is stepping, if any.
    static ACTIVE: RefCell<Option<Arc<Drive>>> = const { RefCell::new(None) };
}

/// Whether the calling thread is inside a direct step, so an awaitable made
/// now can be awaited without asyncio.
pub(crate) fn in_direct_step() -> bool {
    ACTIVE.with(|active| active.borrow().is_some())
}

fn active_drive() -> Option<Arc<Drive>> {
    ACTIVE.with(|active| active.borrow().clone())
}

// ---------------------------------------------------------------------------
// The directly driven coroutine.
// ---------------------------------------------------------------------------

/// What the step that ended a coroutine's direct phase produced, replayed by
/// the [`HandoverCoroutine`] to the task that takes over.
enum First {
    /// The coroutine is suspended, having yielded this.
    Yielded(Py<PyAny>),
    /// The coroutine finished.
    Finished(PyResult<Py<PyAny>>),
}

/// The real task a coroutine was handed to.
struct Real {
    /// `cancel()`-able from any thread.
    cancel: Py<PyAny>,
    /// The task's outcome, until a [`PendingCoroutine`] is made of it.
    receiver: Option<oneshot::Receiver<PyResult<Py<PyAny>>>>,
}

enum Phase {
    /// A thread is running a step.
    Stepping,
    /// Suspended on a siphon awaitable.
    Waiting,
    /// A real asyncio task runs it.
    HandedOver,
    /// It finished in a direct step.
    Done,
}

struct DriveState {
    phase: Phase,
    waiting_on: Option<Py<SiphonAwaitable>>,
    baton: Option<Arc<Baton>>,
    real: Option<Real>,
    first: Option<First>,
    /// A cancellation the coroutine has not been told about yet. The next
    /// resume throws `CancelledError` into it instead of sending, once. Under
    /// the same lock as `phase`, so a cancellation either sees the coroutine
    /// waiting and wakes it, or is seen by the step before it waits.
    cancel_pending: bool,
}

/// What a finished coroutine's result goes to: called on the thread that
/// finished it, released from the interpreter.
pub(crate) type Completion = Box<dyn FnOnce(PyResult<Py<PyAny>>) + Send>;

enum Slot {
    /// Nobody asked for the result yet.
    Empty,
    Waiting(Completion),
    /// It finished before anybody asked.
    Result(PyResult<Py<PyAny>>),
    /// It was handed to asyncio before anybody asked: the result comes from
    /// there.
    HandedOver(PendingCoroutine),
    /// Delivered, or taken by the timeout.
    Taken,
}

/// How a step ended.
enum StepEnd {
    Finished(PyResult<Py<PyAny>>),
    /// Suspended on a siphon awaitable; its completion queues the next step.
    Suspended,
    /// A real asyncio task has it now.
    HandedOver,
}

/// The coroutine timeout of a coroutine whose waiter stays awake for the
/// result and bounds the wait itself, which costs it a timer and nothing else.
pub(crate) struct Deadline {
    drive: Arc<Drive>,
}

impl Deadline {
    /// How long the waiter may still wait.
    pub(crate) fn left(&self) -> Duration {
        self.drive.time_left()
    }

    /// The waiter waited that long: fail it with the timeout and cancel the
    /// coroutine, unless it finished or went to a driver in the meantime.
    /// Either way the waiter's result still arrives where it was going.
    ///
    /// Returns once the timeout is on its way to the waiter. From then on
    /// nothing the caller does, being dropped included, can stop it arriving.
    pub(crate) fn expire(self) {
        Drive::time_out(self.drive);
    }
}

/// How a coroutine started under [`start`].
pub(crate) enum DirectStart {
    /// It ran to the end in its first step.
    Finished(PyResult<Py<PyAny>>),
    /// It is suspended, on a siphon awaitable or on a driver.
    Pending(PendingCoroutine),
}

/// One coroutine driven from the executor.
pub(crate) struct Drive {
    coroutine: Py<PyAny>,
    /// What names the unit to remember as using asyncio, when not the code.
    demotion_key: Option<Py<PyAny>>,
    /// The driver loop the coroutine is bound to: its running loop in every
    /// step, and where it goes if it is handed over.
    event_loop: Py<PyAny>,
    pool: Arc<AsyncPool>,
    driver: usize,
    /// The coroutine's `contextvars.Context`.
    context: Py<PyAny>,
    task: Py<DirectTask>,
    started: Instant,
    timeout: Duration,
    state: Mutex<DriveState>,
    slot: Mutex<Slot>,
    watchdog: Mutex<Option<tokio::task::AbortHandle>>,
}

/// Start `coroutine` on the calling executor worker without an asyncio task.
///
/// `None` leaves the coroutine untouched, for the caller to hand to a driver:
/// its handler is known to use asyncio, its loop has a task factory or is in
/// debug mode, or the direct path is unavailable or failed its self-test.
/// Otherwise the first step has run and the coroutine is finished, suspended
/// on a siphon awaitable, or already on a driver.
/// Also takes the object that names the unit to remember as using asyncio:
/// a host that runs many handlers through one shared wrapper coroutine passes
/// one per handler, since the wrapper's code object is the same for all of
/// them. `None` keys on the coroutine's code object.
pub(crate) fn start_keyed(
    pool: &Arc<AsyncPool>,
    python: Python<'_>,
    coroutine: &Bound<'_, PyAny>,
    demotion_key: Option<&Bound<'_, PyAny>>,
) -> Option<DirectStart> {
    if !enabled() {
        return None;
    }
    start_unchecked(pool, python, coroutine, demotion_key)
}

/// [`start_keyed`] without asking whether direct dispatch passed its self-test,
/// which is how the self-test itself starts.
fn start_unchecked(
    pool: &Arc<AsyncPool>,
    python: Python<'_>,
    coroutine: &Bound<'_, PyAny>,
    demotion_key: Option<&Bound<'_, PyAny>>,
) -> Option<DirectStart> {
    if is_demoted(coroutine, demotion_key) {
        return None;
    }
    helpers(python)?;
    let driver = pool.pick_driver()?;
    let driver_loop = pool.driver_loop(driver)?;
    // Not against a loop with a task factory or in debug mode.
    if !driver_loop.direct.as_ref()?.switch.get().allows() {
        return None;
    }
    // SAFETY: attached; a new reference or NULL with an exception set.
    let context =
        unsafe { Bound::from_owned_ptr_or_err(python, pyo3::ffi::PyContext_CopyCurrent()).ok()? };
    let task = Py::new(
        python,
        DirectTask {
            drive: OnceLock::new(),
            real: OnceLock::new(),
            event_loop: driver_loop.event_loop.clone_ref(python),
            name: Mutex::new(None),
        },
    )
    .ok()?;
    let drive = Arc::new(Drive {
        coroutine: coroutine.clone().unbind(),
        demotion_key: demotion_key.map(|key| key.clone().unbind()),
        event_loop: driver_loop.event_loop.clone_ref(python),
        pool: Arc::clone(pool),
        driver,
        context: context.unbind(),
        task: task.clone_ref(python),
        started: Instant::now(),
        timeout: pool.coroutine_timeout(),
        state: Mutex::new(DriveState {
            phase: Phase::Stepping,
            waiting_on: None,
            baton: None,
            real: None,
            first: None,
            cancel_pending: false,
        }),
        slot: Mutex::new(Slot::Empty),
        watchdog: Mutex::new(None),
    });
    let _ = task.get().drive.set(Arc::downgrade(&drive));
    Some(match drive.step(python) {
        StepEnd::Finished(result) => DirectStart::Finished(result),
        StepEnd::Suspended | StepEnd::HandedOver => {
            DirectStart::Pending(PendingCoroutine::direct(drive))
        }
    })
}

/// What one `send` into the coroutine came to.
enum Sent<'py> {
    Yielded(Bound<'py, PyAny>),
    Returned(Bound<'py, PyAny>),
    Raised(PyErr),
}

impl Drive {
    pub(crate) fn timeout(&self) -> Duration {
        self.timeout
    }

    /// For a waiter that bounds its own wait instead of [`Self::arm_timeout`].
    pub(crate) fn deadline(self: &Arc<Self>) -> Deadline {
        Deadline {
            drive: Arc::clone(self),
        }
    }

    /// Run the coroutine until it finishes, suspends on a siphon awaitable,
    /// or has to be handed to asyncio.
    fn step(self: &Arc<Self>, python: Python<'_>) -> StepEnd {
        loop {
            let sent = self.resume(python);
            let (materialised, holds_baton) = {
                let state = locked(&self.state);
                (state.real.is_some(), state.baton.is_some())
            };
            match sent {
                Sent::Yielded(yielded) => {
                    if !materialised && !holds_baton {
                        if let Ok(awaitable) = yielded.cast::<SiphonAwaitable>() {
                            match self.suspend_on(python, awaitable) {
                                Some(end) => return end,
                                None => continue,
                            }
                        }
                    }
                    return self.hand_over(python, First::Yielded(yielded.unbind()));
                }
                Sent::Returned(value) if materialised => {
                    return self.hand_over(python, First::Finished(Ok(value.unbind())));
                }
                Sent::Raised(error) if materialised => {
                    return self.hand_over(python, First::Finished(Err(error)));
                }
                Sent::Returned(value) => {
                    // Cancelled during the step that returned: the handler
                    // ends cancelled, as an asyncio task does.
                    let cancelled = std::mem::take(&mut locked(&self.state).cancel_pending);
                    let result = if cancelled {
                        Err(awaitable::cancelled_error(python))
                    } else {
                        Ok(value.unbind())
                    };
                    return self.finish(python, result);
                }
                Sent::Raised(error) => return self.finish(python, Err(error)),
            }
        }
    }

    /// The coroutine finished in a direct step.
    fn finish(&self, python: Python<'_>, result: PyResult<Py<PyAny>>) -> StepEnd {
        let baton = {
            let mut state = locked(&self.state);
            state.phase = Phase::Done;
            state.baton.take()
        };
        if let Some(baton) = baton {
            // It scheduled on the loop (a task it created, a callback) and
            // returned: that work runs now, and the handler starts on a
            // driver next time.
            demote(
                self.coroutine.bind(python),
                self.demotion_key.as_ref().map(|key| key.bind(python)),
            );
            baton.release();
        }
        StepEnd::Finished(result)
    }

    /// The coroutine yielded a siphon awaitable in a step that has not used
    /// the loop. `None` to resume at once: the awaitable has finished, or a
    /// cancellation is pending.
    fn suspend_on(
        self: &Arc<Self>,
        python: Python<'_>,
        awaitable: &Bound<'_, SiphonAwaitable>,
    ) -> Option<StepEnd> {
        let shared = &awaitable.get().shared;
        #[cfg(test)]
        test_hooks::fire(python, test_hooks::Point::AtSuspend, self);
        let cancelled = {
            let mut state = locked(&self.state);
            if state.cancel_pending {
                true
            } else {
                state.phase = Phase::Waiting;
                state.waiting_on = Some(awaitable.clone().unbind());
                false
            }
        };
        if cancelled {
            // Cancelled before it could wait: the awaitable is cancelled as a
            // task's is, and the next resume throws.
            shared.cancel(python);
            return None;
        }
        #[cfg(test)]
        test_hooks::fire(python, test_hooks::Point::BeforeRegister, self);
        // From here another thread may be stepping the coroutine: nothing
        // below touches it.
        match shared.register(self) {
            Registered::Waiting => Some(StepEnd::Suspended),
            outcome => {
                let released = {
                    let mut state = locked(&self.state);
                    state.phase = Phase::Stepping;
                    state.waiting_on.take()
                };
                drop(released);
                match outcome {
                    Registered::Busy => {
                        // Two coroutines on one awaitable: this one waits for
                        // it as an asyncio future.
                        Some(self.hand_over(
                            python,
                            First::Yielded(awaitable.clone().into_any().unbind()),
                        ))
                    }
                    _ => None,
                }
            }
        }
    }

    /// One resume with the running loop, current task, context and
    /// async-generator hooks of this coroutine in place on this thread:
    /// `send(None)`, or `throw(CancelledError)` when a cancellation is
    /// pending.
    fn resume<'py>(self: &Arc<Self>, python: Python<'py>) -> Sent<'py> {
        let Some(helpers) = helpers(python) else {
            return Sent::Raised(PyRuntimeError::new_err(
                "the direct-dispatch helpers are missing",
            ));
        };
        let hooks = self
            .pool
            .driver_loop(self.driver)
            .and_then(|driver_loop| driver_loop.direct.as_ref());
        let event_loop = self.event_loop.bind(python);
        let set_loop = helpers.set_running_loop.bind(python);
        let swap_task = helpers.swap_current_task.bind(python);
        let set_hooks = helpers.set_asyncgen_hooks.bind(python);

        // A step can nest in another's (a handler calling a synchronous API
        // that dispatches a second handler): put back what was there.
        let outer = ACTIVE.with(|active| active.replace(Some(Arc::clone(self))));
        let restore_active = |outer: Option<Arc<Drive>>| {
            ACTIVE.with(|active| active.replace(outer));
        };
        let outer_loop = match &outer {
            Some(outer) => outer.event_loop.bind(python).clone(),
            None => python.None().into_bound(python),
        };
        if let Err(error) = set_loop.call1((event_loop,)) {
            restore_active(outer);
            return Sent::Raised(error);
        }
        let previous_task = match swap_task.call1((event_loop, &self.task)) {
            Ok(previous) => previous,
            Err(error) => {
                if let Err(restore) = set_loop.call1((&outer_loop,)) {
                    thread_state_broken("restoring the running loop", &restore);
                }
                restore_active(outer);
                return Sent::Raised(error);
            }
        };
        if let Some(hooks) = hooks {
            if let Err(error) = set_hooks.call1((&hooks.firstiter, &hooks.finalizer)) {
                thread_state_broken("installing the async-generator hooks", &error);
            }
        }
        let cancel = std::mem::take(&mut locked(&self.state).cancel_pending);

        // SAFETY: attached; `context` is a `contextvars.Context`. Enter and
        // exit are paired on this thread around the one call.
        let entered = unsafe { pyo3::ffi::PyContext_Enter(self.context.as_ptr()) } == 0;
        let sent = if entered {
            let sent = if cancel {
                throw_cancelled(self.coroutine.bind(python))
            } else {
                send_none(self.coroutine.bind(python))
            };
            // SAFETY: as above; entered just before on this thread.
            if unsafe { pyo3::ffi::PyContext_Exit(self.context.as_ptr()) } != 0 {
                // Unreachable for a context this thread entered. Fetched so it
                // is not raised by an unrelated call later.
                thread_state_broken("leaving the handler's context", &PyErr::fetch(python));
            }
            sent
        } else {
            Sent::Raised(PyErr::fetch(python))
        };

        let outer_hooks = outer.as_ref().and_then(|outer| {
            outer
                .pool
                .driver_loop(outer.driver)
                .and_then(|driver_loop| driver_loop.direct.as_ref())
        });
        // Putting the thread back as it was. A failure here leaves it looking
        // like a loop thread to whatever runs on it next, so it is never
        // dropped: it is logged and direct dispatch is turned off.
        let restored = match outer_hooks {
            Some(hooks) => set_hooks.call1((&hooks.firstiter, &hooks.finalizer)),
            None => set_hooks.call1((python.None(), python.None())),
        };
        if let Err(error) = restored {
            thread_state_broken("restoring the async-generator hooks", &error);
        }
        if let Err(error) = swap_task.call1((event_loop, previous_task)) {
            thread_state_broken("restoring the current task", &error);
        }
        if let Err(error) = set_loop.call1((&outer_loop,)) {
            thread_state_broken("restoring the running loop", &error);
        }
        restore_active(outer);
        sent
    }

    /// Park the driver loop for the rest of this step. Called from inside the
    /// step, by the loop class or the task.
    fn take_baton(self: &Arc<Self>, python: Python<'_>) -> PyResult<()> {
        if locked(&self.state).baton.is_some() {
            return Ok(());
        }
        // Before the driver is asked to park, not after: calls of this
        // handler that start meanwhile go straight to a driver instead of
        // each parking one and holding an executor worker while it does.
        demote(
            self.coroutine.bind(python),
            self.demotion_key.as_ref().map(|key| key.bind(python)),
        );
        let baton = Arc::new(Baton::new());
        let park = Py::new(
            python,
            LoopPark {
                baton: Arc::clone(&baton),
            },
        )?;
        self.event_loop
            .bind(python)
            .call_method1(intern!(python, "call_soon_threadsafe"), (park,))?;
        let patience = self.timeout;
        let waiting = Arc::clone(&baton);
        if !python.detach(move || waiting.wait_parked(patience)) {
            return Err(PyRuntimeError::new_err(
                "the handler's asyncio driver did not respond; its event loop \
                 is blocked or shutting down",
            ));
        }
        locked(&self.state).baton = Some(baton);
        Ok(())
    }

    /// Create the real asyncio task for this coroutine, on its driver thread,
    /// while the driver is parked for this step. The task does nothing until
    /// the step ends and leaves it something to replay ([`First`]).
    fn materialise(self: &Arc<Self>, python: Python<'_>) -> PyResult<()> {
        if locked(&self.state).real.is_some() {
            return Ok(());
        }
        self.take_baton(python)?;
        let Some(baton) = locked(&self.state).baton.clone() else {
            return Err(PyRuntimeError::new_err("the driver loop is not parked"));
        };
        type Made = PyResult<(Py<PyAny>, Real)>;
        let made: Arc<Mutex<Option<Made>>> = Arc::new(Mutex::new(None));
        let output = Arc::clone(&made);
        let drive = Arc::clone(self);
        let command: LoopCommand = Box::new(move |python| {
            let result = drive.make_task(python);
            *locked(&output) = Some(result);
        });
        python.detach(move || baton.run(command));
        let made = locked(&made).take();
        let (task, real) = made
            .ok_or_else(|| PyRuntimeError::new_err("the asyncio driver did not make the task"))??;
        let _ = self.task.get().real.set(task);
        locked(&self.state).real = Some(real);
        Ok(())
    }

    /// On the driver thread: the task, with its completion bridged to Rust.
    fn make_task(self: &Arc<Self>, python: Python<'_>) -> PyResult<(Py<PyAny>, Real)> {
        let helpers = helpers(python)
            .ok_or_else(|| PyRuntimeError::new_err("the direct-dispatch helpers are missing"))?;
        let (bridge, receiver) = AsyncPool::completion_bridge(python)?;
        let handover = Py::new(
            python,
            HandoverCoroutine {
                live: Mutex::new(Some(HandoverLive {
                    drive: Arc::clone(self),
                    task: self.task.clone_ref(python),
                })),
                coroutine: self.coroutine.clone_ref(python),
                event_loop: self.event_loop.clone_ref(python),
            },
        )?;
        let made = helpers.make_task.bind(python).call1((
            &self.event_loop,
            handover,
            &self.context,
            bridge,
        ))?;
        let (task, cancel): (Py<PyAny>, Py<PyAny>) = made.extract()?;
        Ok((
            task,
            Real {
                cancel,
                receiver: Some(receiver),
            },
        ))
    }

    /// End the direct phase: a real task continues from `first`.
    fn hand_over(self: &Arc<Self>, python: Python<'_>, first: First) -> StepEnd {
        if let Err(error) = self.materialise(python) {
            // The coroutine is mid-flight and no task can take it. Say so,
            // and close it so its `finally` blocks run, rather than leave it
            // suspended for ever.
            error!(
                %error,
                "an async handler could not be handed to its asyncio driver; \
                 failing the call"
            );
            let _ = self
                .coroutine
                .bind(python)
                .call_method0(intern!(python, "close"));
            return self.finish(python, Err(error));
        }
        let (baton, classic, cancel) = {
            let mut state = locked(&self.state);
            state.first = Some(first);
            state.phase = Phase::HandedOver;
            // A cancellation the coroutine was not told about goes to the
            // task that takes it over.
            let cancel = if std::mem::take(&mut state.cancel_pending) {
                state
                    .real
                    .as_ref()
                    .map(|real| real.cancel.clone_ref(python))
            } else {
                None
            };
            let classic = state.real.as_mut().and_then(|real| {
                let receiver = real.receiver.take()?;
                Some(PendingCoroutine::handed_over(
                    receiver,
                    real.cancel.clone_ref(python),
                    self.coroutine.clone_ref(python),
                    self.timeout.saturating_sub(self.started.elapsed()),
                ))
            });
            (state.baton.take(), classic, cancel)
        };
        if let Some(cancel) = cancel {
            if let Err(error) = cancel.bind(python).call_method0(intern!(python, "cancel")) {
                error!(%error, "could not cancel a handler handed to its asyncio driver");
            }
        }
        // The driver goes back to its loop: what the step scheduled runs,
        // then the task's first step replays `first`.
        if let Some(baton) = baton {
            baton.release();
        }
        if let Some(classic) = classic {
            self.stop_watchdog();
            let waiting = {
                let mut slot = locked(&self.slot);
                match std::mem::replace(&mut *slot, Slot::Taken) {
                    Slot::Waiting(completion) => Some((classic, completion)),
                    Slot::Empty => {
                        *slot = Slot::HandedOver(classic);
                        None
                    }
                    other => {
                        *slot = other;
                        None
                    }
                }
            };
            if let Some((classic, completion)) = waiting {
                classic.resume_on_executor(completion);
            }
        }
        StepEnd::HandedOver
    }

    /// What the last direct step left for the real task, once.
    fn take_first(&self) -> Option<First> {
        locked(&self.state).first.take()
    }

    /// An executor job: the awaitable this coroutine waited on has finished.
    fn run(self: Arc<Self>) {
        let delivery = crate::script::attach::attach(|python| {
            let released = {
                let mut state = locked(&self.state);
                if !matches!(state.phase, Phase::Waiting) {
                    return None;
                }
                state.phase = Phase::Stepping;
                state.waiting_on.take()
            };
            drop(released);
            match self.step(python) {
                StepEnd::Finished(result) => self.deliver(python, result),
                StepEnd::Suspended | StepEnd::HandedOver => None,
            }
        });
        if let Some((completion, result)) = delivery {
            completion(result);
        }
    }

    /// The coroutine finished in a later step: who gets the result. Returned
    /// rather than called, so it runs released from the interpreter.
    fn deliver(
        &self,
        _python: Python<'_>,
        result: PyResult<Py<PyAny>>,
    ) -> Option<(Completion, PyResult<Py<PyAny>>)> {
        self.stop_watchdog();
        let mut slot = locked(&self.slot);
        match std::mem::replace(&mut *slot, Slot::Taken) {
            Slot::Waiting(completion) => Some((completion, result)),
            Slot::Empty => {
                *slot = Slot::Result(result);
                None
            }
            // The timeout answered for it: the late result is dropped here,
            // attached.
            _ => None,
        }
    }

    /// Queue the next step from a tokio task. Never shed: a coroutine that is
    /// not resumed is a handler that silently never finishes.
    async fn queue_step(drive: Arc<Self>) {
        if !crate::script::py_executor::spawn_queued(move || drive.run()).await {
            error!(
                "Python executor closed while an async handler was awaiting; \
                 the handler cannot be resumed"
            );
        }
    }

    /// [`Self::queue_step`] from a thread that cannot await.
    fn queue_step_from_sync(drive: Arc<Self>) {
        pyo3_async_runtimes::tokio::get_runtime().spawn(Self::queue_step(drive));
    }

    /// Give the coroutine's result to `completion` when it finishes, on the
    /// executor, released from the interpreter. Must be called with a tokio
    /// runtime entered.
    pub(crate) fn on_complete(self: &Arc<Self>, completion: Completion) {
        let ready = {
            let mut slot = locked(&self.slot);
            match std::mem::replace(&mut *slot, Slot::Taken) {
                Slot::Empty => {
                    *slot = Slot::Waiting(completion);
                    return;
                }
                other => (other, completion),
            }
        };
        match ready {
            (Slot::Result(result), completion) => {
                pyo3_async_runtimes::tokio::get_runtime().spawn(async move {
                    let queued =
                        crate::script::py_executor::spawn_queued(move || completion(result)).await;
                    if !queued {
                        error!(
                            "Python executor closed while an async handler was awaiting; \
                             the work after its await cannot run"
                        );
                    }
                });
            }
            (Slot::HandedOver(classic), completion) => classic.resume_on_executor(completion),
            // One completion per coroutine: `PendingCoroutine` is consumed by
            // whichever wait installs it.
            _ => error!("a directly driven coroutine was waited for twice"),
        }
    }

    /// Fail the coroutine's waiter with the coroutine timeout if it has not
    /// finished by then, and cancel it. For a waiter nothing else bounds, at
    /// the cost of a tokio task; one that stays awake for the result bounds
    /// the wait itself ([`Deadline`]). Must be called with a tokio runtime
    /// entered.
    pub(crate) fn arm_timeout(self: &Arc<Self>) {
        let drive = Arc::clone(self);
        let left = self.time_left();
        let watchdog = tokio::spawn(async move {
            tokio::time::sleep(left).await;
            Self::time_out(drive);
        });
        *locked(&self.watchdog) = Some(watchdog.abort_handle());
        // It may have finished while the watchdog was being armed.
        if !matches!(*locked(&self.slot), Slot::Waiting(_)) {
            self.stop_watchdog();
        }
    }

    /// How much of the coroutine timeout is left.
    fn time_left(&self) -> Duration {
        self.timeout.saturating_sub(self.started.elapsed())
    }

    /// The coroutine timeout ran out: if the coroutine is still the
    /// executor's and somebody waits for it, cancel it and give the waiter
    /// the timeout instead of a result. One that finished, or was handed to
    /// a driver (where the wait has its own bound), is left alone.
    ///
    /// Not `async`, on purpose. The caller is a task that is aborted or
    /// dropped as soon as the coroutine finishes, and once the completion is
    /// out of the slot nothing else will ever deliver it. So nothing between
    /// taking it and handing it to a task of its own can be interrupted, and
    /// that task is nobody's to abort: it waits for room in the executor
    /// queue for as long as that takes. Must be called with a tokio runtime
    /// entered.
    fn time_out(drive: Arc<Self>) {
        let completion = {
            let mut slot = locked(&drive.slot);
            match std::mem::replace(&mut *slot, Slot::Taken) {
                Slot::Waiting(completion) => completion,
                other => {
                    *slot = other;
                    return;
                }
            }
        };
        tokio::spawn(async move {
            let queued = crate::script::py_executor::spawn_queued(move || {
                let error = crate::script::attach::attach(|python| drive.expire(python));
                completion(Err(error));
            })
            .await;
            if !queued {
                error!(
                    "Python executor closed while an async handler was awaiting; \
                     its timeout cannot be reported"
                );
            }
        });
    }

    fn stop_watchdog(&self) {
        if let Some(watchdog) = locked(&self.watchdog).take() {
            watchdog.abort();
        }
    }

    /// The coroutine outlived the coroutine timeout: cancel it and build the
    /// error its caller gets.
    pub(crate) fn expire(&self, python: Python<'_>) -> PyErr {
        let cancelled = self.cancel(python);
        let handler = crate::script::async_pool::coroutine_name(self.coroutine.bind(python));
        error!(
            handler = %handler,
            timeout_secs = self.timeout.as_secs(),
            cancelled,
            "async script handler did not settle within the coroutine timeout; \
             failing this call. The handler is awaiting something that never \
             completes — an unbounded backend call, a DNS lookup, or a future \
             nothing resolves."
        );
        PyTimeoutError::new_err(format!(
            "async handler '{handler}' did not settle within {}s",
            self.timeout.as_secs()
        ))
    }

    /// Cancel the coroutine wherever it is, as `asyncio.Task.cancel` does:
    /// the next time it is resumed `CancelledError` is thrown into it, once,
    /// and if it is waiting it is woken for that. `false` if it has finished.
    pub(crate) fn cancel(&self, python: Python<'_>) -> bool {
        enum Target {
            /// Waiting on this: cancelling it wakes the coroutine.
            Awaitable(Py<SiphonAwaitable>),
            Task(Py<PyAny>),
            /// A step is running, or one is queued: it sees the flag.
            Step,
            Nothing,
        }
        let target = {
            let mut state = locked(&self.state);
            if matches!(state.phase, Phase::Done) {
                Target::Nothing
            } else if let Some(real) = &state.real {
                Target::Task(real.cancel.clone_ref(python))
            } else {
                state.cancel_pending = true;
                match (&state.phase, &state.waiting_on) {
                    (Phase::Waiting, Some(awaitable)) => {
                        Target::Awaitable(awaitable.clone_ref(python))
                    }
                    _ => Target::Step,
                }
            }
        };
        match target {
            Target::Nothing => false,
            Target::Step => true,
            Target::Awaitable(awaitable) => {
                // Wakes the coroutine if it is registered. If the awaitable
                // finished first, the step it queued throws instead; if the
                // coroutine is not registered yet, registering finds the
                // awaitable cancelled and resumes at once.
                awaitable.get().shared.cancel(python);
                true
            }
            Target::Task(cancel) => cancel
                .bind(python)
                .call_method0(intern!(python, "cancel"))
                .and_then(|cancelled| cancelled.extract::<bool>())
                .unwrap_or(false),
        }
    }
}

impl Drop for Drive {
    fn drop(&mut self) {
        self.stop_watchdog();
        if matches!(
            *self
                .slot
                .get_mut()
                .unwrap_or_else(|poison| poison.into_inner()),
            Slot::Waiting(_)
        ) {
            error!(
                "a directly driven async handler was dropped before it \
                 finished; whatever waited for it is never resumed"
            );
        }
    }
}

/// `coroutine.throw(CancelledError())`.
fn throw_cancelled<'py>(coroutine: &Bound<'py, PyAny>) -> Sent<'py> {
    let python = coroutine.py();
    let cancelled = awaitable::cancelled_error(python).into_value(python);
    match coroutine.call_method1(intern!(python, "throw"), (cancelled,)) {
        Ok(yielded) => Sent::Yielded(yielded),
        Err(error) if error.is_instance_of::<pyo3::exceptions::PyStopIteration>(python) => {
            // It caught the cancellation and returned.
            match error.value(python).getattr(intern!(python, "value")) {
                Ok(value) => Sent::Returned(value),
                Err(error) => Sent::Raised(error),
            }
        }
        Err(error) => Sent::Raised(error),
    }
}

/// `coroutine.send(None)`.
fn send_none<'py>(coroutine: &Bound<'py, PyAny>) -> Sent<'py> {
    let python = coroutine.py();
    let mut result: *mut pyo3::ffi::PyObject = std::ptr::null_mut();
    // SAFETY: attached; `coroutine` is a live object and `result` receives a
    // new reference on `PYGEN_NEXT` and `PYGEN_RETURN`, NULL with an
    // exception set on `PYGEN_ERROR`.
    let status =
        unsafe { pyo3::ffi::PyIter_Send(coroutine.as_ptr(), pyo3::ffi::Py_None(), &mut result) };
    match status {
        pyo3::ffi::PySendResult::PYGEN_NEXT | pyo3::ffi::PySendResult::PYGEN_RETURN
            if result.is_null() =>
        {
            Sent::Raised(PyErr::fetch(python))
        }
        // SAFETY: a new, non-null reference, per the status.
        pyo3::ffi::PySendResult::PYGEN_NEXT => {
            Sent::Yielded(unsafe { Bound::from_owned_ptr(python, result) })
        }
        // SAFETY: as above.
        pyo3::ffi::PySendResult::PYGEN_RETURN => {
            Sent::Returned(unsafe { Bound::from_owned_ptr(python, result) })
        }
        pyo3::ffi::PySendResult::PYGEN_ERROR => Sent::Raised(PyErr::fetch(python)),
    }
}
