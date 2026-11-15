//! The task asyncio sees for a directly driven handler, and the coroutine
//! that carries the handler over to a real one.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::ThreadId;

use pyo3::exceptions::{PyAttributeError, PyRuntimeError, PyStopIteration};
use pyo3::intern;
use pyo3::prelude::*;

use super::awaitable::SiphonAwaitable;
use super::drive::{self, locked, CancelReason, DriveKey, First};
use super::python::helpers;
use super::{Fate, Message, RunnerShared, Work};

/// `asyncio.current_task()` for a directly driven handler, for its whole
/// life: in the runner's steps and, after a hand-over, in the real task's.
///
/// While the handler has not asked it for anything a real task must answer,
/// it answers the cheap questions itself (`get_name()`, which `logging` asks
/// for every record; `done()`; `cancelling()`; `cancel()`). The first other
/// use creates the real `asyncio.Task`, on the handler's own thread, and
/// every attribute is that task's from then on.
#[pyclass(frozen, weakref, name = "SiphonHandlerTask")]
pub(crate) struct DirectTask {
    /// The handler's slab key, 0 until its entry exists.
    key: AtomicU64,
    owner: ThreadId,
    runner: Arc<RunnerShared>,
    /// The real task, once the handler has one. Behind a lock so that the
    /// collector can be shown it and take it back (`__traverse__`,
    /// `__clear__`): a task's result or exception can lead back here.
    real: Mutex<Option<Py<PyAny>>>,
    event_loop: Py<PyAny>,
    name: Mutex<Option<Py<PyAny>>>,
    /// The handler finished without a real task.
    done: AtomicBool,
    /// It finished by `CancelledError`.
    ended_cancelled: AtomicBool,
    /// `cancel()` calls not yet taken back by `uncancel()`.
    cancel_requests: AtomicUsize,
}

/// Where a [`DirectTask`] stands when something is asked of it.
enum TaskStanding<'py> {
    /// A real asyncio task answers.
    Real(Bound<'py, PyAny>),
    /// The handler asks from its own step.
    OwnStep(DriveKey),
    /// The handler is suspended, driven by siphon, and the caller is
    /// something else on its driver thread.
    Suspended(DriveKey),
    /// The caller is on another thread.
    Foreign(DriveKey),
    /// The handler finished without ever needing a real task.
    Finished,
}

impl DirectTask {
    pub(super) fn new(runner: Arc<RunnerShared>, event_loop: Py<PyAny>) -> Self {
        Self {
            key: AtomicU64::new(0),
            owner: std::thread::current().id(),
            runner,
            real: Mutex::new(None),
            event_loop,
            name: Mutex::new(None),
            done: AtomicBool::new(false),
            ended_cancelled: AtomicBool::new(false),
            cancel_requests: AtomicUsize::new(0),
        }
    }

    pub(super) fn bind_key(&self, key: DriveKey) {
        self.key.store(key.0, Ordering::Release);
    }

    pub(super) fn mark_done(&self, cancelled: bool) {
        self.ended_cancelled.store(cancelled, Ordering::Release);
        self.done.store(true, Ordering::Release);
    }

    pub(super) fn set_real(&self, real: Py<PyAny>) {
        // Set once, on the owner thread; a second one is dropped, attached,
        // with the lock released.
        let mut real = Some(real);
        {
            let mut slot = locked(&self.real);
            if slot.is_none() {
                *slot = real.take();
            }
        }
        drop(real);
    }

    /// Let go of the real task; the caller drops it, attached.
    pub(super) fn forget_real(&self) -> Option<Py<PyAny>> {
        locked(&self.real).take()
    }

    fn real_task<'py>(&self, python: Python<'py>) -> Option<Bound<'py, PyAny>> {
        let real = locked(&self.real)
            .as_ref()
            .map(|real| real.clone_ref(python));
        real.map(|real| real.into_bound(python))
    }

    fn key(&self) -> Option<DriveKey> {
        match self.key.load(Ordering::Acquire) {
            0 => None,
            key => Some(DriveKey(key)),
        }
    }

    fn standing<'py>(&self, python: Python<'py>) -> TaskStanding<'py> {
        if let Some(real) = self.real_task(python) {
            return TaskStanding::Real(real);
        }
        let Some(key) = self.key() else {
            return TaskStanding::Finished;
        };
        if self.done.load(Ordering::Acquire) {
            return TaskStanding::Finished;
        }
        if std::thread::current().id() != self.owner {
            return TaskStanding::Foreign(key);
        }
        if drive::active() == Some(key) {
            TaskStanding::OwnStep(key)
        } else {
            TaskStanding::Suspended(key)
        }
    }

    /// The real task, created now if the caller is on the handler's thread.
    fn real<'py>(&self, python: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        match self.standing(python) {
            TaskStanding::Real(real) => Ok(real),
            TaskStanding::OwnStep(key) => Ok(drive::materialise(python, key)?.into_bound(python)),
            TaskStanding::Suspended(key) => {
                Ok(drive::hand_over_suspended(python, key)?.into_bound(python))
            }
            TaskStanding::Foreign(_) | TaskStanding::Finished => Err(PyRuntimeError::new_err(
                "this handler's task was only ever driven by siphon and is \
                 used outside the handler: it has no asyncio task behind it",
            )),
        }
    }
}

#[pymethods]
impl DirectTask {
    fn get_name(slf: &Bound<'_, Self>) -> PyResult<Py<PyAny>> {
        let python = slf.py();
        let this = slf.get();
        if let Some(real) = this.real_task(python) {
            return Ok(real.call_method0(intern!(python, "get_name"))?.unbind());
        }
        let named = locked(&this.name)
            .as_ref()
            .map(|name| name.clone_ref(python));
        if let Some(name) = named {
            return Ok(name);
        }
        // Unique while the task lives, at no cost to a handler that never
        // asks.
        Ok(format!("siphon-handler-{:x}", slf.as_ptr() as usize)
            .into_pyobject(python)?
            .into_any()
            .unbind())
    }

    fn set_name(&self, python: Python<'_>, value: Bound<'_, PyAny>) -> PyResult<()> {
        if let Some(real) = self.real_task(python) {
            real.call_method1(intern!(python, "set_name"), (value,))?;
            return Ok(());
        }
        let text = value.str()?.into_any().unbind();
        let previous = locked(&self.name).replace(text);
        drop(previous);
        Ok(())
    }

    fn get_loop(&self, python: Python<'_>) -> Py<PyAny> {
        self.event_loop.clone_ref(python)
    }

    /// The handler's coroutine, not the wrapper a real task runs.
    fn get_coro(&self, python: Python<'_>) -> Py<PyAny> {
        let on_owner = std::thread::current().id() == self.owner;
        match self.key().filter(|_| on_owner) {
            Some(key) => drive::coroutine_and_context(python, key)
                .map_or_else(|| python.None(), |(coroutine, _)| coroutine),
            None => python.None(),
        }
    }

    fn get_context(&self, python: Python<'_>) -> PyResult<Py<PyAny>> {
        let on_owner = std::thread::current().id() == self.owner;
        if let Some((_, context)) = self
            .key()
            .filter(|_| on_owner)
            .and_then(|key| drive::coroutine_and_context(python, key))
        {
            return Ok(context);
        }
        Ok(self
            .real(python)?
            .call_method0(intern!(python, "get_context"))?
            .unbind())
    }

    fn done(&self, python: Python<'_>) -> PyResult<bool> {
        if let Some(real) = self.real_task(python) {
            return real.call_method0(intern!(python, "done"))?.extract();
        }
        Ok(self.key().is_none() || self.done.load(Ordering::Acquire))
    }

    fn cancelled(&self, python: Python<'_>) -> PyResult<bool> {
        match self.real_task(python) {
            Some(real) => real.call_method0(intern!(python, "cancelled"))?.extract(),
            None => Ok(self.ended_cancelled.load(Ordering::Acquire)),
        }
    }

    fn cancelling(&self, python: Python<'_>) -> PyResult<usize> {
        match self.real_task(python) {
            Some(real) => real.call_method0(intern!(python, "cancelling"))?.extract(),
            None => Ok(self.cancel_requests.load(Ordering::Acquire)),
        }
    }

    /// Request cancellation, as `asyncio.Task.cancel` does: `CancelledError`
    /// is raised in the handler at its current or next await.
    #[pyo3(signature = (msg=None))]
    fn cancel(&self, python: Python<'_>, msg: Option<Bound<'_, PyAny>>) -> PyResult<bool> {
        match self.standing(python) {
            TaskStanding::Finished => Ok(false),
            TaskStanding::Real(real) => real
                .call_method1(intern!(python, "cancel"), (msg,))?
                .extract(),
            TaskStanding::OwnStep(key) => {
                // Thrown at the handler's next await, by its own step.
                self.cancel_requests.fetch_add(1, Ordering::AcqRel);
                Ok(drive::note_cancel(key, msg.map(Bound::unbind), true))
            }
            standing @ (TaskStanding::Suspended(_) | TaskStanding::Foreign(_)) => {
                // Never stepped from here: the caller is a loop callback, or
                // another thread. The runner throws on its next drain.
                self.cancel_requests.fetch_add(1, Ordering::AcqRel);
                let key = match standing {
                    TaskStanding::Suspended(key) => {
                        // On the handler's thread: the message can be left
                        // with the coroutine for that drain.
                        drive::note_cancel(key, msg.map(Bound::unbind), false);
                        key
                    }
                    // From another thread the message stays behind: nothing
                    // Python crosses to the runner.
                    TaskStanding::Foreign(key) => key,
                    _ => return Ok(false),
                };
                let posted = self
                    .runner
                    .post(Message::Cancel(Work::new(move |python, fate| {
                        if fate == Fate::Run {
                            drive::cancel_drive(python, key, CancelReason::Task);
                        }
                    })));
                Ok(posted.is_ok())
            }
        }
    }

    fn uncancel(&self, python: Python<'_>) -> PyResult<usize> {
        if let Some(real) = self.real_task(python) {
            return real.call_method0(intern!(python, "uncancel"))?.extract();
        }
        // A compare-exchange loop, not `fetch_update`: newer toolchains
        // deprecate that name and its replacement is past the MSRV.
        let mut before = self.cancel_requests.load(Ordering::Acquire);
        loop {
            match self.cancel_requests.compare_exchange_weak(
                before,
                before.saturating_sub(1),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(current) => before = current,
            }
        }
        let left = before.saturating_sub(1);
        if left == 0 && std::thread::current().id() == self.owner {
            // As a task does: a cancellation not yet delivered is taken back.
            if let Some(key) = self.key() {
                drive::withdraw_cancel(key);
            }
        }
        Ok(left)
    }

    #[pyo3(signature = (callback, *, context=None))]
    fn add_done_callback(
        slf: &Bound<'_, Self>,
        callback: Bound<'_, PyAny>,
        context: Option<Bound<'_, PyAny>>,
    ) -> PyResult<()> {
        let python = slf.py();
        let this = slf.get();
        let kwargs = pyo3::types::PyDict::new(python);
        kwargs.set_item(intern!(python, "context"), context)?;
        if matches!(this.standing(python), TaskStanding::Finished) {
            // A finished task calls back soon, on its loop.
            this.event_loop.bind(python).call_method(
                intern!(python, "call_soon_threadsafe"),
                (callback, slf),
                Some(&kwargs),
            )?;
            return Ok(());
        }
        this.real(python)?.call_method(
            intern!(python, "add_done_callback"),
            (callback,),
            Some(&kwargs),
        )?;
        Ok(())
    }

    fn __await__<'py>(&self, python: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        self.real(python)?
            .call_method0(intern!(python, "__await__"))
    }

    /// `result`, `exception`, `remove_done_callback` and the rest are a real
    /// task's.
    fn __getattr__<'py>(&self, python: Python<'py>, name: &str) -> PyResult<Bound<'py, PyAny>> {
        if name.starts_with("__") {
            return Err(PyAttributeError::new_err(name.to_string()));
        }
        self.real(python)?.getattr(name)
    }

    /// Show the collector what the task holds. Called with the world stopped:
    /// it must not wait for a lock a stopped thread may hold.
    fn __traverse__(&self, visit: pyo3::PyVisit<'_>) -> Result<(), pyo3::PyTraverseError> {
        for slot in [&self.real, &self.name] {
            let held = match slot.try_lock() {
                Ok(held) => held,
                Err(std::sync::TryLockError::Poisoned(poison)) => poison.into_inner(),
                Err(std::sync::TryLockError::WouldBlock) => continue,
            };
            if let Some(held) = held.as_ref() {
                visit.call(held)?;
            }
        }
        Ok(())
    }

    /// Let go of what [`Self::__traverse__`] showed: the task is garbage.
    fn __clear__(&self) {
        for slot in [&self.real, &self.name] {
            let released = match slot.try_lock() {
                Ok(mut held) => held.take(),
                Err(std::sync::TryLockError::Poisoned(poison)) => poison.into_inner().take(),
                Err(std::sync::TryLockError::WouldBlock) => None,
            };
            // Dropped with the lock released: a decref can run a finaliser.
            drop(released);
        }
    }

    fn __repr__(slf: &Bound<'_, Self>) -> String {
        format!("<SiphonHandlerTask at {:#x}>", slf.as_ptr() as usize)
    }
}

/// The coroutine a hand-over's real task runs: the handler's coroutine,
/// picked up where the runner left it.
///
/// Its first step replays what the last direct step produced; every later one
/// forwards. Each runs with the handler's [`DirectTask`] as the current task,
/// so `asyncio.current_task()` is the same object before and after.
#[pyclass(frozen)]
pub(super) struct HandoverCoroutine {
    key: DriveKey,
    /// Dropped when the coroutine finishes: it leads back to the real task,
    /// which holds this, and nothing the collector can see breaks that ring.
    task: Mutex<Option<Py<DirectTask>>>,
    coroutine: Py<PyAny>,
    event_loop: Py<PyAny>,
}

enum Resume<'py> {
    Send(Bound<'py, PyAny>),
    Throw(Bound<'py, PyAny>),
}

impl HandoverCoroutine {
    pub(super) fn new(
        key: DriveKey,
        coroutine: Py<PyAny>,
        event_loop: Py<PyAny>,
        task: Py<DirectTask>,
    ) -> Self {
        Self {
            key,
            task: Mutex::new(Some(task)),
            coroutine,
            event_loop,
        }
    }

    fn advance(&self, python: Python<'_>, resume: Resume<'_>) -> PyResult<Py<PyAny>> {
        let helpers = helpers(python)
            .ok_or_else(|| PyRuntimeError::new_err("the direct-dispatch helpers are missing"))?;
        let task = locked(&self.task)
            .as_ref()
            .map(|task| task.clone_ref(python));
        let Some(task) = task else {
            return Err(PyRuntimeError::new_err(
                "cannot reuse already awaited coroutine",
            ));
        };
        let swap_task = helpers.swap_current_task.bind(python);
        let previous = swap_task.call1((&self.event_loop, task))?;
        let advanced = self.advance_as_task(python, resume);
        let restored = swap_task.call1((&self.event_loop, previous));
        if advanced.is_err() {
            // Finished, by return or by raise.
            let finished = locked(&self.task).take();
            drop(finished);
        }
        restored?;
        advanced
    }

    fn advance_as_task(&self, python: Python<'_>, resume: Resume<'_>) -> PyResult<Py<PyAny>> {
        let coroutine = self.coroutine.bind(python);
        let first = drive::take_first(self.key);
        match (first, resume) {
            (None, Resume::Send(value)) => coroutine
                .call_method1(intern!(python, "send"), (value,))
                .map(Bound::unbind),
            (None, Resume::Throw(exception)) => coroutine
                .call_method1(intern!(python, "throw"), (exception,))
                .map(Bound::unbind),
            (Some(First::Yielded(yielded)), Resume::Send(_)) => {
                let yielded = yielded.into_bound(python);
                match yielded.cast::<SiphonAwaitable>() {
                    // The coroutine is suspended on a siphon awaitable: the
                    // task waits for it as a future on this loop.
                    Ok(awaitable) => {
                        let future = SiphonAwaitable::asyncio_future(
                            awaitable,
                            self.event_loop.bind(python),
                        )?;
                        future.setattr(intern!(python, "_asyncio_future_blocking"), true)?;
                        Ok(future.unbind())
                    }
                    Err(_) => Ok(yielded.unbind()),
                }
            }
            (Some(First::Yielded(yielded)), Resume::Throw(exception)) => {
                // Cancelled before its first step here: the exception goes in
                // at the await the coroutine is suspended on.
                if let Ok(awaitable) = yielded.bind(python).cast::<SiphonAwaitable>() {
                    awaitable.get().cancel_without_wake(python);
                }
                coroutine
                    .call_method1(intern!(python, "throw"), (exception,))
                    .map(Bound::unbind)
            }
            (Some(First::Finished(Ok(value))), Resume::Send(_)) => {
                Err(PyStopIteration::new_err((value,)))
            }
            // Cancelled between finishing and saying so: the task ends
            // cancelled, as asyncio's does.
            (Some(First::Finished(Ok(_))), Resume::Throw(exception)) => {
                Err(PyErr::from_value(exception))
            }
            (Some(First::Finished(Err(error))), _) => Err(error),
        }
    }
}

#[pymethods]
impl HandoverCoroutine {
    fn send(&self, python: Python<'_>, value: Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
        self.advance(python, Resume::Send(value))
    }

    #[pyo3(signature = (exception, value=None, traceback=None))]
    fn throw(
        &self,
        python: Python<'_>,
        exception: Bound<'_, PyAny>,
        value: Option<Bound<'_, PyAny>>,
        traceback: Option<Bound<'_, PyAny>>,
    ) -> PyResult<Py<PyAny>> {
        // asyncio throws an exception instance; the two legacy arguments are
        // accepted for the coroutine protocol's sake.
        let _ = (value, traceback);
        self.advance(python, Resume::Throw(exception))
    }

    fn close(&self, python: Python<'_>) -> PyResult<()> {
        let finished = locked(&self.task).take();
        drop(finished);
        self.coroutine
            .bind(python)
            .call_method0(intern!(python, "close"))?;
        Ok(())
    }

    fn __await__(slf: Bound<'_, Self>) -> Bound<'_, Self> {
        slf
    }

    fn __iter__(slf: Bound<'_, Self>) -> Bound<'_, Self> {
        slf
    }

    fn __next__(&self, python: Python<'_>) -> PyResult<Py<PyAny>> {
        self.advance(python, Resume::Send(python.None().into_bound(python)))
    }

    /// What `asyncio` reads to name the task's coroutine.
    #[getter]
    fn __qualname__(&self, python: Python<'_>) -> Py<PyAny> {
        self.coroutine
            .bind(python)
            .getattr(intern!(python, "__qualname__"))
            .map(Bound::unbind)
            .unwrap_or_else(|_| python.None())
    }

    #[getter]
    fn __name__(&self, python: Python<'_>) -> Py<PyAny> {
        self.coroutine
            .bind(python)
            .getattr(intern!(python, "__name__"))
            .map(Bound::unbind)
            .unwrap_or_else(|_| python.None())
    }

    /// Show the collector the ring through the handler's task and coroutine.
    /// Called with the world stopped: it must not wait for a lock.
    fn __traverse__(&self, visit: pyo3::PyVisit<'_>) -> Result<(), pyo3::PyTraverseError> {
        visit.call(&self.coroutine)?;
        let task = match self.task.try_lock() {
            Ok(task) => task,
            Err(std::sync::TryLockError::Poisoned(poison)) => poison.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => return Ok(()),
        };
        if let Some(task) = task.as_ref() {
            visit.call(task)?;
        }
        Ok(())
    }

    fn __clear__(&self) {
        let released = match self.task.try_lock() {
            Ok(mut task) => task.take(),
            Err(std::sync::TryLockError::Poisoned(poison)) => poison.into_inner().take(),
            Err(std::sync::TryLockError::WouldBlock) => None,
        };
        drop(released);
    }
}

/// Done-callback of the real task a handler runs as: its outcome goes to the
/// handler's waiter and its slab entry is released. Runs on the loop thread.
#[pyclass(frozen)]
pub(super) struct HandoverDone {
    key: DriveKey,
}

impl HandoverDone {
    pub(super) fn new(key: DriveKey) -> Self {
        Self { key }
    }
}

#[pymethods]
impl HandoverDone {
    #[pyo3(signature = (future, /))]
    fn __call__(&self, python: Python<'_>, future: &Bound<'_, PyAny>) {
        let result = match future.call_method0(intern!(python, "exception")) {
            Ok(exception) if exception.is_none() => future
                .call_method0(intern!(python, "result"))
                .map(Bound::unbind),
            // A `BaseException` instance.
            Ok(exception) => Err(PyErr::from_value(exception)),
            // Cancelled: `exception()` raises the `CancelledError`.
            Err(error) => Err(error),
        };
        drive::finish(python, self.key, result);
    }
}
