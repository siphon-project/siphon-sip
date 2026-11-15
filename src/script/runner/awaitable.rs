//! What an awaitable script API returns inside a directly driven handler.
//!
//! The Rust future runs on tokio and knows its awaitable only by a number.
//! When it finishes, the worker posts a wake to the runner that owns the
//! awaitable and is done: it never attaches. The runner builds the Python
//! value, on its own thread, and resumes whatever waits.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::ThreadId;

use futures_util::FutureExt;
use pyo3::exceptions::{PyAttributeError, PyRuntimeError, PyStopIteration};
use pyo3::intern;
use pyo3::prelude::*;
use tracing::debug;

use super::drive::{self, locked, DriveKey};
use super::python::{cancelled_error, helpers, invalid_state};
use super::{Fate, Message, RunnerShared, Work};

/// Builds an awaitable's Python result, attached.
pub type BuildValue = Box<dyn for<'py> FnOnce(Python<'py>) -> PyResult<Py<PyAny>> + Send>;

/// An awaitable's Rust future, type-erased once by its caller.
pub type AwaitableFuture = Pin<Box<dyn Future<Output = BuildValue> + Send>>;

enum State {
    Pending,
    /// The value, or the exception instance. Kept as plain references, not a
    /// `PyErr`, so the collector can be shown them (`__traverse__`).
    Done(Result<Py<PyAny>, Py<PyAny>>),
    Cancelled,
}

/// An asyncio future standing in for the awaitable on one event loop.
struct Bridge {
    event_loop: Py<PyAny>,
    future: Py<PyAny>,
}

impl Bridge {
    fn clone_ref(&self, python: Python<'_>) -> Self {
        Self {
            event_loop: self.event_loop.clone_ref(python),
            future: self.future.clone_ref(python),
        }
    }
}

/// What the runner resumes when an awaitable finishes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Waiter {
    /// The directly driven coroutine suspended on it.
    Drive(DriveKey),
    /// The gather it is argument `index` of.
    Gather { gather: u64, index: usize },
}

struct Inner {
    state: State,
    waiter: Option<Waiter>,
    bridges: Vec<Bridge>,
}

/// What registering a coroutine as an awaitable's waiter came to.
pub(super) enum Registered {
    /// It will be woken when the awaitable finishes.
    Waiting,
    /// The awaitable finished first: resume now.
    Finished,
    /// Another coroutine waits on it already, or it belongs to another
    /// driver thread.
    Elsewhere,
}

/// What a script gets from an awaitable API called in a directly driven
/// handler.
///
/// Awaited from a direct step, it yields itself and the runner resumes the
/// coroutine when the Rust future finishes. Anywhere else (a task on a loop,
/// `asyncio.gather`, `wait_for`, a done callback) it is an `asyncio.Future`:
/// awaiting it there awaits one made for that loop, and every attribute it
/// does not have is that future's.
///
/// Its state changes on the driver thread that made it. The mutex is there
/// because nothing stops a script from handing the object to another thread;
/// no Python runs while it is held.
#[pyclass(frozen, weakref, name = "SiphonAwaitable")]
pub(crate) struct SiphonAwaitable {
    id: u64,
    owner: ThreadId,
    runner: Arc<RunnerShared>,
    /// The owner's event loop.
    event_loop: Py<PyAny>,
    inner: Mutex<Inner>,
    /// Aborts the Rust future.
    abort: OnceLock<tokio::task::AbortHandle>,
}

impl SiphonAwaitable {
    pub(super) fn id(&self) -> u64 {
        self.id
    }

    fn on_owner_thread(&self) -> bool {
        std::thread::current().id() == self.owner
    }

    /// Record coroutine `key` as the one to wake.
    pub(super) fn register(&self, key: DriveKey) -> Registered {
        if !self.on_owner_thread() {
            return Registered::Elsewhere;
        }
        let mut inner = locked(&self.inner);
        if !matches!(inner.state, State::Pending) {
            return Registered::Finished;
        }
        if inner.waiter.is_some() {
            return Registered::Elsewhere;
        }
        inner.waiter = Some(Waiter::Drive(key));
        Registered::Waiting
    }

    pub(super) fn forget_waiter(&self, key: DriveKey) {
        let mut inner = locked(&self.inner);
        if inner.waiter == Some(Waiter::Drive(key)) {
            inner.waiter = None;
        }
    }

    /// Record gather `gather` as the one to tell, as its argument `index`.
    pub(super) fn register_gather(&self, gather: u64, index: usize) -> Registered {
        if !self.on_owner_thread() {
            return Registered::Elsewhere;
        }
        let mut inner = locked(&self.inner);
        if !matches!(inner.state, State::Pending) {
            return Registered::Finished;
        }
        if inner.waiter.is_some() {
            return Registered::Elsewhere;
        }
        inner.waiter = Some(Waiter::Gather { gather, index });
        Registered::Waiting
    }

    /// Gather `gather` no longer wants to hear of this awaitable.
    pub(super) fn forget_gather(&self, gather: u64) {
        let mut inner = locked(&self.inner);
        if matches!(inner.waiter, Some(Waiter::Gather { gather: waiting, .. }) if waiting == gather)
        {
            inner.waiter = None;
        }
    }

    /// The Rust future finished: build its value and settle everything that
    /// waits. Runs on the owner thread, attached. Returns what to resume.
    pub(super) fn settle(&self, python: Python<'_>, build: BuildValue) -> Option<Waiter> {
        // The conversion is Python (a `Deferred` builds a value), so it runs
        // before the lock is taken. A panic in it must still wake the waiter.
        let built = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| build(python)))
            .unwrap_or_else(|_panic| {
                Err(PyRuntimeError::new_err(
                    "building the awaitable's result panicked",
                ))
            });
        let (ok, value) = match built {
            Ok(value) => (true, value),
            Err(error) => (false, error.into_value(python).into_any()),
        };
        let stored = if ok {
            Ok(value.clone_ref(python))
        } else {
            Err(value.clone_ref(python))
        };
        let mut stored = Some(stored);
        let settled = {
            let mut inner = locked(&self.inner);
            if matches!(inner.state, State::Pending) {
                if let Some(stored) = stored.take() {
                    inner.state = State::Done(stored);
                }
                let bridges: Vec<Bridge> = inner
                    .bridges
                    .iter()
                    .map(|bridge| bridge.clone_ref(python))
                    .collect();
                Some((inner.waiter.take(), bridges))
            } else {
                None
            }
        };
        // Cancelled while the future was finishing: the value goes unused.
        drop(stored);
        let (waiter, bridges) = settled?;
        if !bridges.is_empty() {
            self.settle_bridges(python, &bridges, ok, &value);
        }
        waiter
    }

    /// Settle the asyncio futures standing in for this awaitable: in place on
    /// the owner's loop, through `call_soon_threadsafe` on any other.
    fn settle_bridges(&self, python: Python<'_>, bridges: &[Bridge], ok: bool, value: &Py<PyAny>) {
        let Some(helpers) = helpers(python) else {
            return;
        };
        for bridge in bridges {
            let settled = if bridge
                .event_loop
                .bind(python)
                .is(self.event_loop.bind(python))
            {
                helpers
                    .settle
                    .bind(python)
                    .call1((&bridge.future, ok, value))
                    .map(drop)
            } else {
                bridge
                    .event_loop
                    .bind(python)
                    .call_method1(
                        intern!(python, "call_soon_threadsafe"),
                        (&helpers.settle, &bridge.future, ok, value),
                    )
                    .map(drop)
            };
            if let Err(error) = settled {
                // The loop is closed: nothing is left to await it.
                debug!(%error, "could not settle an awaitable's asyncio future");
            }
        }
    }

    /// The awaitable's result.
    pub(super) fn result(&self, python: Python<'_>) -> PyResult<Py<PyAny>> {
        enum Read {
            Value(Py<PyAny>),
            Raised(Py<PyAny>),
            Cancelled,
            Pending,
        }
        let read = {
            let inner = locked(&self.inner);
            match &inner.state {
                State::Done(Ok(value)) => Read::Value(value.clone_ref(python)),
                State::Done(Err(raised)) => Read::Raised(raised.clone_ref(python)),
                State::Cancelled => Read::Cancelled,
                State::Pending => Read::Pending,
            }
        };
        // Making an exception is Python: done with the lock released.
        match read {
            Read::Value(value) => Ok(value),
            Read::Raised(raised) => Err(PyErr::from_value(raised.into_bound(python))),
            Read::Cancelled => Err(cancelled_error(python)),
            Read::Pending => Err(invalid_state(python)),
        }
    }

    fn finished(&self) -> bool {
        !matches!(locked(&self.inner).state, State::Pending)
    }

    /// Mark the awaitable cancelled and drop its Rust future. `None` if it
    /// had finished; otherwise what waited on it.
    fn cancel_inner(&self, python: Python<'_>) -> Option<Option<Waiter>> {
        let (waiter, bridges) = {
            let mut inner = locked(&self.inner);
            if !matches!(inner.state, State::Pending) {
                return None;
            }
            inner.state = State::Cancelled;
            let bridges: Vec<Bridge> = inner
                .bridges
                .iter()
                .map(|bridge| bridge.clone_ref(python))
                .collect();
            (inner.waiter.take(), bridges)
        };
        if let Some(abort) = self.abort.get() {
            abort.abort();
        }
        // Its future will never post a wake: stop tracking it here. If it is
        // a gather's, what the gather still runs is cancelled with it.
        if self.on_owner_thread() {
            drop(drive::untrack_awaitable(self.id));
            super::gather::cancel(python, self.id);
        } else {
            let id = self.id;
            let _ = self
                .runner
                .post(Message::Cancel(Work::new(move |python, fate| {
                    if fate == Fate::Run {
                        drop(drive::untrack_awaitable(id));
                        super::gather::cancel(python, id);
                    }
                })));
        }
        for bridge in bridges {
            let cancel = bridge
                .future
                .bind(python)
                .getattr(intern!(python, "cancel"));
            let scheduled = cancel.and_then(|cancel| {
                bridge
                    .event_loop
                    .bind(python)
                    .call_method1(intern!(python, "call_soon_threadsafe"), (cancel,))
            });
            if let Err(error) = scheduled {
                debug!(%error, "could not cancel an awaitable's asyncio future");
            }
        }
        Some(waiter)
    }

    /// Cancel the awaitable: its Rust future is dropped and whatever waits on
    /// it is woken with `CancelledError`. `false` if it had finished.
    pub(super) fn cancel(&self, python: Python<'_>) -> bool {
        let Some(waiter) = self.cancel_inner(python) else {
            return false;
        };
        if let Some(waiter) = waiter {
            self.post_cancelled(waiter);
        }
        true
    }

    /// Tell `waiter`, from the runner's next drain, that the awaitable it
    /// waited on was cancelled. Never resumed from here: the caller may be
    /// another coroutine's step.
    fn post_cancelled(&self, waiter: Waiter) {
        let id = self.id;
        let _ = self
            .runner
            .post(Message::Wake(Work::new(move |python, fate| {
                if fate != Fate::Run {
                    return;
                }
                match waiter {
                    // The resume raises.
                    Waiter::Drive(key) => drive::wake(python, key, id),
                    Waiter::Gather { gather, index } => super::gather::child_done(
                        python,
                        gather,
                        index,
                        Err(cancelled_error(python)),
                    ),
                }
            })));
    }

    /// [`Self::cancel`] for a caller that resumes the coroutine waiting on it
    /// itself. A gather that waited on it is still told.
    pub(super) fn cancel_without_wake(&self, python: Python<'_>) {
        if let Some(Some(waiter @ Waiter::Gather { .. })) = self.cancel_inner(python) {
            self.post_cancelled(waiter);
        }
    }

    /// The owner is closing: nothing will resume or settle this awaitable.
    pub(super) fn abandon(&self, python: Python<'_>) {
        let released = {
            let mut inner = locked(&self.inner);
            if matches!(inner.state, State::Pending) {
                inner.state = State::Cancelled;
            }
            inner.waiter = None;
            std::mem::take(&mut inner.bridges)
        };
        if let Some(abort) = self.abort.get() {
            abort.abort();
        }
        let _ = python;
        drop(released);
    }

    /// Cancel the awaitable as its waiter's cancellation would.
    #[cfg(test)]
    pub(crate) fn cancel_for_test(&self, python: Python<'_>) -> bool {
        self.cancel(python)
    }

    /// The asyncio future standing in for this awaitable on `event_loop`,
    /// made on first use.
    pub(super) fn asyncio_future<'py>(
        slf: &Bound<'py, Self>,
        event_loop: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let python = slf.py();
        let this = slf.get();
        let existing = |inner: &Inner| {
            inner
                .bridges
                .iter()
                .find(|bridge| bridge.event_loop.bind(python).is(event_loop))
                .map(|bridge| bridge.future.clone_ref(python))
        };
        let found = existing(&locked(&this.inner));
        if let Some(future) = found {
            return Ok(future.into_bound(python));
        }
        let helpers = helpers(python)
            .ok_or_else(|| PyRuntimeError::new_err("the direct-dispatch helpers are missing"))?;
        let future = event_loop.call_method0(intern!(python, "create_future"))?;
        let bridge = Bridge {
            event_loop: event_loop.clone().unbind(),
            future: future.clone().unbind(),
        };
        let finished = {
            let mut inner = locked(&this.inner);
            inner.bridges.push(bridge);
            !matches!(inner.state, State::Pending)
        };
        if finished {
            // Nothing else has this future yet: settle it in place.
            let (ok, value, cancelled) = match this.result(python) {
                Ok(value) => (true, value, false),
                Err(error) if error.matches(python, &helpers.cancelled_error)? => {
                    (false, python.None(), true)
                }
                Err(error) => (false, error.into_value(python).into_any(), false),
            };
            helpers
                .settle_now
                .bind(python)
                .call1((&future, ok, value, cancelled))?;
        }
        // Cancelling the asyncio future cancels the awaitable, as it always
        // did: the Rust future is dropped.
        let hook = Py::new(
            python,
            CancelHook {
                awaitable: slf.clone().unbind(),
            },
        )?;
        future.call_method1(intern!(python, "add_done_callback"), (hook,))?;
        Ok(future)
    }

    /// The asyncio future for the loop running on this thread.
    fn future_here<'py>(slf: &Bound<'py, Self>) -> PyResult<Bound<'py, PyAny>> {
        let python = slf.py();
        let helpers = helpers(python)
            .ok_or_else(|| PyRuntimeError::new_err("the direct-dispatch helpers are missing"))?;
        let event_loop = helpers.get_running_loop.bind(python).call0()?;
        Self::asyncio_future(slf, &event_loop)
    }
}

/// Whether the coroutine awaiting right now is the one this thread's runner
/// is stepping, and not something else running inside its step (a task
/// started eagerly, say), which could not take the awaitable as a yield.
pub(super) fn awaited_by_the_step(python: Python<'_>) -> bool {
    let Some(task) = drive::active_task(python) else {
        return false;
    };
    let Some(helpers) = helpers(python) else {
        return false;
    };
    helpers
        .current_task
        .bind(python)
        .call0()
        .is_ok_and(|current| current.is(task.bind(python)))
}

/// Done-callback on an awaitable's asyncio future: a cancelled future cancels
/// the awaitable.
#[pyclass(frozen)]
struct CancelHook {
    awaitable: Py<SiphonAwaitable>,
}

#[pymethods]
impl CancelHook {
    fn __call__(&self, python: Python<'_>, future: &Bound<'_, PyAny>) -> PyResult<()> {
        if future
            .call_method0(intern!(python, "cancelled"))?
            .extract::<bool>()?
        {
            self.awaitable.get().cancel(python);
        }
        Ok(())
    }
}

#[pymethods]
impl SiphonAwaitable {
    fn __await__<'py>(slf: &Bound<'py, Self>) -> PyResult<Bound<'py, PyAny>> {
        if awaited_by_the_step(slf.py()) {
            return Ok(slf.clone().into_any());
        }
        Self::future_here(slf)?.call_method0(intern!(slf.py(), "__await__"))
    }

    fn __iter__(slf: Bound<'_, Self>) -> Bound<'_, Self> {
        slf
    }

    fn __next__(slf: &Bound<'_, Self>) -> PyResult<Py<PyAny>> {
        let python = slf.py();
        let this = slf.get();
        if this.finished() {
            let value = this.result(python)?;
            return Err(PyStopIteration::new_err((value,)));
        }
        // Pending: yield to the step, which waits for it. Anything else that
        // resumes a coroutine suspended here before it has finished did not
        // wait for it.
        if drive::in_direct_step() {
            return Ok(slf.clone().into_any().unbind());
        }
        Err(PyRuntimeError::new_err("await wasn't used with future"))
    }

    /// Everything else a script may do with what an awaitable API returned
    /// (`add_done_callback`, `cancel`, `done`, `result`, ...) is the asyncio
    /// future's.
    fn __getattr__<'py>(slf: &Bound<'py, Self>, name: &str) -> PyResult<Bound<'py, PyAny>> {
        // Protocol probes must not conjure a future: dunder lookups, and the
        // generator protocol, which the interpreter looks up on whatever a
        // coroutine is awaiting when something is thrown into the coroutine
        // or it is closed. A future has none of the three.
        if name.starts_with("__") || matches!(name, "throw" | "close" | "send") {
            return Err(PyAttributeError::new_err(name.to_string()));
        }
        Self::future_here(slf)?.getattr(name)
    }

    /// Show the collector what the awaitable holds. Called with the world
    /// stopped: it must not wait for a lock a stopped thread may hold.
    fn __traverse__(&self, visit: pyo3::PyVisit<'_>) -> Result<(), pyo3::PyTraverseError> {
        let inner = match self.inner.try_lock() {
            Ok(inner) => inner,
            Err(std::sync::TryLockError::Poisoned(poison)) => poison.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => return Ok(()),
        };
        if let State::Done(Ok(held) | Err(held)) = &inner.state {
            visit.call(held)?;
        }
        for bridge in &inner.bridges {
            visit.call(&bridge.event_loop)?;
            visit.call(&bridge.future)?;
        }
        Ok(())
    }

    /// Let go of what [`Self::__traverse__`] showed: the awaitable is garbage.
    fn __clear__(&self) {
        let released = {
            let mut inner = match self.inner.try_lock() {
                Ok(inner) => inner,
                Err(std::sync::TryLockError::Poisoned(poison)) => poison.into_inner(),
                Err(std::sync::TryLockError::WouldBlock) => return,
            };
            let state = if matches!(inner.state, State::Done(_)) {
                Some(std::mem::replace(&mut inner.state, State::Cancelled))
            } else {
                None
            };
            (state, std::mem::take(&mut inner.bridges))
        };
        // Dropped with the lock released: a decref can run a finaliser.
        drop(released);
    }

    fn __repr__(&self) -> String {
        let state = match locked(&self.inner).state {
            State::Pending => "pending",
            State::Cancelled => "cancelled",
            State::Done(_) => "finished",
        };
        format!("<SiphonAwaitable {state}>")
    }
}

/// An awaitable no Rust future stands behind: the runner settles it itself,
/// through [`drive::complete_awaitable`], or it is cancelled. Made on a
/// driver thread; `None` off one, or once the driver is shutting down.
pub(super) fn local_awaitable(python: Python<'_>) -> PyResult<Option<(Py<SiphonAwaitable>, u64)>> {
    let Some((id, runner, event_loop)) = drive::next_awaitable(python) else {
        return Ok(None);
    };
    let awaitable = Py::new(
        python,
        SiphonAwaitable {
            id,
            owner: std::thread::current().id(),
            runner,
            event_loop,
            inner: Mutex::new(Inner {
                state: State::Pending,
                waiter: None,
                bridges: Vec::new(),
            }),
            abort: OnceLock::new(),
        },
    )?;
    if !drive::track_awaitable(awaitable.clone_ref(python), id) {
        return Ok(None);
    }
    Ok(Some((awaitable, id)))
}

/// [`crate::script::blocking::awaitable`] for a caller inside a direct step:
/// run `future` on tokio, now, and hand back the object that resumes the
/// coroutine without asyncio.
///
/// Not generic, on purpose: every awaitable API in the crate comes through
/// here, and a generic body would be compiled once for each of them.
pub fn spawn_awaitable(python: Python<'_>, future: AwaitableFuture) -> PyResult<Bound<'_, PyAny>> {
    let Some((id, runner, event_loop)) = drive::next_awaitable(python) else {
        return Err(PyRuntimeError::new_err(
            "a siphon awaitable was made for a direct step off an asyncio driver thread",
        ));
    };
    let awaitable = Py::new(
        python,
        SiphonAwaitable {
            id,
            owner: std::thread::current().id(),
            runner: Arc::clone(&runner),
            event_loop,
            inner: Mutex::new(Inner {
                state: State::Pending,
                waiter: None,
                bridges: Vec::new(),
            }),
            abort: OnceLock::new(),
        },
    )?;
    if !drive::track_awaitable(awaitable.clone_ref(python), id) {
        return Err(PyRuntimeError::new_err(
            "the asyncio driver is shutting down",
        ));
    }
    let task = pyo3_async_runtimes::tokio::get_runtime().spawn(async move {
        // A panic in the future must still wake the coroutine.
        let build: BuildValue = match std::panic::AssertUnwindSafe(future).catch_unwind().await {
            Ok(build) => build,
            Err(_panic) => Box::new(|_python| Err(PyRuntimeError::new_err("rust future panicked"))),
        };
        // On a tokio worker: one push and, at most, one byte down a pipe.
        // Refused only by a runner that has shut down and closed the
        // coroutine itself.
        let _ = runner.post(Message::Wake(Work::new(move |python, fate| {
            drive::complete_awaitable(python, fate, id, build);
        })));
    });
    let _ = awaitable.get().abort.set(task.abort_handle());
    Ok(awaitable.into_bound(python).into_any())
}
