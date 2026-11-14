//! What an awaitable script API returns inside a directly driven handler.

use std::future::Future;
use std::sync::{Arc, Condvar, Mutex, OnceLock};

use futures_util::FutureExt;
use pyo3::exceptions::{PyAttributeError, PyRuntimeError, PyStopIteration};
use pyo3::intern;
use pyo3::prelude::*;
use tracing::debug;

use super::python::helpers;
use super::{in_direct_step, locked, Drive};

/// Builds an awaitable's Python result, attached.
type BuildValue = Box<dyn for<'py> FnOnce(Python<'py>) -> PyResult<Py<PyAny>> + Send>;

enum AwaitableState {
    Pending,
    /// The future finished; its value is not converted yet.
    Ready(BuildValue),
    /// A thread is converting the value.
    Converting,
    /// The value, or the exception instance. Kept as plain references, not a
    /// `PyErr`, so the collector can be shown them (`__traverse__`).
    Done(Result<Py<PyAny>, Py<PyAny>>),
    Cancelled,
}

/// What [`AwaitableShared::result`] found under the lock, to act on once the
/// lock is released: making an exception is Python, and Python is never run
/// with the lock held.
enum Read {
    Value(Py<PyAny>),
    Raised(Py<PyAny>),
    Cancelled,
    Pending,
    Converting,
    Build(BuildValue),
}

/// An asyncio future standing in for the awaitable on one event loop.
struct Bridge {
    event_loop: Py<PyAny>,
    future: Py<PyAny>,
}

/// Told, from whichever thread finishes or cancels the awaitable, that it
/// has. Touches no Python object: it only wakes something.
pub(super) type Watcher = Box<dyn FnOnce() + Send>;

/// What cancelling the awaitable also cancels (the background work behind a
/// spawn handle), run attached once the awaitable is cancelled.
pub(super) type OnCancel = Box<dyn for<'py> FnOnce(Python<'py>) + Send>;

struct AwaitableInner {
    state: AwaitableState,
    /// The directly driven coroutine suspended on this awaitable.
    waiter: Option<Arc<Drive>>,
    bridges: Vec<Bridge>,
    /// `tasks.wait_first` calls watching for this awaitable to finish, by the
    /// token each took out. Empty once it has finished.
    watchers: Vec<(u64, Watcher)>,
    on_cancel: Option<OnCancel>,
}

pub(super) struct AwaitableShared {
    inner: Mutex<AwaitableInner>,
    /// Signalled when a conversion finishes.
    converted: Condvar,
    /// Aborts the Rust future.
    abort: OnceLock<tokio::task::AbortHandle>,
}

/// What registering a coroutine as an awaitable's waiter came to.
pub(super) enum Registered {
    /// It will be woken when the awaitable finishes.
    Waiting,
    /// The awaitable finished first: resume now.
    Finished,
    /// Another coroutine is already waiting on it.
    Busy,
}

impl AwaitableShared {
    pub(super) fn register(&self, drive: &Arc<Drive>) -> Registered {
        let mut inner = locked(&self.inner);
        if !matches!(inner.state, AwaitableState::Pending) {
            return Registered::Finished;
        }
        if inner.waiter.is_some() {
            return Registered::Busy;
        }
        inner.waiter = Some(Arc::clone(drive));
        Registered::Waiting
    }

    /// The Rust future finished. Runs on a tokio worker: touches no Python
    /// object beyond moving references.
    async fn complete(self: Arc<Self>, build: BuildValue) {
        let (waiter, bridged, watchers, on_cancel) = {
            let mut inner = locked(&self.inner);
            if !matches!(inner.state, AwaitableState::Pending) {
                // Cancelled while the future was finishing.
                return;
            }
            inner.state = AwaitableState::Ready(build);
            (
                inner.waiter.take(),
                !inner.bridges.is_empty(),
                std::mem::take(&mut inner.watchers),
                inner.on_cancel.take(),
            )
        };
        // Finished: there is nothing left to cancel.
        drop(on_cancel);
        for (_token, watcher) in watchers {
            watcher();
        }
        if bridged {
            // The asyncio futures are settled attached, off the workers, on
            // the pinned completion threads.
            let shared = Arc::clone(&self);
            crate::script::completions::submit(Box::new(move || {
                Python::attach(|python| shared.settle_bridges(python));
            }));
        }
        if let Some(drive) = waiter {
            Drive::queue_step(drive).await;
        }
    }

    /// The awaitable's result, converting it on first use.
    pub(super) fn result(&self, python: Python<'_>) -> PyResult<Py<PyAny>> {
        loop {
            let read = {
                let mut inner = locked(&self.inner);
                match &inner.state {
                    AwaitableState::Done(Ok(value)) => Read::Value(value.clone_ref(python)),
                    AwaitableState::Done(Err(raised)) => Read::Raised(raised.clone_ref(python)),
                    AwaitableState::Cancelled => Read::Cancelled,
                    AwaitableState::Pending => Read::Pending,
                    AwaitableState::Converting => Read::Converting,
                    AwaitableState::Ready(_) => {
                        match std::mem::replace(&mut inner.state, AwaitableState::Converting) {
                            AwaitableState::Ready(build) => Read::Build(build),
                            // Just matched as `Ready` under this lock.
                            other => {
                                inner.state = other;
                                Read::Converting
                            }
                        }
                    }
                }
            };
            let build = match read {
                Read::Value(value) => return Ok(value),
                Read::Raised(raised) => return Err(PyErr::from_value(raised.into_bound(python))),
                Read::Cancelled => return Err(cancelled_error(python)),
                Read::Pending => return Err(invalid_state(python)),
                Read::Converting => {
                    // Another thread is converting: wait for it, released.
                    python.detach(|| {
                        let mut inner = locked(&self.inner);
                        while matches!(inner.state, AwaitableState::Converting) {
                            inner = self
                                .converted
                                .wait(inner)
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                        }
                    });
                    continue;
                }
                Read::Build(build) => build,
            };
            // The conversion is Python (a `Deferred` builds a value). A panic
            // in it must not leave the state at `Converting`, which another
            // thread may be waiting on.
            let built = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| build(python)))
                .unwrap_or_else(|_panic| {
                    Err(PyRuntimeError::new_err(
                        "building the awaitable's result panicked",
                    ))
                });
            let (stored, built) = match built {
                Ok(value) => (Ok(value.clone_ref(python)), Ok(value)),
                Err(error) => {
                    let raised = error.into_value(python).into_any();
                    (
                        Err(raised.clone_ref(python)),
                        Err(PyErr::from_value(raised.into_bound(python))),
                    )
                }
            };
            locked(&self.inner).state = AwaitableState::Done(stored);
            self.converted.notify_all();
            return built;
        }
    }

    /// Show the collector what the awaitable holds. Called with the world
    /// stopped: it must not wait for a lock a stopped thread may hold.
    fn traverse(&self, visit: &pyo3::PyVisit<'_>) -> Result<(), pyo3::PyTraverseError> {
        let inner = match self.inner.try_lock() {
            Ok(inner) => inner,
            Err(std::sync::TryLockError::Poisoned(poison)) => poison.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => return Ok(()),
        };
        if let AwaitableState::Done(Ok(held) | Err(held)) = &inner.state {
            visit.call(held)?;
        }
        for bridge in &inner.bridges {
            visit.call(&bridge.event_loop)?;
            visit.call(&bridge.future)?;
        }
        Ok(())
    }

    /// Let go of what [`Self::traverse`] showed: the awaitable is garbage.
    fn clear(&self) {
        let released = {
            let mut inner = match self.inner.try_lock() {
                Ok(inner) => inner,
                Err(std::sync::TryLockError::Poisoned(poison)) => poison.into_inner(),
                Err(std::sync::TryLockError::WouldBlock) => return,
            };
            let state = if matches!(inner.state, AwaitableState::Done(_)) {
                Some(std::mem::replace(
                    &mut inner.state,
                    AwaitableState::Cancelled,
                ))
            } else {
                None
            };
            (state, std::mem::take(&mut inner.bridges))
        };
        // Dropped with the lock released: a decref can run a finaliser.
        drop(released);
    }

    pub(super) fn finished(&self) -> bool {
        !matches!(locked(&self.inner).state, AwaitableState::Pending)
    }

    /// Call `watcher` once this awaitable has finished or been cancelled.
    /// `false`, with `watcher` dropped uncalled, if it already has: the caller
    /// acts on that itself.
    pub(super) fn watch(&self, token: u64, watcher: Watcher) -> bool {
        let mut inner = locked(&self.inner);
        if !matches!(inner.state, AwaitableState::Pending) {
            return false;
        }
        inner.watchers.push((token, watcher));
        true
    }

    /// Withdraw the watcher `token` took out, if it has not been called.
    pub(super) fn unwatch(&self, token: u64) {
        let removed = {
            let mut inner = locked(&self.inner);
            inner
                .watchers
                .iter()
                .position(|(held, _)| *held == token)
                .map(|index| inner.watchers.remove(index))
        };
        drop(removed);
    }

    /// Whether anything is waiting to be told how this awaitable ended: a
    /// coroutine awaiting it, an asyncio future standing in for it, or a
    /// watcher.
    pub(super) fn observed(&self) -> bool {
        let inner = locked(&self.inner);
        inner.waiter.is_some() || !inner.bridges.is_empty() || !inner.watchers.is_empty()
    }

    /// Have cancelling this awaitable also run `on_cancel`. Ignored if it has
    /// finished already.
    pub(super) fn set_on_cancel(&self, on_cancel: OnCancel) {
        let mut inner = locked(&self.inner);
        if matches!(inner.state, AwaitableState::Pending) {
            inner.on_cancel = Some(on_cancel);
        }
    }

    /// Watchers still registered, for the leak tests.
    #[cfg(test)]
    pub(super) fn watcher_count(&self) -> usize {
        locked(&self.inner).watchers.len()
    }

    /// Cancel the awaitable: its Rust future is dropped and whatever waits on
    /// it is woken with `CancelledError`. `false` if it had finished.
    pub(super) fn cancel(&self, python: Python<'_>) -> bool {
        let (waiter, futures, watchers, on_cancel) = {
            let mut inner = locked(&self.inner);
            if !matches!(inner.state, AwaitableState::Pending) {
                return false;
            }
            inner.state = AwaitableState::Cancelled;
            let futures: Vec<Bridge> = inner
                .bridges
                .iter()
                .map(|bridge| Bridge {
                    event_loop: bridge.event_loop.clone_ref(python),
                    future: bridge.future.clone_ref(python),
                })
                .collect();
            (
                inner.waiter.take(),
                futures,
                std::mem::take(&mut inner.watchers),
                inner.on_cancel.take(),
            )
        };
        if let Some(abort) = self.abort.get() {
            abort.abort();
        }
        if let Some(on_cancel) = on_cancel {
            on_cancel(python);
        }
        for (_token, watcher) in watchers {
            watcher();
        }
        for bridge in futures {
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
        if let Some(drive) = waiter {
            Drive::queue_step_from_sync(drive);
        }
        true
    }

    /// Settle every asyncio future standing in for this awaitable, each on
    /// its own loop.
    fn settle_bridges(&self, python: Python<'_>) {
        let Some(helpers) = helpers(python) else {
            return;
        };
        let (ok, value) = match self.result(python) {
            Ok(value) => (true, value),
            Err(error) => (false, error.into_value(python).into_any()),
        };
        let bridges: Vec<Bridge> = locked(&self.inner)
            .bridges
            .iter()
            .map(|bridge| Bridge {
                event_loop: bridge.event_loop.clone_ref(python),
                future: bridge.future.clone_ref(python),
            })
            .collect();
        for bridge in bridges {
            let scheduled = bridge.event_loop.bind(python).call_method1(
                intern!(python, "call_soon_threadsafe"),
                (&helpers.settle, &bridge.future, ok, &value),
            );
            if let Err(error) = scheduled {
                // The loop is closed: nothing is left to await it.
                debug!(%error, "could not settle an awaitable's asyncio future");
            }
        }
    }

    /// The asyncio future standing in for this awaitable on `event_loop`,
    /// made on first use.
    pub(super) fn asyncio_future<'py>(
        self: &Arc<Self>,
        python: Python<'py>,
        event_loop: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let existing = |inner: &AwaitableInner| {
            inner
                .bridges
                .iter()
                .find(|bridge| bridge.event_loop.bind(python).is(event_loop))
                .map(|bridge| bridge.future.clone_ref(python))
        };
        if let Some(future) = existing(&locked(&self.inner)) {
            return Ok(future.into_bound(python));
        }
        let helpers = helpers(python)
            .ok_or_else(|| PyRuntimeError::new_err("the direct-dispatch helpers are missing"))?;
        let future = event_loop.call_method0(intern!(python, "create_future"))?;
        let finished = {
            let mut inner = locked(&self.inner);
            if let Some(raced) = existing(&inner) {
                return Ok(raced.into_bound(python));
            }
            inner.bridges.push(Bridge {
                event_loop: event_loop.clone().unbind(),
                future: future.clone().unbind(),
            });
            !matches!(inner.state, AwaitableState::Pending)
        };
        if finished {
            // Nothing else has this future yet: settle it in place.
            let (ok, value, cancelled) = match self.result(python) {
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
                shared: Arc::clone(self),
            },
        )?;
        future.call_method1(intern!(python, "add_done_callback"), (hook,))?;
        Ok(future)
    }
}

pub(super) fn cancelled_error(python: Python<'_>) -> PyErr {
    match helpers(python) {
        Some(helpers) => match helpers.cancelled_error.bind(python).call0() {
            Ok(error) => PyErr::from_value(error),
            Err(error) => error,
        },
        None => PyRuntimeError::new_err("cancelled"),
    }
}

fn invalid_state(python: Python<'_>) -> PyErr {
    match helpers(python) {
        Some(helpers) => match helpers
            .invalid_state_error
            .bind(python)
            .call1(("Result is not set.",))
        {
            Ok(error) => PyErr::from_value(error),
            Err(error) => error,
        },
        None => PyRuntimeError::new_err("Result is not set."),
    }
}

/// Done-callback on an awaitable's asyncio future: a cancelled future cancels
/// the awaitable.
#[pyclass(frozen)]
struct CancelHook {
    shared: Arc<AwaitableShared>,
}

#[pymethods]
impl CancelHook {
    fn __call__(&self, python: Python<'_>, future: &Bound<'_, PyAny>) -> PyResult<()> {
        if future
            .call_method0(intern!(python, "cancelled"))?
            .extract::<bool>()?
        {
            self.shared.cancel(python);
        }
        Ok(())
    }
}

/// What a script gets from an awaitable API called in a directly driven
/// handler.
///
/// Awaited from a step, it yields itself and the executor resumes the
/// coroutine when the Rust future finishes. Anywhere else (a task on a driver
/// loop, `asyncio.gather`, `wait_for`, a done callback) it is an
/// `asyncio.Future`: awaiting it there awaits one made for that loop, and
/// every attribute it does not have is that future's.
#[pyclass(frozen, weakref, name = "SiphonAwaitable")]
pub(crate) struct SiphonAwaitable {
    pub(super) shared: Arc<AwaitableShared>,
}

impl SiphonAwaitable {
    /// Cancel the awaitable as its waiter's cancellation would.
    #[cfg(test)]
    pub(crate) fn cancel_for_test(&self, python: Python<'_>) -> bool {
        self.shared.cancel(python)
    }

    /// Watchers still registered on this awaitable.
    #[cfg(test)]
    pub(crate) fn watcher_count_for_test(&self) -> usize {
        self.shared.watcher_count()
    }

    /// The asyncio future for the loop running on this thread.
    fn future_here<'py>(&self, python: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let helpers = helpers(python)
            .ok_or_else(|| PyRuntimeError::new_err("the direct-dispatch helpers are missing"))?;
        let event_loop = helpers.get_running_loop.bind(python).call0()?;
        self.shared.asyncio_future(python, &event_loop)
    }
}

#[pymethods]
impl SiphonAwaitable {
    fn __await__<'py>(slf: &Bound<'py, Self>) -> PyResult<Bound<'py, PyAny>> {
        if in_direct_step() {
            return Ok(slf.clone().into_any());
        }
        slf.get()
            .future_here(slf.py())?
            .call_method0(intern!(slf.py(), "__await__"))
    }

    fn __iter__(slf: Bound<'_, Self>) -> Bound<'_, Self> {
        slf
    }

    fn __next__(slf: &Bound<'_, Self>) -> PyResult<Py<PyAny>> {
        let python = slf.py();
        let this = slf.get();
        if this.shared.finished() {
            let value = this.shared.result(python)?;
            return Err(PyStopIteration::new_err((value,)));
        }
        // Pending: yield to the step, which waits for it. Anything else that
        // resumes a coroutine suspended here before it has finished did not
        // wait for it.
        if in_direct_step() {
            return Ok(slf.clone().into_any().unbind());
        }
        Err(PyRuntimeError::new_err("await wasn't used with future"))
    }

    /// Cancel the awaitable (and, for a `tasks.spawn` handle, the background
    /// coroutine behind it). `False` if it had finished. Native, because the
    /// asyncio future's `cancel` schedules its callbacks on the loop and so
    /// takes the handler off the executor.
    #[pyo3(signature = (msg=None))]
    fn cancel(&self, python: Python<'_>, msg: Option<Py<PyAny>>) -> bool {
        let _ = msg;
        self.shared.cancel(python)
    }

    /// Whether the awaitable has finished, failed or been cancelled.
    fn done(&self) -> bool {
        self.shared.finished()
    }

    /// Whether the awaitable was cancelled.
    fn cancelled(&self) -> bool {
        matches!(locked(&self.shared.inner).state, AwaitableState::Cancelled)
    }

    /// The value, or raise the exception it ended with
    /// (`asyncio.InvalidStateError` while it is still running).
    fn result(&self, python: Python<'_>) -> PyResult<Py<PyAny>> {
        if !self.shared.finished() {
            return Err(invalid_state(python));
        }
        self.shared.result(python)
    }

    /// The exception it ended with, or `None`
    /// (`asyncio.InvalidStateError` while it is still running).
    fn exception(&self, python: Python<'_>) -> PyResult<Option<Py<PyAny>>> {
        if !self.shared.finished() {
            return Err(invalid_state(python));
        }
        match self.shared.result(python) {
            Ok(_) => Ok(None),
            Err(error) if self.cancelled() => Err(error),
            Err(error) => Ok(Some(error.into_value(python).into_any())),
        }
    }

    /// Everything else a script may do with what an awaitable API returned
    /// (`add_done_callback`, ...) is the asyncio future's.
    fn __getattr__<'py>(slf: &Bound<'py, Self>, name: &str) -> PyResult<Bound<'py, PyAny>> {
        // Protocol probes must not conjure a future: dunder lookups, and the
        // generator protocol, which the interpreter looks up on whatever a
        // coroutine is awaiting when something is thrown into the coroutine
        // or it is closed. A future has none of the three.
        if name.starts_with("__") || matches!(name, "throw" | "close" | "send") {
            return Err(PyAttributeError::new_err(name.to_string()));
        }
        slf.get().future_here(slf.py())?.getattr(name)
    }

    fn __traverse__(&self, visit: pyo3::PyVisit<'_>) -> Result<(), pyo3::PyTraverseError> {
        self.shared.traverse(&visit)
    }

    fn __clear__(&self) {
        self.shared.clear();
    }

    fn __repr__(&self) -> String {
        let state = match locked(&self.shared.inner).state {
            AwaitableState::Pending => "pending",
            AwaitableState::Cancelled => "cancelled",
            _ => "finished",
        };
        format!("<SiphonAwaitable {state}>")
    }
}

/// [`super::blocking::awaitable`] for a caller inside a direct step: run
/// `future` on tokio, now, and hand back the object that resumes the
/// coroutine without asyncio.
pub(crate) fn awaitable_in_step<'py, F, T>(
    python: Python<'py>,
    future: F,
) -> PyResult<Bound<'py, PyAny>>
where
    F: Future<Output = PyResult<T>> + Send + 'static,
    T: for<'a> IntoPyObject<'a> + Send + 'static,
{
    let shared = Arc::new(AwaitableShared {
        inner: Mutex::new(AwaitableInner {
            state: AwaitableState::Pending,
            waiter: None,
            bridges: Vec::new(),
            watchers: Vec::new(),
            on_cancel: None,
        }),
        converted: Condvar::new(),
        abort: OnceLock::new(),
    });
    let completing = Arc::clone(&shared);
    let task = pyo3_async_runtimes::tokio::get_runtime().spawn(async move {
        // A panic in the future must still wake the coroutine.
        let outcome = std::panic::AssertUnwindSafe(future).catch_unwind().await;
        let build: BuildValue = match outcome {
            Ok(Ok(value)) => Box::new(move |python| {
                use pyo3::IntoPyObjectExt;
                value.into_py_any(python)
            }),
            Ok(Err(error)) => Box::new(move |_python| Err(error)),
            Err(_panic) => Box::new(|_python| Err(PyRuntimeError::new_err("rust future panicked"))),
        };
        completing.complete(build).await;
    });
    let _ = shared.abort.set(task.abort_handle());
    let awaitable = Py::new(python, SiphonAwaitable { shared })?;
    Ok(awaitable.into_bound(python).into_any())
}
