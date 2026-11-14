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

struct AwaitableInner {
    state: AwaitableState,
    /// The directly driven coroutine suspended on this awaitable.
    waiter: Option<Arc<Drive>>,
    bridges: Vec<Bridge>,
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
        let (waiter, bridged) = {
            let mut inner = locked(&self.inner);
            if !matches!(inner.state, AwaitableState::Pending) {
                // Cancelled while the future was finishing.
                return;
            }
            inner.state = AwaitableState::Ready(build);
            (inner.waiter.take(), !inner.bridges.is_empty())
        };
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
    fn result(&self, python: Python<'_>) -> PyResult<Py<PyAny>> {
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

    fn finished(&self) -> bool {
        !matches!(locked(&self.inner).state, AwaitableState::Pending)
    }

    /// Cancel the awaitable: its Rust future is dropped and whatever waits on
    /// it is woken with `CancelledError`. `false` if it had finished.
    pub(super) fn cancel(&self, python: Python<'_>) -> bool {
        let (waiter, futures) = {
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
            (inner.waiter.take(), futures)
        };
        if let Some(abort) = self.abort.get() {
            abort.abort();
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
