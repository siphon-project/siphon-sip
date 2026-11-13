//! The task asyncio sees for a directly driven handler, and the coroutine
//! that carries the handler over to a real one.

use std::sync::{Arc, Mutex, OnceLock, Weak};

use pyo3::exceptions::{PyAttributeError, PyRuntimeError, PyStopIteration};
use pyo3::intern;
use pyo3::prelude::*;

use super::awaitable::SiphonAwaitable;
use super::python::helpers;
use super::{active_drive, locked, Drive, First, Phase};

/// `asyncio.current_task()` for a directly driven handler, for its whole
/// life: in the executor's steps and, after a hand-over, in the driver's.
///
/// While the handler has not asked it for anything a real task must answer,
/// it answers the cheap questions itself (`get_name()`, which `logging` asks
/// for every record; `done()`; `cancelling()`). The first other use, in a
/// step, creates the real `asyncio.Task` and every attribute is that task's
/// from then on.
#[pyclass(frozen, weakref, name = "SiphonHandlerTask")]
pub(crate) struct DirectTask {
    pub(super) drive: OnceLock<Weak<Drive>>,
    pub(super) real: OnceLock<Py<PyAny>>,
    pub(super) event_loop: Py<PyAny>,
    pub(super) name: Mutex<Option<Py<PyAny>>>,
}

/// Where a [`DirectTask`] stands when something is asked of it.
enum TaskStanding<'py> {
    /// A real asyncio task answers.
    Real(Bound<'py, PyAny>),
    /// The handler asks from its own step: a real task can be made now.
    OwnStep(Arc<Drive>),
    /// The handler is running or suspended, driven by siphon, and the caller
    /// is something else.
    Elsewhere(Arc<Drive>),
    /// The handler finished without ever needing a real task.
    Finished,
}

impl DirectTask {
    fn drive(&self) -> Option<Arc<Drive>> {
        self.drive.get().and_then(Weak::upgrade)
    }

    fn standing<'py>(&self, python: Python<'py>) -> TaskStanding<'py> {
        if let Some(real) = self.real.get() {
            return TaskStanding::Real(real.bind(python).clone());
        }
        let Some(drive) = self.drive() else {
            return TaskStanding::Finished;
        };
        if matches!(locked(&drive.state).phase, Phase::Done) {
            return TaskStanding::Finished;
        }
        match active_drive() {
            Some(active) if Arc::ptr_eq(&drive, &active) => TaskStanding::OwnStep(drive),
            _ => TaskStanding::Elsewhere(drive),
        }
    }

    /// The real task, created now if this is the handler's own step.
    fn real<'py>(&self, python: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        match self.standing(python) {
            TaskStanding::Real(real) => Ok(real),
            TaskStanding::OwnStep(drive) => {
                drive.materialise(python)?;
                self.real
                    .get()
                    .map(|real| real.bind(python).clone())
                    .ok_or_else(|| PyRuntimeError::new_err("the asyncio task was not created"))
            }
            TaskStanding::Elsewhere(_) | TaskStanding::Finished => Err(PyRuntimeError::new_err(
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
        if let Some(real) = this.real.get() {
            return Ok(real
                .bind(python)
                .call_method0(intern!(python, "get_name"))?
                .unbind());
        }
        if let Some(name) = locked(&this.name).as_ref() {
            return Ok(name.clone_ref(python));
        }
        // Unique while the task lives, at no cost to a handler that never
        // asks.
        Ok(format!("siphon-handler-{:x}", slf.as_ptr() as usize)
            .into_pyobject(python)?
            .into_any()
            .unbind())
    }

    fn set_name(&self, python: Python<'_>, value: Bound<'_, PyAny>) -> PyResult<()> {
        if let Some(real) = self.real.get() {
            real.bind(python)
                .call_method1(intern!(python, "set_name"), (value,))?;
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
        match self.drive() {
            Some(drive) => drive.coroutine.clone_ref(python),
            None => python.None(),
        }
    }

    fn get_context(&self, python: Python<'_>) -> PyResult<Py<PyAny>> {
        match self.drive() {
            Some(drive) => Ok(drive.context.clone_ref(python)),
            None => Ok(self
                .real(python)?
                .call_method0(intern!(python, "get_context"))?
                .unbind()),
        }
    }

    fn done(&self, python: Python<'_>) -> PyResult<bool> {
        if let Some(real) = self.real.get() {
            return real
                .bind(python)
                .call_method0(intern!(python, "done"))?
                .extract();
        }
        Ok(match self.drive() {
            Some(drive) => matches!(locked(&drive.state).phase, Phase::Done),
            None => true,
        })
    }

    fn cancelled(&self, python: Python<'_>) -> PyResult<bool> {
        match self.real.get() {
            Some(real) => real
                .bind(python)
                .call_method0(intern!(python, "cancelled"))?
                .extract(),
            None => Ok(false),
        }
    }

    fn cancelling(&self, python: Python<'_>) -> PyResult<usize> {
        match self.real.get() {
            Some(real) => real
                .bind(python)
                .call_method0(intern!(python, "cancelling"))?
                .extract(),
            None => Ok(0),
        }
    }

    /// Request cancellation, as `asyncio.Task.cancel` does: `CancelledError`
    /// is raised in the handler at its current or next await.
    #[pyo3(signature = (msg=None))]
    fn cancel(&self, python: Python<'_>, msg: Option<Bound<'_, PyAny>>) -> PyResult<bool> {
        let real = match self.standing(python) {
            TaskStanding::Finished => return Ok(false),
            // Not this thread's step: the coroutine is cancelled where it is,
            // without a task.
            TaskStanding::Elsewhere(drive) => return Ok(drive.cancel(python)),
            TaskStanding::Real(real) => real,
            TaskStanding::OwnStep(_) => self.real(python)?,
        };
        real.call_method1(intern!(python, "cancel"), (msg,))?
            .extract()
    }

    fn uncancel(&self, python: Python<'_>) -> PyResult<usize> {
        match self.real.get() {
            Some(real) => real
                .bind(python)
                .call_method0(intern!(python, "uncancel"))?
                .extract(),
            // A cancellation that counts creates the real task first.
            None => Ok(0),
        }
    }

    #[pyo3(signature = (callback, *, context=None))]
    fn add_done_callback(
        slf: &Bound<'_, Self>,
        callback: Bound<'_, PyAny>,
        context: Option<Bound<'_, PyAny>>,
    ) -> PyResult<()> {
        let python = slf.py();
        let this = slf.get();
        if matches!(this.standing(python), TaskStanding::Finished) {
            // A finished task calls back soon, on its loop.
            let kwargs = pyo3::types::PyDict::new(python);
            kwargs.set_item(intern!(python, "context"), context)?;
            this.event_loop.bind(python).call_method(
                intern!(python, "call_soon_threadsafe"),
                (callback, slf),
                Some(&kwargs),
            )?;
            return Ok(());
        }
        let kwargs = pyo3::types::PyDict::new(python);
        kwargs.set_item(intern!(python, "context"), context)?;
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

    fn __repr__(slf: &Bound<'_, Self>) -> String {
        format!("<SiphonHandlerTask at {:#x}>", slf.as_ptr() as usize)
    }
}

/// The coroutine a hand-over's real task runs: the handler's coroutine,
/// picked up where the executor left it.
///
/// Its first step replays what the last direct step produced; every later one
/// forwards. Each runs with the handler's [`DirectTask`] as the current task,
/// so `asyncio.current_task()` is the same object before and after.
#[pyclass(frozen)]
pub(super) struct HandoverCoroutine {
    /// Dropped when the coroutine finishes: both lead back to the real task,
    /// which holds this, and nothing the collector can see breaks that ring.
    pub(super) live: Mutex<Option<HandoverLive>>,
    pub(super) coroutine: Py<PyAny>,
    pub(super) event_loop: Py<PyAny>,
}

pub(super) struct HandoverLive {
    pub(super) drive: Arc<Drive>,
    pub(super) task: Py<DirectTask>,
}

enum Resume<'py> {
    Send(Bound<'py, PyAny>),
    Throw(Bound<'py, PyAny>),
}

impl HandoverCoroutine {
    fn advance(&self, python: Python<'_>, resume: Resume<'_>) -> PyResult<Py<PyAny>> {
        let helpers = helpers(python)
            .ok_or_else(|| PyRuntimeError::new_err("the direct-dispatch helpers are missing"))?;
        let Some((drive, task)) = locked(&self.live)
            .as_ref()
            .map(|live| (Arc::clone(&live.drive), live.task.clone_ref(python)))
        else {
            return Err(PyRuntimeError::new_err(
                "cannot reuse already awaited coroutine",
            ));
        };
        let swap_task = helpers.swap_current_task.bind(python);
        let previous = swap_task.call1((&self.event_loop, task))?;
        let advanced = self.advance_as_task(python, &drive, resume);
        let restored = swap_task.call1((&self.event_loop, previous));
        if advanced.is_err() {
            // Finished, by return or by raise.
            let finished = locked(&self.live).take();
            drop(finished);
        }
        restored?;
        advanced
    }

    fn advance_as_task(
        &self,
        python: Python<'_>,
        drive: &Drive,
        resume: Resume<'_>,
    ) -> PyResult<Py<PyAny>> {
        let coroutine = self.coroutine.bind(python);
        let first = drive.take_first();
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
                        let future = awaitable
                            .get()
                            .shared
                            .asyncio_future(python, self.event_loop.bind(python))?;
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
                    awaitable.get().shared.cancel(python);
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
        let finished = locked(&self.live).take();
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
}
