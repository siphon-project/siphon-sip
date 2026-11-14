//! PyO3 wrapper for the `tasks` namespace: background work, and waiting for
//! the first of several awaitables, without asyncio.
//!
//! ```python
//! from siphon import tasks
//!
//! async def delete_session(session):
//!     release = tasks.spawn(release_resources(session))   # background work
//!     answered = tasks.event()                            # set by other code
//!     first = await tasks.wait_first(
//!         [release, answered.wait()], timeout=2.0,
//!     )
//!     if first.timed_out:
//!         log.warn("release still running, answering anyway")
//!     return "deleted"
//! ```
//!
//! Everything here stays on the executor-driven path of
//! `docs/handler-execution-model.md`: no asyncio task is made for the
//! background coroutine, the wait or the event while they use siphon's own
//! awaitables, and a coroutine that uses asyncio for anything else is handed
//! to an asyncio driver, intact, as a handler would be.

use std::sync::Arc;

use pyo3::exceptions::PyTimeoutError;
use pyo3::prelude::*;

use crate::script::direct::{EventCore, FirstOutcome};

/// The `tasks` namespace: `spawn`, `wait_first` and `event`.
#[pyclass(name = "TasksNamespace", frozen)]
#[derive(Default)]
pub struct PyTasksNamespace;

impl PyTasksNamespace {
    pub fn new() -> Self {
        Self
    }
}

#[pymethods]
impl PyTasksNamespace {
    /// Start `coroutine` as background work and return a handle for it.
    ///
    /// The handle is awaitable (it finishes with the coroutine's value, or
    /// raises its exception), can be passed to `wait_first`, and `cancel()`
    /// cancels the coroutine. An exception nothing is awaiting when it
    /// happens is logged at error level. The work is bounded by
    /// `script.handler_timeout_secs` like a handler, and a graceful shutdown
    /// waits for it.
    ///
    /// ```python
    /// handle = tasks.spawn(release(session), name="release")
    /// ```
    #[pyo3(signature = (coroutine, *, name=None))]
    fn spawn<'py>(
        &self,
        python: Python<'py>,
        coroutine: &Bound<'py, PyAny>,
        name: Option<String>,
    ) -> PyResult<Bound<'py, PyAny>> {
        crate::script::direct::spawn_background(python, coroutine, name)
    }

    /// An awaitable that finishes with a `FirstResult` as soon as the first of
    /// `awaitables` finishes, or with `timed_out` after `timeout` seconds.
    ///
    /// `awaitables` are `spawn` handles, `event().wait()` and the awaitables
    /// siphon's APIs return inside a handler siphon drives itself. The others
    /// are left running unless `cancel_losers` is true: the default matches
    /// `asyncio.wait`, and a request already sent (a release, a Diameter
    /// answer) usually still has to complete after the caller stopped waiting.
    ///
    /// ```python
    /// first = await tasks.wait_first([release, answered.wait()], timeout=2.0)
    /// ```
    #[pyo3(signature = (awaitables, *, timeout=None, cancel_losers=false))]
    fn wait_first<'py>(
        &self,
        python: Python<'py>,
        awaitables: &Bound<'py, PyAny>,
        timeout: Option<f64>,
        cancel_losers: bool,
    ) -> PyResult<Bound<'py, PyAny>> {
        crate::script::direct::wait_first(python, awaitables, timeout, cancel_losers)
    }

    /// A new, unset `Event`.
    fn event(&self) -> PyTaskEvent {
        PyTaskEvent {
            core: Arc::new(EventCore::new()),
        }
    }
}

/// A flag one piece of code sets and another awaits.
#[pyclass(name = "Event", frozen)]
pub struct PyTaskEvent {
    core: Arc<EventCore>,
}

#[pymethods]
impl PyTaskEvent {
    /// Set the event: everything awaiting `wait()` finishes, and later calls
    /// to `wait()` finish at once. Safe from any handler.
    fn set(&self) {
        self.core.set();
    }

    /// Unset the event.
    fn clear(&self) {
        self.core.clear();
    }

    /// Whether the event is set.
    fn is_set(&self) -> bool {
        self.core.is_set()
    }

    /// An awaitable that finishes with `True` once the event is set.
    fn wait<'py>(&self, python: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        self.core.wait(python)
    }
}

/// How a `wait_first` ended.
#[pyclass(name = "FirstResult", frozen)]
pub struct PyFirstResult {
    index: Option<usize>,
    awaitable: Option<Py<PyAny>>,
    outcome: Option<Result<Py<PyAny>, Py<PyAny>>>,
}

#[pymethods]
impl PyFirstResult {
    /// Position, in the list given to `wait_first`, of the awaitable that
    /// finished first; `None` if the timeout did.
    #[getter]
    fn index(&self) -> Option<usize> {
        self.index
    }

    /// Whether the timeout ended the wait.
    #[getter]
    fn timed_out(&self) -> bool {
        self.index.is_none()
    }

    /// The awaitable that finished first; `None` on a timeout.
    #[getter]
    fn awaitable(&self, python: Python<'_>) -> Option<Py<PyAny>> {
        self.awaitable.as_ref().map(|held| held.clone_ref(python))
    }

    /// The exception the winner ended with, or `None`.
    #[getter]
    fn exception(&self, python: Python<'_>) -> Option<Py<PyAny>> {
        match &self.outcome {
            Some(Err(raised)) => Some(raised.clone_ref(python)),
            _ => None,
        }
    }

    /// The winner's value; raises its exception, or `TimeoutError` if the
    /// timeout ended the wait.
    fn result(&self, python: Python<'_>) -> PyResult<Py<PyAny>> {
        match &self.outcome {
            Some(Ok(value)) => Ok(value.clone_ref(python)),
            Some(Err(raised)) => Err(PyErr::from_value(raised.bind(python).clone())),
            None => Err(PyTimeoutError::new_err(
                "tasks.wait_first() timed out before any awaitable finished",
            )),
        }
    }

    fn __repr__(&self) -> String {
        match self.index {
            Some(index) => format!("<FirstResult index={index}>"),
            None => "<FirstResult timed_out>".to_string(),
        }
    }
}

impl<'py> IntoPyObject<'py> for FirstOutcome {
    type Target = PyFirstResult;
    type Output = Bound<'py, PyFirstResult>;
    type Error = PyErr;

    fn into_pyobject(self, python: Python<'py>) -> Result<Self::Output, Self::Error> {
        let resolved = self.resolve(python);
        Bound::new(
            python,
            PyFirstResult {
                index: resolved.index,
                awaitable: resolved.awaitable,
                outcome: resolved.outcome,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_result_without_a_winner_is_a_timeout() {
        Python::initialize();
        Python::attach(|python| {
            let result = PyFirstResult {
                index: None,
                awaitable: None,
                outcome: None,
            };
            assert!(result.timed_out());
            assert!(result.exception(python).is_none());
            let error = result.result(python).expect_err("a timeout raises");
            assert!(error.is_instance_of::<PyTimeoutError>(python));
            assert_eq!(result.__repr__(), "<FirstResult timed_out>");
        });
    }

    #[test]
    fn a_result_with_a_winner_carries_its_value() {
        Python::initialize();
        Python::attach(|python| {
            let result = PyFirstResult {
                index: Some(1),
                awaitable: None,
                outcome: Some(Ok(7i64.into_pyobject(python).unwrap().into_any().unbind())),
            };
            assert!(!result.timed_out());
            assert_eq!(result.index(), Some(1));
            assert_eq!(
                result
                    .result(python)
                    .unwrap()
                    .extract::<i64>(python)
                    .unwrap(),
                7
            );
            assert_eq!(result.__repr__(), "<FirstResult index=1>");
        });
    }

    #[test]
    fn a_result_with_a_failed_winner_raises_its_exception() {
        Python::initialize();
        Python::attach(|python| {
            let raised = pyo3::exceptions::PyValueError::new_err("boom")
                .into_value(python)
                .into_any();
            let result = PyFirstResult {
                index: Some(0),
                awaitable: None,
                outcome: Some(Err(raised)),
            };
            assert!(result.exception(python).is_some());
            let error = result.result(python).expect_err("raises");
            assert!(error.is_instance_of::<pyo3::exceptions::PyValueError>(python));
        });
    }

    #[test]
    fn an_event_sets_and_clears() {
        let event = PyTasksNamespace::new().event();
        assert!(!event.is_set());
        event.set();
        assert!(event.is_set());
        event.clear();
        assert!(!event.is_set());
    }
}
