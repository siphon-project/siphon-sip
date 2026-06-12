//! PyO3 wrapper for the `timer` namespace — periodic (`@timer.every`) and
//! one-shot (`timer.set`) timer scheduling.
//!
//! Usage from scripts:
//!
//! ```python
//! from siphon import timer
//!
//! # Periodic (registered at script load, managed by ScriptEngine::restart_timers)
//! @timer.every(seconds=30)
//! async def health_check():
//!     ...
//!
//! # One-shot, cancellable by key
//! def on_timeout(key):
//!     log.info(f"timer {key} fired")
//!
//! handle = timer.set("cfnr-abc", 20_000, on_timeout)
//! ...
//! timer.cancel("cfnr-abc")   # or: handle.cancel()
//! ```

use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use tokio::task::JoinHandle;
use tracing::{debug, error, warn};

use crate::script::engine::run_coroutine;

// `run_coroutine` is `pub(crate)` — accessible from this module (same crate).

/// Per-process registry of live one-shot timers, keyed by user-supplied string.
///
/// Setting the same key twice cancels the previous timer and reschedules.
#[derive(Default)]
pub struct TimerScheduler {
    timers: DashMap<String, JoinHandle<()>>,
}

impl TimerScheduler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Cancel and remove any timer registered under `key`.
    fn cancel_key(&self, key: &str) -> bool {
        if let Some((_, handle)) = self.timers.remove(key) {
            handle.abort();
            true
        } else {
            false
        }
    }
}

/// Python-visible timer namespace.
#[pyclass(name = "TimerNamespace")]
pub struct PyTimerNamespace {
    scheduler: Arc<TimerScheduler>,
}

impl PyTimerNamespace {
    pub fn new() -> Self {
        Self {
            scheduler: Arc::new(TimerScheduler::new()),
        }
    }
}

impl Default for PyTimerNamespace {
    fn default() -> Self {
        Self::new()
    }
}

#[pymethods]
impl PyTimerNamespace {
    /// Register a periodic timer callback.
    ///
    /// Returns a decorator; the handler runs every ``seconds`` with optional
    /// ``jitter`` (random 0..jitter seconds added each tick).  Periodic
    /// timers are started at script load and restarted on hot-reload —
    /// they cannot be cancelled at runtime; use :meth:`set` for that.
    #[pyo3(signature = (seconds, name=None, jitter=0))]
    fn every<'py>(
        &self,
        python: Python<'py>,
        seconds: u64,
        name: Option<String>,
        jitter: u64,
    ) -> PyResult<Bound<'py, PyAny>> {
        // Build the decorator in pure Python — delegates to _siphon_registry
        // just like the stub used to.
        let code = r#"
def make_decorator(seconds, name, jitter):
    import asyncio
    import _siphon_registry
    def decorator(fn):
        timer_name = name if name is not None else fn.__name__
        is_async = asyncio.iscoroutinefunction(fn)
        metadata = {"seconds": seconds, "name": timer_name, "jitter": jitter}
        _siphon_registry.register("timer.every", None, fn, is_async, metadata)
        return fn
    return decorator
"#;
        let globals = PyDict::new(python);
        python.run(&std::ffi::CString::new(code).unwrap(), Some(&globals), None)?;
        let make_decorator = globals.get_item("make_decorator")?.ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err("failed to build timer.every decorator")
        })?;
        make_decorator.call1((seconds, name, jitter))
    }

    /// Schedule a one-shot callback to fire after ``delay_ms`` milliseconds.
    ///
    /// ``key`` identifies the timer so it can be cancelled via
    /// :meth:`cancel` (or via the returned :class:`TimerHandle`).  Setting
    /// the same key twice cancels the prior timer and reschedules.
    ///
    /// The handler is invoked with the key as its single argument.  Both
    /// sync and async handlers are supported.
    #[pyo3(signature = (key, delay_ms, handler))]
    fn set(
        &self,
        python: Python<'_>,
        key: String,
        delay_ms: u64,
        handler: Py<PyAny>,
    ) -> PyResult<PyTimerHandle> {
        let asyncio = python.import("asyncio")?;
        let is_async = asyncio
            .call_method1("iscoroutinefunction", (handler.bind(python),))?
            .is_truthy()?;

        // Cancel any prior timer under this key before rescheduling.
        self.scheduler.cancel_key(&key);

        let scheduler = Arc::clone(&self.scheduler);
        let key_clone = key.clone();
        let duration = Duration::from_millis(delay_ms);

        let join_handle: JoinHandle<()> = tokio::spawn(async move {
            tokio::time::sleep(duration).await;

            // Fire the callback inside Python::attach, then pop the registry
            // entry so a subsequent set() under the same key works cleanly.
            crate::script::py_executor::run(move || {
                pyo3::Python::attach(|python| {
                    let callable = handler.bind(python);
                    match callable.call1((key_clone.as_str(),)) {
                        Ok(returned) => {
                            if is_async {
                                if let Err(error) = run_coroutine(python, &returned) {
                                    error!(%error, key = %key_clone, "async timer handler error");
                                }
                            }
                        }
                        Err(error) => {
                            error!(%error, key = %key_clone, "timer handler failed");
                        }
                    }
                });

                scheduler.timers.remove(&key_clone);
            })
            .await;
        });

        self.scheduler.timers.insert(key.clone(), join_handle);
        debug!(key = %key, delay_ms, "timer.set scheduled");

        Ok(PyTimerHandle {
            key,
            scheduler: Arc::clone(&self.scheduler),
        })
    }

    /// Cancel the timer registered under ``key``.  Returns ``True`` if a
    /// timer was cancelled, ``False`` if no timer matched.
    #[pyo3(signature = (key))]
    fn cancel(&self, key: &str) -> bool {
        let cancelled = self.scheduler.cancel_key(key);
        if cancelled {
            debug!(key = %key, "timer.cancel");
        } else {
            warn!(key = %key, "timer.cancel: no such key");
        }
        cancelled
    }

    /// Number of currently-armed one-shot timers.
    #[getter]
    fn active_count(&self) -> usize {
        self.scheduler.timers.len()
    }
}

/// Handle returned by :meth:`TimerNamespace.set` — exposes the key and a
/// convenience ``cancel()`` method.
#[pyclass(name = "TimerHandle")]
pub struct PyTimerHandle {
    key: String,
    scheduler: Arc<TimerScheduler>,
}

#[pymethods]
impl PyTimerHandle {
    /// The key the timer was registered under.
    #[getter]
    fn key(&self) -> &str {
        &self.key
    }

    /// Cancel this timer.  Returns ``True`` if the timer was still armed.
    fn cancel(&self) -> bool {
        self.scheduler.cancel_key(&self.key)
    }

    fn __repr__(&self) -> String {
        format!("TimerHandle(key={:?})", &self.key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheduler_cancel_missing_key_returns_false() {
        let scheduler = TimerScheduler::new();
        assert!(!scheduler.cancel_key("not-registered"));
    }
}
