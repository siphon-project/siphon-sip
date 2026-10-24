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
///
/// Each arming gets a generation, so a timer that fires can only retire its
/// own entry: a handler that re-arms its key (or another thread that does)
/// keeps the new timer registered and cancellable.
#[derive(Default)]
pub struct TimerScheduler {
    timers: DashMap<String, ArmedTimer>,
    generations: std::sync::atomic::AtomicU64,
}

/// One armed timer: its task and the arming it belongs to.
struct ArmedTimer {
    generation: u64,
    task: JoinHandle<()>,
}

impl TimerScheduler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Cancel and remove any timer registered under `key`.
    fn cancel_key(&self, key: &str) -> bool {
        if let Some((_, armed)) = self.timers.remove(key) {
            armed.task.abort();
            true
        } else {
            false
        }
    }

    /// Arm `key`, replacing (and cancelling) any timer already under it.
    ///
    /// The entry is written while its shard is held, before `spawn` can let
    /// the task run, so a timer that fires at once still finds its own entry
    /// to retire instead of leaving a finished task registered.
    fn arm(&self, key: String, spawn: impl FnOnce(u64) -> JoinHandle<()>) {
        let generation = self
            .generations
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        match self.timers.entry(key) {
            dashmap::Entry::Occupied(mut occupied) => {
                let previous = occupied.insert(ArmedTimer {
                    generation,
                    task: spawn(generation),
                });
                previous.task.abort();
            }
            dashmap::Entry::Vacant(vacant) => {
                vacant.insert(ArmedTimer {
                    generation,
                    task: spawn(generation),
                });
            }
        }
    }

    /// Retire `key` if it is still the arming `generation` fired for.
    fn retire(&self, key: &str, generation: u64) {
        self.timers
            .remove_if(key, |_, armed| armed.generation == generation);
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

        let scheduler = Arc::clone(&self.scheduler);
        let key_clone = key.clone();
        let duration = Duration::from_millis(delay_ms);

        // Arming replaces (and cancels) any prior timer under this key.
        self.scheduler.arm(key.clone(), move |generation| {
            tokio::spawn(async move {
                tokio::time::sleep(duration).await;

                let fired_key = key_clone.clone();
                let _ = crate::script::py_executor::try_run(move || {
                    crate::script::attach::attach(|python| {
                        let callable = handler.bind(python);
                        match callable.call1((fired_key.as_str(),)) {
                            Ok(returned) => {
                                if is_async {
                                    if let Err(error) = run_coroutine(python, &returned) {
                                        error!(error = %crate::script::error_report::describe(python, &error), key = %fired_key, "async timer handler error");
                                    }
                                }
                            }
                            Err(error) => {
                                error!(error = %crate::script::error_report::describe(python, &error), key = %fired_key, "timer handler failed");
                            }
                        }
                    });
                })
                .await;

                // Retire this arming only: the handler may have re-armed the
                // key, and that timer stays registered. Done here rather than
                // in the job so a job that never ran (shed) or panicked still
                // retires its entry.
                scheduler.retire(&key_clone, generation);
            })
        });
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
        format!("TimerHandle(key={:?})", self.key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Run `source` (which defines `handler(key)`) and arm `key` with it.
    /// Returns the script module, for reading what the handler recorded.
    fn arm_from_script(
        namespace: &Py<PyTimerNamespace>,
        source: &str,
        key: &str,
        delay_ms: u64,
    ) -> Py<pyo3::types::PyModule> {
        Python::attach(|python| {
            let module = pyo3::types::PyModule::from_code(
                python,
                &std::ffi::CString::new(source).expect("source"),
                &std::ffi::CString::new(format!("timer_test_{key}.py")).expect("file"),
                &std::ffi::CString::new(format!("timer_test_{key}")).expect("module"),
            )
            .expect("module");
            module
                .setattr("timer", namespace.clone_ref(python))
                .expect("timer global");
            let handler = module.getattr("handler").expect("handler").unbind();
            namespace
                .borrow(python)
                .set(python, key.to_string(), delay_ms, handler)
                .expect("armed");
            module.unbind()
        })
    }

    fn active(namespace: &Py<PyTimerNamespace>) -> usize {
        Python::attach(|python| namespace.borrow(python).active_count())
    }

    /// A handler that re-arms its own key leaves that new timer registered.
    ///
    /// The fired task used to retire the key by name after the handler
    /// returned, which removed the timer the handler had just armed: it kept
    /// running, but `timer.cancel` could no longer reach it and
    /// `active_count` said nothing was armed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_handler_that_rearms_its_key_keeps_the_new_timer() {
        Python::initialize();
        let namespace =
            Python::attach(|python| Py::new(python, PyTimerNamespace::new())).expect("namespace");
        let module = arm_from_script(
            &namespace,
            "fired = []\ndef handler(key):\n    timer.set(key, 600_000, handler)\n    fired.append(key)\n",
            "rearm",
            10,
        );

        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let fired = Python::attach(|python| {
                module
                    .bind(python)
                    .getattr("fired")
                    .and_then(|fired| fired.len())
                    .unwrap_or(0)
            });
            if fired > 0 {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the timer never fired"
            );
        }
        // Give the fired task time to retire (it must not take the new entry).
        tokio::time::sleep(Duration::from_millis(300)).await;

        assert_eq!(active(&namespace), 1, "the re-armed timer stays registered");
        assert!(
            Python::attach(|python| namespace.borrow(python).cancel("rearm")),
            "and stays cancellable"
        );
        assert_eq!(active(&namespace), 0);
    }

    /// Timers that fire at once retire themselves: none is left registered
    /// after it ran, whichever of the arming and the firing wins.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn timers_that_fire_at_once_leave_nothing_registered() {
        Python::initialize();
        let namespace =
            Python::attach(|python| Py::new(python, PyTimerNamespace::new())).expect("namespace");
        for index in 0..200 {
            let _ = arm_from_script(
                &namespace,
                "def handler(key):\n    pass\n",
                &format!("instant_{index}"),
                0,
            );
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        while active(&namespace) != 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "{} fired timers are still registered",
                active(&namespace)
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    #[test]
    fn scheduler_cancel_missing_key_returns_false() {
        let scheduler = TimerScheduler::new();
        assert!(!scheduler.cancel_key("not-registered"));
    }
}
