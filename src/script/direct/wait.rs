//! `tasks.wait_first` and `tasks.event`: waiting on several siphon awaitables
//! at once, and an awaitable other code can set.
//!
//! Neither touches asyncio. A wait is one siphon awaitable of its own, so a
//! directly driven coroutine awaiting it is resumed by the executor like it is
//! for any other.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use pyo3::exceptions::{PyRuntimeError, PyTypeError, PyValueError};
use pyo3::prelude::*;
use tokio::sync::{mpsc, watch};

use super::awaitable::{awaitable_in_step, AwaitableShared, SiphonAwaitable};

static NEXT_TOKEN: AtomicU64 = AtomicU64::new(1);

/// The watchers a wait has registered, withdrawn when the wait ends in any
/// way: it finished, or its future was dropped because the waiter was
/// cancelled.
struct Watching {
    registered: Vec<(Arc<AwaitableShared>, u64)>,
}

impl Drop for Watching {
    fn drop(&mut self) {
        for (shared, token) in &self.registered {
            shared.unwatch(*token);
        }
    }
}

/// How a `wait_first` ended, before the interpreter is needed to describe it.
pub(crate) struct FirstOutcome {
    winner: Option<usize>,
    shareds: Vec<Arc<AwaitableShared>>,
    awaitables: Vec<Py<PyAny>>,
    cancel_losers: bool,
}

/// What a script is told about a finished `wait_first`.
pub(crate) struct Resolved {
    /// The position in the list of the awaitable that finished first;
    /// `None` when the timeout did.
    pub(crate) index: Option<usize>,
    /// The awaitable that finished first.
    pub(crate) awaitable: Option<Py<PyAny>>,
    /// Its value, or the exception it ended with.
    pub(crate) outcome: Option<Result<Py<PyAny>, Py<PyAny>>>,
}

impl FirstOutcome {
    /// Read the winner's outcome and, if asked, cancel the others. Runs
    /// attached, in the step that resumes the waiter.
    pub(crate) fn resolve(self, python: Python<'_>) -> Resolved {
        let Some(index) = self.winner else {
            // The timeout won: every awaitable is a loser.
            if self.cancel_losers {
                for shared in &self.shareds {
                    shared.cancel(python);
                }
            }
            return Resolved {
                index: None,
                awaitable: None,
                outcome: None,
            };
        };
        let outcome = match self.shareds[index].result(python) {
            Ok(value) => Ok(value),
            Err(error) => Err(error.into_value(python).into_any()),
        };
        if self.cancel_losers {
            for (position, shared) in self.shareds.iter().enumerate() {
                if position != index {
                    shared.cancel(python);
                }
            }
        }
        Resolved {
            index: Some(index),
            awaitable: Some(self.awaitables[index].clone_ref(python)),
            outcome: Some(outcome),
        }
    }
}

/// The awaitable that finishes with the first of `awaitables` to finish (or
/// cancel), or with a timeout. `T` is what the waiter is given.
pub(crate) fn wait_first<'py>(
    python: Python<'py>,
    awaitables: &Bound<'py, PyAny>,
    timeout: Option<f64>,
    cancel_losers: bool,
) -> PyResult<Bound<'py, PyAny>> {
    let timeout = match timeout {
        None => None,
        Some(seconds) if seconds.is_finite() && seconds >= 0.0 => {
            Some(Duration::from_secs_f64(seconds))
        }
        Some(seconds) => {
            return Err(PyValueError::new_err(format!(
                "tasks.wait_first(timeout=) must be a non-negative number of seconds, got {seconds}"
            )))
        }
    };
    let mut shareds = Vec::new();
    let mut held = Vec::new();
    for item in awaitables.try_iter()? {
        let item = item?;
        let siphon = item.cast::<SiphonAwaitable>().map_err(|_| {
            PyTypeError::new_err(format!(
                "tasks.wait_first() takes awaitables siphon returned (a tasks.spawn() \
                 handle, tasks.event().wait(), a siphon API call made in a handler siphon \
                 drives itself), not {}",
                item.get_type()
                    .name()
                    .map(|name| name.to_string())
                    .unwrap_or_default()
            ))
        })?;
        shareds.push(Arc::clone(&siphon.get().shared));
        held.push(item.unbind());
    }
    if shareds.is_empty() {
        return Err(PyValueError::new_err(
            "tasks.wait_first() needs at least one awaitable",
        ));
    }

    let (sender, mut receiver) = mpsc::unbounded_channel::<usize>();
    let mut watching = Watching {
        registered: Vec::new(),
    };
    for (index, shared) in shareds.iter().enumerate() {
        let token = NEXT_TOKEN.fetch_add(1, Ordering::Relaxed);
        let wake = sender.clone();
        let watcher = Box::new(move || {
            let _ = wake.send(index);
        });
        if shared.watch(token, watcher) {
            watching.registered.push((Arc::clone(shared), token));
        } else {
            // Finished already: it is a candidate straight away.
            let _ = sender.send(index);
        }
    }
    drop(sender);

    let waiting_on = shareds.clone();
    awaitable_in_step(python, async move {
        let _watching = watching;
        let first = match timeout {
            Some(bound) => tokio::time::timeout(bound, receiver.recv())
                .await
                .ok()
                .flatten(),
            None => receiver.recv().await,
        };
        Ok::<FirstOutcome, PyErr>(FirstOutcome {
            winner: first,
            shareds: waiting_on,
            awaitables: held,
            cancel_losers,
        })
    })
}

/// A flag other code sets and a coroutine awaits.
pub(crate) struct EventCore {
    flag: Arc<watch::Sender<bool>>,
}

impl EventCore {
    pub(crate) fn new() -> Self {
        Self {
            flag: Arc::new(watch::Sender::new(false)),
        }
    }

    pub(crate) fn set(&self) {
        self.flag.send_replace(true);
    }

    pub(crate) fn clear(&self) {
        self.flag.send_replace(false);
    }

    pub(crate) fn is_set(&self) -> bool {
        *self.flag.borrow()
    }

    /// An awaitable that finishes, with `True`, once the event is set; at once
    /// if it is. Cancelling it, or the coroutine awaiting it, drops its
    /// subscription.
    pub(crate) fn wait<'py>(&self, python: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let flag = Arc::clone(&self.flag);
        awaitable_in_step(python, async move {
            let mut receiver = flag.subscribe();
            receiver
                .wait_for(|set| *set)
                .await
                .map(|_| true)
                .map_err(|_closed| PyRuntimeError::new_err("the event was dropped"))
        })
    }
}
