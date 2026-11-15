//! A gather's coroutine arguments as slab entries: made, started, and ended
//! when the handler that gathered them is over. See [`super::super::gather`].

use std::sync::atomic::Ordering;
use std::sync::Arc;

use pyo3::exceptions::PyRuntimeError;
use pyo3::intern;
use pyo3::prelude::*;
use tracing::debug;

use super::{finish, on_owner, start_as_task, step, Completion, DriveKey, Entry, Phase};
use crate::script::runner::python::{cancelled_error, helpers};
use crate::script::runner::switch::{is_demoted, DemotionKey};
use crate::script::runner::task::DirectTask;

/// Put `coroutine` in the slab as argument `index` of gather `gather`, not
/// yet started. It takes no place of its own among the handlers in flight.
pub(in crate::script::runner) fn insert_child(
    python: Python<'_>,
    coroutine: Py<PyAny>,
    context: Py<PyAny>,
    gather: u64,
    index: usize,
) -> PyResult<DriveKey> {
    let gone = || PyRuntimeError::new_err("the asyncio driver is shutting down");
    let (runner, event_loop) = on_owner(|owner| {
        (
            Arc::clone(&owner.runner),
            owner.event_loop.clone_ref(python),
        )
    })
    .ok_or_else(gone)?;
    // Remembered by its code: a child that turned out to use asyncio starts
    // as a task the next time.
    let demotion = DemotionKey::new(Arc::new(
        coroutine
            .bind(python)
            .getattr(intern!(python, "cr_code"))?
            .unbind(),
    ));
    let task = if is_demoted(&demotion) {
        None
    } else {
        Some(Py::new(python, DirectTask::new(runner, event_loop))?)
    };
    let entry = Entry {
        coroutine,
        context,
        task: task.as_ref().map(|task| task.clone_ref(python)),
        phase: if task.is_some() {
            Phase::Stepping
        } else {
            Phase::HandedOver
        },
        real: None,
        first: None,
        cancel_pending: false,
        cancel_message: None,
        completion: Completion::Gather { gather, index },
        demotion,
        gathers: Vec::new(),
        _admission: None,
        _pending: None,
    };
    let mut entry = Some(entry);
    let key = on_owner(|owner| {
        entry.take().map(|entry| {
            owner.runner.drives.fetch_add(1, Ordering::Relaxed);
            owner.slab.insert(entry)
        })
    })
    .flatten();
    // Not inserted: the owner went. Dropped here, attached.
    drop(entry);
    let key = key.ok_or_else(gone)?;
    if let Some(task) = task {
        task.get().bind_key(key);
    }
    Ok(key)
}

/// The first step of a gather's child, or its start as a task if it is known
/// to use asyncio. A child cancelled before it started ends cancelled without
/// running.
pub(in crate::script::runner) fn start_child(python: Python<'_>, key: DriveKey) {
    let state = on_owner(|owner| {
        let event_loop = owner.event_loop.clone_ref(python);
        let entry = owner.slab.get_mut(key)?;
        Some((
            entry.task.is_some(),
            entry.cancel_pending,
            entry.coroutine.clone_ref(python),
            event_loop,
        ))
    })
    .flatten();
    let Some((direct, cancelled, coroutine, event_loop)) = state else {
        return;
    };
    if direct {
        // A pending cancellation is thrown in by the step.
        step(python, key);
        return;
    }
    if cancelled {
        let _ = coroutine
            .bind(python)
            .call_method0(intern!(python, "close"));
        finish(python, key, Err(cancelled_error(python)));
        return;
    }
    match helpers(python) {
        Some(helpers) => start_as_task(python, helpers, key, &event_loop),
        None => {
            let _ = coroutine
                .bind(python)
                .call_method0(intern!(python, "close"));
            finish(
                python,
                key,
                Err(PyRuntimeError::new_err(
                    "the direct-dispatch helpers are missing",
                )),
            );
        }
    }
}

/// Note that gather `gather` was made in a step of coroutine `key`.
pub(in crate::script::runner) fn note_gather(key: DriveKey, gather: u64) {
    on_owner(|owner| {
        let gathers = &owner.gathers;
        if let Some(entry) = owner.slab.get_mut(key) {
            if entry.gathers.len() >= 8 {
                // A handler that gathers in a loop: forget the finished ones.
                entry.gathers.retain(|id| gathers.contains_key(id));
            }
            entry.gathers.push(gather);
        }
    });
}

/// End a gather's child that is still suspended although it was cancelled:
/// its handler is over and nothing may outlive it. The coroutine is closed,
/// so its `finally` blocks run. A child a real task runs was cancelled as a
/// task is and ends when the task does.
pub(in crate::script::runner) fn force_close(python: Python<'_>, key: DriveKey) {
    let suspended = on_owner(|owner| {
        let entry = owner.slab.get_mut(key)?;
        if entry.real.is_some() {
            return None;
        }
        match std::mem::replace(&mut entry.phase, Phase::Stepping) {
            Phase::Waiting(awaitable) => Some((awaitable, entry.coroutine.clone_ref(python))),
            other => {
                entry.phase = other;
                None
            }
        }
    })
    .flatten();
    let Some((awaitable, coroutine)) = suspended else {
        return;
    };
    awaitable.get().forget_waiter(key);
    awaitable.get().cancel_without_wake(python);
    drop(awaitable);
    if let Err(error) = coroutine
        .bind(python)
        .call_method0(intern!(python, "close"))
    {
        debug!(%error, "closing a gathered coroutine that outlived its handler raised");
    }
    finish(python, key, Err(cancelled_error(python)));
}
