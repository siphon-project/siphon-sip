//! `tasks.gather`: several awaitables of one directly driven handler, run at
//! the same time on the handler's own runner.
//!
//! `asyncio.gather` wraps each coroutine in a task and waits on a future, so
//! a handler that calls it is handed to asyncio for good. That is still what
//! happens where no runner steps the caller (the switch is off, or the
//! handler runs as a task already). In a directly driven handler each coroutine
//! argument becomes a second entry in the same driver's slab, stepped by the
//! same runner as its handler, and a siphon awaitable is waited on as it is.
//! What the handler awaits is one more siphon awaitable, which the runner
//! settles when the last child has ended. Nothing leaves the driver thread
//! and no task is made.
//!
//! # What a child is
//!
//! - a siphon awaitable: the gather is recorded as what its completion tells;
//! - a coroutine: a slab entry of its own, with its own task object and a
//!   copy of the handler's context, as a task would have. If it turns out to
//!   use asyncio it is handed to a real task on the same thread, as a handler
//!   is, and still reports here;
//! - any other awaitable (an asyncio future, a task): wrapped in a coroutine
//!   that awaits it, which is then the case above.
//!
//! # How it ends
//!
//! With every child's result, in argument order. A child that raises ends the
//! gather at once with that exception and cancels the others, unless
//! `return_exceptions` is set, in which case exceptions are results.
//! Cancelling the gather (its handler timed out, or was cancelled while
//! awaiting it) cancels every child still running. A handler that ends takes
//! its gathers with it: children still running are cancelled, and one that
//! ignores the cancellation is closed.

use std::sync::atomic::Ordering;

use pyo3::exceptions::PyRuntimeError;
use pyo3::intern;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyTuple};

use super::awaitable::{awaited_by_the_step, local_awaitable, Registered, SiphonAwaitable};
use super::drive::{self, on_owner, CancelReason, DriveKey};
use super::python::{helpers, Helpers};
use super::switch::enabled;
use super::Fate;

/// One argument of a gather.
enum Child {
    /// A siphon awaitable that tells the gather when it finishes.
    Awaitable(Py<SiphonAwaitable>),
    /// A coroutine in the slab.
    Drive(DriveKey),
    /// It has ended, or was cancelled and will not report.
    Ended,
}

/// How a child ended: its value, or the exception instance.
type Ended = Result<Py<PyAny>, Py<PyAny>>;

/// A gather with a child still running. Lives in its driver's
/// [`drive::Owner`], touched only there.
pub(super) struct Gather {
    children: Vec<Child>,
    /// For each argument, the child that answers it: an awaitable passed
    /// twice is awaited once.
    positions: Vec<usize>,
    results: Vec<Option<Ended>>,
    /// Children that have not ended.
    live: usize,
    /// The awaitable the handler holds has its outcome, or was cancelled:
    /// what children report from now on is dropped.
    settled: bool,
    return_exceptions: bool,
}

/// A child to cancel, taken out of its gather.
enum Running {
    Awaitable(Py<SiphonAwaitable>),
    Drive(DriveKey),
}

impl Gather {
    /// The children still running, to be cancelled. An awaitable will not
    /// report after that, so it counts as ended now; a coroutine reports its
    /// own end.
    fn take_running(&mut self) -> Vec<Running> {
        let mut running = Vec::new();
        for child in &mut self.children {
            match std::mem::replace(child, Child::Ended) {
                Child::Awaitable(awaitable) => {
                    self.live = self.live.saturating_sub(1);
                    running.push(Running::Awaitable(awaitable));
                }
                Child::Drive(key) => {
                    *child = Child::Drive(key);
                    running.push(Running::Drive(key));
                }
                Child::Ended => {}
            }
        }
        running
    }
}

/// The gather of a caller no runner steps: `asyncio.gather` over asyncio
/// tasks, with a failing child cancelling the others as it does here.
fn gather_as_tasks<'py>(
    python: Python<'py>,
    awaitables: &Bound<'py, PyTuple>,
    return_exceptions: bool,
) -> PyResult<Bound<'py, PyAny>> {
    if let Some(helpers) = helpers(python) {
        return helpers
            .gather_as_tasks
            .bind(python)
            .call1((awaitables, return_exceptions));
    }
    // The helpers could not be built, which was reported: plain asyncio.
    let kwargs = PyDict::new(python);
    kwargs.set_item(intern!(python, "return_exceptions"), return_exceptions)?;
    python
        .import(intern!(python, "asyncio"))?
        .getattr(intern!(python, "gather"))?
        .call(awaitables.clone(), Some(&kwargs))
}

/// Whether `object` is a coroutine made by an `async def`.
fn is_coroutine(object: &Bound<'_, PyAny>) -> bool {
    // SAFETY: attached; `object` is a live object and the check only reads
    // its type.
    unsafe { pyo3::ffi::PyCoro_CheckExact(object.as_ptr()) != 0 }
}

/// Close coroutines that will not be awaited, so that they are not reported
/// as never awaited.
fn close_all(python: Python<'_>, coroutines: &[Bound<'_, PyAny>]) {
    for coroutine in coroutines {
        if is_coroutine(coroutine) {
            let _ = coroutine.call_method0(intern!(python, "close"));
        }
    }
}

/// `tasks.gather(*awaitables, return_exceptions=False)`.
///
/// In a step of a directly driven handler the children run on the handler's
/// runner and what comes back is a siphon awaitable. Anywhere else (the
/// switch is off, the handler runs as an asyncio task, the caller is a task
/// the handler made) the children are asyncio tasks under `asyncio.gather`,
/// with the same results and the same cancellation.
pub(crate) fn gather<'py>(
    python: Python<'py>,
    awaitables: &Bound<'py, PyTuple>,
    return_exceptions: bool,
) -> PyResult<Bound<'py, PyAny>> {
    let parent = if enabled() && awaited_by_the_step(python) {
        drive::active()
    } else {
        None
    };
    let (Some(parent), Some(helpers)) = (parent, helpers(python)) else {
        return gather_as_tasks(python, awaitables, return_exceptions);
    };

    // An argument passed twice is one child, as with `asyncio.gather`.
    let mut unique: Vec<Bound<'py, PyAny>> = Vec::with_capacity(awaitables.len());
    let mut positions = Vec::with_capacity(awaitables.len());
    for argument in awaitables.iter() {
        match unique.iter().position(|seen| seen.is(&argument)) {
            Some(index) => positions.push(index),
            None => {
                positions.push(unique.len());
                unique.push(argument);
            }
        }
    }
    // Anything that is neither ours nor a coroutine is wrapped in one. An
    // argument that cannot be awaited raises here, before anything started.
    let mut arguments: Vec<Bound<'py, PyAny>> = Vec::with_capacity(unique.len());
    for argument in &unique {
        if argument.cast::<SiphonAwaitable>().is_ok() || is_coroutine(argument) {
            arguments.push(argument.clone());
            continue;
        }
        match helpers.as_coroutine.bind(python).call1((argument,)) {
            Ok(wrapped) => arguments.push(wrapped),
            Err(error) => {
                close_all(python, &arguments);
                close_all(python, &unique);
                return Err(error);
            }
        }
    }

    let Some((awaitable, id)) = local_awaitable(python)? else {
        close_all(python, &arguments);
        return Err(PyRuntimeError::new_err(
            "the asyncio driver is shutting down",
        ));
    };
    if arguments.is_empty() {
        drive::complete_awaitable(
            python,
            Fate::Run,
            id,
            Box::new(|python| Ok(PyList::empty(python).into_any().unbind())),
        );
        return Ok(awaitable.into_bound(python).into_any());
    }

    let (children, ready, failure) = make_children(python, helpers, id, &arguments);
    let started: Vec<DriveKey> = children
        .iter()
        .filter_map(|child| match child {
            Child::Drive(key) => Some(*key),
            _ => None,
        })
        .collect();
    let mut gather = Some(Gather {
        live: children.len(),
        results: children.iter().map(|_| None).collect(),
        children,
        positions,
        settled: false,
        return_exceptions,
    });
    let installed = on_owner(|owner| {
        if let Some(gather) = gather.take() {
            owner.gathers.insert(id, gather);
            owner.runner.gathers.fetch_add(1, Ordering::Relaxed);
        }
    })
    .is_some();
    // Not installed: the owner went, and the slab with it.
    drop(gather);
    if !installed {
        return Err(PyRuntimeError::new_err(
            "the asyncio driver is shutting down",
        ));
    }
    drive::note_gather(parent, id);

    if let Some(error) = failure {
        // A child could not be made: nothing of the gather is left behind.
        awaitable.get().cancel_without_wake(python);
        for key in started {
            drive::start_child(python, key);
        }
        return Err(error);
    }
    for (index, result) in ready {
        child_done(python, id, index, result);
    }
    // In argument order, now: a child runs to its first suspension before
    // the handler goes on, and one that never suspends has finished by then.
    for key in started {
        drive::start_child(python, key);
    }
    Ok(awaitable.into_bound(python).into_any())
}

/// The results of the awaitables that had finished before they were gathered,
/// by child.
type Ready = Vec<(usize, PyResult<Py<PyAny>>)>;

/// Make a child of each argument: register with the awaitables, put the
/// coroutines in the slab, unstarted. On an error the children made so far
/// come back with it, for the caller to cancel.
fn make_children(
    python: Python<'_>,
    helpers: &Helpers,
    id: u64,
    arguments: &[Bound<'_, PyAny>],
) -> (Vec<Child>, Ready, Option<PyErr>) {
    let mut children = Vec::with_capacity(arguments.len());
    let mut ready = Vec::new();
    for (index, argument) in arguments.iter().enumerate() {
        let made = (|| -> PyResult<Child> {
            let coroutine = match argument.cast::<SiphonAwaitable>() {
                Ok(awaitable) => match awaitable.get().register_gather(id, index) {
                    Registered::Waiting => return Ok(Child::Awaitable(awaitable.clone().unbind())),
                    Registered::Finished => {
                        ready.push((index, awaitable.get().result(python)));
                        return Ok(Child::Awaitable(awaitable.clone().unbind()));
                    }
                    // Something else waits on it already, or it is another
                    // driver's: a coroutine awaits it, as an asyncio future.
                    Registered::Elsewhere => {
                        helpers.as_coroutine.bind(python).call1((awaitable,))?
                    }
                },
                Err(_) => argument.clone(),
            };
            // SAFETY: attached; a new reference, or NULL with an exception
            // set. Called inside the handler's step, so this is a copy of
            // the handler's context, as a task made here would get.
            let context = unsafe {
                Bound::from_owned_ptr_or_err(python, pyo3::ffi::PyContext_CopyCurrent())?
            };
            let key = drive::insert_child(python, coroutine.unbind(), context.unbind(), id, index)?;
            Ok(Child::Drive(key))
        })();
        match made {
            Ok(child) => children.push(child),
            Err(error) => {
                close_all(python, &arguments[index..]);
                return (children, ready, Some(error));
            }
        }
    }
    (children, ready, None)
}

/// On the runner: child `index` of gather `id` ended with `result`.
pub(super) fn child_done(python: Python<'_>, id: u64, index: usize, result: PyResult<Py<PyAny>>) {
    enum Next {
        Nothing,
        /// Every child has ended: the gather has its list.
        Settle(Vec<Option<Ended>>, Vec<usize>),
        /// A child raised: the others are cancelled and the gather raises.
        Fail(Py<PyAny>, Vec<Running>),
    }
    let ended: Ended = result.map_err(|error| error.into_value(python).into_any());
    let mut ended = Some(ended);
    // The awaitable that was the child: let go of outside the borrow.
    let mut was = None;
    let found = on_owner(|owner| {
        let gather = owner.gathers.get_mut(&id)?;
        let child = gather.children.get_mut(index)?;
        match std::mem::replace(child, Child::Ended) {
            // Reported already, or cancelled and counted then.
            Child::Ended => return None,
            other => was = Some(other),
        }
        gather.live = gather.live.saturating_sub(1);
        let mut next = Next::Nothing;
        if !gather.settled {
            match ended.take() {
                Some(Err(raised)) if !gather.return_exceptions => {
                    gather.settled = true;
                    next = Next::Fail(raised, gather.take_running());
                }
                outcome => {
                    if let Some(slot) = gather.results.get_mut(index) {
                        *slot = outcome;
                    }
                    if gather.live == 0 {
                        gather.settled = true;
                        next = Next::Settle(
                            std::mem::take(&mut gather.results),
                            std::mem::take(&mut gather.positions),
                        );
                    }
                }
            }
        }
        let over = if gather.live == 0 {
            owner.runner.gathers.fetch_sub(1, Ordering::Relaxed);
            owner.gathers.remove(&id)
        } else {
            None
        };
        Some((next, over))
    })
    .flatten();
    // A result nobody takes, and a gather that is over, go here: outside the
    // borrow, attached.
    drop(ended);
    drop(was);
    let Some((next, over)) = found else { return };
    drop(over);
    match next {
        Next::Nothing => {}
        Next::Settle(results, positions) => drive::complete_awaitable(
            python,
            Fate::Run,
            id,
            Box::new(move |python| {
                let list = PyList::empty(python);
                for position in positions {
                    match results.get(position) {
                        Some(Some(Ok(value) | Err(value))) => list.append(value.bind(python))?,
                        _ => list.append(python.None())?,
                    }
                }
                Ok(list.into_any().unbind())
            }),
        ),
        Next::Fail(raised, running) => {
            // The others first, so the handler resumes with them cancelled.
            cancel_children(python, id, running);
            drive::complete_awaitable(
                python,
                Fate::Run,
                id,
                Box::new(move |python| Err(PyErr::from_value(raised.into_bound(python)))),
            );
        }
    }
}

/// Cancel what was taken out of gather `id` with [`Gather::take_running`].
fn cancel_children(python: Python<'_>, id: u64, running: Vec<Running>) {
    for child in running {
        match child {
            Running::Awaitable(awaitable) => {
                awaitable.get().forget_gather(id);
                awaitable.get().cancel_without_wake(python);
            }
            // Throws `CancelledError` into it now, or asks its task to. It
            // reports its own end.
            Running::Drive(key) => {
                drive::cancel_drive(python, key, CancelReason::Task);
            }
        }
    }
}

/// On the runner: the awaitable of gather `id` was cancelled, so every child
/// still running is. Nothing to do if `id` is not a gather, or is over.
pub(super) fn cancel(python: Python<'_>, id: u64) {
    let found = on_owner(|owner| {
        let gather = owner.gathers.get_mut(&id)?;
        gather.settled = true;
        let running = gather.take_running();
        let over = if gather.live == 0 {
            owner.runner.gathers.fetch_sub(1, Ordering::Relaxed);
            owner.gathers.remove(&id)
        } else {
            None
        };
        Some((running, over))
    })
    .flatten();
    let Some((running, over)) = found else { return };
    drop(over);
    cancel_children(python, id, running);
}

/// On the runner: the coroutine that made gather `id` is over. Whatever the
/// gather still runs is cancelled, and a coroutine that ignored that is
/// closed: nothing a handler gathered outlives it.
pub(super) fn reap(python: Python<'_>, id: u64) {
    match drive::untrack_awaitable(id) {
        // Never settled: cancelling it cancels the children.
        Some(awaitable) => {
            awaitable.get().cancel_without_wake(python);
            drop(awaitable);
        }
        None => cancel(python, id),
    }
    let left: Vec<DriveKey> = on_owner(|owner| {
        owner.gathers.get(&id).map(|gather| {
            gather
                .children
                .iter()
                .filter_map(|child| match child {
                    Child::Drive(key) => Some(*key),
                    _ => None,
                })
                .collect()
        })
    })
    .flatten()
    .unwrap_or_default();
    for key in left {
        drive::force_close(python, key);
    }
}
