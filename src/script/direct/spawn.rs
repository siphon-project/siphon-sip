//! Background work a script starts with `tasks.spawn`.
//!
//! The coroutine is started the way a handler's is ([`super::start`]): on the
//! calling executor worker, with no asyncio task, for as long as it awaits
//! only siphon's own awaitables, and on an asyncio driver, intact, the moment
//! it uses asyncio for anything else (or when it is started from a thread
//! that is itself running an event loop). What the script gets back is a
//! siphon awaitable for its outcome, so it can be awaited from a direct
//! coroutine, watched by `tasks.wait_first`, and cancelled.
//!
//! Every spawned coroutine is tracked from before it starts until its outcome
//! has been delivered: the count is the `siphon_script_background_tasks`
//! gauge, it holds the shutdown drain open, and what is still running when the
//! drain gives up is cancelled ([`cancel_all`]).

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use dashmap::DashMap;
use pyo3::exceptions::{PyRuntimeError, PyTypeError};
use pyo3::intern;
use pyo3::prelude::*;
use tokio::sync::oneshot;
use tracing::{error, warn};

use crate::script::async_pool::{coroutine_name, AsyncPool, Canceller, PendingCoroutine};

use super::awaitable::{awaitable_in_step, AwaitableShared, SiphonAwaitable};
use super::python::helpers;
use super::{in_direct_step, start, Completion, DirectStart};

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// Spawned coroutines that have not delivered their outcome yet.
static COUNT: AtomicUsize = AtomicUsize::new(0);

/// What cancels a tracked coroutine, filled in once it has started.
struct Entry {
    canceller: OnceLock<Arc<Canceller>>,
}

static TRACKED: OnceLock<DashMap<u64, Arc<Entry>>> = OnceLock::new();

fn tracked() -> &'static DashMap<u64, Arc<Entry>> {
    TRACKED.get_or_init(DashMap::new)
}

fn publish(count: usize) {
    if let Some(registry) = crate::metrics::try_metrics() {
        registry.script_background_tasks.set(count as i64);
    }
}

/// A spawned coroutine's place in the tracker, held until its outcome has
/// been delivered. Every way out gives it back: delivered, timed out, or the
/// completion dropped unrun because the executor closed.
struct Tracked {
    id: u64,
}

impl Tracked {
    fn start() -> (Self, Arc<Entry>) {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let entry = Arc::new(Entry {
            canceller: OnceLock::new(),
        });
        tracked().insert(id, Arc::clone(&entry));
        publish(COUNT.fetch_add(1, Ordering::Relaxed) + 1);
        (Self { id }, entry)
    }
}

impl Drop for Tracked {
    fn drop(&mut self) {
        tracked().remove(&self.id);
        publish(COUNT.fetch_sub(1, Ordering::Relaxed).saturating_sub(1));
    }
}

/// Spawned coroutines still running, which the shutdown drain waits for.
pub(crate) fn outstanding() -> usize {
    COUNT.load(Ordering::Relaxed)
}

/// Cancel everything still running, as `Task.cancel` would. Attaches: call it
/// from a thread that may, never from a tokio worker.
pub(crate) fn cancel_all() -> usize {
    let cancellers: Vec<Arc<Canceller>> = tracked()
        .iter()
        .filter_map(|entry| entry.value().canceller.get().cloned())
        .collect();
    if cancellers.is_empty() {
        return 0;
    }
    crate::script::attach::attach(|python| {
        cancellers
            .iter()
            .filter(|canceller| canceller.cancel(python))
            .count()
    })
}

/// Cancel what is still running and wait, for at most `bound`, for it to
/// finish. What is left after that is logged and abandoned with the process.
pub(crate) async fn cancel_all_and_wait(bound: Duration) {
    if outstanding() == 0 {
        return;
    }
    let cancelled = tokio::task::spawn_blocking(cancel_all).await.unwrap_or(0);
    let deadline = tokio::time::Instant::now() + bound;
    while outstanding() > 0 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let left = outstanding();
    if left > 0 {
        warn!(
            cancelled,
            left, "background tasks a script spawned are still running at shutdown"
        );
    }
}

/// The lifecycle participant that makes the shutdown drain wait for spawned
/// coroutines and cancel the ones the deadline finds still running.
pub(crate) struct BackgroundTasks;

impl crate::lifecycle::LifecycleParticipant for BackgroundTasks {
    fn ready(&self) -> Result<(), String> {
        Ok(())
    }

    fn set_draining(&self, _draining: bool) {}

    fn outstanding(&self) -> usize {
        outstanding()
    }

    fn force(&self) {
        // Attaches, so it runs on a thread of its own.
        if let Err(error) = std::thread::Builder::new()
            .name("siphon-background-cancel".to_string())
            .spawn(|| {
                cancel_all();
            })
        {
            error!(%error, "could not cancel the script's background tasks at shutdown");
        }
    }
}

/// Make sure Tokio calls made while handing the coroutine over have a runtime,
/// as they do on every executor worker.
fn runtime_guard() -> Option<tokio::runtime::EnterGuard<'static>> {
    if tokio::runtime::Handle::try_current().is_ok() {
        None
    } else {
        Some(pyo3_async_runtimes::tokio::get_runtime().enter())
    }
}

/// Whether this thread can start a coroutine directly: inside a step already,
/// or on a thread that is not running an event loop. A driver thread is
/// running one, and a step would take its running loop away.
fn may_start_directly(python: Python<'_>) -> bool {
    if in_direct_step() {
        return true;
    }
    helpers(python)
        .and_then(|helpers| helpers.peek_running_loop.bind(python).call0().ok())
        .is_some_and(|running| running.is_none())
}

/// What a spawned coroutine's outcome goes to, once it has one.
fn completion(
    tracked: Tracked,
    shared: Arc<AwaitableShared>,
    label: String,
    sender: oneshot::Sender<PyResult<Py<PyAny>>>,
) -> Completion {
    Box::new(move |result| {
        if let Err(raised) = &result {
            // Awaiting the handle re-raises it; a failure nothing awaits would
            // otherwise be lost.
            if !shared.observed() {
                crate::script::attach::attach(|python| report_unobserved(python, &label, raised));
            }
        }
        drop(tracked);
        // A cancelled handle has no receiver: the outcome is dropped here.
        let _ = sender.send(result);
    })
}

fn report_unobserved(python: Python<'_>, label: &str, raised: &PyErr) {
    let cancelled = helpers(python)
        .and_then(|helpers| raised.matches(python, &helpers.cancelled_error).ok())
        .unwrap_or(false);
    if cancelled {
        return;
    }
    let traceback = raised
        .traceback(python)
        .and_then(|traceback| traceback.format().ok())
        .unwrap_or_default();
    error!(
        task = %label,
        error = %raised,
        %traceback,
        "a background task started with tasks.spawn failed and nothing was \
         awaiting it; await the handle (or pass it to tasks.wait_first) to \
         handle the error"
    );
}

/// Start `coroutine` as background work and return the awaitable for its
/// outcome.
pub(crate) fn spawn<'py>(
    python: Python<'py>,
    coroutine: &Bound<'py, PyAny>,
    name: Option<String>,
) -> PyResult<Bound<'py, PyAny>> {
    if !coroutine.hasattr(intern!(python, "cr_code"))? {
        return Err(PyTypeError::new_err(
            "tasks.spawn() takes a coroutine: call the async def function and \
             pass the result, e.g. tasks.spawn(release(session))",
        ));
    }
    let pool = AsyncPool::global()
        .ok_or_else(|| PyRuntimeError::new_err("tasks.spawn() needs the script async pool"))?;
    let label = name.unwrap_or_else(|| coroutine_name(coroutine));
    let (sender, receiver) = oneshot::channel::<PyResult<Py<PyAny>>>();
    let handle = awaitable_in_step(python, async move {
        match receiver.await {
            Ok(outcome) => outcome,
            Err(_dropped) => Err(PyRuntimeError::new_err(
                "the background task was dropped before it finished",
            )),
        }
    })?;
    let shared = Arc::clone(&handle.cast::<SiphonAwaitable>()?.get().shared);

    let _entered = runtime_guard();
    let (tracked, entry) = Tracked::start();
    let completion = completion(tracked, Arc::clone(&shared), label, sender);

    let started = if may_start_directly(python) {
        start(&pool, python, coroutine)
    } else {
        None
    };
    let pending = match started {
        Some(DirectStart::Finished(result)) => {
            // It ran to the end in its first step.
            completion(result);
            return Ok(handle);
        }
        Some(DirectStart::Pending(pending)) => pending,
        None => PendingCoroutine::submit(&pool, python, coroutine)?,
    };
    // Cancelling the handle cancels the work, as cancelling a task does.
    let canceller = Arc::new(pending.canceller(python));
    let _ = entry.canceller.set(Arc::clone(&canceller));
    shared.set_on_cancel(Box::new(move |python| {
        canceller.cancel(python);
    }));
    // Bounded by the coroutine timeout, like a handler: a coroutine that never
    // settles is cancelled and its entry released, not kept for the life of
    // the process.
    pending.resume_on_executor(completion);
    Ok(handle)
}
