//! Driving an `async def` handler on its driver's runner, without an asyncio
//! task, for as long as all it awaits is siphon's own awaitables.
//!
//! # Why
//!
//! An awaitable ([`crate::script::blocking::awaitable`]) is a Rust future on
//! tokio. Awaiting one through asyncio costs an event-loop task, a
//! `concurrent.futures.Future`, a completion-thread hop and several
//! `call_soon_threadsafe` round trips, none of which do any of the handler's
//! work. Here the runner steps the coroutine itself: the awaitable yields
//! itself, the step records the coroutine as the awaitable's waiter, and the
//! future's completion posts a wake to the same runner, which converts the
//! value and sends it in.
//!
//! # Ownership
//!
//! A coroutine lives on one driver thread from its first step to teardown.
//! Everything Python about it (the coroutine, its `contextvars.Context`, its
//! [`DirectTask`], the awaitable it waits on) sits in that thread's slab
//! ([`Owner`]) and is only touched there, attached. Other threads hold a
//! [`DriveHandle`], which carries no Python object, and reach the coroutine by
//! posting to its runner. Nothing here waits: no lock is held across Python,
//! and no thread blocks attached.
//!
//! # What keeps it correct
//!
//! A handler is free to use asyncio at any point. A step runs on the loop's
//! own thread inside one of its callbacks, so the running loop is right
//! already; the step puts the handler's [`DirectTask`] in place as the
//! current task and enters the handler's context, as a task would.
//!
//! The first time the handler yields something that is not a siphon awaitable
//! (an asyncio future: `asyncio.sleep`, a task, a foreign future), or asks its
//! task for anything a real task must answer, it is handed over: a real
//! `asyncio.Task` is made on the same thread around a `HandoverCoroutine`,
//! which replays what the last step produced and forwards from then on. Such
//! a handler is remembered and starts as a task from its next call.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::intern;
use pyo3::prelude::*;
use tokio::sync::oneshot;
use tracing::{debug, error};

use super::awaitable::{Registered, SiphonAwaitable};
use super::python::{cancelled_error, helpers, Helpers};
use super::switch::{admission_limit, count_rejection, demote, enabled, is_demoted, DemotionKey};
use super::task::{DirectTask, HandoverCoroutine, HandoverDone};
use super::{Fate, Message, RunnerShared, Work};
use crate::script::async_pool::{AsyncPool, PendingCount};

/// Lock a mutex whose critical sections are a few moves of plain data: a
/// poisoned one is still consistent, and failing here would strand a
/// coroutine.
pub(super) fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

// ---------------------------------------------------------------------------
// The slab.
// ---------------------------------------------------------------------------

/// A slab index and the generation of the slot when the coroutine took it,
/// packed so that it fits an atomic and is never 0.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) struct DriveKey(pub(super) u64);

impl DriveKey {
    fn new(index: usize, generation: u32) -> Self {
        Self((u64::from(generation) << 32) | index as u64)
    }

    fn index(self) -> usize {
        (self.0 & u64::from(u32::MAX)) as usize
    }

    fn generation(self) -> u32 {
        (self.0 >> 32) as u32
    }
}

/// What the step that ended a coroutine's direct phase produced, replayed by
/// the [`HandoverCoroutine`] to the task that takes over.
pub(super) enum First {
    /// The coroutine is suspended, having yielded this.
    Yielded(Py<PyAny>),
    /// The coroutine finished.
    Finished(PyResult<Py<PyAny>>),
}

enum Phase {
    /// A step is running.
    Stepping,
    /// Suspended on this awaitable.
    Waiting(Py<SiphonAwaitable>),
    /// A real asyncio task runs it.
    HandedOver,
}

struct Entry {
    coroutine: Py<PyAny>,
    /// The coroutine's `contextvars.Context`.
    context: Py<PyAny>,
    /// `None` for a handler that started as a task.
    task: Option<Py<DirectTask>>,
    phase: Phase,
    /// The real task, once one exists.
    real: Option<Py<PyAny>>,
    first: Option<First>,
    /// A cancellation the coroutine has not been told about yet. The next
    /// resume throws `CancelledError` into it instead of sending, once.
    cancel_pending: bool,
    /// What `Task.cancel(msg)` was called with, for that `CancelledError`.
    cancel_message: Option<Py<PyAny>>,
    outcome: Arc<Outcome>,
    demotion: DemotionKey,
    // Given back when the entry goes: the coroutine has unwound.
    _admission: Admission,
    _pending: PendingCount,
}

struct Slot<T> {
    generation: u32,
    entry: Option<T>,
}

/// Slots reused under a fresh generation, so that a key held past its
/// coroutine's end never reaches the coroutine that took the slot next.
struct Slab<T> {
    slots: Vec<Slot<T>>,
    free: Vec<usize>,
}

impl<T> Default for Slab<T> {
    fn default() -> Self {
        Self {
            slots: Vec::new(),
            free: Vec::new(),
        }
    }
}

impl<T> Slab<T> {
    fn insert(&mut self, entry: T) -> DriveKey {
        match self.free.pop() {
            Some(index) => {
                let slot = &mut self.slots[index];
                slot.entry = Some(entry);
                DriveKey::new(index, slot.generation)
            }
            None => {
                self.slots.push(Slot {
                    generation: 1,
                    entry: Some(entry),
                });
                DriveKey::new(self.slots.len() - 1, 1)
            }
        }
    }

    fn get_mut(&mut self, key: DriveKey) -> Option<&mut T> {
        let slot = self.slots.get_mut(key.index())?;
        if slot.generation != key.generation() {
            return None;
        }
        slot.entry.as_mut()
    }

    fn remove(&mut self, key: DriveKey) -> Option<T> {
        let slot = self.slots.get_mut(key.index())?;
        if slot.generation != key.generation() {
            return None;
        }
        let entry = slot.entry.take()?;
        // Never 0, so a key is never 0 either.
        slot.generation = slot.generation.checked_add(1).unwrap_or(1);
        self.free.push(key.index());
        Some(entry)
    }

    fn drain(&mut self) -> Vec<T> {
        self.free.clear();
        std::mem::take(&mut self.slots)
            .into_iter()
            .filter_map(|slot| slot.entry)
            .collect()
    }
}

/// What a driver thread owns for direct dispatch. Touched only on that
/// thread, attached, and never borrowed across a call into Python: every
/// access copies out what it needs (`clone_ref`) and returns.
pub(super) struct Owner {
    pub(super) runner: Arc<RunnerShared>,
    pub(super) event_loop: Py<PyAny>,
    slab: Slab<Entry>,
    /// Awaitables whose Rust future has not finished, by id: what a wake finds
    /// its awaitable by, since the future carries no Python object.
    awaitables: HashMap<u64, Py<SiphonAwaitable>>,
    next_awaitable: u64,
}

thread_local! {
    static OWNER: RefCell<Option<Owner>> = const { RefCell::new(None) };
    /// The key of the coroutine this thread is stepping, 0 for none.
    static ACTIVE: Cell<u64> = const { Cell::new(0) };
}

/// Run `work` on this driver thread's state. `None` off a driver thread, once
/// the runner is closed, or if the state is already borrowed (a bug: no borrow
/// is held across Python).
pub(super) fn on_owner<R>(work: impl FnOnce(&mut Owner) -> R) -> Option<R> {
    OWNER
        .try_with(|cell| match cell.try_borrow_mut() {
            Ok(mut owner) => owner.as_mut().map(work),
            Err(_) => {
                error!("script runner state was borrowed across a call into Python");
                None
            }
        })
        .ok()
        .flatten()
}

/// Whether the calling thread is inside a direct step, so an awaitable made
/// now can be awaited without asyncio.
pub(crate) fn in_direct_step() -> bool {
    ACTIVE.try_with(Cell::get).is_ok_and(|key| key != 0)
}

/// The coroutine this thread is stepping.
pub(super) fn active() -> Option<DriveKey> {
    match ACTIVE.try_with(Cell::get) {
        Ok(0) | Err(_) => None,
        Ok(key) => Some(DriveKey(key)),
    }
}

/// Make the calling driver thread the owner of `runner`'s coroutines. Called
/// attached, on the loop's own thread, before the loop runs.
pub(super) fn install_owner(
    python: Python<'_>,
    runner: &Arc<RunnerShared>,
    event_loop: &Bound<'_, PyAny>,
) {
    let _ = python;
    let _ = OWNER.try_with(|cell| {
        if let Ok(mut owner) = cell.try_borrow_mut() {
            *owner = Some(Owner {
                runner: Arc::clone(runner),
                event_loop: event_loop.clone().unbind(),
                slab: Slab::default(),
                awaitables: HashMap::new(),
                next_awaitable: 1,
            });
        }
    });
}

/// The runner is closing: close every coroutine still in the slab, fail what
/// waits for it, and let go of every Python object. Called attached, on the
/// owner thread, once the loop has stopped.
pub(super) fn close_owner(python: Python<'_>) {
    let owner = OWNER
        .try_with(|cell| {
            cell.try_borrow_mut()
                .ok()
                .and_then(|mut owner| owner.take())
        })
        .ok()
        .flatten();
    let Some(mut owner) = owner else { return };
    for entry in owner.slab.drain() {
        owner.runner.drives.fetch_sub(1, Ordering::Relaxed);
        if let Some(task) = &entry.task {
            task.get().mark_done(false);
            // The ring through the task it was handed to, which will never
            // run to the end that breaks it.
            drop(task.get().forget_real());
        }
        if entry.real.is_none() {
            // Its `finally` blocks run here, attached, on its own thread.
            if let Err(error) = entry
                .coroutine
                .bind(python)
                .call_method0(intern!(python, "close"))
            {
                debug!(%error, "closing a handler coroutine at shutdown raised");
            }
        }
        entry.outcome.deliver(Err(shut_down()));
        drop(entry);
    }
    for (_, awaitable) in owner.awaitables.drain() {
        owner.runner.awaitables.fetch_sub(1, Ordering::Relaxed);
        awaitable.get().abandon(python);
    }
    drop(owner);
}

fn shut_down() -> PyErr {
    PyRuntimeError::new_err("the asyncio driver shut down before the async handler finished")
}

/// Register an awaitable made on this driver thread until its future ends.
pub(super) fn track_awaitable(awaitable: Py<SiphonAwaitable>, id: u64) -> bool {
    on_owner(|owner| {
        owner.awaitables.insert(id, awaitable);
        owner.runner.awaitables.fetch_add(1, Ordering::Relaxed);
    })
    .is_some()
}

/// A fresh awaitable id and what an awaitable needs of its owner.
pub(super) fn next_awaitable(python: Python<'_>) -> Option<(u64, Arc<RunnerShared>, Py<PyAny>)> {
    on_owner(|owner| {
        let id = owner.next_awaitable;
        owner.next_awaitable += 1;
        (
            id,
            Arc::clone(&owner.runner),
            owner.event_loop.clone_ref(python),
        )
    })
}

/// Stop tracking awaitable `id`; the caller drops what comes back, attached.
pub(super) fn untrack_awaitable(id: u64) -> Option<Py<SiphonAwaitable>> {
    on_owner(|owner| {
        let awaitable = owner.awaitables.remove(&id);
        if awaitable.is_some() {
            owner.runner.awaitables.fetch_sub(1, Ordering::Relaxed);
        }
        awaitable
    })
    .flatten()
}

// ---------------------------------------------------------------------------
// What other threads hold.
// ---------------------------------------------------------------------------

/// One reserved place among a runner's handlers in flight.
pub(crate) struct Admission(Arc<RunnerShared>);

impl Admission {
    pub(crate) fn runner(&self) -> &Arc<RunnerShared> {
        &self.0
    }
}

impl Drop for Admission {
    fn drop(&mut self) {
        self.0.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

impl RunnerShared {
    /// Reserve a place for one more handler unless `limit` are in flight.
    /// Never waits.
    pub(crate) fn try_admit(self: &Arc<Self>, limit: usize) -> Option<Admission> {
        if self.is_shut_down() {
            return None;
        }
        self.in_flight
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |in_flight| {
                (in_flight < limit).then_some(in_flight + 1)
            })
            .ok()
            .map(|_| Admission(Arc::clone(self)))
    }
}

/// Where a coroutine's result goes, shared by its waiter and its runner.
/// Holds no Python object while nobody has sent one.
pub(super) struct Outcome {
    sender: Mutex<Option<oneshot::Sender<PyResult<Py<PyAny>>>>>,
    /// The coroutine's slab key once its start has run, 0 before.
    key: AtomicU64,
    /// The waiter gave up; a start that has not run yet must not.
    abandoned: AtomicBool,
    /// Signalled when the coroutine is over, for a watchdog that outlives a
    /// caller who went away.
    over: tokio::sync::Notify,
}

impl Outcome {
    /// Hand the result to the waiter. If it gave up, the result is dropped
    /// here, on the runner, attached.
    fn deliver(&self, result: PyResult<Py<PyAny>>) {
        let sender = locked(&self.sender).take();
        if let Some(sender) = sender {
            // A waiter that went away without giving up: dropped here too.
            drop(sender.send(result));
        } else {
            drop(result);
        }
        self.over.notify_one();
    }

    /// The waiter stops waiting. `false` if the result was sent first.
    fn give_up(&self) -> bool {
        let sender = locked(&self.sender).take();
        sender.is_some()
    }
}

/// A coroutine running on a runner, as its caller holds it: no Python object,
/// so it can be awaited and dropped on any thread.
///
/// Dropped before the coroutine is over (the caller's future was dropped), it
/// leaves the coroutine running, as a caller of the asyncio path does, but
/// keeps the coroutine timeout armed: a handler nobody waits for is still
/// cancelled when its time is up.
pub(crate) struct DriveHandle {
    /// `None` once the wait is over.
    waiting: Option<Waiting>,
}

struct Waiting {
    runner: Arc<RunnerShared>,
    outcome: Arc<Outcome>,
    receiver: oneshot::Receiver<PyResult<Py<PyAny>>>,
    deadline: tokio::time::Instant,
    timeout: Duration,
}

/// How waiting for a [`DriveHandle`] ended.
pub(crate) enum Waited {
    /// The handler's value, or what it raised.
    Settled(PyResult<Py<PyAny>>),
    /// It outlived the coroutine timeout and has been cancelled.
    TimedOut(Duration),
}

fn lost() -> Waited {
    Waited::Settled(Err(PyValueError::new_err(
        "script runner dropped the coroutine before completion",
    )))
}

impl Waiting {
    async fn settle(&mut self) -> Waited {
        match tokio::time::timeout_at(self.deadline, &mut self.receiver).await {
            Ok(Ok(result)) => Waited::Settled(result),
            Ok(Err(_closed)) => lost(),
            Err(_elapsed) => {
                if self.outcome.give_up() {
                    self.cancel();
                    Waited::TimedOut(self.timeout)
                } else {
                    // The result was sent as the timer fired.
                    match (&mut self.receiver).await {
                        Ok(result) => Waited::Settled(result),
                        Err(_closed) => lost(),
                    }
                }
            }
        }
    }

    /// The coroutine timeout ran out: cancel the coroutine on its runner.
    fn cancel(&self) {
        self.outcome.abandoned.store(true, Ordering::SeqCst);
        let outcome = Arc::clone(&self.outcome);
        let reason = CancelReason::Timeout(self.timeout);
        // Refused only by a runner that has shut down, which closes the
        // coroutine itself.
        let _ = self
            .runner
            .post(Message::Cancel(Work::new(move |python, fate| {
                if fate == Fate::Abandoned {
                    return;
                }
                let key = outcome.key.load(Ordering::SeqCst);
                if key != 0 {
                    cancel_drive(python, DriveKey(key), reason);
                }
            })));
    }

    /// The caller went away. Its result is the runner's to drop from now on,
    /// and the timeout still stands: wait for the coroutine to be over or for
    /// its deadline, whichever is first, holding no Python object.
    async fn watch_unattended(self) {
        let over = self.outcome.over.notified();
        if tokio::time::timeout_at(self.deadline, over).await.is_err() {
            self.cancel();
        }
    }
}

impl DriveHandle {
    /// Wait for the coroutine's result, for at most the coroutine timeout.
    /// Touches no Python object and never attaches. On timeout the coroutine
    /// is cancelled on its runner and the result, if one still comes, is
    /// dropped there.
    pub(crate) async fn wait(mut self) -> Waited {
        let Some(waiting) = self.waiting.as_mut() else {
            return lost();
        };
        let waited = waiting.settle().await;
        // Over: nothing is left for `Drop` to watch.
        self.waiting = None;
        waited
    }
}

impl Drop for DriveHandle {
    fn drop(&mut self) {
        let Some(waiting) = self.waiting.take() else {
            return;
        };
        if !waiting.outcome.give_up() {
            // Its result was sent already; it goes with the receiver.
            return;
        }
        pyo3_async_runtimes::tokio::get_runtime().spawn(waiting.watch_unattended());
    }
}

/// The error a caller gets for a handler that outlived the coroutine timeout.
pub(crate) fn timeout_error(handler: &str, timeout: Duration) -> PyErr {
    pyo3::exceptions::PyTimeoutError::new_err(format!(
        "async handler '{handler}' did not settle within {}s",
        timeout.as_secs()
    ))
}

// ---------------------------------------------------------------------------
// Start.
// ---------------------------------------------------------------------------

struct StartRequest {
    coroutine: Py<PyAny>,
    context: Py<PyAny>,
    outcome: Arc<Outcome>,
    demotion: DemotionKey,
    admission: Admission,
    pending: PendingCount,
}

/// Start `coroutine` on a runner without an asyncio task.
///
/// Call attached, on the thread that made the coroutine. `handler` is the
/// callable it came from, which a handler that turns out to use asyncio is
/// remembered by.
///
/// `Ok(None)` leaves the coroutine untouched for the caller to run as a task:
/// direct dispatch is off, or the handler is known to use asyncio. `Err` means
/// every runner is full: the coroutine has been closed and the call must fail.
pub(crate) fn start(
    pool: &Arc<AsyncPool>,
    python: Python<'_>,
    coroutine: &Bound<'_, PyAny>,
    handler: Option<&Arc<Py<PyAny>>>,
) -> PyResult<Option<DriveHandle>> {
    if !enabled() {
        return Ok(None);
    }
    start_unchecked(pool, python, coroutine, handler)
}

pub(super) fn start_unchecked(
    pool: &Arc<AsyncPool>,
    python: Python<'_>,
    coroutine: &Bound<'_, PyAny>,
    handler: Option<&Arc<Py<PyAny>>>,
) -> PyResult<Option<DriveHandle>> {
    let demotion = match handler {
        Some(handler) => DemotionKey::new(Arc::clone(handler)),
        None => match coroutine.getattr(intern!(python, "cr_code")) {
            Ok(code) => DemotionKey::new(Arc::new(code.unbind())),
            // Not a native coroutine: nothing to remember it by.
            Err(_) => return Ok(None),
        },
    };
    if is_demoted(&demotion) {
        return Ok(None);
    }
    let limit = admission_limit();
    let Some(admission) = pool.admit(limit) else {
        count_rejection(limit);
        // Never started: closed so it is not reported as never awaited.
        let _ = coroutine.call_method0(intern!(python, "close"));
        return Err(PyRuntimeError::new_err(format!(
            "async handler refused: every asyncio driver has {limit} handlers in flight"
        )));
    };
    // SAFETY: attached; a new reference, or NULL with an exception set.
    let context =
        unsafe { Bound::from_owned_ptr_or_err(python, pyo3::ffi::PyContext_CopyCurrent())? };
    let (sender, receiver) = oneshot::channel();
    let outcome = Arc::new(Outcome {
        sender: Mutex::new(Some(sender)),
        key: AtomicU64::new(0),
        abandoned: AtomicBool::new(false),
        over: tokio::sync::Notify::new(),
    });
    let runner = Arc::clone(admission.runner());
    let request = StartRequest {
        coroutine: coroutine.clone().unbind(),
        context: context.unbind(),
        outcome: Arc::clone(&outcome),
        demotion,
        admission,
        pending: PendingCount::start(),
    };
    let posted = runner.post(Message::Start(Work::new(move |python, fate| {
        run_start(python, fate, request);
    })));
    if let Err(Message::Start(work) | Message::Wake(work) | Message::Cancel(work)) = posted {
        // The runner shut down between the admission and the post: the
        // request fails its waiter and closes the coroutine, here.
        work.abandon(python);
    }
    let timeout = pool.coroutine_timeout();
    Ok(Some(DriveHandle {
        waiting: Some(Waiting {
            runner,
            outcome,
            receiver,
            deadline: tokio::time::Instant::now() + timeout,
            timeout,
        }),
    }))
}

/// On the runner: the first step of a newly admitted coroutine.
fn run_start(python: Python<'_>, fate: Fate, request: StartRequest) {
    let StartRequest {
        coroutine,
        context,
        outcome,
        demotion,
        admission,
        pending,
    } = request;
    let refuse = |error: Option<PyErr>| {
        if let Err(raised) = coroutine
            .bind(python)
            .call_method0(intern!(python, "close"))
        {
            debug!(error = %raised, "closing a handler coroutine that never started raised");
        }
        if let Some(error) = error {
            outcome.deliver(Err(error));
        }
    };
    if fate == Fate::Abandoned {
        return refuse(Some(shut_down()));
    }
    if outcome.abandoned.load(Ordering::SeqCst) {
        // Its waiter timed out before it could start.
        return refuse(None);
    }
    let Some(helpers) = helpers(python) else {
        return refuse(Some(PyRuntimeError::new_err(
            "the direct-dispatch helpers are missing",
        )));
    };
    let Some((runner, event_loop)) = on_owner(|owner| {
        (
            Arc::clone(&owner.runner),
            owner.event_loop.clone_ref(python),
        )
    }) else {
        return refuse(Some(shut_down()));
    };

    // With a task factory on the loop the handler starts as a task: an eager
    // one runs coroutines inside whatever step creates them, where an awaited
    // siphon awaitable would be yielded to a task that cannot take it.
    let as_task = helpers
        .has_task_factory
        .bind(python)
        .call1((&event_loop,))
        .and_then(|has| has.extract::<bool>())
        .unwrap_or(true);
    let task = if as_task {
        None
    } else {
        match Py::new(
            python,
            DirectTask::new(Arc::clone(&runner), event_loop.clone_ref(python)),
        ) {
            Ok(task) => Some(task),
            Err(error) => return refuse(Some(error)),
        }
    };
    let entry = Entry {
        coroutine,
        context,
        task: task.as_ref().map(|task| task.clone_ref(python)),
        phase: if as_task {
            Phase::HandedOver
        } else {
            Phase::Stepping
        },
        real: None,
        first: None,
        cancel_pending: false,
        cancel_message: None,
        outcome: Arc::clone(&outcome),
        demotion,
        _admission: admission,
        _pending: pending,
    };
    let Some(key) = on_owner(|owner| {
        owner.runner.drives.fetch_add(1, Ordering::Relaxed);
        owner.slab.insert(entry)
    }) else {
        // Unreachable: the owner was there a moment ago. The entry went with
        // the closure; its waiter learns from the dropped sender.
        return;
    };
    outcome.key.store(key.0, Ordering::SeqCst);
    match task {
        Some(task) => {
            task.get().bind_key(key);
            runner.direct_starts.fetch_add(1, Ordering::Relaxed);
            step(python, key);
        }
        None => start_as_task(python, helpers, key, &event_loop),
    }
}

/// On the runner: run the coroutine in slab entry `key` as an asyncio task
/// from its first step.
fn start_as_task(python: Python<'_>, helpers: &Helpers, key: DriveKey, event_loop: &Py<PyAny>) {
    let Some(Some((coroutine, context))) = on_owner(|owner| {
        let entry = owner.slab.get_mut(key)?;
        Some((
            entry.coroutine.clone_ref(python),
            entry.context.clone_ref(python),
        ))
    }) else {
        return;
    };
    let made = Py::new(python, HandoverDone::new(key)).and_then(|done| {
        helpers
            .start_task
            .bind(python)
            .call1((event_loop, &coroutine, &context, done))
    });
    match made {
        Ok(real) => {
            let real = real.unbind();
            let stale = on_owner(|owner| {
                owner
                    .slab
                    .get_mut(key)
                    .and_then(|entry| entry.real.replace(real))
            });
            drop(stale);
        }
        Err(error) => {
            let _ = coroutine
                .bind(python)
                .call_method0(intern!(python, "close"));
            finish(python, key, Err(error));
        }
    }
}

// ---------------------------------------------------------------------------
// A step.
// ---------------------------------------------------------------------------

/// What one `send` into the coroutine came to.
enum Sent<'py> {
    Yielded(Bound<'py, PyAny>),
    Returned(Bound<'py, PyAny>),
    Raised(PyErr),
}

/// What a step needs of its entry, copied out so that no borrow of the slab
/// is held while the coroutine runs.
struct Prepared {
    coroutine: Py<PyAny>,
    context: Py<PyAny>,
    task: Py<DirectTask>,
    event_loop: Py<PyAny>,
    cancel: bool,
    cancel_message: Option<Py<PyAny>>,
}

/// How a coroutine that yielded a siphon awaitable goes on.
enum Suspend {
    /// The awaitable's completion wakes it.
    Waiting,
    /// Resume at once: the awaitable has finished, or a cancellation is due.
    Resume,
    /// It waits for the awaitable as an asyncio future.
    HandOver,
}

/// Marks the calling thread as stepping a coroutine, and puts back what was
/// there when dropped: also if the step unwinds, so that a panic cannot leave
/// the thread looking as if it were inside a step for ever.
struct Stepping {
    outer: u64,
}

impl Stepping {
    fn enter(key: DriveKey) -> Self {
        Self {
            outer: ACTIVE.replace(key.0),
        }
    }
}

impl Drop for Stepping {
    fn drop(&mut self) {
        let _ = ACTIVE.try_with(|active| active.set(self.outer));
    }
}

/// Run the coroutine in slab entry `key` until it finishes, suspends on a
/// siphon awaitable, or has to be handed to asyncio. Call attached, on the
/// owner thread, from a runner item.
pub(super) fn step(python: Python<'_>, key: DriveKey) {
    let Some(helpers) = helpers(python) else {
        finish(
            python,
            key,
            Err(PyRuntimeError::new_err(
                "the direct-dispatch helpers are missing",
            )),
        );
        return;
    };
    loop {
        let prepared = on_owner(|owner| {
            let event_loop = owner.event_loop.clone_ref(python);
            let runner = Arc::clone(&owner.runner);
            let entry = owner.slab.get_mut(key)?;
            if entry.real.is_some() && matches!(entry.phase, Phase::HandedOver) {
                // A task runs it now.
                return None;
            }
            let task = entry.task.as_ref()?.clone_ref(python);
            let was = std::mem::replace(&mut entry.phase, Phase::Stepping);
            runner.direct_steps.fetch_add(1, Ordering::Relaxed);
            Some((
                Prepared {
                    coroutine: entry.coroutine.clone_ref(python),
                    context: entry.context.clone_ref(python),
                    task,
                    event_loop,
                    cancel: std::mem::take(&mut entry.cancel_pending),
                    cancel_message: entry.cancel_message.take(),
                },
                was,
            ))
        })
        .flatten();
        let Some((prepared, was)) = prepared else {
            return;
        };
        // The awaitable it waited on, let go of outside the borrow.
        drop(was);

        let sent = {
            let _stepping = Stepping::enter(key);
            resume(python, helpers, &prepared)
        };

        let materialised = on_owner(|owner| {
            owner
                .slab
                .get_mut(key)
                .is_some_and(|entry| entry.real.is_some())
        })
        .unwrap_or(false);
        match sent {
            Sent::Yielded(yielded) => {
                if !materialised {
                    if let Ok(awaitable) = yielded.cast::<SiphonAwaitable>() {
                        match suspend_on(python, key, awaitable) {
                            Suspend::Waiting => return,
                            Suspend::Resume => continue,
                            Suspend::HandOver => {}
                        }
                    }
                }
                hand_over(python, key, First::Yielded(yielded.unbind()));
            }
            Sent::Returned(value) if materialised => {
                hand_over(python, key, First::Finished(Ok(value.unbind())));
            }
            Sent::Raised(error) if materialised => {
                hand_over(python, key, First::Finished(Err(error)));
            }
            Sent::Returned(value) => {
                // Cancelled during the step that returned: the handler ends
                // cancelled, as an asyncio task does.
                let cancelled = on_owner(|owner| {
                    owner
                        .slab
                        .get_mut(key)
                        .is_some_and(|entry| std::mem::take(&mut entry.cancel_pending))
                })
                .unwrap_or(false);
                let result = if cancelled {
                    Err(cancelled_error(python))
                } else {
                    Ok(value.unbind())
                };
                finish(python, key, result);
            }
            Sent::Raised(error) => finish(python, key, Err(error)),
        }
        return;
    }
}

/// One resume with the handler's task as the current task and its context
/// entered: `send(None)`, or `throw(CancelledError)` when a cancellation is
/// due. The running loop is this thread's already.
fn resume<'py>(python: Python<'py>, helpers: &Helpers, prepared: &Prepared) -> Sent<'py> {
    let swap_task = helpers.swap_current_task.bind(python);
    let coroutine = prepared.coroutine.bind(python);
    let previous = match swap_task.call1((&prepared.event_loop, &prepared.task)) {
        Ok(previous) => previous,
        Err(error) => {
            // The coroutine did not run and cannot: close it, so the call
            // fails with what went wrong rather than hanging.
            let _ = coroutine.call_method0(intern!(python, "close"));
            return Sent::Raised(error);
        }
    };
    // SAFETY: attached; `context` is a `contextvars.Context`. Enter and exit
    // are paired on this thread around the one call.
    let entered = unsafe { pyo3::ffi::PyContext_Enter(prepared.context.as_ptr()) } == 0;
    let sent = if entered {
        let sent = if prepared.cancel {
            throw_cancelled(coroutine, prepared.cancel_message.as_ref())
        } else {
            send_none(coroutine)
        };
        // SAFETY: as above; entered just before on this thread.
        if unsafe { pyo3::ffi::PyContext_Exit(prepared.context.as_ptr()) } != 0 {
            // Unreachable for a context this thread entered. Fetched so it is
            // not raised by an unrelated call later.
            let error = PyErr::fetch(python);
            error!(%error, "could not leave an async handler's context after its step");
        }
        sent
    } else {
        let error = PyErr::fetch(python);
        let _ = coroutine.call_method0(intern!(python, "close"));
        Sent::Raised(error)
    };
    if let Err(error) = swap_task.call1((&prepared.event_loop, previous)) {
        error!(%error, "could not restore the current asyncio task after an async handler's step");
    }
    sent
}

/// The coroutine yielded a siphon awaitable in a step with no real task.
fn suspend_on(
    python: Python<'_>,
    key: DriveKey,
    awaitable: &Bound<'_, SiphonAwaitable>,
) -> Suspend {
    let cancel_due = on_owner(|owner| {
        owner
            .slab
            .get_mut(key)
            .is_some_and(|entry| entry.cancel_pending)
    })
    .unwrap_or(false);
    if cancel_due {
        // Cancelled before it could wait: the awaitable is cancelled as a
        // task's is, and the next resume throws.
        awaitable.get().cancel_without_wake(python);
        return Suspend::Resume;
    }
    match awaitable.get().register(key) {
        Registered::Waiting => {
            let waiting = awaitable.clone().unbind();
            let parked = on_owner(|owner| match owner.slab.get_mut(key) {
                Some(entry) => {
                    entry.phase = Phase::Waiting(waiting);
                    true
                }
                None => false,
            })
            .unwrap_or(false);
            if parked {
                Suspend::Waiting
            } else {
                awaitable.get().forget_waiter(key);
                Suspend::Resume
            }
        }
        Registered::Finished => Suspend::Resume,
        // Another coroutine waits on it already, or it belongs to another
        // driver: this one waits for it as an asyncio future.
        Registered::Elsewhere => Suspend::HandOver,
    }
}

/// On the runner: awaitable `id`'s future finished with `build`.
pub(super) fn complete_awaitable(
    python: Python<'_>,
    fate: Fate,
    id: u64,
    build: super::awaitable::BuildValue,
) {
    if fate == Fate::Abandoned {
        // The owner is closing; it lets go of the awaitable itself. The value
        // was never built.
        drop(build);
        return;
    }
    let Some(awaitable) = untrack_awaitable(id) else {
        // Cancelled while its future was finishing.
        drop(build);
        return;
    };
    let waiter = awaitable.get().settle(python, build);
    if let Some(key) = waiter {
        wake(python, key, id);
    }
    drop(awaitable);
}

/// Step coroutine `key` if it is still waiting on awaitable `id`.
pub(super) fn wake(python: Python<'_>, key: DriveKey, id: u64) {
    let waiting = on_owner(|owner| {
        owner.slab.get_mut(key).is_some_and(
            |entry| matches!(&entry.phase, Phase::Waiting(awaitable) if awaitable.get().id() == id),
        )
    })
    .unwrap_or(false);
    if waiting {
        step(python, key);
    }
}

// ---------------------------------------------------------------------------
// Finishing and handing over.
// ---------------------------------------------------------------------------

/// The coroutine in `key` is over: release its slab entry and hand the result
/// to its waiter.
pub(super) fn finish(python: Python<'_>, key: DriveKey, result: PyResult<Py<PyAny>>) {
    let entry = on_owner(|owner| {
        let entry = owner.slab.remove(key);
        if entry.is_some() {
            owner.runner.drives.fetch_sub(1, Ordering::Relaxed);
        }
        entry
    })
    .flatten();
    let Some(entry) = entry else {
        // The owner closed and failed the waiter already.
        drop(result);
        return;
    };
    if let Some(task) = &entry.task {
        let cancelled = result.as_ref().is_err_and(|error| {
            helpers(python).is_some_and(|helpers| {
                error
                    .matches(python, &helpers.cancelled_error)
                    .unwrap_or(false)
            })
        });
        task.get().mark_done(cancelled);
    }
    entry.outcome.deliver(result);
    // The coroutine, its context and its task go here: attached, on the
    // thread that ran them.
    let _ = python;
    drop(entry);
}

/// Create the real asyncio task for the coroutine in `key`, on this thread.
/// The task does nothing until the step in progress ends and leaves it
/// something to replay ([`First`]).
pub(super) fn materialise(python: Python<'_>, key: DriveKey) -> PyResult<Py<PyAny>> {
    let gone = || PyRuntimeError::new_err("this handler has finished");
    let copied = on_owner(|owner| {
        let event_loop = owner.event_loop.clone_ref(python);
        let entry = owner.slab.get_mut(key)?;
        Some(match &entry.real {
            Some(real) => Err(real.clone_ref(python)),
            None => Ok((
                entry.coroutine.clone_ref(python),
                entry.context.clone_ref(python),
                entry.task.as_ref().map(|task| task.clone_ref(python)),
                entry.demotion.clone(),
                event_loop,
            )),
        })
    })
    .flatten()
    .ok_or_else(gone)?;
    let (coroutine, context, task, demotion, event_loop) = match copied {
        Ok(copied) => copied,
        Err(real) => return Ok(real),
    };
    let task = task.ok_or_else(gone)?;
    let helpers = helpers(python)
        .ok_or_else(|| PyRuntimeError::new_err("the direct-dispatch helpers are missing"))?;
    let handover = Py::new(
        python,
        HandoverCoroutine::new(
            key,
            coroutine,
            event_loop.clone_ref(python),
            task.clone_ref(python),
        ),
    )?;
    let done = Py::new(python, HandoverDone::new(key))?;
    let real = helpers
        .make_task
        .bind(python)
        .call1((&event_loop, handover, &context, done))?
        .unbind();
    task.get().set_real(real.clone_ref(python));
    let stored = real.clone_ref(python);
    let stale = on_owner(|owner| {
        owner
            .slab
            .get_mut(key)
            .and_then(|entry| entry.real.replace(stored))
    });
    drop(stale);
    // Remembered now, not when the step ends: calls of this handler that
    // start meanwhile go straight to a task.
    demote(python, &demotion);
    Ok(real)
}

/// End the direct phase of the coroutine in `key`: a real task continues from
/// `first`.
pub(super) fn hand_over(python: Python<'_>, key: DriveKey, first: First) {
    let real = match materialise(python, key) {
        Ok(real) => real,
        Err(error) => {
            // The coroutine is mid-flight and no task can take it. Say so,
            // and close it so its `finally` blocks run, rather than leave it
            // suspended for ever.
            error!(
                %error,
                "an async handler could not be handed to an asyncio task; \
                 failing the call"
            );
            let coroutine = on_owner(|owner| {
                owner
                    .slab
                    .get_mut(key)
                    .map(|entry| entry.coroutine.clone_ref(python))
            })
            .flatten();
            if let Some(coroutine) = coroutine {
                let _ = coroutine
                    .bind(python)
                    .call_method0(intern!(python, "close"));
            }
            drop(first);
            finish(python, key, Err(error));
            return;
        }
    };
    let mut first = Some(first);
    let placed = on_owner(|owner| {
        let entry = owner.slab.get_mut(key)?;
        entry.first = first.take();
        let was = std::mem::replace(&mut entry.phase, Phase::HandedOver);
        // A cancellation the coroutine was not told about goes to the task
        // that takes it over.
        Some((
            was,
            std::mem::take(&mut entry.cancel_pending),
            entry.cancel_message.take(),
        ))
    })
    .flatten();
    // Not placed: the owner is gone. Dropped here, attached.
    drop(first);
    let Some((was, cancel, message)) = placed else {
        return;
    };
    drop(was);
    if cancel {
        if let Err(error) = real
            .bind(python)
            .call_method1(intern!(python, "cancel"), (message,))
        {
            error!(%error, "could not cancel a handler handed to an asyncio task");
        }
    }
}

/// What the last direct step left for the real task, once.
pub(super) fn take_first(key: DriveKey) -> Option<First> {
    on_owner(|owner| owner.slab.get_mut(key).and_then(|entry| entry.first.take())).flatten()
}

/// Hand the coroutine in `key` to a real task from outside its own step,
/// while it is suspended on a siphon awaitable: something on its loop asked
/// its task for what only a real task answers.
pub(super) fn hand_over_suspended(python: Python<'_>, key: DriveKey) -> PyResult<Py<PyAny>> {
    let waiting = on_owner(|owner| {
        let entry = owner.slab.get_mut(key)?;
        if entry.real.is_some() {
            return None;
        }
        match std::mem::replace(&mut entry.phase, Phase::Stepping) {
            Phase::Waiting(awaitable) => Some(awaitable),
            other => {
                entry.phase = other;
                None
            }
        }
    })
    .flatten();
    match waiting {
        Some(awaitable) => {
            awaitable.get().forget_waiter(key);
            hand_over(python, key, First::Yielded(awaitable.into_any()));
        }
        None => {
            // Already a task, or mid-step: `materialise` answers both.
        }
    }
    materialise(python, key)
}

// ---------------------------------------------------------------------------
// Cancellation.
// ---------------------------------------------------------------------------

/// Why a coroutine is being cancelled.
#[derive(Clone, Copy)]
pub(super) enum CancelReason {
    /// Its task was asked to (`Task.cancel()`).
    Task,
    /// Its waiter gave up after the coroutine timeout.
    Timeout(Duration),
}

/// Cancel the coroutine in `key` wherever it is, as `asyncio.Task.cancel`
/// does: its awaitable's Rust future is dropped and `CancelledError` is thrown
/// into it, once. `false` if it has finished. Call attached, on the owner
/// thread, from a runner item.
pub(super) fn cancel_drive(python: Python<'_>, key: DriveKey, reason: CancelReason) -> bool {
    enum Target {
        Nothing,
        Task(Py<PyAny>),
        Awaitable(Py<SiphonAwaitable>),
        /// Mid-step: the step sees the flag.
        Step,
    }
    let found = on_owner(|owner| {
        let Some(entry) = owner.slab.get_mut(key) else {
            return (Target::Nothing, None);
        };
        let coroutine =
            matches!(reason, CancelReason::Timeout(_)).then(|| entry.coroutine.clone_ref(python));
        if let Some(real) = &entry.real {
            return (Target::Task(real.clone_ref(python)), coroutine);
        }
        entry.cancel_pending = true;
        match std::mem::replace(&mut entry.phase, Phase::Stepping) {
            Phase::Waiting(awaitable) => (Target::Awaitable(awaitable), coroutine),
            other => {
                entry.phase = other;
                (Target::Step, coroutine)
            }
        }
    });
    let Some((target, coroutine)) = found else {
        return false;
    };
    let cancelled = !matches!(target, Target::Nothing);
    if let (CancelReason::Timeout(timeout), Some(coroutine)) = (reason, coroutine) {
        let handler = crate::script::async_pool::coroutine_name(coroutine.bind(python));
        error!(
            handler = %handler,
            timeout_secs = timeout.as_secs(),
            cancelled,
            "async script handler did not settle within the coroutine timeout; \
             failing this call. The handler is awaiting something that never \
             completes — an unbounded backend call, a DNS lookup, or a future \
             nothing resolves."
        );
    }
    match target {
        Target::Nothing => false,
        Target::Step => true,
        Target::Task(real) => real
            .bind(python)
            .call_method0(intern!(python, "cancel"))
            .and_then(|cancelled| cancelled.extract::<bool>())
            .unwrap_or(false),
        Target::Awaitable(awaitable) => {
            awaitable.get().cancel_without_wake(python);
            drop(awaitable);
            step(python, key);
            true
        }
    }
}

/// Note a cancellation requested on the coroutine's own thread: from its own
/// step it is thrown at its next await, from anywhere else on the thread the
/// caller posts the cancel that throws it. `false` if `key` is not there any
/// more.
pub(super) fn note_cancel(key: DriveKey, message: Option<Py<PyAny>>, pending: bool) -> bool {
    let mut message = message;
    let noted = on_owner(|owner| match owner.slab.get_mut(key) {
        Some(entry) => {
            entry.cancel_pending |= pending;
            Some(std::mem::replace(&mut entry.cancel_message, message.take()))
        }
        None => None,
    })
    .flatten();
    // An earlier message, or this one if the coroutine is gone: dropped
    // outside the borrow.
    drop(message);
    noted.is_some()
}

/// Withdraw a cancellation the coroutine has not been told about.
pub(super) fn withdraw_cancel(key: DriveKey) {
    let message = on_owner(|owner| {
        owner.slab.get_mut(key).and_then(|entry| {
            entry.cancel_pending = false;
            entry.cancel_message.take()
        })
    });
    drop(message);
}

/// `CancelledError(message)`, or a bare one.
fn cancelled_error_with(python: Python<'_>, message: Option<&Py<PyAny>>) -> PyErr {
    let (Some(message), Some(helpers)) = (message, helpers(python)) else {
        return cancelled_error(python);
    };
    match helpers.cancelled_error.bind(python).call1((message,)) {
        Ok(error) => PyErr::from_value(error),
        Err(error) => error,
    }
}

/// The coroutine and context of `key`, for its task's accessors.
pub(super) fn coroutine_and_context(
    python: Python<'_>,
    key: DriveKey,
) -> Option<(Py<PyAny>, Py<PyAny>)> {
    on_owner(|owner| {
        owner.slab.get_mut(key).map(|entry| {
            (
                entry.coroutine.clone_ref(python),
                entry.context.clone_ref(python),
            )
        })
    })
    .flatten()
}

/// The task of the coroutine this thread is stepping.
pub(super) fn active_task(python: Python<'_>) -> Option<Py<DirectTask>> {
    let key = active()?;
    on_owner(|owner| {
        owner
            .slab
            .get_mut(key)
            .and_then(|entry| entry.task.as_ref().map(|task| task.clone_ref(python)))
    })
    .flatten()
}

/// `coroutine.throw(CancelledError(message))`.
fn throw_cancelled<'py>(coroutine: &Bound<'py, PyAny>, message: Option<&Py<PyAny>>) -> Sent<'py> {
    let python = coroutine.py();
    let cancelled = cancelled_error_with(python, message).into_value(python);
    match coroutine.call_method1(intern!(python, "throw"), (cancelled,)) {
        Ok(yielded) => Sent::Yielded(yielded),
        Err(error) if error.is_instance_of::<pyo3::exceptions::PyStopIteration>(python) => {
            // It caught the cancellation and returned.
            match error.value(python).getattr(intern!(python, "value")) {
                Ok(value) => Sent::Returned(value),
                Err(error) => Sent::Raised(error),
            }
        }
        Err(error) => Sent::Raised(error),
    }
}

/// `coroutine.send(None)`.
fn send_none<'py>(coroutine: &Bound<'py, PyAny>) -> Sent<'py> {
    let python = coroutine.py();
    let mut result: *mut pyo3::ffi::PyObject = std::ptr::null_mut();
    // SAFETY: attached; `coroutine` is a live object and `result` receives a
    // new reference on `PYGEN_NEXT` and `PYGEN_RETURN`, NULL with an
    // exception set on `PYGEN_ERROR`.
    let status =
        unsafe { pyo3::ffi::PyIter_Send(coroutine.as_ptr(), pyo3::ffi::Py_None(), &mut result) };
    match status {
        pyo3::ffi::PySendResult::PYGEN_NEXT | pyo3::ffi::PySendResult::PYGEN_RETURN
            if result.is_null() =>
        {
            Sent::Raised(PyErr::fetch(python))
        }
        // SAFETY: a new, non-null reference, per the status.
        pyo3::ffi::PySendResult::PYGEN_NEXT => {
            Sent::Yielded(unsafe { Bound::from_owned_ptr(python, result) })
        }
        // SAFETY: as above.
        pyo3::ffi::PySendResult::PYGEN_RETURN => {
            Sent::Returned(unsafe { Bound::from_owned_ptr(python, result) })
        }
        pyo3::ffi::PySendResult::PYGEN_ERROR => Sent::Raised(PyErr::fetch(python)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_packs_its_index_and_generation_and_is_never_zero() {
        let key = DriveKey::new(7, 3);
        assert_eq!((key.index(), key.generation()), (7, 3));
        assert_ne!(DriveKey::new(0, 1).0, 0);
        let wide = DriveKey::new(u32::MAX as usize, u32::MAX);
        assert_eq!(
            (wide.index(), wide.generation()),
            (u32::MAX as usize, u32::MAX)
        );
    }

    #[test]
    fn a_slab_hands_out_and_takes_back_entries() {
        let mut slab = Slab::default();
        let first = slab.insert("first");
        let second = slab.insert("second");
        assert_ne!(first, second);
        assert_eq!(slab.get_mut(first).copied(), Some("first"));
        assert_eq!(slab.remove(first), Some("first"));
        assert_eq!(slab.remove(first), None, "removed once");
        assert_eq!(slab.get_mut(first), None);
        assert_eq!(slab.get_mut(second).copied(), Some("second"));
    }

    /// The key of a coroutine that has finished must not reach whichever
    /// coroutine takes its slot next: a late wake or cancel would otherwise
    /// step or cancel a stranger.
    #[test]
    fn a_stale_key_does_not_reach_the_slot_s_next_entry() {
        let mut slab = Slab::default();
        let old = slab.insert(1);
        assert_eq!(slab.remove(old), Some(1));
        let new = slab.insert(2);
        assert_eq!(new.index(), old.index(), "the slot is reused");
        assert_ne!(new, old);
        assert_eq!(slab.get_mut(old), None);
        assert_eq!(slab.remove(old), None);
        assert_eq!(slab.get_mut(new).copied(), Some(2));
    }

    #[test]
    fn a_generation_wraps_past_zero() {
        let mut slab = Slab::default();
        let key = slab.insert(0u8);
        slab.slots[key.index()].generation = u32::MAX;
        let last = DriveKey::new(key.index(), u32::MAX);
        assert_eq!(slab.remove(last), Some(0));
        let next = slab.insert(1);
        assert_eq!(next.generation(), 1);
        assert_ne!(next.0, 0);
    }

    #[test]
    fn draining_a_slab_returns_every_live_entry() {
        let mut slab = Slab::default();
        let gone = slab.insert(1);
        slab.insert(2);
        slab.insert(3);
        slab.remove(gone);
        let mut left = slab.drain();
        left.sort_unstable();
        assert_eq!(left, vec![2, 3]);
        assert!(slab.drain().is_empty());
    }

    #[test]
    fn admission_is_bounded_and_given_back() {
        let owner = crate::script::runner::RunnerOwner::new().expect("a runner");
        let runner = Arc::clone(owner.shared());
        let first = runner.try_admit(2).expect("room");
        let second = runner.try_admit(2).expect("room");
        assert!(runner.try_admit(2).is_none(), "full at the limit");
        assert_eq!(runner.in_flight(), 2);
        drop(first);
        assert_eq!(runner.in_flight(), 1);
        let third = runner.try_admit(2).expect("room again");
        drop((second, third));
        assert_eq!(runner.in_flight(), 0);
        runner.shutdown();
    }
}
