//! A native runner on each asyncio driver thread.
//!
//! Every driver loop in [`crate::script::async_pool`] owns one. Other threads
//! hand it work with [`RunnerShared::post`], which never touches the
//! interpreter: it queues the message and, if the runner is not already due
//! to look, makes the runner's fd readable (see [`wake`]). The loop's selector
//! then calls `RunnerDrain` on the driver thread, attached, where the work
//! runs.
//!
//! What this buys over queueing on the Python executor: work for a driver
//! stays on that driver's thread from start to teardown, never waits behind
//! new work in a shared queue, and adds no attached thread.
//!
//! # Draining
//!
//! One drain runs queued work in priority order: cancels, then wakes, then
//! starts, so work in flight finishes before new work is admitted. It stops
//! after [`DRAIN_ITEM_BUDGET`] items or [`DRAIN_TIME_BUDGET`], whichever comes
//! first, re-arms its own wake and returns, so the loop's ready queue and
//! timers run between drains.
//!
//! # Shutdown
//!
//! [`RunnerShared::shutdown`] is sent before the loop is stopped; from the
//! moment the runner sees it, nothing more runs. The driver thread then
//! closes the runner (`RunnerOwner::close`): every item still queued is
//! invoked once with [`Fate::Abandoned`], attached, on the owner thread, and
//! the fd is closed. A post that loses the race gets its message back.
//!
//! # Direct dispatch
//!
//! With `script.direct_dispatch: on`, an `async def` handler called through
//! [`crate::script::ScriptHandle`] is stepped here, on its driver thread,
//! without an asyncio task, for as long as it awaits only siphon's own
//! awaitables. See [`drive`].

mod awaitable;
mod drive;
mod python;
mod switch;
mod task;
mod wake;

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::time::{Duration, Instant};

use pyo3::prelude::*;
use tracing::{debug, error};

use wake::{wake_pair, WakeReceiver, WakeSender};

#[cfg(test)]
pub(crate) use awaitable::SiphonAwaitable;
pub use awaitable::{spawn_awaitable, AwaitableFuture, BuildValue};
pub(crate) use drive::{in_direct_step, start, timeout_error, Admission, DriveHandle, Waited};
pub use switch::{admission_rejected, configure, demotions, DEFAULT_ADMISSION_LIMIT};
pub(crate) use switch::{clear_demoted, enabled as direct_dispatch_enabled, register};
#[cfg(test)]
pub(crate) use switch::{demoted_handlers, set_admission_limit_for_test, set_enabled_for_test};

/// Items one drain runs before it yields to the loop.
pub(crate) const DRAIN_ITEM_BUDGET: usize = 64;

/// How long one drain runs before it yields to the loop.
pub(crate) const DRAIN_TIME_BUDGET: Duration = Duration::from_millis(1);

/// Messages moved off the channel per look at it. A drain looks once per item
/// it runs, so intake stays far ahead of the work without a busy poster being
/// able to hold the loop thread in the intake alone.
const PULL_BATCH: usize = 256;

/// Why a [`Work`] item is being invoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Fate {
    /// Its turn came.
    Run,
    /// The runner shut down first. The item must fail whoever waits on it.
    Abandoned,
}

/// Something to do on the driver thread, attached to the interpreter.
///
/// A posted item is invoked exactly once, on the runner's own thread, with the
/// reason. It runs on the event loop, so it must not wait.
pub(crate) struct Work(Box<dyn for<'py> FnOnce(Python<'py>, Fate) + Send>);

impl Work {
    pub(crate) fn new(work: impl for<'py> FnOnce(Python<'py>, Fate) + Send + 'static) -> Self {
        Self(Box::new(work))
    }

    /// Invoke an item its runner refused, with [`Fate::Abandoned`], on the
    /// calling thread.
    pub(crate) fn abandon(self, python: Python<'_>) {
        invoke(self, python, Fate::Abandoned);
    }
}

/// What a runner is asked to do. The variant is the priority class.
pub(crate) enum Message {
    /// New work: runs after everything in flight.
    Start(Work),
    /// A continuation of work in flight: runs before any start.
    Wake(Work),
    /// A cancellation of work in flight: runs first.
    Cancel(Work),
    /// Stop running work. Sent before the loop is stopped.
    Shutdown,
}

/// A point-in-time copy of a runner's counters.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RunnerStats {
    /// Items posted and not yet invoked.
    pub queued: usize,
    /// Items invoked with [`Fate::Run`].
    pub ran: u64,
    /// Items invoked with [`Fate::Abandoned`].
    pub abandoned: u64,
    /// Bytes written to the wake pipe.
    pub wake_writes: u64,
    /// Times the loop called the drain.
    pub drains: u64,
    /// Drains that stopped on their budget with work left.
    pub budget_yields: u64,
    /// Handlers admitted and not yet unwound.
    pub in_flight: usize,
    /// Coroutines in the driver's slab.
    pub drives: usize,
    /// Awaitables whose Rust future has not finished.
    pub awaitables: usize,
    /// Coroutines started without an asyncio task.
    pub direct_starts: u64,
    /// Steps run without an asyncio task.
    pub direct_steps: u64,
}

/// The side of a runner any thread may hold. Carries no Python object.
pub(crate) struct RunnerShared {
    sender: Sender<Message>,
    wake: WakeSender,
    /// Set once the runner takes no more work.
    sealed: AtomicBool,
    /// Items accepted and not yet invoked. A post counts itself before its
    /// last check of `sealed`, so the close can tell when none is in transit.
    queued: AtomicUsize,
    ran: AtomicU64,
    abandoned: AtomicU64,
    drains: AtomicU64,
    budget_yields: AtomicU64,
    /// Handlers admitted and not yet unwound: what admission bounds.
    in_flight: AtomicUsize,
    drives: AtomicUsize,
    awaitables: AtomicUsize,
    direct_starts: AtomicU64,
    direct_steps: AtomicU64,
}

impl RunnerShared {
    /// Hand `message` to the runner. Synchronous, callable from any thread,
    /// and it never attaches to the interpreter.
    ///
    /// `Err` gives the message back: the runner has shut down and will not
    /// invoke it.
    pub(crate) fn post(&self, message: Message) -> Result<(), Message> {
        // Refused here, a post never touches `queued`: only the posts already
        // past this line when the runner seals can hold the close up, and
        // there is a bounded number of those.
        if self.sealed.load(Ordering::SeqCst) {
            return Err(message);
        }
        let counted = !matches!(message, Message::Shutdown);
        if counted {
            self.queued.fetch_add(1, Ordering::SeqCst);
        }
        let refused = if self.sealed.load(Ordering::SeqCst) {
            Some(message)
        } else {
            self.sender.send(message).err().map(|error| error.0)
        };
        if let Some(message) = refused {
            if counted {
                self.queued.fetch_sub(1, Ordering::SeqCst);
            }
            return Err(message);
        }
        self.wake.wake();
        Ok(())
    }

    /// Tell the runner to stop running work. The caller stops the loop next;
    /// what is still queued is abandoned when the driver thread closes the
    /// runner.
    pub(crate) fn shutdown(&self) {
        // Refused only when the runner is sealed already.
        let _ = self.post(Message::Shutdown);
    }

    /// Whether the runner has stopped taking work.
    pub(crate) fn is_shut_down(&self) -> bool {
        self.sealed.load(Ordering::SeqCst)
    }

    /// Handlers this runner has admitted and not yet unwound.
    pub(crate) fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::SeqCst)
    }

    #[cfg(test)]
    pub(crate) fn stats(&self) -> RunnerStats {
        RunnerStats {
            queued: self.queued.load(Ordering::SeqCst),
            ran: self.ran.load(Ordering::Relaxed),
            abandoned: self.abandoned.load(Ordering::Relaxed),
            wake_writes: self.wake.writes(),
            drains: self.drains.load(Ordering::Relaxed),
            budget_yields: self.budget_yields.load(Ordering::Relaxed),
            in_flight: self.in_flight.load(Ordering::SeqCst),
            drives: self.drives.load(Ordering::Relaxed),
            awaitables: self.awaitables.load(Ordering::Relaxed),
            direct_starts: self.direct_starts.load(Ordering::Relaxed),
            direct_steps: self.direct_steps.load(Ordering::Relaxed),
        }
    }

    #[cfg(test)]
    pub(crate) fn wake_probe(&self) -> std::os::unix::net::UnixStream {
        self.wake.probe()
    }
}

/// What only the driver thread touches.
struct Local {
    receiver: Receiver<Message>,
    /// `None` once the runner is closed.
    wake: Option<WakeReceiver>,
    cancels: VecDeque<Work>,
    wakes: VecDeque<Work>,
    starts: VecDeque<Work>,
    /// A shutdown was seen: nothing more runs.
    stopping: bool,
}

impl Local {
    /// Move what has been posted into its priority class, [`PULL_BATCH`]
    /// messages at most. If nothing is queued here afterwards, the channel
    /// was seen empty.
    fn pull(&mut self, shared: &RunnerShared) {
        for _ in 0..PULL_BATCH {
            let Ok(message) = self.receiver.try_recv() else {
                return;
            };
            match message {
                Message::Start(work) => self.starts.push_back(work),
                Message::Wake(work) => self.wakes.push_back(work),
                Message::Cancel(work) => self.cancels.push_back(work),
                Message::Shutdown => {
                    self.stopping = true;
                    shared.sealed.store(true, Ordering::SeqCst);
                }
            }
        }
    }

    fn pop(&mut self) -> Option<Work> {
        self.cancels
            .pop_front()
            .or_else(|| self.wakes.pop_front())
            .or_else(|| self.starts.pop_front())
    }

    fn has_work(&self) -> bool {
        !(self.cancels.is_empty() && self.wakes.is_empty() && self.starts.is_empty())
    }

    fn take_all(&mut self) -> Vec<Work> {
        let mut all = Vec::with_capacity(self.cancels.len() + self.wakes.len() + self.starts.len());
        all.extend(self.cancels.drain(..));
        all.extend(self.wakes.drain(..));
        all.extend(self.starts.drain(..));
        all
    }
}

/// What one pass of the drain loop decided, with the lock released.
enum Step {
    Run(Work),
    /// The budget is spent and work is left.
    Yield,
    Idle,
}

/// The driver thread's side of a runner.
pub(crate) struct RunnerOwner {
    shared: Arc<RunnerShared>,
    /// Only the driver thread locks it, and never across an item: the mutex
    /// is here to make the type shareable with the loop's callback, not to
    /// arbitrate. It is taken with `try_lock`, so it cannot park an attached
    /// thread whatever else goes wrong.
    local: Mutex<Local>,
}

impl RunnerOwner {
    /// A runner with nothing queued. Its drain is not installed yet.
    pub(crate) fn new() -> std::io::Result<Arc<Self>> {
        let (wake_sender, wake_receiver) = wake_pair()?;
        let (sender, receiver) = mpsc::channel();
        Ok(Arc::new(Self {
            shared: Arc::new(RunnerShared {
                sender,
                wake: wake_sender,
                sealed: AtomicBool::new(false),
                queued: AtomicUsize::new(0),
                ran: AtomicU64::new(0),
                abandoned: AtomicU64::new(0),
                drains: AtomicU64::new(0),
                budget_yields: AtomicU64::new(0),
                in_flight: AtomicUsize::new(0),
                drives: AtomicUsize::new(0),
                awaitables: AtomicUsize::new(0),
                direct_starts: AtomicU64::new(0),
                direct_steps: AtomicU64::new(0),
            }),
            local: Mutex::new(Local {
                receiver,
                wake: Some(wake_receiver),
                cancels: VecDeque::new(),
                wakes: VecDeque::new(),
                starts: VecDeque::new(),
                stopping: false,
            }),
        }))
    }

    pub(crate) fn shared(&self) -> &Arc<RunnerShared> {
        &self.shared
    }

    fn local(&self) -> Option<MutexGuard<'_, Local>> {
        match self.local.try_lock() {
            Ok(local) => Some(local),
            // No item runs under the lock, so a poisoned one is still whole.
            Err(TryLockError::Poisoned(poisoned)) => Some(poisoned.into_inner()),
            Err(TryLockError::WouldBlock) => {
                error!("script runner state is in use off its driver thread");
                None
            }
        }
    }

    /// Have `event_loop` call the drain whenever the runner is woken. Call on
    /// the loop's own thread.
    pub(crate) fn install(
        self: &Arc<Self>,
        python: Python<'_>,
        event_loop: &Bound<'_, PyAny>,
    ) -> PyResult<()> {
        let Some(fd) = self
            .local()
            .and_then(|local| local.wake.as_ref().map(WakeReceiver::fd))
        else {
            return Err(pyo3::exceptions::PyRuntimeError::new_err(
                "script runner is closed",
            ));
        };
        let drain = Py::new(
            python,
            RunnerDrain {
                owner: Arc::clone(self),
            },
        )?;
        event_loop.call_method1("add_reader", (fd, drain))?;
        drive::install_owner(python, &self.shared, event_loop);
        Ok(())
    }

    /// Run queued work until it is gone or the budget is spent. Call attached,
    /// on the loop's own thread.
    fn drain(&self, python: Python<'_>) {
        let shared = &*self.shared;
        shared.drains.fetch_add(1, Ordering::Relaxed);
        {
            let Some(local) = self.local() else { return };
            if let Some(wake) = &local.wake {
                wake.clear();
            }
        }
        // Before the first look at the queue: see `wake`.
        shared.wake.disarm();

        let started = Instant::now();
        let mut ran = 0usize;
        loop {
            let step = {
                let Some(mut local) = self.local() else {
                    return;
                };
                local.pull(shared);
                if local.stopping {
                    // What is left is abandoned by `close`.
                    return;
                }
                let spent =
                    ran >= DRAIN_ITEM_BUDGET || (ran > 0 && started.elapsed() >= DRAIN_TIME_BUDGET);
                if !spent {
                    local.pop().map_or(Step::Idle, Step::Run)
                } else if local.has_work() {
                    Step::Yield
                } else {
                    Step::Idle
                }
            };
            match step {
                Step::Run(work) => {
                    shared.queued.fetch_sub(1, Ordering::SeqCst);
                    shared.ran.fetch_add(1, Ordering::Relaxed);
                    invoke(work, python, Fate::Run);
                    ran += 1;
                }
                Step::Yield => {
                    shared.budget_yields.fetch_add(1, Ordering::Relaxed);
                    // Readable again, so the loop comes back after its ready
                    // queue and due timers have run.
                    shared.wake.wake();
                    return;
                }
                Step::Idle => return,
            }
        }
    }

    /// Stop the runner for good: unhook it from `event_loop`, abandon every
    /// item still queued and close the fd. Call attached, on the loop's own
    /// thread, once the loop has stopped.
    pub(crate) fn close(&self, python: Python<'_>, event_loop: &Bound<'_, PyAny>) {
        let wake = self.local().and_then(|mut local| local.wake.take());
        if let Some(wake) = &wake {
            if let Err(error) = event_loop.call_method1("remove_reader", (wake.fd(),)) {
                debug!(%error, "could not unhook the script runner from its loop");
            }
        }

        let shared = &*self.shared;
        shared.sealed.store(true, Ordering::SeqCst);
        loop {
            let Some(mut local) = self.local() else { break };
            local.pull(shared);
            let left = local.take_all();
            drop(local);
            if left.is_empty() {
                if shared.queued.load(Ordering::SeqCst) == 0 {
                    break;
                }
                // A post counted itself before the seal and has not finished
                // sending. It is a few instructions from done; give it the
                // CPU, released from the interpreter.
                python.detach(std::thread::yield_now);
                continue;
            }
            for work in left {
                shared.queued.fetch_sub(1, Ordering::SeqCst);
                shared.abandoned.fetch_add(1, Ordering::Relaxed);
                invoke(work, python, Fate::Abandoned);
            }
        }
        // Nothing more can reach the slab: close what is still in it.
        drive::close_owner(python);
        // Closes the read end, here rather than whenever the loop lets go of
        // the callback.
        drop(wake);
    }
}

/// Invoke one item. A panic in it must not take the loop's callback down with
/// the rest of the queue still to run.
fn invoke(work: Work, python: Python<'_>, fate: Fate) {
    let run = std::panic::AssertUnwindSafe(|| (work.0)(python, fate));
    if std::panic::catch_unwind(run).is_err() {
        error!(?fate, "a script runner item panicked");
    }
}

/// The callback the driver loop calls when the runner's fd is readable.
#[pyclass(frozen)]
pub(crate) struct RunnerDrain {
    owner: Arc<RunnerOwner>,
}

#[pymethods]
impl RunnerDrain {
    fn __call__(&self, python: Python<'_>) {
        self.owner.drain(python);
    }
}

#[cfg(test)]
mod direct_edge_tests;
#[cfg(test)]
pub(crate) mod direct_tests;
#[cfg(test)]
mod tests;
