//! The baton: holding a driver loop still for the rest of a handler step.

use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use pyo3::prelude::*;
use tracing::error;

use super::locked;

pub(super) type LoopCommand = Box<dyn for<'py> FnOnce(Python<'py>) + Send>;

enum BatonState {
    /// The park callback is queued on the loop and has not run yet.
    Requested,
    /// The loop thread is waiting in the park callback.
    Parked,
    /// The step asked the loop thread to run this.
    Command(LoopCommand),
    /// The loop thread is running a command.
    Running,
    /// The step is over: the loop thread goes back to its loop.
    Released,
    /// The step gave up waiting for the loop: the callback returns at once
    /// when it finally runs.
    Abandoned,
}

/// A driver loop parked for one executor thread.
///
/// While it is held the loop thread sits in a callback, released from the
/// interpreter, so the step that holds it may use the loop as that thread
/// would: nothing else is running on it. The step can also have the loop
/// thread run something for it ([`Baton::run_on_loop`]), which is how the
/// real task is created on the thread that will own it.
pub(super) struct Baton {
    state: Mutex<BatonState>,
    changed: Condvar,
}

impl Baton {
    pub(super) fn new() -> Self {
        Self {
            state: Mutex::new(BatonState::Requested),
            changed: Condvar::new(),
        }
    }

    /// Wait for the loop thread to park. `false` if it did not within
    /// `patience`; the baton is then abandoned. Call released from the
    /// interpreter.
    pub(super) fn wait_parked(&self, patience: Duration) -> bool {
        let deadline = Instant::now() + patience;
        let mut state = locked(&self.state);
        loop {
            match *state {
                BatonState::Parked => return true,
                BatonState::Requested => {}
                _ => return false,
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                *state = BatonState::Abandoned;
                return false;
            }
            state = self
                .changed
                .wait_timeout(state, left)
                .map(|(guard, _)| guard)
                .unwrap_or_else(|poison| poison.into_inner().0);
        }
    }

    /// Hand `command` to the parked loop thread and wait for it to finish.
    /// Call released from the interpreter.
    pub(super) fn run(&self, command: LoopCommand) {
        let mut state = locked(&self.state);
        *state = BatonState::Command(command);
        self.changed.notify_all();
        while matches!(*state, BatonState::Command(_) | BatonState::Running) {
            state = self
                .changed
                .wait(state)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }

    pub(super) fn release(&self) {
        *locked(&self.state) = BatonState::Released;
        self.changed.notify_all();
    }

    /// The loop thread's side: `None` when the step is over. Call released
    /// from the interpreter.
    fn next_command(&self) -> Option<LoopCommand> {
        let mut state = locked(&self.state);
        loop {
            match std::mem::replace(&mut *state, BatonState::Running) {
                BatonState::Command(command) => return Some(command),
                BatonState::Parked => *state = BatonState::Parked,
                other => {
                    *state = other;
                    return None;
                }
            }
            state = self
                .changed
                .wait(state)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }

    /// The loop thread parks. `false` if the step stopped waiting for it.
    fn park(&self) -> bool {
        let mut state = locked(&self.state);
        if !matches!(*state, BatonState::Requested) {
            return false;
        }
        *state = BatonState::Parked;
        self.changed.notify_all();
        true
    }

    fn command_done(&self) {
        *locked(&self.state) = BatonState::Parked;
        self.changed.notify_all();
    }
}

/// The callback a step queues on a driver loop to park it.
#[pyclass(frozen)]
pub(super) struct LoopPark {
    pub(super) baton: Arc<Baton>,
}

#[pymethods]
impl LoopPark {
    fn __call__(&self, python: Python<'_>) {
        let baton = &self.baton;
        if !baton.park() {
            return;
        }
        while let Some(command) = python.detach(|| baton.next_command()) {
            // A panic must not leave the step waiting for this command.
            let ran =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| command(python))).is_ok();
            baton.command_done();
            if !ran {
                error!("a command run on a parked asyncio driver panicked");
            }
        }
    }
}
