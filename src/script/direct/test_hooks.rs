//! Points in a step where a test can stop the stepping thread, to place
//! another thread's move (a cancellation, a completion) exactly there.

use std::sync::{Arc, Mutex};

use pyo3::prelude::*;

use super::{locked, Drive};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Point {
    /// The coroutine yielded an awaitable; nothing is decided yet.
    AtSuspend,
    /// The coroutine is marked as waiting and not yet registered.
    BeforeRegister,
}

type Hook = Arc<dyn Fn(Point, &Arc<Drive>) + Send + Sync>;

static HOOK: Mutex<Option<Hook>> = Mutex::new(None);

/// Install `hook` until the returned guard is dropped. Tests that use it
/// hold the pool guard, so one is installed at a time.
pub(crate) fn install(hook: Hook) -> Installed {
    *locked(&HOOK) = Some(hook);
    Installed
}

pub(crate) struct Installed;

impl Drop for Installed {
    fn drop(&mut self) {
        *locked(&HOOK) = None;
    }
}

/// Run the installed hook, released from the interpreter: it may block.
pub(super) fn fire(python: Python<'_>, point: Point, drive: &Arc<Drive>) {
    let hook = locked(&HOOK).clone();
    if let Some(hook) = hook {
        let drive = Arc::clone(drive);
        python.detach(move || hook(point, &drive));
    }
}
