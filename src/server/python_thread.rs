//! Runtime-thread Python attachment: pin every tokio runtime thread to the
//! interpreter for its life, and let pyo3-async-runtimes complete awaitables
//! on those pinned threads.

thread_local! {
    /// The attach this thread is pinned with, so [`unpin_python_thread_state`]
    /// can unwind it symmetrically. `None` on a thread that was never pinned
    /// (or has already been unpinned), which makes the unpin idempotent.
    static PINNED_PYTHON_ATTACH: std::cell::Cell<
        Option<(pyo3::ffi::PyGILState_STATE, *mut pyo3::ffi::PyThreadState)>,
    > = const { std::cell::Cell::new(None) };
}

/// Pin this runtime thread to the Python interpreter for its whole life.
///
/// Free-threaded Python (3.14t) tears down a thread's mimalloc heap on every
/// `PyGILState_Release` whose attach count returns to 0 — calling `munmap` and
/// serializing every worker on the process-wide `mm_struct` rwsem (visible in
/// perf as `_PyThreadState_ClearMimallocHeaps → rwsem_down_write_slowpath`).
/// Holding one attach open for the thread's lifetime keeps that count above 0,
/// so each per-request pyo3 attach is a cheap nested no-op.
///
/// The attach is *held*, not leaked: the `(gstate, tstate)` pair is parked in a
/// thread-local so [`unpin_python_thread_state`] can release it when the thread
/// is reaped. That pairing is load-bearing — see that function.
pub(super) fn pin_python_thread_state() {
    // SAFETY: called once per runtime thread, before any pyo3 attach on it.
    // `PyEval_SaveThread` re-detaches so other threads (and pyo3 attaches on
    // this one) can take the per-thread state without conflict, while the
    // underlying `PyThreadState` stays cached against the OS thread.
    unsafe {
        let gstate = pyo3::ffi::PyGILState_Ensure();
        let tstate = pyo3::ffi::PyEval_SaveThread();
        PINNED_PYTHON_ATTACH.with(|slot| slot.set(Some((gstate, tstate))));
    }
}

/// Let pyo3-async-runtimes complete awaitables on `runtime`.
///
/// `future_into_py`, behind every awaitable script API, completes on the
/// runtime pyo3-async-runtimes holds. Unless it is given one it builds its
/// own, whose threads [`pin_python_thread_state`] never ran on, so the
/// `Python::attach` of each completion creates a `PyThreadState` and destroys
/// it again. On free-threaded Python that is a mimalloc heap set up and
/// collected per call, with the `munmap`s and page zeroing that go with it.
/// Handed this runtime, the completions run on pinned threads.
///
/// False when pyo3-async-runtimes already had a runtime.
pub(super) fn share_runtime_with_python(runtime: &'static tokio::runtime::Runtime) -> bool {
    pyo3_async_runtimes::tokio::init_with_runtime(runtime).is_ok()
}

/// Whether [`pin_python_thread_state`] pinned the current thread.
#[cfg(test)]
pub(super) fn python_thread_state_pinned() -> bool {
    PINNED_PYTHON_ATTACH.with(|slot| slot.get().is_some())
}

/// Release the attach [`pin_python_thread_state`] took, so CPython frees this
/// thread's `PyThreadState` when the OS thread goes away.
///
/// Without this half, the pin is a leak. `PyGILState_Ensure` allocates the
/// state with `PyMem_RawCalloc` — CPython's *raw* domain, i.e. plain
/// `malloc`, invisible to jemalloc and therefore to `siphon_memory_*` — and an
/// unreleased `GILState` keeps CPython from ever destroying it. The runtime's
/// fixed async workers live for the whole process so it never showed there, but
/// `on_thread_start` also fires for tokio's **elastic blocking pool**, whose
/// threads are reaped after their idle keep-alive. Every reaped blocking thread
/// then orphaned its `PyThreadState` on the C heap, for the life of the process:
/// a steady, traffic-independent RSS climb on any deployment that does blocking
/// work on a timer (DNS, netlink, TLS handshakes, health probes).
///
/// Releasing on thread *stop* costs nothing on the hot path — the workers this
/// optimization exists for never stop — while bounding the blocking pool.
pub(super) fn unpin_python_thread_state() {
    let Some((gstate, tstate)) = PINNED_PYTHON_ATTACH.with(|slot| slot.take()) else {
        return;
    };
    // SAFETY: runs on the same thread `pin_python_thread_state` pinned, after
    // its work is done. The thread is currently detached (the pin ended with
    // `PyEval_SaveThread`), so restore that exact state before releasing the
    // matching `GILState` — `PyGILState_Release` requires an attached thread.
    unsafe {
        pyo3::ffi::PyEval_RestoreThread(tstate);
        pyo3::ffi::PyGILState_Release(gstate);
    }
}
