//! Runtime-thread Python attachment: pin tokio's async **workers** to the
//! interpreter while they live, and leave the elastic blocking pool unpinned.
//!
//! Workers are pinned when they first park (`on_thread_park` runs on workers
//! only), not when they start: `on_thread_start` also runs for every thread
//! of the blocking pool, which tokio grows to 512 under a pile-up of blocking
//! waits and reaps after its keep-alive. A pinned blocking thread holds a
//! Python thread state for nothing (no Python runs there: awaitable
//! completions run on `script::completions`' fixed threads), and each one the
//! pool started created a thread state and each one it reaped destroyed it.

thread_local! {
    /// The attach this thread is pinned with, so [`unpin_python_thread_state`]
    /// can unwind it symmetrically. `None` on a thread that was never pinned
    /// (or has already been unpinned), which makes the unpin idempotent.
    static PINNED_PYTHON_ATTACH: std::cell::Cell<
        Option<(pyo3::ffi::PyGILState_STATE, *mut pyo3::ffi::PyThreadState)>,
    > = const { std::cell::Cell::new(None) };
}

/// Pin this worker thread to the Python interpreter for its whole life.
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
    // SAFETY: called once per worker thread (`on_worker_park` checks), while
    // it is not attached.
    // `PyEval_SaveThread` re-detaches so other threads (and pyo3 attaches on
    // this one) can take the per-thread state without conflict, while the
    // underlying `PyThreadState` stays cached against the OS thread.
    unsafe {
        let gstate = pyo3::ffi::PyGILState_Ensure();
        let tstate = pyo3::ffi::PyEval_SaveThread();
        PINNED_PYTHON_ATTACH.with(|slot| slot.set(Some((gstate, tstate))));
    }
}

/// The `on_thread_park` hook of siphon's runtime, which tokio runs on its async
/// workers only: mark the thread a worker, and pin it the first time.
///
/// A blocking-pool thread that takes over a worker's core (`block_in_place`
/// hands the core to one) parks as a worker too and is pinned from then on;
/// [`unpin_python_thread_state`] releases it if the pool later reaps it.
fn on_worker_park() {
    crate::script::attach::mark_tokio_worker();
    if pinned() {
        return;
    }
    // SAFETY: `Py_IsInitialized` reads a flag and is callable at any time. A
    // runtime built before the interpreter (a test) stays unpinned rather
    // than initialise it from a park hook.
    if unsafe { pyo3::ffi::Py_IsInitialized() } != 0 {
        pin_python_thread_state();
    }
}

fn pinned() -> bool {
    PINNED_PYTHON_ATTACH.with(|slot| slot.get().is_some())
}

/// Build the tokio runtime siphon runs on, with every thread hook it needs,
/// and hand it to pyo3-async-runtimes (see [`share_runtime_with_python`]).
///
/// `configure` adjusts the builder before it is built: the server passes a
/// no-op, the footprint tests shrink the pool's keep-alive so a churn cycle
/// takes seconds. One function, so those tests measure the runtime the server
/// runs. Lives for the process: `'static` so pyo3-async-runtimes can hold it.
#[doc(hidden)]
pub fn build_runtime(
    configure: impl FnOnce(&mut tokio::runtime::Builder),
) -> std::io::Result<&'static tokio::runtime::Runtime> {
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder
        .enable_all()
        .on_thread_park(on_worker_park)
        .on_thread_stop(unpin_python_thread_state);
    configure(&mut builder);
    let runtime: &'static tokio::runtime::Runtime = Box::leak(Box::new(builder.build()?));
    if !share_runtime_with_python(runtime) {
        tracing::warn!(
            "pyo3-async-runtimes already had a runtime: awaitable script APIs \
             complete on threads without a pinned Python thread state"
        );
    }
    Ok(runtime)
}

/// Let pyo3-async-runtimes run awaitables' futures on `runtime`.
///
/// Unless it is given one it builds its own. siphon's awaitables
/// (`script::blocking::awaitable`) run their futures here and their
/// completions on `script::completions`' pinned threads; an extension that
/// calls `pyo3_async_runtimes::tokio::future_into_py` itself still completes
/// on this runtime's blocking pool, which is unpinned, so each completion sets
/// up and tears down a thread state: it should call `awaitable` instead.
///
/// False when pyo3-async-runtimes already had a runtime.
pub(super) fn share_runtime_with_python(runtime: &'static tokio::runtime::Runtime) -> bool {
    pyo3_async_runtimes::tokio::init_with_runtime(runtime).is_ok()
}

/// Whether [`pin_python_thread_state`] pinned the current thread.
#[cfg(test)]
pub(super) fn python_thread_state_pinned() -> bool {
    pinned()
}

/// Release the attach [`pin_python_thread_state`] took, so CPython frees this
/// thread's `PyThreadState` when the OS thread goes away.
///
/// Without this half, the pin is a leak. `PyGILState_Ensure` allocates the
/// state with `PyMem_RawCalloc` — CPython's *raw* domain, i.e. plain
/// `malloc`, invisible to jemalloc and therefore to `siphon_memory_*` — and an
/// unreleased `GILState` keeps CPython from ever destroying it. A worker is not
/// forever: one that calls `block_in_place` hands its core to another thread
/// and may end up back in the elastic blocking pool, which reaps it after its
/// idle keep-alive. Unreleased, every such thread orphaned its `PyThreadState`
/// on the C heap, for the life of the process (and, while the pin was taken in
/// `on_thread_start`, so did every blocking thread).
///
/// Releasing on thread *stop* costs nothing on the hot path: a thread only
/// stops once it is idle.
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
