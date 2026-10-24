//! `Python::attach` that refuses to run on a tokio worker thread.
//!
//! A tokio worker that attaches parks in the attach for as long as a garbage
//! collection's stop-the-world is pending, and everything queued on that
//! worker waits with it. Once every worker has parked, nothing polls the
//! reactor, and a stop-the-world that is itself waiting on a tokio future
//! never ends. Python work belongs on the script executor (`py_executor`) or
//! an asyncio driver; a tokio task hands it over and awaits.
//!
//! [`attach`] is the attach siphon's own paths use. In debug and test builds it
//! asserts the calling thread is not a tokio worker, so a path that drifts back
//! onto a worker fails its tests instead of parking a node. Release builds pay
//! one thread-local read.
//!
//! A worker is recognised by a thread-local the runtime's park hook sets
//! ([`mark_tokio_worker`]): tokio runs `on_thread_park` on worker threads
//! only, never on its blocking pool, where attaching (pyo3-async-runtimes'
//! completions, `spawn_blocking` jobs) is fine.

use std::cell::Cell;

use pyo3::prelude::*;

thread_local! {
    static TOKIO_WORKER: Cell<bool> = const { Cell::new(false) };
}

/// The `on_thread_park` hook that marks a runtime's worker threads. Every
/// runtime that runs siphon's tasks installs it (the server's, and the tests').
pub(crate) fn mark_tokio_worker() {
    TOKIO_WORKER.with(|worker| worker.set(true));
}

/// Whether this thread is a tokio worker of a runtime built with
/// [`mark_tokio_worker`] (once it has parked at least once).
pub(crate) fn on_tokio_worker() -> bool {
    TOKIO_WORKER.with(Cell::get)
}

/// `Python::attach`, asserting (debug and test builds) that this thread is not
/// a tokio worker.
#[track_caller]
pub(crate) fn attach<F, R>(work: F) -> R
where
    F: for<'py> FnOnce(Python<'py>) -> R,
{
    debug_assert!(
        !on_tokio_worker(),
        "Python::attach on a tokio worker thread: run this on the script \
         executor (py_executor) instead, an attach here parks the worker \
         through every garbage collection's stop-the-world"
    );
    Python::attach(work)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn marked_runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .on_thread_park(mark_tokio_worker)
            .build()
            .expect("runtime")
    }

    #[test]
    fn a_worker_thread_is_recognised_and_a_blocking_thread_is_not() {
        let runtime = marked_runtime();
        let (on_worker, on_blocking) = runtime.block_on(async {
            // Park once so the hook has run on the worker.
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            let on_worker = tokio::spawn(async { on_tokio_worker() })
                .await
                .expect("worker task");
            let on_blocking = tokio::task::spawn_blocking(on_tokio_worker)
                .await
                .expect("blocking task");
            (on_worker, on_blocking)
        });
        assert!(on_worker);
        assert!(!on_blocking);
        assert!(!on_tokio_worker(), "the test thread is no worker");
    }

    #[test]
    fn attach_on_a_worker_fails_loudly_in_debug_builds() {
        Python::initialize();
        let runtime = marked_runtime();
        let outcome = runtime.block_on(async {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            tokio::spawn(async { attach(|_| ()) }).await
        });
        if cfg!(debug_assertions) {
            assert!(outcome.is_err_and(|error| error.is_panic()));
        } else {
            assert!(outcome.is_ok());
        }
        // Off the workers it attaches normally.
        assert!(attach(|python| python.version_info().major) >= 3);
    }
}
