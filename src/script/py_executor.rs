//! Fixed, never-reaped pool of persistently-attached Python worker threads for
//! *synchronous* script-handler invocation.
//!
//! # Why this exists
//!
//! [`crate::server::SiphonServer`] pins a `PyThreadState` on every tokio
//! runtime thread in its `on_thread_start` hook so free-threaded CPython 3.14t
//! does not tear down the thread's mimalloc heap on every `PyGILState_Release`
//! (the expensive `munmap` / `mm_struct` rwsem path).  That pin is *correct*
//! for the fixed async worker threads — they are reclaimed only at process
//! exit.  But Python handlers were dispatched with
//! `tokio::task::spawn_blocking(|| Python::attach(...))`, which runs on tokio's
//! **elastic** blocking pool.  Those threads are reaped after the idle
//! keep-alive (~10 s) while the process keeps running, and a reaped thread
//! orphans its pinned `PyThreadState` plus its ~2 MB free-threaded-CPython
//! mimalloc heap segment — there is no paired `on_thread_stop` to release it,
//! and the attach count was deliberately never returned to 0.  Net effect:
//! ~2 MB of anonymous heap leaked per reaped blocking thread that touched
//! Python, i.e. one leak step per Python-invoking SIP event.  Threads and FDs
//! stay flat (the OS thread is gone); only the anonymous heap grows.
//!
//! # How this fixes it
//!
//! Route every synchronous `Python::attach` handler invocation through this
//! fixed pool instead of `spawn_blocking`.  Each worker thread is spawned once
//! at startup, performs the same persistent-attach trick, and lives until
//! process exit — so its Python heap is reclaimed only at exit and never leaks.
//! This is the synchronous analogue of [`crate::script::async_pool`], which
//! already solves the same class of problem for the asyncio driver threads.
//!
//! # Correctness constraints (mirrored from `async_pool::driver_main`)
//!
//! 1. Each worker holds `tokio_handle.enter()` for its lifetime, so script
//!    handlers that call Rust APIs which do
//!    `block_in_place(|| Handle::current().block_on(...))`
//!    (`proxy.send_request`, `cache.fetch`, `diameter.send_*`, …) keep working.
//! 2. The persistent un-paired `PyGILState_Ensure` is mandatory — without it
//!    free-threaded CPython would churn the worker's mimalloc heap on every
//!    handler.  It is safe here precisely because these threads are fixed.

use std::any::Any;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::OnceLock;
use std::thread::JoinHandle;

use tokio::runtime::Handle as TokioHandle;
use tokio::sync::oneshot;
use tracing::{debug, error, info};

/// A unit of work submitted to the pool. The closure is fully self-contained —
/// it captures whatever it needs (including any result channel).
type Job = Box<dyn FnOnce() + Send + 'static>;

/// Process-wide pool, installed once at server startup. Submission helpers
/// fall back to `tokio::task::spawn_blocking` when no pool is installed (tests
/// / CLI helpers), so behaviour is unchanged off the server path.
static GLOBAL: OnceLock<Arc<PyExecutor>> = OnceLock::new();

/// Fixed pool of persistently-attached Python worker threads.
pub struct PyExecutor {
    /// Job queue. `Option` so [`Drop`] can close the channel (drop the only
    /// sender) before joining the worker threads.
    sender: StdMutex<Option<flume::Sender<Job>>>,
    /// Worker thread handles, joined on drop.
    threads: StdMutex<Vec<JoinHandle<()>>>,
    size: usize,
}

impl PyExecutor {
    /// Install the global pool with `size` worker threads, each entering
    /// `tokio_handle` for its lifetime. Idempotent — subsequent calls return
    /// the already-installed pool (the loser of an install race tears its own
    /// threads down). `size` is clamped to at least 1.
    ///
    /// `tokio_handle` **must outlive the process / test binary** — every worker
    /// holds an `EnterGuard` for it for its whole life (same requirement as
    /// [`crate::script::async_pool::AsyncPool::install`]). In production pass
    /// the bootstrap runtime's `Handle::current()`.
    pub fn install(size: usize, tokio_handle: TokioHandle) -> Arc<PyExecutor> {
        if let Some(existing) = GLOBAL.get() {
            return Arc::clone(existing);
        }
        let size = size.max(1);
        let pool = Arc::new(PyExecutor::spawn(size, tokio_handle));
        match GLOBAL.set(Arc::clone(&pool)) {
            Ok(()) => {
                info!(size, "synchronous Python executor pool initialised");
                pool
            }
            Err(_) => {
                // Another thread won the race — tear our threads back down and
                // use the installed pool instead.
                drop(pool);
                Arc::clone(GLOBAL.get().expect("pool just installed"))
            }
        }
    }

    /// Borrow the installed pool, if any.
    pub fn global() -> Option<Arc<PyExecutor>> {
        GLOBAL.get().cloned()
    }

    /// Number of worker threads. Stable for the process lifetime.
    pub fn size(&self) -> usize {
        self.size
    }

    fn spawn(size: usize, tokio_handle: TokioHandle) -> Self {
        let (sender, receiver) = flume::unbounded::<Job>();
        let mut threads = Vec::with_capacity(size);
        for index in 0..size {
            let receiver = receiver.clone();
            let tokio_handle = tokio_handle.clone();
            let thread = std::thread::Builder::new()
                .name(format!("siphon-pyexec-{index}"))
                .spawn(move || worker_main(index, receiver, tokio_handle))
                .expect("failed to spawn Python executor thread");
            threads.push(thread);
        }
        Self {
            sender: StdMutex::new(Some(sender)),
            threads: StdMutex::new(threads),
            size,
        }
    }

    /// Submit a job. Returns `false` if the channel is closed (pool shutting
    /// down).
    fn submit(&self, job: Job) -> bool {
        match self.sender.lock() {
            Ok(guard) => match guard.as_ref() {
                Some(sender) => sender.send(job).is_ok(),
                None => false,
            },
            Err(_) => false,
        }
    }
}

impl Drop for PyExecutor {
    fn drop(&mut self) {
        // Close the channel so workers' `recv()` returns `Err` and they exit.
        // Normally never runs in production (the pool lives in `OnceLock`); it
        // only matters for the transient `Arc` an install-race loser holds.
        if let Ok(mut guard) = self.sender.lock() {
            guard.take();
        }
        let threads = self
            .threads
            .lock()
            .map(|mut t| std::mem::take(&mut *t))
            .unwrap_or_default();
        for thread in threads {
            if thread.join().is_err() {
                error!("Python executor worker thread panicked during shutdown");
            }
        }
    }
}

fn worker_main(index: usize, receiver: flume::Receiver<Job>, tokio_handle: TokioHandle) {
    // Hold the bootstrap runtime context for this thread's lifetime so that
    // blocking Rust-API callbacks invoked from script handlers reach a live
    // reactor (`Handle::current()` / `block_in_place`). Dropped only when the
    // worker returns, i.e. at shutdown.
    let _runtime_guard = tokio_handle.enter();

    // Persistent attach — same rationale as the tokio worker threads
    // (`server.rs::on_thread_start`) and `async_pool::driver_main`: keep this
    // thread's Python attach count > 0 for its whole life so free-threaded
    // mimalloc does not tear down its heap on every detach.
    //
    // SAFETY: we deliberately never call `PyGILState_Release` /
    // `PyEval_RestoreThread`, so the per-thread Python state outlives every
    // pyo3 attach/detach for this worker's whole life. This OS thread lives
    // until process exit, so the state is reclaimed there — which is exactly
    // why it never leaks here, unlike the elastic blocking pool this replaces.
    // The handles are `Copy` (plain pointers); letting them drop is a no-op.
    unsafe {
        let _gstate = pyo3::ffi::PyGILState_Ensure();
        let _tstate = pyo3::ffi::PyEval_SaveThread();
    }

    while let Ok(job) = receiver.recv() {
        // Backstop: a panicking job must never take down the worker thread (the
        // submission wrappers already isolate panics, but defend in depth so a
        // raw job can't shrink the pool).
        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(job)).is_err() {
            error!(worker = index, "Python executor job panicked");
        }
    }
    debug!(worker = index, "Python executor worker exiting");
}

/// Run `f` on a pool thread and await its result — the async analogue of
/// `tokio::task::spawn_blocking(f).await.unwrap()`. A panic inside `f`
/// propagates to the caller via `resume_unwind`, matching `spawn_blocking`.
///
/// Falls back to `tokio::task::spawn_blocking` when no pool is installed.
pub async fn run<T, F>(f: F) -> T
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    match try_run(f).await {
        Ok(value) => value,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

/// Like [`run`], but returns the panic payload as `Err` instead of propagating
/// it — the analogue of `tokio::task::spawn_blocking(f).await` (where `Err`
/// means the task panicked). Use at sites that turn a dispatch panic into an
/// error rather than unwinding.
pub async fn try_run<T, F>(f: F) -> std::thread::Result<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    match PyExecutor::global() {
        Some(pool) => {
            let (sender, receiver) = oneshot::channel();
            let job: Job = Box::new(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
                // Receiver may already be gone if the caller dropped the future;
                // that's fine — the work still ran.
                let _ = sender.send(result);
            });
            if !pool.submit(job) {
                return Err(boxed_message("Python executor channel closed"));
            }
            receiver
                .await
                .unwrap_or_else(|_| Err(boxed_message("Python executor worker dropped")))
        }
        None => {
            // No pool (tests / CLI): preserve the old blocking-pool behaviour.
            match tokio::task::spawn_blocking(f).await {
                Ok(value) => Ok(value),
                Err(join_error) if join_error.is_panic() => Err(join_error.into_panic()),
                Err(_) => Err(boxed_message("spawn_blocking task cancelled")),
            }
        }
    }
}

/// Fire-and-forget: run `f` on a pool thread, discarding its result. For sites
/// that previously called `spawn_blocking(...)` without awaiting the handle.
///
/// Falls back to `tokio::task::spawn_blocking` when no pool is installed.
pub fn spawn<F>(f: F)
where
    F: FnOnce() + Send + 'static,
{
    match PyExecutor::global() {
        Some(pool) => {
            let job: Job = Box::new(move || {
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
            });
            if !pool.submit(job) {
                error!("Python executor channel closed — dropping fire-and-forget job");
            }
        }
        None => {
            tokio::task::spawn_blocking(f);
        }
    }
}

/// Wrap a static message as a panic payload so callers see a meaningful value
/// in the `Err` arm.
fn boxed_message(message: &'static str) -> Box<dyn Any + Send + 'static> {
    Box::new(message)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use pyo3::prelude::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Long-lived process-wide runtime — the pool's worker threads enter the
    /// runtime captured at install time and hold the guard forever, so a
    /// per-test `#[tokio::test]` runtime would be torn down underneath them.
    /// Mirrors `async_pool::tests::test_runtime`.
    fn test_runtime() -> &'static tokio::runtime::Runtime {
        static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
        RUNTIME.get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .enable_all()
                .thread_name("pyexec-test-rt")
                .build()
                .expect("failed to build test runtime")
        })
    }

    fn ensure_pool() -> Arc<PyExecutor> {
        pyo3::Python::initialize();
        PyExecutor::install(3, test_runtime().handle().clone())
    }

    #[test]
    fn run_returns_closure_value() {
        test_runtime().block_on(async {
            ensure_pool();
            let value = run(|| 2 + 3).await;
            assert_eq!(value, 5);
        });
    }

    #[test]
    fn run_executes_python_attach_on_pool_thread() {
        test_runtime().block_on(async {
            ensure_pool();
            // The worker thread is persistently attached, so a nested
            // `Python::attach` must be a cheap no-op that still works.
            let answer: i64 = run(|| {
                pyo3::Python::attach(|python| {
                    let result = python
                        .eval(std::ffi::CString::new("6 * 7").unwrap().as_c_str(), None, None)
                        .unwrap();
                    result.extract::<i64>().unwrap()
                })
            })
            .await;
            assert_eq!(answer, 42);
        });
    }

    #[test]
    fn spawn_runs_fire_and_forget_job() {
        test_runtime().block_on(async {
            ensure_pool();
            let (sender, receiver) = oneshot::channel();
            spawn(move || {
                let _ = sender.send(99u8);
            });
            let received = receiver.await.unwrap();
            assert_eq!(received, 99);
        });
    }

    #[test]
    fn worker_holds_tokio_runtime_context() {
        test_runtime().block_on(async {
            ensure_pool();
            // A pool thread must be inside the runtime so `Handle::current()`
            // resolves — this is what keeps `block_in_place`-based Rust-API
            // callbacks from script handlers working.
            let in_runtime = run(|| tokio::runtime::Handle::try_current().is_ok()).await;
            assert!(in_runtime, "pool worker must hold a tokio runtime context");
        });
    }

    #[test]
    fn panicking_job_does_not_kill_worker() {
        test_runtime().block_on(async {
            ensure_pool();
            // try_run surfaces the panic as Err...
            let outcome = try_run(|| -> i32 { panic!("boom") }).await;
            assert!(outcome.is_err(), "panic must be reported as Err");
            // ...and the pool keeps working for subsequent jobs.
            let counter = Arc::new(AtomicUsize::new(0));
            for _ in 0..16 {
                let counter = Arc::clone(&counter);
                run(move || {
                    counter.fetch_add(1, Ordering::Relaxed);
                })
                .await;
            }
            assert_eq!(counter.load(Ordering::Relaxed), 16);
        });
    }

    #[test]
    fn many_jobs_run_to_completion() {
        test_runtime().block_on(async {
            ensure_pool();
            let mut handles = Vec::new();
            for index in 0..200usize {
                handles.push(tokio::spawn(async move { run(move || index * 2).await }));
            }
            let mut total = 0usize;
            for handle in handles {
                total += handle.await.unwrap();
            }
            assert_eq!(total, (0..200usize).map(|i| i * 2).sum::<usize>());
        });
    }

    #[cfg(target_os = "linux")]
    fn read_rss_kb() -> Option<u64> {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("VmRSS:") {
                return rest.split_whitespace().next()?.parse().ok();
            }
        }
        None
    }

    #[cfg(not(target_os = "linux"))]
    fn read_rss_kb() -> Option<u64> {
        None
    }

    /// Leak regression — the steady-state RSS of the *synchronous* handler
    /// path must not grow.  This is the in-process analogue of
    /// `async_pool::pool_steady_state_rss_does_not_grow`, and the guard for the
    /// free-threaded-CPython heap leak this pool was built to fix: because the
    /// worker threads are fixed and persistently attached, repeated handler
    /// invocations reuse the same per-thread mimalloc heaps instead of
    /// orphaning ~2 MB per reaped thread (the elastic `spawn_blocking` bug).
    ///
    /// Each job allocates a small Python dict so any per-handler retention
    /// shows up.  Skipped on non-Linux (no `/proc/self/status`).
    #[test]
    fn pool_steady_state_rss_does_not_grow() {
        test_runtime().block_on(async {
            ensure_pool();
            let Some(_) = read_rss_kb() else {
                eprintln!("[pool_steady_state_rss_does_not_grow] no /proc/self/status — skipping");
                return;
            };

            const BATCH: usize = 10_000;
            const PER_HANDLER_BUDGET_BYTES: u64 = 512;

            let fire = || async {
                for _ in 0..BATCH {
                    run(|| {
                        pyo3::Python::attach(|python| {
                            let dict = pyo3::types::PyDict::new(python);
                            let _ = dict.set_item("k", "v".repeat(32));
                        });
                    })
                    .await;
                }
            };

            // Warm-up batch (allocator free lists, interpreter caches, and the
            // worker threads' one-time heap growth).
            fire().await;
            let rss_baseline = read_rss_kb().unwrap();

            // Steady-state batch — must reuse the warmed heaps, not leak.
            fire().await;
            let rss_after = read_rss_kb().unwrap();

            let delta_kb = rss_after.saturating_sub(rss_baseline);
            let budget_kb = (BATCH as u64 * PER_HANDLER_BUDGET_BYTES) / 1024;
            assert!(
                delta_kb < budget_kb,
                "RSS grew {delta_kb} KB across {BATCH} steady-state sync handlers \
                 (budget {budget_kb} KB ≈ {PER_HANDLER_BUDGET_BYTES} bytes/handler) — likely a leak",
            );
        });
    }
}
