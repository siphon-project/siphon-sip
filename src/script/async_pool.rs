//! Long-running asyncio event-loop driver pool for script handlers.
//!
//! # Why this exists
//!
//! Each Python handler invocation used to spin up `loop.run_until_complete(coro)`
//! on a per-blocking-thread persistent loop.  `run_until_complete` returns the
//! moment the top-level coroutine resolves — any `asyncio.create_task(...)`
//! the handler spawned ends up in the loop's `_ready` queue but never runs,
//! because the loop stops *before* scheduling those new tasks.  Combined with
//! `tokio::task::spawn_blocking` distributing handlers across the entire
//! blocking pool, an orphan task on blocking-thread N has effectively no
//! chance of being driven again — its `await` points wake-up callbacks
//! land on a dormant loop nobody returns to.
//!
//! # How the pool fixes it
//!
//! At startup we spawn a small fixed pool of OS threads, each:
//!   1. Performs the same "persistent attach" trick as the tokio worker
//!      threads (one un-paired `PyGILState_Ensure` so free-threaded Python
//!      doesn't tear down the thread's mimalloc heap on every release).
//!   2. Creates a fresh `asyncio` event loop and binds it as the thread's
//!      current loop.
//!   3. Calls `loop.run_forever()` and stays there for the lifetime of
//!      the process.
//!
//! Handler dispatch then becomes:
//!   * Caller (a tokio blocking thread) calls the Python handler under
//!     attach to obtain a coroutine object.
//!   * Caller hands that coroutine to a driver via
//!     `asyncio.run_coroutine_threadsafe(coro, driver_loop)`, which returns
//!     a `concurrent.futures.Future` (CF).
//!   * A small `#[pyclass]` bridge is registered as a done-callback on the
//!     CF; when the CF settles, the bridge sends the resolved value (or
//!     exception) through a tokio `oneshot`.
//!   * Caller awaits the oneshot.
//!
//! Because the driver loop runs forever, every `asyncio.create_task` the
//! handler spawns is fully driven, including its `await` continuations on
//! pyo3-async-bridged tokio futures (the wake-up
//! `loop.call_soon_threadsafe(set_result, ...)` always lands on a live loop).

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::OnceLock;
use std::thread::JoinHandle;
use std::time::Duration;

use pyo3::exceptions::{PyRuntimeError, PyTimeoutError, PyValueError};
use pyo3::prelude::*;
use tokio::runtime::Handle as TokioHandle;
use tokio::sync::oneshot;
use tracing::{debug, error, info, warn};

/// Global pool, initialised once at server startup.  Handlers route through
/// here when present; tests and CLI helpers without a configured pool fall
/// back to the legacy per-thread `run_until_complete` path.
static GLOBAL: OnceLock<Arc<AsyncPool>> = OnceLock::new();

/// One driver thread + its asyncio event loop handle.
struct Driver {
    /// Python `asyncio.AbstractEventLoop` bound to this driver's OS thread.
    loop_obj: Py<PyAny>,
    /// OS thread running `loop.run_forever()`.  `None` after [`AsyncPool::drop`].
    thread: StdMutex<Option<JoinHandle<()>>>,
    /// Pings the heartbeat monitor has scheduled on this loop.
    pinged: Arc<AtomicU64>,
    /// Pings the loop has actually run. Equal to `pinged` means the loop is
    /// turning; falling behind means something is blocking on it.
    landed: Arc<AtomicU64>,
}

/// A `#[pyclass]` callable the heartbeat schedules on a driver loop. Running
/// at all is the whole signal — a pinned loop never gets to it.
#[pyclass]
struct DriverHeartbeat {
    landed: Arc<AtomicU64>,
}

#[pymethods]
impl DriverHeartbeat {
    fn __call__(&self) {
        self.landed.fetch_add(1, Ordering::Release);
    }
}

/// A coroutine handed to a driver: the oneshot its result arrives on, and the
/// `concurrent.futures.Future` driving it, which the waiter cancels if it gives
/// up first.
type SubmittedCoroutine = (oneshot::Receiver<PyResult<Py<PyAny>>>, Py<PyAny>);

/// How often the monitor pings each driver loop.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(1);

/// Pings a driver may owe before it counts as stalled. A loop running a
/// handler that is merely slow still drains its callback queue, so this only
/// trips on a loop that is not turning at all.
const HEARTBEAT_MISSES_BEFORE_STALLED: u64 = 5;

/// Fixed pool of asyncio event loops, each driven by a dedicated OS thread.
pub struct AsyncPool {
    drivers: Vec<Driver>,
    /// Round-robin selector. `Relaxed` is fine — we only care about
    /// even-ish distribution, not strict ordering.
    next: AtomicUsize,
    /// How long [`run_coroutine_via_pool`] waits for a coroutine before it
    /// gives the worker thread back.
    ///
    /// Every inbound message becomes a pyexec job, and an `async def` handler
    /// parks its worker here for as long as the coroutine takes. Unbounded,
    /// one handler that never settles costs that worker for the life of the
    /// process, and the `py_executor` watchdog — which trips on "work
    /// in-flight and nothing completed", independent of how full the pool is —
    /// then aborts a process whose pool may be mostly idle. Sized under the
    /// watchdog's stall window so a wedged handler is a failed call rather
    /// than a failed node.
    coroutine_timeout: Duration,
    /// `submit(coro, loop, done) -> concurrent.futures.Future`, compiled once.
    ///
    /// Handing a coroutine over used to take five separate Rust→Python calls
    /// per request: `import asyncio`, a getattr for `run_coroutine_threadsafe`,
    /// the call itself, a getattr for `add_done_callback`, and that call. Every
    /// one of them touches an object shared by every worker thread — the
    /// `asyncio` module, the loop, the `Future` type — and under free-threaded
    /// Python a shared-object touch is an atomic refcount update on a cache
    /// line all 24 threads are contending for. Doing the same work inside one
    /// Python function turns those into local lookups behind a single boundary
    /// crossing.
    submit_fn: Py<PyAny>,
}

impl AsyncPool {
    /// Initialise the global pool with `size` driver threads, each
    /// entering `tokio_handle` for its lifetime.  Subsequent calls are
    /// no-ops and return the previously-installed pool — safe to call
    /// multiple times (e.g. once from server bootstrap, then again from
    /// each test that wants pool-backed dispatch).
    ///
    /// `size` is clamped to at least 1.
    ///
    /// `tokio_handle` **must outlive the process / test binary** — every
    /// driver thread holds an `EnterGuard` for that handle for the entire
    /// time it's running.  Rust API methods invoked back from script
    /// coroutines (`proxy.send_request`, `proxy.subscribe_state.send`,
    /// `diameter.send_*`, etc.) resolve `Handle::current()` to the
    /// captured handle, so passing in a runtime that's about to be torn
    /// down (e.g. a `#[tokio::test]`'s implicit per-test runtime) leads
    /// to spurious "context was found, but it is being shutdown" panics
    /// once that runtime drops.  In production, pass the bootstrap
    /// runtime's `Handle::current()`.  In tests, use a long-lived
    /// static runtime.
    pub fn install(
        size: usize,
        tokio_handle: TokioHandle,
        coroutine_timeout: Duration,
    ) -> Arc<AsyncPool> {
        if let Some(existing) = GLOBAL.get() {
            return Arc::clone(existing);
        }
        let size = size.max(1);
        let pool = Arc::new(AsyncPool::spawn(size, tokio_handle, coroutine_timeout));
        match GLOBAL.set(Arc::clone(&pool)) {
            Ok(()) => {
                info!(
                    size,
                    coroutine_timeout_secs = coroutine_timeout.as_secs(),
                    "async script pool initialised"
                );
                let monitored = Arc::clone(&pool);
                if let Err(error) = std::thread::Builder::new()
                    .name("siphon-asyncio-heartbeat".to_string())
                    .spawn(move || AsyncPool::run_heartbeat(monitored))
                {
                    // Not fatal: dispatch works without it, but a pinned
                    // driver then shows up as handlers timing out with
                    // nothing saying why.
                    error!(%error, "could not start the asyncio driver heartbeat");
                }
                pool
            }
            Err(_) => {
                // Another thread won the race.  Tear our drivers back
                // down and use the installed pool instead.
                drop(pool);
                Arc::clone(GLOBAL.get().expect("pool just installed"))
            }
        }
    }

    /// Borrow the installed pool, if any.
    pub fn global() -> Option<Arc<AsyncPool>> {
        GLOBAL.get().cloned()
    }

    /// Number of driver threads.  Stable for the process lifetime.
    pub fn size(&self) -> usize {
        self.drivers.len()
    }

    fn spawn(size: usize, tokio_handle: TokioHandle, coroutine_timeout: Duration) -> Self {
        let mut drivers = Vec::with_capacity(size);
        for index in 0..size {
            drivers.push(spawn_driver(index, tokio_handle.clone()));
        }
        Self {
            drivers,
            next: AtomicUsize::new(0),
            coroutine_timeout,
            submit_fn: compile_submit_fn(),
        }
    }

    /// How long a synchronous caller waits for a coroutine before giving its
    /// worker thread back. See [`AsyncPool::coroutine_timeout`].
    pub fn coroutine_timeout(&self) -> Duration {
        self.coroutine_timeout
    }

    /// Whether this driver's loop has stopped running scheduled callbacks.
    ///
    /// True means something is blocking *on the loop thread* — a script API
    /// that blocks (Diameter, HTTP auth, DNS) called from inside an
    /// `async def` runs there, not on the worker. Every coroutine on that
    /// driver is stopped for the duration, including ones belonging to calls
    /// that never touched the blocking API.
    fn driver_is_stalled(driver: &Driver) -> bool {
        let pinged = driver.pinged.load(Ordering::Acquire);
        let landed = driver.landed.load(Ordering::Acquire);
        pinged.saturating_sub(landed) >= HEARTBEAT_MISSES_BEFORE_STALLED
    }

    /// Driver loops currently pinned by a blocking call.
    pub fn stalled_drivers(&self) -> usize {
        self.drivers
            .iter()
            .filter(|driver| Self::driver_is_stalled(driver))
            .count()
    }

    /// Ping every driver once and report how many are stalled. Called on the
    /// monitor's tick; also what the tests step by hand.
    fn heartbeat_tick(&self) -> usize {
        Python::attach(|python| {
            for driver in &self.drivers {
                let heartbeat = DriverHeartbeat {
                    landed: Arc::clone(&driver.landed),
                };
                let Ok(callback) = Py::new(python, heartbeat) else {
                    continue;
                };
                // `call_soon_threadsafe` only enqueues; the loop has to turn
                // for the callback to run, which is exactly the property under
                // test. A closed loop raises, and a driver whose loop is gone
                // is not a stall worth reporting.
                if driver
                    .loop_obj
                    .bind(python)
                    .call_method1("call_soon_threadsafe", (callback,))
                    .is_ok()
                {
                    driver.pinged.fetch_add(1, Ordering::Release);
                }
            }
        });
        self.stalled_drivers()
    }

    /// Run the heartbeat monitor until the process ends.
    fn run_heartbeat(pool: Arc<AsyncPool>) {
        let mut reported = 0usize;
        loop {
            std::thread::sleep(HEARTBEAT_INTERVAL);
            let stalled = pool.heartbeat_tick();
            if let Some(registry) = crate::metrics::try_metrics() {
                registry.async_drivers_stalled.set(stalled as i64);
            }
            if stalled != reported {
                if stalled > reported {
                    warn!(
                        stalled,
                        drivers = pool.drivers.len(),
                        "asyncio driver loop pinned by a blocking call: every coroutine on it \
                         is stopped until it returns. A script API that blocks (Diameter, HTTP \
                         auth, DNS) called from inside an `async def` runs on the loop thread."
                    );
                } else {
                    info!(stalled, "asyncio driver loops recovered");
                }
                reported = stalled;
            }
        }
    }

    /// Submit a Python coroutine for execution on one of the pool's
    /// asyncio loops.  Returns a oneshot receiver that resolves with the
    /// coroutine's result (or its exception, mapped to a `PyErr`), and the
    /// `concurrent.futures.Future` driving it.
    ///
    /// The caller keeps that future so it can `cancel()` a coroutine it has
    /// stopped waiting for: dropping the receiver alone leaves the task
    /// running on the driver loop for the life of the process, which is the
    /// leak a timeout would otherwise trade the wedged thread for.
    ///
    /// Caller must already hold an attach scope on `python` — `coroutine`
    /// is a `Bound` reference into that scope.
    pub fn submit<'py>(
        &self,
        python: Python<'py>,
        coroutine: &Bound<'py, PyAny>,
    ) -> PyResult<SubmittedCoroutine> {
        if self.drivers.is_empty() {
            return Err(PyRuntimeError::new_err("async pool has no drivers"));
        }
        // Round-robin, but step over a driver whose loop is pinned: handing a
        // coroutine to a stalled loop buys it a timeout rather than a turn.
        // Falls back to the round-robin pick when every driver is stalled —
        // there is nowhere better, and the wait is bounded either way.
        let start = self.next.fetch_add(1, Ordering::Relaxed);
        let index = (0..self.drivers.len())
            .map(|offset| (start + offset) % self.drivers.len())
            .find(|candidate| !Self::driver_is_stalled(&self.drivers[*candidate]))
            .unwrap_or(start % self.drivers.len());
        let driver_loop = self.drivers[index].loop_obj.bind(python);

        let (sender, receiver) = oneshot::channel();
        let bridge = AsyncPoolBridge {
            sender: StdMutex::new(Some(sender)),
        };
        let py_bridge = Py::new(python, bridge)?;

        // One boundary crossing for the whole handover. The `is_closed()`
        // pre-check this replaced cost a Python call on every request to
        // improve an error message; `run_coroutine_threadsafe` on a closed loop
        // raises anyway, so the message is recovered below instead.
        let cf = self
            .submit_fn
            .bind(python)
            .call1((coroutine, driver_loop, py_bridge))
            .map_err(|error| {
                if driver_loop
                    .call_method0("is_closed")
                    .and_then(|value| value.extract::<bool>())
                    .unwrap_or(false)
                {
                    PyRuntimeError::new_err(
                        "async pool driver loop is closed (pool already shut down)",
                    )
                } else {
                    error
                }
            })?;
        Ok((receiver, cf.unbind()))
    }
}

impl Drop for AsyncPool {
    fn drop(&mut self) {
        // Best-effort shutdown: stop each loop and join its thread.  The
        // global pool is normally never dropped (it lives in `OnceLock`),
        // so this only matters for `Arc<AsyncPool>` instances the loser
        // of an `install()` race holds briefly.
        for driver in &self.drivers {
            // `loop.call_soon_threadsafe(loop.stop)` schedules `stop()` on
            // the loop thread, which makes `run_forever` return on the
            // next iteration.
            let _ = Python::attach(|python| -> PyResult<()> {
                let bound = driver.loop_obj.bind(python);
                let stop = bound.getattr("stop")?;
                bound.call_method1("call_soon_threadsafe", (stop,))?;
                Ok(())
            });
        }
        for driver in &self.drivers {
            let thread = driver.thread.lock().ok().and_then(|mut t| t.take());
            if let Some(thread) = thread {
                if thread.join().is_err() {
                    warn!("async pool driver thread panicked during shutdown");
                }
            }
        }
    }
}

/// Spawn a single driver thread and return its handle once the loop is
/// ready to accept work.
fn spawn_driver(index: usize, tokio_handle: TokioHandle) -> Driver {
    let (tx, rx) = std::sync::mpsc::sync_channel::<DriverHandshake>(1);

    let thread = std::thread::Builder::new()
        .name(format!("siphon-asyncio-{index}"))
        .spawn(move || driver_main(index, tx, tokio_handle))
        .expect("failed to spawn asyncio driver thread");

    let handshake = rx
        .recv()
        .expect("asyncio driver thread dropped sender before handing back its loop");

    match handshake {
        DriverHandshake::Ready(loop_obj) => Driver {
            loop_obj,
            thread: StdMutex::new(Some(thread)),
            pinged: Arc::new(AtomicU64::new(0)),
            landed: Arc::new(AtomicU64::new(0)),
        },
        DriverHandshake::Failed(message) => {
            // We can't recover from a missing asyncio loop; abort.
            panic!("asyncio driver thread {index} failed during init: {message}");
        }
    }
}

enum DriverHandshake {
    Ready(Py<PyAny>),
    Failed(String),
}

fn driver_main(
    index: usize,
    handshake: std::sync::mpsc::SyncSender<DriverHandshake>,
    tokio_handle: TokioHandle,
) {
    // Enter the bootstrap Tokio runtime context for the lifetime of this
    // driver.  Every Rust API method script coroutines call into
    // (`proxy.send_request`, `proxy.subscribe_state`, `diameter.send_*`,
    // etc.) ultimately reaches `Handle::current()` or `tokio::spawn` — and
    // without an entered runtime the reactor lookup panics with
    // "there is no reactor running, must be called from the context of a
    // Tokio 1.x runtime".  The guard is dropped only when this function
    // returns, i.e. when the driver loop has stopped at shutdown.
    let _runtime_guard = tokio_handle.enter();

    // Persistent attach trick — same rationale as the tokio worker threads
    // (`server.rs::on_thread_start`): keep the per-thread Python state
    // alive for the lifetime of this OS thread so free-threaded mimalloc
    // doesn't churn the heap on every detach.
    //
    // SAFETY: the gstate is intentionally leaked.  The OS thread runs for
    // the lifetime of the process; the gstate is reclaimed on thread exit.
    // We never call PyGILState_Release / PyEval_RestoreThread — that omission
    // is what keeps the per-thread state alive.  The returned handles are
    // Copy (an enum + a raw pointer, no Drop), so they need no mem::forget;
    // letting the bindings fall out of scope is a no-op by construction.
    unsafe {
        let _gstate = pyo3::ffi::PyGILState_Ensure();
        let _tstate = pyo3::ffi::PyEval_SaveThread();
    }

    // Phase 1: build the loop and hand a handle back to the spawning thread.
    let loop_obj = match Python::attach(|python| -> PyResult<Py<PyAny>> {
        let asyncio = python.import("asyncio")?;
        let new_loop = asyncio.call_method0("new_event_loop")?;
        // `set_event_loop` binds the loop to *this* thread so any code
        // that still calls the deprecated `asyncio.get_event_loop()` on
        // the driver thread gets ours.
        asyncio.call_method1("set_event_loop", (&new_loop,))?;
        Ok(new_loop.unbind())
    }) {
        Ok(handle) => handle,
        Err(error) => {
            let _ = handshake.send(DriverHandshake::Failed(error.to_string()));
            return;
        }
    };

    let loop_for_caller = Python::attach(|python| loop_obj.clone_ref(python));
    if handshake
        .send(DriverHandshake::Ready(loop_for_caller))
        .is_err()
    {
        // Caller went away before we could hand off — nothing to drive.
        debug!(driver = index, "async pool spawner dropped; driver exiting");
        return;
    }

    // Phase 2: drive forever.  `run_forever` only returns when something
    // calls `loop.stop()` (via `call_soon_threadsafe`) — see `Drop`.
    let result = Python::attach(|python| -> PyResult<()> {
        let bound = loop_obj.bind(python);
        bound.call_method0("run_forever")?;
        Ok(())
    });
    if let Err(error) = result {
        error!(driver = index, %error, "asyncio driver loop terminated with error");
    } else {
        debug!(driver = index, "asyncio driver loop stopped cleanly");
    }

    // Phase 3: best-effort loop teardown.  Cancel any still-pending tasks
    // and close the loop so file descriptors aren't leaked.
    let _ = Python::attach(|python| -> PyResult<()> {
        let bound = loop_obj.bind(python);
        let asyncio = python.import("asyncio")?;
        let pending = asyncio.call_method1("all_tasks", (&bound,))?;
        let task_iter = pending.try_iter()?;
        for task in task_iter {
            let task = task?;
            let _ = task.call_method0("cancel");
        }
        bound.call_method0("close")?;
        Ok(())
    });
}

/// `concurrent.futures.Future.add_done_callback` adapter — invoked on the
/// driver thread when the CF settles, signals the awaiting tokio side via
/// a `oneshot::Sender`.
#[pyclass]
struct AsyncPoolBridge {
    /// `None` after the first `__call__`; bridges are single-shot.
    sender: StdMutex<Option<oneshot::Sender<PyResult<Py<PyAny>>>>>,
}

#[pymethods]
impl AsyncPoolBridge {
    /// Called by the driver loop when the wrapped CF resolves.  CPython's
    /// `concurrent.futures.Future` invokes done-callbacks synchronously
    /// inside `set_result` / `set_exception`, so we're already on the
    /// driver thread (which has Python attached).
    #[pyo3(signature = (future, /))]
    fn __call__(&self, python: Python<'_>, future: &Bound<'_, PyAny>) -> PyResult<()> {
        let Some(sender) = self
            .sender
            .lock()
            .map_err(|_| PyRuntimeError::new_err("AsyncPoolBridge sender mutex poisoned"))?
            .take()
        else {
            // Done-callback fired twice — nothing to do, but log because
            // CPython shouldn't call us twice for the same future.
            debug!("AsyncPoolBridge __call__ invoked twice; second call ignored");
            return Ok(());
        };

        let result = match future.call_method0("exception") {
            Ok(exception_obj) => {
                if exception_obj.is_none() {
                    match future.call_method0("result") {
                        Ok(value) => Ok(value.unbind()),
                        Err(error) => Err(error),
                    }
                } else {
                    // `BaseException` instance — wrap into a PyErr.
                    Err(PyErr::from_value(exception_obj))
                }
            }
            Err(error) => Err(error),
        };

        // Receiver may already be gone (caller cancelled / was dropped) —
        // that's fine, we just discard the result.  Stash the value as
        // `Py<PyAny>` so the receiver doesn't need to be in an attach
        // scope at await time.
        let _ = sender.send(result);
        // Free the future reference before returning so we don't keep
        // the CF alive longer than needed.
        let _ = python;
        Ok(())
    }
}

/// Convenience wrapper used by tests — fail fast if the pool isn't
/// installed instead of silently falling back to the legacy path.
#[cfg(test)]
pub(crate) fn require_global() -> Arc<AsyncPool> {
    AsyncPool::global().expect("AsyncPool::install was not called")
}

/// Run a coroutine on the async pool, blocking the calling thread until
/// it resolves.  Intended for synchronous callers (the script handler
/// dispatcher) that are already on a tokio blocking-pool thread.
///
/// Returns `Ok(None)` if no pool is installed — caller should fall back
/// to the legacy per-thread `run_until_complete` path.
pub(crate) fn run_coroutine_via_pool(
    python: Python<'_>,
    coroutine: &Bound<'_, PyAny>,
) -> PyResult<Option<Py<PyAny>>> {
    let Some(pool) = AsyncPool::global() else {
        return Ok(None);
    };

    // The handler's name is only needed if this wedges, so it is read lazily.
    // Reading it eagerly cost a `__qualname__` getattr and a String allocation
    // on every request to serve one log line on the rare timeout path. The
    // coroutine object outlives the wait (the caller holds `future`), so it is
    // still nameable afterwards.
    let (receiver, future) = pool.submit(python, coroutine)?;

    // We need to await the oneshot synchronously.  `Handle::current()`
    // works inside `tokio::task::spawn_blocking`; if the caller isn't
    // running under a tokio runtime at all we surface a clear error
    // instead of deadlocking.
    let runtime = tokio::runtime::Handle::try_current().map_err(|error| {
        PyRuntimeError::new_err(format!(
            "async pool dispatch requires a running tokio runtime: {error}"
        ))
    })?;

    // Release the Python attach scope while waiting so the driver thread
    // and any pyo3-async tokio futures aren't blocked behind us.  Under
    // free-threaded Python this is technically unnecessary (no GIL), but
    // it keeps the contract clear: the calling thread is idle while the
    // coroutine runs.
    //
    // Wrap the blocking wait in `block_in_place`: this function is also called
    // synchronously from a tokio runtime WORKER thread (the dispatcher's
    // answer-timeout sweep fires a sync `@b2bua.on_failure` on the B-leg
    // timeout path), and a bare `Handle::block_on` panics "Cannot start a
    // runtime from within a runtime" on a worker.  `block_in_place` hands the
    // worker's tasks off to a sibling so blocking here is safe; on the
    // py_executor pool / `spawn_blocking` threads that already reach this path
    // it is the same passthrough those callers use elsewhere (blocking.rs,
    // engine.rs, diameter.rs).
    //
    // Bounded, because this is the one place every `async def` handler in the
    // process funnels through. The responder is a done-callback on the
    // `concurrent.futures.Future`; a coroutine that never settles never fires
    // it and never drops the sender either, so not even `RecvError` arrives
    // and the wait has no other way out. Unbounded, one such handler costs
    // this worker for the life of the process, and the `py_executor` watchdog
    // — which trips on "work in-flight, nothing completed" whatever the pool's
    // fill — then aborts a node that still had idle workers and an empty
    // queue.
    let timeout = pool.coroutine_timeout();
    let outcome = python.detach(|| {
        tokio::task::block_in_place(|| runtime.block_on(tokio::time::timeout(timeout, receiver)))
    });

    match outcome {
        Ok(Ok(Ok(value))) => Ok(Some(value)),
        Ok(Ok(Err(py_err))) => Err(py_err),
        Ok(Err(_recv_err)) => Err(PyValueError::new_err(
            "async pool driver dropped the coroutine sender before completion",
        )),
        Err(_elapsed) => {
            // Cancel on the way out: the coroutine is still scheduled on its
            // driver, and abandoning it only would trade a wedged worker for a
            // task that lives for ever.
            let cancelled = future
                .bind(python)
                .call_method0("cancel")
                .and_then(|value| value.extract::<bool>())
                .unwrap_or(false);
            let handler = coroutine_name(coroutine);
            error!(
                handler = %handler,
                timeout_secs = timeout.as_secs(),
                cancelled,
                "async script handler did not settle within the coroutine timeout;                  giving the worker thread back and failing this call. The handler is                  awaiting something that never completes — an unbounded backend call,                  a DNS lookup, or a future nothing resolves."
            );
            Err(PyTimeoutError::new_err(format!(
                "async handler '{handler}' did not settle within {}s",
                timeout.as_secs()
            )))
        }
    }
}

/// The handler name behind a coroutine object, for the timeout log line.
///
/// `__qualname__` names the `async def` the script author wrote; the code
/// object's name is the fallback for a coroutine built some other way.
/// Compile `submit(coro, loop, done)` once, for [`AsyncPool::submit_fn`].
///
/// Falls back to a `None` object on failure rather than panicking at startup;
/// `submit` then raises on first use, which surfaces as a failed call instead of
/// a node that will not boot.
fn compile_submit_fn() -> Py<PyAny> {
    const SOURCE: &str = "\
import asyncio


def submit(coro, loop, done):
    future = asyncio.run_coroutine_threadsafe(coro, loop)
    future.add_done_callback(done)
    return future
";
    Python::attach(|python| {
        let build = || -> PyResult<Py<PyAny>> {
            let module = PyModule::from_code(
                python,
                &std::ffi::CString::new(SOURCE)?,
                &std::ffi::CString::new("siphon_async_pool_submit.py")?,
                &std::ffi::CString::new("siphon_async_pool_submit")?,
            )?;
            Ok(module.getattr("submit")?.unbind())
        };
        match build() {
            Ok(function) => function,
            Err(error) => {
                error!(%error, "could not compile the async pool submit helper");
                python.None()
            }
        }
    })
}

fn coroutine_name(coroutine: &Bound<'_, PyAny>) -> String {
    coroutine
        .getattr("__qualname__")
        .and_then(|value| value.extract::<String>())
        .or_else(|_| {
            coroutine
                .getattr("cr_code")
                .and_then(|code| code.getattr("co_name"))
                .and_then(|value| value.extract::<String>())
        })
        .unwrap_or_else(|_| "<unknown>".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyo3::types::{PyAnyMethods, PyDict, PyDictMethods, PyModule, PyModuleMethods};
    use std::ffi::CString;
    use std::sync::atomic::{AtomicBool, AtomicUsize};
    use std::sync::Arc;
    use std::time::Duration;

    /// Bridge a tokio sleep into Python via `future_into_py` — the same
    /// shape `cache.fetch` / `registrar.aor_count` use in real handlers.
    /// Used to verify that `create_task`-spawned coroutines can `await`
    /// pyo3-async futures and complete.
    #[pyfunction]
    fn _ap_async_op(py: Python<'_>) -> PyResult<Bound<'_, PyAny>> {
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            tokio::time::sleep(Duration::from_millis(2)).await;
            Ok(7i64)
        })
    }

    /// Mimics the synchronous `block_in_place + Handle::current().block_on(...)`
    /// pattern used by `proxy.send_request`, `proxy.subscribe_state.send`,
    /// `diameter.send_*`, etc.  Without entering the bootstrap Tokio
    /// runtime on the driver thread, `Handle::current()` panics with
    /// "there is no reactor running".  Used by the regression test below.
    #[pyfunction]
    fn _ap_blocking_tokio_call() -> PyResult<i64> {
        let value = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                tokio::time::sleep(Duration::from_millis(2)).await;
                42i64
            })
        });
        Ok(value)
    }

    fn install_test_module(python: Python<'_>) {
        // Module name needs to be process-unique because we install once
        // per test binary.  Re-installation just overwrites which is OK.
        let module = PyModule::new(python, "_siphon_async_pool_test").unwrap();
        module
            .add_function(pyo3::wrap_pyfunction!(_ap_async_op, &module).unwrap())
            .unwrap();
        module
            .add_function(pyo3::wrap_pyfunction!(_ap_blocking_tokio_call, &module).unwrap())
            .unwrap();
        let sys = python.import("sys").unwrap();
        sys.getattr("modules")
            .unwrap()
            .set_item("_siphon_async_pool_test", &module)
            .unwrap();
    }

    /// Long-lived multi-threaded runtime used by every test in this
    /// module.  Cannot use the implicit per-test runtime created by
    /// `#[tokio::test]`: the pool's driver threads enter the runtime
    /// captured at install time and hold the guard forever, so a
    /// per-test runtime gets torn down underneath the drivers and
    /// subsequent tests panic with "context was found, but it is being
    /// shutdown".  A single process-wide runtime survives all tests.
    fn test_runtime() -> &'static tokio::runtime::Runtime {
        static RUNTIME: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
        RUNTIME.get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .enable_all()
                .thread_name("async-pool-test-rt")
                .build()
                .expect("failed to build test runtime")
        })
    }

    /// Tests share one process-global `AsyncPool` (`GLOBAL`) and the harness
    /// runs them on parallel threads.  The leak probes (`pool_drains_*`,
    /// `pool_steady_state_*`) read the per-driver asyncio task tables / the
    /// process-global jemalloc `allocated` gauge — both of which a *sibling*
    /// test dispatching to the same pool perturbs mid-probe.  That is a
    /// cross-test race, not a leak.  Every pool test holds this guard for its
    /// whole duration, so exactly one runs at a time and the probes observe a
    /// quiescent pool.  Poison is recovered deliberately: a panicking test has
    /// already failed and must not cascade a poison error into the others.
    static POOL_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn pool_test_guard() -> std::sync::MutexGuard<'static, ()> {
        POOL_SERIAL
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    /// Short enough that a wedged-coroutine test finishes, long enough that a
    /// normal coroutine in these tests never races it.
    const TEST_COROUTINE_TIMEOUT: Duration = Duration::from_secs(3);

    fn ensure_pool() -> Arc<AsyncPool> {
        Python::initialize();
        Python::attach(install_test_module);
        AsyncPool::install(2, test_runtime().handle().clone(), TEST_COROUTINE_TIMEOUT)
    }

    /// Build a coroutine factory from a Python source string.  Returns
    /// the factory callable, which yields a fresh coroutine each call.
    fn build_factory(python: Python<'_>, source: &str) -> Py<PyAny> {
        let code = CString::new(source).unwrap();
        let globals = PyDict::new(python);
        python.run(code.as_c_str(), Some(&globals), None).unwrap();
        globals.get_item("factory").unwrap().unwrap().unbind()
    }

    /// Drives a Python coroutine factory through the pool from a
    /// blocking-pool context, then asserts on the returned value.
    async fn dispatch(factory: Arc<Py<PyAny>>) -> Py<PyAny> {
        tokio::task::spawn_blocking(move || {
            Python::attach(|python| {
                let coro = factory.bind(python).call0().unwrap();
                run_coroutine_via_pool(python, &coro)
                    .unwrap()
                    .expect("pool must be installed in tests")
            })
        })
        .await
        .unwrap()
    }

    #[test]
    fn pool_runs_simple_coroutine() {
        let _serial = pool_test_guard();
        test_runtime().block_on(async move {
            ensure_pool();
            let factory = Python::attach(|python| {
                Arc::new(build_factory(
                    python,
                    "async def factory():\n    return 1 + 2\n",
                ))
            });
            let value = dispatch(factory).await;
            let extracted: i64 = Python::attach(|python| value.bind(python).extract().unwrap());
            assert_eq!(extracted, 3);
        });
    }

    /// The submit helper must still fail loudly on a closed loop.
    ///
    /// `submit` replaced a per-request `loop.is_closed()` pre-check, whose only
    /// job was to turn a confusing error into a clear one. Dropping it is only
    /// safe because `run_coroutine_threadsafe` raises on a closed loop by
    /// itself — if it returned a future that never settled instead, the removal
    /// would have traded a clear error for a handler that hangs until the
    /// coroutine timeout. This pins that precondition rather than the wording.
    #[test]
    fn submit_helper_raises_on_a_closed_loop() {
        Python::initialize();
        Python::attach(|python| {
            let submit = compile_submit_fn();
            let asyncio = python.import("asyncio").unwrap();
            let event_loop = asyncio.call_method0("new_event_loop").unwrap();
            event_loop.call_method0("close").unwrap();

            let coroutine = build_factory(python, "async def factory():\n    return 1\n");
            let coroutine = coroutine.bind(python).call0().unwrap();
            let noop = python
                .eval(
                    &std::ffi::CString::new("lambda future: None").unwrap(),
                    None,
                    None,
                )
                .unwrap();

            let outcome = submit.bind(python).call1((coroutine, event_loop, noop));

            assert!(
                outcome.is_err(),
                "submitting to a closed loop must raise, not hand back a future \
                 that never settles"
            );
        });
    }

    /// Regression: `run_coroutine_via_pool` must be safe to call synchronously
    /// from a tokio runtime WORKER thread. The dispatcher's B-leg answer-timeout
    /// sweep runs in the `select!` loop (a worker) and fires a sync
    /// `@b2bua.on_failure` through this path; before the `block_in_place` wrap
    /// the bare `Handle::block_on` panicked "Cannot start a runtime from within a
    /// runtime" on every B-leg timeout, and the spawned task resolved to a
    /// JoinError. `tokio::spawn` (NOT `spawn_blocking`) reproduces the worker
    /// context exactly.
    #[test]
    fn pool_dispatch_from_worker_thread_does_not_panic() {
        let _serial = pool_test_guard();
        test_runtime().block_on(async move {
            ensure_pool();
            let factory = Python::attach(|python| {
                Arc::new(build_factory(
                    python,
                    "async def factory():\n    return 5\n",
                ))
            });
            let value = tokio::spawn(async move {
                Python::attach(|python| {
                    let coro = factory.bind(python).call0().unwrap();
                    run_coroutine_via_pool(python, &coro)
                        .unwrap()
                        .expect("pool must be installed in tests")
                })
            })
            .await
            .expect("worker-thread dispatch must not panic");
            let extracted: i64 = Python::attach(|python| value.bind(python).extract().unwrap());
            assert_eq!(extracted, 5);
        });
    }

    /// Regression test for the orphan-create_task bug: an `asyncio.create_task`
    /// spawned inside a handler must run to completion before `submit`
    /// returns.  Previously, `run_until_complete` stopped the loop the
    /// moment the handler coroutine resolved, leaving the spawned task
    /// stuck in `_ready` forever.
    #[test]
    fn pool_drives_create_task_to_completion() {
        let _serial = pool_test_guard();
        test_runtime().block_on(async move {
            ensure_pool();
            let factory = Python::attach(|python| {
                Arc::new(build_factory(
                    python,
                    "import asyncio\n\
                     _hits = []\n\
                     async def child():\n\
                     \x20\x20\x20\x20await asyncio.sleep(0.01)\n\
                     \x20\x20\x20\x20_hits.append('child ran')\n\
                     async def factory():\n\
                     \x20\x20\x20\x20task = asyncio.create_task(child())\n\
                     \x20\x20\x20\x20# Don't await it — fire-and-forget.\n\
                     \x20\x20\x20\x20await asyncio.sleep(0)\n\
                     \x20\x20\x20\x20return task\n",
                ))
            });
            let task = dispatch(factory).await;

            // Give the driver loop a beat to actually run the orphan task.
            tokio::time::sleep(Duration::from_millis(100)).await;

            Python::attach(|python| {
                let task = task.bind(python);
                assert!(
                    task.call_method0("done")
                        .unwrap()
                        .extract::<bool>()
                        .unwrap(),
                    "child task must run to completion after handler returns"
                );
            });
        });
    }

    /// `create_task` whose body awaits a pyo3-async-bridged tokio future —
    /// this is the exact shape of `queueing.drain` in the bug report.  The
    /// orphan task must reach `await helper._ap_async_op()`, the tokio
    /// future must wake it via `loop.call_soon_threadsafe(set_result, ...)`,
    /// and the task body must finish.
    #[test]
    fn pool_drives_create_task_through_pyo3_async_future() {
        let _serial = pool_test_guard();
        test_runtime().block_on(async move {
            ensure_pool();
            let factory = Python::attach(|python| {
                Arc::new(build_factory(
                    python,
                    "import asyncio\n\
                     import _siphon_async_pool_test as helper\n\
                     async def child():\n\
                     \x20\x20\x20\x20return await helper._ap_async_op()\n\
                     async def factory():\n\
                     \x20\x20\x20\x20task = asyncio.create_task(child())\n\
                     \x20\x20\x20\x20await asyncio.sleep(0)\n\
                     \x20\x20\x20\x20return task\n",
                ))
            });
            let task = dispatch(factory).await;

            // Wait for the orphan task to finish on the driver loop.
            for _ in 0..50 {
                let done = Python::attach(|python| {
                    task.bind(python)
                        .call_method0("done")
                        .unwrap()
                        .extract::<bool>()
                        .unwrap()
                });
                if done {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }

            Python::attach(|python| {
                let task = task.bind(python);
                assert!(
                    task.call_method0("done")
                        .unwrap()
                        .extract::<bool>()
                        .unwrap(),
                    "child task awaiting future_into_py future must complete"
                );
                let value: i64 = task.call_method0("result").unwrap().extract().unwrap();
                assert_eq!(value, 7);
            });
        });
    }

    /// Concurrency smoke test — submit many coroutines simultaneously
    /// across the pool's drivers and verify each resolves to its own
    /// distinct value.
    #[test]
    fn pool_handles_concurrent_submissions() {
        let _serial = pool_test_guard();
        test_runtime().block_on(async move {
            ensure_pool();
            let factory = Python::attach(|python| {
                Arc::new(build_factory(
                    python,
                    "import _siphon_async_pool_test as helper\n\
                     async def factory():\n\
                     \x20\x20\x20\x20return await helper._ap_async_op()\n",
                ))
            });

            let success = Arc::new(AtomicUsize::new(0));
            let mut handles = Vec::new();
            for _ in 0..40 {
                let factory = Arc::clone(&factory);
                let success = Arc::clone(&success);
                handles.push(tokio::spawn(async move {
                    let value = dispatch(factory).await;
                    let extracted: i64 =
                        Python::attach(|python| value.bind(python).extract().unwrap());
                    assert_eq!(extracted, 7);
                    success.fetch_add(1, Ordering::Relaxed);
                }));
            }
            for handle in handles {
                handle.await.unwrap();
            }
            assert_eq!(success.load(Ordering::Relaxed), 40);
        });
    }

    /// Regression test for the v1f2cbc6 panic: a script coroutine that
    /// calls back into a Rust API doing
    /// `tokio::task::block_in_place(|| Handle::current().block_on(...))`
    /// must work — that is the synchronous shape used by
    /// `proxy.send_request`, `proxy.subscribe_state.send`,
    /// `diameter.send_*`, `proxy.relay`, etc.  Driver threads enter the
    /// bootstrap runtime in `driver_main`; without that, `Handle::current()`
    /// inside the API call panics with "there is no reactor running".
    #[test]
    fn pool_drivers_have_tokio_runtime_context() {
        let _serial = pool_test_guard();
        test_runtime().block_on(async move {
            ensure_pool();
            let factory = Python::attach(|python| {
                Arc::new(build_factory(
                    python,
                    "import _siphon_async_pool_test as helper\n\
                     async def factory():\n\
                     \x20\x20\x20\x20return helper._ap_blocking_tokio_call()\n",
                ))
            });
            let value = dispatch(factory).await;
            let extracted: i64 = Python::attach(|python| value.bind(python).extract().unwrap());
            assert_eq!(extracted, 42);
        });
    }

    /// Force a Python-side gc.collect() to break any cyclic references
    /// that asyncio leaves behind (specifically the
    /// `destination._done_callbacks → _call_check_cancel → destination`
    /// cycle that `asyncio.futures._chain_future` sets up between the
    /// `concurrent.futures.Future` returned by `run_coroutine_threadsafe`
    /// and the asyncio Task on the driver loop).  Refcount GC clears
    /// everything else in the chain promptly.
    fn force_python_gc() {
        Python::attach(|python| {
            let gc = python.import("gc").expect("gc module");
            // Three passes covers the rare case where collecting one
            // generation makes another collectable.
            for _ in 0..3 {
                gc.call_method0("collect").expect("gc.collect");
            }
        });
    }

    /// Submit a no-op coroutine to each driver so the loop has a chance
    /// to drain its `_ready` queue (the asyncio Task chain takes one
    /// extra loop iteration after `set_result` to fire its callbacks).
    async fn flush_drivers() {
        let pool = require_global();
        let factory = Python::attach(|python| {
            Arc::new(build_factory(
                python,
                "async def factory():\n    return None\n",
            ))
        });
        // Submit pool.size() coroutines so each driver definitely sees one.
        let mut handles = Vec::new();
        for _ in 0..pool.size() * 2 {
            let factory = Arc::clone(&factory);
            handles.push(tokio::spawn(async move {
                dispatch(factory).await;
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
    }

    /// Count outstanding asyncio tasks across all driver loops.  Uses
    /// `asyncio.run_coroutine_threadsafe` to query each driver from the
    /// driver's own thread (asyncio task lists aren't thread-safe to
    /// inspect from outside the loop thread).
    async fn count_pending_tasks_per_driver() -> Vec<usize> {
        let pool = require_global();
        let factory = Python::attach(|python| {
            Arc::new(build_factory(
                python,
                "import asyncio\n\
                 async def factory():\n\
                 \x20\x20\x20\x20me = asyncio.current_task()\n\
                 \x20\x20\x20\x20# Don't count ourselves — we're the probe.\n\
                 \x20\x20\x20\x20return sum(\n\
                 \x20\x20\x20\x20\x20\x20\x20\x201 for t in asyncio.all_tasks() if t is not me\n\
                 \x20\x20\x20\x20)\n",
            ))
        });

        // Submit one probe to each driver.  Round-robin in `submit`
        // means submitting `size()` probes hits each driver exactly
        // once, but submission ordering is racy — easier to submit
        // (size() * K) and bucket by driver index after the fact.
        // Simpler still: submit `size()` and accept that a single
        // driver may see two probes while another sees zero.  For our
        // assertion (all counts == 0) that's fine.
        let mut counts = Vec::new();
        for _ in 0..pool.size() {
            let factory = Arc::clone(&factory);
            let value = dispatch(factory).await;
            let count: usize = Python::attach(|python| value.bind(python).extract().unwrap());
            counts.push(count);
        }
        counts
    }

    #[cfg(target_os = "linux")]
    fn read_rss_kb() -> Option<u64> {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("VmRSS:") {
                let kb: u64 = rest.split_whitespace().next()?.parse().ok()?;
                return Some(kb);
            }
        }
        None
    }

    #[cfg(not(target_os = "linux"))]
    fn read_rss_kb() -> Option<u64> {
        None
    }

    /// Leak test 1 — a Python object created by the handler must be
    /// reclaimed once we drop our last reference.  If the asyncio Task
    /// or the dispatch chain is hanging onto the coroutine frame, the
    /// returned Marker stays alive and the weakref keeps resolving.
    #[test]
    fn pool_releases_python_objects_after_handler() {
        let _serial = pool_test_guard();
        test_runtime().block_on(async move {
            ensure_pool();
            let factory = Python::attach(|python| {
                Arc::new(build_factory(
                    python,
                    "class Marker:\n\
                     \x20\x20\x20\x20pass\n\
                     async def factory():\n\
                     \x20\x20\x20\x20return Marker()\n",
                ))
            });

            // Run the handler, capture the returned Marker, then a
            // weakref to it before dropping the strong ref.
            let marker = dispatch(Arc::clone(&factory)).await;
            let weak = Python::attach(|python| {
                let weakref = python.import("weakref").unwrap();
                weakref
                    .call_method1("ref", (marker.bind(python),))
                    .unwrap()
                    .unbind()
            });
            drop(marker);

            // Let the loop process anything left in its ready queue,
            // then force gc to break the asyncio chain_future cycle.
            flush_drivers().await;
            force_python_gc();

            // Weakref should resolve to None — the Marker was reclaimed.
            let alive = Python::attach(|python| {
                let weak_obj = weak.bind(python);
                let result = weak_obj.call0().unwrap();
                !result.is_none()
            });
            assert!(
                !alive,
                "handler-returned Python object leaked: weakref still resolves \
                 (asyncio Task chain or dispatcher path is keeping the \
                 coroutine frame alive)"
            );
        });
    }

    /// Leak test 2 — after a batch of handlers, every driver loop's
    /// asyncio task table must drain back to 0 (probe task aside).
    /// Lingering tasks indicate that the asyncio Task chain isn't
    /// being released, which would slowly accumulate frames + locals.
    #[test]
    fn pool_drains_asyncio_tasks_after_batch() {
        let _serial = pool_test_guard();
        test_runtime().block_on(async move {
            ensure_pool();
            let factory = Python::attach(|python| {
                Arc::new(build_factory(
                    python,
                    "import asyncio\n\
                     async def child():\n\
                     \x20\x20\x20\x20await asyncio.sleep(0)\n\
                     async def factory():\n\
                     \x20\x20\x20\x20await asyncio.create_task(child())\n\
                     \x20\x20\x20\x20return None\n",
                ))
            });

            // Submit 50 handlers, each spawning + awaiting a child task.
            for _ in 0..50 {
                let factory = Arc::clone(&factory);
                dispatch(factory).await;
            }

            // Let drivers settle, then force a GC pass.
            flush_drivers().await;
            force_python_gc();
            flush_drivers().await;

            // Poll until every driver's asyncio task table drains. A completed
            // task lingers in `asyncio.all_tasks()` until the driver loop runs its
            // done-callback + finalizer, which can lag the single flush above — so
            // give the drivers a bounded window (flush + GC + a short settle) to
            // reach 0 rather than probing a beat too early. This does NOT weaken
            // the leak assertion: a genuine leak never drains, so the loop exhausts
            // its window and still fails; it only removes the finalization race.
            let mut counts = count_pending_tasks_per_driver().await;
            for _ in 0..50 {
                if counts.iter().all(|count| *count == 0) {
                    break;
                }
                flush_drivers().await;
                force_python_gc();
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                counts = count_pending_tasks_per_driver().await;
            }
            for (driver, count) in counts.iter().enumerate() {
                assert_eq!(
                    *count, 0,
                    "driver {} has {} pending tasks after handler batch — leak \
                     (did not drain within the poll window)",
                    driver, count
                );
            }
        });
    }

    /// Leak test 3 — live allocated bytes must reach a steady state.  Run a
    /// warm-up batch (allocator free-lists, Python interp caches grow),
    /// snapshot jemalloc `stats.allocated`, run an equal batch, snapshot
    /// again.  The delta amortised per handler should be tiny.
    ///
    /// Gates on jemalloc `allocated` (live bytes), **not** RSS.  jemalloc
    /// retains freed pages, so RSS stays elevated under a constant,
    /// completed-call workload even with zero leak — project convention is
    /// that RSS alone is too noisy to gate on for exactly that reason, so the
    /// gate is `allocated`.  It is the precise leak signal; RSS is
    /// still printed for context.
    ///
    /// Skipped if jemalloc stats are unavailable.  jemalloc-gated because the
    /// stats interface only exists when jemalloc is the global allocator.
    #[cfg(not(target_env = "msvc"))]
    #[test]
    fn pool_steady_state_allocated_does_not_grow() {
        let _serial = pool_test_guard();
        test_runtime().block_on(async move {
            ensure_pool();
            let factory = Python::attach(|python| {
                Arc::new(build_factory(
                    python,
                    // Allocate a small dict on each call so any
                    // per-handler retention shows up.
                    "async def factory():\n\
                     \x20\x20\x20\x20d = {'k': 'v' * 32}\n\
                     \x20\x20\x20\x20return None\n",
                ))
            });

            // jemalloc snapshots its stats at epoch advance; without the
            // advance the reads are stale.
            fn allocated_bytes() -> Option<u64> {
                tikv_jemalloc_ctl::epoch::advance().ok()?;
                tikv_jemalloc_ctl::stats::allocated::read()
                    .ok()
                    .map(|value| value as u64)
            }

            let Some(_) = allocated_bytes() else {
                eprintln!(
                    "[pool_steady_state_allocated_does_not_grow] jemalloc stats unavailable — skipping"
                );
                return;
            };

            const BATCH: usize = 10_000;
            const PER_HANDLER_BUDGET_BYTES: u64 = 512;

            // Warm-up batch (allocator free lists, Python interp caches, ...).
            for _ in 0..BATCH {
                let factory = Arc::clone(&factory);
                dispatch(factory).await;
            }
            flush_drivers().await;
            force_python_gc();
            flush_drivers().await;

            let rss_baseline = read_rss_kb();
            let allocated_baseline = allocated_bytes().unwrap();

            for _ in 0..BATCH {
                let factory = Arc::clone(&factory);
                dispatch(factory).await;
            }
            flush_drivers().await;
            force_python_gc();
            flush_drivers().await;

            let allocated_delta = allocated_bytes().unwrap().saturating_sub(allocated_baseline);
            let budget_bytes = BATCH as u64 * PER_HANDLER_BUDGET_BYTES;

            // RSS is logged for context only — jemalloc page retention makes
            // it climb without a real leak, which is exactly why the gate is
            // on `allocated` rather than RSS.
            if let (Some(before), Some(after)) = (rss_baseline, read_rss_kb()) {
                eprintln!(
                    "[pool_steady_state_allocated_does_not_grow] RSS delta {} KB (context only) \
                     vs allocated delta {} bytes (budget {} bytes)",
                    after.saturating_sub(before),
                    allocated_delta,
                    budget_bytes,
                );
            }

            assert!(
                allocated_delta < budget_bytes,
                "jemalloc allocated grew {} bytes across {} steady-state handlers \
                 (budget {} bytes ≈ {} bytes/handler) — likely a leak",
                allocated_delta, BATCH, budget_bytes, PER_HANDLER_BUDGET_BYTES,
            );
        });
    }

    /// Coroutine that raises must surface the exception to the caller.
    #[test]
    fn pool_propagates_python_exception() {
        let _serial = pool_test_guard();
        test_runtime().block_on(async move {
            ensure_pool();
            let factory = Python::attach(|python| {
                Arc::new(build_factory(
                    python,
                    "async def factory():\n\
                     \x20\x20\x20\x20raise ValueError('boom')\n",
                ))
            });
            let outcome = tokio::task::spawn_blocking(move || {
                Python::attach(|python| {
                    let coro = factory.bind(python).call0().unwrap();
                    run_coroutine_via_pool(python, &coro)
                })
            })
            .await
            .unwrap();

            let error = outcome.expect_err("ValueError must propagate");
            assert!(
                error.to_string().contains("boom"),
                "expected raised exception, got {error}"
            );
        });
    }

    /// The reproduction for the incident this bound exists for.
    ///
    /// An `async def` handler that never settles used to park its worker
    /// thread for the life of the process: the responder is a done-callback on
    /// the `concurrent.futures.Future`, so a coroutine that never resolves
    /// never fires it and never drops the sender either — not even `RecvError`
    /// arrives. On a node whose handlers are all async, a few of these take
    /// every worker, `completed` goes flat, and the `py_executor` watchdog
    /// aborts the process.
    ///
    /// The worker must come back, with an error naming the handler, and the
    /// abandoned coroutine must be cancelled rather than left on the driver.
    #[test]
    fn a_coroutine_that_never_settles_gives_the_worker_back() {
        let _serial = pool_test_guard();
        test_runtime().block_on(async move {
            ensure_pool();
            let before = count_pending_tasks_per_driver().await;

            let factory = Python::attach(|python| {
                Arc::new(build_factory(
                    python,
                    concat!(
                        "import asyncio\n",
                        "async def wedged_handler():\n",
                        "    await asyncio.Event().wait()\n",
                        "def factory():\n",
                        "    return wedged_handler()\n",
                    ),
                ))
            });

            let started = std::time::Instant::now();
            let outcome = tokio::task::spawn_blocking(move || {
                Python::attach(|python| {
                    let coro = factory.bind(python).call0().unwrap();
                    let result = run_coroutine_via_pool(python, &coro);
                    result.map(|_| ()).map_err(|error| error.to_string())
                })
            })
            .await
            .unwrap();
            let elapsed = started.elapsed();

            let message = outcome.expect_err("a coroutine that never settles must not succeed");
            assert!(
                message.contains("wedged_handler"),
                "the error names the handler that wedged, got: {message}"
            );
            assert!(
                message.contains("TimeoutError"),
                "the error is a timeout, got: {message}"
            );
            assert!(
                elapsed >= TEST_COROUTINE_TIMEOUT,
                "returned before the timeout ({elapsed:?})"
            );
            assert!(
                elapsed < TEST_COROUTINE_TIMEOUT * 4,
                "the worker was parked well past the timeout ({elapsed:?})"
            );

            // The abandoned coroutine is cancelled, not left running: dropping
            // the receiver alone would trade a wedged thread for a task that
            // lives for ever on the driver loop.
            flush_drivers().await;
            force_python_gc();
            flush_drivers().await;
            let after = count_pending_tasks_per_driver().await;
            assert_eq!(
                after.iter().sum::<usize>(),
                before.iter().sum::<usize>(),
                "the timed-out coroutine is still scheduled on a driver loop"
            );
        });
    }

    /// A driver loop pinned by a blocking call is reported, and recovers.
    ///
    /// This is the failure the coroutine timeout alone cannot fix: the worker
    /// gets its thread back, but the loop stays parked and every coroutine on
    /// it — including calls that never touched the blocking API — is stopped.
    /// Without a signal for it, bounding the wait turns a loud crash into a
    /// node that quietly fails async dispatch.
    #[test]
    fn a_driver_pinned_by_a_blocking_call_is_reported_stalled() {
        let _serial = pool_test_guard();
        test_runtime().block_on(async move {
            let pool = ensure_pool();
            // Settle: a pool that has just run other tests may owe a ping.
            for _ in 0..HEARTBEAT_MISSES_BEFORE_STALLED + 2 {
                pool.heartbeat_tick();
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            assert_eq!(pool.heartbeat_tick(), 0, "a turning pool has no stalls");

            // Pin every driver the way a blocking script API does: a callback
            // that sleeps on the loop thread itself.
            let release = Arc::new(AtomicBool::new(false));
            let blocked = Arc::new(AtomicUsize::new(0));
            Python::attach(|python| {
                for driver in &pool.drivers {
                    let callback = Py::new(
                        python,
                        BlockingCallback {
                            release: Arc::clone(&release),
                            entered: Arc::clone(&blocked),
                        },
                    )
                    .unwrap();
                    driver
                        .loop_obj
                        .bind(python)
                        .call_method1("call_soon_threadsafe", (callback,))
                        .unwrap();
                }
            });
            while blocked.load(Ordering::Acquire) < pool.drivers.len() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }

            for _ in 0..HEARTBEAT_MISSES_BEFORE_STALLED + 1 {
                pool.heartbeat_tick();
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            assert_eq!(
                pool.stalled_drivers(),
                pool.drivers.len(),
                "a loop blocked on its own thread must be reported stalled"
            );

            release.store(true, Ordering::Release);
            let mut recovered = false;
            for _ in 0..100 {
                pool.heartbeat_tick();
                tokio::time::sleep(Duration::from_millis(20)).await;
                if pool.stalled_drivers() == 0 {
                    recovered = true;
                    break;
                }
            }
            assert!(recovered, "the drivers must clear once the block returns");
        });
    }

    /// A callback that parks the driver loop it runs on until released — what
    /// a blocking script API does when called from inside an `async def`.
    #[pyclass]
    struct BlockingCallback {
        release: Arc<AtomicBool>,
        entered: Arc<AtomicUsize>,
    }

    #[pymethods]
    impl BlockingCallback {
        fn __call__(&self, python: Python<'_>) {
            self.entered.fetch_add(1, Ordering::Release);
            python.detach(|| {
                while !self.release.load(Ordering::Acquire) {
                    std::thread::sleep(Duration::from_millis(5));
                }
            });
        }
    }
}
