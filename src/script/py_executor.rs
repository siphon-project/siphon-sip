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
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use tokio::runtime::Handle as TokioHandle;
use tokio::sync::oneshot;
use tracing::{debug, error, info, warn};

/// A unit of work submitted to the pool. The closure is fully self-contained —
/// it captures whatever it needs (including any result channel).
type Job = Box<dyn FnOnce() + Send + 'static>;

/// Tunables for the synchronous Python executor pool.
#[derive(Clone, Copy, Debug)]
pub struct ExecutorConfig {
    /// Always-on worker threads, spawned at startup. Clamped to at least 1.
    pub core_threads: usize,
    /// Hard ceiling on worker threads. The pool grows from `core_threads` up to
    /// this on demand — whenever a job is submitted with every worker busy and
    /// room under the cap — and **never shrinks**. Never-reaping is exactly what
    /// keeps the persistent free-threaded-CPython attach from leaking (the
    /// reason the pool stopped using tokio's elastic `spawn_blocking`), while
    /// growth-on-demand restores the headroom that blocking handlers (HTTP /
    /// Diameter auth, an `on_change` notify) need so a handful of concurrent
    /// blocking calls can't starve the engine. Clamped to at least `core_threads`.
    pub max_threads: usize,
    /// Maximum number of jobs that may queue before submission sheds (the queue
    /// is bounded, so an at-capacity pool can no longer grow it without limit).
    /// Clamped to at least 1.
    pub queue_capacity: usize,
    /// Abort the process when the pool shows *zero forward progress while at the
    /// thread cap* for at least this long, so a supervisor restarts it. `None`
    /// disables the liveness watchdog (the background thread still publishes
    /// queue-depth / in-flight metrics).
    pub stall_abort: Option<Duration>,
}

impl Default for ExecutorConfig {
    fn default() -> Self {
        Self {
            core_threads: 8,
            max_threads: 32,
            queue_capacity: 1024,
            stall_abort: Some(Duration::from_secs(30)),
        }
    }
}

// ---------------------------------------------------------------------------
// Memory-aware pool sizing
// ---------------------------------------------------------------------------

/// Persistent per-worker Python heap on free-threaded CPython 3.14t, in MB.
///
/// Each elastic worker holds a persistent `PyGILState_Ensure` attach for its
/// whole life (the never-reap design that fixes the mimalloc-heap leak), so it
/// carries its own free-threaded mimalloc heap that grows as the worker runs
/// handlers and then stays resident. Measured at **~8 MB** per warm worker on a
/// free-threaded 3.14t IMS deployment — `scscf` (32 workers) − `pcscf`
/// (8 workers) = 24 workers for +198 MB RSS ≈ 8.25 MB/worker. The original
/// "~2 MB" estimate predated free-threading and was ~4× low. Rounded up to 10
/// here so the derived budget is conservative (never under-counts the heap).
const PER_WORKER_HEAP_MB: u64 = 10;

/// Fraction of the container's memory limit the pool's *peak* heap
/// (`max_threads × PER_WORKER_HEAP_MB`) is allowed to occupy by default. Keeps
/// the pool from defaulting past ~30 % of the NF's RAM no matter how many CPUs
/// the host has — the per-worker heap budget, not the host core count, sets the
/// ceiling.
const POOL_BUDGET_FRACTION: f64 = 0.30;

/// Absolute floor for the CPU-derived thread ceiling (legacy default shape:
/// `max(MIN_MAX_THREADS, 4 × core)`), before the memory budget caps it down.
const MIN_MAX_THREADS: usize = 32;

/// Always-on core-worker floor. A small container (`cpus: 0.5`) reports
/// `available_parallelism() == 1`, which `2×` alone would make a 2-thread
/// baseline — too small for the hot inbound path.
const MIN_CORE_THREADS: usize = 8;

/// cgroup v1 reports "no limit" as a page-aligned value near `i64::MAX`
/// (`PAGE_COUNTER_MAX × PAGE_SIZE`, ≈ 9.22e18). A real memory limit — even a
/// multi-terabyte one — is many orders of magnitude smaller, so treat anything
/// at or above this threshold as unlimited.
const CGROUP_V1_UNLIMITED: u64 = 0x7000_0000_0000_0000;

/// Which budget determined the resolved `max_threads`, surfaced in the startup
/// log so an operator can see why the ceiling landed where it did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SizingBound {
    /// The CPU-derived ceiling (`max(MIN_MAX_THREADS, 4 × core)`) was binding.
    Cpu,
    /// The container memory budget (`POOL_BUDGET_FRACTION` of the limit) was binding.
    Memory,
    /// An explicit `script.sync_pool_max` override was set.
    Override,
}

impl SizingBound {
    /// Lower-case label for structured logs.
    pub fn as_str(self) -> &'static str {
        match self {
            SizingBound::Cpu => "cpu",
            SizingBound::Memory => "memory",
            SizingBound::Override => "override",
        }
    }
}

/// Resolved `core` / `max` worker counts plus the bound that set the ceiling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoolSizing {
    pub core_threads: usize,
    pub max_threads: usize,
    pub bound: SizingBound,
}

/// Resolve the elastic pool's `core` / `max` worker counts from the CPU count
/// and the container memory limit, honouring explicit overrides.
///
/// The ceiling is the **minimum** of a CPU-derived cap (`max(32, 4 × core)`)
/// and a memory budget (`POOL_BUDGET_FRACTION` of the limit ÷ per-worker heap),
/// so the pool can't default past ~30 % of the NF's RAM however many CPUs the
/// host happens to have. `core` is likewise capped by the memory budget so an
/// un-cpu-limited NF on a many-core box doesn't *start* at 32 always-on workers.
/// Explicit `sync_pool_size` / `sync_pool_max` always win. `mem_limit_bytes` is
/// `None` when no limit is readable (non-Linux / no `/proc`), in which case the
/// CPU-derived ceiling stands unchanged (prior behaviour).
pub fn resolve_sizing(
    cpus: usize,
    mem_limit_bytes: Option<u64>,
    sync_pool_size: Option<usize>,
    sync_pool_max: Option<usize>,
) -> PoolSizing {
    // How many per-worker heaps fit in the pool's memory budget. `None` keeps
    // the CPU-derived shape (no limit known).
    let per_worker_bytes = PER_WORKER_HEAP_MB * 1024 * 1024;
    let mem_cap = mem_limit_bytes.map(|limit| {
        let budget = (limit as f64) * POOL_BUDGET_FRACTION;
        ((budget / per_worker_bytes as f64) as usize).max(1)
    });

    // Core: 2× CPUs floored at 8, but never above what the memory budget affords.
    let cpu_core = cpus.saturating_mul(2).max(MIN_CORE_THREADS);
    let core_threads = sync_pool_size
        .unwrap_or(match mem_cap {
            Some(cap) => cpu_core.min(cap),
            None => cpu_core,
        })
        .max(1);

    // Max: CPU-derived ceiling capped by the memory budget; an explicit
    // override wins, clamped to at least `core` (existing contract).
    let cpu_cap = core_threads.saturating_mul(4).max(MIN_MAX_THREADS);
    let (max_threads, bound) = match sync_pool_max {
        Some(explicit) => (explicit.max(core_threads), SizingBound::Override),
        None => match mem_cap {
            Some(cap) => {
                let mem_max = cap.max(core_threads);
                if mem_max < cpu_cap {
                    (mem_max, SizingBound::Memory)
                } else {
                    (cpu_cap, SizingBound::Cpu)
                }
            }
            None => (cpu_cap, SizingBound::Cpu),
        },
    };

    PoolSizing {
        core_threads,
        max_threads,
        bound,
    }
}

/// Resolve the effective memory limit (bytes) for pool budgeting: the
/// container's cgroup limit when one is set (cgroup v2 `memory.max`, then v1
/// `memory.limit_in_bytes`), else host RAM (`/proc/meminfo` `MemTotal`). The
/// cgroup limit is clamped to host RAM — a limit above physical RAM isn't a
/// real budget. Returns `None` only when nothing is readable (non-Linux /
/// no `/proc`), so callers fall back to the CPU-derived ceiling.
pub fn read_memory_limit_bytes() -> Option<u64> {
    let host_ram = read_host_ram_bytes();
    let cgroup = read_cgroup_mem_limit();
    match (cgroup, host_ram) {
        (Some(cgroup_limit), Some(ram)) => Some(cgroup_limit.min(ram)),
        (Some(cgroup_limit), None) => Some(cgroup_limit),
        (None, Some(ram)) => Some(ram),
        (None, None) => None,
    }
}

/// Read the cgroup memory limit (v2 first, then v1). `None` when no limit is set
/// (the `max` / unlimited sentinels) or the files are absent.
fn read_cgroup_mem_limit() -> Option<u64> {
    if let Some(limit) = std::fs::read_to_string("/sys/fs/cgroup/memory.max")
        .ok()
        .and_then(|content| parse_cgroup_v2_max(&content))
    {
        return Some(limit);
    }
    std::fs::read_to_string("/sys/fs/cgroup/memory/memory.limit_in_bytes")
        .ok()
        .and_then(|content| parse_cgroup_v1_limit(&content))
}

/// Read host physical RAM from `/proc/meminfo` (`MemTotal`, reported in kB).
fn read_host_ram_bytes() -> Option<u64> {
    std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|content| parse_meminfo_total(&content))
}

/// Parse cgroup v2 `memory.max`: a decimal byte count, or `max` (no limit).
fn parse_cgroup_v2_max(content: &str) -> Option<u64> {
    let trimmed = content.trim();
    if trimmed == "max" {
        return None;
    }
    trimmed.parse::<u64>().ok().filter(|&value| value > 0)
}

/// Parse cgroup v1 `memory.limit_in_bytes`: a decimal byte count. Treat the
/// near-`i64::MAX` "unlimited" sentinel (see [`CGROUP_V1_UNLIMITED`]) as no limit.
fn parse_cgroup_v1_limit(content: &str) -> Option<u64> {
    content
        .trim()
        .parse::<u64>()
        .ok()
        .filter(|&value| value > 0 && value < CGROUP_V1_UNLIMITED)
}

/// Parse `MemTotal:  N kB` from `/proc/meminfo`, returning bytes.
fn parse_meminfo_total(content: &str) -> Option<u64> {
    content
        .lines()
        .find_map(|line| line.strip_prefix("MemTotal:"))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|kb| kb.parse::<u64>().ok())
        .map(|kb| kb.saturating_mul(1024))
}

/// Live, lock-free counters shared between the worker threads (which mutate
/// them), `submit` (which reads `idle`/`total` to decide whether to grow), and
/// the watchdog thread. `inflight`/`completed` are the watchdog's forward-progress
/// signal; all are published to Prometheus by the watchdog off the hot path.
#[derive(Default)]
struct PoolMetrics {
    /// Jobs currently executing on a worker thread.
    inflight: AtomicUsize,
    /// Total jobs completed (monotonic). A flat value while the pool is at its
    /// thread cap with every worker busy is the precise "pool wedged" signal.
    completed: AtomicU64,
    /// Workers currently parked in `recv()` waiting for a job. `0` means every
    /// worker is busy, so a new submission should grow the pool (up to the cap).
    idle: AtomicUsize,
    /// Live worker threads. Grows from `core_threads` to `max_threads` on
    /// demand; never shrinks (never-reaped, so no heap leak).
    total: AtomicUsize,
}

/// Outcome of submitting a job to the bounded queue.
enum SubmitResult {
    /// Job was enqueued.
    Submitted,
    /// Queue was full — job dropped (load-shed under overload).
    Full,
    /// Channel closed (pool shutting down) — job dropped.
    Closed,
}

/// Process-wide pool, installed once at server startup. Submission helpers
/// fall back to `tokio::task::spawn_blocking` when no pool is installed (tests
/// / CLI helpers), so behaviour is unchanged off the server path.
static GLOBAL: OnceLock<Arc<PyExecutor>> = OnceLock::new();

/// Interval at which the background grower checks for a backlog to absorb. The
/// growth latency under a sudden blocking burst is at most this; fast handlers
/// keep the queue empty so the pool never grows and this is pure overhead-free
/// idle sleeping.
const GROWER_INTERVAL: Duration = Duration::from_millis(50);

/// Elastic, capped, never-reaped pool of persistently-attached Python worker
/// threads. Grows from `core_threads` to `max_threads` under load.
pub struct PyExecutor {
    /// Bounded job queue. `Option` so [`Drop`] can close the channel (drop the
    /// only sender) before joining the worker threads.
    sender: StdMutex<Option<flume::Sender<Job>>>,
    /// Worker thread handles (core + grown), joined on drop. Shared with the
    /// grower thread, which appends a handle each time it adds a worker.
    threads: Arc<StdMutex<Vec<JoinHandle<()>>>>,
    /// Background grower thread handle, joined on drop. `None` for a non-elastic
    /// pool (`core == max`), which needs no grower.
    grower: StdMutex<Option<JoinHandle<()>>>,
    /// Liveness watchdog / metrics-sampler thread handle, joined on drop.
    watchdog: StdMutex<Option<JoinHandle<()>>>,
    /// Set on drop so the background threads exit their sleep loops.
    shutdown: Arc<AtomicBool>,
    /// In-flight / completed / idle / total counters (shared with workers,
    /// grower, and watchdog).
    metrics: Arc<PoolMetrics>,
    /// Hard ceiling on worker threads.
    max_threads: usize,
}

impl PyExecutor {
    /// Install the global pool, each worker entering `tokio_handle` for its
    /// lifetime. Idempotent — subsequent calls return the already-installed pool
    /// (the loser of an install race tears its own threads down).
    ///
    /// `tokio_handle` **must outlive the process / test binary** — every worker
    /// holds an `EnterGuard` for it for its whole life (same requirement as
    /// [`crate::script::async_pool::AsyncPool::install`]). In production pass
    /// the bootstrap runtime's `Handle::current()`.
    pub fn install(tokio_handle: TokioHandle, config: ExecutorConfig) -> Arc<PyExecutor> {
        if let Some(existing) = GLOBAL.get() {
            return Arc::clone(existing);
        }
        let pool = Arc::new(PyExecutor::spawn(tokio_handle, config));
        match GLOBAL.set(Arc::clone(&pool)) {
            Ok(()) => {
                info!(
                    core_threads = config.core_threads.max(1),
                    max_threads = config.max_threads.max(config.core_threads.max(1)),
                    queue_capacity = config.queue_capacity.max(1),
                    stall_abort_secs = config.stall_abort.map(|d| d.as_secs()),
                    "synchronous Python executor pool initialised (elastic)"
                );
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

    /// Current live worker-thread count (grows from core toward max under load).
    pub fn size(&self) -> usize {
        self.metrics.total.load(Ordering::Relaxed)
    }

    /// Hard ceiling on worker threads.
    pub fn max_size(&self) -> usize {
        self.max_threads
    }

    fn spawn(tokio_handle: TokioHandle, config: ExecutorConfig) -> Self {
        let core_threads = config.core_threads.max(1);
        let max_threads = config.max_threads.max(core_threads);
        let capacity = config.queue_capacity.max(1);
        let (sender, receiver) = flume::bounded::<Job>(capacity);
        let metrics = Arc::new(PoolMetrics::default());

        let threads: Arc<StdMutex<Vec<JoinHandle<()>>>> =
            Arc::new(StdMutex::new(Vec::with_capacity(core_threads)));
        for index in 0..core_threads {
            let handle = spawn_worker(
                index,
                receiver.clone(),
                tokio_handle.clone(),
                Arc::clone(&metrics),
            );
            if let Ok(mut guard) = threads.lock() {
                guard.push(handle);
            }
        }

        // Publish the static ceiling + initial live count so dashboards can
        // compute saturation (`pyexec_inflight / pyexec_pool_size`) immediately.
        if let Some(registry) = crate::metrics::try_metrics() {
            registry.pyexec_pool_max.set(max_threads as i64);
            registry.pyexec_pool_size.set(core_threads as i64);
        }

        let shutdown = Arc::new(AtomicBool::new(false));

        // Background grower: the elasticity that the fixed pool removed. On a
        // short interval it adds workers (up to the cap, never reaped) to cover
        // any queue backlog the current workers can't absorb — so a burst of
        // *blocking* handlers grows the pool instead of starving the engine.
        // Driven off a dedicated thread, not at submit time, so growth never
        // depends on submission timing or CPU scheduling of the hot path.
        // Skipped entirely for a non-elastic pool (`core == max`).
        let grower = if max_threads > core_threads {
            let receiver = receiver.clone();
            let tokio_handle = tokio_handle.clone();
            let threads = Arc::clone(&threads);
            let metrics = Arc::clone(&metrics);
            let shutdown = Arc::clone(&shutdown);
            Some(
                std::thread::Builder::new()
                    .name("siphon-pyexec-grower".to_string())
                    .spawn(move || {
                        run_grower(
                            receiver,
                            tokio_handle,
                            threads,
                            metrics,
                            max_threads,
                            GROWER_INTERVAL,
                            shutdown,
                        )
                    })
                    .expect("failed to spawn Python executor grower thread"),
            )
        } else {
            None
        };

        // Liveness watchdog + metrics sampler on a dedicated OS thread. It only
        // sleeps and reads atomics / the queue length, so it can never be
        // blocked by a lock a wedged handler holds — that is the whole point:
        // it stays alive to fail the process fast when every worker is stuck.
        let watchdog = {
            let metrics = Arc::clone(&metrics);
            let receiver = receiver.clone();
            let shutdown = Arc::clone(&shutdown);
            let params = WatchdogParams {
                max_threads,
                stall_abort: config.stall_abort,
                check_interval: Duration::from_secs(1),
            };
            let on_stall: Arc<dyn Fn() + Send + Sync> = Arc::new(|| {
                // SIGABRT, not exit(): never run destructors here — they could
                // deadlock on the very lock a wedged handler is holding. abort()
                // also leaves a core for post-mortem and gives a non-zero exit
                // so `restart: always` / systemd restart the process.
                std::process::abort();
            });
            std::thread::Builder::new()
                .name("siphon-pyexec-watchdog".to_string())
                .spawn(move || run_watchdog(metrics, receiver, params, shutdown, on_stall))
                .expect("failed to spawn Python executor watchdog thread")
        };

        Self {
            sender: StdMutex::new(Some(sender)),
            threads,
            grower: StdMutex::new(grower),
            watchdog: StdMutex::new(Some(watchdog)),
            shutdown,
            metrics,
            max_threads,
        }
    }

    /// Submit a job to the bounded queue without blocking the caller. Elastic
    /// growth is handled off-thread by the grower, so `submit` is just a
    /// non-blocking enqueue.
    fn submit(&self, job: Job) -> SubmitResult {
        match self.sender.lock() {
            Ok(guard) => match guard.as_ref() {
                Some(sender) => match sender.try_send(job) {
                    Ok(()) => SubmitResult::Submitted,
                    Err(flume::TrySendError::Full(_)) => SubmitResult::Full,
                    Err(flume::TrySendError::Disconnected(_)) => SubmitResult::Closed,
                },
                None => SubmitResult::Closed,
            },
            Err(_) => SubmitResult::Closed,
        }
    }
}

/// Spawn a core worker at startup, reserving its `total` slot. Panics on spawn
/// failure (a startup failure is fatal). On-demand growth uses [`run_grower`].
fn spawn_worker(
    index: usize,
    receiver: flume::Receiver<Job>,
    tokio_handle: TokioHandle,
    metrics: Arc<PoolMetrics>,
) -> JoinHandle<()> {
    metrics.total.fetch_add(1, Ordering::Relaxed);
    std::thread::Builder::new()
        .name(format!("siphon-pyexec-{index}"))
        .spawn(move || worker_loop(index, receiver, tokio_handle, metrics))
        .expect("failed to spawn Python executor thread")
}

/// Workers to add to cover the current backlog: the queued jobs the idle
/// workers can't immediately take, capped by the room under `max_threads`.
/// Pure so the policy is unit-testable without threads or a clock.
fn grow_deficit(queue_len: usize, idle: usize, total: usize, max_threads: usize) -> usize {
    if total >= max_threads {
        return 0;
    }
    queue_len.saturating_sub(idle).min(max_threads - total)
}

/// Background grower: on every `check_interval`, add enough never-reaped workers
/// to absorb the queue backlog, up to `max_threads`. Decoupling growth from the
/// submit path makes it robust to submission timing and CPU scheduling — a
/// stranded backlog is always picked up within one interval. Runs until
/// `shutdown` is set (on pool drop).
fn run_grower(
    receiver: flume::Receiver<Job>,
    tokio_handle: TokioHandle,
    threads: Arc<StdMutex<Vec<JoinHandle<()>>>>,
    metrics: Arc<PoolMetrics>,
    max_threads: usize,
    check_interval: Duration,
    shutdown: Arc<AtomicBool>,
) {
    loop {
        std::thread::sleep(check_interval);
        if shutdown.load(Ordering::Relaxed) {
            return;
        }

        let queue_len = receiver.len();
        let idle = metrics.idle.load(Ordering::Relaxed);
        let total = metrics.total.load(Ordering::Relaxed);
        let grow_n = grow_deficit(queue_len, idle, total, max_threads);

        for _ in 0..grow_n {
            // Reserve a slot atomically; never overshoot the cap even if another
            // path raced us (defensive — `grow_deficit` already bounds it).
            let reserved = metrics.total.fetch_add(1, Ordering::Relaxed);
            if reserved >= max_threads {
                metrics.total.fetch_sub(1, Ordering::Relaxed);
                break;
            }
            let receiver = receiver.clone();
            let tokio_handle = tokio_handle.clone();
            let worker_metrics = Arc::clone(&metrics);
            match std::thread::Builder::new()
                .name(format!("siphon-pyexec-{reserved}"))
                .spawn(move || worker_loop(reserved, receiver, tokio_handle, worker_metrics))
            {
                Ok(thread) => {
                    if let Ok(mut guard) = threads.lock() {
                        guard.push(thread);
                    }
                    debug!(
                        index = reserved,
                        total = metrics.total.load(Ordering::Relaxed),
                        "grew Python executor pool under load"
                    );
                }
                Err(error) => {
                    metrics.total.fetch_sub(1, Ordering::Relaxed);
                    error!(%error, "failed to grow Python executor pool");
                    break;
                }
            }
        }
    }
}

impl Drop for PyExecutor {
    fn drop(&mut self) {
        // Stop the watchdog's sleep loop and close the channel so workers'
        // `recv()` returns `Err` and they exit. Normally never runs in
        // production (the pool lives in `OnceLock`); it only matters for the
        // transient `Arc` an install-race loser holds.
        self.shutdown.store(true, Ordering::Relaxed);
        if let Ok(mut guard) = self.sender.lock() {
            guard.take();
        }
        // Join the grower first so it can't spawn a new worker after we've taken
        // the worker-handle vector.
        let grower = self.grower.lock().ok().and_then(|mut t| t.take());
        if let Some(grower) = grower {
            if grower.join().is_err() {
                error!("Python executor grower thread panicked during shutdown");
            }
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
        let watchdog = self.watchdog.lock().ok().and_then(|mut t| t.take());
        if let Some(watchdog) = watchdog {
            if watchdog.join().is_err() {
                error!("Python executor watchdog thread panicked during shutdown");
            }
        }
    }
}

/// Tuning for [`run_watchdog`].
struct WatchdogParams {
    /// Configured thread ceiling — used only for the diagnostic abort log, not
    /// for the trigger condition.
    max_threads: usize,
    /// Stall threshold; `None` = sample metrics only, never abort.
    stall_abort: Option<Duration>,
    /// Sleep between samples.
    check_interval: Duration,
}

/// Sample the pool every `check_interval`: publish live thread count / queue-depth
/// / in-flight / completed to Prometheus, and — when `stall_abort` is set — fire
/// `on_stall` (in production: abort the process) once the pool has shown **zero
/// forward progress while any work is pending** for `stall_abort`.
///
/// The trigger is intentionally **independent of pool fill**: it fires whenever
/// there is work to do (a handler in-flight *or* jobs queued) and not one job
/// has completed for the whole window. This catches a **low-concurrency
/// deadlock** — a few workers stuck on a lock/await that never returns while the
/// pool sits far below its cap — which an earlier "at the thread cap + fully
/// busy" condition could never detect (the pool never grows to the cap, so the
/// precondition was unreachable, and the engine wedged silently). A healthy pool
/// advances `completed` every tick so it never accumulates; a genuinely idle
/// pool has no in-flight/queued work so it never trips. The only false positive
/// is a *single* handler that legitimately runs longer than the window —
/// pathological for a SIP handler, and the default 30 s (6× the 5 s HTTP-auth
/// timeout) is sized so transient blocking never reaches it.
///
/// Runs on a dedicated OS thread that never takes a lock or touches Python, so
/// a handler that wedges every worker (or holds a lock forever) cannot stall
/// the watchdog itself.
fn run_watchdog(
    metrics: Arc<PoolMetrics>,
    receiver: flume::Receiver<Job>,
    params: WatchdogParams,
    shutdown: Arc<AtomicBool>,
    on_stall: Arc<dyn Fn() + Send + Sync>,
) {
    let mut stalled_for = Duration::ZERO;
    let mut last_completed = metrics.completed.load(Ordering::Relaxed);
    let mut last_published = last_completed;

    loop {
        std::thread::sleep(params.check_interval);
        if shutdown.load(Ordering::Relaxed) {
            return;
        }

        let inflight = metrics.inflight.load(Ordering::Relaxed);
        let total = metrics.total.load(Ordering::Relaxed);
        let queue_depth = receiver.len();
        let completed = metrics.completed.load(Ordering::Relaxed);

        // Publish snapshots off the hot path.
        if let Some(registry) = crate::metrics::try_metrics() {
            registry.pyexec_inflight.set(inflight as i64);
            registry.pyexec_pool_size.set(total as i64);
            registry.pyexec_queue_depth.set(queue_depth as i64);
            let delta = completed.saturating_sub(last_published);
            if delta > 0 {
                registry.pyexec_jobs_completed_total.inc_by(delta);
                last_published = completed;
            }
        }

        let Some(threshold) = params.stall_abort else {
            last_completed = completed;
            continue;
        };

        // Wedged ⟺ there is work to do (a handler in-flight OR jobs queued) yet
        // not one has completed since the last sample. Independent of pool fill,
        // so it catches a low-concurrency deadlock (workers stuck on a
        // lock/await that never returns) as well as full saturation. A healthy
        // pool advances `completed` every tick; an idle pool has no pending work
        // — neither trips.
        let has_work = inflight > 0 || queue_depth > 0;
        if has_work && completed == last_completed {
            stalled_for += params.check_interval;
            if stalled_for >= threshold {
                error!(
                    inflight,
                    total,
                    queue_depth,
                    max_threads = params.max_threads,
                    stalled_secs = stalled_for.as_secs(),
                    "Python executor pool wedged: work pending (in-flight/queued) \
                     with zero completions for the stall window — aborting so a \
                     supervisor restarts the process (a hung-but-alive SIP engine \
                     never recovers on its own). Fires regardless of pool fill, so \
                     it catches a low-concurrency deadlock, not just saturation."
                );
                on_stall();
                // Reach here only in tests (production aborted above). Reset so
                // the injected action fires at most once per stall episode.
                stalled_for = Duration::ZERO;
            }
        } else {
            stalled_for = Duration::ZERO;
        }
        last_completed = completed;
    }
}

/// Record a shed (queue-full) event: bump the Prometheus counter and emit a
/// rate-limited warning (the metric carries the precise count; the log is a
/// breadcrumb that avoids flooding under sustained overload).
fn record_shed() {
    if let Some(registry) = crate::metrics::try_metrics() {
        registry.pyexec_jobs_shed_total.inc();
    }
    static SHED_WARN_COUNT: AtomicU64 = AtomicU64::new(0);
    let n = SHED_WARN_COUNT.fetch_add(1, Ordering::Relaxed);
    if n == 0 || n % 5000 == 0 {
        warn!(
            shed_total_since_start = n + 1,
            "Python executor queue full — shedding handler job (pool saturated; \
             SIP client will retransmit)"
        );
    }
}

fn worker_loop(
    index: usize,
    receiver: flume::Receiver<Job>,
    tokio_handle: TokioHandle,
    metrics: Arc<PoolMetrics>,
) {
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

    loop {
        // Mark this worker idle while it waits for a job, so `submit` can tell
        // when every worker is busy and the pool should grow.
        metrics.idle.fetch_add(1, Ordering::Relaxed);
        let job = receiver.recv();
        metrics.idle.fetch_sub(1, Ordering::Relaxed);
        let Ok(job) = job else {
            break; // channel closed → pool shutting down
        };

        // `inflight`/`completed` bracket the job so the watchdog can tell a
        // saturated-but-progressing pool from a wedged one. A few relaxed atomics
        // per job — negligible on the hot path; the Prometheus counters are
        // updated off-thread by the watchdog from these.
        metrics.inflight.fetch_add(1, Ordering::Relaxed);
        // Backstop: a panicking job must never take down the worker thread (the
        // submission wrappers already isolate panics, but defend in depth so a
        // raw job can't shrink the pool).
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(job));
        metrics.inflight.fetch_sub(1, Ordering::Relaxed);
        metrics.completed.fetch_add(1, Ordering::Relaxed);
        if outcome.is_err() {
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
            match pool.submit(job) {
                SubmitResult::Submitted => receiver
                    .await
                    .unwrap_or_else(|_| Err(boxed_message("Python executor worker dropped"))),
                SubmitResult::Full => {
                    record_shed();
                    Err(boxed_message("Python executor queue full — load shed"))
                }
                SubmitResult::Closed => Err(boxed_message("Python executor channel closed")),
            }
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
            match pool.submit(job) {
                SubmitResult::Submitted => {}
                SubmitResult::Full => record_shed(),
                SubmitResult::Closed => {
                    error!("Python executor channel closed — dropping fire-and-forget job");
                }
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
        // Disable the abort-watchdog on the *shared global* pool — a false
        // positive would kill the whole test binary. The watchdog logic is
        // covered in isolation by `watchdog_*` below.
        PyExecutor::install(
            test_runtime().handle().clone(),
            ExecutorConfig {
                core_threads: 3,
                max_threads: 3,
                queue_capacity: 1024,
                stall_abort: None,
            },
        )
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

    fn noop_job() -> Job {
        Box::new(|| {})
    }

    #[test]
    fn grow_deficit_policy() {
        // No backlog beyond idle capacity → no growth.
        assert_eq!(grow_deficit(0, 0, 2, 8), 0);
        assert_eq!(grow_deficit(2, 2, 2, 8), 0);
        assert_eq!(grow_deficit(1, 4, 2, 8), 0);
        // Backlog the idle workers can't take → grow to cover it.
        assert_eq!(grow_deficit(3, 0, 2, 8), 3);
        assert_eq!(grow_deficit(5, 1, 2, 8), 4);
        // Growth is capped by the room under max_threads.
        assert_eq!(grow_deficit(100, 0, 6, 8), 2);
        assert_eq!(grow_deficit(100, 0, 8, 8), 0);
        assert_eq!(grow_deficit(100, 0, 9, 8), 0);
    }

    const MB: u64 = 1024 * 1024;

    /// With no readable memory limit (`None`), the ceiling is the legacy
    /// CPU-derived shape — unchanged behaviour on non-Linux / no-`/proc` hosts.
    #[test]
    fn resolve_sizing_without_mem_limit_uses_cpu_ceiling() {
        let sizing = resolve_sizing(8, None, None, None);
        // core = max(8, 2×8) = 16; max = max(32, 4×16) = 64.
        assert_eq!(sizing.core_threads, 16);
        assert_eq!(sizing.max_threads, 64);
        assert_eq!(sizing.bound, SizingBound::Cpu);
    }

    /// Acceptance §4.1 — a 512 MB-cgroup NF resolves `max` to ~12–16 (not 32),
    /// and the memory budget is the binding bound.
    #[test]
    fn resolve_sizing_512mb_caps_max_to_memory_budget() {
        let sizing = resolve_sizing(2, Some(512 * MB), None, None);
        // mem budget = 512×0.30 / 10 MB ≈ 15.
        assert_eq!(sizing.core_threads, 8); // min(max(8, 2×2)=8, 15)
        assert_eq!(sizing.max_threads, 15);
        assert_eq!(sizing.bound, SizingBound::Memory);
        assert!((12..=16).contains(&sizing.max_threads));
    }

    /// A 256 MB NF budgets even fewer workers (~7).
    #[test]
    fn resolve_sizing_256mb_caps_lower() {
        let sizing = resolve_sizing(2, Some(256 * MB), None, None);
        // mem budget = 256×0.30 / 10 MB ≈ 7.
        assert_eq!(sizing.max_threads, 7);
        assert_eq!(sizing.bound, SizingBound::Memory);
    }

    /// Acceptance §4.2 — an un-cpu-limited NF on a 16-core box no longer defaults
    /// to core=32/max=128; both are bounded by the memory budget. `core` is
    /// capped too, so the pool doesn't *start* at 32 always-on workers.
    #[test]
    fn resolve_sizing_big_cpu_box_bounded_by_memory() {
        let sizing = resolve_sizing(16, Some(512 * MB), None, None);
        assert_eq!(sizing.core_threads, 15); // min(max(8, 2×16)=32, 15)
        assert_eq!(sizing.max_threads, 15);
        assert_eq!(sizing.bound, SizingBound::Memory);
    }

    /// A generous memory budget leaves the CPU-derived ceiling in charge.
    #[test]
    fn resolve_sizing_high_mem_leaves_cpu_bound() {
        // 8 CPUs, 8 GB: mem budget = 8192×0.30 / 10 ≈ 245 ≫ cpu cap (64).
        let sizing = resolve_sizing(8, Some(8192 * MB), None, None);
        assert_eq!(sizing.core_threads, 16);
        assert_eq!(sizing.max_threads, 64);
        assert_eq!(sizing.bound, SizingBound::Cpu);
    }

    /// Acceptance §4.5 — explicit overrides win over the memory budget.
    #[test]
    fn resolve_sizing_explicit_overrides_win() {
        let sizing = resolve_sizing(2, Some(256 * MB), Some(20), Some(40));
        assert_eq!(sizing.core_threads, 20);
        assert_eq!(sizing.max_threads, 40);
        assert_eq!(sizing.bound, SizingBound::Override);
    }

    /// `max` is always clamped to at least `core` (existing contract), even when
    /// an override would set it lower.
    #[test]
    fn resolve_sizing_max_clamped_to_core() {
        let sizing = resolve_sizing(2, None, Some(12), Some(4));
        assert_eq!(sizing.core_threads, 12);
        assert_eq!(sizing.max_threads, 12);
        assert_eq!(sizing.bound, SizingBound::Override);
    }

    /// A pathologically tiny budget still yields a usable (≥1) pool.
    #[test]
    fn resolve_sizing_tiny_budget_floors_at_one() {
        let sizing = resolve_sizing(1, Some(8 * MB), None, None);
        assert!(sizing.core_threads >= 1);
        assert!(sizing.max_threads >= sizing.core_threads);
    }

    #[test]
    fn parse_cgroup_v2_max_handles_max_and_number() {
        assert_eq!(parse_cgroup_v2_max("max\n"), None);
        assert_eq!(parse_cgroup_v2_max("536870912\n"), Some(536_870_912));
        assert_eq!(parse_cgroup_v2_max("0\n"), None);
        assert_eq!(parse_cgroup_v2_max("garbage"), None);
    }

    #[test]
    fn parse_cgroup_v1_limit_handles_sentinel() {
        // The kernel "unlimited" sentinel (near i64::MAX) is not a real limit.
        assert_eq!(parse_cgroup_v1_limit("9223372036854771712\n"), None);
        assert_eq!(parse_cgroup_v1_limit("268435456"), Some(268_435_456));
        assert_eq!(parse_cgroup_v1_limit("0"), None);
    }

    #[test]
    fn parse_meminfo_total_parses_kb_to_bytes() {
        let meminfo = "MemTotal:       16384000 kB\nMemFree:         8000000 kB\n";
        assert_eq!(parse_meminfo_total(meminfo), Some(16_384_000 * 1024));
        assert_eq!(parse_meminfo_total("MemFree: 100 kB\n"), None);
    }

    /// The bounded queue sheds once full instead of growing without bound: with
    /// a non-elastic pool (core == max == 1) whose single worker is pinned on a
    /// blocking job, the next `queue_capacity` jobs queue and everything beyond
    /// is reported `Full` (load-shed).
    #[test]
    fn bounded_queue_sheds_when_full() {
        pyo3::Python::initialize();
        let pool = PyExecutor::spawn(
            test_runtime().handle().clone(),
            ExecutorConfig {
                core_threads: 1,
                max_threads: 1,
                queue_capacity: 2,
                stall_abort: None,
            },
        );

        // Job A pins the only worker until we unblock it.
        let (unblock_tx, unblock_rx) = std::sync::mpsc::channel::<()>();
        let blocker: Job = Box::new(move || {
            let _ = unblock_rx.recv();
        });
        assert!(matches!(pool.submit(blocker), SubmitResult::Submitted));

        // Wait until the worker has actually picked A up (inflight == 1), so the
        // queue is empty and the capacity accounting below is deterministic.
        let mut picked = false;
        for _ in 0..200 {
            if pool.metrics.inflight.load(Ordering::Relaxed) == 1 {
                picked = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(picked, "worker never picked up the blocking job");

        // Queue capacity is 2: the next two fit, the rest shed.
        let r_b = pool.submit(noop_job());
        let r_c = pool.submit(noop_job());
        let r_d = pool.submit(noop_job());
        let r_e = pool.submit(noop_job());

        // Unblock before asserting so a failed assert can't hang Drop's join.
        let _ = unblock_tx.send(());

        assert!(matches!(r_b, SubmitResult::Submitted), "B should enqueue");
        assert!(matches!(r_c, SubmitResult::Submitted), "C should enqueue");
        assert!(matches!(r_d, SubmitResult::Full), "D should shed (queue full)");
        assert!(matches!(r_e, SubmitResult::Full), "E should shed (queue full)");

        drop(pool);
    }

    /// `inflight` returns to 0 and `completed` counts every job — including one
    /// that panics (the worker catches it and still records completion).
    #[test]
    fn inflight_and_completed_track_jobs_including_panics() {
        pyo3::Python::initialize();
        let pool = PyExecutor::spawn(
            test_runtime().handle().clone(),
            ExecutorConfig {
                core_threads: 2,
                max_threads: 2,
                queue_capacity: 64,
                stall_abort: None,
            },
        );

        const JOBS: u64 = 32;
        for index in 0..JOBS {
            let job: Job = if index == 7 {
                Box::new(|| panic!("boom — must not break accounting"))
            } else {
                noop_job()
            };
            assert!(matches!(pool.submit(job), SubmitResult::Submitted));
        }

        let mut done = false;
        for _ in 0..400 {
            if pool.metrics.completed.load(Ordering::Relaxed) >= JOBS {
                done = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(done, "pool did not complete all jobs");
        assert_eq!(
            pool.metrics.inflight.load(Ordering::Relaxed),
            0,
            "every worker must be idle once the batch drains"
        );

        drop(pool);
    }

    /// Watchdog positive: a pool with an in-flight handler and zero completions
    /// for the stall window fires the abort action.
    #[test]
    fn watchdog_fires_when_pool_wedged() {
        let metrics = Arc::new(PoolMetrics::default());
        // One worker, busy, never completes.
        metrics.total.store(1, Ordering::Relaxed);
        metrics.inflight.store(1, Ordering::Relaxed);

        let (_keep_alive_sender, receiver) = flume::bounded::<Job>(8);
        let shutdown = Arc::new(AtomicBool::new(false));
        let fired = Arc::new(AtomicBool::new(false));
        let fired_for_action = Arc::clone(&fired);
        let on_stall: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
            fired_for_action.store(true, Ordering::Relaxed);
        });

        let params = WatchdogParams {
            max_threads: 1,
            stall_abort: Some(Duration::from_millis(150)),
            check_interval: Duration::from_millis(50),
        };

        let metrics_for_thread = Arc::clone(&metrics);
        let shutdown_for_thread = Arc::clone(&shutdown);
        let handle = std::thread::spawn(move || {
            run_watchdog(
                metrics_for_thread,
                receiver,
                params,
                shutdown_for_thread,
                on_stall,
            )
        });

        std::thread::sleep(Duration::from_millis(600));
        assert!(
            fired.load(Ordering::Relaxed),
            "watchdog must fire when every worker is busy with zero completions"
        );

        shutdown.store(true, Ordering::Relaxed);
        let _ = handle.join();
    }

    /// Watchdog negative: a pool that keeps completing jobs (even while fully
    /// busy) never trips, so transient backend slowness can't abort the process.
    #[test]
    fn watchdog_does_not_fire_while_progressing() {
        let metrics = Arc::new(PoolMetrics::default());
        metrics.total.store(1, Ordering::Relaxed);
        metrics.inflight.store(1, Ordering::Relaxed);

        let (_keep_alive_sender, receiver) = flume::bounded::<Job>(8);
        let shutdown = Arc::new(AtomicBool::new(false));
        let fired = Arc::new(AtomicBool::new(false));
        let fired_for_action = Arc::clone(&fired);
        let on_stall: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
            fired_for_action.store(true, Ordering::Relaxed);
        });

        // Bump `completed` faster than the watchdog samples, so no tick ever
        // sees zero forward progress.
        let metrics_for_progress = Arc::clone(&metrics);
        let shutdown_for_progress = Arc::clone(&shutdown);
        let progress = std::thread::spawn(move || {
            while !shutdown_for_progress.load(Ordering::Relaxed) {
                metrics_for_progress.completed.fetch_add(1, Ordering::Relaxed);
                std::thread::sleep(Duration::from_millis(20));
            }
        });

        let params = WatchdogParams {
            max_threads: 1,
            stall_abort: Some(Duration::from_millis(150)),
            check_interval: Duration::from_millis(50),
        };
        let metrics_for_thread = Arc::clone(&metrics);
        let shutdown_for_thread = Arc::clone(&shutdown);
        let handle = std::thread::spawn(move || {
            run_watchdog(
                metrics_for_thread,
                receiver,
                params,
                shutdown_for_thread,
                on_stall,
            )
        });

        std::thread::sleep(Duration::from_millis(600));
        assert!(
            !fired.load(Ordering::Relaxed),
            "watchdog must not fire while the pool keeps completing jobs"
        );

        shutdown.store(true, Ordering::Relaxed);
        let _ = handle.join();
        let _ = progress.join();
    }

    /// **Regression guard for the low-concurrency deadlock** — the watchdog must
    /// fire even when the pool is far below its thread cap. A handler stuck on a
    /// lock/await that never returns wedges the engine at low concurrency; the
    /// pool never grows to max, so an "at the cap" trigger could never catch it
    /// (the bug in the prior watchdog). Here one worker is busy with zero
    /// completions while max_threads=8 — it MUST still abort.
    #[test]
    fn watchdog_fires_below_cap_on_low_concurrency_deadlock() {
        let metrics = Arc::new(PoolMetrics::default());
        // One of a possible 8 workers is wedged; the pool is nowhere near cap.
        metrics.total.store(1, Ordering::Relaxed);
        metrics.inflight.store(1, Ordering::Relaxed);

        let (_keep_alive_sender, receiver) = flume::bounded::<Job>(8);
        let shutdown = Arc::new(AtomicBool::new(false));
        let fired = Arc::new(AtomicBool::new(false));
        let fired_for_action = Arc::clone(&fired);
        let on_stall: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
            fired_for_action.store(true, Ordering::Relaxed);
        });

        let params = WatchdogParams {
            max_threads: 8,
            stall_abort: Some(Duration::from_millis(150)),
            check_interval: Duration::from_millis(50),
        };
        let metrics_for_thread = Arc::clone(&metrics);
        let shutdown_for_thread = Arc::clone(&shutdown);
        let handle = std::thread::spawn(move || {
            run_watchdog(
                metrics_for_thread,
                receiver,
                params,
                shutdown_for_thread,
                on_stall,
            )
        });

        std::thread::sleep(Duration::from_millis(600));
        assert!(
            fired.load(Ordering::Relaxed),
            "watchdog must fire on an in-flight handler that never completes, \
             even far below the thread cap (low-concurrency deadlock)"
        );

        shutdown.store(true, Ordering::Relaxed);
        let _ = handle.join();
    }

    /// Watchdog must fire on a stranded *queued* job too (work pending with zero
    /// completions), not only on an in-flight one.
    #[test]
    fn watchdog_fires_on_stranded_queued_work() {
        let metrics = Arc::new(PoolMetrics::default());
        // No worker is running it, but a job sits in the queue unconsumed.
        metrics.total.store(2, Ordering::Relaxed);
        metrics.inflight.store(0, Ordering::Relaxed);

        let (keep_alive_sender, receiver) = flume::bounded::<Job>(8);
        keep_alive_sender
            .try_send(Box::new(|| {}) as Job)
            .expect("queue a job that is never consumed");

        let shutdown = Arc::new(AtomicBool::new(false));
        let fired = Arc::new(AtomicBool::new(false));
        let fired_for_action = Arc::clone(&fired);
        let on_stall: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
            fired_for_action.store(true, Ordering::Relaxed);
        });

        let params = WatchdogParams {
            max_threads: 4,
            stall_abort: Some(Duration::from_millis(150)),
            check_interval: Duration::from_millis(50),
        };
        let metrics_for_thread = Arc::clone(&metrics);
        let shutdown_for_thread = Arc::clone(&shutdown);
        let handle = std::thread::spawn(move || {
            run_watchdog(
                metrics_for_thread,
                receiver,
                params,
                shutdown_for_thread,
                on_stall,
            )
        });

        std::thread::sleep(Duration::from_millis(600));
        assert!(
            fired.load(Ordering::Relaxed),
            "watchdog must fire on a queued job that is never picked up"
        );

        shutdown.store(true, Ordering::Relaxed);
        let _ = handle.join();
        drop(keep_alive_sender);
    }

    /// Watchdog must NOT fire when the pool is genuinely idle (no in-flight and
    /// no queued work) — zero completions then is normal, not a deadlock.
    #[test]
    fn watchdog_does_not_fire_when_idle() {
        let metrics = Arc::new(PoolMetrics::default());
        metrics.total.store(8, Ordering::Relaxed); // workers exist...
        metrics.inflight.store(0, Ordering::Relaxed); // ...but none are busy

        let (_keep_alive_sender, receiver) = flume::bounded::<Job>(8); // empty queue
        let shutdown = Arc::new(AtomicBool::new(false));
        let fired = Arc::new(AtomicBool::new(false));
        let fired_for_action = Arc::clone(&fired);
        let on_stall: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
            fired_for_action.store(true, Ordering::Relaxed);
        });

        let params = WatchdogParams {
            max_threads: 8,
            stall_abort: Some(Duration::from_millis(150)),
            check_interval: Duration::from_millis(50),
        };
        let metrics_for_thread = Arc::clone(&metrics);
        let shutdown_for_thread = Arc::clone(&shutdown);
        let handle = std::thread::spawn(move || {
            run_watchdog(
                metrics_for_thread,
                receiver,
                params,
                shutdown_for_thread,
                on_stall,
            )
        });

        std::thread::sleep(Duration::from_millis(600));
        assert!(
            !fired.load(Ordering::Relaxed),
            "watchdog must not fire on an idle pool (no in-flight or queued work)"
        );

        shutdown.store(true, Ordering::Relaxed);
        let _ = handle.join();
    }

    /// **Regression guard for the free-threaded GC stop-the-world deadlock.**
    ///
    /// On free-threaded CPython (3.14t) the cyclic GC pauses every *attached*
    /// thread at a safe point. A handler that performs a blocking call (the HTTP
    /// auth fetch) WHILE attached can never reach that safe point, so a
    /// concurrent `gc.collect()` — triggered constantly by Python allocation —
    /// hangs, and every other thread blocks behind it: the engine-wide deadlock.
    /// The fix is to `py.detach()` around blocking calls. This test proves that
    /// a thread blocking *while detached* does NOT stall a concurrent
    /// `gc.collect()`. (With the buggy attached-blocking pattern this same test
    /// hangs until the blocker is released — verified during investigation.)
    #[test]
    fn detached_blocking_does_not_stall_gc() {
        pyo3::Python::initialize();
        let unblock = Arc::new(AtomicBool::new(false));
        let in_block = Arc::new(AtomicBool::new(false));

        // Thread A: a handler that blocks the way the fixed code does — DETACHED.
        let unblock_a = Arc::clone(&unblock);
        let in_block_a = Arc::clone(&in_block);
        let blocker = std::thread::spawn(move || {
            pyo3::Python::attach(|python| {
                python.detach(|| {
                    in_block_a.store(true, Ordering::Relaxed);
                    while !unblock_a.load(Ordering::Relaxed) {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                });
            });
        });
        while !in_block.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(1));
        }
        std::thread::sleep(Duration::from_millis(50));

        // Thread B: a stop-the-world gc.collect() must complete while A is still
        // parked in its blocking section.
        let gc_done = Arc::new(AtomicBool::new(false));
        let gc_done_b = Arc::clone(&gc_done);
        let collector = std::thread::spawn(move || {
            pyo3::Python::attach(|python| {
                // Allocate cyclic garbage so collect() actually does STW work.
                let _ = python.run(
                    std::ffi::CString::new(
                        "import gc\nfor _ in range(1000):\n    a=[]; a.append(a)\ngc.collect()",
                    )
                    .unwrap()
                    .as_c_str(),
                    None,
                    None,
                );
            });
            gc_done_b.store(true, Ordering::Relaxed);
        });

        let mut gc_completed = false;
        for _ in 0..200 {
            if gc_done.load(Ordering::Relaxed) {
                gc_completed = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }

        // Release the blocker regardless, so the test can never hang the suite.
        let still_blocking = in_block.load(Ordering::Relaxed) && !gc_done.load(Ordering::Relaxed);
        unblock.store(true, Ordering::Relaxed);
        let _ = blocker.join();
        let _ = collector.join();

        assert!(
            gc_completed,
            "gc.collect() did not complete while a handler was in its blocking \
             section — a detached blocking call must not stall the free-threaded \
             stop-the-world GC (engine-wide deadlock)"
        );
        // Sanity: GC finished before we released the blocker, proving it didn't
        // simply wait the blocker out.
        let _ = still_blocking;
    }

    /// **Regression guard for commit 1c541e3** — the fixed (non-elastic) pool
    /// let `core`-many concurrent *blocking* handlers starve every other
    /// handler, wedging the engine. The pool must GROW past its core size so a
    /// new handler still runs while more-than-core handlers block. This test
    /// fails on a non-elastic pool (the canary would queue forever) and passes
    /// on the elastic one.
    #[test]
    fn pool_grows_under_blocking_load() {
        pyo3::Python::initialize();
        let pool = PyExecutor::spawn(
            test_runtime().handle().clone(),
            ExecutorConfig {
                core_threads: 2,
                max_threads: 8,
                queue_capacity: 64,
                stall_abort: None,
            },
        );

        // Occupy more workers than the core size with handlers that block until
        // released (busy-park, minimal CPU).
        const BLOCKERS: usize = 4; // > core_threads (2)
        let release = Arc::new(AtomicBool::new(false));
        for _ in 0..BLOCKERS {
            let release = Arc::clone(&release);
            let blocker: Job = Box::new(move || {
                while !release.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(2));
                }
            });
            assert!(matches!(pool.submit(blocker), SubmitResult::Submitted));
        }

        // A canary handler must still run despite all BLOCKERS being stuck —
        // which is only possible if the pool grew past its core size.
        let canary_ran = Arc::new(AtomicBool::new(false));
        let canary_flag = Arc::clone(&canary_ran);
        let canary: Job = Box::new(move || {
            canary_flag.store(true, Ordering::Relaxed);
        });
        assert!(matches!(pool.submit(canary), SubmitResult::Submitted));

        let mut ran = false;
        for _ in 0..300 {
            if canary_ran.load(Ordering::Relaxed) {
                ran = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let grown_to = pool.size();

        // Release blockers before asserting so a failed assert can't hang Drop.
        release.store(true, Ordering::Relaxed);

        assert!(
            ran,
            "canary handler must run despite {BLOCKERS} blocking handlers — the \
             pool must grow past its core size (this is the 1c541e3 regression)"
        );
        assert!(
            grown_to > BLOCKERS,
            "pool must grow to absorb {BLOCKERS} blockers + the canary; grew to {grown_to}"
        );

        drop(pool);
    }

    /// The pool grows only up to `max_threads` and never shrinks afterwards
    /// (never-reaped → the persistent free-threaded-CPython attach can't leak).
    #[test]
    fn pool_caps_at_max_and_never_reaps() {
        pyo3::Python::initialize();
        let pool = PyExecutor::spawn(
            test_runtime().handle().clone(),
            ExecutorConfig {
                core_threads: 1,
                max_threads: 3,
                queue_capacity: 64,
                stall_abort: None,
            },
        );

        // Submit far more blockers than the cap to force growth to the ceiling.
        let release = Arc::new(AtomicBool::new(false));
        for _ in 0..10 {
            let release = Arc::clone(&release);
            let blocker: Job = Box::new(move || {
                while !release.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(2));
                }
            });
            let _ = pool.submit(blocker);
        }

        // Total must reach — and never exceed — max_threads.
        let mut capped = false;
        for _ in 0..300 {
            let total = pool.size();
            assert!(total <= 3, "pool must never exceed max_threads; saw {total}");
            if total == 3 {
                capped = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(capped, "pool should have grown to max_threads under heavy load");

        // Drain and confirm the pool does NOT shrink (no reaping → no leak).
        release.store(true, Ordering::Relaxed);
        std::thread::sleep(Duration::from_millis(150));
        assert_eq!(
            pool.size(),
            3,
            "pool must not shrink after load subsides (workers are never reaped)"
        );

        drop(pool);
    }
}
