//! `script:` engine configuration.

use serde::Deserialize;

// ---------------------------------------------------------------------------
// Script engine
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Clone)]
pub struct ScriptConfig {
    #[serde(default = "default_script_path")]
    pub path: String,
    #[serde(default = "default_reload")]
    pub reload: ReloadMode,
    /// Size of the asyncio loop driver pool used to run async script
    /// handlers.  Each driver is a dedicated OS thread running a Python
    /// event loop forever — see `script::async_pool` for why this is
    /// needed (orphaned `asyncio.create_task` survival).  Defaults to
    /// the number of available CPUs (clamped to at least 1).
    #[serde(default)]
    pub async_pool_size: Option<usize>,
    /// Size of the synchronous Python executor pool used to run *sync*
    /// script-handler invocations.  Each worker is a fixed, never-reaped
    /// OS thread with a persistent Python attach — see `script::py_executor`
    /// for why this is needed (the free-threaded-CPython mimalloc heap leak
    /// on the elastic `spawn_blocking` pool).  Defaults to 2× the number of
    /// available CPUs (floored at 8), but **capped by the container memory
    /// budget** so an un-cpu-limited NF on a many-core box doesn't *start* at 32
    /// always-on workers (each carries ~8 MB of persistent free-threaded-CPython
    /// heap).  The hot inbound path runs here, and 2× restores the burst headroom
    /// the elastic pool gave at the throughput ceiling.  Lower it on
    /// memory-constrained, low-traffic NFs.
    #[serde(default)]
    pub sync_pool_size: Option<usize>,
    /// Hard ceiling on synchronous Python executor worker threads. The pool is
    /// elastic — it starts at `sync_pool_size` (the always-on core) and grows
    /// on demand up to this when every worker is busy, then never shrinks. This
    /// restores the burst headroom blocking-I/O handlers need (a handful of
    /// concurrent blocking REGISTERs no longer wedge the engine) without the
    /// free-threaded-CPython heap leak that reaping caused. Each grown worker
    /// costs ~8 MB of persistent free-threaded-CPython heap (measured on 3.14t;
    /// the earlier ~2 MB estimate was ~4× low), so the pool's memory ceiling is
    /// roughly `sync_pool_max × 8 MB`. The default is **memory-aware**: the
    /// MINIMUM of the CPU-derived `max(32, 4 × sync_pool_size)` and a memory
    /// budget (~30 % of the container's cgroup memory limit ÷ per-worker heap),
    /// clamped to at least `sync_pool_size`. On a 512 MB NF that resolves to ~15
    /// (not 32); set this explicitly to override the budget either way.
    /// An explicit value below the core (`sync_pool_size`, default
    /// `max(8, 2 × CPUs)`) is raised to the core with a startup warning; set
    /// `sync_pool_size` as well to cap the pool lower.
    #[serde(default)]
    pub sync_pool_max: Option<usize>,
    /// Seconds the synchronous Python executor pool may show *zero forward
    /// progress while fully saturated* before SIPhon aborts the process so a
    /// supervisor (`restart: always`, systemd) restarts it.  Guards against a
    /// handler that blocks every worker indefinitely (a thread-unsafe HTTP
    /// client wedging, a backend that never returns, a lock held forever):
    /// without it the process stays alive but serves no SIP, and a
    /// restart-on-exit policy never fires because the process never exits.
    /// Defaults to 30 (6× the default 5 s HTTP-auth timeout, so transient
    /// backend slowness never trips it); `0` disables the watchdog.  See
    /// `script::py_executor`.
    #[serde(default = "default_handler_stall_abort_secs")]
    pub handler_stall_abort_secs: u64,
    /// Seconds the process may show no sign of life before SIPhon aborts it
    /// so a supervisor restarts it: the tokio runtime running no task (timer
    /// and socket included), most of its workers stuck in one poll, no thread
    /// able to attach to the Python interpreter (a garbage collection's
    /// stop-the-world that never ends), or the timer sweep not turning.
    ///
    /// Separate from `handler_stall_abort_secs`, which judges the executor
    /// pool and stays quiet while the pool has idle capacity: a wedge of the
    /// whole process starves the pool of work too, so the pool looks idle
    /// while nothing is served. Defaults to 30; `0` disables it. See
    /// `script::liveness`.
    #[serde(default = "default_process_stall_abort_secs")]
    pub process_stall_abort_secs: u64,
    /// Seconds a synchronous worker waits for one `async def` handler's
    /// coroutine before it gives the worker thread back and fails that call.
    ///
    /// Every inbound message becomes a job on the executor pool, and an async
    /// handler parks its worker for as long as its coroutine runs. Without a
    /// bound, a handler awaiting something that never completes costs that
    /// worker for the life of the process.
    ///
    /// This is a leak guard, not a service-level deadline. Plenty of correct
    /// handlers run for tens of seconds — a ring-before-answer `asyncio.sleep`,
    /// a `proxy.send_request` waiting out RFC 3261 Timer B (32 s), a Diameter
    /// round trip on RFC 6733 Tx (30 s) — so the default sits far above all of
    /// them at 300 s. Reaching it means a handler is awaiting something that
    /// will never arrive, which is a bug in the script or the thing it calls.
    /// What keeps a wedged handler from taking the node down is the executor
    /// watchdog declining to abort a pool that still has spare capacity, not
    /// this value, so there is nothing to gain by tightening it.
    #[serde(default)]
    pub handler_timeout_secs: Option<u64>,
    /// Maximum number of handler jobs that may queue for the synchronous
    /// Python executor pool before new inbound work is shed (dropped — the SIP
    /// client retransmits).  Bounds memory under overload so a stuck pool can
    /// no longer grow the queue without limit.  Defaults to 1024; raise it on
    /// high-throughput NFs so normal bursts never shed.  Clamped to at least 1.
    #[serde(default = "default_executor_queue_capacity")]
    pub executor_queue_capacity: usize,
    /// Extra directories added to the Python `sys.path` so a script can
    /// `import` shared helper modules that live outside its own directory.
    /// The script's *own* directory (the parent of `path`) is always added
    /// automatically; this list is only for helpers shared across scripts/NFs
    /// (e.g. a common `/etc/siphon/lib`).  Modules imported from any of these
    /// directories (and from the script's own directory) hot-reload on change
    /// just like the main script.  Defaults to empty.
    #[serde(default)]
    pub include_paths: Vec<String>,
    /// Whether an `async def` handler called through the script handle (an
    /// extension's HTTP route, SMPP handler and the like) is stepped on its
    /// asyncio driver without an asyncio task while it awaits only siphon's
    /// own awaitables. `off` (the default) runs every such handler as an
    /// asyncio task, as before. `on` skips the task, its
    /// `concurrent.futures` bridge and the completion-thread hop for each
    /// await; a handler that uses asyncio itself (`asyncio.sleep`, a foreign
    /// future, `gather`) is handed to a task on the same thread the first
    /// time it does, and starts as one from then on. SIP request and Diameter
    /// handlers are not affected by this switch. See `script::runner`.
    #[serde(default)]
    pub direct_dispatch: DirectDispatch,
    /// Python garbage-collector settings, applied once at startup. See
    /// [`ScriptGcConfig`].
    #[serde(default)]
    pub gc: ScriptGcConfig,
}

/// `script.gc`: what siphon tells the interpreter's cyclic garbage collector
/// once, at startup. Both keys default to leaving CPython as it is.
///
/// The line references are to CPython 3.14.2, `Python/gc_free_threading.c`
/// (the collector of a free-threaded build) and `Modules/gcmodule.c`.
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct ScriptGcConfig {
    /// Run one full collection and then `gc.freeze()` when the script and the
    /// extensions have loaded, so no later collection examines the objects
    /// alive at that point (the standard library, the script's modules,
    /// whatever its top level built).
    ///
    /// On a free-threaded build every collection is a stop-the-world over the
    /// whole heap. A frozen object is still stepped over in that walk
    /// (`gc_visit_heaps`), but `op_from_block` drops it before any
    /// `tp_traverse` or refcount work (lines 360-374), and the pass that marks
    /// what is reachable from the roots is skipped altogether (lines
    /// 2184-2190). Measured on 3.14.2t with 2.1 million tracked objects: a
    /// full collection went from 35 ms to 17 ms.
    ///
    /// Frozen objects are never examined again, so a reference cycle among
    /// them that dies later is never freed. The freeze happens once: a script
    /// reload builds new modules, which are not frozen and are collected as
    /// usual when the next reload replaces them, while the copy of the
    /// script's modules that was frozen at startup stays allocated after the
    /// first reload. That is a one-off cost of the size of the script's own
    /// module-level objects, not a leak per reload.
    ///
    /// The collector counts only unfrozen objects as long-lived (line 1214),
    /// and it does not start an automatic collection while fewer objects than
    /// a quarter of that count are new (line 2099). With most of the heap
    /// frozen that floor drops, so the freeze alone makes collections shorter
    /// and far more frequent (24 against 2 in one measurement, three times
    /// the pause in total). Set `threshold` with it; a quarter of the frozen
    /// count restores the floor.
    #[serde(default)]
    pub freeze_after_load: bool,
    /// `gc.set_threshold(threshold)`, which sets only the first of CPython's
    /// three thresholds (`gcmodule.c` line 162). Unset leaves CPython's 2000
    /// (line 1588).
    ///
    /// On a free-threaded build an automatic collection is considered when
    /// the young count (container objects allocated minus those freed since
    /// the collector last looked) exceeds this (line 2091) and is at least a
    /// quarter of the unfrozen objects that survived the last collection
    /// (line 2099). It then runs if the counts set aside since the last
    /// collection exceed 40 times the threshold (line 2057), or the process's
    /// RSS plus swap has grown since then by more than a tenth, and by more
    /// than 128 KiB (lines 2066-2068). Otherwise the young count is set aside
    /// and starts again from zero (lines 2077-2079).
    ///
    /// So the value is the floor under which nothing is considered and, times
    /// 40, what must have been set aside before a process whose memory is
    /// steady collects anyway: 80,000 by default. Neither is an interval. A
    /// heap of 2 million unfrozen survivors is not considered before 500,000
    /// objects are new, whatever the threshold.
    ///
    /// 0 is refused: it turns automatic collection off (line 2091), and then
    /// no reference cycle is freed unless something calls `gc.collect()`. So
    /// is anything above 53,687,091, where CPython's `threshold * 40`
    /// overflows a C `int`.
    #[serde(default, deserialize_with = "deserialize_gc_threshold")]
    pub threshold: Option<u32>,
}

/// The largest `script.gc.threshold`: CPython computes `threshold * 40` in a
/// C `int` (`Python/gc_free_threading.c` line 2057 in 3.14.2).
pub const GC_THRESHOLD_MAX: u32 = i32::MAX.unsigned_abs() / 40;

fn deserialize_gc_threshold<'de, D>(deserializer: D) -> Result<Option<u32>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let Some(threshold) = Option::<u64>::deserialize(deserializer)? else {
        return Ok(None);
    };
    if threshold == 0 {
        return Err(serde::de::Error::custom(
            "script.gc.threshold must be at least 1: 0 turns Python's automatic garbage \
             collection off, and reference cycles are then not freed (leave the key out \
             to keep CPython's default)",
        ));
    }
    match u32::try_from(threshold) {
        Ok(threshold) if threshold <= GC_THRESHOLD_MAX => Ok(Some(threshold)),
        _ => Err(serde::de::Error::custom(format!(
            "script.gc.threshold must be at most {GC_THRESHOLD_MAX}, not {threshold}: \
             CPython multiplies it by 40 in a C int"
        ))),
    }
}

/// `script.direct_dispatch`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DirectDispatch {
    #[default]
    Off,
    On,
}

impl DirectDispatch {
    pub fn is_on(self) -> bool {
        self == Self::On
    }
}

impl<'de> Deserialize<'de> for DirectDispatch {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // `on` and `off` are booleans to a YAML 1.1 reader and strings to a
        // YAML 1.2 one; both spellings mean the same thing here.
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Written {
            Flag(bool),
            Word(String),
        }
        match Written::deserialize(deserializer)? {
            Written::Flag(true) => Ok(Self::On),
            Written::Flag(false) => Ok(Self::Off),
            Written::Word(word) => match word.to_ascii_lowercase().as_str() {
                "on" => Ok(Self::On),
                "off" => Ok(Self::Off),
                other => Err(serde::de::Error::custom(format!(
                    "script.direct_dispatch must be `on` or `off`, not `{other}`"
                ))),
            },
        }
    }
}

fn default_script_path() -> String {
    String::new()
}

fn default_handler_stall_abort_secs() -> u64 {
    30
}

fn default_process_stall_abort_secs() -> u64 {
    30
}

/// Seconds a worker waits for one coroutine when the operator sets nothing.
///
/// A leak guard well clear of every legitimate long handler (a 30 s ring, a
/// 32 s Timer B wait, a 30 s Diameter Tx), so reaching it always means
/// something is never going to arrive.
fn default_handler_timeout_secs() -> u64 {
    300
}

/// The coroutine wait a worker uses, given the configured value.
///
/// Deliberately independent of `handler_stall_abort_secs`: deriving it from
/// the stall window would cap every handler below 30 s, which is shorter than
/// a normal ring and shorter than Timer B, so correct handlers would start
/// failing. The watchdog's own guard — it does not abort a pool with idle
/// capacity — is what stops a wedged handler taking the process with it.
pub fn coroutine_timeout(handler_timeout_secs: Option<u64>) -> std::time::Duration {
    std::time::Duration::from_secs(
        handler_timeout_secs
            .unwrap_or_else(default_handler_timeout_secs)
            .max(1),
    )
}

fn default_executor_queue_capacity() -> usize {
    1024
}

impl Default for ScriptConfig {
    fn default() -> Self {
        Self {
            path: default_script_path(),
            reload: default_reload(),
            async_pool_size: None,
            sync_pool_size: None,
            sync_pool_max: None,
            handler_stall_abort_secs: default_handler_stall_abort_secs(),
            process_stall_abort_secs: default_process_stall_abort_secs(),
            handler_timeout_secs: None,
            executor_queue_capacity: default_executor_queue_capacity(),
            include_paths: Vec::new(),
            direct_dispatch: DirectDispatch::Off,
            gc: ScriptGcConfig::default(),
        }
    }
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ReloadMode {
    /// inotify watch — reload on file change, no restart required.
    Auto,
    /// Only reload on SIGHUP.
    Sighup,
}

fn default_reload() -> ReloadMode {
    ReloadMode::Auto
}
