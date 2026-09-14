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
}

fn default_script_path() -> String {
    String::new()
}

fn default_handler_stall_abort_secs() -> u64 {
    30
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
            executor_queue_capacity: default_executor_queue_capacity(),
            include_paths: Vec::new(),
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
