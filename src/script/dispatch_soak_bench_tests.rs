//! A soak of script dispatch under a load shaped like a busy node: handlers
//! that really suspend, a large live heap that changes, blocking sync handlers
//! beside the async ones, and the interpreter's stop-the-world measured from
//! outside.
//!
//! Not a criterion bench and not a per-handler cost table. What it is for is
//! the failure a short closed-loop run cannot show: a dispatch path that is
//! cheaper per call and still makes the whole process slower, because of what
//! it does to the executor queue, the collector and every thread that has to
//! attach. So the figures that matter here are the attach wait, the collector
//! pauses, the executor's in-flight count and the pending coroutines, read
//! over minutes at a fixed arrival rate.
//!
//! ```text
//! PYO3_PYTHON=python3.14t taskset -c 0-5 cargo test --release --lib -- \
//!     --ignored --nocapture --test-threads=1 \
//!     script::dispatch_soak_bench_tests::dispatch_soak
//! ```
//!
//! # The run that tells two dispatch paths apart
//!
//! With every CPU of the machine and handlers that do nothing between awaits,
//! awaits driven from the executor and awaits driven by asyncio measure the
//! same. They part on a node with a CPU limit whose handlers run some Python
//! between awaits: a limit sizes the executor small (4 threads growing to 32
//! under one CPU), and once the pool has grown, every thread in it is running
//! handler code on that one CPU. So run the built test binary under a quota,
//! at a rate the limit carries with room to spare:
//!
//! ```text
//! SOAK_RATE=300 SOAK_WORK=1100 SOAK_HEAP_MB=0 SOAK_SECONDS=120 \
//!     systemd-run --user --scope -p CPUQuota=100% taskset -c 0-5 \
//!     target/release/deps/siphon-<hash> --ignored --nocapture --test-threads=1 \
//!     script::dispatch_soak_bench_tests::dispatch_soak
//! ```
//!
//! `docs/dev/direct-dispatch-soak.md` has what that run and its variants
//! measured.
//!
//! # Load
//!
//! Arrivals are open loop (exponential gaps at `SOAK_RATE` per second, each
//! request its own task), so a slow node does not slow its own offered load.
//! Every request picks one of these by weight (`SOAK_MIX`):
//!
//! | Kind | Path | Handler |
//! |---|---|---|
//! | `call` | `ScriptHandle::call_handler_with` | `async def`, K siphon awaitables |
//! | `request` | executor job, `start_handler_coroutine`, `resume_on_executor`, as the request dispatcher | `async def`, K siphon awaitables |
//! | `request_gather` | as `request` | `tasks.gather` of a script coroutine (K - 1 awaitables) and one awaitable |
//! | `sync` | `ScriptHandle::call_handler_with` | `def`, blocks released for 5 to 50 ms |
//! | `gather` | `ScriptHandle::call_handler_with` | `asyncio.gather` of two awaitables, then K - 2 more |
//! | `wrapped` | `ScriptHandle::call_handler_with` | K awaitables behind a wrapper coroutine shared with `wrapped_asyncio` |
//! | `wrapped_asyncio` | `ScriptHandle::call_handler_with` | `asyncio.sleep`, then K - 1 awaitables, behind the same wrapper |
//!
//! K is uniform in `SOAK_AWAITS`. An awaitable is a tokio sleep with a
//! log-normal delay (`SOAK_DELAY_P50_MS`, `SOAK_DELAY_P99_MS`), so every await
//! suspends. No caller attaches to the interpreter on a tokio worker.
//!
//! The script builds `SOAK_HEAP_MB` of session objects at import (dicts, lists
//! and objects that refer back to their owner, so a replaced session is cyclic
//! garbage only the collector frees) and every handler replaces a few, at
//! `SOAK_MUTATE_PERCENT` of the heap per second in total.
//!
//! # Knobs
//!
//! | Variable | Default | Meaning |
//! |---|---|---|
//! | `SOAK_RATE` | `300` | Arrivals per second |
//! | `SOAK_SECONDS` | `300` | Measured seconds |
//! | `SOAK_WARMUP_SECONDS` | `10` | Load before measuring starts |
//! | `SOAK_HEAP_MB` | `300` | Live session heap built at import |
//! | `SOAK_MUTATE_PERCENT` | `1` | Share of the sessions replaced per second |
//! | `SOAK_AWAITS` | `3,6` | Fewest and most awaits per async handler |
//! | `SOAK_WORK` | `0` | Session reads a handler does before each await and before it returns |
//! | `SOAK_DELAY_P50_MS` / `SOAK_DELAY_P99_MS` | `2` / `80` | Awaitable delay |
//! | `SOAK_SYNC_BLOCK_MS` | `5,50` | Shortest and longest sync block |
//! | `SOAK_MIX` | `call=25,request=25,sync=30,gather=5,wrapped=10,wrapped_asyncio=5` | Weights (`request_gather` is 0 unless named) |
//! | `SOAK_DIRECT` | `0` | `1` runs with `script.direct_dispatch: on` |
//! | `SOAK_ASYNCIO` | `1` | `0` moves the two asyncio kinds' weight to `call` |
//! | `SOAK_WORKERS` | `6` | Tokio workers |
//! | `SOAK_DRIVERS` | `6` | Asyncio drivers (`script.async_pool_size`) |
//! | `SOAK_CPUS` | available | CPU count the executor is sized from |
//! | `SOAK_EXECUTOR_CORE` / `SOAK_EXECUTOR_MAX` | resolved | `script.sync_pool_size` / `sync_pool_max` |
//! | `SOAK_QUEUE` | `1024` | Executor queue capacity |
//! | `SOAK_SLA_MS` | `2000` | A request slower than this is not goodput |
//! | `SOAK_UNPINNED_PROBE_MS` | `100` | Interval of the second attach probe; `0` turns it off |
//!
//! # Output
//!
//! One table. The attach wait is measured by a thread of its own that attaches
//! and detaches every millisecond, holding its thread state like an executor
//! worker; a second thread times the attach siphon's own liveness probe makes,
//! which sets a thread state up and tears it down each time. A collector pause
//! is the time between the `start` and `stop` of `gc.callbacks` on the
//! collecting thread: it brackets the whole collection, so it is an upper
//! bound on the stop-the-world inside it. In-flight, pool size and queue wait
//! are the executor's own gauges, which it publishes once a second. One line
//! says how many async handlers finished as an asyncio task and how many
//! without one, which is how to tell which path a run took. A last
//! `SOAK_RESULT` line repeats the headline figures as `key=value` for
//! collating runs, with the switch, the calls the runners refused and the
//! machine's one-minute load average at the end.

use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyModule, PyModuleMethods};

use crate::script::engine::ScriptEngine;
use crate::script::handle::{HandlerHandle, ScriptHandle};
use crate::script::inline_dispatch::{start_handler_coroutine, HandlerStart, PendingHandler};
use crate::script::py_executor::{self, RunFailure};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

fn env_parse<T: std::str::FromStr>(name: &str, default: T) -> T {
    std::env::var(name)
        .ok()
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(default)
}

fn env_pair(name: &str, default: (u64, u64)) -> (u64, u64) {
    let Ok(value) = std::env::var(name) else {
        return default;
    };
    let mut parts = value.split(',').filter_map(|part| part.trim().parse().ok());
    match (parts.next(), parts.next()) {
        (Some(low), Some(high)) if low <= high => (low, high),
        (Some(only), None) => (only, only),
        _ => default,
    }
}

/// The request kinds, in table order.
const KINDS: [&str; 7] = [
    "call",
    "request",
    "sync",
    "gather",
    "wrapped",
    "wrapped_asyncio",
    "request_gather",
];
/// The kinds dispatched as the request dispatcher does.
const REQUEST_KINDS: [usize; 2] = [1, 6];
const ASYNCIO_KINDS: [usize; 2] = [3, 5];
const DEFAULT_MIX: &str = "call=25,request=25,sync=30,gather=5,wrapped=10,wrapped_asyncio=5";

struct SoakConfig {
    rate: f64,
    seconds: u64,
    warmup_seconds: u64,
    heap_mb: u64,
    mutate_percent: f64,
    awaits: (u64, u64),
    work: u64,
    sync_block_ms: (u64, u64),
    delay_p50_ms: f64,
    delay_p99_ms: f64,
    weights: [u64; 7],
    /// `script.direct_dispatch`.
    direct: bool,
    workers: usize,
    drivers: usize,
    cpus: usize,
    executor_core: Option<usize>,
    executor_max: Option<usize>,
    queue: usize,
    sla: Duration,
    unpinned_probe: Duration,
}

impl SoakConfig {
    fn from_env() -> Self {
        let mix = std::env::var("SOAK_MIX").unwrap_or_else(|_| DEFAULT_MIX.to_string());
        let mut weights = [0u64; 7];
        for entry in mix.split(',') {
            let Some((name, weight)) = entry.split_once('=') else {
                continue;
            };
            let index = KINDS
                .iter()
                .position(|kind| *kind == name.trim())
                .unwrap_or_else(|| panic!("SOAK_MIX names an unknown kind: {name}"));
            weights[index] = weight.trim().parse().expect("SOAK_MIX weight");
        }
        if env_parse("SOAK_ASYNCIO", 1u8) == 0 {
            for index in ASYNCIO_KINDS {
                weights[0] += std::mem::take(&mut weights[index]);
            }
        }
        assert!(weights.iter().sum::<u64>() > 0, "SOAK_MIX is all zero");
        let available = std::thread::available_parallelism().map_or(1, |count| count.get());
        Self {
            rate: env_parse("SOAK_RATE", 300.0),
            seconds: env_parse("SOAK_SECONDS", 300),
            warmup_seconds: env_parse("SOAK_WARMUP_SECONDS", 10),
            heap_mb: env_parse("SOAK_HEAP_MB", 300),
            mutate_percent: env_parse("SOAK_MUTATE_PERCENT", 1.0),
            awaits: env_pair("SOAK_AWAITS", (3, 6)),
            work: env_parse("SOAK_WORK", 0),
            sync_block_ms: env_pair("SOAK_SYNC_BLOCK_MS", (5, 50)),
            delay_p50_ms: env_parse("SOAK_DELAY_P50_MS", 2.0),
            delay_p99_ms: env_parse("SOAK_DELAY_P99_MS", 80.0),
            weights,
            direct: env_parse("SOAK_DIRECT", 0u8) != 0,
            workers: env_parse("SOAK_WORKERS", 6),
            drivers: env_parse("SOAK_DRIVERS", 6),
            cpus: env_parse("SOAK_CPUS", available),
            executor_core: std::env::var("SOAK_EXECUTOR_CORE")
                .ok()
                .and_then(|value| value.parse().ok()),
            executor_max: std::env::var("SOAK_EXECUTOR_MAX")
                .ok()
                .and_then(|value| value.parse().ok()),
            queue: env_parse("SOAK_QUEUE", 1024),
            sla: Duration::from_millis(env_parse("SOAK_SLA_MS", 2000)),
            unpinned_probe: Duration::from_millis(env_parse("SOAK_UNPINNED_PROBE_MS", 100)),
        }
    }

    fn mix(&self) -> String {
        KINDS
            .iter()
            .zip(self.weights)
            .filter(|(_, weight)| *weight > 0)
            .map(|(kind, weight)| format!("{kind}={weight}"))
            .collect::<Vec<_>>()
            .join(",")
    }
}

// ---------------------------------------------------------------------------
// Random draws
// ---------------------------------------------------------------------------

/// One splitmix64 stream for every draw: any thread may draw, and a run's
/// arrivals and delays come from the same seed every time.
static DRAWS: AtomicU64 = AtomicU64::new(0x5EED_0FD1_5BA7_C4A1);

/// Uniform in (0, 1).
fn uniform() -> f64 {
    let mut value = DRAWS.fetch_add(0x9E37_79B9_7F4A_7C15, Ordering::Relaxed);
    value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    value ^= value >> 31;
    ((value >> 11) as f64 + 0.5) / (1u64 << 53) as f64
}

/// Uniform over `low..=high`.
fn uniform_between(range: (u64, u64)) -> u64 {
    let span = (range.1 - range.0 + 1) as f64;
    range.0 + ((uniform() * span) as u64).min(range.1 - range.0)
}

/// The delays the script's awaitables and blocking calls take.
struct Delays {
    /// Median of the log-normal awaitable delay, in milliseconds.
    median_ms: f64,
    /// Its shape: `ln(p99 / p50) / z(0.99)`.
    sigma: f64,
    sync_block_ms: (u64, u64),
}

static DELAYS: OnceLock<Delays> = OnceLock::new();

/// No awaitable takes longer than this, whatever the tail draws.
const DELAY_CAP: Duration = Duration::from_secs(1);

impl Delays {
    fn new(config: &SoakConfig) -> Self {
        // The 99th percentile of a standard normal.
        const Z_99: f64 = 2.326_347_874;
        Self {
            median_ms: config.delay_p50_ms,
            sigma: (config.delay_p99_ms / config.delay_p50_ms).ln().max(0.0) / Z_99,
            sync_block_ms: config.sync_block_ms,
        }
    }

    fn awaitable(&self) -> Duration {
        // Box-Muller: one standard normal from two uniforms.
        let normal =
            (-2.0 * uniform().ln()).sqrt() * (2.0 * std::f64::consts::PI * uniform()).cos();
        let millis = self.median_ms * (self.sigma * normal).exp();
        Duration::from_secs_f64(millis / 1e3).min(DELAY_CAP)
    }

    fn sync_block(&self) -> Duration {
        Duration::from_millis(uniform_between(self.sync_block_ms))
    }
}

fn delays() -> &'static Delays {
    DELAYS.get().expect("the soak installed its delays")
}

// ---------------------------------------------------------------------------
// The script and what it calls
// ---------------------------------------------------------------------------

/// An awaitable that takes a log-normal time on tokio's timer, as a backend
/// round trip does. Resolves to the microseconds it took.
#[pyfunction]
fn wait(python: Python<'_>) -> PyResult<Bound<'_, PyAny>> {
    let delay = delays().awaitable();
    crate::script::awaitable(python, async move {
        tokio::time::sleep(delay).await;
        Ok(delay.as_micros() as u64)
    })
}

/// A blocking script API: parks the calling executor worker, released from the
/// interpreter, for a uniform time.
#[pyfunction]
fn block() -> u64 {
    let delay = delays().sync_block();
    crate::script::detach_block_on(tokio::time::sleep(delay));
    delay.as_micros() as u64
}

const SCRIPT: &str = r#"
import asyncio
import gc
import os
import threading
import time
import _siphon_registry as _r
import _dispatch_soak as soak
from siphon import tasks

_PAGE = os.sysconf("SC_PAGE_SIZE")

def _rss():
    with open("/proc/self/statm") as statm:
        return int(statm.read().split()[1]) * _PAGE

class Session:
    """One registered subscriber's state, shaped like what a registrar and a
    dialog store keep: nested containers, and a dialog that refers back to its
    session, so a replaced session is garbage only the collector frees."""

    __slots__ = ("identity", "contacts", "dialogs", "attributes", "touched")

    def __init__(self, number):
        self.identity = "sip:user%07d@example.test" % number
        self.contacts = [{
            "uri": "sip:user%07d@192.0.2.%d:5060" % (number, number % 250 + 1),
            "expires": 3600,
            "q": 1.0,
            "instance": "urn:uuid:%032x" % number,
        }]
        self.dialogs = [{
            "call_id": "%032x" % (number * 2654435761 % 2 ** 64),
            "owner": self,
            "route": ["sip:edge%d.example.test;lr" % (number % 7)],
            "cseq": number,
        }]
        self.attributes = {
            "imsi": "00101%010d" % number,
            "barred": False,
            "services": ["voice", "sms"],
            "counters": [0, 0, 0, 0],
        }
        self.touched = 0

SESSIONS = {}

def _build(target_bytes):
    # At least enough sessions for the handlers to have something to touch.
    start = _rss()
    number = 0
    while number < 1000 or _rss() - start < target_bytes:
        for _ in range(1000):
            SESSIONS[number] = Session(number)
            number += 1
    return number

gc.disable()
COUNT = _build(soak.HEAP_MB * 1024 * 1024)
gc.enable()
gc.collect()
# Sessions each handler call replaces, for MUTATE_PERCENT of them per second.
MUTATE = max(1, round(COUNT * soak.MUTATE_PERCENT / 100.0 / soak.RATE))

WORK = soak.WORK

def _work(seed):
    # The Python a handler runs between awaits: reads of shared session state.
    total = 0
    for step in range(WORK):
        total += SESSIONS[(seed + step * 7919) % COUNT].touched
    return total

def _touch(seed):
    number = seed % COUNT
    for step in range(MUTATE):
        replaced = (number + step * 7919) % COUNT
        SESSIONS[replaced] = Session(replaced)
    session = SESSIONS[number]
    session.touched += 1
    session.attributes["counters"][seed & 3] += 1
    _work(seed)
    return session

# How many async handlers finished as an asyncio task, and how many did not.
# Unsynchronised, so threads finishing together lose counts: it tells the two
# paths apart, it is not a tally.
_finished = {}

def _note_finish():
    kind = type(asyncio.current_task()).__name__
    _finished[kind] = _finished.get(kind, 0) + 1

async def call_h(seed, awaits):
    _touch(seed)
    total = 0
    for _ in range(awaits):
        total += await soak.wait()
        _work(seed + total)
    _note_finish()
    return total

async def request_h(request):
    _touch(request["seed"])
    for _ in range(request["awaits"]):
        request["waited"] += await soak.wait()
        _work(request["seed"] + request["waited"])
    _note_finish()

async def _lookup(seed, awaits):
    total = 0
    for _ in range(awaits):
        total += await soak.wait()
        _work(seed + total)
    return total

async def request_gather_h(request):
    _touch(request["seed"])
    looked_up, waited = await tasks.gather(
        _lookup(request["seed"], max(1, request["awaits"] - 1)), soak.wait())
    request["waited"] += looked_up + waited
    _work(request["seed"] + request["waited"])
    _note_finish()

def sync_h(seed, awaits):
    _touch(seed)
    return soak.block()

async def gather_h(seed, awaits):
    _touch(seed)
    first, second = await asyncio.gather(soak.wait(), soak.wait())
    total = first + second
    for _ in range(max(0, awaits - 2)):
        total += await soak.wait()
        _work(seed + total)
    _note_finish()
    return total

def route(handler):
    # One wrapper coroutine function for every route behind it, as a
    # decorator-based extension registers them.
    async def wrapper(seed, awaits):
        return await handler(seed, awaits)
    return wrapper

async def _wrapped(seed, awaits):
    _touch(seed)
    total = 0
    for _ in range(awaits):
        total += await soak.wait()
        _work(seed + total)
    _note_finish()
    return total

async def _wrapped_asyncio(seed, awaits):
    _touch(seed)
    await asyncio.sleep(0.001)
    total = 0
    for _ in range(max(0, awaits - 1)):
        total += await soak.wait()
        _work(seed + total)
    _note_finish()
    return total

# Collector pauses: `start` to `stop` on the collecting thread, nanoseconds.
_gc_started = {}
_gc_pauses = []

def _on_gc(phase, info):
    thread = threading.get_ident()
    if phase == "start":
        _gc_started[thread] = time.perf_counter_ns()
        return
    started = _gc_started.pop(thread, None)
    if started is not None:
        _gc_pauses.append(time.perf_counter_ns() - started)

gc.callbacks.append(_on_gc)

def gc_reset():
    _gc_pauses.clear()
    _finished.clear()
    return [COUNT, MUTATE]

def finished():
    as_task = _finished.get("Task", 0)
    return [as_task, sum(_finished.values()) - as_task]

def gc_report():
    return list(_gc_pauses)

for name, handler, is_async in [
    ("call", call_h, True),
    ("request", request_h, True),
    ("sync", sync_h, False),
    ("gather", gather_h, True),
    ("wrapped", route(_wrapped), True),
    ("wrapped_asyncio", route(_wrapped_asyncio), True),
    ("request_gather", request_gather_h, True),
    ("gc_reset", gc_reset, False),
    ("gc_report", gc_report, False),
    ("finished", finished, False),
]:
    _r.register("soak." + name, None, handler, is_async, None)
"#;

/// Publish `_dispatch_soak`, the module the script imports.
fn install_module(config: &SoakConfig) {
    Python::attach(|python| {
        let module = PyModule::new(python, "_dispatch_soak").unwrap();
        module
            .add_function(pyo3::wrap_pyfunction!(wait, &module).unwrap())
            .unwrap();
        module
            .add_function(pyo3::wrap_pyfunction!(block, &module).unwrap())
            .unwrap();
        module.add("HEAP_MB", config.heap_mb).unwrap();
        module.add("RATE", config.rate).unwrap();
        module.add("MUTATE_PERCENT", config.mutate_percent).unwrap();
        module.add("WORK", config.work).unwrap();
        python
            .import("sys")
            .unwrap()
            .getattr("modules")
            .unwrap()
            .set_item("_dispatch_soak", &module)
            .unwrap();
    });
}

fn load_engine(config: &SoakConfig) -> Arc<ScriptEngine> {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(SCRIPT.as_bytes()).unwrap();
    file.flush().unwrap();
    Arc::new(
        ScriptEngine::new(&crate::config::ScriptConfig {
            path: file.path().to_str().unwrap().to_owned(),
            reload: crate::config::ReloadMode::Sighup,
            async_pool_size: Some(config.drivers),
            sync_pool_size: config.executor_core,
            sync_pool_max: config.executor_max,
            handler_stall_abort_secs: 0,
            process_stall_abort_secs: 0,
            handler_timeout_secs: None,
            executor_queue_capacity: config.queue,
            include_paths: Vec::new(),
            direct_dispatch: if config.direct {
                crate::config::DirectDispatch::On
            } else {
                crate::config::DirectDispatch::Off
            },
        })
        .unwrap(),
    )
}

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

/// How one request ended.
enum Outcome {
    Completed,
    /// The handler raised, or its coroutine timed out.
    Failed(String),
    /// The executor shed the job, or lost it.
    Shed,
}

#[derive(Default)]
struct KindStats {
    latencies_us: Vec<u32>,
    failed: u64,
    shed: u64,
}

/// What the request tasks share.
struct Shared {
    handle: ScriptHandle,
    /// By kind; `None` for the request kinds, which are not called through
    /// the handle.
    handlers: Vec<Option<HandlerHandle>>,
    /// By kind: a request kind's callable, as the dispatcher holds a
    /// handler's.
    request_callables: Vec<Option<Arc<Py<PyAny>>>>,
    awaits: (u64, u64),
    measuring: AtomicBool,
    stopping: AtomicBool,
    offered: AtomicU64,
    outstanding: AtomicU64,
    stats: Mutex<Vec<KindStats>>,
    first_error: Mutex<Option<String>>,
}

impl Shared {
    fn record(&self, kind: usize, latency: Duration, outcome: Outcome) {
        let mut stats = self.stats.lock().unwrap();
        // Gone once the report has been taken: a request that outlived the
        // drain is counted as unfinished there.
        let Some(entry) = stats.get_mut(kind) else {
            return;
        };
        match outcome {
            Outcome::Completed => entry
                .latencies_us
                .push(latency.as_micros().min(u128::from(u32::MAX)) as u32),
            Outcome::Shed => entry.shed += 1,
            Outcome::Failed(error) => {
                entry.failed += 1;
                drop(stats);
                self.first_error.lock().unwrap().get_or_insert(error);
            }
        }
    }
}

/// A handler called through the script handle, as an extension calls one:
/// arguments built and the outcome read inside the executor jobs.
async fn call_through_handle(shared: &Shared, kind: usize, seed: u64, awaits: u64) -> Outcome {
    let handler = shared.handlers[kind].as_ref().expect("a handle kind");
    let called = shared
        .handle
        .call_handler_with(
            handler,
            move |python| {
                Ok(vec![
                    seed.into_pyobject(python)?.into_any().unbind(),
                    awaits.into_pyobject(python)?.into_any().unbind(),
                ])
            },
            |_python, result| result.map(|_| ()).map_err(|error| error.to_string()),
        )
        .await;
    match called {
        Ok(Ok(())) => Outcome::Completed,
        Ok(Err(error)) => Outcome::Failed(error),
        Err(_) => Outcome::Shed,
    }
}

/// What the first executor job of a request-path call came to.
enum RequestStep {
    Decided(Result<(), String>),
    Suspended(PendingHandler, Py<PyAny>),
    /// No runner had room: the dispatcher answers such a request as shed.
    Refused,
}

/// The request dispatcher's shape (`dispatcher::request_script`): a job calls
/// the handler and starts its coroutine; if that suspends the job ends, and
/// the rest runs as a new executor job once the coroutine has settled.
async fn call_as_request(shared: &Shared, kind: usize, seed: u64, awaits: u64) -> Outcome {
    let callable = Arc::clone(
        shared.request_callables[kind]
            .as_ref()
            .expect("a request kind"),
    );
    let (sender, receiver) = tokio::sync::oneshot::channel::<Result<(), String>>();
    let started = py_executor::try_run_classified(move || {
        let step = crate::script::attach::attach(|python| {
            let build = || -> PyResult<Bound<'_, PyDict>> {
                let request = PyDict::new(python);
                request.set_item("seed", seed)?;
                request.set_item("awaits", awaits)?;
                request.set_item("waited", 0u64)?;
                Ok(request)
            };
            let started = build().and_then(|request| {
                let returned = callable.bind(python).call1((&request,))?;
                let started = start_handler_coroutine(
                    python,
                    &returned,
                    &callable,
                    crate::script::runner::Admit::Bounded,
                )?;
                Ok((started, request))
            });
            match started {
                Ok((HandlerStart::Finished(_), _)) => RequestStep::Decided(Ok(())),
                Ok((HandlerStart::Suspended(pending), request)) => {
                    RequestStep::Suspended(pending, request.into_any().unbind())
                }
                Ok((HandlerStart::Refused(_), _)) => RequestStep::Refused,
                Err(error) => RequestStep::Decided(Err(error.to_string())),
            }
        });
        match step {
            RequestStep::Decided(result) => {
                let _ = sender.send(result);
            }
            // The sender goes unused: the caller counts the request as shed.
            RequestStep::Refused => drop(sender),
            RequestStep::Suspended(pending, request) => {
                pending.resume_on_executor(move |result| {
                    // The handler's value is dropped released, as the
                    // dispatcher drops it; the request is read attached, as
                    // the dispatcher reads its decision.
                    let settled = result.map(drop).map_err(|error| error.to_string());
                    crate::script::attach::attach(|python| {
                        let _ = request.bind(python).get_item("waited");
                        drop(request);
                    });
                    let _ = sender.send(settled);
                });
            }
        }
    })
    .await;
    match started {
        Ok(()) => match receiver.await {
            Ok(Ok(())) => Outcome::Completed,
            Ok(Err(error)) => Outcome::Failed(error),
            Err(_) => Outcome::Shed,
        },
        Err(RunFailure::Panicked(_)) => Outcome::Failed("the request job panicked".to_string()),
        Err(_) => Outcome::Shed,
    }
}

async fn one_request(shared: Arc<Shared>, kind: usize, measured: bool) {
    let seed = (uniform() * 1e12) as u64;
    let awaits = uniform_between(shared.awaits);
    let begun = Instant::now();
    let outcome = if REQUEST_KINDS.contains(&kind) {
        call_as_request(&shared, kind, seed, awaits).await
    } else {
        call_through_handle(&shared, kind, seed, awaits).await
    };
    if measured {
        shared.record(kind, begun.elapsed(), outcome);
    }
    shared.outstanding.fetch_sub(1, Ordering::Relaxed);
}

/// Open-loop arrivals: exponential gaps, and a late tick is followed at once
/// by the ones it delayed, so the offered load never bends to the node.
async fn generate(shared: Arc<Shared>, rate: f64, weights: [u64; 7]) {
    let total: u64 = weights.iter().sum();
    let mut next = tokio::time::Instant::now();
    while !shared.stopping.load(Ordering::Relaxed) {
        next += Duration::from_secs_f64(-uniform().ln() / rate);
        tokio::time::sleep_until(next).await;
        let mut pick = (uniform() * total as f64) as u64;
        let mut kind = 0;
        for (index, weight) in weights.iter().enumerate() {
            if pick < *weight {
                kind = index;
                break;
            }
            pick -= weight;
        }
        let measured = shared.measuring.load(Ordering::Relaxed);
        if measured {
            shared.offered.fetch_add(1, Ordering::Relaxed);
        }
        shared.outstanding.fetch_add(1, Ordering::Relaxed);
        tokio::spawn(one_request(Arc::clone(&shared), kind, measured));
    }
}

// ---------------------------------------------------------------------------
// Measurement
// ---------------------------------------------------------------------------

/// Attach to the interpreter and detach again every millisecond, timing each
/// attach. The thread keeps its thread state for life, so an attach costs what
/// it costs an executor worker: nothing, unless the world is stopped.
fn spawn_attach_probe(
    stop: Arc<AtomicBool>,
    measuring: Arc<AtomicBool>,
) -> std::thread::JoinHandle<Vec<u32>> {
    std::thread::Builder::new()
        .name("soak-attach-probe".to_string())
        .spawn(move || {
            // SAFETY: the interpreter is initialised; the pair leaves this
            // thread with a thread state, detached, as siphon's own pinned
            // threads are.
            unsafe {
                pyo3::ffi::PyGILState_Ensure();
                pyo3::ffi::PyEval_SaveThread();
            }
            let mut waits_us = Vec::with_capacity(1 << 19);
            while !stop.load(Ordering::Relaxed) {
                let started = Instant::now();
                let attached = Python::try_attach(|_python| ());
                let waited = started.elapsed();
                if attached.is_some() && measuring.load(Ordering::Relaxed) {
                    waits_us.push(waited.as_micros().min(u128::from(u32::MAX)) as u32);
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            waits_us
        })
        .expect("the attach probe thread starts")
}

/// The attach siphon's own liveness probe times: from a thread that keeps no
/// thread state, so each attach sets one up and tears it down again. Slower
/// than the pinned probe when nothing is wrong, and it waits on more than a
/// stopped world (the interpreter's thread list, the allocator), which is why
/// both are measured.
fn spawn_unpinned_probe(
    stop: Arc<AtomicBool>,
    measuring: Arc<AtomicBool>,
    interval: Duration,
) -> std::thread::JoinHandle<Vec<u32>> {
    std::thread::Builder::new()
        .name("soak-unpinned-probe".to_string())
        .spawn(move || {
            let mut waits_us = Vec::new();
            while !interval.is_zero() && !stop.load(Ordering::Relaxed) {
                let started = Instant::now();
                let attached = Python::try_attach(|_python| ());
                let waited = started.elapsed();
                if attached.is_some() && measuring.load(Ordering::Relaxed) {
                    waits_us.push(waited.as_micros().min(u128::from(u32::MAX)) as u32);
                }
                std::thread::sleep(interval);
            }
            waits_us
        })
        .expect("the unpinned probe thread starts")
}

#[derive(Default)]
struct Samples {
    inflight: Vec<u32>,
    pool_size: Vec<u32>,
    queue_depth: Vec<u32>,
    queue_wait_ms: Vec<u32>,
    pending: Vec<u32>,
    rss_mb: Vec<u32>,
}

fn rss_mb() -> u32 {
    let statm = std::fs::read_to_string("/proc/self/statm").unwrap_or_default();
    let pages: u64 = statm
        .split_whitespace()
        .nth(1)
        .and_then(|field| field.parse().ok())
        .unwrap_or(0);
    // SAFETY: `sysconf` reads a constant.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(0) as u64;
    (pages * page / (1024 * 1024)) as u32
}

/// The CPU quota of this process's cgroup (v2), as a share of one CPU.
fn cpu_quota() -> String {
    let quota = || {
        let cgroup = std::fs::read_to_string("/proc/self/cgroup").ok()?;
        let path = cgroup.lines().find_map(|line| line.strip_prefix("0::"))?;
        let limit = std::fs::read_to_string(format!("/sys/fs/cgroup{path}/cpu.max")).ok()?;
        let mut fields = limit.split_whitespace();
        let quota: f64 = fields.next()?.parse().ok()?;
        let period: f64 = fields.next()?.parse().ok()?;
        Some(format!("{:.0}%", quota / period * 100.0))
    };
    quota().unwrap_or_else(|| "none".to_string())
}

/// The machine's one-minute load average.
fn load_average() -> f64 {
    std::fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|text| text.split_whitespace().next()?.parse().ok())
        .unwrap_or(0.0)
}

/// Threads in the process.
fn thread_count() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap_or_default()
        .lines()
        .find_map(|line| line.strip_prefix("Threads:"))
        .and_then(|count| count.trim().parse().ok())
        .unwrap_or(0)
}

/// `siphon_pyexec_queue_wait_ms`, which the executor registers itself.
fn queue_wait_ms() -> u32 {
    let Some(metrics) = crate::metrics::try_metrics() else {
        return 0;
    };
    metrics
        .registry
        .gather()
        .iter()
        .find(|family| family.name() == "siphon_pyexec_queue_wait_ms")
        .and_then(|family| {
            family
                .get_metric()
                .first()
                .map(|metric| metric.get_gauge().value())
        })
        .map_or(0, |value| value.max(0.0) as u32)
}

/// Sample the counters the executor and the async pool already keep. The
/// queue depth and the pending coroutines are live reads, every 100 ms; the
/// gauges the executor publishes once a second are read once a second. Never
/// attaches.
fn spawn_sampler(
    stop: Arc<AtomicBool>,
    measuring: Arc<AtomicBool>,
) -> std::thread::JoinHandle<Samples> {
    std::thread::Builder::new()
        .name("soak-sampler".to_string())
        .spawn(move || {
            let mut samples = Samples::default();
            let mut tick = 0u64;
            while !stop.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(100));
                tick += 1;
                if !measuring.load(Ordering::Relaxed) {
                    continue;
                }
                samples.queue_depth.push(py_executor::queue_depth() as u32);
                samples
                    .pending
                    .push(crate::script::async_pool::pending_coroutines() as u32);
                if !tick.is_multiple_of(10) {
                    continue;
                }
                if let Some(metrics) = crate::metrics::try_metrics() {
                    samples
                        .inflight
                        .push(metrics.pyexec_inflight.get().max(0) as u32);
                    samples
                        .pool_size
                        .push(metrics.pyexec_pool_size.get().max(0) as u32);
                }
                samples.queue_wait_ms.push(queue_wait_ms());
                samples.rss_mb.push(rss_mb());
            }
            samples
        })
        .expect("the sampler thread starts")
}

/// Process CPU seconds (user + system), then voluntary and involuntary
/// context switches.
fn rusage() -> (f64, i64, i64) {
    // SAFETY: `getrusage` fills the struct it is handed, which this owns.
    let usage = unsafe {
        let mut usage: libc::rusage = std::mem::zeroed();
        libc::getrusage(libc::RUSAGE_SELF, &mut usage);
        usage
    };
    let seconds = |time: libc::timeval| time.tv_sec as f64 + time.tv_usec as f64 / 1e6;
    (
        seconds(usage.ru_utime) + seconds(usage.ru_stime),
        usage.ru_nvcsw,
        usage.ru_nivcsw,
    )
}

/// Order statistics of one series.
struct Spread {
    count: usize,
    mean: f64,
    p50: f64,
    p99: f64,
    max: f64,
}

fn spread(values: &[u32], scale: f64) -> Spread {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let count = sorted.len();
    let at = |quantile: f64| {
        let index = ((count as f64 * quantile) as usize).min(count.saturating_sub(1));
        sorted.get(index).copied().unwrap_or(0) as f64 / scale
    };
    Spread {
        count,
        mean: sorted.iter().map(|value| f64::from(*value)).sum::<f64>()
            / count.max(1) as f64
            / scale
            + 0.0,
        p50: at(0.50),
        p99: at(0.99),
        max: sorted.last().copied().unwrap_or(0) as f64 / scale,
    }
}

/// Call a sync bookkeeping handler and read the integers it returns. An
/// overloaded executor sheds the call like any other, so it is repeated until
/// it gets through.
fn script_numbers(
    runtime: &tokio::runtime::Runtime,
    handle: &ScriptHandle,
    kind: &str,
) -> Vec<u64> {
    let handler = handle
        .handlers_for(kind)
        .into_iter()
        .next()
        .expect("registered");
    let give_up = Instant::now() + Duration::from_secs(120);
    loop {
        let called = runtime.block_on(handle.call_handler_with(
            &handler,
            |_python| Ok(Vec::new()),
            |_python, result| result.and_then(|value| value.extract::<Vec<u64>>()),
        ));
        match called {
            Ok(numbers) => return numbers.expect("the bookkeeping handler returned integers"),
            Err(error) => assert!(
                Instant::now() < give_up,
                "the bookkeeping handler never got through: {error}"
            ),
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

// ---------------------------------------------------------------------------
// The run
// ---------------------------------------------------------------------------

/// What a run measured, ready to print.
struct Report {
    elapsed: f64,
    cpu_seconds: f64,
    switches: i64,
    preemptions: i64,
    /// Async handlers that finished as an asyncio task, and that did not.
    finished: Vec<u64>,
    threads: u64,
    offered: u64,
    unfinished: u64,
    stats: Vec<KindStats>,
    attach_us: Vec<u32>,
    unpinned_us: Vec<u32>,
    gc_pauses_us: Vec<u32>,
    samples: Samples,
    rss_start_mb: u32,
    pool_max: usize,
    first_error: Option<String>,
}

fn print_report(config: &SoakConfig, report: &Report) {
    let all_latencies: Vec<u32> = report
        .stats
        .iter()
        .flat_map(|kind| kind.latencies_us.iter().copied())
        .collect();
    let completed = all_latencies.len() as u64;
    let failed: u64 = report.stats.iter().map(|kind| kind.failed).sum();
    let shed: u64 = report.stats.iter().map(|kind| kind.shed).sum();
    let sla_us = config.sla.as_micros() as u32;
    let late = all_latencies
        .iter()
        .filter(|value| **value > sla_us)
        .count() as u64;
    let goodput = (completed - late) as f64 / report.elapsed;
    let answered = (completed + failed).max(1) as f64;

    let attach = spread(&report.attach_us, 1e3);
    let unpinned = spread(&report.unpinned_us, 1e3);
    let gc = spread(&report.gc_pauses_us, 1e3);
    let latency = spread(&all_latencies, 1e3);
    let inflight = spread(&report.samples.inflight, 1.0);
    let pool = spread(&report.samples.pool_size, 1.0);
    let depth = spread(&report.samples.queue_depth, 1.0);
    let queue_wait = spread(&report.samples.queue_wait_ms, 1.0);
    let pending = spread(&report.samples.pending, 1.0);
    let rss = spread(&report.samples.rss_mb, 1.0);
    let cpu_us = report.cpu_seconds * 1e6 / answered;
    let switches = report.switches as f64 / answered;
    let preemptions = report.preemptions as f64 / answered;
    let attach_over = |millis: f64| {
        report
            .attach_us
            .iter()
            .filter(|wait| f64::from(**wait) > millis * 1e3)
            .count()
    };

    println!();
    println!(
        "{:<30} {:>10} {:>10} {:>10} {:>10}",
        "", "mean", "p50", "p99", "max"
    );
    let row = |name: &str, values: &Spread| {
        println!(
            "{:<30} {:>10.2} {:>10.2} {:>10.2} {:>10.2}",
            name, values.mean, values.p50, values.p99, values.max
        );
    };
    row(&format!("attach wait ms (n={})", attach.count), &attach);
    println!(
        "{:<30} >0.1 ms: {}  >1 ms: {}  >10 ms: {}  >100 ms: {}",
        "  attach waits",
        attach_over(0.1),
        attach_over(1.0),
        attach_over(10.0),
        attach_over(100.0)
    );
    row(
        &format!("attach wait ms, unpinned (n={})", unpinned.count),
        &unpinned,
    );
    row(&format!("gc pause ms (n={})", gc.count), &gc);
    row("executor in-flight", &inflight);
    row(&format!("executor pool (max {})", report.pool_max), &pool);
    row("executor queue depth", &depth);
    row("executor queue wait ms", &queue_wait);
    row("pending coroutines", &pending);
    row("latency ms", &latency);
    row(&format!("rss MB (start {})", report.rss_start_mb), &rss);
    println!();
    println!(
        "offered {}  completed {}  failed {}  shed {}  unfinished {}  late(>{} ms) {}",
        report.offered,
        completed,
        failed,
        shed,
        report.unfinished,
        config.sla.as_millis(),
        late
    );
    println!(
        "goodput {goodput:.1}/s  cpu {cpu_us:.0} us/request ({:.0}% of one core)  switches per request: \
         {switches:.1} voluntary, {preemptions:.1} involuntary",
        report.cpu_seconds / report.elapsed * 100.0
    );
    println!(
        "async handlers finished as an asyncio task: {}  without one: {}  threads: {}",
        report.finished[0], report.finished[1], report.threads
    );
    println!();
    println!(
        "{:<16} {:>8} {:>7} {:>6} {:>10} {:>10} {:>10}",
        "kind", "ok", "failed", "shed", "p50_ms", "p99_ms", "max_ms"
    );
    for (name, kind) in KINDS.iter().zip(&report.stats) {
        if kind.latencies_us.is_empty() && kind.failed == 0 && kind.shed == 0 {
            continue;
        }
        let values = spread(&kind.latencies_us, 1e3);
        println!(
            "{:<16} {:>8} {:>7} {:>6} {:>10.2} {:>10.2} {:>10.2}",
            name, values.count, kind.failed, kind.shed, values.p50, values.p99, values.max
        );
    }
    if let Some(error) = &report.first_error {
        println!("first failure: {error}");
    }
    println!(
        "SOAK_RESULT rate={} heap_mb={} attach_p50_ms={:.3} attach_p99_ms={:.3} attach_max_ms={:.3} \
         gc_count={} gc_p99_ms={:.2} gc_max_ms={:.2} inflight_mean={:.1} inflight_max={:.0} \
         pool_end={:.0} queue_wait_max_ms={:.0} pending_mean={:.1} pending_max={:.0} \
         goodput={goodput:.1} failed={failed} shed={shed} unfinished={} late={late} \
         latency_p50_ms={:.2} latency_p99_ms={:.2} latency_max_ms={:.2} cpu_us={cpu_us:.0} \
         switches={switches:.1} preemptions={preemptions:.1} rss_max_mb={:.0} attach_over_1ms={} \
         attach_over_10ms={} no_task={} threads={} unpinned_p50_ms={:.3} unpinned_p99_ms={:.3} \
         unpinned_max_ms={:.3} direct={} runner_rejected={} load1={:.2}",
        config.rate,
        config.heap_mb,
        attach.p50,
        attach.p99,
        attach.max,
        gc.count,
        gc.p99,
        gc.max,
        inflight.mean,
        inflight.max,
        report.samples.pool_size.last().copied().unwrap_or(0) as f64,
        queue_wait.max,
        pending.mean,
        pending.max,
        report.unfinished,
        latency.p50,
        latency.p99,
        latency.max,
        rss.max,
        attach_over(1.0),
        attach_over(10.0),
        report.finished[1],
        report.threads,
        unpinned.p50,
        unpinned.p99,
        unpinned.max,
        u8::from(config.direct),
        crate::script::runner::admission_rejected(),
        load_average(),
    );
}

#[test]
#[ignore = "a soak: run it by name, in a release build, on free-threaded Python"]
fn dispatch_soak() {
    let config = SoakConfig::from_env();
    assert!(DELAYS.set(Delays::new(&config)).is_ok());

    Python::initialize();
    crate::metrics::init().expect("metrics");
    let runtime = crate::server::build_runtime(|builder| {
        builder.worker_threads(config.workers);
    })
    .expect("runtime");
    // Sized as the server sizes it.
    let sizing = py_executor::resolve_sizing(
        config.cpus,
        py_executor::read_memory_limit_bytes(),
        config.executor_core,
        config.executor_max,
    );
    let executor = py_executor::PyExecutor::install(
        runtime.handle().clone(),
        py_executor::ExecutorConfig {
            core_threads: sizing.core_threads,
            max_threads: sizing.max_threads,
            queue_capacity: config.queue,
            stall_abort: None,
        },
    );
    let async_pool = crate::script::async_pool::AsyncPool::install(
        config.drivers,
        runtime.handle().clone(),
        crate::config::coroutine_timeout(None),
    );
    // As the server applies `script.direct_dispatch`: on only if the
    // self-test passes on this interpreter.
    let direct = crate::script::runner::configure(config.direct, &async_pool);
    assert_eq!(direct, config.direct, "the direct dispatch self-test");
    install_module(&config);

    let building = Instant::now();
    let engine = load_engine(&config);
    let handle = ScriptHandle::new(engine.state_arc(), runtime.handle().clone());
    let sessions = script_numbers(runtime, &handle, "soak.gc_reset");
    let free_threaded = Python::attach(|python| {
        python
            .import("sys")
            .and_then(|sys| sys.call_method0("_is_gil_enabled"))
            .and_then(|enabled| enabled.extract::<bool>())
            .map(|enabled| !enabled)
            .unwrap_or(false)
    });
    println!(
        "rate={}/s seconds={} warmup={} heap={} MB ({} sessions, {} replaced per call, built in {:.1} s) \
         awaits={}..{} work={} delay p50={} ms p99={} ms sync block={}..{} ms",
        config.rate,
        config.seconds,
        config.warmup_seconds,
        config.heap_mb,
        sessions[0],
        sessions[1],
        building.elapsed().as_secs_f64(),
        config.awaits.0,
        config.awaits.1,
        config.work,
        config.delay_p50_ms,
        config.delay_p99_ms,
        config.sync_block_ms.0,
        config.sync_block_ms.1,
    );
    println!(
        "mix={} workers={} drivers={} cpus={} cpu quota={} executor core={} max={} queue={} \
         free_threaded={} direct_dispatch={}",
        config.mix(),
        config.workers,
        config.drivers,
        config.cpus,
        cpu_quota(),
        sizing.core_threads,
        sizing.max_threads,
        config.queue,
        free_threaded,
        if direct { "on" } else { "off" },
    );

    let request_callables = KINDS
        .iter()
        .enumerate()
        .map(|(index, kind)| {
            REQUEST_KINDS.contains(&index).then(|| {
                Arc::clone(
                    &engine
                        .state_arc()
                        .load()
                        .handlers_for_custom(&format!("soak.{kind}"))
                        .first()
                        .expect("registered")
                        .callable,
                )
            })
        })
        .collect();
    let handlers = KINDS
        .iter()
        .enumerate()
        .map(|(index, kind)| {
            (!REQUEST_KINDS.contains(&index)).then(|| {
                handle
                    .handlers_for(&format!("soak.{kind}"))
                    .into_iter()
                    .next()
                    .expect("registered")
            })
        })
        .collect();
    let shared = Arc::new(Shared {
        handle: handle.clone(),
        handlers,
        request_callables,
        awaits: config.awaits,
        measuring: AtomicBool::new(false),
        stopping: AtomicBool::new(false),
        offered: AtomicU64::new(0),
        outstanding: AtomicU64::new(0),
        stats: Mutex::new(KINDS.iter().map(|_| KindStats::default()).collect()),
        first_error: Mutex::new(None),
    });

    let stop_threads = Arc::new(AtomicBool::new(false));
    let measuring = Arc::new(AtomicBool::new(false));
    let probe = spawn_attach_probe(Arc::clone(&stop_threads), Arc::clone(&measuring));
    let unpinned_probe = spawn_unpinned_probe(
        Arc::clone(&stop_threads),
        Arc::clone(&measuring),
        config.unpinned_probe,
    );
    let sampler = spawn_sampler(Arc::clone(&stop_threads), Arc::clone(&measuring));
    let generator = runtime.spawn(generate(Arc::clone(&shared), config.rate, config.weights));

    std::thread::sleep(Duration::from_secs(config.warmup_seconds));
    script_numbers(runtime, &handle, "soak.gc_reset");
    let rss_start_mb = rss_mb();
    let (cpu_before, switches_before, preemptions_before) = rusage();
    let started = Instant::now();
    shared.measuring.store(true, Ordering::Relaxed);
    measuring.store(true, Ordering::Relaxed);

    std::thread::sleep(Duration::from_secs(config.seconds));
    shared.measuring.store(false, Ordering::Relaxed);
    measuring.store(false, Ordering::Relaxed);
    let elapsed = started.elapsed().as_secs_f64();
    let (cpu_after, switches_after, preemptions_after) = rusage();
    shared.stopping.store(true, Ordering::Relaxed);
    runtime.block_on(generator).expect("the generator ends");

    // What was offered in the window gets the coroutine timeout to finish.
    let drain_until = Instant::now() + crate::config::coroutine_timeout(None);
    while shared.outstanding.load(Ordering::Relaxed) > 0 && Instant::now() < drain_until {
        std::thread::sleep(Duration::from_millis(50));
    }
    let unfinished = shared.outstanding.load(Ordering::Relaxed);
    let gc_pauses_us = script_numbers(runtime, &handle, "soak.gc_report")
        .into_iter()
        .map(|nanos| (nanos / 1000).min(u64::from(u32::MAX)) as u32)
        .collect();
    let finished = script_numbers(runtime, &handle, "soak.finished");
    stop_threads.store(true, Ordering::Relaxed);

    let report = Report {
        elapsed,
        cpu_seconds: cpu_after - cpu_before,
        switches: switches_after - switches_before,
        preemptions: preemptions_after - preemptions_before,
        finished,
        threads: thread_count(),
        offered: shared.offered.load(Ordering::Relaxed),
        unfinished,
        stats: std::mem::take(&mut *shared.stats.lock().unwrap()),
        attach_us: probe.join().expect("the attach probe ends"),
        unpinned_us: unpinned_probe.join().expect("the unpinned probe ends"),
        gc_pauses_us,
        samples: sampler.join().expect("the sampler ends"),
        rss_start_mb,
        pool_max: executor.max_size(),
        first_error: shared.first_error.lock().unwrap().take(),
    };
    print_report(&config, &report);
}
