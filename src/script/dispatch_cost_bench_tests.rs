//! What one script dispatch costs, per handler shape, through
//! [`ScriptHandle::call_handler`] as an extension calls it.
//!
//! Not a criterion bench: the figure that matters is CPU per request across
//! every thread a dispatch touches (tokio workers, executor workers, asyncio
//! drivers, completion threads), which a single-threaded timing loop cannot
//! see. It runs the real pools and reads `getrusage` around each case.
//!
//! ```text
//! PYO3_PYTHON=python3.14t cargo test --release --lib -- --ignored --nocapture \
//!     --test-threads=1 script::dispatch_cost_bench_tests::dispatch_cost
//! ```
//!
//! Knobs, all optional environment variables:
//!
//! | Variable | Default | Meaning |
//! |---|---|---|
//! | `BENCH_CONC` | `1,16,256` | Closed-loop callers per case |
//! | `BENCH_RATE` | `0` | Open loop at this many requests/s in total when above zero |
//! | `BENCH_SECONDS` | `3` | Seconds per case |
//! | `BENCH_ONLY` | all | Comma-separated handler names to run |
//! | `BENCH_WORKERS` | `8` | Tokio workers |
//! | `BENCH_DRIVERS` | `8` | Asyncio drivers |
//! | `BENCH_EXECUTORS` | `16` | Executor core threads |
//!
//! Columns: throughput, latency percentiles in microseconds, CPU microseconds
//! per request summed over all threads, voluntary context switches per
//! request, and garbage collections during the case.

use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use pyo3::prelude::*;
use pyo3::types::{PyModule, PyModuleMethods};

use crate::script::engine::ScriptEngine;
use crate::script::handle::ScriptHandle;

/// An awaitable that is ready as soon as tokio polls it.
#[pyfunction]
fn ready(py: Python<'_>) -> PyResult<Bound<'_, PyAny>> {
    crate::script::awaitable(py, async move { Ok(7i64) })
}

/// An awaitable that waits `micros` on tokio's timer.
#[pyfunction]
fn sleep_us(py: Python<'_>, micros: u64) -> PyResult<Bound<'_, PyAny>> {
    crate::script::awaitable(py, async move {
        tokio::time::sleep(Duration::from_micros(micros)).await;
        Ok(7i64)
    })
}

const SCRIPT: &str = r#"
import asyncio
import gc
import _siphon_registry as _r
import _dispatch_bench
from siphon import tasks

def sync_h(x):
    return x

async def async_plain(x):
    return x

async def async_await(x):
    return await _dispatch_bench.ready()

async def async_await10(x):
    for _ in range(10):
        await _dispatch_bench.ready()
    return x

async def async_sleep(x):
    return await _dispatch_bench.sleep_us(1000)

async def async_yield(x):
    await asyncio.sleep(0)
    return x

async def async_mixed(x):
    value = await _dispatch_bench.ready()
    await asyncio.sleep(0)
    return value

async def background_child():
    return await _dispatch_bench.ready()

async def spawn_wait(x):
    handle = tasks.spawn(background_child())
    first = await tasks.wait_first([handle], timeout=1.0)
    return first.result()

async def asyncio_spawn_wait(x):
    task = asyncio.ensure_future(background_child())
    await asyncio.wait({task}, timeout=1.0, return_when=asyncio.FIRST_COMPLETED)
    return task.result()

def gc_collections(*_):
    return sum(generation['collections'] for generation in gc.get_stats())

for name, fn, is_async in [
    ("sync_h", sync_h, False),
    ("async_plain", async_plain, True),
    ("async_await", async_await, True),
    ("async_await10", async_await10, True),
    ("async_sleep", async_sleep, True),
    ("async_yield", async_yield, True),
    ("async_mixed", async_mixed, True),
    ("spawn_wait", spawn_wait, True),
    ("asyncio_spawn_wait", asyncio_spawn_wait, True),
    ("gc_collections", gc_collections, False),
]:
    _r.register("bench." + name, None, fn, is_async, None)
"#;

const CASES: &[&str] = &[
    "sync_h",
    "async_plain",
    "async_await",
    "async_await10",
    "async_sleep",
    "async_yield",
    "async_mixed",
    "spawn_wait",
    "asyncio_spawn_wait",
];

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

/// Process CPU seconds (user + system) and voluntary context switches.
fn rusage() -> (f64, i64) {
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
    )
}

#[test]
#[ignore = "a benchmark: run it by name, in a release build"]
fn dispatch_cost() {
    let workers = env_usize("BENCH_WORKERS", 8);
    let drivers = env_usize("BENCH_DRIVERS", 8);
    let executors = env_usize("BENCH_EXECUTORS", 16);
    let seconds = env_usize("BENCH_SECONDS", 3);
    let rate = env_usize("BENCH_RATE", 0);
    let only = std::env::var("BENCH_ONLY").ok();
    let concurrencies: Vec<usize> = std::env::var("BENCH_CONC")
        .unwrap_or_else(|_| "1,16,256".into())
        .split(',')
        .filter_map(|value| value.parse().ok())
        .collect();

    Python::initialize();
    let runtime = crate::server::build_runtime(|builder| {
        builder.worker_threads(workers);
    })
    .expect("runtime");
    crate::script::py_executor::PyExecutor::install(
        runtime.handle().clone(),
        crate::script::py_executor::ExecutorConfig {
            core_threads: executors,
            max_threads: executors.max(32),
            queue_capacity: 4096,
            stall_abort: None,
        },
    );
    crate::script::async_pool::AsyncPool::install(
        drivers,
        runtime.handle().clone(),
        Duration::from_secs(10),
    );
    Python::attach(|python| {
        let module = PyModule::new(python, "_dispatch_bench").unwrap();
        module
            .add_function(pyo3::wrap_pyfunction!(ready, &module).unwrap())
            .unwrap();
        module
            .add_function(pyo3::wrap_pyfunction!(sleep_us, &module).unwrap())
            .unwrap();
        python
            .import("sys")
            .unwrap()
            .getattr("modules")
            .unwrap()
            .set_item("_dispatch_bench", &module)
            .unwrap();
    });

    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(SCRIPT.as_bytes()).unwrap();
    file.flush().unwrap();
    let engine = Arc::new(
        ScriptEngine::new(&crate::config::ScriptConfig {
            path: file.path().to_str().unwrap().to_owned(),
            reload: crate::config::ReloadMode::Sighup,
            async_pool_size: None,
            sync_pool_size: None,
            sync_pool_max: None,
            handler_stall_abort_secs: 30,
            process_stall_abort_secs: 30,
            handler_timeout_secs: None,
            executor_queue_capacity: 4096,
            include_paths: Vec::new(),
        })
        .unwrap(),
    );
    let handle = ScriptHandle::new(engine.state_arc(), runtime.handle().clone());
    let handler_named = |name: &str| {
        Arc::new(
            handle
                .handlers_for(&format!("bench.{name}"))
                .into_iter()
                .next()
                .expect("registered"),
        )
    };
    let gc_counter = handler_named("gc_collections");
    let collections = || -> i64 {
        let value = runtime
            .block_on(handle.call_handler(&gc_counter, Vec::new()))
            .expect("gc count");
        Python::attach(|python| value.bind(python).extract().unwrap())
    };

    println!(
        "workers={workers} drivers={drivers} executors={executors} seconds={seconds} rate={rate}"
    );
    println!(
        "{:<14} {:>5} {:>9} {:>8} {:>8} {:>8} {:>10} {:>9} {:>4}",
        "handler", "conc", "req/s", "p50_us", "p99_us", "max_us", "cpu_us/req", "vcsw/req", "gc"
    );
    for name in CASES {
        if let Some(only) = &only {
            if !only.split(',').any(|wanted| wanted == *name) {
                continue;
            }
        }
        let handler = handler_named(name);
        for &concurrency in &concurrencies {
            let gc_before = collections();
            let stop = Arc::new(AtomicBool::new(false));
            let (cpu_before, switches_before) = rusage();
            let started = Instant::now();
            let mut tasks = Vec::new();
            for index in 0..concurrency {
                let handle = handle.clone();
                let handler = Arc::clone(&handler);
                let stop = Arc::clone(&stop);
                let period =
                    (rate > 0).then(|| Duration::from_secs_f64(concurrency as f64 / rate as f64));
                tasks.push(runtime.spawn(async move {
                    let mut latencies: Vec<u32> = Vec::with_capacity(1 << 16);
                    let mut ticker = None;
                    if let Some(period) = period {
                        // Spread the callers over one period.
                        tokio::time::sleep(period.mul_f64(index as f64 / concurrency as f64)).await;
                        let mut interval = tokio::time::interval(period);
                        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Burst);
                        ticker = Some(interval);
                    }
                    while !stop.load(Ordering::Relaxed) {
                        if let Some(ticker) = ticker.as_mut() {
                            ticker.tick().await;
                        }
                        let begun = Instant::now();
                        let argument = Python::attach(|python| {
                            7i64.into_pyobject(python).unwrap().into_any().unbind()
                        });
                        let result = handle
                            .call_handler(&handler, vec![argument])
                            .await
                            .expect("dispatch");
                        Python::attach(|python| drop(result.into_bound(python)));
                        latencies.push(begun.elapsed().as_nanos().min(u32::MAX as u128) as u32);
                    }
                    latencies
                }));
            }
            std::thread::sleep(Duration::from_secs(seconds as u64));
            stop.store(true, Ordering::Relaxed);
            let mut all: Vec<u32> = Vec::new();
            for task in tasks {
                all.extend(runtime.block_on(task).unwrap());
            }
            let elapsed = started.elapsed().as_secs_f64();
            let (cpu_after, switches_after) = rusage();
            let gc_runs = collections() - gc_before;
            all.sort_unstable();
            let count = all.len().max(1);
            let at = |quantile: f64| {
                all.get(((count as f64 * quantile) as usize).min(count - 1))
                    .copied()
                    .unwrap_or(0)
                    / 1000
            };
            println!(
                "{:<14} {:>5} {:>9.0} {:>8} {:>8} {:>8} {:>10.1} {:>9.1} {:>4}",
                name,
                concurrency,
                count as f64 / elapsed,
                at(0.50),
                at(0.99),
                at(1.0),
                (cpu_after - cpu_before) * 1e6 / count as f64,
                (switches_after - switches_before) as f64 / count as f64,
                gc_runs,
            );
        }
    }
}
