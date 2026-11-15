#![allow(clippy::disallowed_methods)] // test, bench and example code may block

//! What one `async def` handler call through the script handle costs, by how
//! many siphon awaitables it awaits (0, 1, 4), with `script.direct_dispatch`
//! off (an asyncio task per call, an asyncio future per await) and on (stepped
//! by the driver's runner).
//!
//! Each iteration runs a batch of calls at once, so the figure is the cost of
//! the dispatch machinery under some concurrency and not the latency of a
//! thread handoff on an idle process.

use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use pyo3::prelude::*;
use pyo3::types::{PyModule, PyModuleMethods};
use siphon::config::{ReloadMode, ScriptConfig};
use siphon::script::async_pool::AsyncPool;
use siphon::script::engine::ScriptEngine;
use siphon::script::py_executor::{ExecutorConfig, PyExecutor};
use siphon::script::{HandlerHandle, ScriptHandle};

/// Calls in flight per iteration.
const BATCH: usize = 64;

/// An awaitable that finishes on its first poll after the handler has had the
/// chance to suspend on it.
#[pyfunction]
fn step(py: Python<'_>, value: i64) -> PyResult<Bound<'_, PyAny>> {
    siphon::script::blocking::awaitable(py, async move {
        tokio::task::yield_now().await;
        Ok(value)
    })
}

const SCRIPT: &str = r#"
import asyncio
import _siphon_registry as _r
import _dispatch_await_bench as probe
from siphon import tasks

async def awaits_0(value):
    return value

async def awaits_1(value):
    return await probe.step(value)

async def awaits_4(value):
    total = 0
    for _ in range(4):
        total += await probe.step(value)
    return total

async def lookup(value):
    return await probe.step(value)

# The shape of a handler that fetches two things at once: a coroutine of the
# script that awaits one siphon API, beside one siphon awaitable.
async def gather_tasks(value):
    left, right = await tasks.gather(lookup(value), probe.step(value))
    return left + right

async def gather_asyncio(value):
    left, right = await asyncio.gather(lookup(value), probe.step(value))
    return left + right

for awaits, handler in ((0, awaits_0), (1, awaits_1), (4, awaits_4)):
    _r.register(f"bench.awaits_{awaits}", None, handler, True, None)
_r.register("bench.gather_tasks", None, gather_tasks, True, None)
_r.register("bench.gather_asyncio", None, gather_asyncio, True, None)
"#;

async fn call(handle: &ScriptHandle, handler: &HandlerHandle, value: i64) -> i64 {
    handle
        .call_handler_with(
            handler,
            move |python| Ok(vec![value.into_pyobject(python)?.into_any().unbind()]),
            |_python, outcome| {
                outcome
                    .and_then(|value| value.extract::<i64>())
                    .unwrap_or(-1)
            },
        )
        .await
        .unwrap_or(-2)
}

fn bench_dispatch_await(criterion: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("a runtime");
    Python::initialize();
    Python::attach(|python| {
        let module = PyModule::new(python, "_dispatch_await_bench").expect("a module");
        module
            .add_function(pyo3::wrap_pyfunction!(step, &module).expect("a function"))
            .expect("added");
        python
            .import("sys")
            .and_then(|sys| sys.getattr("modules"))
            .and_then(|modules| modules.set_item("_dispatch_await_bench", &module))
            .expect("registered");
    });
    PyExecutor::install(
        runtime.handle().clone(),
        ExecutorConfig {
            core_threads: 4,
            max_threads: 4,
            queue_capacity: 4096,
            stall_abort: None,
        },
    );
    let pool = AsyncPool::install(2, runtime.handle().clone(), Duration::from_secs(30));

    let mut file = tempfile::NamedTempFile::new().expect("a script file");
    file.write_all(SCRIPT.as_bytes()).expect("written");
    file.flush().expect("flushed");
    let engine = ScriptEngine::new(&ScriptConfig {
        path: file.path().to_string_lossy().into_owned(),
        reload: ReloadMode::Sighup,
        ..Default::default()
    })
    .expect("the script loads");
    let handle = Arc::new(ScriptHandle::for_engine(&engine, runtime.handle().clone()));

    let mut group = criterion.benchmark_group("dispatch_await");
    group.throughput(Throughput::Elements(BATCH as u64));
    group.sample_size(30);
    // The handler, what it is called in the report, and how many times its
    // argument it returns.
    let cases: [(&str, String, usize); 5] = [
        ("awaits_0", "0".to_string(), 1),
        ("awaits_1", "1".to_string(), 1),
        ("awaits_4", "4".to_string(), 4),
        ("gather_tasks", "gather_tasks".to_string(), 2),
        ("gather_asyncio", "gather_asyncio".to_string(), 2),
    ];
    for (name, label, awaits) in cases {
        let handler = handle
            .handlers_for(&format!("bench.{name}"))
            .into_iter()
            .next()
            .expect("registered");
        for on in [false, true] {
            let applied = siphon::script::runner::configure(on, &pool);
            assert_eq!(applied, on, "the switch took");
            let mode = if on { "on" } else { "off" };
            group.bench_with_input(
                BenchmarkId::new(mode, &label),
                &awaits,
                |bencher, &awaits| {
                    bencher.iter(|| {
                        let total: i64 = runtime.block_on(async {
                            let calls: Vec<_> = (0..BATCH)
                                .map(|index| {
                                    let handle = Arc::clone(&handle);
                                    let handler = handler.clone();
                                    tokio::spawn(async move {
                                        call(&handle, &handler, index as i64).await
                                    })
                                })
                                .collect();
                            let mut total = 0;
                            for call in calls {
                                total += call.await.unwrap_or(-3);
                            }
                            total
                        });
                        let each: i64 = (0..BATCH as i64).sum();
                        assert_eq!(total, each * awaits as i64);
                    });
                },
            );
        }
    }
    group.finish();
    siphon::script::runner::configure(false, &pool);
}

criterion_group!(benches, bench_dispatch_await);
criterion_main!(benches);
