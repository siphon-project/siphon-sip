#![allow(clippy::disallowed_methods)] // test code may block

//! `ScriptHandle::start_coroutine` as an extension crate uses it: only the
//! public API, a coroutine the extension builds itself (as middleware around a
//! handler would), and siphon awaitables made with `blocking::awaitable`.

use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use pyo3::exceptions::{PyTimeoutError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyModule;
use siphon::script::async_pool::{pending_coroutines, AsyncPool};
use siphon::script::engine::ScriptEngine;
use siphon::script::handle::ScriptHandle;
use siphon::script::py_executor::{ExecutorConfig, PyExecutor};

/// Longer than every coroutine here that is meant to finish, short enough that
/// the timeout tests do not dominate the run.
const COROUTINE_TIMEOUT: Duration = Duration::from_secs(1);

#[pyfunction]
fn ready(python: Python<'_>, value: i64) -> PyResult<Bound<'_, PyAny>> {
    siphon::script::blocking::awaitable(python, async move { Ok(value) })
}

#[pyfunction]
fn sleep_ms(python: Python<'_>, millis: u64, value: i64) -> PyResult<Bound<'_, PyAny>> {
    siphon::script::blocking::awaitable(python, async move {
        tokio::time::sleep(Duration::from_millis(millis)).await;
        Ok(value)
    })
}

#[pyfunction]
fn never(python: Python<'_>) -> PyResult<Bound<'_, PyAny>> {
    siphon::script::blocking::awaitable(python, async move {
        std::future::pending::<()>().await;
        Ok(0_i64)
    })
}

/// The OS thread name: Python's `threading` only knows threads it started.
#[pyfunction]
fn thread_name() -> String {
    std::thread::current()
        .name()
        .unwrap_or("<unnamed>")
        .to_string()
}

const COROUTINES: &std::ffi::CStr = c"
import asyncio
import probe

cancelled = []

def on_driver():
    return probe.thread_name().startswith('siphon-asyncio')

async def siphon_only(x):
    before = on_driver()
    value = await probe.ready(x)
    value += await probe.sleep_ms(2, 1)
    return f'{value}|{before}|{on_driver()}'

async def uses_asyncio(x):
    first = await probe.ready(x)
    await asyncio.sleep(0.01)
    return f'{first}|{on_driver()}'

async def raises(x):
    await probe.ready(x)
    raise KeyError('after the await')

async def wedged(x):
    try:
        await probe.never()
    finally:
        cancelled.append(x)

async def wedged_in_asyncio(x):
    try:
        await asyncio.sleep(3600)
    finally:
        cancelled.append(x)
";

fn runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .expect("a runtime")
    })
}

/// The pools the way a server installs them, once, and a handle onto an
/// engine; the tests share one process and run one at a time.
struct Rig {
    handle: ScriptHandle,
    _engine: ScriptEngine,
    _serial: std::sync::MutexGuard<'static, ()>,
}

fn rig() -> Rig {
    static SERIAL: Mutex<()> = Mutex::new(());
    let serial = SERIAL.lock().unwrap_or_else(|poison| poison.into_inner());
    Python::initialize();
    Python::attach(|python| {
        let module = PyModule::new(python, "probe").expect("module");
        for function in [
            pyo3::wrap_pyfunction!(ready, &module),
            pyo3::wrap_pyfunction!(sleep_ms, &module),
            pyo3::wrap_pyfunction!(never, &module),
            pyo3::wrap_pyfunction!(thread_name, &module),
        ] {
            module
                .add_function(function.expect("function"))
                .expect("add");
        }
        let modules = python.import("sys").and_then(|sys| sys.getattr("modules"));
        let modules = modules.expect("sys.modules");
        if !modules.contains("probe").expect("lookup") {
            modules.set_item("probe", &module).expect("register");
            PyModule::from_code(
                python,
                COROUTINES,
                c"start_coroutine_probe.py",
                c"start_coroutine_probe",
            )
            .expect("the probe compiles");
        }
    });
    let _guard = runtime().enter();
    PyExecutor::install(
        runtime().handle().clone(),
        ExecutorConfig {
            core_threads: 3,
            max_threads: 3,
            queue_capacity: 1024,
            stall_abort: None,
        },
    );
    AsyncPool::install(2, runtime().handle().clone(), COROUTINE_TIMEOUT);

    let mut file = tempfile::NamedTempFile::new().expect("script file");
    file.write_all(b"# no handlers: the extension builds its own coroutines\n")
        .expect("script written");
    let engine = ScriptEngine::new(&siphon::config::ScriptConfig {
        path: file.path().to_str().expect("utf-8 path").to_owned(),
        reload: siphon::config::ReloadMode::Sighup,
        async_pool_size: None,
        sync_pool_size: None,
        sync_pool_max: None,
        handler_stall_abort_secs: 30,
        process_stall_abort_secs: 30,
        handler_timeout_secs: None,
        executor_queue_capacity: 1024,
        include_paths: Vec::new(),
    })
    .expect("engine");
    Rig {
        handle: ScriptHandle::for_engine(&engine, runtime().handle().clone()),
        _engine: engine,
        _serial: serial,
    }
}

/// Start `function(argument)` from the probe module as the extension would:
/// the coroutine is built in the job, and the outcome is read there.
async fn run(
    handle: &ScriptHandle,
    function: &'static str,
    argument: i64,
) -> Result<String, String> {
    handle
        .start_coroutine(
            move |python| {
                let module = PyModule::import(python, "start_coroutine_probe")?;
                module.getattr(function)?.call1((argument,))
            },
            |python, outcome| {
                outcome
                    .and_then(|value| value.str()?.extract::<String>())
                    .map_err(|error| {
                        if error.is_instance_of::<PyTimeoutError>(python) {
                            "TimeoutError".to_string()
                        } else {
                            error.to_string()
                        }
                    })
            },
        )
        .await
        .expect("the coroutine was started")
}

fn within<F: std::future::Future>(future: F) -> F::Output {
    runtime().block_on(async {
        tokio::time::timeout(Duration::from_secs(60), future)
            .await
            .expect("finished within the test timeout")
    })
}

#[test]
fn a_coroutine_awaiting_only_siphon_awaitables_runs_on_the_executor() {
    let rig = rig();
    let answer = within(run(&rig.handle, "siphon_only", 5));
    // 5 + 1, and never on an asyncio driver before or after the awaits.
    assert_eq!(answer, Ok("6|False|False".to_string()));
}

#[test]
fn a_coroutine_that_uses_asyncio_falls_back_and_completes() {
    let rig = rig();
    let answer = within(run(&rig.handle, "uses_asyncio", 7));
    assert_eq!(answer, Ok("7|True".to_string()));
}

#[test]
fn a_raising_coroutine_surfaces_its_exception() {
    let rig = rig();
    let answer = within(run(&rig.handle, "raises", 1));
    let error = answer.expect_err("raised");
    assert!(error.contains("after the await"), "{error}");
    // A coroutine the extension fails to build reaches `finish` too.
    let built_wrong = within(rig.handle.start_coroutine(
        |_python| Err(PyValueError::new_err("no such handler")),
        |_python, outcome| outcome.map(|_| ()).map_err(|error| error.to_string()),
    ))
    .expect("dispatched");
    assert!(built_wrong.expect_err("raised").contains("no such handler"));
}

fn cancelled_count() -> usize {
    Python::attach(|python| {
        PyModule::import(python, "start_coroutine_probe")
            .and_then(|module| module.getattr("cancelled")?.len())
            .unwrap_or(0)
    })
}

/// N that finish and N that time out, on the direct path and on a driver: the
/// timed-out ones are cancelled (their `finally` ran) and nothing stays
/// pending.
#[test]
fn a_timed_out_coroutine_is_cancelled_and_leaves_nothing_pending() {
    let rig = rig();
    const COUNT: usize = 8;
    let baseline = pending_coroutines();
    let cancelled_before = cancelled_count();
    let outcomes = within(async {
        let mut joins = Vec::new();
        for index in 0..COUNT {
            let handle = rig.handle.clone();
            joins.push(tokio::spawn(async move {
                let finished = run(&handle, "siphon_only", index as i64).await;
                let wedged = run(&handle, "wedged", index as i64).await;
                let wedged_driver = run(&handle, "wedged_in_asyncio", index as i64).await;
                (finished, wedged, wedged_driver)
            }));
        }
        let mut outcomes = Vec::new();
        for join in joins {
            outcomes.push(join.await.expect("joined"));
        }
        outcomes
    });
    for (index, (finished, wedged, wedged_driver)) in outcomes.into_iter().enumerate() {
        assert_eq!(finished, Ok(format!("{}|False|False", index + 1)));
        assert_eq!(wedged, Err("TimeoutError".to_string()));
        assert_eq!(wedged_driver, Err("TimeoutError".to_string()));
    }
    assert_eq!(
        cancelled_count() - cancelled_before,
        COUNT * 2,
        "every timed-out coroutine was cancelled"
    );
    assert_eq!(
        pending_coroutines(),
        baseline,
        "the pending store is back where it started"
    );
}

/// A stop-the-world collection from another thread while coroutines are in
/// flight does not hang them.
#[test]
fn a_forced_collection_during_coroutines_does_not_hang() {
    let rig = rig();
    let stop = Arc::new(AtomicBool::new(false));
    let collector = {
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                Python::attach(|python| {
                    let _ = python
                        .import("gc")
                        .and_then(|gc| gc.call_method0("collect"));
                });
                std::thread::sleep(Duration::from_millis(1));
            }
        })
    };
    let answers = within(async {
        let mut joins = Vec::new();
        for index in 0..64_i64 {
            let handle = rig.handle.clone();
            joins.push(tokio::spawn(async move {
                let function = if index % 4 == 0 {
                    "uses_asyncio"
                } else {
                    "siphon_only"
                };
                (index, run(&handle, function, index).await)
            }));
        }
        let mut answers = Vec::new();
        for join in joins {
            answers.push(join.await.expect("joined"));
        }
        answers
    });
    stop.store(true, Ordering::Relaxed);
    collector.join().expect("the collector stops");
    for (index, answer) in answers {
        let expected = if index % 4 == 0 {
            format!("{index}|True")
        } else {
            format!("{}|False|False", index + 1)
        };
        assert_eq!(answer, Ok(expected));
    }
}
