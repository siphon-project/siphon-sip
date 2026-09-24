//! Running a script coroutine: inline where that is provably safe, on the
//! asyncio driver pool otherwise.
//!
//! An asyncio task per SIP message is expensive out of all proportion to the
//! work it wraps. Profiling the 40k proxy row moved **+23.85 % of total CPU into
//! libpython** across 606 symbols when one handler was `async def` rather than
//! `def`: Task/Future bytecode, the object churn behind it, and
//! `_Py_DecRefShared` from objects crossing between the worker and driver
//! threads. Measured end to end, a handler that awaits nothing cost 648 % peak
//! CPU through the driver pool and 317 % through this path, against 332 % for the
//! same logic written `def`.
//!
//! The safety argument is narrow on purpose. `await`, `async for` and `async
//! with` all compile to a `YIELD_VALUE` in the enclosing coroutine, so a code
//! object without one cannot suspend, and its first `send(None)` must run to
//! completion. That is the only case taken here, because a coroutine that *does*
//! suspend cannot be recovered: probing it consumes the future the event loop
//! needed, and handing it on afterwards fails with `RuntimeError: await wasn't
//! used with future`. There is no general fast path, only this one.

use std::cell::RefCell;
use std::sync::OnceLock;

use dashmap::DashMap;
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use tracing::{debug, error};

/// Verdicts for [`run_coroutine_inline`], keyed by code-object address.
///
/// The value holds a strong reference to the code object itself, which is what
/// makes the address safe to key on: a freed code object's address could be
/// reused by a later one and the verdict would then be read for the wrong
/// function. Keeping it alive makes the address unique for as long as the entry
/// exists. Bounded by the number of distinct handlers, and cleared on reload so
/// it cannot grow across them.
static INLINE_VERDICTS: OnceLock<DashMap<usize, (Py<PyAny>, bool)>> = OnceLock::new();

fn inline_verdicts() -> &'static DashMap<usize, (Py<PyAny>, bool)> {
    INLINE_VERDICTS.get_or_init(DashMap::new)
}

/// Drop the cached inline verdicts. Called on reload, where the code objects
/// the verdicts describe are replaced.
pub(crate) fn clear_inline_verdicts() {
    if let Some(cache) = INLINE_VERDICTS.get() {
        cache.clear();
    }
}

/// Whether this coroutine's code can suspend at all.
///
/// `await`, `async for` and `async with` all compile to a `YIELD_VALUE` in the
/// enclosing coroutine, so a code object without one cannot suspend — its first
/// `send(None)` must run to completion. That is what makes the inline path below
/// sound: there is no suspension to mishandle, which is precisely the problem
/// with probing a coroutine in general (a probed `await` on a real Future cannot
/// be handed back to asyncio — `RuntimeError: await wasn't used with future`).
///
/// Conservative in both directions: nested code objects are inspected too and
/// any `YIELD_VALUE` anywhere disqualifies the handler, and anything that cannot
/// be analysed is treated as suspending. A false negative costs the old dispatch
/// path; a false positive would be a correctness bug, so the inline path guards
/// against one at runtime as well.
fn coroutine_cannot_suspend(python: Python<'_>, coroutine: &Bound<'_, PyAny>) -> bool {
    let Ok(code) = coroutine.getattr("cr_code") else {
        return false;
    };
    let key = code.as_ptr() as usize;
    if let Some(entry) = inline_verdicts().get(&key) {
        return entry.1;
    }

    let verdict = analyse_code_for_suspension(python, &code).unwrap_or(false);
    inline_verdicts().insert(key, (code.clone().unbind(), verdict));
    if verdict {
        debug!(
            handler = %code
                .getattr("co_qualname")
                .and_then(|value| value.extract::<String>())
                .unwrap_or_else(|_| "<unknown>".to_string()),
            "async handler cannot suspend; dispatching inline without an asyncio task"
        );
    }
    verdict
}

/// `Ok(true)` when neither `code` nor any code object nested in it yields.
fn analyse_code_for_suspension(python: Python<'_>, code: &Bound<'_, PyAny>) -> PyResult<bool> {
    let dis = python.import("dis")?;
    let instructions = dis.call_method1("get_instructions", (code,))?;
    for instruction in instructions.try_iter()? {
        let name: String = instruction?.getattr("opname")?.extract()?;
        // `YIELD_VALUE` is the only way out of a coroutine frame; `SEND` and
        // `GET_AWAITABLE` always accompany one, so testing for it alone is
        // enough and does not depend on the surrounding opcode sequence.
        if name == "YIELD_VALUE" {
            return Ok(false);
        }
    }
    for constant in code.getattr("co_consts")?.try_iter()? {
        let constant = constant?;
        // Nested function bodies, comprehensions and generator expressions.
        if constant.hasattr("co_code")? && !analyse_code_for_suspension(python, &constant)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Run a coroutine that provably cannot suspend, without an asyncio task.
///
/// Returns `Ok(None)` when the coroutine may suspend, leaving the caller on the
/// driver-pool path.
///
/// Worth doing because an asyncio task per message is expensive out of all
/// proportion to the work: profiling the 40k proxy row moved **+23.85 % of total
/// CPU into libpython** across 606 symbols when the same handler was `async def`
/// rather than `def` — Task/Future bytecode, the object churn behind it, and
/// `_Py_DecRefShared` from objects crossing between the worker and driver
/// threads. None of that is needed for a coroutine that completes on its first
/// step.
pub(crate) fn run_coroutine_inline<'py>(
    python: Python<'py>,
    coroutine: &Bound<'py, PyAny>,
) -> PyResult<Option<Py<PyAny>>> {
    if !coroutine_cannot_suspend(python, coroutine) {
        return Ok(None);
    }

    match coroutine.call_method1("send", (python.None(),)) {
        // A coroutine analysed as non-suspending yielded anyway. Only a bug in
        // the analysis reaches here. The coroutine is mid-flight and cannot be
        // handed to asyncio (that is the `await wasn't used with future` case),
        // so close it and fail this call loudly rather than continue on a
        // half-run handler or silently drop the outcome.
        Ok(_) => {
            let _ = coroutine.call_method0("close");
            let name = coroutine
                .getattr("__qualname__")
                .and_then(|value| value.extract::<String>())
                .unwrap_or_else(|_| "<unknown>".to_string());
            error!(
                handler = %name,
                "handler analysed as non-suspending suspended anyway; failing this call. \
                 This is a bug in the inline dispatch analysis, not in the script."
            );
            Err(PyRuntimeError::new_err(
                "async handler suspended despite static analysis saying it could not",
            ))
        }
        Err(error) if error.is_instance_of::<pyo3::exceptions::PyStopIteration>(python) => {
            // Normal completion: a coroutine returns by raising StopIteration
            // with the return value attached.
            let value = error
                .value(python)
                .getattr("value")
                .map(|value| value.unbind())
                .unwrap_or_else(|_| python.None());
            Ok(Some(value))
        }
        Err(error) => Err(error),
    }
}

thread_local! {
    /// Per-thread asyncio event loop reused across `run_coroutine` calls.
    ///
    /// `pyo3_async_runtimes::tokio::future_into_py(...)` captures the asyncio
    /// loop that is running at the moment a script `await`s the bridged
    /// awaitable, then later wakes the awaiter from a Tokio worker via
    /// `loop.call_soon_threadsafe(...)`.  Driving each handler with a fresh
    /// `asyncio.run(coro)` would close that loop between handler invocations,
    /// racing the Tokio side and surfacing as `RuntimeError: Event loop is
    /// closed` (with the chained `TypeError` because the awaiter's result is
    /// never delivered).  Reusing one long-lived loop per worker thread keeps
    /// `call_soon_threadsafe` targets valid for the lifetime of the thread.
    static PYTHON_LOOP: RefCell<Option<Py<PyAny>>> = const { RefCell::new(None) };
}

/// Acquire — creating it on first use — this thread's persistent fallback
/// asyncio loop (the legacy path used when no global async pool is installed).
/// Reused across calls so `call_soon_threadsafe` targets stay valid for the
/// lifetime of the thread (see [`PYTHON_LOOP`]).
///
/// Pulled out as a named helper so the per-thread caching can be unit-tested
/// directly: the public [`run_coroutine`] entry point short-circuits to the
/// global async pool when one is installed (a process-wide `OnceLock`), which
/// would otherwise route around — and thus never populate — this fallback loop
/// whenever a sibling test installs the pool.
fn fallback_thread_loop(python: Python<'_>) -> PyResult<Py<PyAny>> {
    PYTHON_LOOP.with(|cell| {
        let mut slot = cell.borrow_mut();
        match slot.as_ref() {
            Some(handle) => Ok(handle.clone_ref(python)),
            None => {
                let asyncio = python.import("asyncio")?;
                let new_loop = asyncio.call_method0("new_event_loop")?;
                // Bind this loop to the thread for any code path that still
                // calls the (deprecated) `asyncio.get_event_loop()`.  The
                // running-loop lookup used by `pyo3_async_runtimes` is set
                // automatically by `run_until_complete`.
                asyncio.call_method1("set_event_loop", (&new_loop,))?;
                let unbound = new_loop.unbind();
                let handle = unbound.clone_ref(python);
                *slot = Some(unbound);
                Ok(handle)
            }
        }
    })
}

/// Run a Python coroutine to completion on this thread's persistent asyncio
/// event loop.
///
/// `block_in_place` lets the multi-threaded Tokio runtime steal this worker
/// for the duration of the synchronous `loop.run_until_complete(...)` call so
/// other Tokio tasks (transport I/O, timers, RTPEngine UDP, etc.) keep
/// progressing on other workers.
pub(crate) fn run_coroutine(
    python: Python<'_>,
    coroutine: &Bound<'_, pyo3::PyAny>,
) -> PyResult<()> {
    run_coroutine_value(python, coroutine).map(|_| ())
}

/// Run a Python coroutine to completion on this thread's persistent asyncio
/// event loop and return its resolved value.
///
/// Same scheduling semantics as [`run_coroutine`] — exposed separately so
/// callers that need the coroutine's return value (e.g. host extensions
/// dispatching to script handlers) don't have to re-drive the loop.
///
/// When the global async pool is installed (the production path,
/// initialised from `SiphonServer` bootstrap), the coroutine is dispatched
/// onto one of the pool's long-running asyncio loops via
/// `asyncio.run_coroutine_threadsafe`.  That path keeps the loop running
/// across handler invocations so `asyncio.create_task(...)` actually runs
/// to completion (see `script::async_pool` for details).  When no pool is
/// installed (e.g. in lightweight tests that don't need fire-and-forget
/// task semantics), we fall back to the legacy per-thread
/// `loop.run_until_complete(coro)` path below.
pub(crate) fn run_coroutine_value(
    python: Python<'_>,
    coroutine: &Bound<'_, pyo3::PyAny>,
) -> PyResult<Py<PyAny>> {
    if let Some(value) = run_coroutine_inline(python, coroutine)? {
        return Ok(value);
    }
    if let Some(value) = crate::script::async_pool::run_coroutine_via_pool(python, coroutine)? {
        return Ok(value);
    }
    let loop_handle = fallback_thread_loop(python)?;

    let bound_loop = loop_handle.bind(python);
    let result = tokio::task::block_in_place(|| {
        bound_loop.call_method1("run_until_complete", (coroutine,))
    })?;
    Ok(result.unbind())
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Build a coroutine from `source` (which must define `handler`) and ask
    /// whether the inline path claims it cannot suspend.
    fn inline_verdict_for(source: &str) -> bool {
        Python::initialize();
        Python::attach(|python| {
            let module = PyModule::from_code(
                python,
                &std::ffi::CString::new(source).unwrap(),
                &std::ffi::CString::new("verdict_probe.py").unwrap(),
                &std::ffi::CString::new("verdict_probe").unwrap(),
            )
            .unwrap();
            let coroutine = module.getattr("handler").unwrap().call0().unwrap();
            let verdict = coroutine_cannot_suspend(python, &coroutine);
            // Never leave the probe coroutine un-run; an un-awaited coroutine
            // emits a RuntimeWarning that would pollute unrelated tests.
            let _ = coroutine.call_method0("close");
            verdict
        })
    }

    /// The analysis must say "cannot suspend" only when that is actually true.
    ///
    /// The false-positive direction is the dangerous one: claiming a
    /// suspending handler cannot suspend runs it inline, and a coroutine that
    /// then yields cannot be handed to asyncio at all. So every shape that can
    /// suspend is listed here, including the ones that hide the `await` inside a
    /// branch never taken, a comprehension, or a nested body.
    #[test]
    fn inline_analysis_rejects_everything_that_can_suspend() {
        let suspending = [
        ("plain await", "import asyncio\nasync def handler():\n    await asyncio.sleep(0)\n"),
        // The shape that caused the 1.10.0 regression: the `await` sits on
        // a branch a given message never reaches. The condition is a module
        // global rather than a literal, because CPython constant-folds
        // `if False:` away entirely — such a coroutine really cannot
        // suspend, and the analysis is right to say so.
        (
            "await on a branch this call does not take",
            "import asyncio\nNEVER = False\nasync def handler():\n    if NEVER:\n        await asyncio.sleep(0)\n    return 1\n",
        ),
        (
            "async for",
            "async def gen():\n    yield 1\nasync def handler():\n    async for _ in gen():\n        pass\n",
        ),
        (
            "async with",
            "class Ctx:\n    async def __aenter__(self):\n        return self\n    async def __aexit__(self, *a):\n        return False\nasync def handler():\n    async with Ctx():\n        pass\n",
        ),
        (
            "await inside a comprehension",
            "import asyncio\nasync def one():\n    await asyncio.sleep(0)\n    return 1\nasync def handler():\n    return [await one() for _ in range(1)]\n",
        ),
        (
            "await inside a nested async def",
            "import asyncio\nasync def handler():\n    async def inner():\n        await asyncio.sleep(0)\n    return inner\n",
        ),
    ];
        for (label, source) in suspending {
            assert!(
                !inline_verdict_for(source),
                "{label}: analysed as non-suspending, which would run it inline and \
             leave a yielded coroutine that asyncio cannot accept"
            );
        }
    }

    /// And it must actually fire for the handlers it exists for, or it is a
    /// no-op that only looks like an optimisation.
    #[test]
    fn inline_analysis_accepts_handlers_that_cannot_suspend() {
        let non_suspending = [
        ("bare return", "async def handler():\n    return 42\n"),
        (
            "real work, no await",
            "async def handler():\n    total = 0\n    for index in range(10):\n        total += index\n    return total\n",
        ),
        (
            "calls a sync helper",
            "def helper(value):\n    return value * 2\nasync def handler():\n    return helper(21)\n",
        ),
        (
            "sync comprehension",
            "async def handler():\n    return [index for index in range(4)]\n",
        ),
    ];
        for (label, source) in non_suspending {
            assert!(
                inline_verdict_for(source),
                "{label}: analysed as suspending, so the inline path never fires"
            );
        }
    }

    /// The verdict cache must be keyed per code object, not per call.
    ///
    /// It holds a strong reference to every code object it has judged, which is
    /// what makes keying on the address safe. If it grew per invocation it would
    /// retain a Python object per message, so this dispatches one handler many
    /// times and checks the cache did not grow with them.
    ///
    /// The bound is loose rather than exact because the cache is process-wide and
    /// sibling tests in this binary populate it concurrently. Loose is still
    /// decisive: per-call growth would add 500 entries, and no amount of
    /// parallel-test noise resembles that.
    #[test]
    fn inline_verdict_cache_is_bounded_per_handler() {
        Python::initialize();
        Python::attach(|python| {
            let module = PyModule::from_code(
                python,
                &std::ffi::CString::new("async def handler():\n    return 7\n").unwrap(),
                &std::ffi::CString::new("cache_probe.py").unwrap(),
                &std::ffi::CString::new("cache_probe").unwrap(),
            )
            .unwrap();
            let handler = module.getattr("handler").unwrap();

            let before = inline_verdicts().len();
            const DISPATCHES: usize = 500;
            for _ in 0..DISPATCHES {
                let coroutine = handler.call0().unwrap();
                let value = run_coroutine_inline(python, &coroutine)
                    .expect("inline dispatch failed")
                    .expect("this handler cannot suspend, so it must run inline");
                assert_eq!(value.bind(python).extract::<i64>().unwrap(), 7);
            }
            let growth = inline_verdicts().len().saturating_sub(before);

            assert!(
                growth < DISPATCHES / 10,
                "{DISPATCHES} dispatches of one handler grew the cache by {growth}; \
                 keyed per call rather than per code object, it would retain a code \
                 object per message"
            );
        });
    }

    /// The inline path must return the coroutine's value and propagate its
    /// exceptions, exactly as the driver-pool path does.
    #[test]
    fn inline_path_returns_values_and_propagates_exceptions() {
        Python::initialize();
        Python::attach(|python| {
            let module = PyModule::from_code(
            python,
            &std::ffi::CString::new(
                "async def ok():\n    return {'a': 1}\nasync def boom():\n    raise ValueError('inline boom')\n",
            )
            .unwrap(),
            &std::ffi::CString::new("inline_probe.py").unwrap(),
            &std::ffi::CString::new("inline_probe").unwrap(),
        )
        .unwrap();

            let coroutine = module.getattr("ok").unwrap().call0().unwrap();
            let value = run_coroutine_inline(python, &coroutine)
                .expect("inline dispatch failed")
                .expect("a non-suspending coroutine must take the inline path");
            let extracted: std::collections::HashMap<String, i64> =
                value.bind(python).extract().unwrap();
            assert_eq!(extracted.get("a"), Some(&1));

            let coroutine = module.getattr("boom").unwrap().call0().unwrap();
            let error = run_coroutine_inline(python, &coroutine)
                .expect_err("the handler's exception must propagate, not be swallowed");
            assert!(
                error.to_string().contains("inline boom"),
                "the original exception must survive, got: {error}"
            );
        });
    }

    /// The fallback (no-pool) path must reuse the same per-thread asyncio
    /// loop across calls; tearing the loop down between calls is exactly what
    /// creates the closed-loop race.
    ///
    /// Exercises `fallback_thread_loop` directly rather than going through
    /// `run_coroutine`: the public entry point short-circuits to the global
    /// async pool when a sibling test has installed it (a process-wide
    /// `OnceLock`), which would route around — and thus never populate — the
    /// per-thread fallback loop this test verifies.  Both calls run on the
    /// same thread inside one `Python::attach`, so they share the thread-local.
    #[test]
    fn fallback_loop_is_reused_across_calls() {
        Python::initialize();
        Python::attach(|python| {
            let first = fallback_thread_loop(python).expect("first fallback loop");
            let second = fallback_thread_loop(python).expect("second fallback loop");
            assert_eq!(
                first.bind(python).as_ptr() as usize,
                second.bind(python).as_ptr() as usize,
                "the same per-thread fallback asyncio loop must be reused across calls"
            );
        });
    }
}
