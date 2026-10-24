//! The released-wait helpers are public, for extension crates.
//!
//! An extension that blocks on Rust from a thread that may be attached to the
//! interpreter (its own pymethods, a handler callback) needs the same helpers
//! siphon uses, and names them in its own `clippy.toml` disallowed-methods
//! reasons. These pin the paths and what each does.

use siphon::script::blocking::{block_on_released, blocking_released, detach_block_on, released};

fn gil_state_check() -> i32 {
    // SAFETY: reads only this thread's own thread state.
    unsafe { pyo3::ffi::PyGILState_Check() }
}

#[test]
fn released_detaches_an_attached_thread_and_passes_a_detached_one_through() {
    pyo3::Python::initialize();
    assert_eq!(released(gil_state_check), 0);
    let inside = pyo3::Python::attach(|_| released(gil_state_check));
    assert_eq!(inside, 0, "the work ran with the interpreter released");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_blocking_helpers_wait_with_the_interpreter_released() {
    pyo3::Python::initialize();
    let value = pyo3::Python::attach(|_| block_on_released(async { 41 + 1 }));
    assert_eq!(value, 42);
    let state = pyo3::Python::attach(|_| blocking_released(gil_state_check));
    assert_eq!(state, 0);
    let detached = detach_block_on(async { gil_state_check() });
    assert_eq!(detached, 0);
}

#[test]
fn awaitable_explains_a_missing_event_loop() {
    pyo3::Python::initialize();
    let error = pyo3::Python::attach(|python| {
        siphon::script::blocking::awaitable(python, async { Ok(1_i64) })
            .err()
            .map(|error| error.to_string())
    });
    let error = error.expect("no running loop on a plain thread");
    assert!(error.contains("async def"), "{error}");
}

#[test]
fn deferred_builds_its_value_on_conversion() {
    use pyo3::prelude::*;
    pyo3::Python::initialize();
    let value = pyo3::Python::attach(|python| {
        siphon::script::Deferred::build(|_| Ok(5_i64))
            .into_pyobject(python)
            .and_then(|bound| bound.extract::<i64>())
    });
    assert_eq!(value.ok(), Some(5));
}

#[test]
fn run_coroutine_inline_runs_only_what_cannot_suspend() {
    use pyo3::prelude::*;
    pyo3::Python::initialize();
    pyo3::Python::attach(|python| {
        let module = pyo3::types::PyModule::from_code(
            python,
            c"import asyncio\nasync def quick():\n    return 7\nasync def slow():\n    await asyncio.sleep(0)\n    return 8\n",
            c"inline_api_test.py",
            c"inline_api_test",
        )
        .expect("module");
        let quick = module
            .getattr("quick")
            .and_then(|f| f.call0())
            .expect("coroutine");
        let ran = siphon::script::inline_dispatch::run_coroutine_inline(python, &quick)
            .expect("inline")
            .expect("cannot suspend, so it ran");
        assert_eq!(ran.extract::<i64>(python).ok(), Some(7));

        let slow = module
            .getattr("slow")
            .and_then(|f| f.call0())
            .expect("coroutine");
        let left =
            siphon::script::inline_dispatch::run_coroutine_inline(python, &slow).expect("inline");
        assert!(left.is_none(), "a suspending coroutine is left alone");
        let _ = slow.call_method0("close");
    });
}
