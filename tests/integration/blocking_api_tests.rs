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
