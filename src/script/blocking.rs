//! How a script API reaches async Rust: awaitably where the caller is a
//! coroutine, and by blocking a handler thread where it is not.
//!
//! Prefer [`awaitable`]. A script API that blocks does so on whatever thread
//! called it, and for an `async def` handler that thread is its asyncio
//! driver — one of a small pool, each running `run_forever` for many
//! coroutines at once. Blocking it stops every coroutine on that loop,
//! including ones belonging to calls that never touched the API. Handing back
//! a future instead lets the loop keep turning while the work runs on tokio.
//!
//! [`detach_block_on`] remains for the paths that are genuinely synchronous
//! (siphon's own internals, reached from a Rust worker rather than a
//! coroutine), where there is no loop to yield to.

use std::ffi::CString;
use std::future::Future;
use std::sync::OnceLock;

use pyo3::prelude::*;

/// Hand Python a coroutine that resolves to `value` without doing any work.
///
/// For the early returns of an otherwise-awaitable API — "no Diameter peer is
/// connected", and the like. The caller writes one `await` and it has to work
/// on every path, so a method returning a plain value on its error path and a
/// coroutine on its success path is unusable.
///
/// Deliberately **not** [`awaitable`]: `future_into_py` needs a running asyncio
/// loop at construction time, and these paths are exactly the ones that may not
/// have one — a sync caller, or a unit test with no loop at all. A plain Python
/// `async def` has no such requirement, so it works in every caller context.
pub(crate) fn ready<'py, T>(python: Python<'py>, value: T) -> PyResult<Bound<'py, PyAny>>
where
    T: IntoPyObject<'py>,
{
    static HELPER: OnceLock<Py<PyAny>> = OnceLock::new();
    if let Some(helper) = HELPER.get() {
        return helper.bind(python).call1((value,));
    }

    let source = CString::new("async def _ready(value):\n    return value\n").map_err(|error| {
        pyo3::exceptions::PyRuntimeError::new_err(format!("ready helper source: {error}"))
    })?;
    let file_name = CString::new("_siphon_ready_helper.py").map_err(|error| {
        pyo3::exceptions::PyRuntimeError::new_err(format!("ready helper file: {error}"))
    })?;
    let module_name = CString::new("_siphon_ready_helper").map_err(|error| {
        pyo3::exceptions::PyRuntimeError::new_err(format!("ready helper module: {error}"))
    })?;
    let module = pyo3::types::PyModule::from_code(python, &source, &file_name, &module_name)?;
    let helper = module.getattr("_ready")?;
    let _ = HELPER.set(helper.clone().unbind());
    helper.call1((value,))
}

/// Run `future` on tokio and hand Python a coroutine for its result.
///
/// The awaitable counterpart of [`detach_block_on`]: the calling thread
/// returns immediately, so an asyncio driver keeps turning its other
/// coroutines while this runs.
pub(crate) fn awaitable<'py, F, T>(python: Python<'py>, future: F) -> PyResult<Bound<'py, PyAny>>
where
    F: Future<Output = PyResult<T>> + Send + 'static,
    T: for<'a> IntoPyObject<'a> + Send + 'static,
{
    pyo3_async_runtimes::tokio::future_into_py(python, future).map_err(explain_missing_loop)
}

/// Turn asyncio's `no running event loop` into an error that says what to do.
///
/// Building the coroutine needs a running loop, which a handler only has when
/// it is `async def`. So this is precisely the error a script gets when it
/// calls one of these from a synchronous handler — the single most likely
/// mistake when migrating — and asyncio's own wording names neither the cause
/// nor the fix.
fn explain_missing_loop(error: PyErr) -> PyErr {
    let is_missing_loop = Python::attach(|python| {
        error.is_instance_of::<pyo3::exceptions::PyRuntimeError>(python)
            && error.to_string().contains("no running event loop")
    });
    if !is_missing_loop {
        return error;
    }
    pyo3::exceptions::PyRuntimeError::new_err(
        "this siphon API is awaitable and needs a running event loop: call it \
         with `await` from an `async def` handler. A synchronous handler cannot \
         await, so change `def handler(...)` to `async def handler(...)`.",
    )
}

/// Drive `future` to completion, blocking the current handler thread, with the
/// Python interpreter **released** for the duration.
///
/// # Why this is mandatory (free-threaded CPython 3.14t)
///
/// Script handlers run *attached* to the interpreter. The cyclic GC performs a
/// stop-the-world that pauses every attached thread at a safe point. A handler
/// that parks in a blocking Rust-API call (Diameter to the HSS/PCRF, an HTTP
/// HA1 fetch, …) **while still attached** can never reach that safe point, so
/// the next thread to allocate cyclic garbage — which Python does constantly —
/// blocks behind the GC, stalling every other handler. Depending on which
/// thread can release the block, the stall is either transient (intermittent
/// failures, e.g. a second REGISTER that "doesn't come in") or, when the only
/// thread that could complete the blocked call is itself caught in the
/// stop-the-world, a permanent engine-wide deadlock.
///
/// Releasing the interpreter with [`pyo3::Python::detach`] for the blocking
/// window puts this thread at a GC safe point; [`tokio::task::block_in_place`]
/// keeps the tokio worker pool from starving while we block.
///
/// # Requirements
///
/// Call only from a thread that holds a Python thread state — every siphon
/// worker does (persistent attach on the executor / tokio threads), and
/// `Python::attach` re-attaches cheaply when one is already held. `future` and
/// its output must not hold Python references (`Ungil`); blocking Rust-API
/// futures never do.
pub(crate) fn detach_block_on<F>(future: F) -> F::Output
where
    F: Future + pyo3::marker::Ungil + Send,
    F::Output: pyo3::marker::Ungil + Send,
{
    pyo3::Python::attach(|python| {
        python.detach(move || {
            tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(future))
        })
    })
}

#[cfg(test)]
mod tests {
    /// Every blocking Rust-API call reachable from a script handler must go
    /// through [`detach_block_on`], never a bare `block_in_place` +
    /// `block_on`. The two compile identically and behave identically on an
    /// idle box, which is exactly why the rule cannot be enforced by review:
    /// the bare form only diverges once the cyclic GC happens to stop the
    /// world while a handler is parked in it, and then it is an engine-wide
    /// deadlock rather than a slow call.
    ///
    /// This drifted once already — three of the twenty-one Diameter methods
    /// were written with the bare form while every sibling in the same file
    /// used the wrapper — so guard it at the source level over the whole
    /// namespace directory, including files that do not exist yet. Anything
    /// in `script::api` that genuinely has to stay attached (driving the
    /// interpreter rather than blocking on Rust) does not belong in a
    /// handler-reachable method in the first place.
    #[test]
    fn no_script_api_method_blocks_while_attached_to_the_interpreter() {
        let api_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/script/api");
        let entries = std::fs::read_dir(&api_dir).expect("script api directory is readable");

        let mut offenders = Vec::new();
        for entry in entries {
            let path = entry.expect("directory entry is readable").path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path).expect("source file is readable");
            if source.contains("block_in_place") {
                let name = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("<unknown>")
                    .to_string();
                offenders.push(name);
            }
        }

        assert!(
            offenders.is_empty(),
            "these script::api files call block_in_place directly instead of \
             going through detach_block_on, so a handler parked in one of them \
             can never reach a GC safe point and the next thread to allocate \
             cyclic garbage deadlocks behind the stop-the-world: {offenders:?}"
        );
    }
}
