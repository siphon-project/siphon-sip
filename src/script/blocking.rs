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
///
/// Public for extension crates. `future` runs on a tokio worker, so it must
/// not attach to the interpreter: return plain Rust (or a `#[pyclass]`), or a
/// [`crate::script::Deferred`] that builds the Python value. The conversion
/// runs in the completion step, off the workers, on one of the fixed threads
/// in [`super::completions`] (never on tokio's elastic blocking pool, whose
/// threads come and go). Called from a synchronous
/// handler (no running event loop) it fails with an error that says to make
/// the handler `async def`.
pub fn awaitable<'py, F, T>(python: Python<'py>, future: F) -> PyResult<Bound<'py, PyAny>>
where
    F: Future<Output = PyResult<T>> + Send + 'static,
    T: for<'a> IntoPyObject<'a> + Send + 'static,
{
    pyo3_async_runtimes::generic::future_into_py::<super::completions::AwaitableRuntime, _, _>(
        python, future,
    )
    .map_err(explain_missing_loop)
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
#[allow(clippy::disallowed_methods)] // the wait runs inside its own python.detach
pub fn detach_block_on<F>(future: F) -> F::Output
where
    F: Future + pyo3::marker::Ungil + Send,
    F::Output: pyo3::marker::Ungil + Send,
{
    let _wait = super::blocking_metrics::track_wait();
    pyo3::Python::attach(|python| {
        python.detach(move || {
            tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(future))
        })
    })
}

/// Block this thread on `work` — Rust work that waits on I/O, a lock, or a
/// tokio future — **released from the interpreter if this thread is attached
/// to it**, and handed off from tokio's scheduler if it is a tokio worker.
///
/// For the dispatcher's synchronous paths (relay, reply, media, B2BUA), which
/// run detached on the first pass but are reached attached from more than one
/// caller. Attached and blocked is the stop-the-world deadlock
/// [`detach_block_on`] describes; unlike it, this does not attach first, so a
/// detached caller pays nothing on the hot path.
#[allow(clippy::disallowed_methods)] // the released helper itself
pub fn blocking_released<T>(work: impl FnOnce() -> T) -> T {
    // `block_on_released` comes through here too, so each wait counts once.
    let _wait = super::blocking_metrics::track_wait();
    released(|| tokio::task::block_in_place(work))
}

/// Run `work` released from the interpreter if this thread is attached to it,
/// as it is; for a wait that already happens off tokio's workers.
pub fn released<T>(work: impl FnOnce() -> T) -> T {
    // Before the interpreter is initialised `PyGILState_Check` reports 1 (its
    // check is not enabled yet), and releasing a thread state that does not
    // exist crashes in `PyEval_SaveThread`. No thread can be attached then.
    // SAFETY: `Py_IsInitialized` reads a runtime flag and may be called at
    // any time.
    if unsafe { pyo3::ffi::Py_IsInitialized() } == 0 {
        return work();
    }
    // SAFETY: `PyGILState_Check` only reads this thread's own thread state.
    let attached = unsafe { pyo3::ffi::PyGILState_Check() } == 1;
    if !attached {
        return work();
    }
    // SAFETY: the check just established that this thread is attached.
    let python = unsafe { Python::assume_attached() };
    // `detach` requires `Ungil` (`Send` on stable) of the closure and its
    // output, for code that might move them to another thread. Both stay on
    // this one: the closure runs here and its value comes back here.
    let work = AssertUngil(work);
    // `into_inner` takes the whole wrapper: destructuring it would have the
    // closure capture only the inner field, which is not `Send`.
    python
        .detach(move || AssertUngil(work.into_inner()()))
        .into_inner()
}

/// [`blocking_released`] for a tokio future: `Handle::current().block_on`.
#[allow(clippy::disallowed_methods)] // the released helper itself
pub fn block_on_released<F: Future>(future: F) -> F::Output {
    blocking_released(|| tokio::runtime::Handle::current().block_on(future))
}

/// Carries a closure, and its output, through [`Python::detach`] on the thread
/// that made them.
struct AssertUngil<T>(T);

impl<T> AssertUngil<T> {
    fn into_inner(self) -> T {
        self.0
    }
}

// SAFETY: only `released` builds one, and `Python::detach` runs the
// closure on the calling thread and returns its output to it, so neither is
// ever sent to another thread. The closures are Rust-side blocking work and
// hold no `Python<'_>` token or `Bound` across the release.
unsafe impl<T> Send for AssertUngil<T> {}

#[cfg(test)]
mod tests {
    /// `released` on a process whose interpreter was never initialised runs
    /// the work and returns: there is no thread state to release. It used to
    /// take `PyGILState_Check`'s 1 (reported before initialisation) as
    /// "attached" and crash in `PyEval_SaveThread`. Checked in a child process,
    /// because this test binary's interpreter is up by the time it runs.
    #[test]
    fn released_before_the_interpreter_is_up_runs_the_work() {
        let output = std::process::Command::new(std::env::current_exe().expect("the test binary"))
            .args([
                "--exact",
                "script::blocking::tests::released_child_without_an_interpreter",
                "--ignored",
                "--test-threads=1",
            ])
            .env("SIPHON_RELEASED_CHILD", "1")
            .output()
            .expect("the child runs");
        assert!(
            output.status.success(),
            "the child crashed or failed: {:?}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
    }

    /// The child half of the test above; does nothing unless run as it.
    #[test]
    #[ignore = "run by released_before_the_interpreter_is_up_runs_the_work"]
    fn released_child_without_an_interpreter() {
        if std::env::var_os("SIPHON_RELEASED_CHILD").is_none() {
            return;
        }
        // SAFETY: reads a runtime flag.
        assert_eq!(unsafe { pyo3::ffi::Py_IsInitialized() }, 0);
        assert_eq!(super::released(|| 7), 7);
        assert_eq!(super::blocking_released(|| 8), 8);
    }

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

    /// The dispatcher and the transport are synchronous Rust reached from more
    /// than one caller, some of them attached to the interpreter (an async
    /// request handler's continuation was, until it was found deadlocking a
    /// node under load). Every blocking wait in them goes through
    /// [`super::blocking_released`] / [`super::block_on_released`] (or
    /// [`super::released`]), which release the interpreter when the thread
    /// holds it, so none of them can wait attached again. A bare
    /// `block_in_place` or `Handle::block_on` outside tests fails this.
    #[test]
    fn no_dispatcher_or_transport_wait_can_block_while_attached() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        // Owned by the IPsec work that makes this hook non-blocking; it moves
        // onto the helpers with that change.
        const PENDING: &[&str] = &["src/ipsec/manager_async.rs", "src/ipsec/runtime.rs"];
        // Waits that are right as written, each with the reason. Matched on
        // the file and a fragment of the line, so a new wait in the same file
        // is still caught.
        const EXEMPT: &[(&str, &str)] = &[
            // The helpers themselves: the wait inside `detach_block_on` runs
            // inside its own `python.detach`.
            ("src/script/blocking.rs", "block_in_place(|| tokio::runtime::Handle::current().block_on(future))"),
            // Inside `python.detach(...)` on the same line.
            ("src/script/async_pool.rs", "python.detach(|| tokio::task::block_in_place(|| runtime.block_on(pending.settle())))"),
            // Drives an asyncio loop with `run_until_complete`: the thread runs
            // the loop's bytecode attached and reaches safe points; releasing
            // the interpreter here would be wrong. Fallback without the pool.
            ("src/script/inline_dispatch.rs", "tokio::task::block_in_place(|| {"),
            // The process entry point: `run()` blocks the main thread on the
            // server future before anything has attached.
            ("src/server/mod.rs", "runtime.block_on(self.run_async())"),
        ];

        let mut offenders = Vec::new();
        // The whole crate: any synchronous Rust can be reached from an
        // attached caller (a script API, an extension, a resumed handler).
        let mut directories = vec![root.join("src")];
        while let Some(directory) = directories.pop() {
            for entry in std::fs::read_dir(&directory).expect("source directory is readable") {
                let path = entry.expect("directory entry is readable").path();
                if path.is_dir() {
                    directories.push(path);
                    continue;
                }
                let relative = path
                    .strip_prefix(root)
                    .expect("under the manifest directory")
                    .to_string_lossy()
                    .replace('\\', "/");
                let is_test_file = relative.ends_with("tests.rs")
                    || relative.ends_with("_harness.rs")
                    || relative.ends_with("test_dispatcher.rs");
                if path.extension().and_then(|ext| ext.to_str()) != Some("rs")
                    || is_test_file
                    || PENDING.contains(&relative.as_str())
                {
                    continue;
                }
                let source = std::fs::read_to_string(&path).expect("source file is readable");
                // Inline `#[cfg(test)] mod tests` sit at the end of the file.
                let production = source.split("#[cfg(test)]\nmod ").next().unwrap_or("");
                let mut previous = "";
                for (number, line) in production.lines().enumerate() {
                    let code = line.split("//").next().unwrap_or("");
                    let waits = code.contains("block_in_place(") || code.contains(".block_on(");
                    // `released(|| {` wrapping the wait from the line above.
                    let wrapped = previous.trim_end().ends_with("released(|| {")
                        || previous.trim_end().ends_with("released(move || {");
                    previous = code;
                    let exempt = EXEMPT
                        .iter()
                        .any(|(file, fragment)| *file == relative && code.contains(fragment));
                    if waits && !code.contains("released(") && !wrapped && !exempt {
                        offenders.push(format!("{relative}:{}", number + 1));
                    }
                }
            }
        }
        offenders.sort();
        assert!(
            offenders.is_empty(),
            "these dispatcher/transport waits block without releasing the \
             interpreter; on an attached thread one deadlocks the process behind \
             a garbage collection's stop-the-world: {offenders:?}"
        );
    }
}
