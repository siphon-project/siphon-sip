//! Public handle into the script engine for host extensions.
//!
//! Host code that registers a task via
//! [`crate::SiphonServer::register_task`] receives a [`ScriptHandle`] from
//! which it can read the live custom-kind handler set the script
//! registered, dispatch into those handlers (sync or async — the loop is
//! the same per-worker asyncio loop the rest of siphon uses), and spawn
//! its own background work on siphon's tokio runtime.
//!
//! The handle is intentionally narrow:
//!   - [`ScriptHandle::tokio_handle`] — for spawning extension-owned tasks
//!   - [`ScriptHandle::handlers_for`] — read-only snapshot of custom handlers
//!   - [`ScriptHandle::call_handler_with`] — dispatch sync or async handlers,
//!     all Python inside executor jobs ([`ScriptHandle::call_handler`] is the
//!     older shape, kept for existing callers)
//!
//! Extensions never see the underlying Python callable directly; dispatch
//! happens through `call_handler_with` so the engine can pick the right
//! execution path (executor job, asyncio driver) consistently.
//!
//! # The embedding pattern: no attach on a tokio worker
//!
//! An extension's per-event dispatch (an HTTP request, an SMPP PDU) runs on a
//! tokio worker. Attaching to the interpreter there parks the worker for as
//! long as a garbage collection's stop-the-world is pending, and once every
//! worker is parked nothing polls the reactor. So the per-event path keeps all
//! Python inside the executor jobs `call_handler_with` runs, and reads handler
//! options as Rust data:
//!
//! ```rust,ignore
//! use pyo3::prelude::*;
//!
//! async fn on_request(handle: &ScriptHandle, path: String) -> Option<String> {
//!     // Route on the options without the interpreter.
//!     let handler = handle.handlers_for("http.route").into_iter().find(|handler| {
//!         handler.options_value().and_then(|options| options["path"].as_str())
//!             == Some(path.as_str())
//!     })?;
//!     handle
//!         .call_handler_with(
//!             &handler,
//!             // Built inside the job, with the Python token there.
//!             move |py| Ok(vec![path.into_pyobject(py)?.into_any().unbind()]),
//!             // Converted inside the job; only Rust comes back.
//!             |_py, outcome| outcome.and_then(|value| value.extract::<String>()).ok(),
//!         )
//!         .await
//!         .ok()
//!         .flatten()
//! }
//! ```
//!
//! An `async def` handler's coroutine runs on an asyncio driver and the
//! conversion runs in a follow-up job once it finishes. Blocking Rust an
//! extension cannot avoid goes through [`crate::script::blocking`]
//! (`released`, `blocking_released`, `block_on_released`, `detach_block_on`).

use std::sync::Arc;

use arc_swap::ArcSwap;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyTuple};

use crate::script::engine::{HandlerEntry, HandlerKind, ScriptState};
use crate::script::inline_dispatch::{start_coroutine, CoroutineStart};

/// Owned, opaque reference to a script-registered handler. Returned by
/// [`ScriptHandle::handlers_for`].
///
/// The handle shares the engine's reference to the Python callable and its
/// optional metadata dict, so it can outlive the script-state guard it was
/// snapshotted from. Taking and cloning one never touches the interpreter: it
/// is `Arc` bumps and a string clone, safe on a tokio worker.
#[derive(Clone)]
pub struct HandlerHandle {
    kind: String,
    callable: Arc<Py<PyAny>>,
    is_async: bool,
    options: Option<Arc<Py<PyDict>>>,
    options_value: Option<Arc<serde_json::Value>>,
}

impl HandlerHandle {
    /// Registry kind string the script registered (e.g. `"audit.sink"`).
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// Whether the underlying Python callable is a coroutine function.
    pub fn is_async(&self) -> bool {
        self.is_async
    }

    /// Per-handler metadata dict, if the script supplied one. Bound to
    /// the supplied Python token so callers can read keys without
    /// re-attaching.
    pub fn options<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyDict>> {
        self.options.as_ref().map(|d| d.bind(py).clone())
    }

    /// The same metadata as Rust data, read without the interpreter.
    ///
    /// Captured once when the script registered the handler, as JSON: strings,
    /// numbers, booleans, `None`, lists and dicts keep their shape, and any
    /// other value is its `repr()`. Use this on a tokio worker (routing on an
    /// option, filtering events) instead of [`Self::options`], which needs an
    /// attach: an attach on a worker parks it through every garbage
    /// collection's stop-the-world.
    pub fn options_value(&self) -> Option<&serde_json::Value> {
        self.options_value.as_deref()
    }

    fn from_entry(entry: &HandlerEntry) -> Option<Self> {
        let kind = match &entry.kind {
            HandlerKind::Custom { kind } => kind.clone(),
            // Built-in kinds are addressed via siphon-core's typed accessors.
            // ScriptHandle only exposes the open extension surface.
            _ => return None,
        };
        Some(Self {
            kind,
            callable: Arc::clone(&entry.callable),
            is_async: entry.is_async,
            options: entry.options.clone(),
            options_value: entry.options_value.clone(),
        })
    }
}

impl std::fmt::Debug for HandlerHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandlerHandle")
            .field("kind", &self.kind)
            .field("is_async", &self.is_async)
            .field("has_options", &self.options.is_some())
            .finish()
    }
}

/// Public handle for host extensions to interact with the live script
/// engine. Cloned out to each task registered with
/// [`crate::SiphonServer::register_task`].
#[derive(Clone)]
pub struct ScriptHandle {
    state: Arc<ArcSwap<ScriptState>>,
    runtime: tokio::runtime::Handle,
}

impl ScriptHandle {
    /// Construct from the engine's state pointer and the tokio runtime
    /// handle. Server bootstrap calls this once after the runtime is
    /// built and the script engine is initialised; extensions never
    /// construct a `ScriptHandle` directly.
    pub(crate) fn new(state: Arc<ArcSwap<ScriptState>>, runtime: tokio::runtime::Handle) -> Self {
        Self { state, runtime }
    }

    /// Tokio runtime handle for spawning extension-owned background work
    /// (HTTP listeners, side-channel clients, periodic sweeps).
    pub fn tokio_handle(&self) -> &tokio::runtime::Handle {
        &self.runtime
    }

    /// Snapshot all custom-kind handlers the script registered under
    /// `kind`. Lookup is exact (no globbing or prefix match). Returns
    /// owned [`HandlerHandle`]s so callers can store or move them across
    /// tasks without lifetime gymnastics.
    pub fn handlers_for(&self, kind: &str) -> Vec<HandlerHandle> {
        let state = self.state.load();
        state
            .handlers_for_custom(kind)
            .into_iter()
            .filter_map(HandlerHandle::from_entry)
            .collect()
    }

    /// Invoke a script-registered handler with the given positional
    /// arguments and return its result.
    ///
    /// Both kinds are called on the Python executor. A sync handler's value
    /// comes back from that job. An async handler's coroutine runs inline when
    /// it cannot suspend; otherwise the job hands it to an asyncio driver and
    /// returns, and this future awaits its result with no executor worker held
    /// and no interpreter attached. So the number of async handlers in flight
    /// is not bounded by the executor's size; each is still bounded by the
    /// coroutine timeout, on which it is cancelled and fails with
    /// `TimeoutError`.
    ///
    /// **Superseded by [`Self::call_handler_with`]** for new code: the caller
    /// has to build `args` and read the result attached, and on a tokio worker
    /// that attach parks the worker through every garbage collection's
    /// stop-the-world. `call_handler_with` does both inside the executor jobs.
    /// Kept, unchanged, for existing callers.
    ///
    /// **Caller contract:** must be invoked from a task running on
    /// [`Self::tokio_handle`]'s runtime — extension tasks registered
    /// via `register_task` are spawned there by default, so this is
    /// only a concern if the extension hands the handle off to an
    /// unrelated runtime.
    pub async fn call_handler(
        &self,
        handler: &HandlerHandle,
        args: Vec<Py<PyAny>>,
    ) -> PyResult<Py<PyAny>> {
        self.call_handler_with(
            handler,
            move |_python| Ok(args),
            |_python, result| result.map(Bound::unbind),
        )
        .await?
    }

    /// Invoke a handler with every touch of Python inside executor jobs, so
    /// the calling tokio task never attaches.
    ///
    /// `args` builds the positional arguments, attached, in the job that calls
    /// the handler. `finish` turns the handler's outcome (its return value, or
    /// the exception it raised) into whatever the extension needs, attached:
    /// in the same job for a sync handler or a coroutine that finished inline,
    /// in a follow-up job once a suspended coroutine has finished. The caller
    /// awaits all of it without holding the interpreter.
    ///
    /// Use it for per-event dispatch on a tokio worker (an HTTP request, an
    /// SMPP PDU): an attach there parks the worker through every garbage
    /// collection's stop-the-world, and once every worker is parked nothing
    /// polls the reactor. Handler options for routing decisions are available
    /// as Rust data from [`HandlerHandle::options_value`] without an attach.
    ///
    /// `Err` means the handler never ran or its job was lost (the executor
    /// shed it or is shutting down, or a closure panicked); what the handler
    /// itself raised reaches `finish`.
    pub async fn call_handler_with<A, F, R>(
        &self,
        handler: &HandlerHandle,
        args: A,
        finish: F,
    ) -> PyResult<R>
    where
        A: for<'py> FnOnce(Python<'py>) -> PyResult<Vec<Py<PyAny>>> + Send + 'static,
        F: for<'py> FnOnce(Python<'py>, PyResult<Bound<'py, PyAny>>) -> R + Send + 'static,
        R: Send + 'static,
    {
        let callable = Arc::clone(&handler.callable);
        let is_async = handler.is_async;

        type Finish<R> =
            Box<dyn for<'py> FnOnce(Python<'py>, PyResult<Bound<'py, PyAny>>) -> R + Send>;
        enum Started<R> {
            Done(R),
            Suspended(crate::script::async_pool::PendingCoroutine, Finish<R>),
        }

        let join = crate::script::py_executor::try_run(move || {
            crate::script::attach::attach(|py| -> Started<R> {
                let returned = args(py).and_then(|args| {
                    let bound_args: Vec<Bound<'_, PyAny>> =
                        args.into_iter().map(|a| a.into_bound(py)).collect();
                    let arg_tuple = PyTuple::new(py, bound_args)?;
                    callable.bind(py).call1(arg_tuple)
                });
                let returned = match returned {
                    Ok(returned) if is_async => match start_coroutine(py, &returned) {
                        Ok(CoroutineStart::Finished(value)) => Ok(value.into_bound(py)),
                        Ok(CoroutineStart::Suspended(pending)) => {
                            return Started::Suspended(pending, Box::new(finish));
                        }
                        Err(error) => Err(error),
                    },
                    other => other,
                };
                Started::Done(finish(py, returned))
            })
        })
        .await;

        match join {
            Ok(Started::Done(value)) => Ok(value),
            Ok(Started::Suspended(pending, finish)) => {
                let settled = pending.wait().await;
                crate::script::py_executor::run_queued(move || {
                    crate::script::attach::attach(|py| {
                        finish(py, settled.map(|value| value.into_bound(py)))
                    })
                })
                .await
                .map_err(|_| {
                    PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                        "script handler continuation did not run".to_string(),
                    )
                })
            }
            Err(_panic) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
                "script handler dispatch panicked".to_string(),
            )),
        }
    }
}

impl std::fmt::Debug for ScriptHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScriptHandle").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::script::engine::ScriptEngine;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn engine_with_source(source: &str) -> Arc<ScriptEngine> {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(source.as_bytes()).unwrap();
        file.flush().unwrap();

        Python::initialize();
        Arc::new(
            ScriptEngine::new(&crate::config::ScriptConfig {
                path: file.path().to_str().unwrap().to_owned(),
                reload: crate::config::ReloadMode::Sighup,
                async_pool_size: None,
                sync_pool_size: None,
                sync_pool_max: None,
                handler_stall_abort_secs: 30,
                handler_timeout_secs: None,
                executor_queue_capacity: 1024,
                include_paths: Vec::new(),
            })
            .unwrap(),
        )
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn handlers_for_returns_owned_handles_for_matching_kind() {
        let engine = engine_with_source(
            r#"
import _siphon_registry as _r

def alpha_a(arg): return arg + "-a"
def alpha_b(arg): return arg + "-b"
def beta_only(arg): return arg + "-beta"

_r.register("alpha.kind", None, alpha_a, False, {"tag": "first"})
_r.register("alpha.kind", None, alpha_b, False, {"tag": "second"})
_r.register("beta.kind",  None, beta_only, False, None)
"#,
        );
        let handle = ScriptHandle::new(engine.state_arc(), tokio::runtime::Handle::current());

        let alphas = handle.handlers_for("alpha.kind");
        assert_eq!(alphas.len(), 2);
        for h in &alphas {
            assert_eq!(h.kind(), "alpha.kind");
            assert!(!h.is_async());
        }

        let betas = handle.handlers_for("beta.kind");
        assert_eq!(betas.len(), 1);
        Python::attach(|py| {
            assert!(betas[0].options(py).is_none());
        });

        assert!(handle.handlers_for("nothing.here").is_empty());
    }

    /// `call_handler_with` builds the arguments and reads the outcome inside
    /// the executor jobs, for sync and async handlers and for a raise.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn call_handler_with_keeps_every_python_touch_in_the_job() {
        let engine = engine_with_source(
            r#"
import asyncio
import _siphon_registry as _r

def shout(name): return name.upper()
async def later(name):
    await asyncio.sleep(0.01)
    return name + "!"
def broken(name): raise ValueError("no " + name)

_r.register("ext.shout", None, shout, False, None)
_r.register("ext.later", None, later, True, None)
_r.register("ext.broken", None, broken, False, None)
"#,
        );
        let handle = ScriptHandle::new(engine.state_arc(), tokio::runtime::Handle::current());
        let first = |kind: &str| handle.handlers_for(kind).into_iter().next().expect(kind);
        let args = |py: Python<'_>| -> PyResult<Vec<Py<PyAny>>> {
            Ok(vec!["abc".into_pyobject(py)?.into_any().unbind()])
        };
        let as_text = |_py: Python<'_>, outcome: PyResult<Bound<'_, PyAny>>| {
            outcome
                .and_then(|value| value.extract::<String>())
                .map_err(|error| error.to_string())
        };

        let shouted = handle
            .call_handler_with(&first("ext.shout"), args, as_text)
            .await;
        assert_eq!(shouted.expect("dispatched"), Ok("ABC".to_string()));
        let later = handle
            .call_handler_with(&first("ext.later"), args, as_text)
            .await;
        assert_eq!(later.expect("dispatched"), Ok("abc!".to_string()));
        let broken = handle
            .call_handler_with(&first("ext.broken"), args, as_text)
            .await;
        let raised = broken
            .expect("dispatched")
            .expect_err("the raise reaches finish");
        assert!(raised.contains("no abc"), "{raised}");
    }

    /// Options are readable as Rust data, with no attach: JSON shapes kept,
    /// anything else as its repr.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn handler_options_are_readable_as_rust_data() {
        let engine = engine_with_source(
            r#"
import _siphon_registry as _r

def fn(_): pass

_r.register("ext.route", None, fn, False, {"methods": ["GET", "POST"], "level": 5, "hook": fn})
_r.register("ext.bare", None, fn, False, None)
"#,
        );
        let handle = ScriptHandle::new(engine.state_arc(), tokio::runtime::Handle::current());
        let route = handle
            .handlers_for("ext.route")
            .into_iter()
            .next()
            .expect("route");
        let options = route.options_value().expect("options captured");
        assert_eq!(options["methods"][1], "POST");
        assert_eq!(options["level"], 5);
        assert!(options["hook"]
            .as_str()
            .is_some_and(|text| text.contains("function")));
        let bare = handle
            .handlers_for("ext.bare")
            .into_iter()
            .next()
            .expect("bare");
        assert!(bare.options_value().is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn handler_handle_options_round_trip() {
        let engine = engine_with_source(
            r#"
import _siphon_registry as _r

def fn(_): pass

_r.register("ext.thing", None, fn, False, {"path": "/tmp/x", "level": 5})
"#,
        );
        let handle = ScriptHandle::new(engine.state_arc(), tokio::runtime::Handle::current());

        let entries = handle.handlers_for("ext.thing");
        assert_eq!(entries.len(), 1);
        Python::attach(|py| {
            let opts = entries[0].options(py).expect("options must be present");
            let path: String = opts.get_item("path").unwrap().unwrap().extract().unwrap();
            assert_eq!(path, "/tmp/x");
            let level: i64 = opts.get_item("level").unwrap().unwrap().extract().unwrap();
            assert_eq!(level, 5);
        });
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn call_handler_dispatches_sync_handler_with_args() {
        let engine = engine_with_source(
            r#"
import _siphon_registry as _r

def echo(name, n):
    return f"{name}={n}"

_r.register("ext.echo", None, echo, False, None)
"#,
        );
        let handle = ScriptHandle::new(engine.state_arc(), tokio::runtime::Handle::current());

        let handler = handle
            .handlers_for("ext.echo")
            .into_iter()
            .next()
            .expect("handler must be registered");

        let (arg_name, arg_count) = Python::attach(|py| {
            (
                "siphon".into_pyobject(py).unwrap().into_any().unbind(),
                7i64.into_pyobject(py).unwrap().into_any().unbind(),
            )
        });

        let result = handle
            .call_handler(&handler, vec![arg_name, arg_count])
            .await
            .expect("sync dispatch should succeed");

        Python::attach(|py| {
            let extracted: String = result.bind(py).extract().unwrap();
            assert_eq!(extracted, "siphon=7");
        });
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn call_handler_dispatches_async_handler() {
        let engine = engine_with_source(
            r#"
import asyncio
import _siphon_registry as _r

async def add_async(a, b):
    await asyncio.sleep(0)
    return a + b

_r.register("ext.add", None, add_async, True, None)
"#,
        );
        let handle = ScriptHandle::new(engine.state_arc(), tokio::runtime::Handle::current());

        let handler = handle
            .handlers_for("ext.add")
            .into_iter()
            .next()
            .expect("handler must be registered");

        let (a, b) = Python::attach(|py| {
            (
                3i64.into_pyobject(py).unwrap().into_any().unbind(),
                4i64.into_pyobject(py).unwrap().into_any().unbind(),
            )
        });

        let result = handle
            .call_handler(&handler, vec![a, b])
            .await
            .expect("async dispatch should succeed");

        Python::attach(|py| {
            let value: i64 = result.bind(py).extract().unwrap();
            assert_eq!(value, 7);
        });
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn call_handler_propagates_python_exception() {
        let engine = engine_with_source(
            r#"
import _siphon_registry as _r

def boom():
    raise ValueError("nope")

_r.register("ext.boom", None, boom, False, None)
"#,
        );
        let handle = ScriptHandle::new(engine.state_arc(), tokio::runtime::Handle::current());

        let handler = handle.handlers_for("ext.boom").into_iter().next().unwrap();

        let result = handle.call_handler(&handler, vec![]).await;
        let error = result.expect_err("ValueError must propagate");
        let message = format!("{error}");
        assert!(message.contains("nope"), "unexpected error: {message}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn handlers_for_only_returns_custom_kinds() {
        // A built-in proxy.on_request handler must NOT show up under any
        // handlers_for() lookup, since ScriptHandle is the open-extension
        // surface only. Built-in kinds stay typed inside siphon-core.
        let engine = engine_with_source(
            r#"
from siphon import proxy
import _siphon_registry as _r

@proxy.on_request
def route(request): pass

def custom(arg): return arg

_r.register("ext.thing", None, custom, False, None)
"#,
        );
        let handle = ScriptHandle::new(engine.state_arc(), tokio::runtime::Handle::current());

        assert_eq!(handle.handlers_for("ext.thing").len(), 1);
        assert!(handle.handlers_for("proxy.on_request").is_empty());
    }

    /// The handler of `kind` in `handle`'s script.
    fn only_handler(handle: &ScriptHandle, kind: &str) -> HandlerHandle {
        handle
            .handlers_for(kind)
            .into_iter()
            .next()
            .expect("handler must be registered")
    }

    fn int_arg(value: i64) -> Py<PyAny> {
        Python::attach(|py| value.into_pyobject(py).unwrap().into_any().unbind())
    }

    /// More awaiting handlers than the executor has workers all run at once:
    /// an `await` costs a pending coroutine, not an executor thread. Parked
    /// workers would run these in three waves of one second each.
    // A plain test that blocks on the pools' runtime: the serialising
    // guard is a std mutex, which is not held across an await of this test's.
    #[test]
    fn awaiting_handlers_beyond_the_executor_size_all_run_at_once() {
        let _serial = crate::script::async_pool::pool_test_guard();
        crate::script::async_pool::test_pools_runtime().block_on(async {
            let (executor, _async_pool) = crate::script::async_pool::ensure_test_pools();
            let engine = engine_with_source(
                r#"
import asyncio
import _siphon_registry as _r

async def slow(value):
    await asyncio.sleep(1.0)
    return value

_r.register("ext.slow", None, slow, True, None)
"#,
            );
            let handle = Arc::new(ScriptHandle::new(
                engine.state_arc(),
                tokio::runtime::Handle::current(),
            ));
            let handler = only_handler(&handle, "ext.slow");

            let calls = 2 * executor.max_size() + 1;
            let started = std::time::Instant::now();
            let mut joins = Vec::new();
            for index in 0..calls {
                let handle = Arc::clone(&handle);
                // `HandlerHandle` holds Python references: clone it attached.
                let handler = Python::attach(|_| handler.clone());
                let arg = int_arg(index as i64);
                joins.push(tokio::spawn(async move {
                    handle.call_handler(&handler, vec![arg]).await
                }));
            }
            let mut answered = Vec::new();
            for join in joins {
                let result = join.await.expect("the call task completes");
                answered.push(Python::attach(|py| {
                    result
                        .expect("every awaiting handler returns")
                        .bind(py)
                        .extract::<i64>()
                        .unwrap()
                }));
            }
            let elapsed = started.elapsed();

            answered.sort_unstable();
            assert_eq!(answered, (0..calls as i64).collect::<Vec<_>>());
            assert!(
                elapsed < std::time::Duration::from_secs(2),
                "{calls} handlers each awaiting 1 s on {} executor workers took {elapsed:?}",
                executor.max_size()
            );
        });
    }

    /// A handler that never settles fails with the coroutine timeout, its
    /// coroutine is cancelled on the driver, and nothing stays pending: after
    /// a batch of timed-out and completed calls the pending count is back
    /// where it started.
    // A plain test that blocks on the pools' runtime: the serialising
    // guard is a std mutex, which is not held across an await of this test's.
    #[test]
    fn timed_out_handlers_are_cancelled_and_leave_nothing_pending() {
        let _serial = crate::script::async_pool::pool_test_guard();
        crate::script::async_pool::test_pools_runtime().block_on(async {
            let (_executor, async_pool) = crate::script::async_pool::ensure_test_pools();
            let engine = engine_with_source(
                r#"
import asyncio
import _siphon_registry as _r

cancelled = []

async def wedged(value):
    try:
        await asyncio.get_running_loop().create_future()
    except asyncio.CancelledError:
        cancelled.append(value)
        raise

async def quick(value):
    await asyncio.sleep(0.01)
    return value

def cancelled_count():
    return len(cancelled)

_r.register("ext.wedged", None, wedged, True, None)
_r.register("ext.quick", None, quick, True, None)
_r.register("ext.cancelled", None, cancelled_count, False, None)
"#,
            );
            let handle = Arc::new(ScriptHandle::new(
                engine.state_arc(),
                tokio::runtime::Handle::current(),
            ));
            let wedged = only_handler(&handle, "ext.wedged");
            let quick = only_handler(&handle, "ext.quick");
            let cancelled = only_handler(&handle, "ext.cancelled");
            let baseline = crate::script::async_pool::pending_coroutines();

            const CALLS: usize = 4;
            let mut joins = Vec::new();
            for index in 0..CALLS {
                let pair = Python::attach(|_| [wedged.clone(), quick.clone()]);
                for handler in pair {
                    let handle = Arc::clone(&handle);
                    let arg = int_arg(index as i64);
                    joins.push(tokio::spawn(async move {
                        handle.call_handler(&handler, vec![arg]).await.is_ok()
                    }));
                }
            }
            let mut succeeded = 0;
            for join in joins {
                if join.await.expect("the call task completes") {
                    succeeded += 1;
                }
            }
            assert_eq!(
                succeeded, CALLS,
                "the quick ones succeed, the wedged ones time out"
            );

            // Cancellation lands on the driver loop a moment after the waiter gave up.
            let deadline = std::time::Instant::now() + async_pool.coroutine_timeout();
            let mut seen = 0;
            while std::time::Instant::now() < deadline {
                let count = handle
                    .call_handler(&cancelled, vec![])
                    .await
                    .expect("a sync probe");
                seen = Python::attach(|py| count.bind(py).extract::<usize>().unwrap());
                if seen == CALLS && crate::script::async_pool::pending_coroutines() <= baseline {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            assert_eq!(
                seen, CALLS,
                "every timed-out coroutine was cancelled on its driver"
            );
            assert!(
                crate::script::async_pool::pending_coroutines() <= baseline,
                "a timed-out or completed call left a coroutine counted as pending"
            );
        });
    }
}
