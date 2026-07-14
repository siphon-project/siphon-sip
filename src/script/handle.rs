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
//!   - [`ScriptHandle::call_handler`] — dispatch sync or async handlers
//!
//! Extensions never see the underlying Python callable directly; dispatch
//! happens through `call_handler` so the engine can pick the right
//! execution path (GIL-only vs. asyncio loop) consistently.

use std::sync::Arc;

use arc_swap::ArcSwap;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyTuple};

use crate::script::engine::{HandlerEntry, HandlerKind, ScriptState, run_coroutine_value};

/// Owned, opaque reference to a script-registered handler. Returned by
/// [`ScriptHandle::handlers_for`].
///
/// The handle holds reference-counted Python objects (the callable and an
/// optional metadata dict) so it can outlive the script-state guard it
/// was snapshotted from. Cloning is cheap (Py refcount bumps + a string
/// clone).
#[derive(Clone)]
pub struct HandlerHandle {
    kind: String,
    callable: Py<PyAny>,
    is_async: bool,
    options: Option<Py<PyDict>>,
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

    fn from_entry(entry: &HandlerEntry) -> Option<Self> {
        let kind = match &entry.kind {
            HandlerKind::Custom { kind } => kind.clone(),
            // Built-in kinds are addressed via siphon-core's typed accessors.
            // ScriptHandle only exposes the open extension surface.
            _ => return None,
        };
        Python::attach(|py| {
            Some(Self {
                kind,
                callable: entry.callable.clone_ref(py),
                is_async: entry.is_async,
                options: entry.options.as_ref().map(|d| d.clone_ref(py)),
            })
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
    pub(crate) fn new(
        state: Arc<ArcSwap<ScriptState>>,
        runtime: tokio::runtime::Handle,
    ) -> Self {
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
    /// Sync handlers are called under the GIL on a tokio blocking
    /// thread. Async handlers run to completion on this worker's
    /// persistent asyncio event loop, with `block_in_place` used inside
    /// to keep other tokio tasks progressing on other workers.
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
        let callable = Python::attach(|py| handler.callable.clone_ref(py));
        let is_async = handler.is_async;

        let join = crate::script::py_executor::try_run(move || {
            Python::attach(|py| -> PyResult<Py<PyAny>> {
                let bound_callable = callable.bind(py);
                let bound_args: Vec<Bound<'_, PyAny>> =
                    args.into_iter().map(|a| a.into_bound(py)).collect();
                let arg_tuple = PyTuple::new(py, bound_args)?;
                let returned = bound_callable.call1(arg_tuple)?;
                if is_async {
                    run_coroutine_value(py, &returned)
                } else {
                    Ok(returned.unbind())
                }
            })
        })
        .await;

        match join {
            Ok(result) => result,
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

        let handler = handle
            .handlers_for("ext.boom")
            .into_iter()
            .next()
            .unwrap();

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
}
