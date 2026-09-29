//! The `@rtpengine.on_*` media-event decorators.
//!
//! Every media-event hook registers the same way: a handler, optionally
//! filtered on the engine call-id and the from-tag, under the hook's registry
//! kind. The one builder here serves them all, so a new event is a kind string
//! and a docstring rather than another copy of the decorator.

use pyo3::prelude::*;
use pyo3::types::PyDict;

/// The Python factory each hook calls: `make_decorator(kind, call_id,
/// from_tag)` returns the decorator that registers a handler under `kind` with
/// the two filters as its metadata.
const MAKE_DECORATOR: &std::ffi::CStr = c"
def make_decorator(kind, call_id, from_tag):
    import asyncio
    import _siphon_registry
    def decorator(fn):
        is_async = asyncio.iscoroutinefunction(fn)
        metadata = {\"call_id\": call_id, \"from_tag\": from_tag}
        _siphon_registry.register(kind, None, fn, is_async, metadata)
        return fn
    return decorator
";

/// The decorator for the media-event hook registered as `kind`, filtered on
/// `call_id` and `from_tag` (`None` matches everything).
///
/// Supports both forms a script writes: bare (`@rtpengine.on_x`), where
/// `func_or_none` is the handler and it is registered at once, and with
/// filters (`@rtpengine.on_x(call_id=...)`), where the decorator is returned.
pub(super) fn event_decorator<'py>(
    python: Python<'py>,
    kind: &str,
    func_or_none: Option<Py<PyAny>>,
    call_id: Option<String>,
    from_tag: Option<String>,
) -> PyResult<Bound<'py, PyAny>> {
    let globals = PyDict::new(python);
    python.run(MAKE_DECORATOR, Some(&globals), None)?;
    let make_decorator = globals.get_item("make_decorator")?.ok_or_else(|| {
        pyo3::exceptions::PyRuntimeError::new_err(format!("failed to build the {kind} decorator"))
    })?;
    let decorator = make_decorator.call1((kind, call_id, from_tag))?;
    match func_or_none {
        Some(func) => decorator.call1((func.bind(python),)),
        None => Ok(decorator),
    }
}
