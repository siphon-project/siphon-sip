//! PyO3 `b2bua` control namespace — imperative B2BUA call operations that act
//! immediately rather than via a deferred [`CallAction`](super::call::CallAction).
//!
//! Injected as `siphon.b2bua._control` at startup; the pure-Python
//! `_B2buaNamespace` forwards `b2bua.terminate(...)` to it. Stateless — it
//! reaches the running dispatcher through a process-global handle, so it works
//! from any context (event callbacks like `@rtpengine.on_dtmf`, timers, async
//! handlers) where the deferred `call.terminate()` is a silent no-op.

use pyo3::prelude::*;

/// Stateless imperative B2BUA control namespace (`siphon.b2bua._control`).
#[pyclass(name = "B2buaControl")]
pub struct PyB2buaControl;

impl Default for PyB2buaControl {
    fn default() -> Self {
        Self::new()
    }
}

impl PyB2buaControl {
    pub fn new() -> Self {
        Self
    }
}

#[pymethods]
impl PyB2buaControl {
    /// Imperatively end a B2BUA call by its SIP Call-ID, sending an in-dialog
    /// BYE to every leg **now** (not deferred until a handler returns, the way
    /// `call.terminate()` is).
    ///
    /// Keyed by SIP Call-ID and backed by shared Rust dialog state, so it is
    /// cross-worker safe and works from an event callback (`@rtpengine.on_dtmf`,
    /// `@rtpengine.on_media_timeout`), a timer, or a normal handler — none of
    /// which give `call.terminate()` a handler-return to act on.
    ///
    /// Returns True if a matching call was found and torn down, False if the
    /// Call-ID is unknown / already gone (e.g. the caller hung up first) — never
    /// raises, so racing a caller-initiated BYE is a clean no-op.
    #[pyo3(signature = (call_id, reason="Normal Clearing"))]
    fn terminate(&self, call_id: &str, reason: &str) -> bool {
        crate::dispatcher::b2bua_terminate_call(call_id, Some(reason))
    }
}
