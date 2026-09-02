//! The `li` Python namespace.
//!
//! # This is no longer the gate
//!
//! Interception is enforced in the dispatcher, against the tasks the ADMF
//! provisioned over X1, for every message on every leg. A warrant applies
//! whether or not a script calls anything here.
//!
//! What remains is:
//!
//! * **Visibility** — [`PyLiNamespace::is_target`] lets a script know a warrant
//!   applies, so it can avoid behaviour that would defeat it (a local reject, a
//!   media release) without having to trigger the intercept itself.
//! * **Operator-driven recording** — `record` / `stop_recording` drive SIPREC,
//!   which is a recording feature, not a warrant.
//!
//! `intercept` and `stop_intercept` are kept so existing scripts keep working,
//! but they **report** rather than act: the dispatcher has already emitted the
//! IRI for any matching message by the time a handler runs. If they still
//! emitted, every script that calls them would produce duplicate IRI records
//! for one event.

use pyo3::prelude::*;

use crate::li::{AuditOperation, LiManager};

/// Python-facing LI namespace.
#[pyclass(name = "LiNamespace")]
pub struct PyLiNamespace {
    manager: LiManager,
}

impl PyLiNamespace {
    /// Wrap the LI subsystem for Python.
    pub fn new(manager: LiManager) -> Self {
        Self { manager }
    }

    /// Whether any provisioned warrant covers this request.
    ///
    /// Asked of the *session*, not the message, so this answers the same
    /// question enforcement did. Matching the message on its own identities
    /// would disagree with the dispatcher on any request whose identities have
    /// moved since the session opened — a re-INVITE from the far end, an
    /// in-dialog REFER, a BYE from either side — and a script told "not a
    /// target" about a call that is being intercepted is worse than no answer
    /// at all.
    ///
    /// The dispatcher decides before any handler runs, so by the time this is
    /// asked the decision already exists and this is a lookup.
    fn matches(&self, request: &super::request::PyRequest) -> bool {
        !self
            .manager
            .check_session(
                &request.li_call_id(),
                request.li_ruri().as_deref(),
                request.li_from_uri().as_deref(),
                request.li_to_uri().as_deref(),
                request.li_source_ip(),
            )
            .is_empty()
    }
}

#[pymethods]
impl PyLiNamespace {
    /// Check whether an active intercept target matches this request.
    ///
    /// Args:
    ///     request: The SIP request object.
    ///
    /// Returns:
    ///     True if a provisioned warrant matches the request's Request-URI,
    ///     From, To or source address.
    ///
    /// Note:
    ///     This is informational. Interception happens in the dispatcher
    ///     regardless of what the script does with the answer.
    fn is_target(&self, request: &super::request::PyRequest) -> bool {
        if !self.manager.is_enabled() {
            return false;
        }
        self.matches(request)
    }

    /// Report whether this request is being intercepted.
    ///
    /// Args:
    ///     request: The SIP request object.
    ///
    /// Returns:
    ///     True if a provisioned warrant matches.
    ///
    /// Note:
    ///     Retained for compatibility. This does **not** trigger interception:
    ///     the dispatcher has already emitted the IRI record for any matching
    ///     message before a script handler runs. Calling it is harmless and
    ///     changes nothing.
    fn intercept(&self, request: &super::request::PyRequest) -> bool {
        if !self.manager.is_enabled() {
            return false;
        }
        self.matches(request)
    }

    /// Report whether this request is being intercepted.
    ///
    /// Args:
    ///     request: The SIP request object.
    ///
    /// Returns:
    ///     True if a provisioned warrant matches.
    ///
    /// Note:
    ///     Retained for compatibility. Session teardown records are emitted by
    ///     the dispatcher when the dialog ends; this does not emit one.
    fn stop_intercept(&self, request: &super::request::PyRequest) -> bool {
        if !self.manager.is_enabled() {
            return false;
        }
        self.matches(request)
    }

    /// Start SIPREC recording for a request or call.
    ///
    /// Accepts either a Request (proxy mode) or Call (B2BUA mode). In B2BUA
    /// mode, sets the recording flag on the call so the dispatcher starts
    /// SIPREC on answer.
    ///
    /// Args:
    ///     target: A Request or Call object.
    ///
    /// Returns:
    ///     True if recording was initiated.
    ///
    /// Note:
    ///     SIPREC is a recording feature, not lawful interception. It produces
    ///     no X2 record and is not tied to a provisioned warrant.
    fn record(&self, target: &Bound<'_, PyAny>) -> PyResult<bool> {
        if !self.manager.is_enabled() {
            return Ok(false);
        }

        if let Ok(mut call) = target.cast::<super::call::PyCall>().map(|c| c.borrow_mut()) {
            let call_id = call.li_call_id();
            call.set_li_record();
            self.manager.audit(
                AuditOperation::MediaCaptureStarted,
                Some(&call_id),
                format!("SIPREC recording started for call {call_id}"),
            );
            return Ok(true);
        }

        if let Ok(request) = target
            .cast::<super::request::PyRequest>()
            .map(|r| r.borrow())
        {
            let call_id = request.li_call_id();
            self.manager.audit(
                AuditOperation::MediaCaptureStarted,
                Some(&call_id),
                format!("SIPREC recording started for call {call_id}"),
            );
            return Ok(true);
        }

        Err(pyo3::exceptions::PyTypeError::new_err(
            "record() expects a Request or Call object",
        ))
    }

    /// Stop SIPREC recording for a request or call.
    ///
    /// Args:
    ///     target: A Request or Call object.
    ///
    /// Returns:
    ///     True if the stop was recorded.
    fn stop_recording(&self, target: &Bound<'_, PyAny>) -> PyResult<bool> {
        if !self.manager.is_enabled() {
            return Ok(false);
        }

        let call_id = if let Ok(call) = target.cast::<super::call::PyCall>().map(|c| c.borrow()) {
            call.li_call_id()
        } else if let Ok(request) = target
            .cast::<super::request::PyRequest>()
            .map(|r| r.borrow())
        {
            request.li_call_id()
        } else {
            return Err(pyo3::exceptions::PyTypeError::new_err(
                "stop_recording() expects a Request or Call object",
            ));
        };

        self.manager.audit(
            AuditOperation::MediaCaptureStopped,
            Some(&call_id),
            format!("SIPREC recording stopped for call {call_id}"),
        );
        Ok(true)
    }

    /// Check if the LI subsystem is enabled.
    #[getter]
    fn is_enabled(&self) -> bool {
        self.manager.is_enabled()
    }

    /// How many intercept tasks the ADMF has provisioned over X1.
    ///
    /// Read-only: warrants are provisioned by the ADMF, never by a script.
    #[getter]
    fn task_count(&self) -> usize {
        self.manager.tasks().len()
    }

    /// How many delivery destinations the ADMF has provisioned over X1.
    #[getter]
    fn destination_count(&self) -> usize {
        self.manager.destinations().len()
    }
}
